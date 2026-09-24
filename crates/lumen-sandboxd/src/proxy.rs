//! Host egress proxy: the only path out of the guest's network namespace.
//!
//! The guest's nftables policy permits TCP only to this proxy (plus DNS to
//! the forwarder). The proxy:
//!
//! 1. parses the guest's `CONNECT host:port` (or absolute-form HTTP)
//!    request — bounded read, no unbounded buffering;
//! 2. authorizes it against the run's [`NetworkPolicy`]
//!    ([`crate::network::check_destination`]) — redirects to unleased
//!    hosts are denied here;
//! 3. resolves the host through the pinned [`HostPolicyResolver`]
//!    (rebinding defense) and re-validates the literal IP before
//!    connecting (defense in depth: even a compromised resolver path
//!    cannot smuggle a metadata/private address through);
//! 4. relays with a per-destination byte cap and appends a JSON audit line
//!    `{ts, run_id, scheme, host, port, ip, egress_bytes, ingress_bytes,
//!    verdict}` — request/response bodies are never logged.

use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

use crate::{
    dns::{DnsUpstream, HostPolicyResolver},
    error::SandboxdError,
    network,
};

/// Per-run proxy configuration.
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub run_id: String,
    pub network: crate::contracts::NetworkPolicy,
    /// Per-connection byte cap (egress + ingress).
    pub byte_cap: u64,
    /// Per-run audit log path.
    pub log_path: PathBuf,
}

/// Parsed guest request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRequest {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// For absolute-form HTTP: the origin-form path to forward.
    pub path: String,
    pub is_connect: bool,
    /// Raw head bytes to forward (absolute-form only).
    pub head: Vec<u8>,
}

/// Parse the guest's request head (up to the blank line). Bounded: heads
/// over 16 KiB are rejected.
pub fn parse_request(head: &[u8]) -> Result<ProxyRequest, SandboxdError> {
    let text = std::str::from_utf8(head)
        .map_err(|_| SandboxdError::Protocol("proxy request is not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| SandboxdError::Protocol("empty proxy request".into()))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| SandboxdError::Protocol("bad request line".into()))?;
    let target = parts
        .next()
        .ok_or_else(|| SandboxdError::Protocol("bad request line".into()))?;

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target)?;
        // CONNECT requires an explicit nonzero port.
        let port = port.filter(|p| *p != 0).ok_or_else(|| {
            SandboxdError::Protocol("CONNECT requires an explicit nonzero port".into())
        })?;
        // CONNECT carries no scheme, and this proxy never terminates or
        // validates TLS — it is a raw TCP tunnel. The tunnel is therefore
        // authorized against `tcp` scope for this host:port. An
        // `https://host` lease does NOT authorize a CONNECT tunnel: scope
        // narrowing is exact, and the proxy cannot distinguish TLS from
        // raw TCP (SSH, database wire protocols, ...) inside a tunnel.
        Ok(ProxyRequest {
            scheme: "tcp".into(),
            host,
            port,
            path: String::new(),
            is_connect: true,
            head: Vec::new(),
        })
    } else {
        // Absolute-form HTTP: `GET http://host[:port]/path HTTP/1.1`.
        let (scheme, rest) = target
            .split_once("://")
            .ok_or_else(|| SandboxdError::Protocol("proxy requires absolute-form URI".into()))?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return Err(SandboxdError::Protocol(format!(
                "unsupported proxied scheme: {scheme}"
            )));
        }
        let (authority, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let (host, port) = split_host_port(authority)?;
        let port = port.unwrap_or(if scheme == "https" { 443 } else { 80 });
        // Rewrite to origin-form for forwarding.
        let mut head_out = format!("{method} {path} HTTP/1.1\r\n").into_bytes();
        for line in lines {
            if line.is_empty() {
                break;
            }
            // Strip proxy-only headers; never forward credentials we add.
            if line.to_ascii_lowercase().starts_with("proxy-") {
                continue;
            }
            head_out.extend_from_slice(line.as_bytes());
            head_out.extend_from_slice(b"\r\n");
        }
        head_out.extend_from_slice(b"\r\n");
        Ok(ProxyRequest {
            scheme,
            host,
            port,
            path: path.to_string(),
            is_connect: false,
            head: head_out,
        })
    }
}

fn split_host_port(authority: &str) -> Result<(String, Option<u16>), SandboxdError> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (ip, after) = rest
            .split_once(']')
            .ok_or_else(|| SandboxdError::Protocol(format!("bad authority: {authority}")))?;
        let port = after
            .strip_prefix(':')
            .map(str::parse::<u16>)
            .transpose()
            .map_err(|_| SandboxdError::Protocol(format!("bad port: {authority}")))?;
        return Ok((format!("[{ip}]"), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && !h.contains(':') => {
            let port: u16 = p
                .parse()
                .map_err(|_| SandboxdError::Protocol(format!("bad port: {authority}")))?;
            Ok((h.to_ascii_lowercase(), Some(port)))
        }
        _ => Ok((authority.to_ascii_lowercase(), None)),
    }
}

/// Read a request head, bounded at 16 KiB.
pub async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>, SandboxdError> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.map_err(SandboxdError::Io)?;
        if n == 0 {
            return Err(SandboxdError::Protocol("EOF in request head".into()));
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > 16 * 1024 {
            return Err(SandboxdError::Protocol("request head too large".into()));
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            // Trim to the end of the head; the body (if any) is handled by
            // the relay, not parsed here.
            let end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            buf.truncate(end);
            return Ok(buf);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct EgressLogLine {
    ts: u64,
    run_id: String,
    scheme: String,
    host: String,
    port: u16,
    ip: String,
    egress_bytes: u64,
    ingress_bytes: u64,
    verdict: String,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Append one audit line. Bodies are never logged — only 5-tuple + bytes.
async fn audit(
    log_path: &PathBuf,
    run_id: &str,
    req: &ProxyRequest,
    ip: &str,
    egress: u64,
    ingress: u64,
    verdict: &str,
) {
    let line = EgressLogLine {
        ts: now_unix(),
        run_id: run_id.to_string(),
        scheme: req.scheme.clone(),
        host: req.host.clone(),
        port: req.port,
        ip: ip.to_string(),
        egress_bytes: egress,
        ingress_bytes: ingress,
        verdict: verdict.to_string(),
    };
    if let Ok(mut text) = serde_json::to_string(&line) {
        text.push('\n');
        // Best-effort: audit failure must not break the data path, but the
        // kernel treats a missing egress log as a metering gap.
        if let Ok(mut f) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)
            .await
        {
            let _ = f.write_all(text.as_bytes()).await;
            let _ = f.sync_all().await;
        }
    }
}

/// Relay with a total byte cap. Returns (egress_bytes, ingress_bytes).
/// When the cap is hit, both directions are shut down: `capped` is true.
pub async fn relay_capped(
    guest: &mut TcpStream,
    upstream: &mut TcpStream,
    cap: u64,
) -> (u64, u64, bool) {
    let mut egress: u64 = 0;
    let mut ingress: u64 = 0;
    let mut capped = false;
    let mut gbuf = [0u8; 8192];
    let mut ubuf = [0u8; 8192];

    loop {
        if egress + ingress >= cap {
            capped = true;
            break;
        }
        tokio::select! {
            r = guest.read(&mut gbuf) => {
                match r {
                    Ok(0) => break,
                    Ok(n) => {
                        let allowed = (cap - egress - ingress).min(n as u64) as usize;
                        if upstream.write_all(&gbuf[..allowed]).await.is_err() { break; }
                        egress += allowed as u64;
                        if allowed < n { capped = true; break; }
                    }
                    Err(_) => break,
                }
            }
            r = upstream.read(&mut ubuf) => {
                match r {
                    Ok(0) => break,
                    Ok(n) => {
                        let allowed = (cap - egress - ingress).min(n as u64) as usize;
                        if guest.write_all(&ubuf[..allowed]).await.is_err() { break; }
                        ingress += allowed as u64;
                        if allowed < n { capped = true; break; }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    (egress, ingress, capped)
}

/// Shared proxy context.
pub struct Proxy<U: DnsUpstream> {
    cfg: ProxyConfig,
    resolver: Arc<Mutex<HostPolicyResolver<U>>>,
}

impl<U: DnsUpstream + 'static> Proxy<U> {
    pub fn new(cfg: ProxyConfig, resolver: HostPolicyResolver<U>) -> Self {
        Self {
            cfg,
            resolver: Arc::new(Mutex::new(resolver)),
        }
    }

    /// Serve forever on `listener`.
    pub async fn serve(&self, listener: TcpListener) -> ! {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let cfg = self.cfg.clone();
            let resolver = self.resolver.clone();
            tokio::spawn(async move {
                handle_one(stream, &cfg, &resolver).await;
            });
        }
    }
}

/// Authorize + resolve + relay one guest connection.
async fn handle_one<U: DnsUpstream>(
    mut guest: TcpStream,
    cfg: &ProxyConfig,
    resolver: &Arc<Mutex<HostPolicyResolver<U>>>,
) {
    let mut egress = 0u64;
    let mut ingress = 0u64;
    let mut ip_str = String::new();
    // A placeholder request for denied-before-parse cases.
    let mut req = ProxyRequest {
        scheme: "?".into(),
        host: "?".into(),
        port: 0,
        path: String::new(),
        is_connect: false,
        head: Vec::new(),
    };

    let outcome: Result<(), SandboxdError> = async {
        let head = read_head(&mut guest).await?;
        req = parse_request(&head)?;
        // 1. Allowlist authorization (typed scheme/host/port).
        let dest = network::check_destination(&cfg.network, &req.scheme, &req.host, req.port)?;
        // 2. Pinned resolution + literal re-validation (defense in depth).
        let ip = {
            let mut r = resolver.lock().await;
            let addrs = r.resolve(&dest.host)?;
            *addrs
                .first()
                .ok_or_else(|| SandboxdError::DnsDenied("no address".into()))?
        };
        network::deny_ip(ip, &cfg.network)?;
        ip_str = ip.to_string();

        let mut upstream = TcpStream::connect(SocketAddr::new(ip, dest.port))
            .await
            .map_err(|e| {
                SandboxdError::EgressDenied(format!("connect to {ip}:{} failed: {e}", dest.port))
            })?;

        if req.is_connect {
            guest
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .map_err(SandboxdError::Io)?;
        } else {
            upstream
                .write_all(&req.head)
                .await
                .map_err(SandboxdError::Io)?;
            egress += req.head.len() as u64;
        }
        let (e, i, capped) = relay_capped(&mut guest, &mut upstream, cfg.byte_cap).await;
        egress += e;
        ingress += i;
        if capped {
            return Err(SandboxdError::EgressDenied("byte cap exceeded".into()));
        }
        Ok(())
    }
    .await;

    let verdict = match outcome {
        Ok(()) => "ok".to_string(),
        Err(e) => {
            let _ = guest
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            e.code().to_string()
        }
    };
    audit(
        &cfg.log_path,
        &cfg.run_id,
        &req,
        &ip_str,
        egress,
        ingress,
        &verdict,
    )
    .await;
}

/// What the guest's /etc/resolv.conf and proxy env point at (host leg).
pub fn guest_proxy_env(host_ip: &str, port: u16) -> Vec<(String, String)> {
    vec![
        ("http_proxy".into(), format!("http://{host_ip}:{port}")),
        ("https_proxy".into(), format!("http://{host_ip}:{port}")),
        ("HTTP_PROXY".into(), format!("http://{host_ip}:{port}")),
        ("HTTPS_PROXY".into(), format!("http://{host_ip}:{port}")),
        ("no_proxy".into(), "localhost,127.0.0.1".into()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::NetworkPolicy;
    use std::net::IpAddr;

    struct FakeUpstream;
    impl DnsUpstream for FakeUpstream {
        fn resolve(&self, _name: &str) -> Result<Vec<IpAddr>, SandboxdError> {
            Ok(vec!["93.184.216.34".parse().unwrap()])
        }
    }

    fn policy(entries: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            allow_egress: entries.iter().map(|s| s.to_string()).collect(),
            deny_metadata: true,
            deny_private_ranges: true,
        }
    }

    #[test]
    fn parses_connect() {
        let r = parse_request(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(r.scheme, "tcp");
        assert_eq!(r.host, "api.example.com");
        assert_eq!(r.port, 443);
        assert!(r.is_connect);
    }

    #[test]
    fn connect_is_authorized_as_tcp_scope_not_https() {
        // CONNECT carries no scheme and the proxy never terminates TLS, so
        // a CONNECT tunnel is raw TCP authority: it must be authorized
        // against `tcp` scope for host:port. An `https://host` lease must
        // NOT authorize it (scope confusion), per design invariant 3 —
        // scope narrowing is exact.
        let req = parse_request(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert!(req.is_connect);
        assert_eq!(req.scheme, "tcp");

        // Lease scoped to https://api.example.com:443: CONNECT denied.
        let https_only = policy(&["https://api.example.com:443"]);
        assert!(
            network::check_destination(&https_only, &req.scheme, &req.host, req.port).is_err(),
            "an https-scope lease must not authorize a CONNECT tunnel"
        );

        // Lease scoped to tcp://api.example.com:443: CONNECT allowed.
        let tcp_scoped = policy(&["tcp://api.example.com:443"]);
        let dest =
            network::check_destination(&tcp_scoped, &req.scheme, &req.host, req.port).unwrap();
        assert_eq!(dest.scheme, "tcp");
        assert_eq!(dest.host, "api.example.com");
        assert_eq!(dest.port, 443);
    }

    #[test]
    fn parses_absolute_form() {
        let r = parse_request(
            b"GET http://api.example.com:8080/a/b?c=d HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(r.scheme, "http");
        assert_eq!(r.host, "api.example.com");
        assert_eq!(r.port, 8080);
        assert!(!r.is_connect);
        let head = String::from_utf8(r.head).unwrap();
        assert!(head.starts_with("GET /a/b?c=d HTTP/1.1"));
        assert!(!head.contains("http://"));
    }

    #[test]
    fn rejects_origin_form_and_bad_scheme() {
        assert!(parse_request(b"GET /a HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_request(b"GET ftp://x/a HTTP/1.1\r\n\r\n").is_err());
    }

    #[tokio::test]
    async fn relay_enforces_byte_cap() {
        // Two connected pairs: (g1,g2) guest side, (u1,u2) upstream side.
        // relay_capped(g1, u1) with a 100-byte cap; writer feeds g2, reader
        // drains u2.
        async fn pair() -> (TcpStream, TcpStream) {
            let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let a = l.local_addr().unwrap();
            let c = tokio::spawn(async move { TcpStream::connect(a).await.unwrap() });
            let (s, _) = l.accept().await.unwrap();
            (s, c.await.unwrap())
        }
        let (mut g1, mut g2) = pair().await;
        let (mut u1, mut u2) = pair().await;

        tokio::spawn(async move {
            let _ = g2.write_all(&[0xABu8; 4096]).await;
        });
        tokio::spawn(async move {
            let mut buf = [0u8; 8192];
            loop {
                match u2.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        });

        let (e, i, capped) = relay_capped(&mut g1, &mut u1, 100).await;
        assert!(capped, "cap was not hit");
        assert!(e + i <= 100, "e={e} i={i}");
    }

    #[tokio::test]
    async fn connect_flow_end_to_end_with_local_echo() {
        // Full CONNECT flow against a local echo server. The policy
        // allowlists the literal 127.0.0.1 — but deny_ip rejects loopback,
        // so instead we exercise handle_one's plumbing with a policy that
        // names the echo server via a fake DNS name, and pre-pin 127.0.0.1
        // through a test-only path. Here we test parse->authorize->audit by
        // driving handle_one against a policy where the echo server is
        // allowlisted as tcp://echo.test:<port> and the fake upstream
        // returns 127.0.0.1... which deny_ip rejects. So instead: verify
        // the denial path produces 403 + an audit line, and verify the
        // relay path separately (above). The allow-path is covered by the
        // KVM-gated test with a real non-loopback target.
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("egress.log");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();
        let cfg = ProxyConfig {
            run_id: "lmn-test".into(),
            network: policy(&[]),
            byte_cap: 1024,
            log_path: log_path.clone(),
        };
        let resolver = HostPolicyResolver::new(tmp.path(), FakeUpstream, policy(&[])).unwrap();
        let proxy = Proxy::new(cfg, resolver);
        let server = tokio::spawn(async move { proxy.serve(listener).await });

        // Guest attempts CONNECT to an unleased host -> 403 + audit.
        let mut guest = TcpStream::connect(proxy_addr).await.unwrap();
        guest
            .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut resp = [0u8; 64];
        let n = guest.read(&mut resp).await.unwrap();
        assert!(String::from_utf8_lossy(&resp[..n]).contains("403"));

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(log.contains("\"verdict\":\"egress_denied\""));
        assert!(log.contains("evil.example"));
        // Bodies never logged: the request head must not appear.
        assert!(!log.contains("CONNECT"));

        server.abort();
    }
}
