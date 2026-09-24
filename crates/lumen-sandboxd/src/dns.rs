//! Host policy DNS layer with rebinding defense and address pinning.
//!
//! The guest never talks to upstream DNS. Its `/etc/resolv.conf` points at
//! the per-run [`DnsForwarder`] on the host leg of the veth. The forwarder
//! resolves through [`HostPolicyResolver`]:
//!
//! 1. every returned address is validated ([`crate::network::deny_ip`]):
//!    metadata, private ranges, loopback, multicast, and unspecified
//!    addresses are dropped per the run's deny flags;
//! 2. the surviving set is PINNED for the run (persisted to
//!    `dns_pins.json`); later queries for the same name are answered from
//!    the pin store without re-querying upstream.
//!
//! Step 2 is the DNS-rebinding defense: even if an attacker controls the
//! authoritative server and flips the answer to `169.254.169.254` or an
//! RFC 1918 address mid-run (classic rebinding / SSRF), the guest keeps
//! receiving the originally validated addresses for the rest of the run.
//! TTLs in answers are capped at 60s so a stale pin cannot outlive the run
//! by much even if the guest caches aggressively.

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, UdpSocket},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};

use crate::{error::SandboxdError, network};

/// Upstream resolution. The real implementation uses the host resolver;
/// tests inject scripted answers.
pub trait DnsUpstream: Send + Sync {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, SandboxdError>;
}

/// Host resolver via the OS (`getaddrinfo`). Used by the real forwarder.
pub struct SystemUpstream;

impl DnsUpstream for SystemUpstream {
    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, SandboxdError> {
        // Port 0: we only want address resolution, no connection.
        let addrs: Vec<IpAddr> = std::net::ToSocketAddrs::to_socket_addrs(&(name, 0))
            .map_err(|e| {
                SandboxdError::DnsDenied(format!("upstream resolve failed for {name}: {e}"))
            })?
            .map(|s| s.ip())
            .collect();
        Ok(addrs)
    }
}

/// One pinned name: validated addresses frozen at first resolution.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pin {
    addrs: Vec<IpAddr>,
    pinned_at: u64,
}

/// Persistent per-run pin store.
pub struct PinStore {
    path: PathBuf,
    pins: HashMap<String, Pin>,
}

impl PinStore {
    pub fn open(run_dir: &Path) -> Result<Self, SandboxdError> {
        let path = run_dir.join("dns_pins.json");
        let pins = if path.exists() {
            let text = std::fs::read_to_string(&path).map_err(SandboxdError::Io)?;
            serde_json::from_str(&text).map_err(SandboxdError::Json)?
        } else {
            HashMap::new()
        };
        Ok(Self { path, pins })
    }

    fn save(&self) -> Result<(), SandboxdError> {
        let text = serde_json::to_string_pretty(&self.pins).map_err(SandboxdError::Json)?;
        std::fs::write(&self.path, text).map_err(SandboxdError::Io)?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<Vec<IpAddr>> {
        self.pins.get(name).map(|p| p.addrs.clone())
    }

    pub fn pin(&mut self, name: &str, addrs: Vec<IpAddr>) -> Result<(), SandboxdError> {
        let pinned_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.pins.insert(name.to_string(), Pin { addrs, pinned_at });
        self.save()
    }
}

/// Policy-enforcing resolver with pinning.
pub struct HostPolicyResolver<U: DnsUpstream> {
    pins: PinStore,
    upstream: U,
    policy: crate::contracts::NetworkPolicy,
}

impl<U: DnsUpstream> HostPolicyResolver<U> {
    pub fn new(
        run_dir: &Path,
        upstream: U,
        policy: crate::contracts::NetworkPolicy,
    ) -> Result<Self, SandboxdError> {
        Ok(Self {
            pins: PinStore::open(run_dir)?,
            upstream,
            policy,
        })
    }

    /// Resolve a name to validated, pinned addresses.
    pub fn resolve(&mut self, name: &str) -> Result<Vec<IpAddr>, SandboxdError> {
        let name = Self::normalize_name(name);
        if name.is_empty() || name.len() > 253 {
            return Err(SandboxdError::DnsDenied("bad name".into()));
        }
        // Exfil guard: the query name itself reaches the upstream resolver
        // (and the name's authoritative servers), so only names covered by
        // the run's egress allowlist may be resolved at all — before any
        // pin lookup or upstream query. An unleased name never reaches the
        // upstream.
        if !name_is_leased(&self.policy, &name) {
            return Err(SandboxdError::DnsDenied(format!(
                "name not on egress allowlist: {name}"
            )));
        }
        // Rebinding defense: a pinned name is never re-resolved.
        if let Some(addrs) = self.pins.get(&name) {
            return Ok(addrs);
        }
        let mut valid = Vec::new();
        for ip in self.upstream.resolve(&name)? {
            if network::deny_ip(ip, &self.policy).is_ok() {
                valid.push(ip);
            }
        }
        // Deduplicate, preserving order.
        valid.dedup();
        if valid.is_empty() {
            return Err(SandboxdError::DnsDenied(format!(
                "no acceptable address for {name}"
            )));
        }
        self.pins.pin(&name, valid.clone())?;
        Ok(valid)
    }

    /// Normalize a query name the way `resolve` does.
    fn normalize_name(name: &str) -> String {
        name.trim_end_matches('.').to_ascii_lowercase()
    }

    /// Pin-cache lookup without any I/O. The proxy uses this for its fast
    /// path so the resolver lock is never held across blocking upstream
    /// resolution. Returns `None` for malformed names (the slow path then
    /// fails closed through `resolve`).
    pub fn cached(&self, name: &str) -> Option<Vec<IpAddr>> {
        let name = Self::normalize_name(name);
        if name.is_empty() || name.len() > 253 {
            return None;
        }
        self.pins.get(&name)
    }
}

/// True when `name` is covered by the run's egress allowlist (exact or
/// `*.` wildcard host match). Scheme and port are irrelevant for DNS: if
/// the guest may egress to the host, it may resolve it.
fn name_is_leased(policy: &crate::contracts::NetworkPolicy, name: &str) -> bool {
    policy
        .allow_egress
        .iter()
        .filter_map(|entry| network::parse_destination(entry).ok())
        .any(|dest| network::host_matches(&dest.host, name))
}

// ---------------------------------------------------------------------------
// Minimal DNS wire codec (queries: 1 question, A/AAAA; answers: A/AAAA).
// ---------------------------------------------------------------------------

const FLAG_QR: u16 = 0x8000;
const FLAG_RD: u16 = 0x0100;
const FLAG_RA: u16 = 0x0080;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError = 0,
    FormatError = 1,
    NotImplemented = 4,
    Refused = 5,
}

/// Parse a DNS query. Supports compression pointers in the question name.
pub fn parse_query(buf: &[u8]) -> Result<DnsQuery, Rcode> {
    if buf.len() < 12 {
        return Err(Rcode::FormatError);
    }
    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & FLAG_QR != 0 {
        return Err(Rcode::FormatError); // not a query
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount != 1 {
        return Err(Rcode::FormatError);
    }
    let (name, mut off) = parse_name(buf, 12)?;
    if off + 4 > buf.len() {
        return Err(Rcode::FormatError);
    }
    let qtype = u16::from_be_bytes([buf[off], buf[off + 1]]);
    let qclass = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
    off += 4;
    let _ = off;
    if qclass != 1 {
        return Err(Rcode::NotImplemented);
    }
    Ok(DnsQuery { id, name, qtype })
}

fn parse_name(buf: &[u8], mut off: usize) -> Result<(String, usize), Rcode> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end = off;
    let mut hops = 0;
    loop {
        if off >= buf.len() {
            return Err(Rcode::FormatError);
        }
        let len = buf[off];
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if off + 1 >= buf.len() {
                return Err(Rcode::FormatError);
            }
            if !jumped {
                end = off + 2;
            }
            off = u16::from_be_bytes([len & 0x3F, buf[off + 1]]) as usize;
            jumped = true;
            hops += 1;
            if hops > 16 {
                return Err(Rcode::FormatError);
            }
            continue;
        }
        if len == 0 {
            if !jumped {
                end = off + 1;
            }
            break;
        }
        if len > 63 || off + 1 + len as usize > buf.len() {
            return Err(Rcode::FormatError);
        }
        let label = std::str::from_utf8(&buf[off + 1..off + 1 + len as usize])
            .map_err(|_| Rcode::FormatError)?;
        labels.push(label.to_ascii_lowercase());
        off += 1 + len as usize;
        if labels.len() > 32 {
            return Err(Rcode::FormatError);
        }
    }
    Ok((labels.join("."), end))
}

/// Build a response. `answers` are the addresses to encode (A and/or AAAA
/// records as appropriate for `qtype`); empty + NoError = NODATA.
pub fn build_response(query: &DnsQuery, answers: &[IpAddr], rcode: Rcode, ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&query.id.to_be_bytes());
    let flags = FLAG_QR | FLAG_RD | FLAG_RA | (rcode as u16);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount = answers
        .iter()
        .filter(|ip| matches_qtype(ip, query.qtype))
        .count() as u16;
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(&mut out, &query.name);
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    for ip in answers.iter().filter(|ip| matches_qtype(ip, query.qtype)) {
        out.extend_from_slice(&[0xC0, 0x0C]); // pointer to question name
        let (rtype, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (28, v6.octets().to_vec()),
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

fn matches_qtype(ip: &IpAddr, qtype: u16) -> bool {
    match qtype {
        1 => matches!(ip, IpAddr::V4(_)),
        28 => matches!(ip, IpAddr::V6(_)),
        _ => false,
    }
}

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

/// Per-run DNS forwarder: answers only from the policy resolver, caps TTL,
/// refuses policy-denied names, and rate-limits queries per run.
pub struct DnsForwarder<U: DnsUpstream> {
    socket: UdpSocket,
    resolver: HostPolicyResolver<U>,
    queries_served: u64,
    max_queries: u64,
}

impl<U: DnsUpstream> DnsForwarder<U> {
    pub fn bind(
        bind: SocketAddr,
        run_dir: &Path,
        upstream: U,
        policy: crate::contracts::NetworkPolicy,
    ) -> Result<Self, SandboxdError> {
        let socket = UdpSocket::bind(bind).map_err(SandboxdError::Io)?;
        socket.set_nonblocking(true).map_err(SandboxdError::Io)?;
        Ok(Self {
            socket,
            resolver: HostPolicyResolver::new(run_dir, upstream, policy)?,
            queries_served: 0,
            max_queries: 10_000,
        })
    }

    /// Answer one pending datagram, if any. Returns false when idle.
    pub fn pump_once(&mut self) -> Result<bool, SandboxdError> {
        let mut buf = [0u8; 512];
        let (len, src) = match self.socket.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(SandboxdError::Io(e)),
        };
        let query = match parse_query(&buf[..len]) {
            Ok(q) => q,
            Err(rcode) => {
                // Best-effort error response; we may not even have an id.
                let id = if len >= 2 {
                    u16::from_be_bytes([buf[0], buf[1]])
                } else {
                    0
                };
                let resp = build_response(
                    &DnsQuery {
                        id,
                        name: String::new(),
                        qtype: 1,
                    },
                    &[],
                    rcode,
                    0,
                );
                let _ = self.socket.send_to(&resp, src);
                return Ok(true);
            }
        };

        let resp = if self.queries_served >= self.max_queries {
            build_response(&query, &[], Rcode::Refused, 0)
        } else {
            self.queries_served += 1;
            match query.qtype {
                1 | 28 => match self.resolver.resolve(&query.name) {
                    Ok(addrs) => build_response(&query, &addrs, Rcode::NoError, 60),
                    Err(_) => build_response(&query, &[], Rcode::Refused, 0),
                },
                _ => build_response(&query, &[], Rcode::NotImplemented, 0),
            }
        };
        let _ = self.socket.send_to(&resp, src);
        Ok(true)
    }

    pub fn local_addr(&self) -> Result<SocketAddr, SandboxdError> {
        self.socket.local_addr().map_err(SandboxdError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeUpstream {
        answers: HashMap<String, Vec<IpAddr>>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl FakeUpstream {
        fn new(answers: HashMap<String, Vec<IpAddr>>) -> Self {
            Self {
                answers,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl DnsUpstream for FakeUpstream {
        fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, SandboxdError> {
            self.calls.lock().unwrap().push(name.to_string());
            Ok(self.answers.get(name).cloned().unwrap_or_default())
        }
    }

    fn policy(entries: &[&str]) -> crate::contracts::NetworkPolicy {
        crate::contracts::NetworkPolicy {
            allow_egress: entries.iter().map(|s| s.to_string()).collect(),
            deny_metadata: true,
            deny_private_ranges: true,
        }
    }

    fn encode_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut out = vec![];
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        encode_name(&mut out, name);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    #[test]
    fn codec_roundtrip() {
        let q = encode_query(0x1234, "api.example.com", 1);
        let parsed = parse_query(&q).unwrap();
        assert_eq!(parsed.id, 0x1234);
        assert_eq!(parsed.name, "api.example.com");
        assert_eq!(parsed.qtype, 1);

        let ip: IpAddr = "93.184.216.34".parse().unwrap();
        let resp = build_response(&parsed, &[ip], Rcode::NoError, 60);
        // Spot-check the answer section: pointer, type A, class IN, ttl 60.
        let ans_off = q.len();
        assert_eq!(&resp[ans_off..ans_off + 2], &[0xC0, 0x0C]);
        assert_eq!(&resp[ans_off + 2..ans_off + 4], &[0, 1]);
        assert_eq!(&resp[ans_off + 6..ans_off + 10], &60u32.to_be_bytes());
        assert_eq!(&resp[ans_off + 12..ans_off + 16], &[93, 184, 216, 34]);
    }

    #[test]
    fn metadata_answer_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let mut answers = HashMap::new();
        answers.insert(
            "metadata.attack".into(),
            vec!["169.254.169.254".parse().unwrap()],
        );
        let upstream = FakeUpstream::new(answers);
        let mut r = HostPolicyResolver::new(
            tmp.path(),
            upstream,
            policy(&["https://metadata.attack:443"]),
        )
        .unwrap();
        assert!(r.resolve("metadata.attack").is_err());
    }

    #[test]
    fn private_answer_denied() {
        let tmp = tempfile::tempdir().unwrap();
        let mut answers = HashMap::new();
        answers.insert("db.internal".into(), vec!["10.0.0.5".parse().unwrap()]);
        let upstream = FakeUpstream::new(answers);
        let mut r =
            HostPolicyResolver::new(tmp.path(), upstream, policy(&["https://db.internal:443"]))
                .unwrap();
        assert!(r.resolve("db.internal").is_err());
    }

    #[test]
    fn unleased_name_never_reaches_upstream() {
        // Data-exfil guard: the query name itself reaches the upstream
        // resolver (and the name's authoritative servers), so a name that
        // is not on the egress allowlist must be refused before any
        // upstream query — the upstream must see nothing.
        let tmp = tempfile::tempdir().unwrap();
        let upstream = FakeUpstream::new(HashMap::new());
        let mut r = HostPolicyResolver::new(
            tmp.path(),
            upstream,
            policy(&["https://api.example.com:443"]),
        )
        .unwrap();
        assert!(r.resolve("exfil.attacker.example").is_err());
        assert!(
            r.into_upstream().calls().is_empty(),
            "unleased name reached the upstream resolver"
        );
    }

    #[test]
    fn leased_name_resolves_and_pins() {
        let tmp = tempfile::tempdir().unwrap();
        let good: IpAddr = "93.184.216.34".parse().unwrap();
        let mut answers = HashMap::new();
        answers.insert("api.example.com".into(), vec![good]);
        let upstream = FakeUpstream::new(answers);
        let mut r = HostPolicyResolver::new(
            tmp.path(),
            upstream,
            policy(&["https://api.example.com:443", "https://*.example.net:443"]),
        )
        .unwrap();
        assert_eq!(r.resolve("api.example.com").unwrap(), vec![good]);
        // Second query is answered from the pin store: one upstream call.
        assert_eq!(r.resolve("api.example.com").unwrap(), vec![good]);
        assert_eq!(
            r.into_upstream().calls(),
            vec!["api.example.com".to_string()]
        );
    }

    #[test]
    fn wildcard_lease_covers_subdomain_but_not_bare_domain() {
        let tmp = tempfile::tempdir().unwrap();
        let good: IpAddr = "93.184.216.34".parse().unwrap();
        let mut answers = HashMap::new();
        answers.insert("a.example.net".into(), vec![good]);
        let upstream = FakeUpstream::new(answers);
        let mut r =
            HostPolicyResolver::new(tmp.path(), upstream, policy(&["https://*.example.net:443"]))
                .unwrap();
        assert!(r.resolve("a.example.net").is_ok());
        // The bare domain is not covered by `*.example.net`.
        assert!(r.resolve("example.net").is_err());
        // Only the leased name reached the upstream.
        assert_eq!(r.into_upstream().calls(), vec!["a.example.net".to_string()]);
    }

    #[test]
    fn rebinding_attack_defeated_by_pinning() {
        // Upstream returns a good address, then (attacker flips the zone)
        // a metadata address. The resolver must keep serving the pinned
        // good address and must not re-query.
        let tmp = tempfile::tempdir().unwrap();
        let good: IpAddr = "93.184.216.34".parse().unwrap();
        let evil: IpAddr = "169.254.169.254".parse().unwrap();

        let mut answers = HashMap::new();
        answers.insert("victim.example".into(), vec![good]);
        let upstream = FakeUpstream::new(answers);
        let mut r = HostPolicyResolver::new(
            tmp.path(),
            upstream,
            policy(&["https://victim.example:443"]),
        )
        .unwrap();

        assert_eq!(r.resolve("victim.example").unwrap(), vec![good]);

        // Attacker flips the upstream answer mid-run.
        // (Fresh resolver sharing the same pin dir.)
        let mut answers2 = HashMap::new();
        answers2.insert("victim.example".into(), vec![evil]);
        let upstream2 = FakeUpstream::new(answers2);
        let mut r2 = HostPolicyResolver::new(
            tmp.path(),
            upstream2,
            policy(&["https://victim.example:443"]),
        )
        .unwrap();
        // Pinned good address served; the evil rebind never reaches the guest.
        assert_eq!(r2.resolve("victim.example").unwrap(), vec![good]);
        // And the upstream flip was never even consulted (pin hit first).
        assert!(r2.into_upstream().calls().is_empty());
    }

    impl<U: DnsUpstream> HostPolicyResolver<U> {
        /// Test hook: consume the resolver and return its upstream.
        fn into_upstream(self) -> U {
            self.upstream
        }
    }

    #[test]
    fn pins_survive_resolver_recreation() {
        let tmp = tempfile::tempdir().unwrap();
        let good: IpAddr = "93.184.216.34".parse().unwrap();
        let mut answers = HashMap::new();
        answers.insert("x.example".into(), vec![good]);
        let mut r = HostPolicyResolver::new(
            tmp.path(),
            FakeUpstream::new(answers),
            policy(&["https://x.example:443"]),
        )
        .unwrap();
        r.resolve("x.example").unwrap();
        drop(r);
        let r2 = HostPolicyResolver::new(
            tmp.path(),
            FakeUpstream::new(HashMap::new()),
            policy(&["https://x.example:443"]),
        )
        .unwrap();
        assert_eq!(r2.pins.get("x.example"), Some(vec![good]));
    }
}
