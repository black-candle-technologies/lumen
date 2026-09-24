//! Default-deny egress: per-run network namespace, TAP, veth, nftables.
//!
//! Every run gets its own network namespace. The default is TOTAL
//! isolation: the nftables policy drops everything except loopback. When
//! the run spec names egress destinations, the guest may talk only to:
//!
//! - the host-side DNS forwarder (UDP/TCP 53), which resolves through the
//!   host policy layer ([`crate::dns`]) with rebinding defense and address
//!   pinning, and
//! - the host-side egress proxy ([`crate::proxy`]), which enforces the
//!   typed destination allowlist and logs destination + bytes.
//!
//! Direct egress from the guest never exists in v1: there is no default
//! route and no MASQUERADE. Cloud metadata (169.254.169.254), private
//! ranges, and loopback are denied regardless of the allowlist.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::error::SandboxdError;

/// A typed egress destination from the allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressDestination {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

/// Parse one allowlist entry: `scheme://host[:port]`.
/// Schemes: `https`, `http`, `tcp`. Unknown schemes are rejected.
pub fn parse_destination(entry: &str) -> Result<EgressDestination, SandboxdError> {
    let (scheme, rest) = entry.split_once("://").ok_or_else(|| {
        SandboxdError::EgressDenied(format!(
            "bad destination (need scheme://host[:port]): {entry}"
        ))
    })?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "https" => 443,
        "http" => 80,
        "tcp" => {
            return Err(SandboxdError::EgressDenied(
                "tcp destinations must name an explicit port".into(),
            ));
        }
        _ => {
            return Err(SandboxdError::EgressDenied(format!(
                "unsupported scheme: {scheme}"
            )));
        }
    };
    // Split host/port. Handles `host`, `host:port`, `[::1]:port`.
    let (host, port) = if let Some(rest) = rest.strip_prefix('[') {
        let (ip, after) = rest
            .split_once(']')
            .ok_or_else(|| SandboxdError::EgressDenied(format!("bad destination: {entry}")))?;
        let port = after
            .strip_prefix(':')
            .map(str::parse)
            .transpose()
            .map_err(|_| {
                SandboxdError::EgressDenied(format!("bad port in destination: {entry}"))
            })?;
        (format!("[{ip}]"), port)
    } else {
        match rest.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() => {
                // `host:port`, but a bare IPv6 literal without brackets is
                // ambiguous — reject it and require brackets.
                if h.contains(':') {
                    return Err(SandboxdError::EgressDenied(format!(
                        "bare IPv6 literal must use brackets: {entry}"
                    )));
                }
                let port: u16 = p.parse().map_err(|_| {
                    SandboxdError::EgressDenied(format!("bad port in destination: {entry}"))
                })?;
                (h.to_string(), Some(port))
            }
            _ => {
                if rest.ends_with(':') {
                    return Err(SandboxdError::EgressDenied(format!(
                        "bad destination (trailing colon): {entry}"
                    )));
                }
                (rest.to_string(), None)
            }
        }
    };
    if host.is_empty() {
        return Err(SandboxdError::EgressDenied(format!(
            "empty host in destination: {entry}"
        )));
    }
    Ok(EgressDestination {
        scheme,
        host: host.to_ascii_lowercase(),
        port: port.unwrap_or(default_port),
    })
}

/// Authorize one egress attempt against the run's [`NetworkPolicy`].
///
/// Fail-closed rules:
/// - IP literals are rejected unless they appear literally in the
///   allowlist AND pass the deny flags (metadata/private/loopback always
///   lose to the deny flags);
/// - DNS names must match an allowlist entry exactly, or as a `*.` suffix
///   wildcard with a full label boundary; bare `*` is rejected;
/// - scheme and port must match the entry.
pub fn check_destination(
    policy: &crate::contracts::NetworkPolicy,
    scheme: &str,
    host: &str,
    port: u16,
) -> Result<EgressDestination, SandboxdError> {
    let host = host.to_ascii_lowercase();
    let scheme = scheme.to_ascii_lowercase();

    // The deny flags always win, even for explicitly listed hosts.
    if let Ok(ip) = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<IpAddr>()
    {
        deny_ip(ip, policy)?;
    }

    for entry in &policy.allow_egress {
        let dest = parse_destination(entry)?;
        if dest.scheme != scheme || dest.port != port {
            continue;
        }
        if host_matches(&dest.host, &host) {
            // If the allowlist entry itself is an IP literal, re-apply the
            // deny flags to it (belt and suspenders).
            if let Ok(ip) = dest
                .host
                .trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
            {
                deny_ip(ip, policy)?;
            }
            return Ok(EgressDestination { scheme, host, port });
        }
    }
    Err(SandboxdError::EgressDenied(format!(
        "no allowlist entry for {scheme}://{host}:{port}"
    )))
}

fn host_matches(pattern: &str, host: &str) -> bool {
    if pattern == host {
        return true;
    }
    // Suffix wildcard: `*.example.com` matches `a.example.com` but not
    // `example.com` itself and not `badexample.com`.
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host.len() > suffix.len()
            && host.ends_with(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    false
}

/// Apply the always-enforced deny flags to a literal IP.
pub fn deny_ip(ip: IpAddr, policy: &crate::contracts::NetworkPolicy) -> Result<(), SandboxdError> {
    if is_metadata_ip(ip) && policy.deny_metadata {
        return Err(SandboxdError::EgressDenied(format!(
            "cloud metadata address denied: {ip}"
        )));
    }
    if is_private_ip(ip) && policy.deny_private_ranges {
        return Err(SandboxdError::EgressDenied(format!(
            "private range address denied: {ip}"
        )));
    }
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Err(SandboxdError::EgressDenied(format!(
            "non-routable address denied: {ip}"
        )));
    }
    Ok(())
}

/// 169.254.169.254 — the cloud metadata endpoint. (The whole 169.254/16
/// is link-local; the metadata address specifically is the exfil target.)
pub fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets() == [169, 254, 169, 254],
        IpAddr::V6(_) => false,
    }
}

/// RFC 1918 + ULA. (Loopback/link-local/multicast handled separately.)
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10 || (o[0] == 172 && (16..32).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
        }
        IpAddr::V6(v6) => (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Per-run L3 plan: one /30 carved from the pod CIDR.
#[derive(Debug, Clone)]
pub struct NetPlan {
    pub netns_name: String,
    pub tap_name: String,
    pub veth_host: String,
    pub veth_guest: String,
    /// Host side (DNS forwarder + proxy bind), e.g. `10.244.0.1`.
    pub host_ip: String,
    /// Guest side, e.g. `10.244.0.2`.
    pub guest_ip: String,
    pub prefix_len: u8,
    pub proxy_port: u16,
}

pub fn plan_net(
    tag: &str,
    pod_cidr: &str,
    slot: u32,
    proxy_port: u16,
    tap_prefix: &str,
    netns_prefix: &str,
) -> Result<NetPlan, SandboxdError> {
    let (base, _) = pod_cidr
        .split_once('/')
        .ok_or_else(|| SandboxdError::State(format!("bad pod_cidr: {pod_cidr}")))?;
    let base_ip: IpAddr = base
        .parse()
        .map_err(|_| SandboxdError::State(format!("bad pod_cidr: {pod_cidr}")))?;
    let IpAddr::V4(base_v4) = base_ip else {
        return Err(SandboxdError::State("pod_cidr must be IPv4".into()));
    };
    let base_u32 = u32::from(base_v4);
    // One /30 per run: network = base + slot*4; .1 host, .2 guest.
    let net = base_u32
        .checked_add(
            slot.checked_mul(4)
                .ok_or_else(|| SandboxdError::State("pod slot overflow".into()))?,
        )
        .ok_or_else(|| SandboxdError::State("pod slot overflow".into()))?;
    let host_ip = std::net::Ipv4Addr::from(net + 1).to_string();
    let guest_ip = std::net::Ipv4Addr::from(net + 2).to_string();
    Ok(NetPlan {
        netns_name: format!("{netns_prefix}{tag}"),
        tap_name: format!("{tap_prefix}{tag}"),
        veth_host: format!("lmvh-{tag}"),
        veth_guest: format!("lmvg-{tag}"),
        host_ip,
        guest_ip,
        prefix_len: 30,
        proxy_port,
    })
}

/// Render the nftables script applied inside the run's netns. Default-drop
/// on input/output/forward; the guest can reach only the DNS forwarder and
/// the egress proxy on the host leg of the veth.
pub fn render_nftables(plan: &NetPlan) -> String {
    format!(
        r#"table inet lumen {{
    chain input {{
        type filter hook input priority 0; policy drop;
        iif "lo" accept
        ct state established,related accept
    }}
    chain output {{
        type filter hook output priority 0; policy drop;
        oif "lo" accept
        ip daddr {host} udp dport 53 accept
        ip daddr {host} tcp dport 53 accept
        ip daddr {host} tcp dport {proxy} accept
        ct state established,related accept
        # Host-side proxy/DNS tasks (daemon, uid 0) may egress upstream.
        # The guest VM's packets never carry a host UID, so this does not
        # open any path for the guest.
        meta skuid 0 accept
    }}
    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}
}}
"#,
        host = plan.host_ip,
        proxy = plan.proxy_port,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::NetworkPolicy;

    fn policy(entries: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            allow_egress: entries.iter().map(|s| s.to_string()).collect(),
            deny_metadata: true,
            deny_private_ranges: true,
        }
    }

    #[test]
    fn parse_destination_ok() {
        let d = parse_destination("https://api.example.com:8443").unwrap();
        assert_eq!(
            d,
            EgressDestination {
                scheme: "https".into(),
                host: "api.example.com".into(),
                port: 8443
            }
        );
        let d = parse_destination("https://api.example.com").unwrap();
        assert_eq!(d.port, 443);
        let d = parse_destination("http://x.test").unwrap();
        assert_eq!(d.port, 80);
    }

    #[test]
    fn parse_destination_rejects() {
        assert!(parse_destination("api.example.com").is_err());
        assert!(parse_destination("ftp://x.test").is_err());
        assert!(parse_destination("tcp://x.test").is_err()); // needs port
        assert!(parse_destination("https://").is_err());
        assert!(parse_destination("https://::1").is_err()); // bare v6
        assert!(parse_destination("https://[::1]:443").is_ok());
    }

    #[test]
    fn allowlisted_destination_passes() {
        let p = policy(&["https://api.example.com:443"]);
        let d = check_destination(&p, "https", "api.example.com", 443).unwrap();
        assert_eq!(d.host, "api.example.com");
    }

    #[test]
    fn redirect_to_unleased_host_blocked() {
        // The plan's adversarial case: the guest follows a redirect to a
        // host that is not on the allowlist.
        let p = policy(&["https://api.example.com:443"]);
        assert!(check_destination(&p, "https", "evil.example.net", 443).is_err());
        // Wrong scheme / port also denied.
        assert!(check_destination(&p, "http", "api.example.com", 443).is_err());
        assert!(check_destination(&p, "https", "api.example.com", 8443).is_err());
    }

    #[test]
    fn empty_allowlist_denies_everything() {
        let p = policy(&[]);
        assert!(check_destination(&p, "https", "api.example.com", 443).is_err());
    }

    #[test]
    fn metadata_and_private_denied_even_when_listed() {
        let p = policy(&[
            "https://169.254.169.254:80",
            "https://10.0.0.5:443",
            "https://192.168.1.1:443",
            "https://127.0.0.1:8080",
        ]);
        // The deny flags always win over the allowlist.
        assert!(check_destination(&p, "https", "169.254.169.254", 80).is_err());
        assert!(check_destination(&p, "https", "10.0.0.5", 443).is_err());
        assert!(check_destination(&p, "https", "192.168.1.1", 443).is_err());
        assert!(check_destination(&p, "https", "127.0.0.1", 8080).is_err());
    }

    #[test]
    fn wildcard_matching_has_label_boundary() {
        let p = policy(&["https://*.example.com:443"]);
        assert!(check_destination(&p, "https", "a.example.com", 443).is_ok());
        assert!(check_destination(&p, "https", "a.b.example.com", 443).is_ok());
        // No match on the bare domain or on a partial label.
        assert!(check_destination(&p, "https", "example.com", 443).is_err());
        assert!(check_destination(&p, "https", "notexample.com", 443).is_err());
        assert!(check_destination(&p, "https", "badexample.com", 443).is_err());
    }

    #[test]
    fn nftables_is_default_drop() {
        let plan = plan_net("abc1234", "10.244.0.0/16", 7, 18080, "lmnt-", "lmn-").unwrap();
        assert_eq!(plan.host_ip, "10.244.0.29");
        assert_eq!(plan.guest_ip, "10.244.0.30");
        let nft = render_nftables(&plan);
        assert!(nft.contains("policy drop"));
        // Only DNS + proxy to the host leg are open.
        assert!(nft.contains("udp dport 53 accept"));
        assert!(nft.contains("tcp dport 18080 accept"));
        assert!(!nft.contains("masquerade"));
    }

    #[test]
    fn ip_classification() {
        assert!(is_metadata_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_metadata_ip("169.254.169.253".parse().unwrap()));
        assert!(is_private_ip("10.1.2.3".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.0.1".parse().unwrap()));
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("172.15.0.1".parse().unwrap()));
    }
}
