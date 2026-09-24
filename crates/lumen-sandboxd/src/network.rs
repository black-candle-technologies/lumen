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
//! route and no MASQUERADE. Cloud metadata (169.254.169.254) and every
//! non-globally-reachable address (private, link-local, shared/CGNAT,
//! reserved, documentation, loopback) are denied regardless of the
//! allowlist — deny-by-default, with globally-reachable unicast as the
//! only permitted class.

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
///
/// Scope model — what the proxy can actually enforce:
/// - `http` / `https`: absolute-form requests (`GET https://host/path`).
///   The proxy rewrites to origin-form and forwards the plaintext bytes;
///   it never terminates or validates TLS, so an `https` lease is
///   host:port authority over the forwarded stream, not a TLS guarantee.
/// - `tcp`: `CONNECT host:port` tunnels. CONNECT carries no scheme, so a
///   tunnel is authorized against `tcp` scope for that host:port only.
///   An `https://host` lease does NOT authorize a CONNECT tunnel — scope
///   narrowing is exact (design invariant 3).
pub fn parse_destination(entry: &str) -> Result<EgressDestination, SandboxdError> {
    let (scheme, rest) = entry.split_once("://").ok_or_else(|| {
        SandboxdError::EgressDenied(format!(
            "bad destination (need scheme://host[:port]): {entry}"
        ))
    })?;
    let scheme = scheme.to_ascii_lowercase();
    // `tcp` has no default port: a tcp-scope entry must name one explicitly.
    let default_port: Option<u16> = match scheme.as_str() {
        "https" => Some(443),
        "http" => Some(80),
        "tcp" => None,
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
    let port = match (port, default_port) {
        (Some(p), _) => p,
        (None, Some(d)) => d,
        (None, None) => {
            return Err(SandboxdError::EgressDenied(
                "tcp destinations must name an explicit port".into(),
            ));
        }
    };
    Ok(EgressDestination {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
    })
}

/// Authorize one egress attempt against the run's [`NetworkPolicy`].
///
/// Fail-closed rules:
/// - IP literals are rejected unless they appear literally in the
///   allowlist AND pass the deny flags (metadata/non-global/loopback
///   always lose to the deny flags);
/// - DNS names must match an allowlist entry exactly, or as a `*.` suffix
///   wildcard with a full label boundary; bare `*` is rejected;
/// - scheme and port must match the entry. In particular a `tcp`-scheme
///   request (i.e. a CONNECT tunnel) never matches an `https` entry.
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

pub(crate) fn host_matches(pattern: &str, host: &str) -> bool {
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
///
/// Fail-closed ordering:
/// - loopback, unspecified, and multicast are never valid egress targets,
///   regardless of the allowlist or the deny flags;
/// - the cloud metadata address is denied when `deny_metadata` holds;
/// - when `deny_private_ranges` holds, the predicate is deny-by-default:
///   only globally-reachable unicast ([`is_global_unicast`]) may be dialed.
///   Every other class — link-local, shared/CGNAT, reserved, documentation,
///   benchmarking, protocol-assignment — is denied even if allowlisted.
pub fn deny_ip(ip: IpAddr, policy: &crate::contracts::NetworkPolicy) -> Result<(), SandboxdError> {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Err(SandboxdError::EgressDenied(format!(
            "non-routable address denied: {ip}"
        )));
    }
    if is_metadata_ip(ip) && policy.deny_metadata {
        return Err(SandboxdError::EgressDenied(format!(
            "cloud metadata address denied: {ip}"
        )));
    }
    if policy.deny_private_ranges && !is_global_unicast(ip) {
        return Err(SandboxdError::EgressDenied(format!(
            "non-global address denied: {ip}"
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

/// True only for globally-reachable unicast addresses.
///
/// Deny-by-default: every IANA special-purpose range (RFC 6890 / RFC 8190)
/// that is not globally reachable is excluded — private, loopback,
/// link-local, shared/CGNAT, reserved, documentation, benchmarking,
/// transition mechanisms (6to4, Teredo), NAT64 local-use, SRv6 SIDs, and
/// protocol-assignment space, plus multicast. IPv4-mapped IPv6 addresses
/// (`::ffff:a.b.c.d`) are judged by their inner IPv4 address, so the
/// mapping cannot smuggle a non-global address past the check.
///
/// Note on `2001::/23` (IETF Protocol Assignments): the registry marks it
/// not globally reachable *unless allowed by a more specific allocation*
/// (RFC 8190 footnote), and large parts of it ARE globally routed
/// (e.g. `2001:4860::/32`). Excluding the whole /23 would deny legitimate
/// global unicast, so only its non-global sub-prefixes are excluded.
pub fn is_global_unicast(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(
                o[0] == 0 // 0.0.0.0/8 — "this network" (RFC 1122)
                || o[0] == 10 // 10.0.0.0/8 — private (RFC 1918)
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40) // 100.64.0.0/10 — shared/CGNAT (RFC 6598)
                || o[0] == 127 // 127.0.0.0/8 — loopback (RFC 1122)
                || (o[0] == 169 && o[1] == 254) // 169.254.0.0/16 — link-local (RFC 3927)
                || (o[0] == 172 && (16..32).contains(&o[1])) // 172.16.0.0/12 — private (RFC 1918)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 — IETF assignments (RFC 6890)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24 — TEST-NET-1 (RFC 5737)
                || (o[0] == 192 && o[1] == 31 && o[2] == 196) // 192.31.196.0/24 — AS112 (RFC 7535)
                || (o[0] == 192 && o[1] == 52 && o[2] == 193) // 192.52.193.0/24 — AMT (RFC 7450)
                || (o[0] == 192 && o[1] == 88 && o[2] == 99) // 192.88.99.0/24 — deprecated 6to4 relay (RFC 7526)
                || (o[0] == 192 && o[1] == 168) // 192.168.0.0/16 — private (RFC 1918)
                || (o[0] == 192 && o[1] == 175 && o[2] == 48) // 192.175.48.0/24 — AS112 direct (RFC 7535)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 — benchmarking (RFC 2544)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24 — TEST-NET-2 (RFC 5737)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24 — TEST-NET-3 (RFC 5737)
                || (o[0] & 0xf0) == 0xe0 // 224.0.0.0/4 — multicast (RFC 5771)
                || (o[0] & 0xf0) == 0xf0
                // 240.0.0.0/4 — reserved (RFC 1112)
            )
        }
        IpAddr::V6(v6) => {
            // Judge IPv4-mapped addresses by their inner IPv4 address.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_global_unicast(IpAddr::V4(v4));
            }
            let s = v6.segments();
            !(
                v6.is_unspecified() // ::/128
                || v6.is_loopback() // ::1/128
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0 && s[3] == 0 && s[4] == 0 && s[5] == 0) // 64:ff9b::/96 — NAT64 WKP (RFC 6052)
                || (s[0] == 0x0064 && s[1] == 0xff9b && s[2] == 0x0001) // 64:ff9b:1::/48 — NAT64 local-use (RFC 8219)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0) // 100::/64 — discard (RFC 6666)
                || (s[0] == 0x0100 && s[1] == 0 && s[2] == 0 && s[3] == 0x0001) // 100:0:0:1::/64 — dummy prefix (RFC 9780)
                || (s[0] == 0x2001 && s[1] == 0x0db8) // 2001:db8::/32 — documentation (RFC 3849)
                || (s[0] == 0x2001 && s[1] == 0x0000) // 2001::/32 — Teredo (RFC 4380); embeds an IPv4 address
                || (s[0] == 0x2001 && s[1] == 0x0002 && s[2] == 0x0000) // 2001:2::/48 — benchmarking (RFC 5180)
                || (s[0] == 0x2001 && (s[1] & 0xfff0) == 0x0010) // 2001:10::/28 — ORCHID, deprecated (RFC 4843)
                || s[0] == 0x2002 // 2002::/16 — 6to4 (RFC 3056); embeds an IPv4 address
                || (s[0] == 0x3fff && (s[1] & 0xf000) == 0) // 3fff::/20 — documentation (RFC 9637)
                || s[0] == 0x5f00 // 5f00::/16 — SRv6 SIDs (RFC 9602)
                || (s[0] & 0xfe00) == 0xfc00 // fc00::/7 — unique-local (RFC 4193)
                || (s[0] & 0xffc0) == 0xfe80 // fe80::/10 — link-local (RFC 4291)
                || (s[0] & 0xffc0) == 0xfec0 // fec0::/10 — site-local, deprecated (RFC 3879)
                || (s[0] & 0xff00) == 0xff00
                // ff00::/8 — multicast (RFC 4291)
            )
        }
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
    let (base, prefix_len) = pod_cidr
        .split_once('/')
        .ok_or_else(|| SandboxdError::State(format!("bad pod_cidr: {pod_cidr}")))?;
    let prefix_len: u8 = prefix_len
        .parse()
        .map_err(|_| SandboxdError::State(format!("bad pod_cidr: {pod_cidr}")))?;
    // A /30 is carved per run, so the pod prefix must be /30 or shorter.
    if prefix_len > 30 {
        return Err(SandboxdError::State(format!(
            "pod_cidr prefix /{prefix_len} cannot hold a /30"
        )));
    }
    let base_ip: IpAddr = base
        .parse()
        .map_err(|_| SandboxdError::State(format!("bad pod_cidr: {pod_cidr}")))?;
    let IpAddr::V4(base_v4) = base_ip else {
        return Err(SandboxdError::State("pod_cidr must be IPv4".into()));
    };
    let base_u32 = u32::from(base_v4);
    // The base must be the aligned network address: an unaligned base
    // would let slots overlap each other or escape the CIDR.
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    if base_u32 & !mask != 0 {
        return Err(SandboxdError::State(format!(
            "pod_cidr base {base} is not aligned to /{prefix_len}"
        )));
    }
    // One /30 per run: slot * 4 addresses. Bounding the slot to the
    // prefix's /30 count keeps every carved address inside the CIDR and
    // makes net+1 / net+2 overflow-impossible.
    let slots = 1u32 << (30 - prefix_len);
    if slot >= slots {
        return Err(SandboxdError::State(format!(
            "pod slot {slot} outside pod_cidr {pod_cidr}"
        )));
    }
    // One /30 per run: network = base + slot*4; .1 host, .2 guest.
    // The slot bound above guarantees these cannot overflow; the checked
    // arithmetic fails closed regardless.
    let net = base_u32
        .checked_add(
            slot.checked_mul(4)
                .ok_or_else(|| SandboxdError::State("pod slot overflow".into()))?,
        )
        .ok_or_else(|| SandboxdError::State("pod slot overflow".into()))?;
    let host_ip = std::net::Ipv4Addr::from(
        net.checked_add(1)
            .ok_or_else(|| SandboxdError::State("pod slot overflow".into()))?,
    )
    .to_string();
    let guest_ip = std::net::Ipv4Addr::from(
        net.checked_add(2)
            .ok_or_else(|| SandboxdError::State("pod slot overflow".into()))?,
    )
    .to_string();
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
        # Guest -> host DNS/proxy. The TAP and the host leg are bridged,
        # so guest traffic traverses this chain (via br_netfilter); only
        # the allowlisted flows pass.
        ip daddr {host} udp dport 53 accept
        ip daddr {host} tcp dport 53 accept
        ip daddr {host} tcp dport {proxy} accept
        ct state established,related accept
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
        // tcp has no default port, but an explicit port is expressible —
        // this is the scope CONNECT tunnels are authorized against.
        let d = parse_destination("tcp://x.test:443").unwrap();
        assert_eq!(
            d,
            EgressDestination {
                scheme: "tcp".into(),
                host: "x.test".into(),
                port: 443
            }
        );
    }

    #[test]
    fn parse_destination_rejects() {
        assert!(parse_destination("api.example.com").is_err());
        assert!(parse_destination("ftp://x.test").is_err());
        assert!(parse_destination("tcp://x.test").is_err()); // needs explicit port
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
    fn plan_net_validates_slot_against_prefix() {
        // The finding's case: with 10.244.0.0/16, slot 16384 used to
        // produce 10.245.0.1/10.245.0.2 — outside the pod CIDR.
        assert!(plan_net("t", "10.244.0.0/16", 16384, 18080, "lmnt-", "lmn-").is_err());
        assert!(plan_net("t", "10.244.0.0/16", u32::MAX, 18080, "lmnt-", "lmn-").is_err());
        // Last valid slot of the /16 stays inside.
        let plan = plan_net("t", "10.244.0.0/16", 16383, 18080, "lmnt-", "lmn-").unwrap();
        assert_eq!(plan.host_ip, "10.244.255.253");
        assert_eq!(plan.guest_ip, "10.244.255.254");
        // A /30 holds exactly one slot.
        let plan = plan_net("t", "10.244.0.0/30", 0, 18080, "lmnt-", "lmn-").unwrap();
        assert_eq!(plan.host_ip, "10.244.0.1");
        assert_eq!(plan.guest_ip, "10.244.0.2");
        assert!(plan_net("t", "10.244.0.0/30", 1, 18080, "lmnt-", "lmn-").is_err());
    }

    #[test]
    fn plan_net_rejects_unaligned_base_and_bad_prefix() {
        // Unaligned base: slots would overlap or escape the CIDR.
        assert!(plan_net("t", "10.244.0.1/16", 0, 18080, "lmnt-", "lmn-").is_err());
        assert!(plan_net("t", "10.244.0.5/24", 0, 18080, "lmnt-", "lmn-").is_err());
        // No room for a /30.
        assert!(plan_net("t", "10.244.0.0/31", 0, 18080, "lmnt-", "lmn-").is_err());
        assert!(plan_net("t", "10.244.0.0/32", 0, 18080, "lmnt-", "lmn-").is_err());
        // Not IPv4 / malformed.
        assert!(plan_net("t", "fd00::/64", 0, 18080, "lmnt-", "lmn-").is_err());
        assert!(plan_net("t", "10.244.0.0", 0, 18080, "lmnt-", "lmn-").is_err());
        assert!(plan_net("t", "10.244.0.0/xx", 0, 18080, "lmnt-", "lmn-").is_err());
    }

    #[test]
    fn plan_net_cannot_overflow_near_u32_max() {
        // Top of the address space: the last /30 of 255.255.255.0/24.
        // net+1/net+2 must not panic (debug) or wrap (release).
        let plan = plan_net("t", "255.255.255.0/24", 63, 18080, "lmnt-", "lmn-").unwrap();
        assert_eq!(plan.host_ip, "255.255.255.253");
        assert_eq!(plan.guest_ip, "255.255.255.254");
        assert!(plan_net("t", "255.255.255.0/24", 64, 18080, "lmnt-", "lmn-").is_err());
    }

    #[test]
    fn metadata_ip_detection() {
        assert!(is_metadata_ip("169.254.169.254".parse().unwrap()));
        assert!(!is_metadata_ip("169.254.169.253".parse().unwrap()));
    }

    #[test]
    fn global_unicast_predicate_is_deny_by_default() {
        // (address, expected is_global_unicast). Every IANA
        // special-purpose range must be excluded; boundary addresses on
        // both sides of each range are covered.
        let cases: &[(&str, bool)] = &[
            // Allowed: globally reachable unicast, incl. range boundaries.
            ("8.8.8.8", true),
            ("1.1.1.1", true),
            ("93.184.216.34", true),
            ("9.255.255.255", true),   // below 10/8
            ("11.0.0.1", true),        // above 10/8
            ("100.63.255.255", true),  // below 100.64/10
            ("100.128.0.1", true),     // above 100.64/10
            ("172.15.255.255", true),  // below 172.16/12
            ("172.32.0.1", true),      // above 172.16/12
            ("192.167.255.255", true), // below 192.168/16
            ("192.169.0.1", true),     // above 192.168/16
            ("198.17.255.255", true),  // below 198.18/15
            ("198.20.0.1", true),      // above 198.18/15
            ("223.255.255.255", true), // below 224/4
            // Denied IPv4: every listed non-global class.
            ("0.0.0.0", false),         // 0/8
            ("0.255.255.255", false),   // 0/8
            ("10.0.0.1", false),        // 10/8
            ("10.255.255.255", false),  // 10/8
            ("100.64.0.1", false),      // 100.64/10
            ("100.127.255.254", false), // 100.64/10
            ("127.0.0.1", false),       // 127/8
            ("127.255.255.255", false), // 127/8
            ("169.254.0.1", false),     // 169.254/16
            ("169.254.169.254", false), // 169.254/16 (metadata)
            ("169.254.255.255", false), // 169.254/16
            ("172.16.0.1", false),      // 172.16/12
            ("172.31.255.255", false),  // 172.16/12
            ("192.0.0.1", false),       // 192.0.0.0/24
            ("192.0.2.1", false),       // 192.0.2.0/24 TEST-NET-1
            ("192.168.0.1", false),     // 192.168/16
            ("192.168.255.255", false), // 192.168/16
            ("198.18.0.1", false),      // 198.18.0.0/15
            ("198.19.255.255", false),  // 198.18.0.0/15
            ("198.51.100.7", false),    // 198.51.100.0/24 TEST-NET-2
            ("203.0.113.9", false),     // 203.0.113.0/24 TEST-NET-3
            ("224.0.0.1", false),       // 224/4 multicast
            ("239.255.255.255", false), // 224/4 multicast
            ("240.0.0.1", false),       // 240/4 reserved
            ("255.255.255.255", false), // 240/4 reserved
            // Allowed IPv6.
            ("2606:4700:4700::1111", true),
            ("2001:4860:4860::8888", true),
            ("::ffff:8.8.8.8", true), // v4-mapped global
            // Denied IPv6.
            ("::", false),                                   // unspecified
            ("::1", false),                                  // loopback
            ("fe80::1", false),                              // fe80::/10
            ("febf::1234", false),                           // fe80::/10 top edge
            ("fc00::1", false),                              // fc00::/7
            ("fd12:3456::1", false),                         // fc00::/7
            ("fec0::1", false),                              // fec0::/10 deprecated site-local
            ("ff02::1", false),                              // ff00::/8 multicast
            ("2001:db8::1", false),                          // documentation
            ("2002:0a00:0001::1", false),                    // 2002::/16 6to4 wrapping 10.0.0.1
            ("2002:c000:0201::1", false),                    // 2002::/16 6to4 wrapping 192.0.2.1
            ("2001:0:ce49:7601:e866:efff:62c3:fffe", false), // 2001::/32 Teredo
            ("2001:2::1", false),                            // 2001:2::/48 benchmarking
            ("2001:10::1", false),                           // 2001:10::/28 deprecated ORCHID
            ("64:ff9b:1::c000:201", false),                  // 64:ff9b:1::/48 NAT64 local-use
            ("3fff::1", false),                              // 3fff::/20 documentation
            ("3fff:0fff::1", false),                         // 3fff::/20 top edge
            ("5f00::1", false),                              // 5f00::/16 SRv6 SIDs
            ("100:0:0:1::1", false),                         // 100:0:0:1::/64 dummy prefix
            ("::ffff:10.0.0.1", false),                      // v4-mapped private
            ("::ffff:169.254.169.254", false),               // v4-mapped link-local/metadata
            // Still allowed: inside 2001::/23 but globally routed by a more
            // specific allocation (RFC 8190: "unless allowed by a more
            // specific allocation"), and just outside 3fff::/20.
            ("3fff:1000::1", true),
        ];
        for (addr, want) in cases {
            let ip: IpAddr = addr.parse().unwrap();
            assert_eq!(is_global_unicast(ip), *want, "is_global_unicast({addr})");
        }
    }

    #[test]
    fn deny_ip_rejects_non_global_when_private_egress_disabled() {
        let strict = policy(&[]); // deny_private_ranges: true
        // The adversarial case: link-local, shared, reserved and
        // documentation ranges are denied even though they are not
        // RFC1918/ULA — and even if allowlisted.
        for addr in [
            "169.254.10.20",
            "100.64.0.5",
            "192.0.0.7",
            "192.0.2.44",
            "198.18.3.3",
            "198.51.100.9",
            "203.0.113.2",
            "240.1.2.3",
            "224.0.0.9",
            "fe80::5",
            "2001:db8::9",
        ] {
            let ip: IpAddr = addr.parse().unwrap();
            assert!(deny_ip(ip, &strict).is_err(), "deny_ip({addr})");
            // The deny flags beat the allowlist: explicitly listing the
            // address must not open it.
            let entry = if addr.contains(':') {
                format!("https://[{addr}]:443")
            } else {
                format!("https://{addr}:443")
            };
            let listed = policy(&[entry.as_str()]);
            assert!(
                check_destination(&listed, "https", addr, 443).is_err(),
                "allowlisted non-global {addr} must still be denied"
            );
        }
        assert!(deny_ip("8.8.8.8".parse().unwrap(), &strict).is_ok());
        assert!(deny_ip("2606:4700:4700::1111".parse().unwrap(), &strict).is_ok());
    }

    #[test]
    fn deny_ip_allows_non_global_when_flag_off_but_never_loopback() {
        let permissive = NetworkPolicy {
            allow_egress: vec![],
            deny_metadata: false,
            deny_private_ranges: false,
        };
        // With private egress explicitly allowed, non-global addresses pass
        // the range check.
        assert!(deny_ip("10.1.2.3".parse().unwrap(), &permissive).is_ok());
        assert!(deny_ip("169.254.10.20".parse().unwrap(), &permissive).is_ok());
        assert!(deny_ip("100.64.0.5".parse().unwrap(), &permissive).is_ok());
        // Loopback / unspecified / multicast are never valid egress
        // targets, regardless of the flags.
        assert!(deny_ip("127.0.0.1".parse().unwrap(), &permissive).is_err());
        assert!(deny_ip("::1".parse().unwrap(), &permissive).is_err());
        assert!(deny_ip("0.0.0.0".parse().unwrap(), &permissive).is_err());
        assert!(deny_ip("224.0.0.1".parse().unwrap(), &permissive).is_err());
        assert!(deny_ip("ff02::1".parse().unwrap(), &permissive).is_err());
    }
}
