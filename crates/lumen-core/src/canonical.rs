//! Canonical resources (Phase 1A): typed, canonicalized identifiers for every
//! resource dimension a lease can name.
//!
//! The kernel never compares raw strings across the trust boundary. Every
//! resource is parsed into a typed value, normalized into a canonical form,
//! and only canonical forms are compared. Subset checks are structural
//! (component-wise, range containment, set inclusion) — never string-prefix
//! tests, which are trivially fooled (`/data` vs `/database`).
//!
//! # Fail-closed rules
//!
//! * Paths: must resolve through the [`PathResolver`] (symlinks, `.`/`..`,
//!   mounts) to an absolute physical path. Unresolvable input is rejected,
//!   not passed through.
//! * Network: DNS names and IP ranges are distinct types and never compare
//!   equal. Ambiguous wildcards (`*`, `*.*`, `*.tld`) are rejected.
//! * If two scopes cannot be compared safely, the subset proof fails.

#[cfg(test)]
use std::collections::HashMap;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, io,
    net::IpAddr,
    path::{Component, Path, PathBuf},
    sync::LazyLock,
};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use semver::{Version, VersionReq};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::pi_boundary::canonical_digest;

/// Errors from resource canonicalization. Every variant fails closed: the
/// caller must treat the resource as unusable, never as "close enough".
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CanonicalError {
    #[error("empty resource")]
    Empty,
    #[error("resource too long")]
    TooLong,
    #[error("invalid characters in resource: {0}")]
    BadChars(String),
    #[error("path is not absolute: {0}")]
    NotAbsolute(String),
    #[error("path could not be resolved: {0}")]
    Unresolvable(String),
    #[error("path escapes its root via traversal: {0}")]
    Traversal(String),
    #[error("invalid tool name: {0}")]
    BadToolName(String),
    #[error("invalid version: {0}")]
    BadVersion(String),
    #[error("invalid network destination: {0}")]
    BadDestination(String),
    #[error("ambiguous wildcard rejected: {0}")]
    AmbiguousWildcard(String),
    #[error("DNS names and IP ranges are not comparable")]
    DnsIpMix,
    #[error("invalid port: {0}")]
    BadPort(String),
    #[error("invalid secret reference")]
    BadSecretRef,
    #[error("invalid account reference: {0}")]
    BadAccountRef(String),
    #[error("invalid model class: {0}")]
    BadModelClass(String),
    #[error("resource types are not comparable")]
    Incomparable,
    #[error("io error resolving path: {0}")]
    Io(String),
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// A validated tool name: lowercase alphanumerics separated by single dots,
/// e.g. `fs.read`. Versions are pinned separately (floating versions never
/// cross the trust boundary).
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ToolName(String);

impl ToolName {
    pub fn parse(value: &str) -> Result<Self, CanonicalError> {
        if value.is_empty() {
            return Err(CanonicalError::Empty);
        }
        if value.len() > 128 {
            return Err(CanonicalError::TooLong);
        }
        let ok = value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'_')
            && !value.starts_with('.')
            && !value.ends_with('.')
            && !value.contains("..");
        if !ok {
            return Err(CanonicalError::BadToolName(value.to_string()));
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Canonical form: the validated name itself.
    pub fn canonical_form(&self) -> String {
        format!("tool:{}", self.0)
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A scope entry for one tool: the parent lease's allowed version requirement.
/// Children must pin an exact version that satisfies the parent requirement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolGrant {
    pub name: ToolName,
    pub allowed: VersionReq,
}

impl ToolGrant {
    /// Structural subset: the child grant is narrower iff it names the same
    /// tool and every version the child allows is also allowed by the parent.
    ///
    /// In practice children pin exact versions (`=1.2.3`), so this reduces to
    /// "child's pinned version satisfies the parent requirement". The general
    /// case is decided conservatively: child ⊆ parent iff the child's
    /// requirement is syntactically at least as restrictive, verified by
    /// probing — we require the child to be an exact pin and test it against
    /// the parent requirement. Non-pinned child requirements fail closed.
    pub fn is_subset_of(&self, parent: &ToolGrant) -> Result<(), CanonicalError> {
        if self.name != parent.name {
            return Err(CanonicalError::Incomparable);
        }
        // Extract the child's pinned version, if it is a single exact pin.
        let pinned = exact_pin(&self.allowed).ok_or_else(|| {
            CanonicalError::BadVersion(format!(
                "child tool grant for {} must pin an exact version",
                self.name
            ))
        })?;
        if parent.allowed.matches(&pinned) {
            Ok(())
        } else {
            Err(CanonicalError::BadVersion(format!(
                "version {} not allowed by parent requirement {}",
                pinned, parent.allowed
            )))
        }
    }

    pub fn allows(&self, version: &Version) -> bool {
        self.allowed.matches(version)
    }
}

/// If `req` is exactly `=x.y.z`, return the pinned version.
fn exact_pin(req: &VersionReq) -> Option<Version> {
    let s = req.to_string();
    let pinned = s.strip_prefix('=')?;
    // Reject compound requirements.
    if pinned.contains(',') || pinned.contains(' ') || pinned.contains("||") {
        return None;
    }
    Version::parse(pinned).ok()
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// How symlinks (and `.`/`..`) are resolved before comparison. The kernel
/// uses [`RealFsResolver`] in production and a fake in tests.
///
/// Contract: `resolve` returns the fully canonical absolute path with all
/// symlinks, `.`, and `..` resolved — `..` is processed *against* symlink
/// resolution (component by component, as the OS does), not folded lexically
/// afterwards. Lexical folding after resolution is wrong: if `/w/data` is a
/// symlink to `/etc`, then `/w/data/../data` resolves to `/data`, not
/// `/w/data`. [`CanonicalPath::parse`] rejects any result that still contains
/// `.`/`..` or is not absolute (fail closed on resolver contract violation).
pub trait PathResolver: Send + Sync {
    fn resolve(&self, path: &Path) -> io::Result<PathBuf>;
}

/// Resolves against the real filesystem (`std::fs::canonicalize`).
#[derive(Clone, Copy, Debug, Default)]
pub struct RealFsResolver;

impl PathResolver for RealFsResolver {
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        std::fs::canonicalize(path)
    }
}

/// A canonical filesystem path: absolute, symlink-resolved, `.`/`..`-free,
/// stored as components. Comparison is component-wise — never a string
/// prefix test.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CanonicalPath {
    /// Resolved components below the root, e.g. `["workspace", "src"]`.
    components: Vec<String>,
    /// Whether comparison folded case (case-insensitive filesystem view).
    case_folded: bool,
}

impl CanonicalPath {
    /// Canonicalize `input` through `resolver`.
    ///
    /// * `case_insensitive`: the filesystem view folds case (macOS/Windows).
    ///   Components are lowercased and `case_folded` is set, so equality and
    ///   prefix tests are performed on the folded form.
    pub fn parse(
        input: &str,
        resolver: &dyn PathResolver,
        case_insensitive: bool,
    ) -> Result<Self, CanonicalError> {
        if input.is_empty() {
            return Err(CanonicalError::Empty);
        }
        if input.len() > 4096 {
            return Err(CanonicalError::TooLong);
        }
        if input.bytes().any(|b| b == 0 || (b < 0x20 && b != b'\t')) {
            return Err(CanonicalError::BadChars(input.to_string()));
        }
        let raw = Path::new(input);
        if !raw.is_absolute() {
            return Err(CanonicalError::NotAbsolute(input.to_string()));
        }
        let resolved = resolver
            .resolve(raw)
            .map_err(|e| CanonicalError::Unresolvable(format!("{input}: {e}")))?;
        if !resolved.is_absolute() {
            return Err(CanonicalError::NotAbsolute(resolved.display().to_string()));
        }
        let mut components = Vec::new();
        for comp in resolved.components() {
            match comp {
                Component::RootDir | Component::Prefix(_) => {}
                Component::CurDir => {}
                Component::ParentDir => {
                    // canonicalize() must never return `..`; a resolver that
                    // does is broken — fail closed.
                    return Err(CanonicalError::Traversal(resolved.display().to_string()));
                }
                Component::Normal(seg) => {
                    let s = seg.to_string_lossy();
                    if s.is_empty() {
                        return Err(CanonicalError::BadChars(input.to_string()));
                    }
                    components.push(if case_insensitive {
                        s.to_lowercase()
                    } else {
                        s.into_owned()
                    });
                }
            }
        }
        Ok(Self {
            components,
            case_folded: case_insensitive,
        })
    }

    /// `true` iff `self` is at or below `root`, compared component-wise.
    /// A path is within a root only on a strict component boundary, so
    /// `/database` is never "within" `/data`.
    pub fn is_within(&self, root: &CanonicalPath) -> bool {
        if self.case_folded != root.case_folded {
            // Different filesystem views cannot be compared safely.
            return false;
        }
        if self.components.len() < root.components.len() {
            return false;
        }
        self.components[..root.components.len()] == root.components[..]
    }

    /// Canonical encoding: `/`-joined components with a leading slash.
    pub fn canonical_form(&self) -> String {
        let mut s = String::from("/");
        s.push_str(&self.components.join("/"));
        if self.case_folded {
            s.push_str("~fold");
        }
        s
    }

    pub fn components(&self) -> &[String] {
        &self.components
    }
}

/// Read/write rights on a path grant, as an explicit pair (not a bitmask
/// string) so subset is structural.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PathRights {
    pub read: bool,
    pub write: bool,
}

impl PathRights {
    pub const READ: Self = Self {
        read: true,
        write: false,
    };
    pub const READ_WRITE: Self = Self {
        read: true,
        write: true,
    };
    pub const WRITE: Self = Self {
        read: false,
        write: true,
    };

    pub fn is_subset_of(self, parent: Self) -> bool {
        (!self.read || parent.read) && (!self.write || parent.write)
    }
}

/// One path grant: a canonical root plus rights. A child grant narrows a
/// parent grant iff the child root is within the parent root (component-wise)
/// and the child rights are a subset of the parent rights.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathGrant {
    pub root: CanonicalPath,
    pub rights: PathRights,
}

impl PathGrant {
    /// Find a parent grant covering `child`, if any.
    pub fn covering<'a>(
        child: &PathGrant,
        parents: &'a [PathGrant],
    ) -> Result<&'a PathGrant, CanonicalError> {
        parents
            .iter()
            .find(|p| child.root.is_within(&p.root) && child.rights.is_subset_of(p.rights))
            .ok_or(CanonicalError::Incomparable)
    }
}

// ---------------------------------------------------------------------------
// Network destinations
// ---------------------------------------------------------------------------

/// A normalized host: DNS names and IP ranges are distinct variants and
/// never compare equal to each other.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum HostPattern {
    /// Lowercased DNS name, no trailing dot, IDNA-encoded.
    DnsName(String),
    /// `*.example.com`, stored as the suffix `example.com`. Never matches the
    /// apex itself.
    DnsWildcard(String),
    Ip(IpAddr),
    IpRange(IpNet),
}

impl HostPattern {
    pub fn parse(value: &str) -> Result<Self, CanonicalError> {
        if value.is_empty() {
            return Err(CanonicalError::Empty);
        }
        if value.len() > 253 {
            return Err(CanonicalError::TooLong);
        }
        if let Some(suffix) = value.strip_prefix("*.") {
            return Self::parse_wildcard(suffix);
        }
        if value.contains('*') {
            return Err(CanonicalError::AmbiguousWildcard(value.to_string()));
        }
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Ok(net) = value.parse::<IpNet>() {
            // A bare IP parses as a /32 or /128; keep the Ip variant for it so
            // canonical forms stay distinct and stable.
            if net.prefix_len() == net.max_prefix_len() {
                return Ok(Self::Ip(net.addr()));
            }
            return Ok(Self::IpRange(net));
        }
        Self::parse_dns(value)
    }

    fn parse_dns(value: &str) -> Result<Self, CanonicalError> {
        let lower = value.to_lowercase();
        let trimmed = lower.strip_suffix('.').unwrap_or(&lower);
        if trimmed.is_empty() || trimmed.len() > 253 {
            return Err(CanonicalError::BadDestination(value.to_string()));
        }
        // Encode via the url crate for IDNA/punycode handling.
        let probe = format!("http://{trimmed}/");
        let url =
            Url::parse(&probe).map_err(|_| CanonicalError::BadDestination(value.to_string()))?;
        let host = url
            .host_str()
            .ok_or_else(|| CanonicalError::BadDestination(value.to_string()))?;
        // url crate rejects IP-looking hosts here only if parse failed above;
        // a successful DNS parse that yields an IP means the input was an IP.
        if host.parse::<IpAddr>().is_ok() {
            return Err(CanonicalError::BadDestination(value.to_string()));
        }
        Ok(Self::DnsName(host.to_string()))
    }

    fn parse_wildcard(suffix: &str) -> Result<Self, CanonicalError> {
        if suffix.is_empty() || suffix == "*" || suffix.contains('*') {
            return Err(CanonicalError::AmbiguousWildcard(format!("*.{suffix}")));
        }
        // The suffix must contain at least two labels: `*.example.com` is
        // allowed, `*.com` is ambiguous and rejected.
        let labels: Vec<&str> = suffix.split('.').collect();
        if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
            return Err(CanonicalError::AmbiguousWildcard(format!("*.{suffix}")));
        }
        match Self::parse_dns(suffix)? {
            Self::DnsName(name) => Ok(Self::DnsWildcard(name)),
            _ => Err(CanonicalError::AmbiguousWildcard(format!("*.{suffix}"))),
        }
    }

    /// Structural subset: is `self` (child) covered by `parent`?
    pub fn is_subset_of(&self, parent: &HostPattern) -> Result<(), CanonicalError> {
        match (self, parent) {
            (Self::DnsName(c), Self::DnsName(p)) => {
                if c == p {
                    Ok(())
                } else {
                    Err(CanonicalError::Incomparable)
                }
            }
            (Self::DnsName(c), Self::DnsWildcard(p)) => {
                // `api.example.com` ⊆ `*.example.com`: exactly one label may
                // precede the suffix. The apex `example.com` itself is NOT
                // covered by its own wildcard.
                let covered = c
                    .strip_suffix(p.as_str())
                    .and_then(|rest| rest.strip_suffix('.'))
                    .is_some_and(|label| !label.is_empty() && !label.contains('.'));
                if covered {
                    Ok(())
                } else {
                    Err(CanonicalError::Incomparable)
                }
            }
            (Self::DnsWildcard(c), Self::DnsWildcard(p)) => {
                // Strict single-label semantics: `*.example.com` covers exactly
                // the names with one label under `example.com`. A deeper
                // pattern like `*.sub.example.com` covers `x.sub.example.com`,
                // which `*.example.com` does NOT cover — so pattern ⊆ pattern
                // only when the suffixes are identical. Fail closed.
                if c == p {
                    Ok(())
                } else {
                    Err(CanonicalError::Incomparable)
                }
            }
            (Self::Ip(c), Self::Ip(p)) => {
                if c == p {
                    Ok(())
                } else {
                    Err(CanonicalError::Incomparable)
                }
            }
            (Self::Ip(c), Self::IpRange(p)) => {
                if p.contains(c) {
                    Ok(())
                } else {
                    Err(CanonicalError::Incomparable)
                }
            }
            (Self::IpRange(c), Self::IpRange(p)) => {
                if p.contains(&c.network()) && p.prefix_len() <= c.prefix_len() {
                    Ok(())
                } else {
                    Err(CanonicalError::Incomparable)
                }
            }
            // DNS names never match IP ranges and vice versa: the kernel does
            // not resolve DNS at comparison time (TOCTOU), so the two live in
            // separate namespaces, fail closed.
            _ => Err(CanonicalError::DnsIpMix),
        }
    }

    /// Classify private/loopback/link-local networks. Used by policy, not by
    /// the subset proof itself.
    ///
    /// An [`HostPattern::IpRange`] is classified by its
    /// least-trusted possible address: a range that merely *contains* a
    /// loopback, private, or otherwise restricted address is reported as
    /// that class, so a spanning CIDR such as `0.0.0.0/0` can never be
    /// mistaken for [`NetworkClass::Public`].
    pub fn network_class(&self) -> NetworkClass {
        match self {
            Self::DnsName(_) | Self::DnsWildcard(_) => NetworkClass::Dns,
            Self::Ip(ip) => classify_ip(*ip),
            Self::IpRange(net) => classify_net(*net),
        }
    }

    pub fn canonical_form(&self) -> String {
        match self {
            Self::DnsName(n) => format!("dns:{n}"),
            Self::DnsWildcard(s) => format!("dnswild:*.{s}"),
            Self::Ip(ip) => format!("ip:{ip}"),
            Self::IpRange(net) => format!("iprange:{net}"),
        }
    }
}

/// Coarse network classification for policy decisions.
///
/// [`NetworkClass::Restricted`] covers addresses that must never be treated
/// as ordinary public *or* private space: unspecified (`0.0.0.0/8`, `::`),
/// limited broadcast (`255.255.255.255`), reserved Class E (`240.0.0.0/4`),
/// and documentation/benchmark ranges. Policy checks must deny `Restricted`
/// alongside the other non-public classes — it is not a weaker form of
/// `Public`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkClass {
    Dns,
    Public,
    Private,
    Loopback,
    LinkLocal,
    Multicast,
    Restricted,
}

/// Fail-closed single-address classification: special-purpose ranges are
/// recognized before the `Public` fallback, and IPv4-mapped IPv6 addresses
/// are classified by their embedded IPv4 address (so `::ffff:10.0.0.1` is
/// `Private`, not `Public`).
fn classify_ip(ip: IpAddr) -> NetworkClass {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 0 {
                // 0.0.0.0/8: "this network" (RFC 1122). Many clients treat
                // 0.0.0.0 as localhost — never Public.
                NetworkClass::Restricted
            } else if v4.is_broadcast() {
                NetworkClass::Restricted
            } else if o[0] == 127 {
                NetworkClass::Loopback
            } else if o[0] == 10
                || (o[0] == 172 && (16..32).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || (o[0] == 100 && (64..128).contains(&o[1]))
            {
                // The last arm is RFC 6598 shared/CGNAT space: not globally
                // routable, so it classifies with private space.
                NetworkClass::Private
            } else if o[0] == 169 && o[1] == 254 {
                NetworkClass::LinkLocal
            } else if o[0] >= 224 && o[0] < 240 {
                NetworkClass::Multicast
            } else if o[0] >= 240
                || (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
                || (o[0] == 198 && (18..20).contains(&o[1]))
            {
                // 240.0.0.0/4 (reserved Class E), TEST-NET-1/2/3
                // (documentation), 198.18.0.0/15 (benchmarking): none of
                // these is routable public space.
                NetworkClass::Restricted
            } else {
                NetworkClass::Public
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                NetworkClass::Restricted
            } else if v6.is_loopback() {
                NetworkClass::Loopback
            } else if let Some(v4) = v6.to_ipv4_mapped() {
                // ::ffff:0:0/96 — classify the embedded IPv4 address.
                classify_ip(IpAddr::V4(v4))
            } else if v6.segments()[..6] == [0, 0, 0, 0, 0, 0] {
                // Deprecated IPv4-compatible ::/96 range (RFC 4291 §2.5.5.1):
                // :: and ::1 were handled above; the rest is not public.
                NetworkClass::Restricted
            } else if v6.is_multicast() {
                NetworkClass::Multicast
            } else {
                let seg = v6.segments();
                if (seg[0] & 0xfe00) == 0xfc00 {
                    NetworkClass::Private
                } else if (seg[0] & 0xffc0) == 0xfe80 {
                    NetworkClass::LinkLocal
                } else if seg[0] == 0x2001 && seg[1] == 0x0db8 {
                    // 2001:db8::/32 documentation range.
                    NetworkClass::Restricted
                } else {
                    NetworkClass::Public
                }
            }
        }
    }
}

/// Special-purpose ranges, ordered most-restricted first. [`classify_net`]
/// returns the class of the first overlapping entry, so a spanning range
/// (e.g. `0.0.0.0/0`) is classified by its least-trusted possible address.
static SPECIAL_NETS: LazyLock<Vec<(IpNet, NetworkClass)>> = LazyLock::new(|| {
    let mut table = Vec::new();
    let mut add = |cidr: &str, class: NetworkClass| {
        table.push((cidr.parse::<IpNet>().expect("static CIDR parses"), class));
    };
    add("127.0.0.0/8", NetworkClass::Loopback);
    add("::1/128", NetworkClass::Loopback);
    // The whole IPv4 space embedded as ::ffff:0:0/96: its least-trusted
    // address is loopback (::ffff:127.0.0.1).
    add("::ffff:0:0/96", NetworkClass::Loopback);
    add("0.0.0.0/8", NetworkClass::Restricted);
    add("::/128", NetworkClass::Restricted);
    add("255.255.255.255/32", NetworkClass::Restricted);
    add("240.0.0.0/4", NetworkClass::Restricted);
    add("192.0.2.0/24", NetworkClass::Restricted);
    add("198.51.100.0/24", NetworkClass::Restricted);
    add("203.0.113.0/24", NetworkClass::Restricted);
    add("198.18.0.0/15", NetworkClass::Restricted);
    add("2001:db8::/32", NetworkClass::Restricted);
    add("10.0.0.0/8", NetworkClass::Private);
    add("172.16.0.0/12", NetworkClass::Private);
    add("192.168.0.0/16", NetworkClass::Private);
    add("100.64.0.0/10", NetworkClass::Private);
    add("fc00::/7", NetworkClass::Private);
    add("169.254.0.0/16", NetworkClass::LinkLocal);
    add("fe80::/10", NetworkClass::LinkLocal);
    add("224.0.0.0/4", NetworkClass::Multicast);
    add("ff00::/8", NetworkClass::Multicast);
    table
});

/// Two CIDR ranges overlap iff one contains the other's network address
/// (prefixes are aligned, so this is exact).
fn nets_overlap(a: IpNet, b: IpNet) -> bool {
    match (a, b) {
        (IpNet::V4(a4), IpNet::V4(b4)) => a4.contains(&b4.network()) || b4.contains(&a4.network()),
        (IpNet::V6(a6), IpNet::V6(b6)) => a6.contains(&b6.network()) || b6.contains(&a6.network()),
        _ => false,
    }
}

/// If the whole IPv6 range sits inside `::ffff:0:0/96`, map it into IPv4
/// space so it classifies by its embedded addresses (e.g.
/// `::ffff:10.0.0.0/104` → `10.0.0.0/8` → `Private`).
fn unwrap_mapped_range(net: Ipv6Net) -> Option<Ipv4Net> {
    if net.prefix_len() < 96 {
        return None;
    }
    let lo = net.network().to_ipv4_mapped()?;
    // Both endpoints map (checked via `lo` and the broadcast below), so the
    // aligned range is fully inside ::ffff:0:0/96.
    let _ = net.broadcast().to_ipv4_mapped()?;
    Ipv4Net::new(lo, net.prefix_len() - 96).ok()
}

/// Fail-closed range classification: the range's class is the class of its
/// least-trusted possible address. A range that merely *contains* a
/// loopback, private, link-local, multicast, or restricted address is
/// reported as that class — it can never be mistaken for `Public`.
fn classify_net(net: IpNet) -> NetworkClass {
    let net = match net {
        IpNet::V6(v6) => unwrap_mapped_range(v6)
            .map(IpNet::V4)
            .unwrap_or(IpNet::V6(v6)),
        v4 => v4,
    };
    for (special, class) in SPECIAL_NETS.iter() {
        if nets_overlap(net, *special) {
            return *class;
        }
    }
    classify_ip(net.addr())
}

/// A set of ports, normalized to sorted non-overlapping ranges.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortSet {
    /// Sorted, non-overlapping, non-adjacent ranges.
    ranges: Vec<(u16, u16)>,
    /// Explicit "any port" grant. Only ⊆ itself.
    any: bool,
}

impl PortSet {
    pub fn any() -> Self {
        Self {
            ranges: vec![],
            any: true,
        }
    }

    pub fn single(port: u16) -> Self {
        Self {
            ranges: vec![(port, port)],
            any: false,
        }
    }

    pub fn range(start: u16, end: u16) -> Result<Self, CanonicalError> {
        if start > end {
            return Err(CanonicalError::BadPort(format!("{start}-{end}")));
        }
        Ok(Self {
            ranges: vec![(start, end)],
            any: false,
        })
    }

    pub fn from_ports(ports: &[u16]) -> Self {
        let mut sorted: Vec<u16> = ports.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for p in sorted {
            match ranges.last_mut() {
                Some(last) if last.1.wrapping_add(1) == p => last.1 = p,
                _ => ranges.push((p, p)),
            }
        }
        Self { ranges, any: false }
    }

    /// Build from `(start, end)` ranges without expanding them into
    /// individual ports. Ranges are sorted, validated, and merged
    /// (adjacent ranges coalesce), so the result is normalized exactly
    /// like [`Self::from_ports`].
    pub fn from_ranges(ranges: &[(u16, u16)]) -> Result<Self, CanonicalError> {
        let mut sorted: Vec<(u16, u16)> = ranges.to_vec();
        for (start, end) in &sorted {
            if start > end {
                return Err(CanonicalError::BadPort(format!("{start}-{end}")));
            }
        }
        sorted.sort_unstable();
        let mut merged: Vec<(u16, u16)> = Vec::new();
        for (start, end) in sorted {
            match merged.last_mut() {
                Some(last) if start <= last.1.wrapping_add(1) => {
                    last.1 = last.1.max(end);
                }
                _ => merged.push((start, end)),
            }
        }
        Ok(Self {
            ranges: merged,
            any: false,
        })
    }

    pub fn contains(&self, port: u16) -> bool {
        self.any || self.ranges.iter().any(|(s, e)| *s <= port && port <= *e)
    }

    /// Structural subset: every child range must be fully covered by parent
    /// ranges. `any` is only a subset of `any`.
    pub fn is_subset_of(&self, parent: &PortSet) -> bool {
        if self.any {
            return parent.any;
        }
        if parent.any {
            return true;
        }
        self.ranges
            .iter()
            .all(|(cs, ce)| parent.ranges.iter().any(|(ps, pe)| ps <= cs && ce <= pe))
    }

    pub fn canonical_form(&self) -> String {
        if self.any {
            return "ports:*".to_string();
        }
        let parts: Vec<String> = self
            .ranges
            .iter()
            .map(|(s, e)| {
                if s == e {
                    s.to_string()
                } else {
                    format!("{s}-{e}")
                }
            })
            .collect();
        format!("ports:{}", parts.join(","))
    }
}

/// A network destination grant: scheme + host pattern + ports + (for
/// HTTP-like schemes) methods.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDestination {
    /// Lowercased scheme, e.g. `https`. Empty means "any scheme" only when
    /// constructed via [`NetworkDestination::any_scheme`] — parsing requires
    /// an explicit scheme.
    pub scheme: String,
    pub host: HostPattern,
    pub ports: PortSet,
    /// Uppercased HTTP methods. Only meaningful for http/https/ws/wss;
    /// ignored otherwise. Empty means *unrestricted* (any method): an
    /// unrestricted child is only covered by an unrestricted parent.
    pub methods: BTreeSet<String>,
}

impl NetworkDestination {
    /// Parse `scheme://host[:port][/...]` with optional method allowlist.
    /// The default port for a known scheme may be omitted or given explicitly;
    /// both canonicalize identically.
    pub fn parse(input: &str, methods: &[&str]) -> Result<Self, CanonicalError> {
        let url =
            Url::parse(input).map_err(|_| CanonicalError::BadDestination(input.to_string()))?;
        let scheme = url.scheme().to_lowercase();
        if scheme.is_empty() {
            return Err(CanonicalError::BadDestination(input.to_string()));
        }
        // Use the typed host: `host_str()` returns IPv6 literals with
        // brackets (`[::1]`), which would misparse as a DNS name and hide
        // loopback/private literals from `network_class()` and the subset
        // proof.
        let host = match url.host() {
            Some(url::Host::Ipv4(v4)) => HostPattern::Ip(IpAddr::V4(v4)),
            Some(url::Host::Ipv6(v6)) => HostPattern::Ip(IpAddr::V6(v6)),
            Some(url::Host::Domain(d)) => HostPattern::parse(d)
                .map_err(|_| CanonicalError::BadDestination(input.to_string()))?,
            None => return Err(CanonicalError::BadDestination(input.to_string())),
        };
        let port = url.port_or_known_default().ok_or_else(|| {
            CanonicalError::BadDestination(format!(
                "{input}: unknown scheme, explicit port required"
            ))
        })?;
        let methods = methods
            .iter()
            .map(|m| m.to_uppercase())
            .collect::<BTreeSet<_>>();
        Ok(Self {
            scheme,
            host,
            ports: PortSet::single(port),
            methods,
        })
    }

    fn methods_apply(&self) -> bool {
        matches!(self.scheme.as_str(), "http" | "https" | "ws" | "wss")
    }

    /// Inverse of [`Self::canonical_form`]: decode a `net:` canonical string
    /// back into a destination. Fails closed on any malformed input.
    ///
    /// The standing-lease mint uses this — the URL parser ([`Self::parse`])
    /// rejects canonical `net:` strings outright, and even where it parsed
    /// it would drop the approved port set and method allowlist the human
    /// actually approved.
    pub fn parse_canonical_form(input: &str) -> Result<Self, CanonicalError> {
        let bad = || CanonicalError::BadDestination(input.to_string());
        let rest = input.strip_prefix("net:").ok_or_else(bad)?;
        let (scheme, rest) = rest.split_once("://").ok_or_else(bad)?;
        // URI scheme syntax (RFC 3986 §3.1); the encoder lowercases, so the
        // decoder requires the canonical lowercase spelling.
        let mut scheme_bytes = scheme.bytes();
        match scheme_bytes.next() {
            Some(b) if b.is_ascii_lowercase() => {}
            _ => return Err(bad()),
        }
        if !scheme_bytes.all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'-' | b'.')
        }) {
            return Err(bad());
        }
        // The host form is `{kind}:{value}` where kind selects how far the
        // value extends: DNS names never contain ':', but IPv6 literals do,
        // so ip:/iprange: values run to the `:ports:` marker instead.
        let (kind, after_kind) = rest.split_once(':').ok_or_else(bad)?;
        let (host_value, rest) = match kind {
            "dns" | "dnswild" => after_kind.split_once(':').ok_or_else(bad)?,
            "ip" | "iprange" => {
                let idx = after_kind.find(":ports:").ok_or_else(bad)?;
                (&after_kind[..idx], &after_kind[idx + 1..])
            }
            _ => return Err(bad()),
        };
        let host = Self::parse_canonical_host(kind, host_value, input)?;
        let ports_and_methods = rest.strip_prefix("ports:").ok_or_else(bad)?;
        let (ports_list, methods_list) = match ports_and_methods.split_once(':') {
            Some((ports, methods)) => (ports, Some(methods)),
            None => (ports_and_methods, None),
        };
        let ports = Self::parse_canonical_ports(ports_list, input)?;
        let methods = match methods_list {
            None => BTreeSet::new(),
            Some(list) => {
                // The encoder only emits a method allowlist for HTTP-family
                // schemes; anything else is not encoder output.
                if !matches!(scheme, "http" | "https" | "ws" | "wss") {
                    return Err(bad());
                }
                let mut set = BTreeSet::new();
                for method in list.split(',') {
                    // Canonical spelling: the encoder uppercases method
                    // tokens (RFC 9110 `token`, restricted to the uppercase
                    // spelling the encoder emits), so the decoder requires
                    // the same. Anything else is not encoder output.
                    if method.is_empty() || !Self::is_canonical_method(method) {
                        return Err(bad());
                    }
                    set.insert(method.to_string());
                }
                set
            }
        };
        let decoded = Self {
            scheme: scheme.to_string(),
            host,
            ports,
            methods,
        };
        // Strict canonicity: the decoded destination must re-encode to the
        // exact input bytes. This catches any structural ambiguity the
        // segment parsing missed and guarantees the mint reproduces the
        // port set and method allowlist the human approved — nothing
        // dropped, nothing invented.
        if decoded.canonical_form() != input {
            return Err(bad());
        }
        Ok(decoded)
    }

    /// Uppercase RFC 9110 `token` characters — the canonical method
    /// spelling the encoder emits (`to_uppercase()` on the allowlist).
    fn is_canonical_method(method: &str) -> bool {
        method
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || Self::is_method_tchar(b))
    }

    /// RFC 9110 `tchar` punctuation (the encoder uppercases letters, so the
    /// canonical spelling keeps only the symbol half here).
    fn is_method_tchar(b: u8) -> bool {
        matches!(
            b,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
    }

    /// Decode the `{kind}:{value}` host segment of a canonical destination.
    /// The kind tag must agree with what the value parses as — `dns:1.2.3.4`
    /// is rejected because the encoder would have emitted `ip:1.2.3.4`.
    fn parse_canonical_host(
        kind: &str,
        value: &str,
        input: &str,
    ) -> Result<HostPattern, CanonicalError> {
        let bad = || CanonicalError::BadDestination(input.to_string());
        match kind {
            "dns" => match HostPattern::parse(value) {
                Ok(HostPattern::DnsName(name)) => Ok(HostPattern::DnsName(name)),
                _ => Err(bad()),
            },
            "dnswild" => {
                let suffix = value.strip_prefix("*.").ok_or_else(bad)?;
                match HostPattern::parse(suffix) {
                    Ok(HostPattern::DnsName(name)) => Ok(HostPattern::DnsWildcard(name)),
                    _ => Err(bad()),
                }
            }
            "ip" => value
                .parse::<IpAddr>()
                .map(HostPattern::Ip)
                .map_err(|_| bad()),
            "iprange" => value
                .parse::<IpNet>()
                .map(HostPattern::IpRange)
                .map_err(|_| bad()),
            _ => Err(bad()),
        }
    }

    /// Decode the `ports:*` / `ports:80,443,8000-9000` segment of a
    /// canonical destination. Ranges are decoded as ranges — never expanded
    /// into individual ports.
    fn parse_canonical_ports(ports_list: &str, input: &str) -> Result<PortSet, CanonicalError> {
        let bad = || CanonicalError::BadDestination(input.to_string());
        if ports_list == "*" {
            return Ok(PortSet::any());
        }
        let mut ranges: Vec<(u16, u16)> = Vec::new();
        for part in ports_list.split(',') {
            if part.is_empty() {
                return Err(bad());
            }
            match part.split_once('-') {
                Some((start, end)) => {
                    let start: u16 = start.parse().map_err(|_| bad())?;
                    let end: u16 = end.parse().map_err(|_| bad())?;
                    if start > end {
                        return Err(bad());
                    }
                    ranges.push((start, end));
                }
                None => {
                    let port: u16 = part.parse().map_err(|_| bad())?;
                    ranges.push((port, port));
                }
            }
        }
        if ranges.is_empty() {
            return Err(bad());
        }
        PortSet::from_ranges(&ranges).map_err(|_| bad())
    }

    /// Structural subset: same scheme (or parent any-scheme), host covered,
    /// ports covered, methods covered (when applicable).
    pub fn is_subset_of(&self, parent: &NetworkDestination) -> Result<(), CanonicalError> {
        if !parent.scheme.is_empty() && self.scheme != parent.scheme {
            return Err(CanonicalError::Incomparable);
        }
        self.host.is_subset_of(&parent.host)?;
        if !self.ports.is_subset_of(&parent.ports) {
            return Err(CanonicalError::Incomparable);
        }
        if self.methods_apply() && parent.methods_apply() {
            // An empty method set is the unrestricted set, not the empty
            // set: a child that may use any method is only covered by a
            // parent that also allows any method. A restricted child is
            // covered by an unrestricted parent or a parent whose allowlist
            // is a superset.
            let covered = if self.methods.is_empty() {
                parent.methods.is_empty()
            } else {
                parent.methods.is_empty() || self.methods.is_subset(&parent.methods)
            };
            if !covered {
                return Err(CanonicalError::Incomparable);
            }
        }
        Ok(())
    }

    pub fn canonical_form(&self) -> String {
        let mut s = format!(
            "net:{}://{}:{}",
            self.scheme,
            self.host.canonical_form(),
            self.ports.canonical_form()
        );
        if self.methods_apply() && !self.methods.is_empty() {
            let mut m: Vec<&String> = self.methods.iter().collect();
            m.sort();
            s.push_str(&format!(
                ":{}",
                m.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(",")
            ));
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Secrets, accounts, models
// ---------------------------------------------------------------------------

/// An opaque secret reference (never the secret itself). Validated charset;
/// subset is set inclusion on the validated string.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretRef(String);

impl SecretRef {
    pub fn parse(value: &str) -> Result<Self, CanonicalError> {
        if value.is_empty() {
            return Err(CanonicalError::Empty);
        }
        if value.len() > 256 {
            return Err(CanonicalError::TooLong);
        }
        let ok = value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:/-".contains(&b));
        if !ok {
            return Err(CanonicalError::BadSecretRef);
        }
        Ok(Self(value.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn canonical_form(&self) -> String {
        format!("secret:{}", self.0)
    }
}

/// A typed external account: provider plus the provider's account identity.
/// Distinct providers never compare equal.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct AccountRef {
    pub provider: String,
    pub account_id: String,
}

impl AccountRef {
    pub fn parse(provider: &str, account_id: &str) -> Result<Self, CanonicalError> {
        for (v, name) in [(provider, "provider"), (account_id, "account id")] {
            if v.is_empty() {
                return Err(CanonicalError::Empty);
            }
            if v.len() > 256 {
                return Err(CanonicalError::TooLong);
            }
            let ok = v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:-@".contains(&b));
            if !ok {
                return Err(CanonicalError::BadAccountRef(format!("{name}: {v}")));
            }
        }
        Ok(Self {
            provider: provider.to_lowercase(),
            account_id: account_id.to_string(),
        })
    }

    pub fn canonical_form(&self) -> String {
        format!("account:{}:{}", self.provider, self.account_id)
    }
}

/// A permitted model/provider class, e.g. provider `openai-compatible`,
/// class `local`. Subset is per-provider set inclusion on classes.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ModelClass {
    pub provider: String,
    pub class: String,
}

impl ModelClass {
    pub fn parse(provider: &str, class: &str) -> Result<Self, CanonicalError> {
        for (v, what) in [(provider, "provider"), (class, "class")] {
            if v.is_empty() {
                return Err(CanonicalError::Empty);
            }
            if v.len() > 128 {
                return Err(CanonicalError::TooLong);
            }
            let ok = v
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
            if !ok {
                return Err(CanonicalError::BadModelClass(format!("{what}: {v}")));
            }
        }
        Ok(Self {
            provider: provider.to_string(),
            class: class.to_string(),
        })
    }

    pub fn canonical_form(&self) -> String {
        format!("model:{}:{}", self.provider, self.class)
    }
}

// ---------------------------------------------------------------------------
// Scope: the full typed resource set of a lease
// ---------------------------------------------------------------------------

/// Kernel-internal effect classes for lease scopes.
///
/// The frozen wire contract carries effects as boolean flags
/// ([`crate::pi_boundary::EffectClasses`]); the kernel derives these classes from
/// those flags at the envelope boundary
/// ([`crate::lease::CanonicalAction::from_envelope`]) for structural
/// scope-subset proofs. This enum is a kernel type, not a wire contract.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    Read,
    Write,
    Network,
    Execute,
    SecretUse,
    MessageSend,
}

impl EffectClass {
    /// Derive the kernel-internal effect classes from the frozen wire flags.
    ///
    /// `secret_refs` is the number of secret references declared on the
    /// envelope; any declared secret implies [`EffectClass::SecretUse`].
    /// There is no wire flag for message sending, so `MessageSend` can only
    /// ever be granted on a lease, never asserted by an action.
    pub fn from_wire(
        flags: &crate::pi_boundary::EffectClasses,
        secret_refs: usize,
    ) -> Vec<EffectClass> {
        let mut out = Vec::new();
        if flags.file_read {
            out.push(EffectClass::Read);
        }
        if flags.file_write {
            out.push(EffectClass::Write);
        }
        if flags.network_egress || flags.network_ingress {
            out.push(EffectClass::Network);
        }
        if flags.process_spawn {
            out.push(EffectClass::Execute);
        }
        if secret_refs > 0 {
            out.push(EffectClass::SecretUse);
        }
        out
    }
}

/// The complete typed resource scope of a lease. Every dimension is a set of
/// typed grants; the subset proof checks each dimension structurally.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceScope {
    /// Tool name → allowed version requirement (children pin exact).
    #[serde(default)]
    pub tools: BTreeMap<String, VersionReq>,
    #[serde(default)]
    pub paths: Vec<PathGrant>,
    #[serde(default)]
    pub destinations: Vec<NetworkDestination>,
    #[serde(default)]
    pub secrets: BTreeSet<String>,
    #[serde(default)]
    pub accounts: BTreeSet<AccountRef>,
    /// Provider → allowed classes.
    #[serde(default)]
    pub models: BTreeMap<String, BTreeSet<String>>,
    #[serde(default)]
    pub effects: Vec<EffectClass>,
}

impl ResourceScope {
    /// The mechanical subset proof: `self` (child) ⊆ `parent`.
    ///
    /// * tools: every child tool pins an exact version allowed by the parent.
    /// * paths: every child grant is covered by some parent grant
    ///   (component-wise containment + rights subset).
    /// * destinations: every child destination is covered by some parent
    ///   destination (scheme/host/ports/methods).
    /// * secrets/accounts/effects: set inclusion.
    /// * models: per-provider class set inclusion.
    ///
    /// Any dimension that cannot be compared safely fails the whole proof.
    pub fn is_subset_of(&self, parent: &ResourceScope) -> Result<(), ScopeSubsetError> {
        for (name, child_req) in &self.tools {
            let parent_req = parent
                .tools
                .get(name)
                .ok_or_else(|| ScopeSubsetError::ToolNotGranted(name.clone()))?;
            let child_name = ToolName::parse(name).map_err(ScopeSubsetError::Canonical)?;
            let grant = ToolGrant {
                name: child_name,
                allowed: child_req.clone(),
            };
            let parent_grant = ToolGrant {
                name: grant.name.clone(),
                allowed: parent_req.clone(),
            };
            grant
                .is_subset_of(&parent_grant)
                .map_err(ScopeSubsetError::Canonical)?;
        }
        for child in &self.paths {
            PathGrant::covering(child, &parent.paths)
                .map_err(|_| ScopeSubsetError::PathNotCovered(child.root.canonical_form()))?;
        }
        for child in &self.destinations {
            let covered = parent
                .destinations
                .iter()
                .any(|p| child.is_subset_of(p).is_ok());
            if !covered {
                return Err(ScopeSubsetError::DestinationNotCovered(
                    child.canonical_form(),
                ));
            }
        }
        for s in &self.secrets {
            if !parent.secrets.contains(s) {
                return Err(ScopeSubsetError::SecretNotGranted(s.clone()));
            }
        }
        for a in &self.accounts {
            if !parent.accounts.contains(a) {
                return Err(ScopeSubsetError::AccountNotGranted(a.canonical_form()));
            }
        }
        for (provider, child_classes) in &self.models {
            match parent.models.get(provider) {
                Some(parent_classes) if child_classes.is_subset(parent_classes) => {}
                _ => {
                    return Err(ScopeSubsetError::ModelClassNotGranted(format!(
                        "{provider}:{}",
                        child_classes.iter().cloned().collect::<Vec<_>>().join(",")
                    )));
                }
            }
        }
        if !effects_subset(&self.effects, &parent.effects) {
            return Err(ScopeSubsetError::EffectNotGranted);
        }
        Ok(())
    }

    /// Stable canonical encoding of the whole scope: sorted typed strings,
    /// hashed for the action/lease digest.
    pub fn canonical_digest(&self) -> Result<String, CanonicalError> {
        let mut items: Vec<String> = Vec::new();
        let mut tools: Vec<(&String, &VersionReq)> = self.tools.iter().collect();
        tools.sort_by(|a, b| a.0.cmp(b.0));
        for (name, req) in tools {
            items.push(format!("tool:{name}@{req}"));
        }
        let mut paths: Vec<String> = self
            .paths
            .iter()
            .map(|p| {
                format!(
                    "path:{}:{}:{}",
                    p.root.canonical_form(),
                    p.rights.read,
                    p.rights.write
                )
            })
            .collect();
        paths.sort();
        items.extend(paths);
        let mut dests: Vec<String> = self
            .destinations
            .iter()
            .map(|d| d.canonical_form())
            .collect();
        dests.sort();
        items.extend(dests);
        for s in &self.secrets {
            items.push(format!("secret:{s}"));
        }
        for a in &self.accounts {
            items.push(a.canonical_form());
        }
        let mut providers: Vec<(&String, &BTreeSet<String>)> = self.models.iter().collect();
        providers.sort_by(|a, b| a.0.cmp(b.0));
        for (provider, classes) in providers {
            let mut c: Vec<&String> = classes.iter().collect();
            c.sort();
            items.push(format!(
                "model:{provider}:{}",
                c.iter().map(|x| x.as_str()).collect::<Vec<_>>().join(",")
            ));
        }
        let mut effects: Vec<String> = self.effects.iter().map(|e| format!("{e:?}")).collect();
        effects.sort();
        effects.dedup();
        for e in effects {
            items.push(format!("effect:{e}"));
        }
        let value = serde_json::to_value(&items).map_err(|_| CanonicalError::TooLong)?;
        canonical_digest(&value).map_err(|_| CanonicalError::TooLong)
    }
}

/// `child` effects ⊆ `parent` effects, by equality (EffectClass has no
/// ordering; the sets are tiny).
fn effects_subset(child: &[EffectClass], parent: &[EffectClass]) -> bool {
    child.iter().all(|c| parent.iter().any(|p| p == c))
}

/// Why a subset proof failed. Each variant names the offending resource so
/// policy denials can explain themselves without leaking anything else.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScopeSubsetError {
    #[error("canonicalization failed: {0}")]
    Canonical(#[source] CanonicalError),
    #[error("tool not granted by parent: {0}")]
    ToolNotGranted(String),
    #[error("path not covered by any parent grant: {0}")]
    PathNotCovered(String),
    #[error("destination not covered by any parent grant: {0}")]
    DestinationNotCovered(String),
    #[error("secret not granted by parent: {0}")]
    SecretNotGranted(String),
    #[error("account not granted by parent: {0}")]
    AccountNotGranted(String),
    #[error("model class not granted by parent: {0}")]
    ModelClassNotGranted(String),
    #[error("effect class not granted by parent")]
    EffectNotGranted,
}

#[cfg(test)]
/// Fake path resolver for tests: maps inputs to outputs lexically.
#[derive(Default)]
pub struct FakeResolver {
    map: HashMap<String, String>,
}

#[cfg(test)]
impl FakeResolver {
    pub fn link(mut self, from: &str, to: &str) -> Self {
        self.map.insert(from.to_string(), to.to_string());
        self
    }
}

#[cfg(test)]
impl PathResolver for FakeResolver {
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        // Longest-prefix link matching on component boundaries, then `..`
        // folding against the *resolved* path — the same order a real
        // resolver uses. (`/w/data` -> `/etc` makes `/w/data/../data`
        // resolve to `/data`, not `/w/data`.)
        let mut cur = path.to_string_lossy().to_string();
        for _ in 0..16 {
            let mut hit: Option<(&str, &str)> = None;
            for (from, to) in &self.map {
                let matches = cur == *from
                    || cur
                        .strip_prefix(from.as_str())
                        .is_some_and(|rest| rest.starts_with('/'));
                if matches && hit.is_none_or(|(f, _)| from.len() > f.len()) {
                    hit = Some((from, to));
                }
            }
            match hit {
                Some((from, to)) => {
                    let rest = cur.strip_prefix(from).unwrap_or("");
                    cur = format!("{to}{rest}");
                }
                None => break,
            }
        }
        let mut out = PathBuf::new();
        for comp in Path::new(&cur).components() {
            match comp {
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                _ => out.push(comp.as_os_str()),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canon(p: &str, r: &dyn PathResolver) -> CanonicalPath {
        CanonicalPath::parse(p, r, false).unwrap()
    }

    #[test]
    fn path_prefix_trick_rejected() {
        let r = FakeResolver::default();
        let root = canon("/data", &r);
        let evil = canon("/database", &r);
        assert!(!evil.is_within(&root));
        let ok = canon("/data/sub/file", &r);
        assert!(ok.is_within(&root));
        assert!(root.is_within(&root));
    }

    #[test]
    fn symlink_escape_defeated() {
        let r = FakeResolver::default().link("/workspace/link", "/etc");
        let root = canon("/workspace", &r);
        let evil = canon("/workspace/link/passwd", &r);
        assert!(!evil.is_within(&root));
    }

    #[test]
    fn traversal_normalized() {
        let r = FakeResolver::default();
        let a = canon("/workspace/a/../b", &r);
        let b = canon("/workspace/b", &r);
        assert_eq!(a, b);
    }

    #[test]
    fn case_folding_view() {
        let r = FakeResolver::default();
        let a = CanonicalPath::parse("/Workspace/SRC", &r, true).unwrap();
        let b = CanonicalPath::parse("/workspace/src", &r, true).unwrap();
        assert_eq!(a, b);
        let c = CanonicalPath::parse("/workspace/src", &r, false).unwrap();
        assert!(!a.is_within(&c)); // different views are incomparable
    }

    #[test]
    fn dns_wildcard_rules() {
        // `*.example.com` covers subdomains but not the apex.
        let parent = HostPattern::parse("*.example.com").unwrap();
        assert!(
            HostPattern::parse("api.example.com")
                .unwrap()
                .is_subset_of(&parent)
                .is_ok()
        );
        assert!(
            HostPattern::parse("example.com")
                .unwrap()
                .is_subset_of(&parent)
                .is_err()
        );
        // Strict single-label semantics: `*.example.com` does not cover
        // deeper nesting or narrower wildcards.
        assert!(
            HostPattern::parse("a.b.example.com")
                .unwrap()
                .is_subset_of(&parent)
                .is_err()
        );
        assert!(
            HostPattern::parse("*.sub.example.com")
                .unwrap()
                .is_subset_of(&parent)
                .is_err()
        );
        assert!(
            HostPattern::parse("*.example.com")
                .unwrap()
                .is_subset_of(&parent)
                .is_ok()
        );
        // Ambiguous wildcards rejected.
        assert!(HostPattern::parse("*").is_err());
        assert!(HostPattern::parse("*.com").is_err());
        assert!(HostPattern::parse("*.*").is_err());
        assert!(HostPattern::parse("*.example.*").is_err());
    }

    #[test]
    fn dns_and_ip_never_mix() {
        let dns = HostPattern::parse("example.com").unwrap();
        let range = HostPattern::parse("93.184.216.0/24").unwrap();
        assert!(matches!(
            dns.is_subset_of(&range),
            Err(CanonicalError::DnsIpMix)
        ));
        assert!(matches!(
            range.is_subset_of(&dns),
            Err(CanonicalError::DnsIpMix)
        ));
    }

    #[test]
    fn ip_range_containment() {
        let parent = HostPattern::parse("10.0.0.0/8").unwrap();
        assert!(
            HostPattern::parse("10.1.2.3")
                .unwrap()
                .is_subset_of(&parent)
                .is_ok()
        );
        assert!(
            HostPattern::parse("10.0.0.0/16")
                .unwrap()
                .is_subset_of(&parent)
                .is_ok()
        );
        assert!(
            HostPattern::parse("11.0.0.1")
                .unwrap()
                .is_subset_of(&parent)
                .is_err()
        );
        // A wider child range is not a subset of a narrower parent.
        let narrow = HostPattern::parse("10.0.0.0/16").unwrap();
        assert!(
            HostPattern::parse("10.0.0.0/8")
                .unwrap()
                .is_subset_of(&narrow)
                .is_err()
        );
    }

    #[test]
    fn default_port_normalization() {
        let a = NetworkDestination::parse("https://example.com/x", &[]).unwrap();
        let b = NetworkDestination::parse("https://example.com:443/x", &[]).unwrap();
        assert_eq!(a.canonical_form(), b.canonical_form());
        let c = NetworkDestination::parse("https://example.com:8443/x", &[]).unwrap();
        assert_ne!(a.canonical_form(), c.canonical_form());
    }

    #[test]
    fn port_subset() {
        assert!(PortSet::single(443).is_subset_of(&PortSet::range(1, 1024).unwrap()));
        assert!(!PortSet::single(8080).is_subset_of(&PortSet::range(1, 1024).unwrap()));
        assert!(PortSet::any().is_subset_of(&PortSet::any()));
        assert!(!PortSet::any().is_subset_of(&PortSet::range(1, 1024).unwrap()));
        assert!(PortSet::single(80).is_subset_of(&PortSet::any()));
    }

    #[test]
    fn tool_pin_subset() {
        let parent = ToolGrant {
            name: ToolName::parse("fs.read").unwrap(),
            allowed: VersionReq::parse("^1.0").unwrap(),
        };
        let child = ToolGrant {
            name: ToolName::parse("fs.read").unwrap(),
            allowed: VersionReq::parse("=1.2.3").unwrap(),
        };
        assert!(child.is_subset_of(&parent).is_ok());
        let bad = ToolGrant {
            name: ToolName::parse("fs.read").unwrap(),
            allowed: VersionReq::parse("=2.0.0").unwrap(),
        };
        assert!(bad.is_subset_of(&parent).is_err());
        // Non-pinned child fails closed.
        let float = ToolGrant {
            name: ToolName::parse("fs.read").unwrap(),
            allowed: VersionReq::parse("^1.2").unwrap(),
        };
        assert!(float.is_subset_of(&parent).is_err());
    }

    #[test]
    fn scope_digest_stable() {
        let r = FakeResolver::default();
        let mut scope = ResourceScope::default();
        scope.paths.push(PathGrant {
            root: canon("/workspace", &r),
            rights: PathRights::READ,
        });
        scope.secrets.insert("db-password".to_string());
        let d1 = scope.canonical_digest().unwrap();
        let d2 = scope.canonical_digest().unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn network_class_private() {
        assert_eq!(
            HostPattern::parse("10.1.2.3").unwrap().network_class(),
            NetworkClass::Private
        );
        assert_eq!(
            HostPattern::parse("8.8.8.8").unwrap().network_class(),
            NetworkClass::Public
        );
        assert_eq!(
            HostPattern::parse("127.0.0.1").unwrap().network_class(),
            NetworkClass::Loopback
        );
        assert_eq!(
            HostPattern::parse("example.com").unwrap().network_class(),
            NetworkClass::Dns
        );
    }

    #[test]
    fn network_class_special_addresses_fail_closed() {
        // IPv4-mapped IPv6 unwraps to the embedded address.
        assert_eq!(
            HostPattern::parse("::ffff:10.0.0.1")
                .unwrap()
                .network_class(),
            NetworkClass::Private
        );
        assert_eq!(
            HostPattern::parse("::ffff:127.0.0.1")
                .unwrap()
                .network_class(),
            NetworkClass::Loopback
        );
        assert_eq!(
            HostPattern::parse("::ffff:8.8.8.8")
                .unwrap()
                .network_class(),
            NetworkClass::Public
        );
        // "This network" and limited broadcast are never Public.
        assert_eq!(
            HostPattern::parse("0.0.0.0").unwrap().network_class(),
            NetworkClass::Restricted
        );
        assert_eq!(
            HostPattern::parse("0.1.2.3").unwrap().network_class(),
            NetworkClass::Restricted
        );
        assert_eq!(
            HostPattern::parse("255.255.255.255")
                .unwrap()
                .network_class(),
            NetworkClass::Restricted
        );
        // Shared (CGNAT) space is not publicly routable.
        assert_eq!(
            HostPattern::parse("100.64.0.1").unwrap().network_class(),
            NetworkClass::Private
        );
        assert_eq!(
            HostPattern::parse("100.127.255.255")
                .unwrap()
                .network_class(),
            NetworkClass::Private
        );
        // Reserved and documentation ranges.
        assert_eq!(
            HostPattern::parse("240.0.0.1").unwrap().network_class(),
            NetworkClass::Restricted
        );
        assert_eq!(
            HostPattern::parse("192.0.2.1").unwrap().network_class(),
            NetworkClass::Restricted
        );
        assert_eq!(
            HostPattern::parse("::").unwrap().network_class(),
            NetworkClass::Restricted
        );
        // Unchanged: genuine public and v6 special addresses.
        assert_eq!(
            HostPattern::parse("::1").unwrap().network_class(),
            NetworkClass::Loopback
        );
        assert_eq!(
            HostPattern::parse("fe80::1").unwrap().network_class(),
            NetworkClass::LinkLocal
        );
        assert_eq!(
            HostPattern::parse("ff02::1").unwrap().network_class(),
            NetworkClass::Multicast
        );
        assert_eq!(
            HostPattern::parse("fd00::1").unwrap().network_class(),
            NetworkClass::Private
        );
        assert_eq!(
            HostPattern::parse("2001:db8::1").unwrap().network_class(),
            NetworkClass::Restricted
        );
        assert_eq!(
            HostPattern::parse("2001:4860:4860::8888")
                .unwrap()
                .network_class(),
            NetworkClass::Public
        );
    }

    #[test]
    fn network_class_range_uses_least_trusted_address() {
        // A range spanning restricted addresses is never Public.
        assert_eq!(
            HostPattern::parse("0.0.0.0/0").unwrap().network_class(),
            NetworkClass::Loopback
        );
        assert_eq!(
            HostPattern::parse("::/0").unwrap().network_class(),
            NetworkClass::Loopback
        );
        assert_eq!(
            HostPattern::parse("0.0.0.0/8").unwrap().network_class(),
            NetworkClass::Restricted
        );
        assert_eq!(
            HostPattern::parse("127.0.0.0/8").unwrap().network_class(),
            NetworkClass::Loopback
        );
        assert_eq!(
            HostPattern::parse("10.0.0.0/8").unwrap().network_class(),
            NetworkClass::Private
        );
        // IPv4-mapped IPv6 ranges unwrap: ::ffff:10.0.0.0/104 is 10/8.
        assert_eq!(
            HostPattern::parse("::ffff:10.0.0.0/104")
                .unwrap()
                .network_class(),
            NetworkClass::Private
        );
        assert_eq!(
            HostPattern::parse("::ffff:0.0.0.0/96")
                .unwrap()
                .network_class(),
            NetworkClass::Loopback
        );
        // Genuinely public ranges stay Public.
        assert_eq!(
            HostPattern::parse("93.184.216.0/24")
                .unwrap()
                .network_class(),
            NetworkClass::Public
        );
        assert_eq!(
            HostPattern::parse("2001:4860::/32")
                .unwrap()
                .network_class(),
            NetworkClass::Public
        );
        // Documentation ranges are Restricted even as ranges.
        assert_eq!(
            HostPattern::parse("2001:db8::/32").unwrap().network_class(),
            NetworkClass::Restricted
        );
    }

    #[test]
    fn ipv6_destination_parses_as_ip_not_dns() {
        // Regression: Url::host_str() keeps the brackets, which used to
        // fall through to a DnsName("[::1]") and hide loopback/private
        // literals from network_class() and the subset proof.
        let loopback = NetworkDestination::parse("https://[::1]:443/x", &[]).unwrap();
        assert_eq!(loopback.host, HostPattern::Ip("::1".parse().unwrap()));
        assert_eq!(loopback.host.network_class(), NetworkClass::Loopback);

        let ula = NetworkDestination::parse("https://[fd00::1]/", &[]).unwrap();
        assert_eq!(ula.host.network_class(), NetworkClass::Private);

        // An IpRange grant covers the IPv6 action (no DnsIpMix).
        let grant = NetworkDestination {
            scheme: "https".to_string(),
            host: HostPattern::parse("fd00::/8").unwrap(),
            ports: PortSet::single(443),
            methods: BTreeSet::new(),
        };
        assert!(ula.is_subset_of(&grant).is_ok());
        assert!(loopback.is_subset_of(&grant).is_err());

        let v4 = NetworkDestination::parse("https://93.184.216.34:8443/", &[]).unwrap();
        assert_eq!(v4.host, HostPattern::Ip("93.184.216.34".parse().unwrap()));
    }

    #[test]
    fn method_subset_treats_empty_as_unrestricted() {
        let dest =
            |methods: &[&str]| NetworkDestination::parse("https://example.com/", methods).unwrap();
        let unrestricted = dest(&[]);
        let get_only = dest(&["GET"]);
        let get_post = dest(&["GET", "POST"]);

        // Unrestricted child: only an unrestricted parent covers it.
        assert!(unrestricted.is_subset_of(&dest(&[])).is_ok());
        assert!(unrestricted.is_subset_of(&get_only).is_err());
        // Restricted child: covered by unrestricted or wider parents.
        assert!(get_only.is_subset_of(&dest(&[])).is_ok());
        assert!(get_only.is_subset_of(&get_only).is_ok());
        assert!(get_only.is_subset_of(&get_post).is_ok());
        assert!(get_post.is_subset_of(&get_only).is_err());
        // Methods are ignored for non-HTTP schemes.
        let dns_child = NetworkDestination::parse("dns://example.com:53/", &[]).unwrap();
        let mut dns_parent = dns_child.clone();
        dns_parent.methods.insert("GET".to_string());
        assert!(dns_child.is_subset_of(&dns_parent).is_ok());
    }

    /// The canonical destination decoder is the exact inverse of the
    /// encoder: every host kind, port shape, and method allowlist
    /// round-trips, and the re-encoded form is byte-identical.
    #[test]
    fn canonical_destination_round_trip() {
        let cases = [
            // (scheme, host, ports, methods)
            (
                "https",
                HostPattern::DnsName("example.com".to_string()),
                PortSet::single(443),
                vec![],
            ),
            (
                "https",
                HostPattern::DnsWildcard("example.com".to_string()),
                PortSet::from_ports(&[80, 443]),
                vec![],
            ),
            (
                "ssh",
                HostPattern::Ip("10.0.0.7".parse().unwrap()),
                PortSet::single(22),
                vec![],
            ),
            (
                "https",
                HostPattern::Ip("::1".parse().unwrap()),
                PortSet::single(443),
                vec![],
            ),
            (
                "https",
                HostPattern::IpRange("10.0.0.0/8".parse().unwrap()),
                PortSet::range(8000, 9000).unwrap(),
                vec![],
            ),
            (
                "wss",
                HostPattern::IpRange("2001:db8::/32".parse().unwrap()),
                PortSet::any(),
                vec![],
            ),
            (
                "https",
                HostPattern::DnsName("api.example.com".to_string()),
                PortSet::from_ports(&[443, 8443]),
                vec!["GET".to_string(), "POST".to_string()],
            ),
        ];
        for (scheme, host, ports, methods) in cases {
            let original = NetworkDestination {
                scheme: scheme.to_string(),
                host,
                ports,
                methods: methods.into_iter().collect(),
            };
            let encoded = original.canonical_form();
            assert!(
                encoded.starts_with("net:"),
                "encoder must emit net: form, got {encoded}"
            );
            let decoded = NetworkDestination::parse_canonical_form(&encoded)
                .unwrap_or_else(|e| panic!("decode failed for {encoded}: {e:?}"));
            assert_eq!(decoded, original, "round-trip mismatch for {encoded}");
            assert_eq!(
                decoded.canonical_form(),
                encoded,
                "re-encode must be byte-identical"
            );
        }
    }

    /// Malformed canonical destinations fail closed — the decoder never
    /// invents authority from garbage.
    #[test]
    fn canonical_destination_decode_rejects_malformed() {
        let bad = [
            "",
            "https://example.com:443",
            "net:https://example.com:443", // host not in canonical form
            "net://dns:example.com:ports:443", // empty scheme
            "net:HTTPS://dns:example.com:ports:443", // non-canonical scheme case
            "net:https://dns::ports:443",  // empty host value
            "net:https://dns:1.2.3.4:ports:443", // kind tag disagrees with value
            "net:https://ip:example.com:ports:443",
            "net:https://dnswild:example.com:ports:443", // wildcard missing *.
            "net:https://iprange:not-a-net:ports:443",
            "net:https://dns:example.com:ports:", // empty ports
            "net:https://dns:example.com:ports:abc",
            "net:https://dns:example.com:ports:9000-80", // inverted range
            "net:https://dns:example.com:ports:443:",
            "net:https://dns:example.com:ports:443:get", // non-canonical method case
            "net:https://dns:example.com:ports:443:GET,",
            "net:ftp://dns:example.com:ports:21:RETR", // methods on non-HTTP scheme
            "net:https://dns:example.com",             // missing ports
            "net:https://dns:example.com:ports:443:GET:extra",
        ];
        for input in bad {
            assert!(
                NetworkDestination::parse_canonical_form(input).is_err(),
                "must reject {input:?}"
            );
        }
    }
}
