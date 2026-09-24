//! Daemon configuration.
//!
//! Loaded from a TOML file (default `/etc/lumen/sandboxd.toml`). Every path
//! and identity below is operator-controlled; none of it is guest-influenced.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::SandboxdError;

/// Top-level sandboxd configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    #[serde(default)]
    pub state: StateConfig,
    #[serde(default)]
    pub api: ApiConfig,
    #[serde(default)]
    pub firecracker: FirecrackerConfig,
    #[serde(default)]
    pub images: ImageConfig,
    #[serde(default)]
    pub net: NetConfig,
    #[serde(default)]
    pub uid_pool: UidPoolConfig,
    #[serde(default)]
    pub limits: HostLimits,
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub secrets: SecretsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateConfig {
    /// Persistent run journals, UID allocator, pinned DNS records.
    pub dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApiConfig {
    /// Unix socket path for the kernel-facing API.
    pub socket: PathBuf,
    /// File holding the bearer token (0600, kernel service user only).
    pub token_file: PathBuf,
    /// Peer UIDs accepted via SO_PEERCRED (kernel service account).
    pub allowed_uids: Vec<u32>,
    /// Group owning the API socket when several UIDs share access (the
    /// socket is then 0660). Unneeded for a single allowed UID, which
    /// gets a 0600 socket chowned to it.
    #[serde(default)]
    pub socket_group: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirecrackerConfig {
    pub binary: PathBuf,
    pub jailer: PathBuf,
    /// Base dir for jailer chroots (`<base>/firecracker/<id>/root`).
    pub chroot_base: PathBuf,
    /// Firecracker release version pinned for this host.
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageConfig {
    /// Approved image store: `<store>/<image_digest>/manifest.json` etc.
    pub store: PathBuf,
    /// Trusted Ed25519 public keys (files) for manifest signatures.
    pub trusted_keys: Vec<PathBuf>,
    /// Digest of the sandbox policy document this daemon enforces.
    pub policy_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetConfig {
    /// Pod CIDR carved into per-run /30s, e.g. `10.244.0.0/16`.
    pub pod_cidr: String,
    /// Host-side DNS forwarder upstream (host policy resolver target).
    pub upstream_dns: String,
    /// Interface name prefixes (Linux ifname <= 15 chars).
    pub tap_prefix: String,
    pub netns_prefix: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UidPoolConfig {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLimits {
    /// Hard cap on concurrent runs; `prepare` fails closed past this.
    pub max_concurrent_runs: u32,
    /// Upper bound any single run may request (defense in depth; the
    /// kernel's lease is the primary bound).
    pub max_memory_mib: u64,
    pub max_vcpu: u32,
    pub max_wall_time_secs: u64,
    pub max_disk_mib: u64,
    /// Guest process cap applied to every run. The frozen v1 contract has no
    /// per-run process field, so this is daemon policy (fail closed).
    #[serde(default = "default_max_processes")]
    pub default_max_processes: u32,
}

fn default_max_processes() -> u32 {
    256
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    /// Port the per-run egress proxy listens on (host side of veth).
    pub port: u16,
    /// Default per-destination egress byte cap when the spec is silent.
    pub default_dest_byte_cap: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Kernel secret-broker socket. `None` (default) denies all secret use.
    pub broker_socket: Option<PathBuf>,
}

impl Default for StateConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("/var/lib/lumen/sandboxd"),
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            socket: PathBuf::from("/run/lumen/sandboxd.sock"),
            token_file: PathBuf::from("/etc/lumen/sandboxd-token"),
            allowed_uids: vec![0],
            socket_group: None,
        }
    }
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("/usr/local/bin/firecracker"),
            jailer: PathBuf::from("/usr/local/bin/jailer"),
            chroot_base: PathBuf::from("/srv/jailer"),
            version: String::from("v1.10.1"),
        }
    }
}

impl Default for ImageConfig {
    fn default() -> Self {
        Self {
            store: PathBuf::from("/var/lib/lumen/images"),
            trusted_keys: vec![PathBuf::from("/etc/lumen/image-signing.pub")],
            policy_version: String::from("sandbox-policy-v1"),
        }
    }
}

impl Default for NetConfig {
    fn default() -> Self {
        Self {
            pod_cidr: String::from("10.244.0.0/16"),
            upstream_dns: String::from("127.0.0.53"),
            tap_prefix: String::from("lmnt-"),
            netns_prefix: String::from("lmn-"),
        }
    }
}

impl Default for UidPoolConfig {
    fn default() -> Self {
        Self {
            start: 61000,
            end: 61999,
        }
    }
}

impl Default for HostLimits {
    fn default() -> Self {
        Self {
            max_concurrent_runs: 16,
            max_memory_mib: 8192,
            max_vcpu: 4,
            max_wall_time_secs: 3600,
            max_disk_mib: 20480,
            default_max_processes: default_max_processes(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            port: 18080,
            default_dest_byte_cap: 16 * 1024 * 1024,
        }
    }
}

impl DaemonConfig {
    /// Load from a TOML file. Unknown fields are rejected.
    pub fn load(path: &std::path::Path) -> Result<Self, SandboxdError> {
        let text = std::fs::read_to_string(path).map_err(SandboxdError::Io)?;
        toml::from_str(&text).map_err(|e| SandboxdError::State(format!("bad config: {e}")))
    }

    /// Validate cross-field invariants. Fails closed.
    pub fn validate(&self) -> Result<(), SandboxdError> {
        use crate::error::SandboxdError;
        if self.uid_pool.start == 0 || self.uid_pool.end <= self.uid_pool.start {
            return Err(SandboxdError::State("uid_pool is empty or inverted".into()));
        }
        if self.uid_pool.start < 1000 {
            return Err(SandboxdError::State(
                "uid_pool must not overlap system UIDs".into(),
            ));
        }
        if self.limits.max_concurrent_runs == 0 {
            return Err(SandboxdError::State(
                "max_concurrent_runs must be > 0".into(),
            ));
        }
        // A zero host resource cap makes the daemon useless: adapt_spec
        // rejects every run against it (a run must request >= 1 vCPU,
        // >= 64 MiB RAM, > 0 wall time, > 0 disk). Reject the
        // misconfiguration at load time with a descriptive error.
        for (name, value) in [
            ("max_vcpu", self.limits.max_vcpu as u64),
            ("max_memory_mib", self.limits.max_memory_mib),
            ("max_wall_time_secs", self.limits.max_wall_time_secs),
            ("max_disk_mib", self.limits.max_disk_mib),
        ] {
            if value == 0 {
                return Err(SandboxdError::State(format!(
                    "{name} must be > 0: a zero cap rejects every run"
                )));
            }
        }
        if self.limits.default_max_processes == 0 {
            return Err(SandboxdError::State(
                "default_max_processes must be > 0".into(),
            ));
        }
        for name in [
            &self.api.socket,
            &self.firecracker.binary,
            &self.firecracker.jailer,
        ] {
            if !name.is_absolute() {
                return Err(SandboxdError::State(format!(
                    "path must be absolute: {}",
                    name.display()
                )));
            }
        }
        if self.net.tap_prefix.len() + 7 > 15 {
            return Err(SandboxdError::State(
                "tap_prefix too long for ifname".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        DaemonConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_unknown_fields() {
        let bad = "[api]\nsocket = \"/x\"\nbogus = 1\n";
        assert!(toml::from_str::<DaemonConfig>(bad).is_err());
    }

    #[test]
    fn rejects_system_uid_pool() {
        let mut cfg = DaemonConfig::default();
        cfg.uid_pool.start = 500;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_long_tap_prefix() {
        let mut cfg = DaemonConfig::default();
        cfg.net.tap_prefix = "way-too-long-prefix-".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn rejects_zero_resource_caps() {
        for set_zero in [
            (|c: &mut DaemonConfig| c.limits.max_vcpu = 0) as fn(&mut DaemonConfig),
            |c: &mut DaemonConfig| c.limits.max_memory_mib = 0,
            |c: &mut DaemonConfig| c.limits.max_wall_time_secs = 0,
            |c: &mut DaemonConfig| c.limits.max_disk_mib = 0,
            |c: &mut DaemonConfig| c.limits.max_concurrent_runs = 0,
        ] {
            let mut cfg = DaemonConfig::default();
            set_zero(&mut cfg);
            let err = cfg.validate().unwrap_err().to_string();
            assert!(err.contains("must be > 0"), "descriptive error: {err}");
        }
    }
}
