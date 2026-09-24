//! Kernel <-> sandboxd boundary: frozen contract re-exports + runtime shapes.
//!
//! The [`SandboxDriver`] v1 trait and its wire types are FROZEN in phase 0
//! (`lumen_core::pi_boundary`, re-exported by the `lumen-protocol` facade).
//! They are re-exported here verbatim and are never redefined: the
//! Firecracker [`crate::driver::Driver`] implements exactly the trait the
//! kernel programs against, so a spec serialized by the kernel deserializes
//! identically here.
//!
//! The remaining types in this module are sandboxd-RUNTIME shapes: the
//! driver's internal resource configuration, network policy, and rich
//! result record. They are not wire contracts and may evolve with the
//! daemon; they are kept here (rather than scattered) because the jailer,
//! cgroups, network, proxy, export, and driver modules all share them.

pub use lumen_protocol::{
    ExportedFile, NetworkResource, OutputChunk, OutputSink, SANDBOX_DRIVER_VERSION, SandboxDriver,
    SandboxError, SandboxHandle, SandboxOutcome, SandboxProfile, SandboxQuotas, SandboxSpec,
    StreamStats,
};

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Runtime-internal shapes (NOT frozen wire contracts)
// ---------------------------------------------------------------------------

/// Host-level resource configuration derived from the frozen
/// [`SandboxQuotas`] plus daemon defaults. The frozen contract deliberately
/// carries only the four kernel-visible quotas; knobs like the guest
/// process cap and the workspace disk cap are daemon policy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// vCPUs.
    pub vcpu: u32,
    /// Memory in MiB.
    pub memory_mib: u64,
    /// Wall-clock deadline in seconds (rounded UP from `wall_time_ms` so the
    /// kernel's deadline is never shortened).
    pub wall_time_secs: u64,
    /// Max guest processes (daemon default; the v1 contract has no field).
    pub max_processes: u32,
    /// Writable workspace size cap in MiB (daemon host limit).
    pub disk_mib: u64,
    /// Max captured stdout+stderr bytes.
    pub max_output_bytes: u64,
}

/// Egress policy enforced by the proxy/DNS forwarder. Default-deny: an
/// empty `allow_egress` means no egress at all, and the metadata/private
/// denials are always enforced regardless of the allowlist.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    #[serde(default)]
    pub allow_egress: Vec<String>,
    /// Always enforced regardless of `allow_egress`.
    #[serde(default = "default_true")]
    pub deny_metadata: bool,
    #[serde(default = "default_true")]
    pub deny_private_ranges: bool,
}

fn default_true() -> bool {
    true
}

/// Runtime run spec: the daemon's working view of a prepared run. Derived
/// from the frozen [`SandboxSpec`] by the prepare adapter (see
/// [`crate::driver::Driver`]'s `SandboxDriver::prepare`), which fills the
/// fields the v1 contract does not carry:
///
/// - `kernel_digest`: resolved from the signed image manifest (the manifest
///   is the trust root; the kernel cannot nominate a kernel different from
///   the image's).
/// - `policy_version`: the daemon-enforced `images.policy_version`.
/// - `max_processes` / `disk_mib`: daemon host limits.
/// - `env`: empty; v1 has no kernel->guest env channel (secrets arrive via
///   the brokered `grant_secrets` path, never the spec).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRunSpec {
    /// Digest of the approved guest image (never a floating tag).
    pub image_digest: String,
    /// Digest of the guest kernel, from the signed image manifest.
    pub kernel_digest: String,
    /// Daemon-enforced sandbox policy document version.
    pub policy_version: String,
    pub profile: SandboxProfile,
    pub limits: ResourceLimits,
    pub network: NetworkPolicy,
    /// Command to execute inside the guest.
    pub command: Vec<String>,
    /// Plain (secret-free) guest environment. Secret-looking names are
    /// rejected at prepare; secrets arrive via `grant_secrets`.
    pub env: Vec<(String, String)>,
}

/// One changed path exported from the guest for kernel-side validation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedPath {
    /// Guest-absolute path of the changed file.
    pub path: String,
    /// SHA-256 hex of the staged content.
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportManifest {
    pub changed: Vec<ChangedPath>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxUsage {
    pub wall_time_ms: u64,
    pub peak_memory_mib: u64,
    pub egress_bytes: u64,
    pub ingress_bytes: u64,
}

/// Rich internal result of a completed run. The frozen trait surfaces
/// completion to the kernel through `stream` (output chunks + [`StreamStats`]);
/// this record keeps the full outcome for the daemon's local API, journal,
/// and tests.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxResult {
    pub exit_code: i32,
    pub timed_out: bool,
    /// Bounded captured output (`stdout` ++ `stderr`).
    pub output: String,
    pub output_truncated: bool,
    pub usage: SandboxUsage,
    /// Manifest for kernel-side writeback validation. `None` when the run
    /// produced no exportable changes.
    pub export_manifest: Option<ExportManifest>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_rejects_unknown_fields() {
        let json = serde_json::json!({
            "image_digest": "sha256:abc",
            "kernel_digest": "sha256:def",
            "policy_version": "1",
            "profile": "strict",
            "limits": {
                "vcpu": 1, "memory_mib": 512, "wall_time_secs": 60,
                "max_processes": 32, "disk_mib": 1024, "max_output_bytes": 65536
            },
            "network": {},
            "command": ["true"],
            "env": [],
            "smuggled": true
        });
        assert!(serde_json::from_value::<SandboxRunSpec>(json).is_err());
    }

    #[test]
    fn default_network_policy_denies_metadata_and_private() {
        let json = serde_json::json!({
            "image_digest": "sha256:abc",
            "kernel_digest": "sha256:def",
            "policy_version": "1",
            "profile": "strict",
            "limits": {
                "vcpu": 1, "memory_mib": 512, "wall_time_secs": 60,
                "max_processes": 32, "disk_mib": 1024, "max_output_bytes": 65536
            },
            "network": {},
            "command": ["true"],
            "env": []
        });
        let spec: SandboxRunSpec = serde_json::from_value(json).unwrap();
        assert!(spec.network.deny_metadata);
        assert!(spec.network.deny_private_ranges);
        assert!(spec.network.allow_egress.is_empty());
    }

    #[test]
    fn frozen_handle_round_trips() {
        // The frozen boundary types must survive a JSON round trip with the
        // exact field names the kernel uses.
        let handle = SandboxHandle {
            version: SANDBOX_DRIVER_VERSION,
            run_id: uuid::Uuid::nil(),
        };
        let json = serde_json::to_value(&handle).unwrap();
        assert_eq!(json["version"], 1);
        let back: SandboxHandle = serde_json::from_value(json).unwrap();
        assert_eq!(back, handle);
    }
}
