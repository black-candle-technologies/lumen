//! FROZEN CONTRACT COPY — DO NOT EDIT.
//!
//! Verbatim copy (modulo this header and one doc-link adaptation) of
//! `crates/lumen-protocol/src/sandbox_driver.rs` as frozen by the phase-0
//! worker (SandboxDriver v1). The authoritative definition lives in
//! `lumen-protocol`; this copy exists so the Phase 2 branch builds and
//! tests standalone. At reconcile, replace this module with a dependency
//! on `lumen-protocol` — the wire format is identical, so no behavior
//! changes.
//!
//! Adaptations vs. the original (doc-only):
//! - `` [`ActionEnvelope`](crate::ActionEnvelope`) `` rendered as plain
//!   `ActionEnvelope` (kernel-side type; avoids a broken intra-doc link).
//!
//! ---
//!
//! SandboxDriver v1: the kernel <-> sandboxd boundary.
//!
//! The driver interface is deliberately narrow: prepare, start, stream,
//! cancel, export, destroy. Policy lives in the kernel; the driver enforces
//! the run spec it is given. The Firecracker implementation lands in Phase 2;
//! any driver (gVisor, process jail, ...) must satisfy this same trait.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Contract version for [`SandboxRunSpec`]/[`SandboxResult`].
pub const SANDBOX_DRIVER_VERSION: u32 = 1;

/// Execution profile. v1 implements `Strict` only: one disposable microVM
/// per action. `Stateful` is a future, separately lease-gated profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfile {
    Strict,
    Stateful,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// vCPUs.
    pub vcpu: u32,
    /// Memory in MiB.
    pub memory_mib: u64,
    /// Wall-clock deadline in seconds.
    pub wall_time_secs: u64,
    /// Max guest processes.
    pub max_processes: u32,
    /// Writable workspace size cap in MiB.
    pub disk_mib: u64,
    /// Max captured stdout+stderr bytes.
    pub max_output_bytes: u64,
}

/// What the sandbox is allowed to do on the network. Default: everything
/// denied. v1 supports an explicit allowlist of destinations; richer
/// proxy mediation arrives with the Firecracker driver in Phase 2.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRunSpec {
    pub protocol_version: u32,
    /// Digest of the approved guest image (never a floating tag).
    pub image_digest: String,
    /// Digest of the guest kernel.
    pub kernel_digest: String,
    /// Sandbox policy document version applied to this run.
    pub policy_version: String,
    pub profile: SandboxProfile,
    pub limits: ResourceLimits,
    pub network: NetworkPolicy,
    /// Command to execute inside the guest.
    pub command: Vec<String>,
    /// Environment for the guest (secret-free; secret handles arrive via a
    /// separate one-action channel in Phase 2).
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Digest of the `ActionEnvelope` (kernel-side type) being served.
    pub action_digest: String,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxResult {
    pub protocol_version: u32,
    pub exit_code: i32,
    pub timed_out: bool,
    /// Bounded captured output.
    pub output: String,
    pub usage: SandboxUsage,
    /// Manifest for kernel-side writeback validation. `None` when the run
    /// produced no exportable changes.
    pub export_manifest: Option<ExportManifest>,
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("driver fault: {0}")]
    Driver(String),
    #[error("run cancelled")]
    Cancelled,
    #[error("image digest not approved: {0}")]
    UnapprovedImage(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

/// The narrow kernel -> sandboxd interface. Implementations must be
/// crash-safe: `destroy` is idempotent and a dead run never leaks a VM,
/// TAP device, or disk layer.
#[async_trait]
pub trait SandboxDriver: Send + Sync {
    /// Reserve resources and validate the spec. Returns a run handle id.
    async fn prepare(&self, spec: &SandboxRunSpec) -> Result<String, SandboxError>;
    /// Boot the guest and start the command. Resolves when the guest agent
    /// handshake completes.
    async fn start(&self, run_id: &str) -> Result<(), SandboxError>;
    /// Wait for completion (or deadline) and collect the bounded result.
    async fn wait(&self, run_id: &str) -> Result<SandboxResult, SandboxError>;
    /// Cancel a running action; the guest is terminated.
    async fn cancel(&self, run_id: &str) -> Result<(), SandboxError>;
    /// Export the change manifest for kernel-side writeback validation.
    async fn export_manifest(&self, run_id: &str) -> Result<ExportManifest, SandboxError>;
    /// Terminate the guest, detach devices, scrub disks. Idempotent.
    async fn destroy(&self, run_id: &str) -> Result<(), SandboxError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_rejects_unknown_fields() {
        let json = serde_json::json!({
            "protocol_version": 1,
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
            "action_digest": "abc",
            "smuggled": true
        });
        assert!(serde_json::from_value::<SandboxRunSpec>(json).is_err());
    }

    #[test]
    fn default_network_policy_denies_metadata_and_private() {
        let json = serde_json::json!({
            "protocol_version": 1,
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
            "action_digest": "abc"
        });
        let spec: SandboxRunSpec = serde_json::from_value(json).unwrap();
        assert!(spec.network.deny_metadata);
        assert!(spec.network.deny_private_ranges);
        assert!(spec.network.allow_egress.is_empty());
    }
}
