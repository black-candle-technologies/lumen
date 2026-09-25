//! Phase-0 architecture spike: versioned trust-boundary contracts.
//!
//! This module is the **authoritative** definition of the boundary between the
//! Pi RPC subprocess (untrusted: model output, extensions, tool arguments),
//! the host supervisor (`lumen-server`) and the Lumen kernel (this crate).
//!
//! Frozen contracts (all v1 — see `docs/adr/0004-canonical-encoding-and-versioning.md`):
//!
//! | Contract | Contents | Owner |
//! |---|---|---|
//! | [`ActionEnvelope`] | action, resources, inputs, effects, lease chain | kernel |
//! | [`PolicyDecision`] | allow / deny / pending-approval, reason, obligations; **no default allow** | kernel |
//! | PiBridge v1 ([`BridgeToolRequest`], [`BridgeEvent`], [`BridgeCancellation`]) | session events, tool request, cancellation | host |
//! | [`AuditEvent`] | actor, action digest, decision, chain link | kernel |
//! | [`SandboxDriver`] | prepare, start, stream, cancel, export, destroy | sandbox |
//!
//! Core invariant (from the rebuild design): no model request, Pi extension,
//! or sub-agent performs an external effect unless the kernel can point to a
//! valid lease or a single-use approval authorizing that exact action. The
//! action digest ([`ActionEnvelope::digest`]) is the approval target and the
//! primary audit key.
//!
//! This module also ships the spike implementation used to *prove* the
//! boundary: [`LocalKernel`] (stub policy + in-memory lease registry),
//! [`AuditLog`] (in-memory append-only hash-chained log), and the
//! authenticated local [`KernelListener`] (Unix domain socket, peer-credential
//! validation, per-session nonce). Phase 1 replaces the stub policy with the
//! real lease engine; the contract shapes stay frozen.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Contract versions
// ---------------------------------------------------------------------------

/// Version of the [`ActionEnvelope`] contract frozen by Phase 0.
pub const ACTION_ENVELOPE_VERSION: u32 = 1;
/// Version of the [`PolicyDecision`] contract.
///
/// v1 was frozen by Phase 0. Phase 1 added the `SettleBudget` obligation
/// variant, so the contract is v2 per ADR-0004 (new version + new fixtures
/// for every protocol change; v1 shapes still parse).
pub const POLICY_DECISION_VERSION: u32 = 2;
/// Version of the PiBridge contract frozen by Phase 0.
pub const PIBRIDGE_VERSION: u32 = 1;
/// Version of the [`AuditEvent`] contract frozen by Phase 0.
pub const AUDIT_EVENT_VERSION: u32 = 1;
/// Version of the [`SandboxDriver`] contract frozen by Phase 0.
pub const SANDBOX_DRIVER_VERSION: u32 = 1;
/// Wire protocol identifier spoken on the kernel's local transport.
pub const KERNEL_WIRE_PROTOCOL: &str = "lumen-kernel/1";
/// Maximum size of one kernel wire record (flood protection).
pub const KERNEL_MAX_RECORD_BYTES: usize = 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BoundaryError {
    #[error("unsupported contract version: expected {expected}, got {got}")]
    UnsupportedVersion { expected: u32, got: u32 },
    #[error("envelope failed validation: {0}")]
    InvalidEnvelope(String),
    #[error("value is not in canonical form: {0}")]
    NonCanonicalValue(String),
    #[error("audit chain broken: {0}")]
    AuditChainBroken(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum KernelError {
    #[error("kernel transport error: {0}")]
    Transport(String),
    #[error("peer failed validation: {0}")]
    PeerRejected(String),
    #[error("request failed authentication")]
    AuthenticationFailed,
    #[error("malformed request: {0}")]
    MalformedRequest(String),
    #[error(transparent)]
    Boundary(#[from] BoundaryError),
    #[error("internal kernel error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Canonical encoding (digest-stable)
// ---------------------------------------------------------------------------
//
// Rules (ADR-0004):
// - UTF-8 JSON, no insignificant whitespace.
// - Object keys sorted by UTF-8 byte order, recursively.
// - Only integers are allowed as numbers; floats are rejected (no canonical
//   float representation exists that is stable across encoders).
// - Strings use standard JSON escaping.

/// Serialize `value` into the digest-stable canonical byte form.
///
/// Returns [`BoundaryError::NonCanonicalValue`] for floats, NaN, or any value
/// that cannot be represented canonically.
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, BoundaryError> {
    let mut out = Vec::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut Vec<u8>) -> Result<(), BoundaryError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else {
                return Err(BoundaryError::NonCanonicalValue(format!(
                    "non-integer number is not canonical: {n}"
                )));
            }
        }
        Value::String(s) => {
            let encoded = serde_json::to_vec(&Value::String(s.clone())).map_err(|e| {
                BoundaryError::Serialization(format!("string encoding failed: {e}"))
            })?;
            out.extend_from_slice(&encoded);
        }
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                let encoded_key =
                    serde_json::to_vec(&Value::String((*key).clone())).map_err(|e| {
                        BoundaryError::Serialization(format!("key encoding failed: {e}"))
                    })?;
                out.extend_from_slice(&encoded_key);
                out.push(b':');
                write_canonical(&map[*key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// SHA-256 hex digest of the canonical form of `value`.
pub fn canonical_digest(value: &Value) -> Result<String, BoundaryError> {
    let bytes = canonical_json(value)?;
    Ok(hex_digest(&bytes))
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Check that every number in `value` is an integer (canonical requirement).
fn all_numbers_integral(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_i64() || n.is_u64(),
        Value::Array(items) => items.iter().all(all_numbers_integral),
        Value::Object(map) => map.values().all(all_numbers_integral),
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// ActionEnvelope v1
// ---------------------------------------------------------------------------

/// Opaque lease identifier (leaf → root chain order in the envelope).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseId(Uuid);

impl LeaseId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for LeaseId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for LeaseId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Stable tool reference: name + contract version of the tool itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolRef {
    pub name: String,
    pub version: String,
}

/// A content input the action depends on, referenced by hash.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct InputRef {
    /// Hex SHA-256 of the input content.
    pub content_hash: String,
    /// Workspace snapshot the input was read from, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathRights {
    Read,
    Write,
}

/// One filesystem resource the action touches.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathResource {
    /// Canonical absolute path (lexically normalized, see [`canonical_path`]).
    pub path: String,
    pub rights: PathRights,
}

/// One network destination the action may contact (unused by phase-0 reads,
/// part of the frozen contract for phase 2+).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkResource {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

/// One secret the action may use (brokered, never disclosed to the model).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretRef {
    pub id: String,
    pub purpose: String,
}

/// Typed resource set named by the action.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceSet {
    #[serde(default)]
    pub paths: Vec<PathResource>,
    #[serde(default)]
    pub network: Vec<NetworkResource>,
    #[serde(default)]
    pub secrets: Vec<SecretRef>,
}

/// Declared effect classes. The kernel checks the *declared* classes against
/// the lease; the sandbox (phase 2) enforces them at runtime.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EffectClasses {
    pub file_read: bool,
    pub file_write: bool,
    pub network_egress: bool,
    pub network_ingress: bool,
    pub process_spawn: bool,
}

/// Canonical action description. The hash of the canonical form is the
/// approval target and the primary audit key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ActionEnvelope {
    /// Must be [`ACTION_ENVELOPE_VERSION`].
    pub version: u32,
    pub action_id: Uuid,
    /// Ephemeral Courier subject identifying the session.
    pub session_id: String,
    pub tool: ToolRef,
    /// Canonical typed payload (integers only — see [`canonical_json`]).
    pub arguments: BTreeMap<String, Value>,
    pub inputs: Vec<InputRef>,
    pub resources: ResourceSet,
    pub expected_effects: EffectClasses,
    /// Lease identifiers, leaf → root.
    pub lease_chain: Vec<LeaseId>,
    /// Single-use replay boundary.
    pub nonce: String,
    /// Hard expiry, milliseconds since the Unix epoch.
    pub expires_at_ms: i64,
}

impl ActionEnvelope {
    /// Structural validation. Does not consult leases.
    pub fn validate(&self) -> Result<(), BoundaryError> {
        if self.version != ACTION_ENVELOPE_VERSION {
            return Err(BoundaryError::UnsupportedVersion {
                expected: ACTION_ENVELOPE_VERSION,
                got: self.version,
            });
        }
        if self.session_id.is_empty() {
            return Err(BoundaryError::InvalidEnvelope(
                "session_id must not be empty".to_string(),
            ));
        }
        if self.tool.name.is_empty() {
            return Err(BoundaryError::InvalidEnvelope(
                "tool.name must not be empty".to_string(),
            ));
        }
        if self.nonce.is_empty() {
            return Err(BoundaryError::InvalidEnvelope(
                "nonce must not be empty".to_string(),
            ));
        }
        for (key, value) in &self.arguments {
            if !all_numbers_integral(value) {
                return Err(BoundaryError::InvalidEnvelope(format!(
                    "argument '{key}' contains a non-integer number"
                )));
            }
        }
        for resource in &self.resources.paths {
            canonical_path(&resource.path).map_err(|e| {
                BoundaryError::InvalidEnvelope(format!(
                    "resource path '{}' is not canonical: {e}",
                    resource.path
                ))
            })?;
        }
        Ok(())
    }

    /// Digest-stable action digest: hex SHA-256 of the canonical form.
    ///
    /// Equivalent envelopes hash alike regardless of serialization field
    /// order; any change to an argument, input hash, resource, effect class,
    /// lease link, nonce, or expiry changes the digest.
    pub fn digest(&self) -> Result<String, BoundaryError> {
        let value = serde_json::to_value(self)
            .map_err(|e| BoundaryError::Serialization(format!("envelope: {e}")))?;
        canonical_digest(&value)
    }
}

/// Lexically normalize an absolute path: resolve `.` and `..` without
/// touching the filesystem, reject relative paths and empty segments.
pub fn canonical_path(path: &str) -> Result<String, BoundaryError> {
    if !path.starts_with('/') {
        return Err(BoundaryError::NonCanonicalValue(format!(
            "path must be absolute: {path}"
        )));
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    let mut out = String::from("/");
    out.push_str(&parts.join("/"));
    Ok(out)
}

/// True when `prefix` covers `path` (equal, or a proper ancestor directory).
pub fn path_prefix_covers(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

// ---------------------------------------------------------------------------
// PolicyDecision v1
// ---------------------------------------------------------------------------

/// Machine-readable deny reason. There is no default-allow: every code path
/// that cannot prove authority must produce one of these.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DenyReason {
    pub code: String,
    pub detail: String,
}

impl DenyReason {
    fn new(code: &str, detail: impl Into<String>) -> Self {
        Self {
            code: code.to_string(),
            detail: detail.into(),
        }
    }

    pub fn no_lease(detail: impl Into<String>) -> Self {
        Self::new("no_lease_for_action", detail)
    }
    pub fn unknown_lease(detail: impl Into<String>) -> Self {
        Self::new("unknown_lease", detail)
    }
    pub fn lease_expired(detail: impl Into<String>) -> Self {
        Self::new("lease_expired", detail)
    }
    pub fn lease_revoked(detail: impl Into<String>) -> Self {
        Self::new("lease_revoked", detail)
    }
    pub fn scope_exceeded(detail: impl Into<String>) -> Self {
        Self::new("scope_exceeded", detail)
    }
    pub fn subject_mismatch(detail: impl Into<String>) -> Self {
        Self::new("subject_mismatch", detail)
    }
    pub fn replay_detected(detail: impl Into<String>) -> Self {
        Self::new("replay_detected", detail)
    }
    pub fn expired_action(detail: impl Into<String>) -> Self {
        Self::new("expired_action", detail)
    }
    pub fn invalid_envelope(detail: impl Into<String>) -> Self {
        Self::new("invalid_envelope", detail)
    }
}

/// Obligations the executor must honor when carrying out an allowed action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Obligation {
    TruncateOutput {
        max_bytes: u64,
    },
    RedactSecrets,
    RequireSandboxProfile {
        profile: String,
    },
    /// Settle or release the execution-budget reservation created at
    /// authorization time. The dispatcher settles the reservation after
    /// dispatch (converting the hold into measured consumption) or releases
    /// it when dispatch never happened or failed before any effect.
    SettleBudget {
        reservation_id: String,
        lease_id: String,
        action_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow { obligations: Vec<Obligation> },
    Deny { reason: DenyReason },
    PendingApproval { approval_id: String, reason: String },
}

/// Kernel verdict for one action. `version` must be [`POLICY_DECISION_VERSION`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecision {
    pub version: u32,
    #[serde(flatten)]
    pub outcome: DecisionOutcome,
}

impl PolicyDecision {
    pub fn allow(obligations: Vec<Obligation>) -> Self {
        Self {
            version: POLICY_DECISION_VERSION,
            outcome: DecisionOutcome::Allow { obligations },
        }
    }

    pub fn deny(reason: DenyReason) -> Self {
        Self {
            version: POLICY_DECISION_VERSION,
            outcome: DecisionOutcome::Deny { reason },
        }
    }

    pub fn pending_approval(approval_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            version: POLICY_DECISION_VERSION,
            outcome: DecisionOutcome::PendingApproval {
                approval_id: approval_id.into(),
                reason: reason.into(),
            },
        }
    }

    pub const fn is_allow(&self) -> bool {
        matches!(self.outcome, DecisionOutcome::Allow { .. })
    }

    /// Short machine-readable summary for audit records.
    pub fn summary(&self) -> &'static str {
        match &self.outcome {
            DecisionOutcome::Allow { .. } => "allow",
            DecisionOutcome::Deny { .. } => "deny",
            DecisionOutcome::PendingApproval { .. } => "pending",
        }
    }
}

// ---------------------------------------------------------------------------
// PiBridge v1
// ---------------------------------------------------------------------------

/// A model-initiated tool call, normalized by the host supervisor into the
/// kernel's action vocabulary.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BridgeToolRequest {
    pub version: u32,
    pub call_id: String,
    pub tool_name: String,
    pub input: Value,
    pub envelope: ActionEnvelope,
}

/// Cancellation of an in-flight tool call.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BridgeCancellation {
    pub version: u32,
    pub call_id: String,
    pub reason: String,
}

/// Normalized Pi session events consumed by the host. The supervisor maps
/// Pi's raw JSONL stream onto these; downstream code only speaks PiBridge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum BridgeEvent {
    SessionStarted {
        version: u32,
        session_id: String,
        pi_version: String,
    },
    ToolCallObserved {
        version: u32,
        call_id: String,
        tool_name: String,
    },
    ToolResultObserved {
        version: u32,
        call_id: String,
        success: bool,
    },
    AgentSettled {
        version: u32,
    },
    StreamIssue {
        version: u32,
        kind: String,
        detail: String,
    },
    ProcessExited {
        version: u32,
        code: Option<i32>,
    },
}

impl BridgeEvent {
    pub const fn version(&self) -> u32 {
        PIBRIDGE_VERSION
    }
}

// ---------------------------------------------------------------------------
// AuditEvent v1
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "actor", rename_all = "snake_case")]
pub enum AuditActor {
    Session { session_id: String },
    Kernel,
    Human { subject: String },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    ActionProposed,
    PolicyAllowed,
    PolicyDenied,
    ApprovalRequested,
    TransportRejected,
    ToolExecuted,
}

impl AuditEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ActionProposed => "action_proposed",
            Self::PolicyAllowed => "policy_allowed",
            Self::PolicyDenied => "policy_denied",
            Self::ApprovalRequested => "approval_requested",
            Self::TransportRejected => "transport_rejected",
            Self::ToolExecuted => "tool_executed",
        }
    }
}

/// One audit event. `hash` chains to `prev_hash`; the genesis event uses
/// `"0" * 64`. Payload fields are secret-free by construction: digests and
/// decisions are recorded, never arguments or content.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub version: u32,
    pub event_id: Uuid,
    pub sequence: u64,
    pub timestamp_ms: i64,
    pub actor: AuditActor,
    pub kind: AuditEventKind,
    pub session_id: String,
    /// Hex action digest, or `"none"` for transport-level events.
    pub action_digest: String,
    /// "allow" | "deny" | "pending", when the event records a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    pub detail: String,
    pub prev_hash: String,
    pub hash: String,
}

impl AuditEvent {
    fn unsigned_value(&self) -> Result<Value, BoundaryError> {
        let mut value = serde_json::to_value(self)
            .map_err(|e| BoundaryError::Serialization(format!("audit event: {e}")))?;
        if let Value::Object(map) = &mut value {
            map.insert("hash".to_string(), Value::String(String::new()));
        }
        Ok(value)
    }

    /// Compute the chain hash for this event given its predecessor hash.
    pub fn compute_hash(&self, prev_hash: &str) -> Result<String, BoundaryError> {
        let mut bytes = canonical_json(&self.unsigned_value()?)?;
        bytes.extend_from_slice(prev_hash.as_bytes());
        Ok(hex_digest(&bytes))
    }
}

/// In-memory append-only audit log with hash chaining.
///
/// Phase 0 keeps the log in memory (the spike proves the chain discipline);
/// phase 1 persists it via `lumen-db`.
#[derive(Debug, Default)]
pub struct AuditLog {
    inner: Mutex<Vec<AuditEvent>>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append an event, assigning sequence, predecessor link, and hash.
    /// Returns the sequence number assigned.
    pub fn append(&self, mut event: AuditEvent) -> Result<u64, BoundaryError> {
        let mut events = self
            .inner
            .lock()
            .map_err(|e| BoundaryError::AuditChainBroken(format!("audit lock poisoned: {e}")))?;
        let sequence = events.len() as u64;
        let prev_hash = events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        event.sequence = sequence;
        event.prev_hash = prev_hash.clone();
        event.hash = event.compute_hash(&prev_hash)?;
        events.push(event);
        Ok(sequence)
    }

    /// Verify the full chain: sequences are contiguous, every link matches,
    /// and every hash recomputes.
    pub fn verify(&self) -> Result<(), BoundaryError> {
        let events = self
            .inner
            .lock()
            .map_err(|e| BoundaryError::AuditChainBroken(format!("audit lock poisoned: {e}")))?;
        let mut expected_prev = "0".repeat(64);
        for (index, event) in events.iter().enumerate() {
            if event.sequence != index as u64 {
                return Err(BoundaryError::AuditChainBroken(format!(
                    "sequence gap at index {index}: got {}",
                    event.sequence
                )));
            }
            if event.prev_hash != expected_prev {
                return Err(BoundaryError::AuditChainBroken(format!(
                    "prev_hash mismatch at sequence {}",
                    event.sequence
                )));
            }
            let recomputed = event.compute_hash(&event.prev_hash)?;
            if recomputed != event.hash {
                return Err(BoundaryError::AuditChainBroken(format!(
                    "hash mismatch at sequence {}",
                    event.sequence
                )));
            }
            expected_prev = event.hash.clone();
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.lock().map(|e| e.len()).unwrap_or(0)
    }

    /// Fetch the event recorded at `sequence`, if present.
    pub fn get(&self, sequence: u64) -> Option<AuditEvent> {
        self.inner
            .lock()
            .ok()?
            .iter()
            .find(|e| e.sequence == sequence)
            .cloned()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn events(&self) -> Vec<AuditEvent> {
        self.inner.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// SandboxDriver v1
// ---------------------------------------------------------------------------
//
// Frozen driver surface. Phase 0 ships only [`NullSandboxDriver`] (fail
// closed); phase 2 implements the Firecracker driver behind this trait.

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SandboxProfile {
    /// Fresh microVM per action, disposable state (the v1 default).
    Strict,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxQuotas {
    pub memory_mb: u64,
    pub vcpus: u32,
    pub wall_time_ms: u64,
    pub output_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxSpec {
    pub version: u32,
    pub profile: SandboxProfile,
    /// Digest of the approved guest image (see design: image provenance).
    pub image_digest: String,
    pub command: Vec<String>,
    pub quotas: SandboxQuotas,
    /// Egress allowlist; empty means default-deny.
    #[serde(default)]
    pub egress_allowlist: Vec<NetworkResource>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SandboxHandle {
    pub version: u32,
    pub run_id: Uuid,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputChunk {
    pub stream: String,
    pub bytes: Vec<u8>,
}

pub trait OutputSink {
    fn push(&mut self, chunk: OutputChunk);
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StreamStats {
    pub bytes: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportedFile {
    pub path: String,
    pub content_hash: String,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SandboxOutcome {
    Completed { exit_code: i32 },
    TimedOut,
    Cancelled,
    Failed { reason: String },
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SandboxError {
    #[error("sandbox unavailable: {0}")]
    Unavailable(String),
    #[error("sandbox run failed: {0}")]
    RunFailed(String),
    #[error("sandbox quota exceeded: {0}")]
    QuotaExceeded(String),
}

/// Frozen driver surface: prepare → start → stream → cancel / export → destroy.
///
/// NOTE: `async fn` in this trait is intentional and exempted from
/// `async_fn_in_trait` below. This is the frozen v1 `SandboxDriver`
/// contract (`SANDBOX_DRIVER_VERSION = 1`); desugaring to
/// `fn() -> impl Future` would change the public API and force a `Send`
/// decision that the contract deliberately does not make — notably
/// `stream()` takes `&mut dyn OutputSink`, which is `!Send` by construction,
/// so a `Send` auto-trait bound would be wrong. The allow is a lint-only
/// suppression: zero runtime/behavior change.
#[allow(async_fn_in_trait)]
pub trait SandboxDriver: Send + Sync {
    async fn prepare(&self, spec: &SandboxSpec) -> Result<SandboxHandle, SandboxError>;
    async fn start(&self, handle: &SandboxHandle) -> Result<(), SandboxError>;
    /// Pump bounded output chunks into `sink` until the action completes or
    /// the output cap is hit.
    async fn stream(
        &self,
        handle: &SandboxHandle,
        sink: &mut dyn OutputSink,
    ) -> Result<StreamStats, SandboxError>;
    async fn cancel(&self, handle: &SandboxHandle) -> Result<(), SandboxError>;
    /// Inventory changed paths for kernel writeback inspection (phase 2).
    async fn export(&self, handle: &SandboxHandle) -> Result<Vec<ExportedFile>, SandboxError>;
    async fn destroy(&self, handle: &SandboxHandle) -> Result<(), SandboxError>;
}

/// Phase-0 driver: refuses everything. Fail closed — there is no execution
/// path until phase 2 implements the Firecracker driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullSandboxDriver;

impl SandboxDriver for NullSandboxDriver {
    async fn prepare(&self, _spec: &SandboxSpec) -> Result<SandboxHandle, SandboxError> {
        Err(SandboxError::Unavailable(
            "phase-0 spike: no sandbox driver; execution is refused".to_string(),
        ))
    }

    async fn start(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::Unavailable(
            "phase-0 spike: no sandbox driver; execution is refused".to_string(),
        ))
    }

    async fn stream(
        &self,
        _handle: &SandboxHandle,
        _sink: &mut dyn OutputSink,
    ) -> Result<StreamStats, SandboxError> {
        Err(SandboxError::Unavailable(
            "phase-0 spike: no sandbox driver; execution is refused".to_string(),
        ))
    }

    async fn cancel(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::Unavailable(
            "phase-0 spike: no sandbox driver; execution is refused".to_string(),
        ))
    }

    async fn export(&self, _handle: &SandboxHandle) -> Result<Vec<ExportedFile>, SandboxError> {
        Err(SandboxError::Unavailable(
            "phase-0 spike: no sandbox driver; execution is refused".to_string(),
        ))
    }

    async fn destroy(&self, _handle: &SandboxHandle) -> Result<(), SandboxError> {
        Err(SandboxError::Unavailable(
            "phase-0 spike: no sandbox driver; execution is refused".to_string(),
        ))
    }
}

// ---------------------------------------------------------------------------
// Kernel
// ---------------------------------------------------------------------------

/// The kernel's policy interface. Implemented by [`LocalKernel`] for the
/// spike; phase 1 provides the full lease engine behind the same trait.
pub trait Kernel: Send + Sync {
    fn evaluate(&self, envelope: &ActionEnvelope) -> Result<PolicyDecision, KernelError>;
}

/// A lease record in the spike's in-memory registry.
///
/// Phase 1 replaces this with signed leases; the *narrowing* semantics
/// (child ⊆ parent on every dimension) are already enforced here.
#[derive(Clone, Debug)]
pub struct LeaseRecord {
    pub id: LeaseId,
    pub subject: String,
    pub parent: Option<LeaseId>,
    pub path_prefixes: Vec<String>,
    pub verbs: Vec<String>,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub revoked: bool,
    pub depth: u32,
    pub max_depth: u32,
}

/// Spike policy configuration.
#[derive(Clone, Debug)]
pub struct LocalKernelConfig {
    /// Roots a human may approve on demand (pending-approval verdicts).
    pub approvable_roots: Vec<String>,
    /// Default obligations attached to every allow.
    pub default_max_output_bytes: u64,
}

impl Default for LocalKernelConfig {
    fn default() -> Self {
        Self {
            approvable_roots: Vec::new(),
            default_max_output_bytes: 64 * 1024,
        }
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Spike kernel: validates envelopes, enforces the lease chain with narrowing
/// proofs, returns allow / deny / pending-approval, and audits everything.
///
/// This is deliberately a *stub policy* (path-prefix allowlists). Phase 1
/// owns the real lease engine, canonical resource types, and reservation
/// accounting; it reuses these contract shapes unchanged.
pub struct LocalKernel {
    config: LocalKernelConfig,
    leases: RwLock<HashMap<LeaseId, LeaseRecord>>,
    seen_nonces: Mutex<HashSet<String>>,
    audit: AuditLog,
}

impl LocalKernel {
    pub fn new(config: LocalKernelConfig) -> Self {
        Self {
            config,
            leases: RwLock::new(HashMap::new()),
            seen_nonces: Mutex::new(HashSet::new()),
            audit: AuditLog::new(),
        }
    }

    pub fn audit_log(&self) -> &AuditLog {
        &self.audit
    }

    /// Issue a root lease (setup path for the spike; phase 1 signs leases).
    pub fn issue_root_lease(
        &self,
        subject: impl Into<String>,
        path_prefixes: Vec<String>,
        verbs: Vec<String>,
        expires_at_ms: i64,
    ) -> Result<LeaseId, KernelError> {
        let id = LeaseId::new();
        let record = LeaseRecord {
            id,
            subject: subject.into(),
            parent: None,
            path_prefixes,
            verbs,
            not_before_ms: now_ms(),
            expires_at_ms,
            revoked: false,
            depth: 0,
            max_depth: 8,
        };
        self.leases
            .write()
            .map_err(|e| KernelError::Internal(format!("lease lock poisoned: {e}")))?
            .insert(id, record);
        Ok(id)
    }

    /// Issue a child lease, enforcing mechanical narrowing: the child's
    /// prefixes, verbs, and expiry must each be within the parent's, and the
    /// depth limit must hold.
    pub fn issue_child_lease(
        &self,
        parent_id: LeaseId,
        subject: impl Into<String>,
        path_prefixes: Vec<String>,
        verbs: Vec<String>,
        expires_at_ms: i64,
    ) -> Result<LeaseId, KernelError> {
        let parent = self
            .leases
            .read()
            .map_err(|e| KernelError::Internal(format!("lease lock poisoned: {e}")))?
            .get(&parent_id)
            .cloned()
            .ok_or_else(|| {
                KernelError::MalformedRequest(format!("unknown parent lease {parent_id}"))
            })?;
        if parent.revoked {
            return Err(KernelError::MalformedRequest(
                "parent lease revoked".to_string(),
            ));
        }
        if parent.depth + 1 > parent.max_depth {
            return Err(KernelError::MalformedRequest(
                "delegation depth exceeded".to_string(),
            ));
        }
        if expires_at_ms > parent.expires_at_ms {
            return Err(KernelError::MalformedRequest(
                "child expiry exceeds parent expiry".to_string(),
            ));
        }
        for prefix in &path_prefixes {
            let covered = parent
                .path_prefixes
                .iter()
                .any(|p| path_prefix_covers(p, prefix));
            if !covered {
                return Err(KernelError::MalformedRequest(format!(
                    "child prefix '{prefix}' not covered by parent"
                )));
            }
        }
        for verb in &verbs {
            if !parent.verbs.iter().any(|v| v == verb) {
                return Err(KernelError::MalformedRequest(format!(
                    "child verb '{verb}' not granted by parent"
                )));
            }
        }
        let id = LeaseId::new();
        let record = LeaseRecord {
            id,
            subject: subject.into(),
            parent: Some(parent_id),
            path_prefixes,
            verbs,
            not_before_ms: now_ms(),
            expires_at_ms,
            revoked: false,
            depth: parent.depth + 1,
            max_depth: parent.max_depth,
        };
        self.leases
            .write()
            .map_err(|e| KernelError::Internal(format!("lease lock poisoned: {e}")))?
            .insert(id, record);
        Ok(id)
    }

    pub fn revoke_lease(&self, id: LeaseId) -> Result<(), KernelError> {
        let mut leases = self
            .leases
            .write()
            .map_err(|e| KernelError::Internal(format!("lease lock poisoned: {e}")))?;
        let record = leases
            .get_mut(&id)
            .ok_or_else(|| KernelError::MalformedRequest(format!("unknown lease {id}")))?;
        record.revoked = true;
        Ok(())
    }

    /// Record an audit event and return the sequence number assigned to it.
    ///
    /// Callers that need to identify the event they just recorded (for
    /// example, a verdict response's `audit_sequence`) must use this return
    /// value: inferring the sequence from the log's global length afterwards
    /// races with concurrent evaluations and can attribute another
    /// evaluation's event to this one.
    fn audit(
        &self,
        actor: AuditActor,
        kind: AuditEventKind,
        session_id: &str,
        action_digest: &str,
        decision: Option<&PolicyDecision>,
        detail: impl Into<String>,
    ) -> Option<u64> {
        let event = AuditEvent {
            version: AUDIT_EVENT_VERSION,
            event_id: Uuid::new_v4(),
            sequence: 0,
            timestamp_ms: now_ms(),
            actor,
            kind,
            session_id: session_id.to_string(),
            action_digest: action_digest.to_string(),
            decision: decision.map(|d| d.summary().to_string()),
            detail: detail.into(),
            prev_hash: String::new(),
            hash: String::new(),
        };
        self.audit.append(event).ok()
    }

    /// Resolve and validate the lease chain (leaf → root), enforcing
    /// revocation, expiry, subject binding, and narrowing at every link.
    fn resolve_chain(&self, envelope: &ActionEnvelope) -> Result<LeaseRecord, DenyReason> {
        if envelope.lease_chain.is_empty() {
            return Err(DenyReason::no_lease("envelope carries no lease chain"));
        }
        let leases = self
            .leases
            .read()
            .map_err(|_| DenyReason::invalid_envelope("kernel lease registry unavailable"))?;
        let now = now_ms();
        let mut leaf: Option<&LeaseRecord> = None;
        let mut previous: Option<&LeaseRecord> = None;
        for lease_id in &envelope.lease_chain {
            let record = leases.get(lease_id).ok_or_else(|| {
                DenyReason::unknown_lease(format!("lease {lease_id} is not known to the kernel"))
            })?;
            if record.revoked {
                return Err(DenyReason::lease_revoked(format!(
                    "lease {lease_id} was revoked"
                )));
            }
            if now < record.not_before_ms || now > record.expires_at_ms {
                return Err(DenyReason::lease_expired(format!(
                    "lease {lease_id} is outside its validity window"
                )));
            }
            if let Some(child_record) = previous {
                // Parent link must match.
                if child_record.parent != Some(record.id) {
                    return Err(DenyReason::invalid_envelope(format!(
                        "lease chain link broken at {lease_id}"
                    )));
                }
                // Narrowing re-verified at evaluation time.
                for prefix in &child_record.path_prefixes {
                    if !record
                        .path_prefixes
                        .iter()
                        .any(|p| path_prefix_covers(p, prefix))
                    {
                        return Err(DenyReason::scope_exceeded(format!(
                            "child prefix '{prefix}' exceeds parent lease {lease_id}"
                        )));
                    }
                }
                if child_record.expires_at_ms > record.expires_at_ms {
                    return Err(DenyReason::scope_exceeded(format!(
                        "child expiry exceeds parent lease {lease_id}"
                    )));
                }
            } else {
                // First entry is the leaf: it must be bound to this session.
                if record.subject != envelope.session_id {
                    return Err(DenyReason::subject_mismatch(
                        "leaf lease subject does not match session".to_string(),
                    ));
                }
                leaf = Some(record);
            }
            previous = Some(record);
        }
        // The submitted chain must terminate at a root lease: accepting a
        // truncated chain would skip the ancestor revocation, expiry, and
        // narrowing checks that the loop above performs on the full chain.
        if previous
            .expect("non-empty chain checked above")
            .parent
            .is_some()
        {
            return Err(DenyReason::invalid_envelope(
                "lease chain does not terminate at a root lease".to_string(),
            ));
        }
        Ok(leaf.expect("non-empty chain checked above").clone())
    }

    fn evaluate_inner(&self, envelope: &ActionEnvelope) -> Result<PolicyDecision, DenyReason> {
        envelope
            .validate()
            .map_err(|e| DenyReason::invalid_envelope(e.to_string()))?;

        // Replay boundary: each nonce is single-use.
        {
            let mut seen = self
                .seen_nonces
                .lock()
                .map_err(|_| DenyReason::invalid_envelope("kernel nonce registry unavailable"))?;
            if !seen.insert(envelope.nonce.clone()) {
                return Err(DenyReason::replay_detected(
                    "envelope nonce was already used",
                ));
            }
        }

        if envelope.expires_at_ms <= now_ms() {
            return Err(DenyReason::expired_action("envelope expired"));
        }

        // Phase-0 canonical action: filesystem read.
        let leaf = self.resolve_chain(envelope)?;

        // The spike mediates one action class: bct.read_file on a leased path.
        let is_read = envelope.tool.name == "bct.read_file"
            && envelope.expected_effects.file_read
            && !envelope.expected_effects.file_write
            && !envelope.expected_effects.network_egress
            && !envelope.expected_effects.network_ingress
            && !envelope.expected_effects.process_spawn;
        if !is_read {
            return Err(DenyReason::scope_exceeded(format!(
                "tool '{}' is not covered by the phase-0 read policy",
                envelope.tool.name
            )));
        }
        if !leaf.verbs.iter().any(|v| v == "read") {
            return Err(DenyReason::scope_exceeded(
                "leaf lease does not grant the read verb",
            ));
        }
        let mut action_paths: Vec<String> = envelope
            .resources
            .paths
            .iter()
            .map(|p| canonical_path(&p.path).unwrap_or_default())
            .collect();
        // Also derive the path from arguments for the canonical read tool.
        if let Some(Value::String(arg_path)) = envelope.arguments.get("path")
            && let Ok(canon) = canonical_path(arg_path)
            && !action_paths.contains(&canon)
        {
            action_paths.push(canon);
        }
        if action_paths.is_empty() {
            return Err(DenyReason::invalid_envelope("read action names no path"));
        }
        for path in &action_paths {
            let covered = leaf
                .path_prefixes
                .iter()
                .any(|prefix| path_prefix_covers(prefix, path));
            if !covered {
                // No lease — but the path may be human-approvable.
                let approvable = self
                    .config
                    .approvable_roots
                    .iter()
                    .any(|root| path_prefix_covers(root, path));
                if approvable {
                    let full_digest = envelope.digest().unwrap_or_default();
                    let short = full_digest.get(..16).unwrap_or(&full_digest);
                    let approval_id = format!("apr-{short}");
                    return Ok(PolicyDecision::pending_approval(
                        approval_id,
                        format!("path '{path}' is outside the lease; human approval required"),
                    ));
                }
                return Err(DenyReason::scope_exceeded(format!(
                    "path '{path}' is outside the leaf lease scope"
                )));
            }
            let read_right = envelope
                .resources
                .paths
                .iter()
                .any(|p| p.rights == PathRights::Read);
            if !read_right {
                return Err(DenyReason::scope_exceeded(format!(
                    "path '{path}' is not requested with read rights"
                )));
            }
        }

        Ok(PolicyDecision::allow(vec![
            Obligation::TruncateOutput {
                max_bytes: self.config.default_max_output_bytes,
            },
            Obligation::RedactSecrets,
        ]))
    }
}

impl Kernel for LocalKernel {
    fn evaluate(&self, envelope: &ActionEnvelope) -> Result<PolicyDecision, KernelError> {
        Ok(self.evaluate_with_verdict_sequence(envelope)?.0)
    }
}

impl LocalKernel {
    /// Evaluate an action and return the audit sequence assigned to this
    /// evaluation's verdict event.
    ///
    /// The sequence comes from the exact audit append for this verdict, so
    /// concurrent evaluations cannot cause it to identify another action's
    /// event. A verdict with no durable audit event fails closed instead of
    /// succeeding silently.
    pub fn evaluate_with_verdict_sequence(
        &self,
        envelope: &ActionEnvelope,
    ) -> Result<(PolicyDecision, u64), KernelError> {
        let digest = envelope.digest().unwrap_or_else(|_| "none".to_string());
        let actor = AuditActor::Session {
            session_id: envelope.session_id.clone(),
        };
        let _ = self.audit(
            actor.clone(),
            AuditEventKind::ActionProposed,
            &envelope.session_id,
            &digest,
            None,
            format!("tool {}", envelope.tool.name),
        );
        match self.evaluate_inner(envelope) {
            Ok(decision) => {
                let kind = match &decision.outcome {
                    DecisionOutcome::Allow { .. } => AuditEventKind::PolicyAllowed,
                    DecisionOutcome::Deny { .. } => AuditEventKind::PolicyDenied,
                    DecisionOutcome::PendingApproval { .. } => AuditEventKind::ApprovalRequested,
                };
                let detail = match &decision.outcome {
                    DecisionOutcome::Allow { .. } => "within lease scope".to_string(),
                    DecisionOutcome::Deny { reason } => {
                        format!("{}: {}", reason.code, reason.detail)
                    }
                    DecisionOutcome::PendingApproval {
                        approval_id,
                        reason,
                    } => {
                        format!("{approval_id}: {reason}")
                    }
                };
                self.audit(
                    actor,
                    kind,
                    &envelope.session_id,
                    &digest,
                    Some(&decision),
                    detail,
                )
                .ok_or_else(|| KernelError::Internal("audit log unavailable".to_string()))
                .map(|sequence| (decision, sequence))
            }
            Err(reason) => {
                let decision = PolicyDecision::deny(reason);
                let detail = match &decision.outcome {
                    DecisionOutcome::Deny { reason } => {
                        format!("{}: {}", reason.code, reason.detail)
                    }
                    _ => unreachable!(),
                };
                self.audit(
                    actor,
                    AuditEventKind::PolicyDenied,
                    &envelope.session_id,
                    &digest,
                    Some(&decision),
                    detail,
                )
                .ok_or_else(|| KernelError::Internal("audit log unavailable".to_string()))
                .map(|sequence| (decision, sequence))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Authenticated local transport
// ---------------------------------------------------------------------------
//
// The kernel listens on a Unix domain socket. Peers are validated twice:
//  1. `SO_PEERCRED`: the peer's uid must equal the kernel process's uid, and
//     (when the host knows it) the peer pid must equal the Pi subprocess pid.
//  2. A per-session nonce delivered to the Pi process out-of-band (child
//     environment). Every wire request presents it; requests without it are
//     rejected and audited as `TransportRejected`.
//
// The threat model here is the *model/extension*, not a hostile local user:
// the nonce keeps a confused or replaced extension from impersonating the
// kernel's client, while the kernel still re-checks every lease itself.

/// Peer identity required by the kernel listener.
#[derive(Clone, Copy, Debug)]
pub struct PeerPolicy {
    /// Required peer uid (normally the kernel process's own uid).
    pub uid: u32,
    /// Required peer pid, when the host knows the Pi subprocess pid.
    pub pid: Option<u32>,
}

impl PeerPolicy {
    /// Accept only peers running as the current process's user.
    pub fn current_user() -> Self {
        Self {
            uid: current_uid(),
            pid: None,
        }
    }

    /// Accept only the given pid running as the current user.
    pub fn subprocess(pid: u32) -> Self {
        Self {
            uid: current_uid(),
            pid: Some(pid),
        }
    }
}

fn current_uid() -> u32 {
    // SAFETY: getuid has no failure modes.
    unsafe { libc::getuid() }
}

/// One request on the kernel wire: JSONL, one object per line.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelWireRequest {
    pub protocol: String,
    pub credential: String,
    pub envelope: ActionEnvelope,
}

/// One response on the kernel wire.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KernelWireResponse {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<PolicyDecision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<WireError>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WireError {
    pub code: String,
    pub detail: String,
}

impl KernelWireResponse {
    fn ok(decision: PolicyDecision, audit_sequence: u64, action_digest: String) -> Self {
        Self {
            protocol: KERNEL_WIRE_PROTOCOL.to_string(),
            decision: Some(decision),
            audit_sequence: Some(audit_sequence),
            action_digest: Some(action_digest),
            error: None,
        }
    }

    fn err(code: &str, detail: impl Into<String>) -> Self {
        Self {
            protocol: KERNEL_WIRE_PROTOCOL.to_string(),
            decision: None,
            audit_sequence: None,
            action_digest: None,
            error: Some(WireError {
                code: code.to_string(),
                detail: detail.into(),
            }),
        }
    }
}

/// What the host hands to the Pi subprocess: where the kernel listens and
/// the nonce that authenticates the extension to it.
#[derive(Clone, Debug)]
pub struct KernelEndpoint {
    pub socket_path: PathBuf,
    pub nonce: String,
}

/// The kernel's authenticated local listener.
///
/// Binds a Unix socket, validates every peer, serves [`Kernel`] evaluations
/// as JSONL request/response pairs, and audits transport rejections.
pub struct KernelListener {
    endpoint: KernelEndpoint,
    shutdown_tx: tokio::sync::oneshot::Sender<()>,
    join: tokio::task::JoinHandle<()>,
}

impl KernelListener {
    /// Bind `socket_path` and start serving `kernel`. Any stale socket file
    /// at the path is removed first.
    pub async fn bind(
        kernel: Arc<LocalKernel>,
        socket_path: PathBuf,
        peer: PeerPolicy,
    ) -> Result<Self, KernelError> {
        if socket_path.exists() {
            std::fs::remove_file(&socket_path)
                .map_err(|e| KernelError::Transport(format!("remove stale socket: {e}")))?;
        }
        if let Some(parent) = socket_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| KernelError::Transport(format!("create socket dir: {e}")))?;
        }
        let listener = tokio::net::UnixListener::bind(&socket_path)
            .map_err(|e| KernelError::Transport(format!("bind unix socket: {e}")))?;
        let nonce = Uuid::new_v4().to_string();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let endpoint = KernelEndpoint {
            socket_path: socket_path.clone(),
            nonce,
        };
        let endpoint_for_task = endpoint.clone();

        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                let kernel = kernel.clone();
                                let peer = peer;
                                let credential = endpoint_for_task.nonce.clone();
                                tokio::spawn(async move {
                                    serve_connection(kernel, stream, peer, &credential).await;
                                });
                            }
                            Err(e) => {
                                eprintln!("kernel listener accept error: {e}");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            endpoint,
            shutdown_tx,
            join,
        })
    }

    pub fn endpoint(&self) -> &KernelEndpoint {
        &self.endpoint
    }

    pub async fn shutdown(self) -> Result<(), KernelError> {
        let _ = self.shutdown_tx.send(());
        self.join
            .await
            .map_err(|e| KernelError::Transport(format!("listener task failed: {e}")))?;
        let _ = std::fs::remove_file(&self.endpoint.socket_path);
        Ok(())
    }
}

async fn serve_connection(
    kernel: Arc<LocalKernel>,
    stream: tokio::net::UnixStream,
    peer: PeerPolicy,
    expected_credential: &str,
) {
    // 1. Peer-process validation.
    let peer_ok = stream
        .peer_cred()
        .ok()
        .map(|cred| {
            let uid_ok = cred.uid() == peer.uid;
            let pid_ok = peer
                .pid
                .map(|p| cred.pid() == Some(p as i32))
                .unwrap_or(true);
            uid_ok && pid_ok
        })
        .unwrap_or(false);
    if !peer_ok {
        let _ = kernel.audit(
            AuditActor::Kernel,
            AuditEventKind::TransportRejected,
            "",
            "none",
            None,
            "peer credential validation failed",
        );
        return;
    }

    let (reader, mut writer) = stream.into_split();
    // Bound the inbound record BEFORE any allocation: `take` caps the byte
    // stream at KERNEL_MAX_RECORD_BYTES + 1, so `next_line` can never grow
    // its internal buffer past the limit even when the peer never sends a
    // newline. (Without this, the length check below runs only after the
    // complete line is already allocated, letting a peer exhaust kernel
    // memory first.)
    let bounded = {
        use tokio::io::AsyncReadExt;
        reader.take(KERNEL_MAX_RECORD_BYTES as u64 + 1)
    };
    let mut lines = {
        use tokio::io::AsyncBufReadExt;
        tokio::io::BufReader::new(bounded).lines()
    };

    loop {
        let line = match lines.next_line().await {
            Ok(Some(line)) => line,
            Ok(None) => return, // EOF
            Err(_) => return,
        };
        if line.len() > KERNEL_MAX_RECORD_BYTES {
            let response = KernelWireResponse::err("record_too_large", "record exceeds 1 MiB");
            let _ = write_response(&mut writer, &response).await;
            let _ = kernel.audit(
                AuditActor::Kernel,
                AuditEventKind::TransportRejected,
                "",
                "none",
                None,
                "wire record exceeded size limit",
            );
            return;
        }
        let request: KernelWireRequest = match serde_json::from_str(&line) {
            Ok(request) => request,
            Err(e) => {
                let response = KernelWireResponse::err("malformed_request", e.to_string());
                let _ = write_response(&mut writer, &response).await;
                continue;
            }
        };
        if request.protocol != KERNEL_WIRE_PROTOCOL {
            let response = KernelWireResponse::err(
                "protocol_mismatch",
                format!("expected {KERNEL_WIRE_PROTOCOL}"),
            );
            let _ = write_response(&mut writer, &response).await;
            continue;
        }
        // 2. Nonce authentication (constant-time comparison).
        if !constant_time_eq(
            request.credential.as_bytes(),
            expected_credential.as_bytes(),
        ) {
            let _ = kernel.audit(
                AuditActor::Kernel,
                AuditEventKind::TransportRejected,
                &request.envelope.session_id,
                "none",
                None,
                "bad kernel credential",
            );
            let response = KernelWireResponse::err("authentication_failed", "bad credential");
            let _ = write_response(&mut writer, &response).await;
            continue;
        }
        let action_digest = request
            .envelope
            .digest()
            .unwrap_or_else(|_| "none".to_string());
        match kernel.evaluate_with_verdict_sequence(&request.envelope) {
            Ok((decision, sequence)) => {
                let response = KernelWireResponse::ok(decision, sequence, action_digest);
                let _ = write_response(&mut writer, &response).await;
            }
            Err(e) => {
                let response = KernelWireResponse::err("kernel_error", e.to_string());
                let _ = write_response(&mut writer, &response).await;
            }
        }
    }
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    response: &KernelWireResponse,
) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut bytes = serde_json::to_vec(response)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    bytes.push(b'\n');
    writer.write_all(&bytes).await?;
    writer.flush().await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// In-process transport (tests)
// ---------------------------------------------------------------------------

/// Direct in-process [`Kernel`] access for unit tests: same contract shapes,
/// no socket.
#[derive(Clone)]
pub struct InProcessKernel {
    kernel: Arc<LocalKernel>,
}

impl InProcessKernel {
    pub fn new(kernel: Arc<LocalKernel>) -> Self {
        Self { kernel }
    }

    pub fn round_trip(
        &self,
        credential: &str,
        expected_credential: &str,
        envelope: &ActionEnvelope,
    ) -> Result<KernelWireResponse, WireError> {
        if !constant_time_eq(credential.as_bytes(), expected_credential.as_bytes()) {
            return Err(WireError {
                code: "authentication_failed".to_string(),
                detail: "bad credential".to_string(),
            });
        }
        let action_digest = envelope.digest().unwrap_or_else(|_| "none".to_string());
        match self.kernel.evaluate_with_verdict_sequence(envelope) {
            Ok((decision, sequence)) => {
                Ok(KernelWireResponse::ok(decision, sequence, action_digest))
            }
            Err(e) => Err(WireError {
                code: "kernel_error".to_string(),
                detail: e.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_envelope(session_id: &str, path: &str, lease_chain: Vec<LeaseId>) -> ActionEnvelope {
        let mut arguments = BTreeMap::new();
        arguments.insert("path".to_string(), Value::String(path.to_string()));
        ActionEnvelope {
            version: ACTION_ENVELOPE_VERSION,
            action_id: Uuid::new_v4(),
            session_id: session_id.to_string(),
            tool: ToolRef {
                name: "bct.read_file".to_string(),
                version: "1".to_string(),
            },
            arguments,
            inputs: vec![],
            resources: ResourceSet {
                paths: vec![PathResource {
                    path: path.to_string(),
                    rights: PathRights::Read,
                }],
                network: vec![],
                secrets: vec![],
            },
            expected_effects: EffectClasses {
                file_read: true,
                file_write: false,
                network_egress: false,
                network_ingress: false,
                process_spawn: false,
            },
            lease_chain,
            nonce: Uuid::new_v4().to_string(),
            expires_at_ms: now_ms() + 60_000,
        }
    }

    fn test_kernel() -> (Arc<LocalKernel>, LeaseId) {
        let kernel = Arc::new(LocalKernel::new(LocalKernelConfig {
            approvable_roots: vec!["/tmp/lumen-approvable".to_string()],
            ..Default::default()
        }));
        let lease = kernel
            .issue_root_lease(
                "session-test",
                vec!["/tmp/lumen-leased".to_string()],
                vec!["read".to_string()],
                now_ms() + 3_600_000,
            )
            .expect("issue root lease");
        (kernel, lease)
    }

    #[test]
    fn canonical_form_is_digest_stable() {
        let a = json!({"z": 1, "a": {"n": 2, "m": 1}, "list": [3, 2, 1]});
        let b = json!({"list": [3, 2, 1], "a": {"m": 1, "n": 2}, "z": 1});
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(canonical_digest(&a).unwrap(), canonical_digest(&b).unwrap());
        // No whitespace, keys sorted.
        assert_eq!(
            String::from_utf8(canonical_json(&a).unwrap()).unwrap(),
            r#"{"a":{"m":1,"n":2},"list":[3,2,1],"z":1}"#
        );
    }

    #[test]
    fn canonical_form_rejects_floats() {
        let v = json!({"x": 1.5});
        assert!(matches!(
            canonical_json(&v),
            Err(BoundaryError::NonCanonicalValue(_))
        ));
    }

    #[test]
    fn envelope_digest_is_stable_and_sensitive() {
        let (kernel, lease) = test_kernel();
        let e1 = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![lease]);
        let mut e2 = e1.clone();
        // Same logical envelope, different serialization order of arguments.
        e2.arguments = {
            let mut m = BTreeMap::new();
            m.insert(
                "path".to_string(),
                Value::String("/tmp/lumen-leased/a.txt".to_string()),
            );
            m
        };
        assert_eq!(e1.digest().unwrap(), e2.digest().unwrap());

        // Any mutation changes the digest.
        e2.arguments.insert(
            "path".to_string(),
            Value::String("/tmp/lumen-leased/b.txt".to_string()),
        );
        assert_ne!(e1.digest().unwrap(), e2.digest().unwrap());
        let _ = kernel;
    }

    #[test]
    fn envelope_validation_rejects_bad_versions_and_paths() {
        let (_, lease) = test_kernel();
        let mut e = test_envelope("s", "/tmp/lumen-leased/a.txt", vec![lease]);
        e.version = 99;
        assert!(e.validate().is_err());
        e.version = ACTION_ENVELOPE_VERSION;
        e.resources.paths[0].path = "relative/path".to_string();
        assert!(e.validate().is_err());
    }

    #[test]
    fn kernel_allows_read_within_lease() {
        let (kernel, lease) = test_kernel();
        let envelope = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![lease]);
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        assert!(decision.is_allow());
        assert_eq!(decision.summary(), "allow");
        match &decision.outcome {
            DecisionOutcome::Allow { obligations } => {
                assert!(obligations.contains(&Obligation::RedactSecrets));
            }
            _ => panic!("expected allow"),
        }
        // Two audit events: proposed + allowed.
        assert_eq!(kernel.audit_log().len(), 2);
        kernel.audit_log().verify().expect("audit chain verifies");
    }

    #[test]
    fn kernel_denies_read_outside_lease() {
        let (kernel, lease) = test_kernel();
        let envelope = test_envelope("session-test", "/etc/passwd", vec![lease]);
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        assert!(!decision.is_allow());
        match &decision.outcome {
            DecisionOutcome::Deny { reason } => {
                assert_eq!(reason.code, "scope_exceeded");
            }
            other => panic!("expected deny, got {other:?}"),
        }
        kernel.audit_log().verify().expect("audit chain verifies");
    }

    #[test]
    fn kernel_returns_pending_for_approvable_path() {
        let (kernel, lease) = test_kernel();
        let envelope = test_envelope(
            "session-test",
            "/tmp/lumen-approvable/notes.txt",
            vec![lease],
        );
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        match &decision.outcome {
            DecisionOutcome::PendingApproval { approval_id, .. } => {
                assert!(approval_id.starts_with("apr-"));
            }
            other => panic!("expected pending, got {other:?}"),
        }
        assert_eq!(decision.summary(), "pending");
    }

    #[test]
    fn kernel_denies_with_no_lease_chain() {
        let (kernel, _) = test_kernel();
        let envelope = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![]);
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        match &decision.outcome {
            DecisionOutcome::Deny { reason } => assert_eq!(reason.code, "no_lease_for_action"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn kernel_denies_unknown_lease() {
        let (kernel, _) = test_kernel();
        let envelope = test_envelope(
            "session-test",
            "/tmp/lumen-leased/a.txt",
            vec![LeaseId::new()],
        );
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        match &decision.outcome {
            DecisionOutcome::Deny { reason } => assert_eq!(reason.code, "unknown_lease"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn kernel_denies_replayed_nonce() {
        let (kernel, lease) = test_kernel();
        let envelope = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![lease]);
        let first = kernel.evaluate(&envelope).expect("evaluate");
        assert!(first.is_allow());
        // Same nonce again → deny, no effect.
        let second = kernel.evaluate(&envelope).expect("evaluate");
        match &second.outcome {
            DecisionOutcome::Deny { reason } => assert_eq!(reason.code, "replay_detected"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn kernel_denies_revoked_lease() {
        let (kernel, lease) = test_kernel();
        kernel.revoke_lease(lease).expect("revoke");
        let envelope = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![lease]);
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        match &decision.outcome {
            DecisionOutcome::Deny { reason } => assert_eq!(reason.code, "lease_revoked"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn kernel_denies_subject_mismatch() {
        let (kernel, lease) = test_kernel();
        let envelope = test_envelope("session-impostor", "/tmp/lumen-leased/a.txt", vec![lease]);
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        match &decision.outcome {
            DecisionOutcome::Deny { reason } => assert_eq!(reason.code, "subject_mismatch"),
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn kernel_denies_path_traversal_escape() {
        let (kernel, lease) = test_kernel();
        // Lexical canonicalization collapses the traversal; the resolved path
        // is outside the lease → deny.
        let envelope = test_envelope(
            "session-test",
            "/tmp/lumen-leased/../secret.txt",
            vec![lease],
        );
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        assert!(!decision.is_allow());
    }

    #[test]
    fn child_lease_narrowing_is_enforced() {
        let (kernel, root) = test_kernel();
        // Valid child.
        let child = kernel
            .issue_child_lease(
                root,
                "session-child",
                vec!["/tmp/lumen-leased/sub".to_string()],
                vec!["read".to_string()],
                now_ms() + 1_000_000,
            )
            .expect("issue child");
        // Child wider than parent → refused at issuance.
        assert!(
            kernel
                .issue_child_lease(
                    root,
                    "session-child",
                    vec!["/tmp/other".to_string()],
                    vec!["read".to_string()],
                    now_ms() + 1_000_000,
                )
                .is_err()
        );
        // Child with longer expiry → refused.
        assert!(
            kernel
                .issue_child_lease(
                    root,
                    "session-child",
                    vec!["/tmp/lumen-leased/sub".to_string()],
                    vec!["read".to_string()],
                    now_ms() + 3_600_000 + 1,
                )
                .is_err()
        );
        // Chain leaf→root evaluates within the child scope.
        let envelope = test_envelope(
            "session-child",
            "/tmp/lumen-leased/sub/f.txt",
            vec![child, root],
        );
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        assert!(decision.is_allow());
        // ...but not outside the child scope, even though the root allows it.
        let envelope2 = test_envelope(
            "session-child",
            "/tmp/lumen-leased/other.txt",
            vec![child, root],
        );
        let decision2 = kernel.evaluate(&envelope2).expect("evaluate");
        assert!(!decision2.is_allow());
    }

    #[test]
    fn truncated_lease_chain_is_rejected() {
        let (kernel, root) = test_kernel();
        let child = kernel
            .issue_child_lease(
                root,
                "session-child",
                vec!["/tmp/lumen-leased/sub".to_string()],
                vec!["read".to_string()],
                now_ms() + 1_000_000,
            )
            .expect("issue child");
        // The child is still valid, but the submitted chain does not
        // terminate at a root lease: accepting it would bypass ancestor
        // revocation, expiry, and narrowing.
        let envelope = test_envelope("session-child", "/tmp/lumen-leased/sub/f.txt", vec![child]);
        let decision = kernel.evaluate(&envelope).expect("evaluate");
        assert!(
            !decision.is_allow(),
            "truncated lease chain must not produce an allow"
        );
    }

    #[test]
    fn verdict_sequences_are_per_evaluation_under_concurrency() {
        let (kernel, _lease) = test_kernel();
        // One root lease per thread so subjects stay distinct; the point is
        // the audit log, which is shared.
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let kernel = kernel.clone();
                std::thread::spawn(move || {
                    let lease = kernel
                        .issue_root_lease(
                            format!("session-{i}"),
                            vec!["/tmp/lumen-leased".to_string()],
                            vec!["read".to_string()],
                            now_ms() + 3_600_000,
                        )
                        .expect("issue root lease");
                    let envelope = test_envelope(
                        &format!("session-{i}"),
                        "/tmp/lumen-leased/a.txt",
                        vec![lease],
                    );
                    let digest = envelope.digest().unwrap_or_else(|_| "none".to_string());
                    let (decision, sequence) = kernel
                        .evaluate_with_verdict_sequence(&envelope)
                        .expect("evaluate");
                    assert!(decision.is_allow());
                    (digest, sequence)
                })
            })
            .collect();
        let results: Vec<(String, u64)> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // Every returned sequence must identify its own evaluation's verdict
        // event — never a concurrent evaluation's.
        for (digest, sequence) in &results {
            let event = kernel
                .audit_log()
                .get(*sequence)
                .expect("verdict sequence must exist in the log");
            assert_eq!(
                &event.action_digest, digest,
                "sequence {sequence} points at another evaluation's event"
            );
            assert!(
                matches!(event.kind, AuditEventKind::PolicyAllowed),
                "sequence {sequence} is not a verdict event"
            );
        }
        let mut sequences: Vec<u64> = results.iter().map(|(_, s)| *s).collect();
        sequences.sort_unstable();
        sequences.dedup();
        assert_eq!(sequences.len(), results.len(), "sequences must be distinct");
    }

    #[test]
    fn audit_chain_detects_tampering() {
        let (kernel, lease) = test_kernel();
        let envelope = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![lease]);
        kernel.evaluate(&envelope).expect("evaluate");
        kernel.audit_log().verify().expect("chain verifies");
        // Tamper with a stored event: verification must fail.
        {
            let mut events = kernel.audit_log().inner.lock().unwrap();
            events[0].detail = "forged".to_string();
        }
        assert!(kernel.audit_log().verify().is_err());
    }

    #[test]
    fn in_process_transport_rejects_bad_credential() {
        let (kernel, lease) = test_kernel();
        let transport = InProcessKernel::new(kernel);
        let envelope = test_envelope("session-test", "/tmp/lumen-leased/a.txt", vec![lease]);
        let err = transport
            .round_trip("wrong-nonce", "right-nonce", &envelope)
            .expect_err("bad credential must fail");
        assert_eq!(err.code, "authentication_failed");
        let ok = transport
            .round_trip("right-nonce", "right-nonce", &envelope)
            .expect("good credential");
        assert!(ok.decision.expect("decision").is_allow());
    }

    #[test]
    fn path_prefix_cover_rules() {
        assert!(path_prefix_covers("/", "/anything/at/all"));
        assert!(path_prefix_covers("/a/b", "/a/b"));
        assert!(path_prefix_covers("/a/b", "/a/b/c"));
        assert!(!path_prefix_covers("/a/b", "/a/bc"));
        assert!(!path_prefix_covers("/a/b", "/a"));
    }

    #[test]
    fn canonical_path_normalizes_lexically() {
        assert_eq!(canonical_path("/a/b/../c").unwrap(), "/a/c");
        assert_eq!(canonical_path("/a/./b").unwrap(), "/a/b");
        assert_eq!(canonical_path("/").unwrap(), "/");
        assert!(canonical_path("relative").is_err());
    }

    #[test]
    fn policy_decision_has_no_default_allow_shape() {
        // The wire shape requires an explicit decision tag; a missing or
        // unknown tag must fail deserialization (fail closed).
        let bad = json!({"version": 1});
        assert!(serde_json::from_value::<PolicyDecision>(bad).is_err());
        let unknown = json!({"version": 1, "decision": "maybe"});
        assert!(serde_json::from_value::<PolicyDecision>(unknown).is_err());
    }
}
