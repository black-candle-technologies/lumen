//! Kernel client seam: v1 host<->kernel contracts and the [`KernelClient`] trait.
//!
//! The host (lumen-server) never implements policy itself. Every effect the
//! host wants to run is described as an [`ActionEnvelope`] v1, sent to the
//! kernel, and answered with a [`PolicyDecision`] v1. The contract shapes
//! below mirror the Phase-1 authority kernel's `lumen-protocol` definitions
//! (see `origin/lumen-rebuild/phase-1-authority-kernel`,
//! `crates/lumen-protocol/src/{action_envelope,policy_decision}.rs`); they
//! are duplicated here rather than imported because the base commit this
//! branch builds on predates that crate. The coordinator wires a real
//! kernel implementation behind this trait at integration time.
//!
//! Contract rules (from the plan's tables):
//! - `ActionEnvelope`: action + resources + inputs + effects + lease chain in,
//!   `PolicyDecision`: allow / deny / pending + reason + obligations out.
//! - There is no default allow. A decision must be explicitly bound to the
//!   envelope digest it answers ([`PolicyDecision::bind`]).
//! - Audit append is part of the seam: if the audit write fails the effect
//!   must not be treated as committed (fail closed).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    future::Future,
    pin::Pin,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

/// Contract version for [`ActionEnvelope`].
pub const ACTION_ENVELOPE_VERSION: u32 = 1;
/// Contract version for [`PolicyDecision`].
pub const POLICY_DECISION_VERSION: u32 = 1;
/// Contract version for [`LeaseDocument`].
pub const LEASE_DOCUMENT_VERSION: u32 = 1;

/// Stable tool identity: name plus pinned version. Floating tool versions
/// are never used across the trust boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRef {
    pub name: String,
    pub version: String,
}

/// Declared effect classes. The kernel authorizes classes, never prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// Read-only inspection (no mutation).
    Read,
    /// Filesystem mutation inside leased roots.
    Write,
    /// Network egress to a leased destination.
    Network,
    /// Execution of code in the sandbox.
    Execute,
    /// Use of a brokered secret by reference.
    SecretUse,
    /// Sending a message through a messaging adapter.
    MessageSend,
}

/// Resources the action may touch. All values are pre-canonicalization
/// inputs; the kernel canonicalizes (symlinks, mounts, hostnames) before
/// comparing against the lease.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceSet {
    /// Filesystem paths (absolute; kernel resolves symlinks/mounts).
    #[serde(default)]
    pub paths: Vec<String>,
    /// Network destinations as `scheme://host:port`.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Opaque secret references (never plaintext).
    #[serde(default)]
    pub secret_refs: Vec<String>,
}

/// ActionEnvelope v1: the canonical description of one requested effect.
///
/// Produced by the host from a Pi tool request; decided on by the kernel.
/// The SHA-256 digest of the canonical envelope is the approval target for
/// VHL, the primary audit key, and the replay-protection boundary.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionEnvelope {
    pub protocol_version: u32,
    /// UUID v4 identifying this action attempt.
    pub action_id: String,
    /// Session subject: the ephemeral Courier address for the session.
    pub session_id: String,
    pub tool: ToolRef,
    /// Canonical typed tool payload.
    pub arguments: serde_json::Value,
    /// Content hashes of inputs the action depends on (repo snapshot, files).
    #[serde(default)]
    pub input_hashes: Vec<String>,
    pub resources: ResourceSet,
    /// Lease identifiers from leaf to root; kernel proves the chain.
    #[serde(default)]
    pub lease_chain: Vec<String>,
    /// Fresh random nonce; single-use envelopes are replay-protected on
    /// (action_id, nonce).
    pub nonce: String,
    /// RFC 3339 hard deadline for starting the action.
    pub expires_at: String,
    /// Declared effect classes; execution must not exceed these.
    pub expected_effects: Vec<EffectClass>,
}

#[derive(Debug, Error)]
pub enum EnvelopeError {
    #[error("unsupported protocol version {0}; expected {1}")]
    VersionMismatch(u32, u32),
    #[error("invalid action_id: {0}")]
    BadActionId(String),
    #[error("invalid expires_at timestamp: {0}")]
    BadExpiry(String),
    #[error("empty tool name")]
    EmptyToolName,
    #[error("effect class not representable at the kernel boundary: {0}")]
    UnsupportedEffect(String),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
}

impl ActionEnvelope {
    /// Structural validation: versions, UUID shape, timestamp shape.
    /// Semantic validation (lease coverage) is the kernel's job.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.protocol_version != ACTION_ENVELOPE_VERSION {
            return Err(EnvelopeError::VersionMismatch(
                self.protocol_version,
                ACTION_ENVELOPE_VERSION,
            ));
        }
        Uuid::parse_str(&self.action_id)
            .map_err(|_| EnvelopeError::BadActionId(self.action_id.clone()))?;
        parse_rfc3339(&self.expires_at)
            .ok_or_else(|| EnvelopeError::BadExpiry(self.expires_at.clone()))?;
        if self.tool.name.trim().is_empty() {
            return Err(EnvelopeError::EmptyToolName);
        }
        Ok(())
    }

    /// SHA-256 hex digest of the canonical JSON encoding of this envelope.
    pub fn digest(&self) -> Result<String, EnvelopeError> {
        let value =
            serde_json::to_value(self).map_err(|e| EnvelopeError::Deserialize(e.to_string()))?;
        Ok(sha256_hex(canonical_json(&value).as_bytes()))
    }
}

/// Obligations the host must satisfy while executing an allowed action
/// (e.g. "stream output to audit", "enforce 60s deadline").
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Obligation {
    pub kind: String,
    pub params: serde_json::Value,
}

/// The kernel's answer. Explicit: allow, deny, or pending human approval.
/// There is deliberately no "default allow".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Decision {
    Allow {
        /// The leaf lease that authorizes this action.
        lease_id: String,
        #[serde(default)]
        obligations: Vec<Obligation>,
    },
    Deny {
        reason: String,
    },
    PendingApproval {
        approval_request_id: String,
        reason: String,
    },
}

/// PolicyDecision v1: the kernel's answer to an [`ActionEnvelope`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDecision {
    pub protocol_version: u32,
    /// Digest of the [`ActionEnvelope`] this decision answers.
    pub action_digest: String,
    pub decision: Decision,
    /// RFC 3339 timestamp of the decision.
    pub decided_at: String,
}

#[derive(Debug, Error)]
pub enum DecisionError {
    #[error("unsupported protocol version {0}; expected {1}")]
    VersionMismatch(u32, u32),
    #[error("decision answers digest {0}, not the presented envelope")]
    DigestMismatch(String),
    #[error("deserialization failed: {0}")]
    Deserialize(String),
}

impl PolicyDecision {
    /// Bind the decision to the envelope it answers. A decision presented
    /// for a different envelope digest is rejected: this is what makes
    /// approval replay and decision substitution fail closed.
    pub fn bind(&self, envelope: &ActionEnvelope) -> Result<(), DecisionError> {
        if self.protocol_version != POLICY_DECISION_VERSION {
            return Err(DecisionError::VersionMismatch(
                self.protocol_version,
                POLICY_DECISION_VERSION,
            ));
        }
        let digest = envelope
            .digest()
            .map_err(|e| DecisionError::Deserialize(e.to_string()))?;
        if digest != self.action_digest {
            return Err(DecisionError::DigestMismatch(self.action_digest.clone()));
        }
        Ok(())
    }

    pub fn is_allow(&self) -> bool {
        matches!(self.decision, Decision::Allow { .. })
    }
}

/// Lease limits carried on a lease, mirroring the Phase-1 kernel's
/// `lumen_core::lease::LeaseLimits` field-for-field.
///
/// `budget` is the kernel's `Budget` map (dimension → cap) kept opaque: the
/// host renders it for approval UX and passes it back, but never
/// re-interprets caps. `max_executions` bounds how many actions the lease
/// may authorize; `single_use` marks one-shot grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseLimits {
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub budget: serde_json::Value,
    #[serde(default)]
    pub max_executions: Option<u64>,
    pub single_use: bool,
}

/// LeaseDocument v1 (host view), mirroring the Phase-1 kernel's
/// `lumen_core::lease::LeaseDocument` field-for-field.
///
/// `scope` is the kernel's `ResourceScope` kept opaque: the kernel
/// interprets it for subset proofs; the host renders it for approval UX
/// and never re-invents the scope grammar. Signature verification happens
/// kernel-side through [`KernelClient::verify_lease`]; the host never
/// re-implements signature checks from untrusted input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseDocument {
    pub protocol_version: u32,
    pub lease_id: String,
    pub parent_id: Option<String>,
    pub subject: String,
    pub issuer_key_id: String,
    pub issued_at_ms: i64,
    pub scope: serde_json::Value,
    pub limits: LeaseLimits,
    pub depth: u32,
    pub depth_limit: u32,
    pub lease_nonce: String,
    /// Hex-encoded Ed25519 signature over the canonical signing bytes.
    pub signature: String,
}

/// Result of [`KernelClient::verify_lease`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseVerification {
    pub lease_id: String,
    pub subject: String,
    pub verified_at_ms: i64,
    /// True when the kernel reports this lease revoked.
    pub revoked: bool,
}

/// A human VHL approval grant, mirroring the Phase-1 kernel's
/// `lumen_core::lease::OneShotGrant` field-for-field.
///
/// The human VHL key signs the grant over its canonical bytes (every field
/// except `signature`); the kernel verifies the signature, the digest
/// binding, expiry, and nonce before minting the single-use lease. The
/// host carries the grant; it never mints authority from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OneShotGrant {
    pub approval_id: String,
    pub action_digest: String,
    pub session_subject: String,
    /// Key id of the human VHL key that signed this grant.
    pub signer_key_id: String,
    pub nonce: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    /// Hex Ed25519 signature by the human VHL key over the canonical grant.
    pub signature: String,
}

/// A kernel audit event as submitted by the host.
///
/// Provider payloads are redacted BEFORE construction: `payload` must
/// contain only normalized, non-sensitive fields (see
/// `model_gateway::redacted_audit_record`). The kernel appends to the
/// hash-chained log and returns the durable reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEvent {
    pub kind: String,
    pub session_id: String,
    /// Digest of the action this event describes, when applicable.
    #[serde(default)]
    pub action_digest: Option<String>,
    pub payload: serde_json::Value,
}

/// Durable reference returned by the kernel for a persisted audit event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRef {
    pub event_id: String,
    pub chain_hash: String,
}

/// Errors from the kernel seam. Every variant fails closed: the host must
/// not treat the associated effect as authorized or committed.
#[derive(Debug, Error)]
pub enum KernelError {
    #[error("kernel unavailable: {0}")]
    Unavailable(String),
    #[error("kernel request timed out")]
    Timeout,
    #[error("kernel protocol error: {0}")]
    Protocol(String),
    #[error("envelope invalid: {0}")]
    BadEnvelope(#[from] EnvelopeError),
    #[error("decision failed to bind: {0}")]
    BadDecision(#[from] DecisionError),
    #[error("lease verification failed: {0}")]
    VerificationFailed(String),
    #[error("lease {0} is revoked")]
    Revoked(String),
    #[error("audit write failed: {0}")]
    AuditFailed(String),
    #[error("one-shot lease request rejected: {0}")]
    OneShotRejected(String),
}

/// Boxed future for [`KernelClient`] methods (the trait must stay
/// object-safe so the coordinator can hold `Arc<dyn KernelClient>`).
pub type KernelFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, KernelError>> + Send + 'a>>;

/// The kernel seam. The host implements ALL policy-adjacent work against
/// this trait; the coordinator wires it to the real kernel at integration.
///
/// Implementations must be fail-closed: on any error the caller treats the
/// effect as neither authorized nor committed.
pub trait KernelClient: Send + Sync {
    /// Ask the kernel to decide on an action envelope.
    fn decide<'a>(&'a self, envelope: &'a ActionEnvelope) -> KernelFuture<'a, PolicyDecision>;

    /// Verify a lease document: signature, liveness, revocation.
    fn verify_lease<'a>(&'a self, lease: &'a LeaseDocument) -> KernelFuture<'a, LeaseVerification>;

    /// Request a one-shot lease from a VHL approval grant.
    fn request_one_shot_lease<'a>(
        &'a self,
        grant: &'a OneShotGrant,
    ) -> KernelFuture<'a, LeaseDocument>;

    /// Revoke every lease held by a session subject. Called at session
    /// termination AFTER the session identity is destroyed through
    /// [`SessionIdentityAuthority`]: a destroyed identity cannot mint new
    /// leases while revocation is in flight.
    fn revoke_session<'a>(&'a self, session_subject: &'a str) -> KernelFuture<'a, ()>;

    /// Append an audit event. On failure the host must NOT commit the
    /// effect the event describes.
    fn append_audit<'a>(&'a self, event: &'a AuditEvent) -> KernelFuture<'a, AuditRef>;
}

/// Identity seam: per-session ephemeral Courier identities minted and
/// destroyed inside kernel-controlled memory (phase-4 vault).
///
/// This is deliberately separate from [`KernelClient`] (whose v1 contract
/// is frozen): identity lifecycle is authority-plane work the supervisor
/// drives, and the real engine implements both traits against the same
/// vault + session registry the kernel authorizes against.
pub trait SessionIdentityAuthority: Send + Sync {
    /// Mint a fresh ephemeral session identity (`ed25519:` subject),
    /// optionally as a child of a live parent subject.
    fn start_session_identity<'a>(
        &'a self,
        parent: Option<&'a str>,
    ) -> KernelFuture<'a, SessionIdentityInfo>;

    /// Destroy a session's root identity and every vault-known
    /// descendant: private keys are zeroized, registry records
    /// deactivated. Returns every affected subject so the supervisor can
    /// revoke their leases. Idempotent across retries for the same
    /// subject.
    fn destroy_session_identity<'a>(
        &'a self,
        subject: &'a str,
    ) -> KernelFuture<'a, SessionEndReport>;
}

/// The full authority a session supervisor needs: kernel policy decisions
/// plus vault identity lifecycle. The real engine implements both against
/// the same vault + session registry the kernel authorizes against.
pub trait SupervisorKernel: KernelClient + SessionIdentityAuthority {}

impl<T: KernelClient + SessionIdentityAuthority> SupervisorKernel for T {}

/// A freshly minted session identity (public material only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentityInfo {
    /// The ephemeral Courier subject (`ed25519:...`).
    pub subject: String,
    /// Hex of the identity's verifying key (public; doubles as the
    /// session's identity fingerprint in host references).
    pub verifying_key_hex: String,
}

/// Report from [`SessionIdentityAuthority::destroy_session_identity`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEndReport {
    pub subject: String,
    /// The destroyed subject plus every vault-known descendant whose
    /// authority died with it.
    pub affected_subjects: Vec<String>,
}

/// Scripting hook for [`MockKernelClient`]: decides the outcome per envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockVerdict {
    Allow,
    Deny,
    PendingApproval,
}

/// In-memory kernel double for host tests and the vertical slice.
///
/// - `decide` returns the scripted verdict, bound to the envelope digest
///   (so `bind` checks behave like the real kernel).
/// - `verify_lease` checks membership in the issued-lease set plus a
///   revocation set.
/// - `append_audit` records into an in-memory hash-chained log; it can be
///   armed to fail to test fail-closed behavior.
#[derive(Debug, Default)]
pub struct MockKernelClient {
    inner: Mutex<MockKernelState>,
}

#[derive(Debug, Default)]
struct MockKernelState {
    verdict: Option<MockVerdict>,
    deny_reason: String,
    leases: BTreeMap<String, LeaseDocument>,
    revoked_subjects: Vec<String>,
    /// Lease ids killed by `revoke_session`. Kept separate from
    /// `revoked_subjects` (the audit trail of revoke calls) so a
    /// restart does not poison the subject's future leases.
    revoked_leases: BTreeSet<String>,
    audit_log: Vec<(AuditEvent, AuditRef)>,
    fail_audit: bool,
    /// Fail every append after the first `n` succeed (see
    /// `fail_audit_after_appends`).
    fail_audit_after: Option<u64>,
    /// Per-kind transient failure injection (see
    /// `fail_next_audit_appends_for_kind`).
    fail_kinds: HashMap<String, u64>,
    fail_revoke: bool,
    decisions_made: u64,
    /// Separate counter for vault-minted session ids (so identity minting
    /// does not perturb `decisions_made`, which tests assert on).
    sessions_minted: u64,
}

impl MockKernelClient {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_verdict(self, verdict: MockVerdict) -> Self {
        self.inner.lock().unwrap().verdict = Some(verdict);
        self
    }

    pub fn with_deny_reason(self, reason: impl Into<String>) -> Self {
        self.inner.lock().unwrap().deny_reason = reason.into();
        self
    }

    /// Pre-register a lease the mock will verify successfully.
    pub fn issue_lease(&self, lease: LeaseDocument) {
        self.inner
            .lock()
            .unwrap()
            .leases
            .insert(lease.lease_id.clone(), lease);
    }

    /// Arm the next (and subsequent) audit appends to fail.
    pub fn fail_audit(&self, fail: bool) {
        self.inner.lock().unwrap().fail_audit = fail;
    }

    /// Fail every audit append after the first `n` succeed. `n = 1`
    /// fails the second append onward (e.g. the post-commit
    /// `tool_committed` record while the pre-commit `tool_staged`
    /// intention lands durably).
    pub fn fail_audit_after_appends(&self, n: u64) {
        self.inner.lock().unwrap().fail_audit_after = Some(n);
    }

    /// Fail the next `n` appends of events with this `kind`, then
    /// succeed again. Models a transient store hiccup the pipeline's
    /// bounded post-commit retry can ride out, without disturbing the
    /// pre-commit `tool_staged` write (which is not retried).
    pub fn fail_next_audit_appends_for_kind(&self, kind: &str, n: u64) {
        self.inner
            .lock()
            .unwrap()
            .fail_kinds
            .insert(kind.to_string(), n);
    }

    /// Arm the next (and subsequent) session revocations to fail.
    pub fn fail_revoke(&self, fail: bool) {
        self.inner.lock().unwrap().fail_revoke = fail;
    }

    pub fn decisions_made(&self) -> u64 {
        self.inner.lock().unwrap().decisions_made
    }

    /// Subjects whose leases were revoked through this mock.
    pub fn revoked_subjects(&self) -> Vec<String> {
        self.inner.lock().unwrap().revoked_subjects.clone()
    }

    pub fn audit_log(&self) -> Vec<(AuditEvent, AuditRef)> {
        self.inner.lock().unwrap().audit_log.clone()
    }
}

impl KernelClient for MockKernelClient {
    fn decide<'a>(&'a self, envelope: &'a ActionEnvelope) -> KernelFuture<'a, PolicyDecision> {
        Box::pin(async move {
            envelope.validate()?;
            let mut state = self.inner.lock().unwrap();
            state.decisions_made += 1;
            let verdict = state.verdict.unwrap_or(MockVerdict::Deny);
            let digest = envelope.digest()?;
            let decision = match verdict {
                MockVerdict::Allow => Decision::Allow {
                    lease_id: "mock-lease-1".to_string(),
                    obligations: vec![Obligation {
                        kind: "stream_output_to_audit".to_string(),
                        params: serde_json::json!({}),
                    }],
                },
                MockVerdict::Deny => Decision::Deny {
                    reason: if state.deny_reason.is_empty() {
                        "mock policy denies by default".to_string()
                    } else {
                        state.deny_reason.clone()
                    },
                },
                MockVerdict::PendingApproval => Decision::PendingApproval {
                    approval_request_id: format!("mock-approval-{}", state.decisions_made),
                    reason: "mock policy requires approval".to_string(),
                },
            };
            Ok(PolicyDecision {
                protocol_version: POLICY_DECISION_VERSION,
                action_digest: digest,
                decision,
                decided_at: now_rfc3339(),
            })
        })
    }

    fn verify_lease<'a>(&'a self, lease: &'a LeaseDocument) -> KernelFuture<'a, LeaseVerification> {
        Box::pin(async move {
            if lease.protocol_version != LEASE_DOCUMENT_VERSION {
                return Err(KernelError::Protocol(format!(
                    "unsupported lease version {}",
                    lease.protocol_version
                )));
            }
            let state = self.inner.lock().unwrap();
            match state.leases.get(&lease.lease_id) {
                Some(known) if known == lease => {
                    if state.revoked_leases.contains(&lease.lease_id) {
                        return Err(KernelError::Revoked(lease.lease_id.clone()));
                    }
                    Ok(LeaseVerification {
                        lease_id: lease.lease_id.clone(),
                        subject: lease.subject.clone(),
                        verified_at_ms: now_ms(),
                        revoked: false,
                    })
                }
                _ => Err(KernelError::VerificationFailed(format!(
                    "unknown lease {}",
                    lease.lease_id
                ))),
            }
        })
    }

    fn request_one_shot_lease<'a>(
        &'a self,
        grant: &'a OneShotGrant,
    ) -> KernelFuture<'a, LeaseDocument> {
        Box::pin(async move {
            if grant.action_digest.is_empty() || grant.nonce.is_empty() {
                return Err(KernelError::OneShotRejected(
                    "empty digest or nonce".to_string(),
                ));
            }
            if grant.expires_at_ms <= now_ms() {
                return Err(KernelError::OneShotRejected("grant expired".to_string()));
            }
            let lease = LeaseDocument {
                protocol_version: LEASE_DOCUMENT_VERSION,
                lease_id: format!("oneshot-{}", grant.approval_id),
                parent_id: None,
                subject: grant.session_subject.clone(),
                issuer_key_id: "mock-vhl-issuer".to_string(),
                issued_at_ms: now_ms(),
                scope: serde_json::json!({"action_digest": grant.action_digest}),
                limits: LeaseLimits {
                    not_before_ms: now_ms(),
                    expires_at_ms: grant.expires_at_ms,
                    budget: serde_json::json!({}),
                    max_executions: Some(1),
                    single_use: true,
                },
                depth: 0,
                depth_limit: 0,
                lease_nonce: grant.nonce.clone(),
                signature: "mock-signature".to_string(),
            };
            self.issue_lease(lease.clone());
            Ok(lease)
        })
    }

    fn revoke_session<'a>(&'a self, session_subject: &'a str) -> KernelFuture<'a, ()> {
        Box::pin(async move {
            let mut state = self.inner.lock().unwrap();
            if state.fail_revoke {
                return Err(KernelError::Unavailable("mock revoke down".to_string()));
            }
            // Revoke by lease id, not by subject: the subject is the
            // session's stable identity and survives restarts; only the
            // outstanding leases die.
            let doomed: Vec<String> = state
                .leases
                .values()
                .filter(|lease| lease.subject == session_subject)
                .map(|lease| lease.lease_id.clone())
                .collect();
            for lease_id in doomed {
                state.revoked_leases.insert(lease_id);
            }
            state.revoked_subjects.push(session_subject.to_string());
            Ok(())
        })
    }

    fn append_audit<'a>(&'a self, event: &'a AuditEvent) -> KernelFuture<'a, AuditRef> {
        Box::pin(async move {
            let mut state = self.inner.lock().unwrap();
            if state.fail_audit {
                return Err(KernelError::AuditFailed(
                    "mock audit store down".to_string(),
                ));
            }
            if let Some(remaining) = state.fail_kinds.get_mut(&event.kind)
                && *remaining > 0
            {
                *remaining -= 1;
                return Err(KernelError::AuditFailed(
                    "mock audit store down".to_string(),
                ));
            }
            if let Some(limit) = state.fail_audit_after
                && state.audit_log.len() as u64 >= limit
            {
                return Err(KernelError::AuditFailed(
                    "mock audit store down".to_string(),
                ));
            }
            let prev = state
                .audit_log
                .last()
                .map(|(_, r)| r.chain_hash.clone())
                .unwrap_or_else(|| "genesis".to_string());
            let event_id = Uuid::new_v4().to_string();
            let chain_hash = sha256_hex(
                format!(
                    "{prev}{event_id}{}",
                    serde_json::to_string(&event.payload).unwrap_or_default()
                )
                .as_bytes(),
            );
            let audit_ref = AuditRef {
                event_id: event_id.clone(),
                chain_hash: chain_hash.clone(),
            };
            state.audit_log.push((event.clone(), audit_ref.clone()));
            Ok(audit_ref)
        })
    }
}

impl SessionIdentityAuthority for MockKernelClient {
    fn start_session_identity<'a>(
        &'a self,
        parent: Option<&'a str>,
    ) -> KernelFuture<'a, SessionIdentityInfo> {
        Box::pin(async move {
            let mut state = self.inner.lock().unwrap();
            let id = state.sessions_minted;
            state.sessions_minted += 1;
            let subject = format!("ed25519:mock-session-{id}");
            if let Some(parent) = parent {
                state
                    .revoked_subjects
                    .push(format!("{parent}::child::{subject}"));
            }
            Ok(SessionIdentityInfo {
                subject: subject.clone(),
                verifying_key_hex: format!("mock-vk-{id}"),
            })
        })
    }

    fn destroy_session_identity<'a>(
        &'a self,
        subject: &'a str,
    ) -> KernelFuture<'a, SessionEndReport> {
        let subject = subject.to_string();
        Box::pin(async move {
            let state = self.inner.lock().unwrap();
            // The mock tracks parent→child links as `{parent}::child::{child}`
            // markers; destroying a parent reports its children as affected.
            let prefix = format!("{subject}::child::");
            let mut affected = vec![subject.clone()];
            for marker in state.revoked_subjects.iter() {
                if let Some(child) = marker.strip_prefix(&prefix) {
                    affected.push(child.to_string());
                }
            }
            Ok(SessionEndReport {
                subject: subject.clone(),
                affected_subjects: affected,
            })
        })
    }
}

/// Canonical JSON: object keys sorted recursively, no whitespace.
/// Used for envelope digests and audit chaining.
pub fn canonical_json(value: &serde_json::Value) -> String {
    fn write(value: &serde_json::Value, out: &mut String) {
        match value {
            serde_json::Value::Null => out.push_str("null"),
            serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            serde_json::Value::Number(n) => out.push_str(&n.to_string()),
            serde_json::Value::String(s) => {
                out.push('"');
                for c in s.chars() {
                    match c {
                        '"' => out.push_str("\\\""),
                        '\\' => out.push_str("\\\\"),
                        '\n' => out.push_str("\\n"),
                        '\r' => out.push_str("\\r"),
                        '\t' => out.push_str("\\t"),
                        c if (c as u32) < 0x20 => {
                            out.push_str(&format!("\\u{:04x}", c as u32));
                        }
                        c => out.push(c),
                    }
                }
                out.push('"');
            }
            serde_json::Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(item, out);
                }
                out.push(']');
            }
            serde_json::Value::Object(map) => {
                out.push('{');
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for (i, key) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(&serde_json::Value::String((*key).clone()), out);
                    out.push(':');
                    write(&map[*key], out);
                }
                out.push('}');
            }
        }
    }
    let mut out = String::new();
    write(value, &mut out);
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Current wall-clock time in milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Current UTC time as RFC 3339 (`YYYY-MM-DDTHH:MM:SSZ`).
pub fn now_rfc3339() -> String {
    format_rfc3339(now_ms() / 1000)
}

/// RFC 3339 timestamp `secs_from_now` seconds in the future. Used for
/// bounded action-start deadlines on envelopes.
pub fn deadline_rfc3339(secs_from_now: u64) -> String {
    format_rfc3339(now_ms() / 1000 + secs_from_now as i64)
}

fn format_rfc3339(unix_secs: i64) -> String {
    // Days-to-civil-date (Howard Hinnant's algorithm), proleptic Gregorian.
    let days = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
}

/// Parse an RFC 3339 timestamp to milliseconds since the Unix epoch.
/// Accepts `YYYY-MM-DDTHH:MM:SS[.frac]Z` or a numeric `±HH:MM` offset.
/// Returns `None` on any malformed input. Hand-rolled: the workspace
/// carries no datetime dependency by design.
pub fn rfc3339_to_ms(s: &str) -> Option<i64> {
    let (dt, offset_secs) = if let Some(base) = s.strip_suffix('Z') {
        (base, 0i64)
    } else {
        let i = s.rfind(['+', '-']).filter(|&i| i >= 19)?;
        let (base, off) = s.split_at(i);
        let (sign, hhmm) = (off.as_bytes()[0], &off[1..]);
        let (hh, mm) = hhmm.split_once(':')?;
        if hh.len() != 2 || mm.len() != 2 {
            return None;
        }
        let secs = hh.parse::<i64>().ok()? * 3600 + mm.parse::<i64>().ok()? * 60;
        (base, if sign == b'+' { secs } else { -secs })
    };
    let (date, time) = dt.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day) = (d.next()?, d.next()?, d.next()?);
    if y.len() != 4 || m.len() != 2 || day.len() != 2 {
        return None;
    }
    let time = time.split('.').next()?;
    let mut t = time.split(':');
    let (h, min, sec) = (t.next()?, t.next()?, t.next()?);
    if h.len() != 2 || min.len() != 2 || sec.len() != 2 {
        return None;
    }
    let (y, m, day): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, day.parse().ok()?);
    let (h, min, sec): (i64, i64, i64) = (h.parse().ok()?, min.parse().ok()?, sec.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&day) || h > 23 || min > 59 || sec > 60 {
        return None;
    }
    // days_from_civil (Howard Hinnant), then un-apply the offset.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (m + 9).rem_euclid(12);
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some((days * 86_400 + h * 3600 + min * 60 + sec - offset_secs) * 1000)
}

/// Lenient RFC 3339 shape check: `YYYY-MM-DDTHH:MM:SS` with optional
/// fractional seconds and a `Z` or numeric offset. Semantic validation of
/// the envelope timestamp is the kernel's job; the host only rejects
/// obvious garbage before sending.
fn parse_rfc3339(s: &str) -> Option<()> {
    let s = s
        .strip_suffix('Z')
        .or_else(|| s.rfind(['+', '-']).filter(|&i| i >= 19).map(|i| &s[..i]))?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let (y, m, day) = (d.next()?, d.next()?, d.next()?);
    if y.len() != 4 || m.len() != 2 || day.len() != 2 {
        return None;
    }
    let time = time.split('.').next()?;
    let mut t = time.split(':');
    let (h, min, sec) = (t.next()?, t.next()?, t.next()?);
    if h.len() != 2 || min.len() != 2 || sec.len() != 2 {
        return None;
    }
    for part in [y, m, day, h, min, sec] {
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> ActionEnvelope {
        ActionEnvelope {
            protocol_version: ACTION_ENVELOPE_VERSION,
            action_id: Uuid::new_v4().to_string(),
            session_id: "ed25519:test-subject".to_string(),
            tool: ToolRef {
                name: "bct.fs.read".to_string(),
                version: "1.0.0".to_string(),
            },
            arguments: serde_json::json!({"path": "/tmp/x"}),
            input_hashes: vec![],
            resources: ResourceSet {
                paths: vec!["/tmp/x".to_string()],
                hosts: vec![],
                secret_refs: vec![],
            },
            lease_chain: vec!["lease-1".to_string()],
            nonce: "nonce-1".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            expected_effects: vec![EffectClass::Read],
        }
    }

    #[test]
    fn envelope_validates_and_digests_stably() {
        let env = sample_envelope();
        env.validate().unwrap();
        let d1 = env.digest().unwrap();
        let d2 = env.digest().unwrap();
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn envelope_digest_changes_with_arguments() {
        let mut env = sample_envelope();
        let d1 = env.digest().unwrap();
        env.arguments = serde_json::json!({"path": "/tmp/y"});
        let d2 = env.digest().unwrap();
        assert_ne!(d1, d2);
    }

    #[test]
    fn envelope_rejects_bad_version_and_id() {
        let mut env = sample_envelope();
        env.protocol_version = 99;
        assert!(matches!(
            env.validate(),
            Err(EnvelopeError::VersionMismatch(99, 1))
        ));
        env.protocol_version = 1;
        env.action_id = "not-a-uuid".to_string();
        assert!(matches!(env.validate(), Err(EnvelopeError::BadActionId(_))));
        env.action_id = Uuid::new_v4().to_string();
        env.expires_at = "yesterday".to_string();
        assert!(matches!(env.validate(), Err(EnvelopeError::BadExpiry(_))));
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let v = serde_json::json!({"b": 1, "a": {"z": 1, "y": 2}});
        assert_eq!(canonical_json(&v), r#"{"a":{"y":2,"z":1},"b":1}"#);
    }

    #[tokio::test]
    async fn mock_kernel_binds_decision_to_digest() {
        let kernel = MockKernelClient::new().with_verdict(MockVerdict::Allow);
        let env = sample_envelope();
        let decision = kernel.decide(&env).await.unwrap();
        decision.bind(&env).unwrap();
        assert!(decision.is_allow());

        let mut other = sample_envelope();
        other.nonce = "different".to_string();
        assert!(matches!(
            decision.bind(&other),
            Err(DecisionError::DigestMismatch(_))
        ));
    }

    #[tokio::test]
    async fn mock_kernel_deny_is_default() {
        let kernel = MockKernelClient::new();
        let env = sample_envelope();
        let decision = kernel.decide(&env).await.unwrap();
        assert!(matches!(decision.decision, Decision::Deny { .. }));
    }

    #[tokio::test]
    async fn mock_lease_verify_and_revoke() {
        let kernel = MockKernelClient::new();
        let lease = LeaseDocument {
            protocol_version: LEASE_DOCUMENT_VERSION,
            lease_id: "l1".to_string(),
            parent_id: None,
            subject: "ed25519:subj".to_string(),
            issuer_key_id: "k1".to_string(),
            issued_at_ms: now_ms(),
            scope: serde_json::json!({}),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: i64::MAX,
                budget: serde_json::json!({"spend_micros": 100}),
                max_executions: None,
                single_use: false,
            },
            depth: 0,
            depth_limit: 3,
            lease_nonce: "n".to_string(),
            signature: "sig".to_string(),
        };
        assert!(kernel.verify_lease(&lease).await.is_err());
        kernel.issue_lease(lease.clone());
        let v = kernel.verify_lease(&lease).await.unwrap();
        assert_eq!(v.lease_id, "l1");
        assert!(!v.revoked);
        kernel.revoke_session("ed25519:subj").await.unwrap();
        assert!(matches!(
            kernel.verify_lease(&lease).await,
            Err(KernelError::Revoked(_))
        ));
    }

    #[tokio::test]
    async fn mock_one_shot_grant_flow() {
        let kernel = MockKernelClient::new();
        let grant = OneShotGrant {
            approval_id: "appr-1".to_string(),
            action_digest: "abc123".to_string(),
            session_subject: "ed25519:subj".to_string(),
            signer_key_id: "vhl-key-1".to_string(),
            nonce: "n1".to_string(),
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + 300_000,
            signature: "deadbeef".to_string(),
        };
        let lease = kernel.request_one_shot_lease(&grant).await.unwrap();
        assert!(lease.limits.single_use);
        assert_eq!(lease.limits.max_executions, Some(1));
        assert_eq!(lease.subject, grant.session_subject);

        let expired = OneShotGrant {
            expires_at_ms: now_ms() - 1,
            ..grant
        };
        assert!(matches!(
            kernel.request_one_shot_lease(&expired).await,
            Err(KernelError::OneShotRejected(_))
        ));
    }

    #[tokio::test]
    async fn mock_audit_chain_and_failure() {
        let kernel = MockKernelClient::new();
        let event = AuditEvent {
            kind: "tool_result".to_string(),
            session_id: "s1".to_string(),
            action_digest: None,
            payload: serde_json::json!({"ok": true}),
        };
        let r1 = kernel.append_audit(&event).await.unwrap();
        let r2 = kernel.append_audit(&event).await.unwrap();
        assert_ne!(r1.chain_hash, r2.chain_hash);
        assert_eq!(kernel.audit_log().len(), 2);
        kernel.fail_audit(true);
        assert!(matches!(
            kernel.append_audit(&event).await,
            Err(KernelError::AuditFailed(_))
        ));
    }

    #[test]
    fn rfc3339_formatting_roundtrip() {
        // 2026-09-23T00:00:00Z
        assert_eq!(format_rfc3339(1_790_121_600), "2026-09-23T00:00:00Z");
        assert!(parse_rfc3339("2026-09-23T22:53:03Z").is_some());
        assert!(parse_rfc3339("2026-09-23T22:53:03.123+00:00").is_some());
        assert!(parse_rfc3339("not a time").is_none());
        assert!(parse_rfc3339("2026-09-23 22:53:03").is_none());
    }
}
