//! Human authority: VHL approval requests, verification, and single-use
//! lease minting (Phase 4B).
//!
//! When an action falls outside the active lease, the kernel blocks it and
//! opens an approval request bound to the canonical action digest, the
//! session identity, the current input hashes, a nonce, and a short expiry.
//! Courier carries the request as a native message
//! ([`VhlCourierMessage`]; transport is wired by phase-5 `lumen-messaging` —
//! this crate only constructs the payload).
//!
//! A valid approval is a Courier VHL Tier-2 attestation: the human's device
//! signs the exact bytes the human reviewed, binding `msg_hash` to the
//! approval body. The wire format and signature semantics are ported
//! byte-for-byte from `courier-vhl` (`internal/vhl/artifact.go`,
//! `policy.go`, `webauthn.go`) — this crate reuses that VHL, it does not
//! invent a competing one. Only FIDO2 (`fido2`) and hold-and-release
//! (`challenge`) proofs can mint exceptional authority; `session` and `pin`
//! proofs are weaker ceremonies and fail closed here.
//!
//! A verified approval lets the kernel mint a **single-use** lease for that
//! exact action through the phase-1 lease engine
//! ([`mint_one_shot_lease`](crate::lease::mint_one_shot_lease)): changing any
//! argument, input hash, snapshot, destination, or requested effect changes
//! the digest and invalidates the approval. Approvals are single-use and
//! replay-protected; timeout, denial, or signature failure leaves the action
//! blocked.
//!
//! "Always allow" is a **separately displayed standing lease**, created only
//! through the explicit [`VhlAuthority::open_standing_request`] /
//! [`VhlAuthority::confirm_standing_lease`] /
//! [`VhlAuthority::mint_standing_lease`] workflow — never inferred from a
//! one-time approval.
//!
//! # State machine
//!
//! ```text
//! Blocked → Requested → Decided → Minted → Consumed
//! ```
//!
//! `Blocked` is the kernel's decision state before a request exists;
//! [`VhlApprovalRequest`] covers `Requested` onward. Every transition is
//! checked in Rust *and* re-checked by the 0023 migration's SQL guard
//! triggers, so a buggy host fails closed at the database too.

use std::collections::{HashMap, VecDeque};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use lumen_protocol::{ActionEnvelope, EffectClass, canonical};

use crate::budget::{Budget, BudgetDimension, BudgetLedger};
use crate::kernel_audit::{AuditStore, KernelAuditLog};
use crate::lease::{
    CanonicalAction, ChildLeaseParams, KernelKeys, LeaseDocument, LeaseError, LeaseLimits,
    OneShotGrant, RevocationIndex, SessionRegistry, mint_child_lease, mint_one_shot_lease,
};
use crate::nonce::NonceStore;
use crate::{
    canonical::ResourceScope,
    session_identity::{SessionEndReceipt, SessionIdentityError, SessionIdentityVault},
};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum VhlError {
    #[error("malformed attestation: {0}")]
    MalformedAttestation(String),
    #[error("unsupported attestation version: {0}")]
    UnsupportedAttestationVersion(u8),
    #[error("attestation signature invalid")]
    BadSignature,
    #[error("approver not enrolled: {0}")]
    ApproverNotEnrolled(String),
    #[error("attestation replayed: {0}")]
    Replay(String),
    #[error("attestation is expired or not yet valid")]
    AttestationExpired,
    #[error("attestation tier {0} cannot authorize exceptional authority (need tier 2)")]
    TierNotSufficient(u8),
    #[error("attestation request id does not match this approval request")]
    RequestMismatch,
    #[error("attestation message hash does not match the reviewed approval body")]
    BodyHashMismatch,
    #[error("proof kind {0} cannot mint exceptional authority (need fido2 or challenge)")]
    InsufficientProof(ProofKind),
    #[error("fido2 proof invalid: {0}")]
    Fido2(String),
    #[error("fido2 credential not enrolled for approver")]
    CredentialNotEnrolled,
    #[error("credential algorithm unsupported: only Ed25519/OKP credentials can be verified")]
    UnsupportedCredentialAlgorithm,
    #[error("no relying party configured: fido2 proofs fail closed")]
    NoRelyingParty,
    #[error("hold-and-release challenge invalid: {0}")]
    Challenge(String),
    #[error("approval request expired")]
    RequestExpired,
    #[error("approval request is not in the requested state: {0}")]
    IllegalTransition(String),
    #[error("action digest mismatch: this approval does not cover the presented action")]
    DigestMismatch,
    #[error("session subject mismatch")]
    SubjectMismatch,
    #[error("nonce mismatch: this grant is not bound to the approval request")]
    NonceMismatch,
    #[error("grant signer is not the approver of record")]
    ApproverMismatch,
    #[error("no enrolled human key verifies the grant signature")]
    GrantSignature,
    #[error("standing lease requires the explicit confirmation workflow; it is never inferred")]
    StandingLeaseNotConfirmed,
    #[error("audit sink failed: {0}")]
    Audit(String),
    #[error("envelope inconsistent with canonical action: {0}")]
    EnvelopeMismatch(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("session identity error: {0}")]
    SessionIdentity(String),
    #[error(transparent)]
    Lease(#[from] LeaseError),
}

// ---------------------------------------------------------------------------
// Courier VHL attestation wire format (ported from courier-vhl)
// ---------------------------------------------------------------------------

/// Current attestation wire version (length-prefixed canonical form).
pub const ATTESTATION_VERSION: u8 = 2;
/// First wire version; still verifies against the frozen v1 canonical form.
pub const ATTESTATION_VERSION_V1: u8 = 1;
/// Tier carrying per-action human approval.
pub const ATTESTATION_TIER_ACTION: u8 = 2;

/// Domain separator for attestation signatures, byte-identical to
/// courier-vhl's `courier-vhl-attest-v1\x00`.
const ATTEST_DOMAIN: &[u8] = b"courier-vhl-attest-v1\x00";
/// Domain separator for session-token signatures (`courier-vhl-token-v1\x00`).
const TOKEN_DOMAIN: &[u8] = b"courier-vhl-token-v1\x00";

/// Human-presence proof kind carried by an attestation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofKind {
    Fido2,
    Challenge,
    Session,
    Pin,
}

impl ProofKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fido2 => "fido2",
            Self::Challenge => "challenge",
            Self::Session => "session",
            Self::Pin => "pin",
        }
    }

    /// Ceremony strength rank, mirroring courier-vhl's PresenceStrength
    /// ordering (pin < challenge < fido2 < fido2_uv).
    pub fn strength_rank(self, strength: &str) -> i8 {
        match self {
            Self::Pin => 0,
            Self::Challenge => 1,
            Self::Fido2 if strength == "fido2_uv" => 3,
            Self::Fido2 => 2,
            // A session proof's strength is whatever the token ceremony was;
            // it never authorizes exceptional authority here regardless.
            Self::Session => -1,
        }
    }

    /// Only FIDO2 and hold-and-release ceremonies can mint exceptional
    /// authority. Session and PIN proofs are weaker and fail closed.
    pub const fn authorizes_exceptional(self) -> bool {
        matches!(self, Self::Fido2 | Self::Challenge)
    }
}

impl std::fmt::Display for ProofKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The human-presence evidence inside an attestation. Field names match the
/// courier-vhl JSON wire format exactly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationProof {
    #[serde(rename = "kind")]
    pub kind: ProofKind,
    pub strength: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<SessionToken>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_id: Option<String>,
}

/// A courier-vhl session token (Tier-1 proof carrier). Ported for canonical
/// verification of session-proof attestations; session proofs never mint
/// exceptional authority in Lumen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionToken {
    #[serde(rename = "v")]
    pub version: u8,
    pub id: String,
    pub issuer: String,
    pub session_id: String,
    pub issued_at: i64,
    pub expires_at: i64,
    #[serde(default)]
    pub scope: String,
    pub presence: String,
    #[serde(default)]
    pub boot_id: String,
    pub sig: String,
}

/// The VHL approval artifact: a Tier-2 attestation binding the human's
/// signature to the exact bytes they reviewed. JSON field names match the
/// courier-vhl wire format exactly (`v`, `id`, `tier`, `msg_hash`,
/// `approver`, `issued_at`, `expires_at`, `proof`, `request_id`, `sig`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    #[serde(rename = "v")]
    pub version: u8,
    pub id: String,
    pub tier: u8,
    pub msg_hash: String,
    pub approver: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub proof: AttestationProof,
    #[serde(default)]
    pub request_id: String,
    pub sig: String,
}

fn decode_b64url(field: &str, value: &str) -> Result<Vec<u8>, VhlError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| VhlError::MalformedAttestation(format!("{field}: invalid base64url")))
}

/// Length-prefixed field: 8-byte big-endian length followed by the bytes
/// (courier-vhl `lpField`).
fn lp_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The signed bytes for an attestation: v2 (current, length-prefixed) or the
/// frozen v1 form. Byte-identical to courier-vhl's `attestationCanonical`.
pub fn attestation_signing_bytes(attestation: &Attestation) -> Result<Vec<u8>, VhlError> {
    match attestation.version {
        ATTESTATION_VERSION_V1 => attestation_canonical_v1(attestation),
        ATTESTATION_VERSION => attestation_canonical_v2(attestation),
        other => Err(VhlError::UnsupportedAttestationVersion(other)),
    }
}

fn attestation_canonical_v2(a: &Attestation) -> Result<Vec<u8>, VhlError> {
    let msg_hash = if a.msg_hash.is_empty() {
        Vec::new()
    } else {
        let decoded = decode_b64url("msg_hash", &a.msg_hash)?;
        if decoded.len() != 32 {
            return Err(VhlError::MalformedAttestation(
                "msg_hash: want 32 bytes".to_string(),
            ));
        }
        decoded
    };
    let id = decode_b64url("id", &a.id)?;
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(ATTEST_DOMAIN);
    out.push(a.version);
    out.push(a.tier);
    lp_field(&mut out, &id);
    lp_field(&mut out, &msg_hash);
    lp_field(&mut out, a.approver.as_bytes());
    out.extend_from_slice(&(a.issued_at as u64).to_be_bytes());
    out.extend_from_slice(&(a.expires_at as u64).to_be_bytes());
    lp_field(&mut out, a.proof.kind.as_str().as_bytes());
    lp_field(&mut out, a.proof.strength.as_bytes());
    match a.proof.kind {
        ProofKind::Session => {
            let token = a.proof.token.as_ref().ok_or_else(|| {
                VhlError::MalformedAttestation("session proof without token".to_string())
            })?;
            lp_field(&mut out, &token_canonical(token)?);
        }
        ProofKind::Fido2 => {
            let credential_id = a.proof.credential_id.as_deref().ok_or_else(|| {
                VhlError::MalformedAttestation("fido2 proof without credential_id".to_string())
            })?;
            let assertion = a.proof.assertion.as_deref().ok_or_else(|| {
                VhlError::MalformedAttestation("fido2 proof without assertion".to_string())
            })?;
            lp_field(&mut out, credential_id.as_bytes());
            lp_field(&mut out, assertion.as_bytes());
        }
        ProofKind::Challenge => {
            let challenge_id = a.proof.challenge_id.as_deref().ok_or_else(|| {
                VhlError::MalformedAttestation("challenge proof without challenge_id".to_string())
            })?;
            lp_field(&mut out, challenge_id.as_bytes());
        }
        ProofKind::Pin => {}
    }
    lp_field(&mut out, a.request_id.as_bytes());
    Ok(out)
}

/// Frozen v1 canonical form — do not change: existing v1 signatures verify
/// against exactly these bytes.
fn attestation_canonical_v1(a: &Attestation) -> Result<Vec<u8>, VhlError> {
    let msg_hash = if a.msg_hash.is_empty() {
        Vec::new()
    } else {
        let decoded = decode_b64url("msg_hash", &a.msg_hash)?;
        if decoded.len() != 32 {
            return Err(VhlError::MalformedAttestation(
                "msg_hash: want 32 bytes".to_string(),
            ));
        }
        decoded
    };
    let id = decode_b64url("id", &a.id)?;
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(ATTEST_DOMAIN);
    out.push(a.version);
    out.push(a.tier);
    out.extend_from_slice(&id);
    out.extend_from_slice(&msg_hash);
    out.extend_from_slice(a.approver.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&(a.issued_at as u64).to_be_bytes());
    out.extend_from_slice(&(a.expires_at as u64).to_be_bytes());
    out.extend_from_slice(a.proof.kind.as_str().as_bytes());
    out.push(0x00);
    out.extend_from_slice(a.proof.strength.as_bytes());
    out.push(0x00);
    match a.proof.kind {
        ProofKind::Session => {
            let token = a.proof.token.as_ref().ok_or_else(|| {
                VhlError::MalformedAttestation("session proof without token".to_string())
            })?;
            out.extend_from_slice(&token_canonical(token)?);
        }
        ProofKind::Fido2 => {
            let credential_id = a.proof.credential_id.as_deref().unwrap_or("");
            let assertion = a.proof.assertion.as_deref().unwrap_or("");
            out.extend_from_slice(credential_id.as_bytes());
            out.push(0x00);
            out.extend_from_slice(assertion.as_bytes());
        }
        ProofKind::Challenge => {
            out.extend_from_slice(a.proof.challenge_id.as_deref().unwrap_or("").as_bytes());
        }
        ProofKind::Pin => {}
    }
    out.extend_from_slice(a.request_id.as_bytes());
    Ok(out)
}

/// Session-token canonical bytes, byte-identical to courier-vhl's
/// `SessionToken.canonical`.
fn token_canonical(token: &SessionToken) -> Result<Vec<u8>, VhlError> {
    if token.version != 1 {
        return Err(VhlError::MalformedAttestation(format!(
            "session token version {} (want 1)",
            token.version
        )));
    }
    let id = decode_b64url("token.id", &token.id)?;
    let session_id = decode_b64url("token.session_id", &token.session_id)?;
    let mut out = Vec::with_capacity(192);
    out.extend_from_slice(TOKEN_DOMAIN);
    out.push(token.version);
    out.extend_from_slice(&id);
    out.extend_from_slice(token.issuer.as_bytes());
    out.push(0x00);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&(token.issued_at as u64).to_be_bytes());
    out.extend_from_slice(&(token.expires_at as u64).to_be_bytes());
    out.extend_from_slice(token.scope.as_bytes());
    out.push(0x00);
    out.extend_from_slice(token.presence.as_bytes());
    out.push(0x00);
    out.extend_from_slice(token.boot_id.as_bytes());
    Ok(out)
}

/// Verify an attestation's Ed25519 signature under the approver's public key.
/// Checks signature only — not enrollment, expiry, or replay; see
/// [`CourierVhlVerifier`].
pub fn verify_attestation_signature(
    attestation: &Attestation,
    key: &VerifyingKey,
) -> Result<(), VhlError> {
    let bytes = attestation_signing_bytes(attestation)?;
    let raw = decode_b64url("sig", &attestation.sig)?;
    let array: [u8; 64] = raw.try_into().map_err(|_| VhlError::BadSignature)?;
    key.verify(&bytes, &Signature::from_bytes(&array))
        .map_err(|_| VhlError::BadSignature)
}

/// SHA-256 over the exact bytes the human reviewed (courier-vhl `MsgHashOf`).
pub fn body_hash(body: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// Approval view and request
// ---------------------------------------------------------------------------

/// Whether the request asks for a one-time approval or a standing lease.
/// The kind is part of the signed render: a one-shot approval can never be
/// reinterpreted as standing-lease authorization.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    OneShot,
    StandingLease,
}

impl ApprovalKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneShot => "one-shot",
            Self::StandingLease => "standing-lease",
        }
    }
}

/// Exactly what the human reviews before approving: resource, action,
/// destination, effect class, budget, and expiry. The canonical JSON render
/// of this view is the attestation's `msg_hash` preimage — changed inputs
/// produce different bytes, so any mutation invalidates the approval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub kind: ApprovalKind,
    pub tool: String,
    /// The exact action digest this approval answers. Covered by the
    /// attestation `msg_hash`, so the approval can never be retargeted at a
    /// different action even if the request id were confused.
    pub action_digest: String,
    /// The session that will execute under this approval. Covered by the
    /// attestation `msg_hash` for the same reason.
    pub session_subject: String,
    pub paths: Vec<String>,
    pub destinations: Vec<String>,
    pub secrets: Vec<String>,
    pub effects: Vec<String>,
    pub arguments_digest: String,
    pub input_hashes: Vec<String>,
    pub budget_executions: u64,
    pub expires_at_ms: i64,
    pub summary: String,
}

fn effect_names(effects: &[EffectClass]) -> Vec<String> {
    let mut names: Vec<String> = effects.iter().map(|e| format!("{e:?}")).collect();
    names.sort();
    names.dedup();
    names
}

impl ApprovalView {
    /// Build the view from the canonical action and the envelope it came
    /// from. Fails closed when the envelope and canonical action disagree.
    pub fn from_action(
        kind: ApprovalKind,
        action: &CanonicalAction,
        envelope: &ActionEnvelope,
        budget_executions: u64,
        expires_at_ms: i64,
    ) -> Result<Self, VhlError> {
        let envelope_digest = envelope
            .digest()
            .map_err(|e| VhlError::EnvelopeMismatch(e.to_string()))?;
        if envelope_digest != action.digest {
            return Err(VhlError::EnvelopeMismatch(
                "envelope digest does not match canonical action digest".to_string(),
            ));
        }
        let arguments_digest = canonical::digest_value(&envelope.arguments)
            .map_err(|e| VhlError::Encoding(e.to_string()))?;
        let tool = format!("{}@{}", action.tool_name.as_str(), action.tool_version);
        let paths: Vec<String> = action.paths.iter().map(|p| p.canonical_form()).collect();
        let destinations: Vec<String> = action
            .destinations
            .iter()
            .map(|d| d.canonical_form())
            .collect();
        let secrets: Vec<String> = action
            .secrets
            .iter()
            .map(|s| s.as_str().to_string())
            .collect();
        let effects = effect_names(&action.effects);
        let banner = match kind {
            ApprovalKind::OneShot => "APPROVE ONCE — single-use, expires after one execution",
            ApprovalKind::StandingLease => {
                "STANDING LEASE — persists until revoked or expired. This is NOT a one-time approval."
            }
        };
        let mut summary = format!(
            "LUMEN APPROVAL REQUEST\n{banner}\naction digest: {}\ntool: {tool}\n",
            action.digest
        );
        for path in &paths {
            summary.push_str(&format!("path: {path}\n"));
        }
        for destination in &destinations {
            summary.push_str(&format!("destination: {destination}\n"));
        }
        for secret in &secrets {
            summary.push_str(&format!("secret: {secret}\n"));
        }
        summary.push_str(&format!("effects: {}\n", effects.join(", ")));
        summary.push_str(&format!("arguments digest: {arguments_digest}\n"));
        for input in &envelope.input_hashes {
            summary.push_str(&format!("input hash: {input}\n"));
        }
        summary.push_str(&format!(
            "session: {}\nbudget: {budget_executions} execution(s)\nexpires: {expires_at_ms}\n",
            envelope.session_id
        ));
        Ok(Self {
            kind,
            tool,
            action_digest: action.digest.clone(),
            session_subject: envelope.session_id.clone(),
            paths,
            destinations,
            secrets,
            effects,
            arguments_digest,
            input_hashes: envelope.input_hashes.clone(),
            budget_executions,
            expires_at_ms,
            summary,
        })
    }

    /// Canonical bytes the human reviews; the attestation `msg_hash` binds
    /// exactly these bytes.
    pub fn render_body(&self) -> Result<Vec<u8>, VhlError> {
        let value = serde_json::to_value(self).map_err(|e| VhlError::Encoding(e.to_string()))?;
        canonical::canonical_json(&value)
            .map(|s| s.into_bytes())
            .map_err(|e| VhlError::Encoding(e.to_string()))
    }

    /// SHA-256 of the rendered body (hex); the attestation carries the same
    /// digest base64url-encoded as `msg_hash`.
    pub fn body_hash_hex(&self) -> Result<String, VhlError> {
        Ok(hex::encode(body_hash(&self.render_body()?)))
    }
}

/// Approval lifecycle: Blocked → Requested → Decided → Minted → Consumed.
/// `Blocked` is the kernel's pre-request decision state; this type covers
/// `Requested` onward.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VhlRequestState {
    Requested,
    Approved {
        attestation_id: String,
        approver: String,
        decided_at_ms: i64,
    },
    Denied {
        reason: String,
        decided_at_ms: i64,
    },
    Expired {
        at_ms: i64,
    },
    Minted {
        lease_id: String,
        minted_at_ms: i64,
    },
    Consumed {
        lease_id: String,
        consumed_at_ms: i64,
    },
}

impl VhlRequestState {
    /// Discriminator for SQL queries and guard triggers.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Approved { .. } => "approved",
            Self::Denied { .. } => "denied",
            Self::Expired { .. } => "expired",
            Self::Minted { .. } => "minted",
            Self::Consumed { .. } => "consumed",
        }
    }

    pub const fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Denied { .. } | Self::Expired { .. } | Self::Consumed { .. }
        )
    }
}

/// An approval request bound to the canonical action digest, session
/// identity, current input hashes, nonce, and short expiry.
///
/// Changed inputs never update a request: there is no update path, only a
/// fresh request with a fresh id and nonce.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhlApprovalRequest {
    pub request_id: String,
    pub action_digest: String,
    pub input_hashes: Vec<String>,
    pub session_subject: String,
    pub nonce: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub view: ApprovalView,
    pub state: VhlRequestState,
}

impl VhlApprovalRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: ApprovalKind,
        action: &CanonicalAction,
        envelope: &ActionEnvelope,
        budget_executions: u64,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<Self, VhlError> {
        if envelope.session_id.trim().is_empty() {
            return Err(VhlError::EnvelopeMismatch(
                "envelope has no session subject".to_string(),
            ));
        }
        if ttl_ms <= 0 {
            return Err(VhlError::Encoding(
                "approval ttl must be positive".to_string(),
            ));
        }
        let expires_at_ms = now_ms.saturating_add(ttl_ms);
        let view =
            ApprovalView::from_action(kind, action, envelope, budget_executions, expires_at_ms)?;
        let mut nonce_bytes = [0u8; 16];
        {
            use rand::RngCore as _;
            OsRng.fill_bytes(&mut nonce_bytes);
        }
        Ok(Self {
            request_id: Uuid::new_v4().to_string(),
            action_digest: action.digest.clone(),
            input_hashes: envelope.input_hashes.clone(),
            session_subject: envelope.session_id.clone(),
            nonce: hex::encode(nonce_bytes),
            created_at_ms: now_ms,
            expires_at_ms,
            view,
            state: VhlRequestState::Requested,
        })
    }

    /// Canonical bytes the human reviewed.
    pub fn render_body(&self) -> Result<Vec<u8>, VhlError> {
        self.view.render_body()
    }

    /// Mark the request expired when its deadline passes. Returns true when
    /// the transition happened.
    pub fn note_expiry(&mut self, now_ms: i64) -> bool {
        if self.state == VhlRequestState::Requested && now_ms >= self.expires_at_ms {
            self.state = VhlRequestState::Expired { at_ms: now_ms };
            return true;
        }
        false
    }

    fn ensure_requested(&mut self, now_ms: i64) -> Result<(), VhlError> {
        if self.note_expiry(now_ms) {
            return Err(VhlError::RequestExpired);
        }
        match &self.state {
            VhlRequestState::Requested => Ok(()),
            other => Err(VhlError::IllegalTransition(format!(
                "decision requires requested, found {}",
                other.kind()
            ))),
        }
    }

    pub fn decide_approved(
        &mut self,
        attestation_id: &str,
        approver: &str,
        now_ms: i64,
    ) -> Result<(), VhlError> {
        self.ensure_requested(now_ms)?;
        self.state = VhlRequestState::Approved {
            attestation_id: attestation_id.to_string(),
            approver: approver.to_string(),
            decided_at_ms: now_ms,
        };
        Ok(())
    }

    pub fn decide_denied(&mut self, reason: &str, now_ms: i64) -> Result<(), VhlError> {
        self.ensure_requested(now_ms)?;
        self.state = VhlRequestState::Denied {
            reason: reason.to_string(),
            decided_at_ms: now_ms,
        };
        Ok(())
    }

    pub fn note_minted(&mut self, lease_id: &str, now_ms: i64) -> Result<(), VhlError> {
        match &self.state {
            VhlRequestState::Approved { .. } => {
                self.state = VhlRequestState::Minted {
                    lease_id: lease_id.to_string(),
                    minted_at_ms: now_ms,
                };
                Ok(())
            }
            other => Err(VhlError::IllegalTransition(format!(
                "mint requires an approved request, found {}",
                other.kind()
            ))),
        }
    }

    pub fn note_consumed(&mut self, now_ms: i64) -> Result<(), VhlError> {
        match &self.state {
            VhlRequestState::Minted { lease_id, .. } => {
                let lease_id = lease_id.clone();
                self.state = VhlRequestState::Consumed {
                    lease_id,
                    consumed_at_ms: now_ms,
                };
                Ok(())
            }
            other => Err(VhlError::IllegalTransition(format!(
                "consume requires a minted request, found {}",
                other.kind()
            ))),
        }
    }

    /// The phase-1 outbox record for this request (carried by the Courier
    /// adapter).
    pub fn to_outbox(&self) -> crate::lease::VhlRequest {
        crate::lease::VhlRequest {
            request_id: self.request_id.clone(),
            action_digest: self.action_digest.clone(),
            session_subject: self.session_subject.clone(),
            nonce: self.nonce.clone(),
            expires_at_ms: self.expires_at_ms,
        }
    }
}

// ---------------------------------------------------------------------------
// Hold-and-release challenges
// ---------------------------------------------------------------------------

/// One-time-code alphabet without ambiguous characters (matches
/// courier-vhl's challenge alphabet).
const CODE_ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
const CODE_LEN: usize = 8;
/// A challenge dies after this many wrong codes — fail closed against
/// online guessing.
const MAX_CHALLENGE_ATTEMPTS: u32 = 5;

/// A hold-and-release ceremony record. The kernel mints the challenge bound
/// to the exact action digest; the one-time code travels out of band to the
/// human (TODO(INTEGRATION): the Courier adapter delivers it to the human's
/// device). The code itself is never stored — only its SHA-256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HoldReleaseChallenge {
    pub challenge_id: String,
    pub action_digest: String,
    code_hash: [u8; 32],
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
    pub attempts: u32,
    pub used: bool,
    /// True once the human submitted the correct code: the ceremony is
    /// complete for exactly `action_digest`.
    pub ceremony_complete: bool,
}

impl HoldReleaseChallenge {
    pub fn code_hash_hex(&self) -> String {
        hex::encode(self.code_hash)
    }
}

/// Kernel-side registry for hold-and-release ceremonies.
#[derive(Default)]
pub struct ChallengeRegistry {
    challenges: HashMap<String, HoldReleaseChallenge>,
}

impl ChallengeRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a challenge bound to `action_digest`. Returns the challenge id
    /// and the one-time code — the code is returned once, at mint.
    pub fn mint(
        &mut self,
        action_digest: &str,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<(String, String), VhlError> {
        if action_digest.trim().is_empty() {
            return Err(VhlError::Challenge("empty action digest".to_string()));
        }
        if ttl_ms <= 0 {
            return Err(VhlError::Challenge("ttl must be positive".to_string()));
        }
        let mut id_bytes = [0u8; 16];
        let mut code_bytes = [0u8; CODE_LEN];
        {
            use rand::RngCore as _;
            OsRng.fill_bytes(&mut id_bytes);
            OsRng.fill_bytes(&mut code_bytes);
        }
        let code: String = code_bytes
            .iter()
            .map(|b| CODE_ALPHABET[(usize::from(*b)) % CODE_ALPHABET.len()] as char)
            .collect();
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let code_hash: [u8; 32] = hasher.finalize().into();
        let challenge_id = URL_SAFE_NO_PAD.encode(id_bytes);
        self.challenges.insert(
            challenge_id.clone(),
            HoldReleaseChallenge {
                challenge_id: challenge_id.clone(),
                action_digest: action_digest.to_string(),
                code_hash,
                issued_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
                attempts: 0,
                used: false,
                ceremony_complete: false,
            },
        );
        Ok((challenge_id, code))
    }

    /// The human submits the out-of-band code. Correct code completes the
    /// ceremony; wrong codes burn attempts and then the challenge. Completion
    /// does NOT authorize anything by itself: the authorization is consumed
    /// exactly once by [`Self::consume_completed`] during verification.
    pub fn submit_code(
        &mut self,
        challenge_id: &str,
        code: &str,
        now_ms: i64,
    ) -> Result<(), VhlError> {
        let challenge = self
            .challenges
            .get_mut(challenge_id)
            .ok_or_else(|| VhlError::Challenge("unknown challenge".to_string()))?;
        if challenge.used {
            return Err(VhlError::Challenge("challenge already used".to_string()));
        }
        if now_ms >= challenge.expires_at_ms {
            challenge.used = true;
            return Err(VhlError::Challenge("challenge expired".to_string()));
        }
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        let candidate: [u8; 32] = hasher.finalize().into();
        if candidate.ct_eq(&challenge.code_hash).unwrap_u8() != 1 {
            challenge.attempts = challenge.attempts.saturating_add(1);
            if challenge.attempts >= MAX_CHALLENGE_ATTEMPTS {
                challenge.used = true;
            }
            return Err(VhlError::Challenge("incorrect code".to_string()));
        }
        challenge.ceremony_complete = true;
        Ok(())
    }

    /// Consume a completed ceremony for exactly this action digest. Returns
    /// true (and marks the challenge used) at most once per ceremony: a
    /// second attestation referencing the same challenge — even with a fresh
    /// attestation id — cannot authorize another decision.
    pub fn consume_completed(
        &mut self,
        challenge_id: &str,
        action_digest: &str,
        now_ms: i64,
    ) -> bool {
        match self.challenges.get_mut(challenge_id) {
            Some(c)
                if c.ceremony_complete
                    && !c.used
                    && now_ms < c.expires_at_ms
                    && c.action_digest
                        .as_bytes()
                        .ct_eq(action_digest.as_bytes())
                        .unwrap_u8()
                        == 1 =>
            {
                c.used = true;
                true
            }
            _ => false,
        }
    }

    pub fn get(&self, challenge_id: &str) -> Option<&HoldReleaseChallenge> {
        self.challenges.get(challenge_id)
    }

    pub fn purge_expired(&mut self, now_ms: i64) {
        self.challenges.retain(|_, c| now_ms < c.expires_at_ms);
    }
}

// ---------------------------------------------------------------------------
// FIDO2 / WebAuthn verification (ported from courier-vhl webauthn.go)
// ---------------------------------------------------------------------------

/// Relying-party configuration for FIDO2 proof verification. When unset,
/// FIDO2 proofs fail closed — the schema alone never counts as verified
/// presence.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fido2RpConfig {
    pub id: String,
    pub origins: Vec<String>,
}

/// An enrolled WebAuthn credential. Only Ed25519 (COSE OKP, alg EdDSA/-8,
/// crv Ed25519/6) credentials can be enrolled: Lumen verifies exactly what
/// it can verify, and anything else fails closed at enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fido2Credential {
    /// base64url credential id, as it appears in attestations.
    pub credential_id: String,
    /// Raw 32-byte Ed25519 public key extracted from the COSE key.
    pub public_key: [u8; 32],
    /// The original COSE_Key bytes, retained for audit.
    pub cose_key: Vec<u8>,
    /// Last seen authenticator sign count (replay control).
    pub sign_count: u32,
    /// Whether the enrollment requires the user-verification flag.
    pub uv_required: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CoseField {
    Int(i64),
    Bytes(Vec<u8>),
}

struct CborReader<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> CborReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn read_byte(&mut self) -> Result<u8, VhlError> {
        let b = self
            .buf
            .get(self.off)
            .copied()
            .ok_or_else(|| VhlError::Fido2("cose: truncated".to_string()))?;
        self.off += 1;
        Ok(b)
    }

    fn read_uint(&mut self, ai: u8) -> Result<u64, VhlError> {
        match ai {
            0..=23 => Ok(u64::from(ai)),
            24 => Ok(u64::from(self.read_byte()?)),
            25 => {
                let mut b = [0u8; 2];
                for slot in &mut b {
                    *slot = self.read_byte()?;
                }
                Ok(u64::from(u16::from_be_bytes(b)))
            }
            26 => {
                let mut b = [0u8; 4];
                for slot in &mut b {
                    *slot = self.read_byte()?;
                }
                Ok(u64::from(u32::from_be_bytes(b)))
            }
            _ => Err(VhlError::Fido2(
                "cose: unsupported integer width".to_string(),
            )),
        }
    }

    fn read_int_or_bytes(&mut self) -> Result<CoseField, VhlError> {
        let initial = self.read_byte()?;
        let major = initial >> 5;
        let ai = initial & 0x1f;
        match major {
            0 => {
                let v = self.read_uint(ai)?;
                i64::try_from(v)
                    .map(CoseField::Int)
                    .map_err(|_| VhlError::Fido2("cose: integer out of range".to_string()))
            }
            1 => {
                let v = self.read_uint(ai)?;
                // CBOR negative: -1 - n.
                let n = i64::try_from(v)
                    .map_err(|_| VhlError::Fido2("cose: integer out of range".to_string()))?;
                Ok(CoseField::Int(-1 - n))
            }
            2 => {
                let len = usize::try_from(self.read_uint(ai)?)
                    .map_err(|_| VhlError::Fido2("cose: length out of range".to_string()))?;
                let end = self
                    .off
                    .checked_add(len)
                    .ok_or_else(|| VhlError::Fido2("cose: truncated".to_string()))?;
                if end > self.buf.len() {
                    return Err(VhlError::Fido2("cose: truncated".to_string()));
                }
                let bytes = self.buf[self.off..end].to_vec();
                self.off = end;
                Ok(CoseField::Bytes(bytes))
            }
            _ => Err(VhlError::Fido2("cose: unsupported major type".to_string())),
        }
    }
}

/// Parse a COSE_Key's flat integer-keyed map (the CBOR subset COSE keys
/// need: maps, integer keys, integer and byte-string values).
fn parse_cose_key(raw: &[u8]) -> Result<HashMap<i64, CoseField>, VhlError> {
    let mut reader = CborReader::new(raw);
    let initial = reader.read_byte()?;
    if initial >> 5 != 5 {
        return Err(VhlError::Fido2("cose: not a map".to_string()));
    }
    let count = usize::try_from(reader.read_uint(initial & 0x1f)?)
        .map_err(|_| VhlError::Fido2("cose: bad map length".to_string()))?;
    if count > 16 {
        return Err(VhlError::Fido2("cose: map too large".to_string()));
    }
    let mut out = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = match reader.read_int_or_bytes()? {
            CoseField::Int(k) => k,
            CoseField::Bytes(_) => {
                return Err(VhlError::Fido2("cose: non-integer key".to_string()));
            }
        };
        let value = reader.read_int_or_bytes()?;
        out.insert(key, value);
    }
    if reader.off != raw.len() {
        return Err(VhlError::Fido2("cose: trailing bytes".to_string()));
    }
    Ok(out)
}

impl Fido2Credential {
    /// Enroll a credential from its COSE_Key bytes. Only OKP/Ed25519 keys
    /// are accepted; every other algorithm fails closed here, at
    /// enrollment, rather than at verification time.
    pub fn enroll(
        credential_id: &str,
        cose_key: &[u8],
        uv_required: bool,
    ) -> Result<Self, VhlError> {
        if credential_id.trim().is_empty() {
            return Err(VhlError::Fido2("empty credential id".to_string()));
        }
        let fields = parse_cose_key(cose_key)?;
        let int_field = |label: i64| -> Result<i64, VhlError> {
            match fields.get(&label) {
                Some(CoseField::Int(v)) => Ok(*v),
                _ => Err(VhlError::Fido2(format!("cose: missing int field {label}"))),
            }
        };
        // kty=1 (OKP), alg=-8 (EdDSA), crv=6 (Ed25519).
        if int_field(1)? != 1 {
            return Err(VhlError::UnsupportedCredentialAlgorithm);
        }
        if int_field(3)? != -8 {
            return Err(VhlError::UnsupportedCredentialAlgorithm);
        }
        if int_field(-1)? != 6 {
            return Err(VhlError::UnsupportedCredentialAlgorithm);
        }
        let x = match fields.get(&-2) {
            Some(CoseField::Bytes(b)) if b.len() == 32 => b,
            _ => return Err(VhlError::Fido2("cose: bad Ed25519 key bytes".to_string())),
        };
        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(x);
        Ok(Self {
            credential_id: credential_id.to_string(),
            public_key,
            cose_key: cose_key.to_vec(),
            sign_count: 0,
            uv_required,
        })
    }
}

const AUTH_FLAG_USER_PRESENT: u8 = 0x01;
const AUTH_FLAG_USER_VERIFIED: u8 = 0x04;

/// Verify a WebAuthn get-assertion over the action hash
/// (what-you-sign-is-what-you-saw: the ceremony challenge is the SHA-256 of
/// the exact bytes the human reviewed). Returns the authenticator's sign
/// count; the caller enforces monotonic increase.
///
/// Semantics mirror courier-vhl's `verifyWebAuthnAssertion`: type must be
/// `webauthn.get`, the challenge must equal the action hash (constant-time),
/// the origin must be allowlisted, `rpIdHash` must match, the UP flag (and
/// UV flag when required) must be set, and the signature must verify over
/// `authenticatorData || SHA256(clientDataJSON)`.
pub fn verify_fido2_assertion(
    credential: &Fido2Credential,
    assertion_b64url: &str,
    action_hash: &[u8; 32],
    rp: &Fido2RpConfig,
    require_uv: bool,
) -> Result<u32, VhlError> {
    if rp.id.is_empty() || rp.origins.is_empty() {
        return Err(VhlError::NoRelyingParty);
    }
    let raw_json = decode_b64url("assertion", assertion_b64url)
        .map_err(|_| VhlError::Fido2("assertion: invalid base64url".to_string()))?;
    let assertion: serde_json::Value = serde_json::from_slice(&raw_json)
        .map_err(|_| VhlError::Fido2("assertion json".to_string()))?;
    let cred_type = assertion.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if !cred_type.is_empty() && cred_type != "public-key" {
        return Err(VhlError::Fido2(format!(
            "bad credential type {cred_type:?}"
        )));
    }
    let response = assertion
        .get("response")
        .ok_or_else(|| VhlError::Fido2("assertion without response".to_string()))?;
    let field_b64 = |name: &str| -> Result<Vec<u8>, VhlError> {
        let s = response
            .get(name)
            .and_then(|v| v.as_str())
            .ok_or_else(|| VhlError::Fido2(format!("assertion response without {name}")))?;
        decode_b64url(name, s).map_err(|_| VhlError::Fido2(format!("{name}: invalid base64url")))
    };
    let auth_data = field_b64("authenticatorData")?;
    let client_data_json = field_b64("clientDataJSON")?;
    let signature = field_b64("signature")?;

    let client_data: serde_json::Value = serde_json::from_slice(&client_data_json)
        .map_err(|_| VhlError::Fido2("clientData json".to_string()))?;
    if client_data.get("type").and_then(|v| v.as_str()) != Some("webauthn.get") {
        return Err(VhlError::Fido2(
            "clientData type is not webauthn.get".to_string(),
        ));
    }
    let challenge_b64 = client_data
        .get("challenge")
        .and_then(|v| v.as_str())
        .ok_or_else(|| VhlError::Fido2("clientData without challenge".to_string()))?;
    let challenge = decode_b64url("challenge", challenge_b64)
        .map_err(|_| VhlError::Fido2("challenge: invalid base64url".to_string()))?;
    if challenge
        .as_slice()
        .ct_eq(action_hash.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(VhlError::Fido2(
            "challenge is not the action hash".to_string(),
        ));
    }
    let origin = client_data
        .get("origin")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if !rp
        .origins
        .iter()
        .any(|allowed| origin.as_bytes().ct_eq(allowed.as_bytes()).unwrap_u8() == 1)
    {
        return Err(VhlError::Fido2(format!("origin {origin:?} not allowed")));
    }

    if auth_data.len() < 37 {
        return Err(VhlError::Fido2("authenticatorData too short".to_string()));
    }
    let mut hasher = Sha256::new();
    hasher.update(rp.id.as_bytes());
    let want_rp_id_hash: [u8; 32] = hasher.finalize().into();
    if auth_data[..32]
        .ct_eq(want_rp_id_hash.as_slice())
        .unwrap_u8()
        != 1
    {
        return Err(VhlError::Fido2("rp id mismatch".to_string()));
    }
    let flags = auth_data[32];
    if flags & AUTH_FLAG_USER_PRESENT == 0 {
        return Err(VhlError::Fido2("user-presence flag not set".to_string()));
    }
    if (require_uv || credential.uv_required) && flags & AUTH_FLAG_USER_VERIFIED == 0 {
        return Err(VhlError::Fido2(
            "user-verification flag not set".to_string(),
        ));
    }
    let sign_count =
        u32::from_be_bytes([auth_data[33], auth_data[34], auth_data[35], auth_data[36]]);

    let mut client_data_hash = Sha256::new();
    client_data_hash.update(&client_data_json);
    let client_data_hash: [u8; 32] = client_data_hash.finalize().into();
    let mut signed = Vec::with_capacity(auth_data.len() + 32);
    signed.extend_from_slice(&auth_data);
    signed.extend_from_slice(&client_data_hash);
    let verifying = VerifyingKey::from_bytes(&credential.public_key)
        .map_err(|_| VhlError::Fido2("bad credential key".to_string()))?;
    let sig_array: [u8; 64] = signature
        .try_into()
        .map_err(|_| VhlError::Fido2("bad ed25519 signature length".to_string()))?;
    verifying
        .verify(&signed, &Signature::from_bytes(&sig_array))
        .map_err(|_| VhlError::Fido2("signature invalid".to_string()))?;
    Ok(sign_count)
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// A successfully verified approval: the attestation is bound to the exact
/// request, signed by an enrolled human key, live, fresh (not replayed), and
/// backed by a sufficient ceremony.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedApproval {
    pub attestation_id: String,
    pub approver: String,
    pub proof_kind: ProofKind,
    pub decided_at_ms: i64,
}

/// Verifier for VHL approval attestations. Implementations hold the trust
/// root (enrolled human keys) and the replay set.
pub trait VhlVerifier {
    /// Verify `attestation` against `request`. On success the attestation id
    /// is consumed so exact replays fail, and a challenge ceremony backing
    /// the attestation is consumed so it cannot authorize a second decision.
    fn verify_approval(
        &mut self,
        request: &VhlApprovalRequest,
        attestation: &Attestation,
        challenges: &mut ChallengeRegistry,
        now_ms: i64,
    ) -> Result<VerifiedApproval, VhlError>;

    /// Enrolled human VHL keys for an approver Courier address.
    fn keys_for(&self, approver: &str) -> Vec<VerifyingKey>;
}

/// Receiver-side clock-skew grace for attestation lifetimes (mirrors
/// courier-vhl's 5-minute grace).
const CLOCK_SKEW_GRACE_SECS: i64 = 300;
/// Bound on the in-memory seen-attestation set.
const MAX_SEEN_ATTESTATIONS: usize = 5000;

/// The real Courier-VHL backend: verifies Tier-2 attestations per the
/// courier-vhl `Evaluate` semantics — structural validity, enrollment,
/// signature, replay, lifetime, request binding, message-hash binding, and
/// proof strength — then consumes the attestation id.
pub struct CourierVhlVerifier {
    enrolled_keys: HashMap<String, Vec<VerifyingKey>>,
    enrolled_credentials: HashMap<(String, String), Fido2Credential>,
    seen: VecDeque<(String, i64)>,
    rp: Fido2RpConfig,
}

impl CourierVhlVerifier {
    pub fn new(rp: Fido2RpConfig) -> Self {
        Self {
            enrolled_keys: HashMap::new(),
            enrolled_credentials: HashMap::new(),
            seen: VecDeque::new(),
            rp,
        }
    }

    /// Enroll a human approver's VHL signing keys under their Courier
    /// address. This registry is the trust root.
    pub fn enroll_approver(&mut self, approver: &str, keys: Vec<VerifyingKey>) {
        self.enrolled_keys.insert(approver.to_string(), keys);
    }

    pub fn is_enrolled(&self, approver: &str) -> bool {
        self.enrolled_keys
            .get(approver)
            .is_some_and(|keys| !keys.is_empty())
    }

    /// Enroll a WebAuthn credential for an approver. Only Ed25519/OKP
    /// credentials are accepted.
    pub fn enroll_credential(&mut self, approver: &str, credential: Fido2Credential) {
        self.enrolled_credentials.insert(
            (approver.to_string(), credential.credential_id.clone()),
            credential,
        );
    }

    fn is_seen(&self, attestation_id: &str) -> bool {
        self.seen.iter().any(|(id, _)| id == attestation_id)
    }

    fn mark_seen(&mut self, attestation_id: &str, now_ms: i64) {
        if !self.is_seen(attestation_id) {
            self.seen.push_back((attestation_id.to_string(), now_ms));
        }
        while self.seen.len() > MAX_SEEN_ATTESTATIONS {
            self.seen.pop_front();
        }
    }

    fn verify_fido2(
        &mut self,
        attestation: &Attestation,
        action_hash: &[u8; 32],
    ) -> Result<(), VhlError> {
        let credential_id = attestation
            .proof
            .credential_id
            .as_deref()
            .ok_or_else(|| VhlError::Fido2("missing credential id".to_string()))?;
        let assertion = attestation
            .proof
            .assertion
            .as_deref()
            .ok_or_else(|| VhlError::Fido2("missing assertion".to_string()))?;
        let key = (attestation.approver.clone(), credential_id.to_string());
        let credential = self
            .enrolled_credentials
            .get(&key)
            .ok_or(VhlError::CredentialNotEnrolled)?;
        let require_uv = attestation.proof.strength == "fido2_uv";
        let sign_count =
            verify_fido2_assertion(credential, assertion, action_hash, &self.rp, require_uv)?;
        // Standard WebAuthn replay control: the counter must strictly
        // increase per credential (a counter-less authenticator reports 0
        // forever, permitted only while the stored value is also 0).
        let stored = credential.sign_count;
        if sign_count <= stored && (stored != 0 || sign_count != 0) {
            return Err(VhlError::Fido2(format!(
                "signature counter did not increase (got {sign_count}, want > {stored})"
            )));
        }
        if let Some(entry) = self.enrolled_credentials.get_mut(&key) {
            entry.sign_count = sign_count;
        }
        Ok(())
    }
}

impl VhlVerifier for CourierVhlVerifier {
    fn verify_approval(
        &mut self,
        request: &VhlApprovalRequest,
        attestation: &Attestation,
        challenges: &mut ChallengeRegistry,
        now_ms: i64,
    ) -> Result<VerifiedApproval, VhlError> {
        // Structural validity (version gate lives in signing_bytes).
        let _ = attestation_signing_bytes(attestation)?;
        // Exceptional authority requires a Tier-2 attestation: Tier 1 is
        // session-scoped, not per-action.
        if attestation.tier != ATTESTATION_TIER_ACTION {
            return Err(VhlError::TierNotSufficient(attestation.tier));
        }
        // The attestation must answer this exact approval request.
        if attestation.request_id != request.request_id {
            return Err(VhlError::RequestMismatch);
        }
        if attestation.id.trim().is_empty() || attestation.approver.trim().is_empty() {
            return Err(VhlError::MalformedAttestation(
                "empty attestation id or approver".to_string(),
            ));
        }
        // Enrollment: the approver must be a known human.
        let keys = self.keys_for(&attestation.approver);
        if keys.is_empty() {
            return Err(VhlError::ApproverNotEnrolled(attestation.approver.clone()));
        }
        // Signature under one of the approver's enrolled keys.
        if !keys
            .iter()
            .any(|key| verify_attestation_signature(attestation, key).is_ok())
        {
            return Err(VhlError::BadSignature);
        }
        // Replay: each attestation authorizes at most once.
        if self.is_seen(&attestation.id) {
            return Err(VhlError::Replay(attestation.id.clone()));
        }
        // Lifetime in attestation (seconds) against kernel (millis) time,
        // with clock-skew grace on expiry.
        let now_secs = now_ms.div_euclid(1000);
        if now_secs < attestation.issued_at
            || now_secs > attestation.expires_at + CLOCK_SKEW_GRACE_SECS
        {
            return Err(VhlError::AttestationExpired);
        }
        // The request itself must still be live and undecided.
        if request.note_expiry_for_check(now_ms) {
            return Err(VhlError::RequestExpired);
        }
        if !matches!(request.state, VhlRequestState::Requested) {
            return Err(VhlError::IllegalTransition(format!(
                "verify requires a requested approval, found {}",
                request.state.kind()
            )));
        }
        // Message-hash binding: the attestation covers exactly the bytes the
        // human reviewed. Any mutation of the request fails here.
        let body = request.render_body()?;
        let expected_hash = body_hash(&body);
        let presented = decode_b64url("msg_hash", &attestation.msg_hash).map_err(|_| {
            VhlError::MalformedAttestation("msg_hash: invalid base64url".to_string())
        })?;
        if presented.len() != 32
            || presented
                .as_slice()
                .ct_eq(expected_hash.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(VhlError::BodyHashMismatch);
        }
        // Proof strength: only fido2 and challenge ceremonies mint
        // exceptional authority.
        if !attestation.proof.kind.authorizes_exceptional() {
            return Err(VhlError::InsufficientProof(attestation.proof.kind));
        }
        match attestation.proof.kind {
            ProofKind::Fido2 => self.verify_fido2(attestation, &expected_hash)?,
            ProofKind::Challenge => {
                let challenge_id = attestation.proof.challenge_id.as_deref().ok_or_else(|| {
                    VhlError::Challenge("challenge proof without challenge_id".to_string())
                })?;
                // Consuming (not just reading) the ceremony: each ceremony
                // authorizes at most one decision.
                if !challenges.consume_completed(challenge_id, &request.action_digest, now_ms) {
                    return Err(VhlError::Challenge(
                        "no unused completed hold-and-release ceremony for this action".to_string(),
                    ));
                }
            }
            ProofKind::Session | ProofKind::Pin => {
                return Err(VhlError::InsufficientProof(attestation.proof.kind));
            }
        }
        // All checks passed: consume the attestation id so exact replays
        // fail, then report the verified approval.
        self.mark_seen(&attestation.id, now_ms);
        Ok(VerifiedApproval {
            attestation_id: attestation.id.clone(),
            approver: attestation.approver.clone(),
            proof_kind: attestation.proof.kind,
            decided_at_ms: now_ms,
        })
    }

    fn keys_for(&self, approver: &str) -> Vec<VerifyingKey> {
        self.enrolled_keys
            .get(approver)
            .cloned()
            .unwrap_or_default()
    }
}

// Non-mutating expiry probe used by the verifier (the authority owns the
// mutating transition).
impl VhlApprovalRequest {
    fn note_expiry_for_check(&self, now_ms: i64) -> bool {
        self.state == VhlRequestState::Requested && now_ms >= self.expires_at_ms
    }
}

// ---------------------------------------------------------------------------
// Audit sink
// ---------------------------------------------------------------------------

/// Where VHL decisions and mints are recorded. The kernel audit log is the
/// production sink; tests use a recording stub.
pub trait VhlAuditSink {
    fn record_vhl(
        &mut self,
        actor: &str,
        action_digest: &str,
        decision: &str,
        details: serde_json::Value,
        now_ms: i64,
    ) -> Result<(), VhlError>;
}

impl<S: AuditStore> VhlAuditSink for KernelAuditLog<S> {
    fn record_vhl(
        &mut self,
        actor: &str,
        action_digest: &str,
        decision: &str,
        details: serde_json::Value,
        now_ms: i64,
    ) -> Result<(), VhlError> {
        self.append(actor, action_digest, decision, now_ms, details)
            .map(|_| ())
            .map_err(|e| VhlError::Audit(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------

/// Opaque confirmation that a standing lease was explicitly approved through
/// [`VhlAuthority::confirm_standing_lease`]. It can only be constructed
/// there, and [`VhlAuthority::mint_standing_lease`] consumes it — a standing
/// lease can never be minted without passing through the explicit workflow.
#[derive(Debug)]
pub struct StandingLeaseConfirmation {
    request_id: String,
    approver: String,
    confirmed_at_ms: i64,
}

impl StandingLeaseConfirmation {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn approver(&self) -> &str {
        &self.approver
    }

    pub fn confirmed_at_ms(&self) -> i64 {
        self.confirmed_at_ms
    }
}

/// Orchestrates the approval state machine: opening requests, verifying
/// attestations, minting single-use leases through the phase-1 lease engine,
/// and the separate explicit standing-lease workflow.
pub struct VhlAuthority<V: VhlVerifier> {
    verifier: V,
    challenges: ChallengeRegistry,
}

impl<V: VhlVerifier> VhlAuthority<V> {
    pub fn new(verifier: V) -> Self {
        Self {
            verifier,
            challenges: ChallengeRegistry::new(),
        }
    }

    pub fn verifier(&self) -> &V {
        &self.verifier
    }

    pub fn verifier_mut(&mut self) -> &mut V {
        &mut self.verifier
    }

    pub fn challenges(&self) -> &ChallengeRegistry {
        &self.challenges
    }

    pub fn challenges_mut(&mut self) -> &mut ChallengeRegistry {
        &mut self.challenges
    }

    /// Blocked → Requested: open a one-shot approval request for an action
    /// that has no covering lease. Always mints a fresh id and nonce;
    /// changed inputs produce a new request, never an update.
    pub fn open_request(
        &self,
        action: &CanonicalAction,
        envelope: &ActionEnvelope,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<VhlApprovalRequest, VhlError> {
        // One-shot approvals authorize a single execution.
        VhlApprovalRequest::new(ApprovalKind::OneShot, action, envelope, 1, ttl_ms, now_ms)
    }

    /// Requested → Approved/Denied: verify the human's attestation and
    /// record the decision. Denial, expiry, and signature failure leave the
    /// action blocked.
    pub fn decide(
        &mut self,
        request: &mut VhlApprovalRequest,
        attestation: &Attestation,
        audit: &mut dyn VhlAuditSink,
        now_ms: i64,
    ) -> Result<VerifiedApproval, VhlError> {
        if request.view.kind != ApprovalKind::OneShot {
            return Err(VhlError::IllegalTransition(
                "decide() is for one-shot approvals; standing leases use confirm_standing_lease()"
                    .to_string(),
            ));
        }
        let verified =
            self.verifier
                .verify_approval(request, attestation, &mut self.challenges, now_ms)?;
        // Audit before mutating request state: if the audit append fails,
        // the request stays Requested and the failure is fail-closed
        // instead of leaving state and audit diverged.
        audit.record_vhl(
            &verified.approver,
            &request.action_digest,
            "approval.granted",
            serde_json::json!({
                "request_id": request.request_id,
                "attestation_id": verified.attestation_id,
                "proof_kind": verified.proof_kind.as_str(),
            }),
            now_ms,
        )?;
        request.decide_approved(
            &verified.attestation_id,
            &verified.approver,
            verified.decided_at_ms,
        )?;
        Ok(verified)
    }

    /// Record a human denial without an attestation (the human rejected the
    /// request in the approval UI).
    pub fn deny(
        &mut self,
        request: &mut VhlApprovalRequest,
        approver: &str,
        reason: &str,
        audit: &mut dyn VhlAuditSink,
        now_ms: i64,
    ) -> Result<(), VhlError> {
        // Audit before mutating request state (see decide()).
        audit.record_vhl(
            approver,
            &request.action_digest,
            "approval.denied",
            serde_json::json!({
                "request_id": request.request_id,
                "reason": reason,
            }),
            now_ms,
        )?;
        request.decide_denied(reason, now_ms)
    }

    /// Approved → Minted: mint the single-use lease for the exact approved
    /// action through the phase-1 lease engine.
    ///
    /// The `grant` must be signed by the enrolled human VHL key and bound to
    /// this exact request (action digest, session subject, nonce). Any
    /// mismatch fails closed before the lease engine runs.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_one_shot(
        &self,
        request: &mut VhlApprovalRequest,
        grant: &OneShotGrant,
        action: &CanonicalAction,
        keys: &KernelKeys,
        sessions: &SessionRegistry,
        ledger: &BudgetLedger,
        nonces: &NonceStore,
        audit: &mut dyn VhlAuditSink,
        now_ms: i64,
    ) -> Result<LeaseDocument, VhlError> {
        let (attestation_id, approver) = match &request.state {
            VhlRequestState::Approved {
                attestation_id,
                approver,
                ..
            } => (attestation_id.clone(), approver.clone()),
            other => {
                return Err(VhlError::IllegalTransition(format!(
                    "mint requires an approved request, found {}",
                    other.kind()
                )));
            }
        };
        // Cross-bind the grant to the request before the lease engine sees
        // it: the grant the human signed must be for this exact approval.
        if grant.action_digest != request.action_digest || grant.action_digest != action.digest {
            return Err(VhlError::DigestMismatch);
        }
        if grant.session_subject != request.session_subject {
            return Err(VhlError::SubjectMismatch);
        }
        if grant.nonce != request.nonce {
            return Err(VhlError::NonceMismatch);
        }
        if grant.signer_key_id != approver {
            return Err(VhlError::ApproverMismatch);
        }
        // The grant signature must verify under one of the approver's
        // enrolled human keys. (mint_one_shot_lease re-verifies under the
        // single key we hand it — defense in depth.)
        let vhl_key = self
            .verifier
            .keys_for(&approver)
            .into_iter()
            .find(|key| grant.verify(key).is_ok())
            .ok_or(VhlError::GrantSignature)?;
        let lease = mint_one_shot_lease(
            grant, &vhl_key, action, keys, sessions, ledger, nonces, now_ms,
        )?;
        request.note_minted(&lease.lease_id, now_ms)?;
        audit.record_vhl(
            &approver,
            &request.action_digest,
            "approval.minted",
            serde_json::json!({
                "request_id": request.request_id,
                "attestation_id": attestation_id,
                "lease_id": lease.lease_id,
            }),
            now_ms,
        )?;
        Ok(lease)
    }

    /// Minted → Consumed: record that the single-use lease was consumed.
    /// Called by the host after the kernel authorizes (and thereby consumes)
    /// the one-shot lease for the action.
    pub fn note_consumed(
        &self,
        request: &mut VhlApprovalRequest,
        audit: &mut dyn VhlAuditSink,
        now_ms: i64,
    ) -> Result<(), VhlError> {
        let lease_id = match &request.state {
            VhlRequestState::Minted { lease_id, .. } => lease_id.clone(),
            other => {
                return Err(VhlError::IllegalTransition(format!(
                    "consume requires a minted request, found {}",
                    other.kind()
                )));
            }
        };
        request.note_consumed(now_ms)?;
        audit.record_vhl(
            "kernel",
            &request.action_digest,
            "approval.consumed",
            serde_json::json!({
                "request_id": request.request_id,
                "lease_id": lease_id,
            }),
            now_ms,
        )
    }

    /// End a session's authority outright: destroy the session key and every
    /// descendant's key, deactivate the registry records, and revoke
    /// `lease_ids` so the real lease engine denies any in-flight commit
    /// that presents a revoked lease (`LeaseError::Revoked`).
    ///
    /// The caller supplies the outstanding lease ids for the ended subjects
    /// (production: `SELECT lease_id FROM kernel_leases WHERE subject IN
    /// (...)`); the vault never sees lease material.
    pub fn end_session_and_revoke_leases(
        vault: &mut SessionIdentityVault,
        sessions: &mut SessionRegistry,
        revocations: &mut RevocationIndex,
        subject: &str,
        lease_ids: &[String],
        now_ms: i64,
    ) -> Result<SessionEndReceipt, SessionIdentityError> {
        let receipt = vault.end_session(sessions, subject, now_ms)?;
        for lease_id in lease_ids {
            revocations.revoke(lease_id);
        }
        Ok(receipt)
    }

    // -- Standing leases: the separate explicit workflow -------------------

    /// Open a standing-lease request. Displayed separately from one-shot
    /// approvals; the render carries the standing-lease banner so the human
    /// can never mistake it for "approve once".
    pub fn open_standing_request(
        &self,
        action: &CanonicalAction,
        envelope: &ActionEnvelope,
        budget_executions: u64,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<VhlApprovalRequest, VhlError> {
        VhlApprovalRequest::new(
            ApprovalKind::StandingLease,
            action,
            envelope,
            budget_executions,
            ttl_ms,
            now_ms,
        )
    }

    /// Verify the human's attestation for a standing-lease request and
    /// produce the opaque confirmation that
    /// [`VhlAuthority::mint_standing_lease`] requires. There is no other way
    /// to obtain a confirmation.
    pub fn confirm_standing_lease(
        &mut self,
        request: &mut VhlApprovalRequest,
        attestation: &Attestation,
        audit: &mut dyn VhlAuditSink,
        now_ms: i64,
    ) -> Result<StandingLeaseConfirmation, VhlError> {
        if request.view.kind != ApprovalKind::StandingLease {
            return Err(VhlError::StandingLeaseNotConfirmed);
        }
        let verified =
            self.verifier
                .verify_approval(request, attestation, &mut self.challenges, now_ms)?;
        // Audit before mutating request state (see decide()).
        audit.record_vhl(
            &verified.approver,
            &request.action_digest,
            "standing-lease.confirmed",
            serde_json::json!({
                "request_id": request.request_id,
                "attestation_id": verified.attestation_id,
            }),
            now_ms,
        )?;
        request.decide_approved(
            &verified.attestation_id,
            &verified.approver,
            verified.decided_at_ms,
        )?;
        Ok(StandingLeaseConfirmation {
            request_id: request.request_id.clone(),
            approver: verified.approver,
            confirmed_at_ms: verified.decided_at_ms,
        })
    }

    /// Mint the standing lease. Consumes the explicit confirmation; without
    /// it this function cannot run, so a standing lease is never inferred
    /// from a one-time approval.
    ///
    /// The lease is parented under `parent` (e.g. the session's standing
    /// authority) and signed with the parent session's vault-held key. Its
    /// scope is exactly the approved action's scope — the same exact
    /// authority as the one-shot, but reusable until expiry or revocation.
    #[allow(clippy::too_many_arguments)]
    pub fn mint_standing_lease(
        &self,
        confirmation: StandingLeaseConfirmation,
        request: &mut VhlApprovalRequest,
        parent: &LeaseDocument,
        vault: &SessionIdentityVault,
        sessions: &SessionRegistry,
        revocations: &RevocationIndex,
        ledger: &BudgetLedger,
        nonces: &NonceStore,
        audit: &mut dyn VhlAuditSink,
        now_ms: i64,
    ) -> Result<LeaseDocument, VhlError> {
        if confirmation.request_id != request.request_id {
            return Err(VhlError::StandingLeaseNotConfirmed);
        }
        if request.view.kind != ApprovalKind::StandingLease {
            return Err(VhlError::StandingLeaseNotConfirmed);
        }
        if !matches!(request.state, VhlRequestState::Approved { .. }) {
            return Err(VhlError::IllegalTransition(format!(
                "standing mint requires an approved request, found {}",
                request.state.kind()
            )));
        }
        if !vault.is_live(&parent.subject) {
            // The parent session's key must be vault-held: only the kernel
            // can sign as the parent.
            return Err(VhlError::SubjectMismatch);
        }
        // Rebuild the exact resource scope from the approved view: the
        // standing lease authorizes precisely what the human reviewed,
        // nothing more.
        let scope = self.standing_scope(request)?;
        let limits = LeaseLimits {
            not_before_ms: now_ms,
            expires_at_ms: request.view.expires_at_ms,
            budget: Budget::new().set(BudgetDimension::Executions, request.view.budget_executions),
            max_executions: Some(request.view.budget_executions),
            single_use: false,
        };
        if limits.expires_at_ms <= now_ms {
            return Err(VhlError::RequestExpired);
        }
        let params = ChildLeaseParams {
            lease_id: format!("standing_{}", Uuid::new_v4()),
            subject: request.session_subject.clone(),
            scope,
            limits,
            depth_limit: parent.depth_limit,
            lease_nonce: format!("standing:{}", request.nonce),
            issued_at_ms: now_ms,
        };
        let lease = vault
            .with_signing_key(&parent.subject, |parent_key| {
                mint_child_lease(
                    parent,
                    params,
                    parent_key,
                    sessions,
                    revocations,
                    ledger,
                    nonces,
                    now_ms,
                )
            })
            .map_err(|e| VhlError::SessionIdentity(e.to_string()))?;
        request.note_minted(&lease.lease_id, now_ms)?;
        audit.record_vhl(
            &confirmation.approver,
            &request.action_digest,
            "standing-lease.minted",
            serde_json::json!({
                "request_id": request.request_id,
                "lease_id": lease.lease_id,
                "parent_lease_id": parent.lease_id,
            }),
            now_ms,
        )?;
        Ok(lease)
    }

    /// Rebuild the exact resource scope from the approved view. Paths,
    /// destinations, and secrets are re-parsed through the canonicalizers —
    /// never trusted as raw strings.
    fn standing_scope(&self, request: &VhlApprovalRequest) -> Result<ResourceScope, VhlError> {
        use crate::canonical::{
            CanonicalPath, NetworkDestination, PathGrant, PathRights, SecretRef,
        };

        let mut scope = ResourceScope::default();
        let tool_name = request.view.tool.split('@').next().unwrap_or("");
        let tool_version = request.view.tool.split('@').nth(1).unwrap_or("0.0.0");
        let version: semver::Version = tool_version
            .parse()
            .map_err(|e: semver::Error| VhlError::Encoding(e.to_string()))?;
        scope.tools.insert(
            tool_name.to_string(),
            semver::VersionReq::parse(&format!("={version}"))
                .map_err(|e: semver::Error| VhlError::Encoding(e.to_string()))?,
        );
        // Path rights mirror the one-shot's exact_scope derivation: read
        // when the action reads or executes, write when it writes.
        let effects = &request.view.effects;
        let rights = PathRights {
            read: effects.iter().any(|e| e == "Read" || e == "Execute"),
            write: effects.iter().any(|e| e == "Write"),
        };
        let resolver = StrictNoFsResolver;
        for path in &request.view.paths {
            let canonical = CanonicalPath::parse(path, &resolver, false)
                .map_err(|e| VhlError::Encoding(e.to_string()))?;
            scope.paths.push(PathGrant {
                root: canonical,
                rights,
            });
        }
        for destination in &request.view.destinations {
            let parsed = NetworkDestination::parse(destination, &[])
                .map_err(|e| VhlError::Encoding(e.to_string()))?;
            scope.destinations.push(parsed);
        }
        for secret in &request.view.secrets {
            scope.secrets.insert(
                SecretRef::parse(secret)
                    .map_err(|e| VhlError::Encoding(e.to_string()))?
                    .as_str()
                    .to_string(),
            );
        }
        scope.effects = request
            .view
            .effects
            .iter()
            .map(|name| {
                Ok(match name.as_str() {
                    "Read" => EffectClass::Read,
                    "Write" => EffectClass::Write,
                    "Network" => EffectClass::Network,
                    "Execute" => EffectClass::Execute,
                    "SecretUse" => EffectClass::SecretUse,
                    "MessageSend" => EffectClass::MessageSend,
                    other => return Err(VhlError::Encoding(format!("unknown effect {other}"))),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(scope)
    }
}

/// A [`PathResolver`](crate::canonical::PathResolver) that resolves purely
/// lexically: the approved view already carries canonical paths, so no
/// filesystem access is needed or allowed here.
struct StrictNoFsResolver;

impl crate::canonical::PathResolver for StrictNoFsResolver {
    fn resolve(&self, path: &std::path::Path) -> std::io::Result<std::path::PathBuf> {
        use std::path::{Component, PathBuf};
        let mut out = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => out.push(prefix.as_os_str()),
                Component::RootDir => out.push("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "parent component in canonical path",
                    ));
                }
                Component::Normal(part) => out.push(part),
            }
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Courier transport seam (TODO(INTEGRATION))
// ---------------------------------------------------------------------------

/// Native Courier message payloads for VHL approval traffic.
///
/// TODO(INTEGRATION): the phase-5 `lumen-messaging` Courier adapter carries
/// these payloads as native message types (`VhlApprovalCarriage` on the
/// outbound path). This crate constructs the payload; it never wires the
/// transport.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VhlCourierMessage {
    /// Kernel → human: an approval request awaiting decision.
    ApprovalRequest { request: VhlApprovalRequest },
    /// Human → kernel: the Tier-2 attestation answering a request.
    Attestation { attestation: Attestation },
    /// Kernel → human device: a hold-and-release challenge was minted for an
    /// action. The one-time code itself travels out of band, never in this
    /// message.
    ChallengeNotice {
        challenge_id: String,
        action_digest: String,
        expires_at_ms: i64,
    },
}

impl VhlCourierMessage {
    /// Stable native message type name for the Courier adapter.
    pub const fn message_type(&self) -> &'static str {
        match self {
            Self::ApprovalRequest { .. } => "lumen.vhl.approval-request.v1",
            Self::Attestation { .. } => "lumen.vhl.attestation.v1",
            Self::ChallengeNotice { .. } => "lumen.vhl.challenge-notice.v1",
        }
    }

    /// Canonical JSON bytes for the wire.
    pub fn encode(&self) -> Result<Vec<u8>, VhlError> {
        let value = serde_json::to_value(self).map_err(|e| VhlError::Encoding(e.to_string()))?;
        canonical::canonical_json(&value)
            .map(|s| s.into_bytes())
            .map_err(|e| VhlError::Encoding(e.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, VhlError> {
        serde_json::from_slice(bytes).map_err(|e| VhlError::Encoding(e.to_string()))
    }
}
