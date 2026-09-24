//! Lease engine (Phase 1B): signed capabilities with mechanical subset proofs.
//!
//! A [`LeaseDocument`] is a signed capability: subject, scope, limits, expiry,
//! depth. Delegation is safe only when narrowing is mechanically provable:
//!
//! ```text
//! valid(child, parent) :=
//!   child.subject is an active descendant session
//!   AND child.resources ⊆ parent.resources        (structural subset proofs)
//!   AND child.expiry ≤ parent.expiry
//!   AND child.depth < parent.depth_limit
//!   AND reserve(child.budget) succeeds            (reservation, not comparison)
//!   AND no lease in the chain is revoked
//! ```
//!
//! Signing: root leases are signed by the kernel issuer key; child leases are
//! signed by the parent session's key (the kernel holds session private keys
//! in kernel-controlled memory, per the design). One-shot leases minted from a
//! human VHL approval are signed by the kernel issuer key.
//!
//! This module reuses the one-shot state-machine concepts from
//! [`crate::approval`]: an approval binds an exact action digest and nonce,
//! is consumable exactly once, and any mismatch invalidates rather than
//! widens authority.

use std::collections::{HashMap, HashSet};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    budget::{Budget, BudgetDimension, BudgetError, BudgetLedger},
    canonical::{
        CanonicalPath, EffectClass, NetworkDestination, PathGrant, PathResolver, PathRights,
        ResourceScope, ScopeSubsetError, SecretRef, ToolName,
    },
    nonce::{NonceError, NonceStore},
    pi_boundary::{ActionEnvelope, BoundaryError, DenyReason, PolicyDecision, canonical_json},
};

/// Contract version for [`LeaseDocument`].
pub const LEASE_PROTOCOL_VERSION: u32 = 1;

/// Limits carried by a lease: time bounds, budget caps, execution caps.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseLimits {
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub budget: Budget,
    pub max_executions: Option<u64>,
    pub single_use: bool,
}

/// A signed lease capability.
///
/// The signature covers every field except `signature` itself, via the
/// canonical JSON encoding. `issuer_key_id` is the kernel issuer key id for
/// roots and VHL one-shots, or the parent session's subject address for
/// delegated children.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseDocument {
    pub protocol_version: u32,
    pub lease_id: String,
    pub parent_id: Option<String>,
    pub subject: String,
    pub issuer_key_id: String,
    pub issued_at_ms: i64,
    pub scope: ResourceScope,
    pub limits: LeaseLimits,
    pub depth: u32,
    pub depth_limit: u32,
    pub lease_nonce: String,
    /// Hex-encoded Ed25519 signature over the canonical signing bytes.
    pub signature: String,
}

/// The signable view: every field except the signature.
#[derive(Serialize)]
struct LeaseSigningView<'a> {
    protocol_version: u32,
    lease_id: &'a str,
    parent_id: &'a Option<String>,
    subject: &'a str,
    issuer_key_id: &'a str,
    issued_at_ms: i64,
    scope: &'a ResourceScope,
    limits: &'a LeaseLimits,
    depth: u32,
    depth_limit: u32,
    lease_nonce: &'a str,
}

impl LeaseDocument {
    fn signing_view(&self) -> LeaseSigningView<'_> {
        LeaseSigningView {
            protocol_version: self.protocol_version,
            lease_id: &self.lease_id,
            parent_id: &self.parent_id,
            subject: &self.subject,
            issuer_key_id: &self.issuer_key_id,
            issued_at_ms: self.issued_at_ms,
            scope: &self.scope,
            limits: &self.limits,
            depth: self.depth,
            depth_limit: self.depth_limit,
            lease_nonce: &self.lease_nonce,
        }
    }

    /// Canonical bytes covered by the signature.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, LeaseError> {
        canonical_json(
            &serde_json::to_value(self.signing_view())
                .map_err(|e| LeaseError::Encoding(e.to_string()))?,
        )
        .map_err(LeaseError::ProtocolCanonical)
    }

    /// Digest of the signed document (audit key).
    pub fn digest(&self) -> Result<String, LeaseError> {
        let bytes = self.signing_bytes()?;
        Ok(crate::sha256_hex(&bytes))
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let bytes = self.signing_bytes().expect("signing bytes are infallible");
        self.signature = hex::encode(key.sign(&bytes).to_bytes());
    }

    pub fn verify_signature(&self, key: &VerifyingKey) -> Result<(), LeaseError> {
        let bytes = self.signing_bytes()?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| LeaseError::BadSignature)?
            .try_into()
            .map_err(|_| LeaseError::BadSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        key.verify(&bytes, &sig)
            .map_err(|_| LeaseError::BadSignature)
    }

    pub fn is_root(&self) -> bool {
        self.parent_id.is_none()
    }

    pub fn live_at(&self, now_ms: i64) -> bool {
        self.limits.not_before_ms <= now_ms && now_ms < self.limits.expires_at_ms
    }
}

#[derive(Debug, Error)]
pub enum LeaseError {
    #[error("lease protocol version {0} unsupported")]
    VersionMismatch(u32),
    #[error("bad signature")]
    BadSignature,
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] crate::canonical::CanonicalError),
    #[error("protocol canonicalization failed: {0}")]
    ProtocolCanonical(#[from] BoundaryError),
    #[error("subset proof failed: {0}")]
    Subset(#[from] ScopeSubsetError),
    #[error("budget error: {0}")]
    Budget(#[from] BudgetError),
    #[error("nonce error: {0}")]
    Nonce(#[from] NonceError),
    #[error("subject {0} is not an active descendant of {1}")]
    SubjectNotDescendant(String, String),
    #[error("subject session {0} is not active")]
    SubjectInactive(String),
    #[error("child expiry {0} exceeds parent expiry {1}")]
    ExpiryTooWide(i64, i64),
    #[error("child not-before {0} precedes parent not-before {1}")]
    NotBeforeTooEarly(i64, i64),
    #[error("invalid time bounds: not_before {0} >= expires_at {1}")]
    InvalidTimeBounds(i64, i64),
    #[error("lease already expired at issuance")]
    AlreadyExpired,
    #[error("depth {0} violates parent depth limit {1}")]
    DepthViolation(u32, u32),
    #[error("child depth limit {0} exceeds parent depth limit {1}")]
    DepthLimitTooWide(u32, u32),
    #[error("single-use leases cannot delegate")]
    SingleUseDelegation,
    #[error("lease {0} is revoked")]
    Revoked(String),
    #[error("lease {0} not found")]
    NotFound(String),
    #[error("chain break: expected parent {0}, found {1}")]
    ChainBreak(String, String),
    #[error("chain too deep or cyclic")]
    ChainCycle,
    #[error("issuer {0} does not match parent subject {1}")]
    IssuerMismatch(String, String),
    #[error("one-shot lease {0} already consumed")]
    AlreadyConsumed(String),
    #[error("lease {0} is not single-use")]
    NotSingleUse(String),
    #[error("envelope invalid: {0}")]
    BadEnvelope(String),
    #[error("action expired")]
    ActionExpired,
    #[error("no covering lease for action")]
    NoCoveringLease,
    #[error("unknown session key for {0}")]
    UnknownKey(String),
}

// ---------------------------------------------------------------------------
// Keys, sessions, revocation
// ---------------------------------------------------------------------------

/// Kernel-held keys: the issuer key signs root leases and VHL one-shots; the
/// host key signs audit checkpoints (see [`crate::kernel_audit`]).
pub struct KernelKeys {
    pub issuer_key_id: String,
    issuer: SigningKey,
    pub host_key_id: String,
    host: SigningKey,
}

impl KernelKeys {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            issuer_key_id: format!("kernel-issuer-{}", Uuid::new_v4()),
            issuer: SigningKey::generate(&mut OsRng),
            host_key_id: format!("kernel-host-{}", Uuid::new_v4()),
            host: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn issuer_verifying(&self) -> VerifyingKey {
        self.issuer.verifying_key()
    }

    pub fn host_verifying(&self) -> VerifyingKey {
        self.host.verifying_key()
    }

    pub fn issuer_sign(&self, msg: &[u8]) -> Signature {
        self.issuer.sign(msg)
    }

    pub fn host_sign(&self, msg: &[u8]) -> Signature {
        self.host.sign(msg)
    }
}

/// One registered session: subject address, parent linkage, verifying key.
#[derive(Clone)]
pub struct SessionRecord {
    pub subject: String,
    pub parent_subject: Option<String>,
    pub verifying_key: VerifyingKey,
    pub active: bool,
}

/// Kernel-side session registry. The kernel holds session *signing* keys
/// separately in a private vault; this registry carries verifying keys and
/// liveness for the descendant check.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: HashMap<String, SessionRecord>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &mut self,
        subject: String,
        parent_subject: Option<String>,
        verifying_key: VerifyingKey,
    ) {
        self.sessions.insert(
            subject.clone(),
            SessionRecord {
                subject,
                parent_subject,
                verifying_key,
                active: true,
            },
        );
    }

    pub fn deactivate(&mut self, subject: &str) {
        if let Some(record) = self.sessions.get_mut(subject) {
            record.active = false;
        }
    }

    pub fn get(&self, subject: &str) -> Option<&SessionRecord> {
        self.sessions.get(subject)
    }

    /// `subject` is an active descendant of `ancestor` (or the same active
    /// session — self-narrowing is safe delegation).
    pub fn is_active_descendant(&self, subject: &str, ancestor: &str) -> bool {
        let mut current = subject;
        for _ in 0..256 {
            let record = match self.sessions.get(current) {
                Some(r) if r.active => r,
                _ => return false,
            };
            if current == ancestor {
                return true;
            }
            match &record.parent_subject {
                Some(parent) => current = parent,
                None => return false,
            }
        }
        false
    }
}

/// Process-local revocation index. Revocation is recorded per lease;
/// validity walks the chain, so revoking a parent transitively invalidates
/// every descendant. The epoch lets the host poll cheaply for changes.
#[derive(Default)]
pub struct RevocationIndex {
    revoked: HashSet<String>,
    epoch: u64,
}

impl RevocationIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revoke(&mut self, lease_id: &str) {
        if self.revoked.insert(lease_id.to_string()) {
            self.epoch = self.epoch.saturating_add(1);
        }
    }

    pub fn is_revoked(&self, lease_id: &str) -> bool {
        self.revoked.contains(lease_id)
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

/// Synchronous lease lookup used by the pure validation functions. Hosts
/// backed by the database load the chain asynchronously, then validate
/// against a map.
pub trait LeaseResolver {
    fn lease(&self, id: &str) -> Option<LeaseDocument>;
}

impl LeaseResolver for HashMap<String, LeaseDocument> {
    fn lease(&self, id: &str) -> Option<LeaseDocument> {
        self.get(id).cloned()
    }
}

/// Tracks one-shot consumption. The durable implementation is the
/// `kernel_one_shot_uses` table; this trait lets validation stay pure.
pub trait OneShotTracker {
    /// Returns `true` if the lease was newly consumed, `false` on replay.
    fn consume(&mut self, lease_id: &str) -> bool;
    fn is_consumed(&self, lease_id: &str) -> bool;
}

impl OneShotTracker for HashSet<String> {
    fn consume(&mut self, lease_id: &str) -> bool {
        self.insert(lease_id.to_string())
    }

    fn is_consumed(&self, lease_id: &str) -> bool {
        self.contains(lease_id)
    }
}

// ---------------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------------

pub struct RootLeaseParams {
    pub lease_id: String,
    pub subject: String,
    pub scope: ResourceScope,
    pub limits: LeaseLimits,
    pub depth_limit: u32,
    pub lease_nonce: String,
    pub issued_at_ms: i64,
}

pub struct ChildLeaseParams {
    pub lease_id: String,
    pub subject: String,
    pub scope: ResourceScope,
    pub limits: LeaseLimits,
    pub depth_limit: u32,
    pub lease_nonce: String,
    pub issued_at_ms: i64,
}

fn check_time_bounds(limits: &LeaseLimits, now_ms: i64) -> Result<(), LeaseError> {
    if limits.not_before_ms >= limits.expires_at_ms {
        return Err(LeaseError::InvalidTimeBounds(
            limits.not_before_ms,
            limits.expires_at_ms,
        ));
    }
    if limits.expires_at_ms <= now_ms {
        return Err(LeaseError::AlreadyExpired);
    }
    Ok(())
}

/// Mint a root lease: standing policy authority, signed by the kernel issuer.
pub fn mint_root_lease(
    params: RootLeaseParams,
    keys: &KernelKeys,
    sessions: &SessionRegistry,
    ledger: &BudgetLedger,
    nonces: &NonceStore,
    now_ms: i64,
) -> Result<LeaseDocument, LeaseError> {
    check_time_bounds(&params.limits, now_ms)?;
    if !sessions.get(&params.subject).is_some_and(|r| r.active) {
        return Err(LeaseError::SubjectInactive(params.subject.clone()));
    }
    if params.depth_limit == 0 {
        return Err(LeaseError::DepthViolation(0, 0));
    }
    nonces.check_and_insert(
        &params.lease_nonce,
        now_ms,
        params.limits.expires_at_ms.saturating_sub(now_ms),
    )?;
    let mut doc = LeaseDocument {
        protocol_version: LEASE_PROTOCOL_VERSION,
        lease_id: params.lease_id.clone(),
        parent_id: None,
        subject: params.subject,
        issuer_key_id: keys.issuer_key_id.clone(),
        issued_at_ms: params.issued_at_ms,
        scope: params.scope,
        limits: params.limits.clone(),
        depth: 0,
        depth_limit: params.depth_limit,
        lease_nonce: params.lease_nonce,
        signature: String::new(),
    };
    ledger.register_lease(&doc.lease_id, &params.limits.budget)?;
    let sig = keys.issuer_sign(&doc.signing_bytes()?);
    doc.signature = hex::encode(sig.to_bytes());
    Ok(doc)
}

/// Mint a child lease: the full `valid(child, parent)` predicate.
///
/// The parent must have been validated (chain, signature, revocation) before
/// this call. The budget reservation happens after every fallible check, so a
/// failed mint never leaks a reservation.
#[allow(clippy::too_many_arguments)]
pub fn mint_child_lease(
    parent: &LeaseDocument,
    params: ChildLeaseParams,
    parent_signing_key: &SigningKey,
    sessions: &SessionRegistry,
    revocations: &RevocationIndex,
    ledger: &BudgetLedger,
    nonces: &NonceStore,
    now_ms: i64,
) -> Result<LeaseDocument, LeaseError> {
    if parent.protocol_version != LEASE_PROTOCOL_VERSION {
        return Err(LeaseError::VersionMismatch(parent.protocol_version));
    }
    if !parent.live_at(now_ms) {
        return Err(LeaseError::AlreadyExpired);
    }
    if revocations.is_revoked(&parent.lease_id) {
        return Err(LeaseError::Revoked(parent.lease_id.clone()));
    }
    if parent.limits.single_use {
        return Err(LeaseError::SingleUseDelegation);
    }
    if !sessions.is_active_descendant(&params.subject, &parent.subject) {
        return Err(LeaseError::SubjectNotDescendant(
            params.subject.clone(),
            parent.subject.clone(),
        ));
    }
    // Mechanical subset proof over every resource dimension.
    params.scope.is_subset_of(&parent.scope)?;
    // Time bounds narrow monotonically.
    check_time_bounds(&params.limits, now_ms)?;
    if params.limits.expires_at_ms > parent.limits.expires_at_ms {
        return Err(LeaseError::ExpiryTooWide(
            params.limits.expires_at_ms,
            parent.limits.expires_at_ms,
        ));
    }
    if params.limits.not_before_ms < parent.limits.not_before_ms {
        return Err(LeaseError::NotBeforeTooEarly(
            params.limits.not_before_ms,
            parent.limits.not_before_ms,
        ));
    }
    // Depth: child.depth = parent.depth + 1 < parent.depth_limit.
    let child_depth = parent.depth.saturating_add(1);
    if child_depth >= parent.depth_limit {
        return Err(LeaseError::DepthViolation(child_depth, parent.depth_limit));
    }
    if params.depth_limit > parent.depth_limit || params.depth_limit <= child_depth {
        return Err(LeaseError::DepthLimitTooWide(
            params.depth_limit,
            parent.depth_limit,
        ));
    }
    nonces.check_and_insert(
        &params.lease_nonce,
        now_ms,
        params.limits.expires_at_ms.saturating_sub(now_ms),
    )?;
    let mut doc = LeaseDocument {
        protocol_version: LEASE_PROTOCOL_VERSION,
        lease_id: params.lease_id.clone(),
        parent_id: Some(parent.lease_id.clone()),
        subject: params.subject,
        issuer_key_id: parent.subject.clone(),
        issued_at_ms: params.issued_at_ms,
        scope: params.scope,
        limits: params.limits.clone(),
        depth: child_depth,
        depth_limit: params.depth_limit,
        lease_nonce: params.lease_nonce,
        signature: String::new(),
    };
    // Reservation, not comparison: the child's maximum is held against the
    // parent's remaining balance. All checks above passed, so this is the
    // only remaining fallible step before the infallible sign.
    ledger.reserve(
        &parent.lease_id,
        &doc.lease_id,
        &params.limits.budget,
        now_ms,
    )?;
    ledger.register_lease(&doc.lease_id, &params.limits.budget)?;
    doc.sign(parent_signing_key);
    Ok(doc)
}

// ---------------------------------------------------------------------------
// Chain validation
// ---------------------------------------------------------------------------

/// A validated chain, leaf first.
#[derive(Clone, Debug)]
pub struct ValidatedChain {
    pub leaf: LeaseDocument,
    pub chain: Vec<LeaseDocument>,
}

/// Validate a full lease chain: signatures, expiry, revocation propagation,
/// depth discipline, and re-proven subset relations (defense in depth against
/// a tampered store).
///
/// `presented_chain` is the leaf→root id list from the envelope; the walked
/// parent links must match it exactly, preventing chain substitution.
#[allow(clippy::too_many_arguments)]
pub fn validate_chain(
    resolver: &dyn LeaseResolver,
    presented_chain: &[String],
    revocations: &RevocationIndex,
    sessions: &SessionRegistry,
    keys: &KernelKeys,
    one_shot: &dyn OneShotTracker,
    now_ms: i64,
) -> Result<ValidatedChain, LeaseError> {
    if presented_chain.is_empty() {
        return Err(LeaseError::NotFound("<empty chain>".to_string()));
    }
    let mut chain: Vec<LeaseDocument> = Vec::new();
    let mut current_id = presented_chain[0].clone();
    for _ in 0..128 {
        if chain
            .iter()
            .any(|d: &LeaseDocument| d.lease_id == current_id)
        {
            return Err(LeaseError::ChainCycle);
        }
        let doc = resolver
            .lease(&current_id)
            .ok_or_else(|| LeaseError::NotFound(current_id.clone()))?;
        if doc.protocol_version != LEASE_PROTOCOL_VERSION {
            return Err(LeaseError::VersionMismatch(doc.protocol_version));
        }
        chain.push(doc.clone());
        match &doc.parent_id {
            Some(parent) => current_id = parent.clone(),
            None => break,
        }
    }
    // The walked chain must match the presented chain exactly.
    let walked_ids: Vec<&String> = chain.iter().map(|d| &d.lease_id).collect();
    let presented_ids: Vec<&String> = presented_chain.iter().collect();
    if walked_ids != presented_ids {
        return Err(LeaseError::ChainBreak(
            presented_chain.join("->"),
            walked_ids
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
                .join("->"),
        ));
    }
    // Per-document checks, leaf → root.
    for (i, doc) in chain.iter().enumerate() {
        if revocations.is_revoked(&doc.lease_id) {
            return Err(LeaseError::Revoked(doc.lease_id.clone()));
        }
        if !doc.live_at(now_ms) {
            return Err(LeaseError::AlreadyExpired);
        }
        if doc.limits.single_use && one_shot.is_consumed(&doc.lease_id) {
            return Err(LeaseError::AlreadyConsumed(doc.lease_id.clone()));
        }
        if i + 1 < chain.len() {
            let parent = &chain[i + 1];
            // Issuer binding: a child's issuer is its parent's subject, and
            // the signature verifies under the parent subject's session key.
            if doc.issuer_key_id != parent.subject {
                return Err(LeaseError::IssuerMismatch(
                    doc.issuer_key_id.clone(),
                    parent.subject.clone(),
                ));
            }
            let key = sessions
                .get(&parent.subject)
                .map(|r| r.verifying_key)
                .ok_or_else(|| LeaseError::UnknownKey(parent.subject.clone()))?;
            doc.verify_signature(&key)?;
            if doc.depth != parent.depth + 1 {
                return Err(LeaseError::DepthViolation(doc.depth, parent.depth_limit));
            }
            if doc.depth >= parent.depth_limit {
                return Err(LeaseError::DepthViolation(doc.depth, parent.depth_limit));
            }
            if doc.depth_limit > parent.depth_limit {
                return Err(LeaseError::DepthLimitTooWide(
                    doc.depth_limit,
                    parent.depth_limit,
                ));
            }
            if doc.limits.expires_at_ms > parent.limits.expires_at_ms {
                return Err(LeaseError::ExpiryTooWide(
                    doc.limits.expires_at_ms,
                    parent.limits.expires_at_ms,
                ));
            }
            // Re-prove narrowing: a tampered store cannot widen a child.
            doc.scope.is_subset_of(&parent.scope)?;
        } else {
            // Root: signed by the kernel issuer.
            if doc.issuer_key_id != keys.issuer_key_id {
                return Err(LeaseError::IssuerMismatch(
                    doc.issuer_key_id.clone(),
                    keys.issuer_key_id.clone(),
                ));
            }
            doc.verify_signature(&keys.issuer_verifying())?;
            if doc.depth != 0 {
                return Err(LeaseError::DepthViolation(doc.depth, doc.depth_limit));
            }
        }
        if doc.depth >= doc.depth_limit {
            return Err(LeaseError::DepthViolation(doc.depth, doc.depth_limit));
        }
    }
    let leaf = chain[0].clone();
    Ok(ValidatedChain { leaf, chain })
}

// ---------------------------------------------------------------------------
// One-shot leases and VHL approvals
// ---------------------------------------------------------------------------

/// A human VHL approval grant: the human approved an exact action digest.
/// Modeled on [`crate::approval::ApprovalRequest`]'s one-shot semantics —
/// digest-bound, nonce-bound, single-use, short expiry — but the grant mints
/// a kernel-signed single-use lease rather than suspending policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Serialize)]
struct GrantSigningView<'a> {
    approval_id: &'a str,
    action_digest: &'a str,
    session_subject: &'a str,
    signer_key_id: &'a str,
    nonce: &'a str,
    created_at_ms: i64,
    expires_at_ms: i64,
}

impl OneShotGrant {
    pub fn signing_bytes(&self) -> Result<Vec<u8>, LeaseError> {
        let view = GrantSigningView {
            approval_id: &self.approval_id,
            action_digest: &self.action_digest,
            session_subject: &self.session_subject,
            signer_key_id: &self.signer_key_id,
            nonce: &self.nonce,
            created_at_ms: self.created_at_ms,
            expires_at_ms: self.expires_at_ms,
        };
        canonical_json(
            &serde_json::to_value(view).map_err(|e| LeaseError::Encoding(e.to_string()))?,
        )
        .map_err(LeaseError::ProtocolCanonical)
    }

    pub fn sign(&mut self, key: &SigningKey) {
        let bytes = self.signing_bytes().expect("grant signing is infallible");
        self.signature = hex::encode(key.sign(&bytes).to_bytes());
    }

    pub fn verify(&self, key: &VerifyingKey) -> Result<(), LeaseError> {
        let bytes = self.signing_bytes()?;
        let sig_bytes: [u8; 64] = hex::decode(&self.signature)
            .map_err(|_| LeaseError::BadSignature)?
            .try_into()
            .map_err(|_| LeaseError::BadSignature)?;
        key.verify(&bytes, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| LeaseError::BadSignature)
    }
}

/// The canonicalized resources of one action, derived from its envelope.
/// This is what a one-shot lease's scope is built from, and what the
/// authorizer checks against the covering lease.
pub struct CanonicalAction {
    pub digest: String,
    pub tool_name: ToolName,
    pub tool_version: semver::Version,
    pub paths: Vec<CanonicalPath>,
    /// Declared rights per path, parallel to `paths`, mapped from the frozen
    /// [`pi_boundary::PathRights`] at the envelope boundary.
    pub path_rights: Vec<PathRights>,
    pub destinations: Vec<NetworkDestination>,
    pub secrets: Vec<SecretRef>,
    pub effects: Vec<EffectClass>,
}

impl CanonicalAction {
    pub fn from_envelope(
        env: &ActionEnvelope,
        resolver: &dyn PathResolver,
        case_insensitive_fs: bool,
    ) -> Result<Self, LeaseError> {
        env.validate()
            .map_err(|e| LeaseError::BadEnvelope(e.to_string()))?;
        let tool_name =
            ToolName::parse(&env.tool.name).map_err(|e| LeaseError::BadEnvelope(e.to_string()))?;
        let tool_version = semver::Version::parse(&env.tool.version)
            .map_err(|e| LeaseError::BadEnvelope(format!("tool version: {e}")))?;
        let mut paths = Vec::new();
        let mut path_rights = Vec::new();
        for p in &env.resources.paths {
            paths.push(
                CanonicalPath::parse(&p.path, resolver, case_insensitive_fs)
                    .map_err(LeaseError::Canonical)?,
            );
            // The frozen contract declares per-resource rights; the kernel
            // authorizes exactly what the envelope declares, nothing more.
            path_rights.push(match p.rights {
                crate::pi_boundary::PathRights::Read => PathRights::READ,
                crate::pi_boundary::PathRights::Write => PathRights::READ_WRITE,
            });
        }
        let mut destinations = Vec::new();
        for nr in &env.resources.network {
            // Bracket IPv6 literals so the destination parses as one host.
            let host = if nr.host.contains(':') && !nr.host.starts_with('[') {
                format!("[{}]", nr.host)
            } else {
                nr.host.clone()
            };
            let rendered = format!("{}://{}:{}", nr.scheme, host, nr.port);
            destinations.push(
                NetworkDestination::parse(&rendered, &[])
                    .map_err(|e| LeaseError::BadEnvelope(e.to_string()))?,
            );
        }
        let mut secrets = Vec::new();
        for s in &env.resources.secrets {
            secrets.push(SecretRef::parse(&s.id).map_err(LeaseError::Canonical)?);
        }
        let digest = env
            .digest()
            .map_err(|e| LeaseError::BadEnvelope(e.to_string()))?;
        Ok(Self {
            digest,
            tool_name,
            tool_version,
            paths,
            path_rights,
            destinations,
            secrets,
            effects: EffectClass::from_wire(&env.expected_effects, env.resources.secrets.len()),
        })
    }

    /// The exact scope authorizing this action and nothing else.
    fn exact_scope(&self) -> ResourceScope {
        let mut scope = ResourceScope::default();
        scope.tools.insert(
            self.tool_name.as_str().to_string(),
            semver::VersionReq::parse(&format!("={}", self.tool_version)).expect("pinned"),
        );
        debug_assert_eq!(
            self.paths.len(),
            self.path_rights.len(),
            "path_rights is parallel to paths"
        );
        for (root, rights) in self.paths.iter().zip(self.path_rights.iter()) {
            scope.paths.push(PathGrant {
                root: root.clone(),
                rights: *rights,
            });
        }
        scope.destinations.extend(self.destinations.iter().cloned());
        scope
            .secrets
            .extend(self.secrets.iter().map(|s| s.as_str().to_string()));
        scope.effects = self.effects.clone();
        scope
    }
}

/// Mint a single-use lease from a human VHL approval grant.
///
/// The lease authorizes exactly the approved action digest, once. Metered
/// consumption (tokens, spend) is debited against the session's standing
/// budget lease, not the one-shot: the one-shot carries `executions = 1`.
#[allow(clippy::too_many_arguments)]
pub fn mint_one_shot_lease(
    grant: &OneShotGrant,
    vhl_key: &VerifyingKey,
    action: &CanonicalAction,
    keys: &KernelKeys,
    sessions: &SessionRegistry,
    ledger: &BudgetLedger,
    nonces: &NonceStore,
    now_ms: i64,
) -> Result<LeaseDocument, LeaseError> {
    grant.verify(vhl_key)?;
    if grant.action_digest != action.digest {
        // Changing any argument invalidates the approval — fail closed,
        // mirroring ApprovalRequest::consume's fingerprint check.
        return Err(LeaseError::BadEnvelope(
            "approval digest does not match action".to_string(),
        ));
    }
    if grant.created_at_ms > now_ms || grant.expires_at_ms <= now_ms {
        return Err(LeaseError::ActionExpired);
    }
    if grant.created_at_ms >= grant.expires_at_ms {
        return Err(LeaseError::InvalidTimeBounds(
            grant.created_at_ms,
            grant.expires_at_ms,
        ));
    }
    nonces.check_and_insert(
        &grant.nonce,
        now_ms,
        grant.expires_at_ms.saturating_sub(now_ms),
    )?;
    sessions
        .get(&grant.session_subject)
        .filter(|r| r.active)
        .ok_or_else(|| LeaseError::SubjectInactive(grant.session_subject.clone()))?;
    let budget = Budget::new().set(BudgetDimension::Executions, 1);
    let mut doc = LeaseDocument {
        protocol_version: LEASE_PROTOCOL_VERSION,
        lease_id: Uuid::new_v4().to_string(),
        parent_id: None,
        subject: grant.session_subject.clone(),
        issuer_key_id: keys.issuer_key_id.clone(),
        issued_at_ms: now_ms,
        scope: action.exact_scope(),
        limits: LeaseLimits {
            not_before_ms: now_ms,
            expires_at_ms: grant.expires_at_ms,
            budget: budget.clone(),
            max_executions: Some(1),
            single_use: true,
        },
        depth: 0,
        depth_limit: 1,
        lease_nonce: format!("oneshot:{}", grant.nonce),
        signature: String::new(),
    };
    ledger.register_lease(&doc.lease_id, &budget)?;
    let sig = keys.issuer_sign(&doc.signing_bytes()?);
    doc.signature = hex::encode(sig.to_bytes());
    Ok(doc)
}

/// Consume a single-use lease: the second call fails as a replay.
pub fn consume_single_use(
    doc: &LeaseDocument,
    tracker: &mut dyn OneShotTracker,
    now_ms: i64,
) -> Result<(), LeaseError> {
    if !doc.limits.single_use {
        return Err(LeaseError::NotSingleUse(doc.lease_id.clone()));
    }
    if !doc.live_at(now_ms) {
        return Err(LeaseError::AlreadyExpired);
    }
    if !tracker.consume(&doc.lease_id) {
        return Err(LeaseError::AlreadyConsumed(doc.lease_id.clone()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Action authorization → PolicyDecision v1
// ---------------------------------------------------------------------------

/// A VHL approval request created when an action has no covering lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VhlRequest {
    pub request_id: String,
    pub action_digest: String,
    pub session_subject: String,
    pub nonce: String,
    pub expires_at_ms: i64,
}

pub trait ApprovalOutbox {
    fn push(&mut self, req: VhlRequest);
}

impl ApprovalOutbox for Vec<VhlRequest> {
    fn push(&mut self, req: VhlRequest) {
        Vec::push(self, req);
    }
}

/// Parameters for [`authorize_envelope`].
pub struct AuthorizeParams {
    pub now_ms: i64,
    pub case_insensitive_fs: bool,
    /// When true and no lease covers the action, emit a [`VhlRequest`] and
    /// return `PendingApproval` instead of `Deny`.
    pub allow_approval_fallback: bool,
    /// TTL for the VHL request when falling back.
    pub approval_ttl_ms: i64,
}

/// Map a lease-chain validation failure to a typed [`DenyReason`].
///
/// Identity-shaped failures (unknown, revoked, consumed, issuer mismatch)
/// get their own codes; structural failures fall back to `invalid_envelope`
/// with the full detail preserved in the reason.
fn deny_reason_for_chain_error(e: &LeaseError) -> DenyReason {
    match e {
        LeaseError::NotFound(id) => DenyReason::unknown_lease(id.clone()),
        LeaseError::Revoked(id) => DenyReason::lease_revoked(id.clone()),
        LeaseError::AlreadyConsumed(id) => {
            DenyReason::replay_detected(format!("one-shot lease {id} already consumed"))
        }
        LeaseError::IssuerMismatch(issuer, parent) => DenyReason::subject_mismatch(format!(
            "issuer {issuer} does not match parent subject {parent}"
        )),
        LeaseError::UnknownKey(subject) => {
            DenyReason::subject_mismatch(format!("unknown session key for {subject}"))
        }
        _ => DenyReason::invalid_envelope(format!("lease chain invalid: {e}")),
    }
}

/// Authorize one [`ActionEnvelope`] against the lease store, producing the
/// frozen [`PolicyDecision`] wire shape.
///
/// This is the kernel's policy decision point (the rebuild's analogue of the
/// old trust-gate evaluation): structural checks only, no natural-language
/// interpretation. There is no default allow.
///
/// The decision carries no action digest or timestamp itself; the binding to
/// the envelope happens at the wire layer
/// ([`crate::pi_boundary::KernelWireResponse::action_digest`]).
#[allow(clippy::too_many_arguments)]
pub fn authorize_envelope(
    env: &ActionEnvelope,
    resolver: &dyn PathResolver,
    lease_resolver: &dyn LeaseResolver,
    revocations: &RevocationIndex,
    sessions: &SessionRegistry,
    keys: &KernelKeys,
    one_shot: &mut dyn OneShotTracker,
    nonces: &NonceStore,
    ledger: &BudgetLedger,
    outbox: &mut dyn ApprovalOutbox,
    params: &AuthorizeParams,
) -> PolicyDecision {
    let now_ms = params.now_ms;
    // Parse and canonicalize the envelope first; a rejected envelope denies
    // with no lease information at all.
    let action = match CanonicalAction::from_envelope(env, resolver, params.case_insensitive_fs) {
        Ok(a) => a,
        Err(e) => {
            return PolicyDecision::deny(DenyReason::invalid_envelope(format!(
                "envelope rejected: {e}"
            )));
        }
    };
    // Hard deadline on the envelope itself.
    if now_ms >= env.expires_at_ms {
        return PolicyDecision::deny(DenyReason::expired_action("action past its hard deadline"));
    }
    // Replay protection on (action_id, nonce).
    let envelope_nonce = format!("{}:{}", env.action_id, env.nonce);
    let ttl = env.expires_at_ms.saturating_sub(now_ms).max(1);
    if let Err(e) = nonces.check_and_insert(&envelope_nonce, now_ms, ttl) {
        return PolicyDecision::deny(DenyReason::replay_detected(format!("replay rejected: {e}")));
    }
    if env.lease_chain.is_empty() {
        return no_covering_lease(&action, env, outbox, params);
    }
    let presented: Vec<String> = env.lease_chain.iter().map(|id| id.to_string()).collect();
    let chain = match validate_chain(
        lease_resolver,
        &presented,
        revocations,
        sessions,
        keys,
        one_shot,
        now_ms,
    ) {
        Ok(c) => c,
        Err(e) => return PolicyDecision::deny(deny_reason_for_chain_error(&e)),
    };
    let leaf = chain.leaf;
    // Single-use leases are consumed exactly once, at authorization time.
    if leaf.limits.single_use
        && let Err(e) = consume_single_use(&leaf, one_shot, now_ms)
    {
        let reason = match e {
            LeaseError::AlreadyConsumed(id) => {
                DenyReason::replay_detected(format!("one-shot lease {id} already consumed"))
            }
            _ => DenyReason::invalid_envelope(format!("one-shot lease: {e}")),
        };
        return PolicyDecision::deny(reason);
    }
    // The action's exact scope must be covered by the leaf lease.
    if let Err(e) = action.exact_scope().is_subset_of(&leaf.scope) {
        return PolicyDecision::deny(DenyReason::scope_exceeded(format!(
            "action not covered by lease: {e}"
        )));
    }
    // Fail fast when the lease has no execution budget left.
    let need = Budget::new().set(BudgetDimension::Executions, 1);
    match ledger.remaining(&leaf.lease_id) {
        Ok(remaining) if remaining.covers(&need) => {}
        _ => {
            return PolicyDecision::deny(DenyReason::scope_exceeded("lease budget exhausted"));
        }
    }
    PolicyDecision::allow(vec![])
}

fn no_covering_lease(
    action: &CanonicalAction,
    env: &ActionEnvelope,
    outbox: &mut dyn ApprovalOutbox,
    params: &AuthorizeParams,
) -> PolicyDecision {
    if !params.allow_approval_fallback {
        return PolicyDecision::deny(DenyReason::no_lease("no covering lease"));
    }
    let req = VhlRequest {
        request_id: format!("vhl_{}", Uuid::new_v4()),
        action_digest: action.digest.clone(),
        session_subject: env.session_id.clone(),
        nonce: env.nonce.clone(),
        expires_at_ms: params.now_ms.saturating_add(params.approval_ttl_ms),
    };
    let request_id = req.request_id.clone();
    outbox.push(req);
    PolicyDecision::pending_approval(request_id, "no covering lease; human approval requested")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::FakeResolver;

    fn test_keys() -> (KernelKeys, SigningKey, VerifyingKey) {
        use rand::rngs::OsRng;
        let keys = KernelKeys::generate();
        let session_key = SigningKey::generate(&mut OsRng);
        let session_vk = session_key.verifying_key();
        (keys, session_key, session_vk)
    }

    fn test_sessions(session_vk: VerifyingKey, child_vk: VerifyingKey) -> SessionRegistry {
        let mut s = SessionRegistry::new();
        s.register("ed25519:parent-session".to_string(), None, session_vk);
        s.register(
            "ed25519:child-session".to_string(),
            Some("ed25519:parent-session".to_string()),
            child_vk,
        );
        s
    }

    fn parent_scope() -> ResourceScope {
        let r = FakeResolver::default();
        let mut scope = ResourceScope::default();
        scope.tools.insert(
            "fs.read".to_string(),
            semver::VersionReq::parse("^1.0").unwrap(),
        );
        scope.paths.push(PathGrant {
            root: CanonicalPath::parse("/workspace", &r, false).unwrap(),
            rights: PathRights::READ,
        });
        scope.effects.push(EffectClass::Read);
        scope
    }

    fn root_params(scope: ResourceScope) -> RootLeaseParams {
        RootLeaseParams {
            lease_id: "lease-root-1".to_string(),
            subject: "ed25519:parent-session".to_string(),
            scope,
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 1_000_000,
                budget: Budget::new()
                    .set(BudgetDimension::Executions, 100)
                    .set(BudgetDimension::SpendMicros, 10_000),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: "root-nonce-1".to_string(),
            issued_at_ms: 100,
        }
    }

    #[test]
    fn root_mint_sign_verify() {
        let (keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let doc = mint_root_lease(
            root_params(parent_scope()),
            &keys,
            &sessions,
            &ledger,
            &nonces,
            100,
        )
        .unwrap();
        assert!(doc.is_root());
        doc.verify_signature(&keys.issuer_verifying()).unwrap();
        // Tampering invalidates the signature.
        let mut evil = doc.clone();
        evil.depth_limit = 99;
        assert!(evil.verify_signature(&keys.issuer_verifying()).is_err());
    }

    #[test]
    fn child_mint_narrowing() {
        let (keys, session_key, session_vk) = test_keys();
        use rand::rngs::OsRng;
        let child_key = SigningKey::generate(&mut OsRng);
        let sessions = test_sessions(session_vk, child_key.verifying_key());
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let root = mint_root_lease(
            root_params(parent_scope()),
            &keys,
            &sessions,
            &ledger,
            &nonces,
            100,
        )
        .unwrap();

        // Narrower child: pinned version, sub-path, smaller budget.
        let r = FakeResolver::default();
        let mut scope = ResourceScope::default();
        scope.tools.insert(
            "fs.read".to_string(),
            semver::VersionReq::parse("=1.2.3").unwrap(),
        );
        scope.paths.push(PathGrant {
            root: CanonicalPath::parse("/workspace/src", &r, false).unwrap(),
            rights: PathRights::READ,
        });
        scope.effects.push(EffectClass::Read);
        let child = mint_child_lease(
            &root,
            ChildLeaseParams {
                lease_id: "lease-child-1".to_string(),
                subject: "ed25519:child-session".to_string(),
                scope,
                limits: LeaseLimits {
                    not_before_ms: 0,
                    expires_at_ms: 500_000,
                    budget: Budget::new().set(BudgetDimension::Executions, 10),
                    max_executions: None,
                    single_use: false,
                },
                depth_limit: 4,
                lease_nonce: "child-nonce-1".to_string(),
                issued_at_ms: 200,
            },
            &session_key,
            &sessions,
            &RevocationIndex::new(),
            &ledger,
            &nonces,
            200,
        )
        .unwrap();
        assert_eq!(child.depth, 1);
        assert_eq!(child.parent_id.as_deref(), Some("lease-root-1"));
        child.verify_signature(&session_vk).unwrap();

        // Wider child is rejected.
        let mut wide = ResourceScope::default();
        wide.tools.insert(
            "fs.read".to_string(),
            semver::VersionReq::parse("=1.2.3").unwrap(),
        );
        wide.paths.push(PathGrant {
            root: CanonicalPath::parse("/other", &r, false).unwrap(),
            rights: PathRights::READ,
        });
        wide.effects.push(EffectClass::Read);
        let err = mint_child_lease(
            &root,
            ChildLeaseParams {
                lease_id: "lease-child-2".to_string(),
                subject: "ed25519:child-session".to_string(),
                scope: wide,
                limits: LeaseLimits {
                    not_before_ms: 0,
                    expires_at_ms: 500_000,
                    budget: Budget::new(),
                    max_executions: None,
                    single_use: false,
                },
                depth_limit: 4,
                lease_nonce: "child-nonce-2".to_string(),
                issued_at_ms: 200,
            },
            &session_key,
            &sessions,
            &RevocationIndex::new(),
            &ledger,
            &nonces,
            200,
        );
        assert!(matches!(err, Err(LeaseError::Subset(_))));
    }

    #[test]
    fn chain_validation_and_revocation() {
        let (keys, session_key, session_vk) = test_keys();
        use rand::rngs::OsRng;
        let child_key = SigningKey::generate(&mut OsRng);
        let sessions = test_sessions(session_vk, child_key.verifying_key());
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let root = mint_root_lease(
            root_params(parent_scope()),
            &keys,
            &sessions,
            &ledger,
            &nonces,
            100,
        )
        .unwrap();
        let r = FakeResolver::default();
        let mut scope = ResourceScope::default();
        scope.tools.insert(
            "fs.read".to_string(),
            semver::VersionReq::parse("=1.2.3").unwrap(),
        );
        scope.paths.push(PathGrant {
            root: CanonicalPath::parse("/workspace/src", &r, false).unwrap(),
            rights: PathRights::READ,
        });
        scope.effects.push(EffectClass::Read);
        let child = mint_child_lease(
            &root,
            ChildLeaseParams {
                lease_id: "lease-child-1".to_string(),
                subject: "ed25519:child-session".to_string(),
                scope,
                limits: LeaseLimits {
                    not_before_ms: 0,
                    expires_at_ms: 500_000,
                    budget: Budget::new().set(BudgetDimension::Executions, 10),
                    max_executions: None,
                    single_use: false,
                },
                depth_limit: 4,
                lease_nonce: "child-nonce-3".to_string(),
                issued_at_ms: 200,
            },
            &session_key,
            &sessions,
            &RevocationIndex::new(),
            &ledger,
            &nonces,
            200,
        )
        .unwrap();
        let mut map = HashMap::new();
        map.insert(root.lease_id.clone(), root.clone());
        map.insert(child.lease_id.clone(), child.clone());
        let revocations = RevocationIndex::new();
        let one_shot = HashSet::new();
        let chain_ids = vec![child.lease_id.clone(), root.lease_id.clone()];
        let validated = validate_chain(
            &map,
            &chain_ids,
            &revocations,
            &sessions,
            &keys,
            &one_shot,
            300,
        )
        .unwrap();
        assert_eq!(validated.leaf.lease_id, "lease-child-1");

        // Revoking the root transitively invalidates the child.
        let mut revocations = RevocationIndex::new();
        revocations.revoke(&root.lease_id);
        let err = validate_chain(
            &map,
            &chain_ids,
            &revocations,
            &sessions,
            &keys,
            &one_shot,
            300,
        );
        assert!(matches!(err, Err(LeaseError::Revoked(_))));
    }

    #[test]
    fn one_shot_grant_flow() {
        use rand::rngs::OsRng;
        let (keys, _, session_vk) = test_keys();
        let vhl_key = SigningKey::generate(&mut OsRng);
        let vhl_vk = vhl_key.verifying_key();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let r = FakeResolver::default();

        // Build an action and its grant.
        let env = ActionEnvelope {
            version: crate::pi_boundary::ACTION_ENVELOPE_VERSION,
            action_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            session_id: "ed25519:parent-session".to_string(),
            tool: crate::pi_boundary::ToolRef {
                name: "fs.read".to_string(),
                version: "1.2.3".to_string(),
            },
            // The frozen contract requires integer-only arguments.
            arguments: [("n".to_string(), serde_json::json!(1))]
                .into_iter()
                .collect(),
            inputs: vec![],
            resources: crate::pi_boundary::ResourceSet {
                paths: vec![crate::pi_boundary::PathResource {
                    path: "/workspace/README.md".to_string(),
                    rights: crate::pi_boundary::PathRights::Read,
                }],
                network: vec![],
                secrets: vec![],
            },
            expected_effects: crate::pi_boundary::EffectClasses {
                file_read: true,
                file_write: false,
                network_egress: false,
                network_ingress: false,
                process_spawn: false,
            },
            lease_chain: vec![],
            nonce: "6ba7b810-9dad-11d1-80b4-00c04fd430c8".to_string(),
            expires_at_ms: 1_000_000,
        };
        let action = CanonicalAction::from_envelope(&env, &r, false).unwrap();
        let mut grant = OneShotGrant {
            approval_id: "appr-1".to_string(),
            action_digest: action.digest.clone(),
            session_subject: "ed25519:parent-session".to_string(),
            signer_key_id: "vhl-human-1".to_string(),
            nonce: "grant-nonce-1".to_string(),
            created_at_ms: 100,
            expires_at_ms: 10_000,
            signature: String::new(),
        };
        grant.sign(&vhl_key);
        let one_shot = mint_one_shot_lease(
            &grant, &vhl_vk, &action, &keys, &sessions, &ledger, &nonces, 200,
        )
        .unwrap();
        assert!(one_shot.limits.single_use);
        one_shot.verify_signature(&keys.issuer_verifying()).unwrap();

        // Authorize the exact action with the one-shot lease: allowed once.
        let mut map = HashMap::new();
        map.insert(one_shot.lease_id.clone(), one_shot.clone());
        let mut env2 = env.clone();
        env2.lease_chain = vec![crate::pi_boundary::LeaseId::from_uuid(
            one_shot.lease_id.parse().expect("one-shot id is a UUID"),
        )];
        let mut tracker: HashSet<String> = HashSet::new();
        let outbox: &mut Vec<VhlRequest> = &mut vec![];
        let params = AuthorizeParams {
            now_ms: 300,
            case_insensitive_fs: false,
            allow_approval_fallback: false,
            approval_ttl_ms: 60_000,
        };
        let d1 = authorize_envelope(
            &env2,
            &r,
            &map,
            &RevocationIndex::new(),
            &sessions,
            &keys,
            &mut tracker,
            &nonces,
            &ledger,
            outbox,
            &params,
        );
        assert!(d1.is_allow());
        // The frozen decision carries no digest; binding to the envelope
        // happens at the wire layer.
        let digest = env2.digest().unwrap();
        let wire = crate::pi_boundary::KernelWireResponse {
            protocol: crate::pi_boundary::KERNEL_WIRE_PROTOCOL.to_string(),
            decision: Some(d1),
            audit_sequence: Some(0),
            action_digest: Some(digest.clone()),
            error: None,
        };
        assert_eq!(wire.action_digest.as_deref(), Some(digest.as_str()));
        assert!(wire.decision.expect("decision").is_allow());
        // The one-shot is consumed exactly once, at authorization time.
        assert!(tracker.contains(&one_shot.lease_id));
        // Second authorization with the same envelope is rejected.
        let d2 = authorize_envelope(
            &env2,
            &r,
            &map,
            &RevocationIndex::new(),
            &sessions,
            &keys,
            &mut tracker,
            &nonces,
            &ledger,
            outbox,
            &params,
        );
        assert!(!d2.is_allow());
    }
}
