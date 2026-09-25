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
    budget::{Budget, BudgetDimension, BudgetError, BudgetLedger, ExecutionReservation},
    canonical::{
        CanonicalPath, EffectClass, HostPattern, NetworkDestination, PathGrant, PathResolver,
        PathRights, PortSet, ResourceScope, ScopeSubsetError, SecretRef, ToolName,
    },
    nonce::{NonceError, NonceStore},
    pi_boundary::{
        ActionEnvelope, BoundaryError, DecisionOutcome, DenyReason, Obligation, PolicyDecision,
        canonical_json,
    },
};

/// Contract version for [`LeaseDocument`].
///
/// v1 was frozen by Phase 0. Phase 1 added `approved_action_digest` (the
/// exact VHL-approved action digest carried by single-use leases), so the
/// contract is v2; v1 documents are rejected, fail closed.
pub const LEASE_PROTOCOL_VERSION: u32 = 2;

/// Maximum root-lease lifetime: 30 days (spec §6.4 retention bound).
pub const MAX_ROOT_LEASE_LIFETIME_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// Default session max lifetime: 24h (spec §6.3).
pub const DEFAULT_SESSION_MAX_LIFETIME_MS: i64 = 24 * 60 * 60 * 1000;

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
    /// For single-use (VHL approval) leases: the exact action digest the
    /// human approved, bound at mint time. `None` for standing leases.
    /// Covered by the issuer signature so a compromised store cannot
    /// rebind an approval to a different action.
    #[serde(default)]
    pub approved_action_digest: Option<String>,
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
    approved_action_digest: &'a Option<String>,
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
            approved_action_digest: &self.approved_action_digest,
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
    #[error("issued_at_ms {0} is after the authority time {1}: minting happens now")]
    IssuedInFuture(i64, i64),
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
    #[error("unknown issuer key generation {0}")]
    UnknownIssuerGeneration(String),
    #[error("issuer key generation {0} was killed")]
    KilledIssuerGeneration(String),
    #[error("root lease lifetime {0}ms exceeds maximum {1}ms")]
    ExceedsMaxLifetime(i64, i64),
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
///
/// Custody: the private keys live only in this struct and are zeroized when
/// it drops, via `ed25519-dalek`'s `Drop for SigningKey` (enabled by the
/// `zeroize` feature in `lumen-core/Cargo.toml`; the
/// `kernel_keys_zeroize_on_drop` test pins the feature so it cannot be
/// silently removed). They are never written to disk or logs. A kernel
/// restart generates fresh keys, which the host treats as a key rotation:
/// retired generations' verifying keys are retained durably and leases
/// signed under them keep verifying, resolved through
/// [`IssuerKeyResolver`]. Private keys are still never persisted — minting
/// always uses the current generation's private key.
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
    /// Boot-relative wall clock when the session was created. Used with
    /// [`SessionRegistry::max_lifetime_ms`] to bound the post-restart
    /// stolen-key window (spec §6.3).
    pub created_at_ms: i64,
}

/// Kernel-side session registry. The kernel holds session *signing* keys
/// separately in a private vault; this registry carries verifying keys and
/// liveness for the descendant check.
#[derive(Default)]
pub struct SessionRegistry {
    sessions: HashMap<String, SessionRecord>,
    /// Session max lifetime, if configured (spec §6.3; default 24h via
    /// [`DEFAULT_SESSION_MAX_LIFETIME_MS`]). Records older than this are
    /// dead for the TTL-checked descendant predicates. `None` disables the
    /// TTL; only the host's durable `kernel_sessions` hydration decides
    /// which records exist at all.
    max_lifetime_ms: Option<i64>,
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
        created_at_ms: i64,
    ) {
        self.sessions.insert(
            subject.clone(),
            SessionRecord {
                subject,
                parent_subject,
                verifying_key,
                active: true,
                created_at_ms,
            },
        );
    }

    /// Configure the session max lifetime (`None` disables the TTL).
    pub fn set_max_lifetime(&mut self, max_lifetime_ms: Option<i64>) {
        self.max_lifetime_ms = max_lifetime_ms;
    }

    pub fn deactivate(&mut self, subject: &str) {
        if let Some(record) = self.sessions.get_mut(subject) {
            record.active = false;
        }
    }

    pub fn get(&self, subject: &str) -> Option<&SessionRecord> {
        self.sessions.get(subject)
    }

    /// Active **and** within the session TTL at `now_ms`.
    fn record_live_at(&self, record: &SessionRecord, now_ms: i64) -> bool {
        if !record.active {
            return false;
        }
        match self.max_lifetime_ms {
            Some(ttl) => now_ms.saturating_sub(record.created_at_ms) < ttl,
            None => true,
        }
    }

    /// `subject` is a live descendant of `ancestor` (or the same live
    /// session — self-narrowing is safe delegation), with the TTL checked at
    /// every hop so a TTL-expired ancestor kills the whole subtree.
    pub fn is_active_descendant(&self, subject: &str, ancestor: &str, now_ms: i64) -> bool {
        let mut current = subject;
        for _ in 0..256 {
            let record = match self.sessions.get(current) {
                Some(r) if self.record_live_at(r, now_ms) => r,
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

    /// Active descendant subjects of `subject`, inclusive, TTL-checked.
    /// Used for post-restart destroy: everything named here loses authority
    /// when `subject` ends.
    pub fn active_descendants_inclusive(&self, subject: &str, now_ms: i64) -> Vec<String> {
        let mut out: Vec<String> = self
            .sessions
            .keys()
            .filter(|s| self.is_active_descendant(s, subject, now_ms))
            .cloned()
            .collect();
        out.sort();
        out
    }

    /// Full active-ancestry predicate: `subject` and every ancestor up to
    /// the root must be live (registered, active, within TTL) at `now_ms`.
    /// Unlike `is_active_descendant(subject, subject, …)` — which checks
    /// only the named record and returns before walking its ancestry — this
    /// walks the whole parent chain, so a live session under a destroyed
    /// or TTL-expired ancestor still fails closed. Bounded at 256 hops;
    /// deeper ancestry is treated as invalid (a cycle can never hydrate —
    /// boot rejects it — but belt and braces costs nothing here).
    pub fn is_subject_live(&self, subject: &str, now_ms: i64) -> bool {
        let mut current = subject;
        for _ in 0..256 {
            let record = match self.sessions.get(current) {
                Some(r) if self.record_live_at(r, now_ms) => r,
                _ => return false,
            };
            match &record.parent_subject {
                Some(parent) => current = parent,
                None => return true,
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

/// Resolves verifying keys for kernel issuer generations, current or
/// retired. The host implements this over the current [`KernelKeys`], the
/// durable `kernel_key_generations` map hydrated at open, and the
/// generation kill set (spec §4.1). `lumen-core` stays IO-free: it never
/// sees the database, only this trait.
pub trait IssuerKeyResolver {
    /// Verifying key for an issuer generation, current or retired.
    fn issuer_verifying_key(&self, key_id: &str) -> Option<VerifyingKey>;
    /// True if the generation was killed (§6.4).
    fn is_generation_killed(&self, key_id: &str) -> bool;
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
    // Retention bound (spec §6.4): cap how long a compromised old issuer
    // key stays a live signing capability. The cap is computed from the
    // trusted authority clock, never from the caller-supplied issued_at_ms:
    // otherwise a caller could set issued_at_ms = expires_at_ms - 1 and
    // get a 1ms computed lifetime for a year-long lease. A future
    // issued_at_ms is likewise rejected — minting happens now — but the
    // lifetime cap is checked first so the spoof cannot hide behind the
    // timestamp rejection.
    let lifetime = params.limits.expires_at_ms.saturating_sub(now_ms);
    if lifetime > MAX_ROOT_LEASE_LIFETIME_MS {
        return Err(LeaseError::ExceedsMaxLifetime(
            lifetime,
            MAX_ROOT_LEASE_LIFETIME_MS,
        ));
    }
    if params.issued_at_ms > now_ms {
        return Err(LeaseError::IssuedInFuture(params.issued_at_ms, now_ms));
    }
    if !sessions.is_subject_live(&params.subject, now_ms) {
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
        approved_action_digest: None,
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
    if !sessions.is_active_descendant(&params.subject, &parent.subject, now_ms) {
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
        approved_action_digest: None,
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
    issuer_resolver: &dyn IssuerKeyResolver,
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
            // Active ancestry at validation time: the issuing session's
            // whole ancestry must be live (registered, active, within
            // its TTL), not merely known. Revocation is the primary kill
            // path for a destroyed session's leases, but validation must
            // not depend on the revocation index alone — a lost
            // revocation row (crash between destroy and durable revoke)
            // must still fail closed here.
            if !sessions.is_subject_live(&parent.subject, now_ms) {
                return Err(LeaseError::SubjectInactive(parent.subject.clone()));
            }
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
            // Root: signed by the kernel issuer generation named in
            // issuer_key_id (current or retired). Revocation and expiry
            // were checked above (D4: liveness precedes crypto).
            //
            // The issuing session's whole ancestry must be live
            // (registered, active, within its TTL): a standing root lease
            // for a TTL-expired session must stop authorizing once the
            // kernel has been running past the session's TTL, not just
            // after a restart or for delegated chains.
            if !sessions.is_subject_live(&doc.subject, now_ms) {
                return Err(LeaseError::SubjectInactive(doc.subject.clone()));
            }
            if issuer_resolver.is_generation_killed(&doc.issuer_key_id) {
                return Err(LeaseError::KilledIssuerGeneration(
                    doc.issuer_key_id.clone(),
                ));
            }
            let key = issuer_resolver
                .issuer_verifying_key(&doc.issuer_key_id)
                .ok_or_else(|| LeaseError::UnknownIssuerGeneration(doc.issuer_key_id.clone()))?;
            doc.verify_signature(&key)?;
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

/// Validate a [`NetworkResource`] host *before* it is interpolated into a
/// URL authority. The host becomes the URL's authority component, so it
/// must not contain authority-breaking characters: `/`, `?`, and `#`
/// would truncate or redirect the parse, `@` would smuggle userinfo
/// (`x@b.com` authorizing `b.com`), and `:` would smuggle a port or be
/// misread. A colon is only allowed inside a valid bracketed IPv6 literal;
/// a bare IPv6 literal is bracketed here so it parses as one host.
fn validate_network_host(host: &str) -> Result<String, LeaseError> {
    let bad_envelope = |detail: String| LeaseError::BadEnvelope(detail);
    if host.is_empty() {
        return Err(bad_envelope("network host is empty".to_string()));
    }
    if host.contains(&['/', '?', '#', '@'][..]) {
        return Err(bad_envelope(format!(
            "network host {host:?} contains a reserved character"
        )));
    }
    if let Some(inner) = host.strip_prefix('[') {
        let inner = inner.strip_suffix(']').ok_or_else(|| {
            bad_envelope(format!("network host {host:?} has an unbalanced bracket"))
        })?;
        inner.parse::<std::net::Ipv6Addr>().map_err(|_| {
            bad_envelope(format!(
                "network host {host:?} is not a valid bracketed IPv6 literal"
            ))
        })?;
        return Ok(host.to_string());
    }
    if host.contains(':') {
        host.parse::<std::net::Ipv6Addr>().map_err(|_| {
            bad_envelope(format!(
                "network host {host:?} contains ':' but is not an IPv6 literal"
            ))
        })?;
        return Ok(format!("[{host}]"));
    }
    Ok(host.to_string())
}

/// Convert one [`NetworkResource`] to its canonical destination, refusing
/// any declaration that does not round-trip exactly.
///
/// After parsing, the normalized host must equal the declared host
/// (modulo brackets, case, and IDNA) and the port must match exactly: the
/// kernel authorizes precisely the declared destination, never a
/// normalized reinterpretation of it.
fn network_destination_from_resource(
    nr: &crate::pi_boundary::NetworkResource,
) -> Result<NetworkDestination, LeaseError> {
    let host = validate_network_host(&nr.host)?;
    let rendered = format!("{}://{}:{}", nr.scheme, host, nr.port);
    let dest = NetworkDestination::parse(&rendered, &[])
        .map_err(|e| LeaseError::BadEnvelope(e.to_string()))?;
    // Post-parse agreement: strip the brackets the URL form requires and
    // compare canonical patterns.
    let declared = nr
        .host
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(&nr.host);
    let expected =
        HostPattern::parse(declared).map_err(|e| LeaseError::BadEnvelope(e.to_string()))?;
    if dest.host != expected {
        return Err(LeaseError::BadEnvelope(format!(
            "network host {:?} parsed as {}",
            nr.host,
            dest.host.canonical_form()
        )));
    }
    if dest.ports != PortSet::single(nr.port) {
        return Err(LeaseError::BadEnvelope(format!(
            "network port {} did not survive parsing",
            nr.port
        )));
    }
    Ok(dest)
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
            destinations.push(network_destination_from_resource(nr)?);
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
        // The lease embodies the human's approval of one exact action
        // envelope (arguments and inputs included), not just its
        // structural scope. `authorize_envelope` re-checks this digest.
        approved_action_digest: Some(action.digest.clone()),
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

/// Build the [`Obligation`] binding an allowed action to its execution
/// budget reservation. The dispatcher settles the reservation after
/// dispatch (converting the hold into measured consumption) or releases it
/// when dispatch never happened or failed before any effect.
pub fn execution_settlement_obligation(
    reservation: &ExecutionReservation,
    lease_id: &str,
) -> Obligation {
    Obligation::SettleBudget {
        reservation_id: reservation.id.clone(),
        lease_id: lease_id.to_string(),
        action_id: reservation.action_id.clone(),
    }
}

/// Extract the execution reservation id from an `Allow` decision's
/// obligations, if the decision carries one.
pub fn execution_reservation_id(decision: &PolicyDecision) -> Option<&str> {
    match &decision.outcome {
        DecisionOutcome::Allow { obligations } => obligations.iter().find_map(|o| match o {
            Obligation::SettleBudget { reservation_id, .. } => Some(reservation_id.as_str()),
            _ => None,
        }),
        _ => None,
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
        LeaseError::UnknownIssuerGeneration(id) => {
            DenyReason::subject_mismatch(format!("unknown issuer generation {id}"))
        }
        LeaseError::KilledIssuerGeneration(id) => {
            DenyReason::invalid_envelope(format!("issuer generation {id} killed"))
        }
        LeaseError::ExceedsMaxLifetime(..) => {
            DenyReason::invalid_envelope(format!("lease invalid: {e}"))
        }

        _ => DenyReason::invalid_envelope(format!("lease chain invalid: {e}")),
    }
}

/// Authorize one [`ActionEnvelope`] against the lease store, producing the
/// frozen [`PolicyDecision`] wire shape.
///
/// This is the kernel's policy decision point (the rebuild's analogue of the
/// old trust-gate evaluation): structural checks only, no natural-language
/// interpretation. There is no default allow. The leaf lease is bound to
/// the envelope's session id; one-shot leases are additionally bound to
/// the exact approved action digest; and the exact action scope must be
/// covered by the leaf. Single-use consumption is the final step of the
/// allow transition — after a successful budget reservation — so a denied
/// authorization never consumes single-use authority.
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
    issuer_resolver: &dyn IssuerKeyResolver,
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
    // The approval fallback must not consume the action nonce: a
    // pending-approval envelope carries the nonce the human will approve,
    // and the approved re-presentation of the verbatim envelope must still
    // pass replay protection. Nonce consumption happens only when the
    // envelope actually reaches authorization.
    if env.lease_chain.is_empty() {
        return no_covering_lease(&action, env, outbox, params);
    }
    // Replay protection on (action_id, nonce).
    let envelope_nonce = format!("{}:{}", env.action_id, env.nonce);
    let ttl = env.expires_at_ms.saturating_sub(now_ms).max(1);
    if let Err(e) = nonces.check_and_insert(&envelope_nonce, now_ms, ttl) {
        return PolicyDecision::deny(DenyReason::replay_detected(format!("replay rejected: {e}")));
    }
    let presented: Vec<String> = env.lease_chain.iter().map(|id| id.to_string()).collect();
    let chain = match validate_chain(
        lease_resolver,
        &presented,
        revocations,
        sessions,
        issuer_resolver,
        one_shot,
        now_ms,
    ) {
        Ok(c) => c,
        Err(e) => return PolicyDecision::deny(deny_reason_for_chain_error(&e)),
    };
    let leaf = chain.leaf;
    // The leaf lease is a capability for its subject session only: an
    // envelope presented by any other session is denied here, at the
    // phase-1 policy entry point. This also closes the cross-session
    // authority-denial primitive: another session cannot even reach the
    // consumption step with a lease id it has learned.
    if leaf.subject != env.session_id {
        return PolicyDecision::deny(DenyReason::subject_mismatch(format!(
            "leaf lease subject {} does not match envelope session {}",
            leaf.subject, env.session_id
        )));
    }
    // One-shot leases are bound to the exact approved action digest, not
    // just its structural scope. A VHL approval covers the envelope the
    // human saw — arguments and inputs included — so a different envelope
    // that merely fits the same scope (benign arguments approved,
    // hostile arguments presented) is denied here. The lease link is
    // excluded from the comparison: it is necessarily empty at approval
    // time and is filled in when the action is presented for
    // authorization. A one-shot lease minted before digest binding
    // (`approved_action_digest` unset) fails closed.
    if leaf.limits.single_use {
        let mut presented = env.clone();
        presented.lease_chain = Vec::new();
        let presented_digest = match presented.digest() {
            Ok(d) => d,
            Err(e) => {
                return PolicyDecision::deny(DenyReason::invalid_envelope(format!(
                    "cannot digest presented action: {e}"
                )));
            }
        };
        if leaf.approved_action_digest.as_deref() != Some(presented_digest.as_str()) {
            return PolicyDecision::deny(DenyReason::scope_exceeded(
                "one-shot lease is not bound to the presented action".to_string(),
            ));
        }
    }
    // The action's exact scope must be covered by the leaf lease. This
    // runs before the budget reservation and single-use consumption so a
    // denied envelope can never burn the human approval behind a one-shot
    // lease or leak a budget hold.
    if let Err(e) = action.exact_scope().is_subset_of(&leaf.scope) {
        return PolicyDecision::deny(DenyReason::scope_exceeded(format!(
            "action not covered by lease: {e}"
        )));
    }
    // Atomically reserve one execution against the leaf lease's remaining
    // balance. The admission check and the hold are a single ledger
    // mutation, so concurrent authorizations cannot both pass on the last
    // execution — a standing lease with a finite budget actually depletes.
    // The reservation id travels in the Allow obligations: the dispatcher
    // must settle it after execution, or release it when dispatch never
    // happened or failed before any effect.
    let need = Budget::new().set(BudgetDimension::Executions, 1);
    let reservation = match ledger.reserve_execution(
        &leaf.lease_id,
        &env.action_id.to_string(),
        &need,
        &envelope_nonce,
        now_ms,
    ) {
        Ok(r) => r,
        Err(e) => {
            return PolicyDecision::deny(DenyReason::scope_exceeded(format!(
                "lease budget exhausted: {e}"
            )));
        }
    };
    // Single-use consumption is the final step of the allow transition:
    // it runs only after the session binding, the one-shot digest
    // binding, the exact-scope check, and a successful budget
    // reservation. A denied authorization never consumes single-use
    // authority. If consumption loses a concurrent race at this point,
    // the budget hold is released and the envelope is denied — fail
    // closed, no leaked hold, no burned approval.
    if leaf.limits.single_use
        && let Err(e) = consume_single_use(&leaf, one_shot, now_ms)
    {
        let _ = ledger.release_execution(&reservation.id, now_ms);
        let reason = match e {
            LeaseError::AlreadyConsumed(id) => {
                DenyReason::replay_detected(format!("one-shot lease {id} already consumed"))
            }
            _ => DenyReason::invalid_envelope(format!("one-shot lease: {e}")),
        };
        return PolicyDecision::deny(reason);
    }
    PolicyDecision::allow(vec![execution_settlement_obligation(
        &reservation,
        &leaf.lease_id,
    )])
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

    /// The host-key custody requirement: `KernelKeys` must destroy its
    /// private keys on drop. Destruction is provided by `ed25519-dalek`'s
    /// `Drop for SigningKey`, which only exists with the crate's
    /// `zeroize` feature. This pins the feature at compile time so a
    /// `Cargo.toml` change cannot silently drop the guarantee.
    #[test]
    fn kernel_keys_zeroize_on_drop() {
        fn requires_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        requires_zeroize_on_drop::<SigningKey>();
        // The keys must still sign (i.e. the struct is usable) right up
        // until they are dropped.
        let keys = KernelKeys::generate();
        let sig = keys.issuer_sign(b"custody-check");
        keys.issuer_verifying()
            .verify(b"custody-check", &sig)
            .expect("issuer key must sign before drop");
    }

    fn test_keys() -> (KernelKeys, SigningKey, VerifyingKey) {
        use rand::rngs::OsRng;
        let keys = KernelKeys::generate();
        let session_key = SigningKey::generate(&mut OsRng);
        let session_vk = session_key.verifying_key();
        (keys, session_key, session_vk)
    }

    fn test_sessions(session_vk: VerifyingKey, child_vk: VerifyingKey) -> SessionRegistry {
        let mut s = SessionRegistry::new();
        s.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        s.register(
            "ed25519:child-session".to_string(),
            Some("ed25519:parent-session".to_string()),
            child_vk,
            0,
        );
        s
    }

    /// Test issuer-key resolver: HashMap-backed generations plus a kill set.
    #[derive(Default)]
    struct TestIssuerResolver {
        keys: HashMap<String, VerifyingKey>,
        killed: HashSet<String>,
    }

    impl TestIssuerResolver {
        fn record(&mut self, keys: &KernelKeys) {
            self.keys
                .insert(keys.issuer_key_id.clone(), keys.issuer_verifying());
        }

        fn kill(&mut self, key_id: &str) {
            self.killed.insert(key_id.to_string());
        }
    }

    impl IssuerKeyResolver for TestIssuerResolver {
        fn issuer_verifying_key(&self, key_id: &str) -> Option<VerifyingKey> {
            self.keys.get(key_id).copied()
        }

        fn is_generation_killed(&self, key_id: &str) -> bool {
            self.killed.contains(key_id)
        }
    }

    fn issuer_resolver(keys: &KernelKeys) -> TestIssuerResolver {
        let mut r = TestIssuerResolver::default();
        r.record(keys);
        r
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
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
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
            &issuer_resolver(&keys),
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
            &issuer_resolver(&keys),
            &one_shot,
            300,
        );
        assert!(matches!(err, Err(LeaseError::Revoked(_))));

        // A destroyed issuing session fails closed even when the
        // revocation index was lost (crash between destroy and durable
        // revoke): validation checks active ancestry, not just the
        // revocation list.
        let (keys, session_key, session_vk) = test_keys();
        let child_key = SigningKey::generate(&mut OsRng);
        let mut sessions = test_sessions(session_vk, child_key.verifying_key());
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
        let mut child_scope = ResourceScope::default();
        child_scope.tools.insert(
            "fs.read".to_string(),
            semver::VersionReq::parse("=1.2.3").unwrap(),
        );
        child_scope.paths.push(PathGrant {
            root: CanonicalPath::parse("/workspace/src", &r, false).unwrap(),
            rights: PathRights::READ,
        });
        child_scope.effects.push(EffectClass::Read);
        let child = mint_child_lease(
            &root,
            ChildLeaseParams {
                lease_id: "lease-child-dead-parent".to_string(),
                subject: "ed25519:child-session".to_string(),
                scope: child_scope,
                limits: LeaseLimits {
                    not_before_ms: 0,
                    expires_at_ms: 500_000,
                    budget: Budget::new().set(BudgetDimension::Executions, 10),
                    max_executions: None,
                    single_use: false,
                },
                depth_limit: 4,
                lease_nonce: "child-nonce-dead".to_string(),
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
        let chain_ids = vec![child.lease_id.clone(), root.lease_id.clone()];
        // Sanity: the chain validates while the issuing session is live.
        validate_chain(
            &map,
            &chain_ids,
            &RevocationIndex::new(),
            &sessions,
            &issuer_resolver(&keys),
            &HashSet::new(),
            300,
        )
        .unwrap();
        // Destroy the issuing session without revoking: validation must
        // still fail closed on the dead ancestry.
        sessions.deactivate("ed25519:parent-session");
        let err = validate_chain(
            &map,
            &chain_ids,
            &RevocationIndex::new(),
            &sessions,
            &issuer_resolver(&keys),
            &HashSet::new(),
            300,
        );
        assert!(matches!(err, Err(LeaseError::SubjectInactive(_))));
    }

    #[test]
    fn subject_liveness_walks_full_ancestry() {
        use rand::rngs::OsRng;
        let gp_key = SigningKey::generate(&mut OsRng);
        let p_key = SigningKey::generate(&mut OsRng);
        let c_key = SigningKey::generate(&mut OsRng);
        let mut sessions = SessionRegistry::new();
        sessions.register(
            "ed25519:grandparent".to_string(),
            None,
            gp_key.verifying_key(),
            0,
        );
        sessions.register(
            "ed25519:parent".to_string(),
            Some("ed25519:grandparent".to_string()),
            p_key.verifying_key(),
            0,
        );
        sessions.register(
            "ed25519:child".to_string(),
            Some("ed25519:parent".to_string()),
            c_key.verifying_key(),
            0,
        );
        // All live: the whole ancestry holds.
        assert!(sessions.is_subject_live("ed25519:child", 300));
        // Deactivating the grandparent kills the child's ancestry even
        // though the child and parent records are still active — this is
        // the case `is_active_descendant(x, x, …)` misses, because it
        // returns after checking only the named record.
        sessions.deactivate("ed25519:grandparent");
        assert!(sessions.is_active_descendant("ed25519:child", "ed25519:child", 300));
        assert!(!sessions.is_subject_live("ed25519:child", 300));
        assert!(!sessions.is_subject_live("ed25519:parent", 300));
        assert!(!sessions.is_subject_live("ed25519:grandparent", 300));
        // Unknown subjects are not live.
        assert!(!sessions.is_subject_live("ed25519:nobody", 300));
    }

    #[test]
    fn subject_liveness_enforces_session_ttl() {
        use rand::rngs::OsRng;
        let key = SigningKey::generate(&mut OsRng);
        let mut sessions = SessionRegistry::new();
        sessions.set_max_lifetime(Some(1_000));
        sessions.register("ed25519:short".to_string(), None, key.verifying_key(), 0);
        assert!(sessions.is_subject_live("ed25519:short", 999));
        assert!(!sessions.is_subject_live("ed25519:short", 1_000));
        // Disabling the TTL restores liveness for the active record.
        sessions.set_max_lifetime(None);
        assert!(sessions.is_subject_live("ed25519:short", 1_000_000));
    }

    #[test]
    fn one_shot_grant_flow() {
        use rand::rngs::OsRng;
        let (keys, _, session_vk) = test_keys();
        let vhl_key = SigningKey::generate(&mut OsRng);
        let vhl_vk = vhl_key.verifying_key();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
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
            &issuer_resolver(&keys),
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
            &issuer_resolver(&keys),
            &mut tracker,
            &nonces,
            &ledger,
            outbox,
            &params,
        );
        assert!(!d2.is_allow());
    }

    #[test]
    fn finite_execution_budget_depletes() {
        let (keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let r = FakeResolver::default();

        // Standing lease with exactly one execution.
        let mut lp = root_params(parent_scope());
        lp.limits.budget = Budget::new().set(BudgetDimension::Executions, 1);
        // The frozen envelope carries lease ids as UUIDs.
        lp.lease_id = Uuid::new_v4().to_string();
        let root = mint_root_lease(lp, &keys, &sessions, &ledger, &nonces, 100).unwrap();

        let mut map = HashMap::new();
        map.insert(root.lease_id.clone(), root.clone());
        let params = AuthorizeParams {
            now_ms: 200,
            case_insensitive_fs: false,
            allow_approval_fallback: false,
            approval_ttl_ms: 60_000,
        };
        let mut env = ActionEnvelope {
            version: crate::pi_boundary::ACTION_ENVELOPE_VERSION,
            action_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440001").unwrap(),
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
            lease_chain: vec![crate::pi_boundary::LeaseId::from_uuid(
                root.lease_id.parse().expect("root id is a UUID"),
            )],
            nonce: "env-nonce-a".to_string(),
            expires_at_ms: 1_000_000,
        };

        // First authorization: allowed, and the Allow carries the execution
        // reservation the dispatcher must settle or release.
        let mut tracker = HashSet::new();
        let outbox: &mut Vec<VhlRequest> = &mut vec![];
        let d1 = authorize_envelope(
            &env,
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
        let res_id = execution_reservation_id(&d1)
            .expect("allow carries the settle_budget obligation")
            .to_string();
        assert!(res_id.starts_with("exec_"));
        assert_eq!(
            ledger
                .remaining(&root.lease_id)
                .unwrap()
                .get(BudgetDimension::Executions),
            0,
            "the hold is visible the moment the action is authorized"
        );

        // Second action: the finite budget is exhausted, denied.
        env.action_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440002").unwrap();
        env.nonce = "env-nonce-b".to_string();
        let d2 = authorize_envelope(
            &env,
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
        match &d2.outcome {
            crate::pi_boundary::DecisionOutcome::Deny { reason } => {
                assert!(
                    reason.detail.contains("budget"),
                    "unexpected reason: {reason:?}"
                )
            }
            other => panic!("expected deny, got {other:?}"),
        }

        // Settling the first reservation converts the hold to consumption;
        // the budget stays spent, never leaks back.
        ledger
            .settle_execution(
                &res_id,
                &Budget::new().set(BudgetDimension::Executions, 1),
                "settle-a",
                300,
            )
            .unwrap();
        env.action_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440003").unwrap();
        env.nonce = "env-nonce-c".to_string();
        let d3 = authorize_envelope(
            &env,
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
        assert!(!d3.is_allow());
        ledger.check_invariants().unwrap();
    }

    // ---- Regression tests: findings 5-7, Lane's one-shot ordering ----
    // ---- (comment 4099747053), and the one-shot digest binding        ----
    // ---- (Codex P1 4096473878)                                        ----

    /// Build an envelope declaring a single network resource for `host`.
    fn envelope_with_network_host(host: &str) -> crate::pi_boundary::ActionEnvelope {
        crate::pi_boundary::ActionEnvelope {
            version: crate::pi_boundary::ACTION_ENVELOPE_VERSION,
            action_id: Uuid::new_v4(),
            session_id: "ed25519:parent-session".to_string(),
            tool: crate::pi_boundary::ToolRef {
                name: "net.fetch".to_string(),
                version: "1.2.3".to_string(),
            },
            arguments: [("n".to_string(), serde_json::json!(1))]
                .into_iter()
                .collect(),
            inputs: vec![],
            resources: crate::pi_boundary::ResourceSet {
                paths: vec![],
                network: vec![crate::pi_boundary::NetworkResource {
                    scheme: "https".to_string(),
                    host: host.to_string(),
                    port: 443,
                }],
                secrets: vec![],
            },
            expected_effects: crate::pi_boundary::EffectClasses {
                file_read: false,
                file_write: false,
                network_egress: true,
                network_ingress: false,
                process_spawn: false,
            },
            lease_chain: vec![],
            nonce: "net-nonce".to_string(),
            expires_at_ms: 500_000,
        }
    }

    #[test]
    fn network_resource_rejects_authority_smuggling() {
        let r = FakeResolver::default();
        // Benign declarations round-trip to exactly the declared host/port.
        for host in [
            "example.com",
            "93.184.216.34",
            "2001:db8::1",
            "[2001:db8::1]",
            "EXAMPLE.com",
        ] {
            let env = envelope_with_network_host(host);
            let action = CanonicalAction::from_envelope(&env, &r, false)
                .unwrap_or_else(|e| panic!("host {host:?} should parse: {e}"));
            assert_eq!(action.destinations.len(), 1);
            assert_eq!(action.destinations[0].ports, PortSet::single(443));
        }
        // Authority smuggling is rejected at the boundary, never normalized.
        for host in [
            "x@b.com",
            "b.com#",
            "b.com?x=1",
            "b.com/",
            "a.com:8443",
            "[::1",
            "[1.2.3.4]",
            "2001:db8::1]:443",
            "",
        ] {
            let env = envelope_with_network_host(host);
            assert!(
                CanonicalAction::from_envelope(&env, &r, false).is_err(),
                "host {host:?} must be rejected"
            );
        }
    }

    /// Mint a one-shot lease for one exact fs.read action, mirroring
    /// `one_shot_grant_flow`. Returns the envelope (verbatim, as the
    /// dispatcher would present it), the lease map, the one-shot lease id,
    /// and the authorizer inputs.
    #[allow(clippy::type_complexity)]
    fn one_shot_fixture() -> (
        crate::pi_boundary::ActionEnvelope,
        HashMap<String, LeaseDocument>,
        String,
        KernelKeys,
        SessionRegistry,
        BudgetLedger,
    ) {
        use rand::rngs::OsRng;
        let (keys, _, session_vk) = test_keys();
        let vhl_key = SigningKey::generate(&mut OsRng);
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let r = FakeResolver::default();
        let mut env = crate::pi_boundary::ActionEnvelope {
            version: crate::pi_boundary::ACTION_ENVELOPE_VERSION,
            action_id: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440099").unwrap(),
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
            nonce: "fixture-nonce-a".to_string(),
            expires_at_ms: 500_000,
        };
        let action = CanonicalAction::from_envelope(&env, &r, false).unwrap();
        let mut grant = OneShotGrant {
            approval_id: "appr-fixture".to_string(),
            action_digest: action.digest.clone(),
            session_subject: "ed25519:parent-session".to_string(),
            signer_key_id: "vhl-human-1".to_string(),
            nonce: "grant-nonce-fixture".to_string(),
            created_at_ms: 100,
            expires_at_ms: 10_000,
            signature: String::new(),
        };
        grant.sign(&vhl_key);
        let one_shot = mint_one_shot_lease(
            &grant,
            &vhl_key.verifying_key(),
            &action,
            &keys,
            &sessions,
            &ledger,
            &nonces,
            200,
        )
        .unwrap();
        // The lease carries the approved digest, covered by the issuer
        // signature.
        assert_eq!(
            one_shot.approved_action_digest.as_deref(),
            Some(action.digest.as_str())
        );
        one_shot.verify_signature(&keys.issuer_verifying()).unwrap();
        let one_shot_lease_id = one_shot.lease_id.clone();
        env.lease_chain = vec![crate::pi_boundary::LeaseId::from_uuid(
            one_shot_lease_id.parse().expect("one-shot id is a UUID"),
        )];
        let mut map = HashMap::new();
        map.insert(one_shot_lease_id.clone(), one_shot);
        (env, map, one_shot_lease_id, keys, sessions, ledger)
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_fixture(
        env: &crate::pi_boundary::ActionEnvelope,
        map: &HashMap<String, LeaseDocument>,
        sessions: &SessionRegistry,
        keys: &KernelKeys,
        tracker: &mut HashSet<String>,
        nonces: &mut NonceStore,
        ledger: &BudgetLedger,
        outbox: &mut Vec<VhlRequest>,
    ) -> PolicyDecision {
        authorize_envelope(
            env,
            &FakeResolver::default(),
            map,
            &RevocationIndex::new(),
            sessions,
            keys,
            tracker,
            nonces,
            ledger,
            outbox,
            &AuthorizeParams {
                now_ms: 300,
                case_insensitive_fs: false,
                allow_approval_fallback: false,
                approval_ttl_ms: 0,
            },
        )
    }

    fn assert_deny_code(decision: &PolicyDecision, code: &str) {
        match &decision.outcome {
            DecisionOutcome::Deny { reason } => {
                assert_eq!(reason.code, code, "unexpected deny reason: {reason:?}")
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn authorize_envelope_binds_leaf_to_session() {
        let (env, map, one_shot_id, keys, sessions, ledger) = one_shot_fixture();
        let mut tracker = HashSet::new();
        let mut nonces = NonceStore::new();
        let mut outbox: Vec<VhlRequest> = vec![];
        // Same valid chain, but presented by a different session: denied at
        // the session binding, before any consumption step is reachable.
        let mut intruder = env.clone();
        intruder.session_id = "ed25519:intruder-session".to_string();
        intruder.nonce = "intruder-nonce".to_string();
        let d = authorize_fixture(
            &intruder,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(!d.is_allow());
        assert_deny_code(&d, "subject_mismatch");
        assert!(
            !tracker.contains(&one_shot_id),
            "a cross-session presentation must not burn the one-shot grant"
        );
        // The legitimate session presents the verbatim approved envelope
        // (the nonce the human approved) and is allowed.
        let d2 = authorize_fixture(
            &env,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(d2.is_allow(), "legitimate session denied: {:?}", d2.outcome);
        assert!(tracker.contains(&one_shot_id));
    }

    #[test]
    fn one_shot_lease_rejects_tampered_arguments() {
        let (env, map, one_shot_id, keys, sessions, ledger) = one_shot_fixture();
        let mut tracker = HashSet::new();
        let mut nonces = NonceStore::new();
        let mut outbox: Vec<VhlRequest> = vec![];
        // Same tool, resources, and effects — but different arguments than
        // the human approved. The structural scope still covers this
        // envelope; only the digest binding denies it.
        let mut tampered = env.clone();
        tampered.arguments = [("n".to_string(), serde_json::json!(2))]
            .into_iter()
            .collect();
        tampered.nonce = "tampered-nonce".to_string();
        let d = authorize_fixture(
            &tampered,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(!d.is_allow());
        assert_deny_code(&d, "scope_exceeded");
        assert!(
            !tracker.contains(&one_shot_id),
            "a digest-mismatched envelope must not burn the one-shot grant"
        );
        // The verbatim approved envelope still authorizes afterwards.
        let d2 = authorize_fixture(
            &env,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(
            d2.is_allow(),
            "verbatim approved action denied: {:?}",
            d2.outcome
        );
        assert!(tracker.contains(&one_shot_id));
    }

    #[test]
    fn one_shot_lease_survives_scope_denied_authorization() {
        let (env, map, one_shot_id, keys, sessions, ledger) = one_shot_fixture();
        let mut tracker = HashSet::new();
        let mut nonces = NonceStore::new();
        let mut outbox: Vec<VhlRequest> = vec![];
        // An out-of-scope action presented against the one-shot lease is
        // denied without consuming the grant. (The digest binding fires
        // first for a differing envelope; either way the deny precedes
        // consumption.)
        let mut bad = env.clone();
        bad.resources.paths = vec![crate::pi_boundary::PathResource {
            path: "/etc/passwd".to_string(),
            rights: crate::pi_boundary::PathRights::Read,
        }];
        bad.nonce = "bad-scope-nonce".to_string();
        let d = authorize_fixture(
            &bad,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(!d.is_allow());
        assert_deny_code(&d, "scope_exceeded");
        assert!(
            !tracker.contains(&one_shot_id),
            "a denied envelope must not burn the one-shot grant"
        );
        // The exact approved action still authorizes afterwards.
        let d2 = authorize_fixture(
            &env,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(
            d2.is_allow(),
            "approved action denied after scope-denied attempt: {:?}",
            d2.outcome
        );
        assert!(tracker.contains(&one_shot_id));
    }

    #[test]
    fn one_shot_lease_survives_budget_denied_authorization() {
        let (env, map, one_shot_id, keys, sessions, ledger) = one_shot_fixture();
        // Exhaust the one-shot's single execution directly on the ledger,
        // so the authorize-time reservation fails after the digest and
        // scope checks have passed.
        let need = Budget::new().set(BudgetDimension::Executions, 1);
        ledger
            .reserve_execution(&one_shot_id, "some-other-action", &need, "prior-hold", 200)
            .unwrap();
        let mut tracker = HashSet::new();
        let mut nonces = NonceStore::new();
        let mut outbox: Vec<VhlRequest> = vec![];
        let d = authorize_fixture(
            &env,
            &map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(!d.is_allow());
        assert_deny_code(&d, "scope_exceeded");
        assert!(
            !tracker.contains(&one_shot_id),
            "a budget-denied envelope must not burn the one-shot grant"
        );
    }

    #[test]
    fn approval_fallback_does_not_consume_action_nonce() {
        let (env, map, one_shot_id, keys, sessions, ledger) = one_shot_fixture();
        // The pre-approval presentation carries no lease chain: it goes to
        // the human-approval fallback and must come back pending.
        let mut pending_env = env.clone();
        pending_env.lease_chain = vec![];
        let mut tracker = HashSet::new();
        let nonces = NonceStore::new();
        let mut outbox: Vec<VhlRequest> = vec![];
        let fallback_params = AuthorizeParams {
            now_ms: 300,
            case_insensitive_fs: false,
            allow_approval_fallback: true,
            approval_ttl_ms: 60_000,
        };
        let d = authorize_envelope(
            &pending_env,
            &FakeResolver::default(),
            &map,
            &RevocationIndex::new(),
            &sessions,
            &keys,
            &mut tracker,
            &nonces,
            &ledger,
            &mut outbox,
            &fallback_params,
        );
        assert!(
            matches!(d.outcome, DecisionOutcome::PendingApproval { .. }),
            "expected pending approval, got {:?}",
            d.outcome
        );
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].nonce, pending_env.nonce);
        // The human approves; the verbatim envelope is re-presented with
        // the minted one-shot lease. The nonce the human approved must
        // still be usable — the fallback must not have burned it.
        let d2 = authorize_envelope(
            &env,
            &FakeResolver::default(),
            &map,
            &RevocationIndex::new(),
            &sessions,
            &keys,
            &mut tracker,
            &nonces,
            &ledger,
            &mut outbox,
            &AuthorizeParams {
                now_ms: 300,
                case_insensitive_fs: false,
                allow_approval_fallback: true,
                approval_ttl_ms: 60_000,
            },
        );
        assert!(
            d2.is_allow(),
            "approved re-presentation denied (nonce burned by fallback?): {:?}",
            d2.outcome
        );
        assert!(tracker.contains(&one_shot_id));
    }

    #[test]
    fn one_shot_lease_without_digest_fails_closed() {
        let (env, map, _one_shot_id, keys, sessions, ledger) = one_shot_fixture();
        // A one-shot lease minted before digest binding (no approved
        // digest recorded) cannot authorize: fail closed, never consume.
        let mut legacy = map.values().next().unwrap().clone();
        legacy.approved_action_digest = None;
        // Re-sign so the chain validates and the test exercises the digest
        // binding itself, not signature verification.
        let sig = keys.issuer_sign(&legacy.signing_bytes().unwrap());
        legacy.signature = hex::encode(sig.to_bytes());
        let mut legacy_map = HashMap::new();
        legacy_map.insert(legacy.lease_id.clone(), legacy);
        let mut tracker = HashSet::new();
        let mut nonces = NonceStore::new();
        let mut outbox: Vec<VhlRequest> = vec![];
        let d = authorize_fixture(
            &env,
            &legacy_map,
            &sessions,
            &keys,
            &mut tracker,
            &mut nonces,
            &ledger,
            &mut outbox,
        );
        assert!(!d.is_allow());
        assert_deny_code(&d, "scope_exceeded");
    /// A root lease minted under a retired generation validates through the
    /// resolver (spec §4.1: retirement no longer invalidates outstanding
    /// leases).
    #[test]
    fn root_validates_via_retired_generation() {
        let (old_keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let doc = mint_root_lease(
            root_params(parent_scope()),
            &old_keys,
            &sessions,
            &ledger,
            &nonces,
            100,
        )
        .unwrap();
        // Simulates post-restart: the resolver carries the retired
        // generation's recorded verifying key.
        let resolver = issuer_resolver(&old_keys);
        let mut map = HashMap::new();
        map.insert(doc.lease_id.clone(), doc.clone());
        let validated = validate_chain(
            &map,
            std::slice::from_ref(&doc.lease_id),
            &RevocationIndex::new(),
            &sessions,
            &resolver,
            &HashSet::new(),
            300,
        )
        .unwrap();
        assert_eq!(validated.leaf.lease_id, doc.lease_id);
    }

    /// A root lease naming an unrecorded generation fails closed with
    /// `UnknownIssuerGeneration` (distinct from `IssuerMismatch`).
    #[test]
    fn unknown_generation_fails_closed() {
        let (old_keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let doc = mint_root_lease(
            root_params(parent_scope()),
            &old_keys,
            &sessions,
            &ledger,
            &nonces,
            100,
        )
        .unwrap();
        // Resolver knows only a different (fresh) generation.
        let (new_keys, _, _) = test_keys();
        let resolver = issuer_resolver(&new_keys);
        let mut map = HashMap::new();
        map.insert(doc.lease_id.clone(), doc.clone());
        let err = validate_chain(
            &map,
            std::slice::from_ref(&doc.lease_id),
            &RevocationIndex::new(),
            &sessions,
            &resolver,
            &HashSet::new(),
            300,
        )
        .expect_err("unknown generation must fail closed");
        assert!(
            matches!(err, LeaseError::UnknownIssuerGeneration(ref id) if id == &old_keys.issuer_key_id),
            "got {err:?}"
        );
    }

    /// A killed generation fails closed with `KilledIssuerGeneration`,
    /// checked before key resolution.
    #[test]
    fn killed_generation_fails_closed() {
        let (old_keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let doc = mint_root_lease(
            root_params(parent_scope()),
            &old_keys,
            &sessions,
            &ledger,
            &nonces,
            100,
        )
        .unwrap();
        let mut resolver = issuer_resolver(&old_keys);
        resolver.kill(&old_keys.issuer_key_id);
        let mut map = HashMap::new();
        map.insert(doc.lease_id.clone(), doc.clone());
        let err = validate_chain(
            &map,
            std::slice::from_ref(&doc.lease_id),
            &RevocationIndex::new(),
            &sessions,
            &resolver,
            &HashSet::new(),
            300,
        )
        .expect_err("killed generation must fail closed");
        assert!(
            matches!(err, LeaseError::KilledIssuerGeneration(ref id) if id == &old_keys.issuer_key_id),
            "got {err:?}"
        );
    }

    /// Root leases longer than 30 days are refused at mint time.
    #[test]
    fn root_mint_rejects_overlong_lifetime() {
        let (keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let mut params = root_params(parent_scope());
        params.lease_nonce = "overlong-nonce".to_string();
        params.issued_at_ms = 100;
        params.limits.not_before_ms = 100;
        params.limits.expires_at_ms = 100 + MAX_ROOT_LEASE_LIFETIME_MS + 1;
        let err = mint_root_lease(params, &keys, &sessions, &ledger, &nonces, 100)
            .expect_err("over-30-day root lease must be refused");
        assert!(
            matches!(err, LeaseError::ExceedsMaxLifetime(l, m) if l == MAX_ROOT_LEASE_LIFETIME_MS + 1 && m == MAX_ROOT_LEASE_LIFETIME_MS),
            "got {err:?}"
        );
        // Exactly at the cap still mints.
        let mut params = root_params(parent_scope());
        params.lease_nonce = "at-cap-nonce".to_string();
        params.issued_at_ms = 100;
        params.limits.not_before_ms = 100;
        params.limits.expires_at_ms = 100 + MAX_ROOT_LEASE_LIFETIME_MS;
        mint_root_lease(params, &keys, &sessions, &ledger, &nonces, 100)
            .expect("30-day root lease mints");
    }

    /// The 30-day cap is computed from the trusted authority clock, not
    /// the caller-supplied issued_at_ms: setting issued_at_ms near
    /// expires_at_ms must not smuggle a year-long lease past the cap.
    #[test]
    fn root_mint_rejects_spoofed_issued_at() {
        let (keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let now = 1_000_000;
        let year_ms = 365 * 24 * 60 * 60 * 1000;
        let mut params = root_params(parent_scope());
        params.lease_nonce = "spoofed-issued-at".to_string();
        params.limits.not_before_ms = now;
        params.limits.expires_at_ms = now + year_ms;
        // Bypass attempt: 1ms of "computed" lifetime, a year of actual use.
        params.issued_at_ms = now + year_ms - 1;
        let err = mint_root_lease(params, &keys, &sessions, &ledger, &nonces, now)
            .expect_err("spoofed issued_at must not bypass the lifetime cap");
        assert!(
            matches!(err, LeaseError::ExceedsMaxLifetime(l, m) if l == year_ms && m == MAX_ROOT_LEASE_LIFETIME_MS),
            "got {err:?}"
        );
    }

    /// A root lease cannot claim to have been issued in the future.
    #[test]
    fn root_mint_rejects_future_issued_at() {
        let (keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let mut params = root_params(parent_scope());
        params.lease_nonce = "future-issued-at".to_string();
        params.issued_at_ms = 200;
        let err = mint_root_lease(params, &keys, &sessions, &ledger, &nonces, 100)
            .expect_err("future issued_at must be refused");
        assert!(
            matches!(err, LeaseError::IssuedInFuture(200, 100)),
            "got {err:?}"
        );
    }

    /// A root-only chain for a TTL-expired session fails closed: the
    /// session bound is enforced for ordinary root leases, not just
    /// after a restart or for delegated chains.
    #[test]
    fn root_chain_rejects_ttl_expired_session() {
        let (keys, _, session_vk) = test_keys();
        let mut sessions = SessionRegistry::new();
        sessions.set_max_lifetime(Some(DEFAULT_SESSION_MAX_LIFETIME_MS));
        sessions.register("ed25519:parent-session".to_string(), None, session_vk, 0);
        let ledger = BudgetLedger::new();
        let nonces = NonceStore::new();
        let mut params = root_params(parent_scope());
        params.lease_nonce = "ttl-root-nonce".to_string();
        // Lease outlives the session TTL so the TTL check is the one
        // that fires.
        params.limits.expires_at_ms = 2 * DEFAULT_SESSION_MAX_LIFETIME_MS;
        let root = mint_root_lease(params, &keys, &sessions, &ledger, &nonces, 100).unwrap();
        let mut map = HashMap::new();
        map.insert(root.lease_id.clone(), root.clone());
        let revocations = RevocationIndex::new();
        let one_shot = HashSet::new();
        let chain_ids = vec![root.lease_id.clone()];
        // Within the TTL the root chain validates.
        validate_chain(
            &map,
            &chain_ids,
            &revocations,
            &sessions,
            &issuer_resolver(&keys),
            &one_shot,
            DEFAULT_SESSION_MAX_LIFETIME_MS - 1,
        )
        .expect("root chain validates within session TTL");
        // Past the session TTL it fails closed.
        let err = validate_chain(
            &map,
            &chain_ids,
            &revocations,
            &sessions,
            &issuer_resolver(&keys),
            &one_shot,
            DEFAULT_SESSION_MAX_LIFETIME_MS + 1,
        )
        .expect_err("TTL-expired session must not authorize");
        assert!(matches!(err, LeaseError::SubjectInactive(_)), "got {err:?}");
    }

    /// Session TTL: a record past `max_lifetime_ms` is not a live
    /// descendant, at every hop of the walk.
    #[test]
    fn session_ttl_bounds_descendant_check() {
        use rand::rngs::OsRng;
        let parent_vk = SigningKey::generate(&mut OsRng).verifying_key();
        let child_vk = SigningKey::generate(&mut OsRng).verifying_key();
        let mut sessions = SessionRegistry::new();
        sessions.set_max_lifetime(Some(DEFAULT_SESSION_MAX_LIFETIME_MS));
        sessions.register("ed25519:parent-session".to_string(), None, parent_vk, 0);
        sessions.register(
            "ed25519:child-session".to_string(),
            Some("ed25519:parent-session".to_string()),
            child_vk,
            0,
        );
        // Within the TTL both walk.
        assert!(sessions.is_active_descendant(
            "ed25519:child-session",
            "ed25519:parent-session",
            DEFAULT_SESSION_MAX_LIFETIME_MS - 1
        ));
        // Past the TTL the child is dead at every hop (parent is expired
        // too, so the walk fails even if the child's own record were fresh).
        assert!(!sessions.is_active_descendant(
            "ed25519:child-session",
            "ed25519:parent-session",
            DEFAULT_SESSION_MAX_LIFETIME_MS + 1
        ));
        assert!(!sessions.is_active_descendant(
            "ed25519:parent-session",
            "ed25519:parent-session",
            DEFAULT_SESSION_MAX_LIFETIME_MS + 1
        ));
        // Re-registered fresh, the child walks again.
        sessions.register(
            "ed25519:child-session".to_string(),
            Some("ed25519:parent-session".to_string()),
            child_vk,
            DEFAULT_SESSION_MAX_LIFETIME_MS,
        );
        assert!(sessions.is_active_descendant(
            "ed25519:child-session",
            "ed25519:child-session",
            DEFAULT_SESSION_MAX_LIFETIME_MS + 1
        ));
    }

    /// `active_descendants_inclusive` returns the TTL-checked subtree,
    /// inclusive of the root, excluding inactive records.
    #[test]
    fn active_descendants_inclusive_correctness() {
        use rand::rngs::OsRng;
        let vks: Vec<VerifyingKey> = (0..4)
            .map(|_| SigningKey::generate(&mut OsRng).verifying_key())
            .collect();
        let mut sessions = SessionRegistry::new();
        sessions.register("root".to_string(), None, vks[0], 0);
        sessions.register("a".to_string(), Some("root".to_string()), vks[1], 0);
        sessions.register("b".to_string(), Some("a".to_string()), vks[2], 0);
        sessions.register("sibling".to_string(), None, vks[3], 0);
        assert_eq!(
            sessions.active_descendants_inclusive("root", 1_000),
            vec!["a".to_string(), "b".to_string(), "root".to_string()]
        );
        // Deactivating `a` prunes its subtree but not the root.
        sessions.deactivate("a");
        assert_eq!(
            sessions.active_descendants_inclusive("root", 1_000),
            vec!["root".to_string()]
        );
        // TTL expiry prunes everything.
        sessions.set_max_lifetime(Some(500));
        assert!(
            sessions
                .active_descendants_inclusive("root", 1_000)
                .is_empty()
        );
        // `get()` keeps its no-TTL-filter semantics: the host decides
        // hydration.
        assert!(sessions.get("root").is_some());
    }
}
