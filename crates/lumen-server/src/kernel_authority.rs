//! Real Phase-1 authority engine: the [`KernelClient`] implementation the
//! coordinator wires at integration.
//!
//! This supersedes the removed `kernel_local` spike (which wrapped the
//! phase-0 `pi_boundary::LocalKernel` whose own docs admit phase-1 assembly
//! was "missing design"). Every decision here runs the real phase-1 kernel
//! from `lumen_core::lease`:
//!
//! - [`authorize_envelope`](lumen_core::lease::authorize_envelope) evaluates
//!   the frozen [`ActionEnvelope`](lumen_core::pi_boundary::ActionEnvelope):
//!   canonicalization, expiry, nonce replay, lease-chain validation and
//!   signature/revocation checks, exact scope, one-shot consumption, and
//!   the budget admission check. No covering lease produces a durable
//!   `PendingApproval` and a [`VhlRequest`](lumen_core::lease::VhlRequest)
//!   on the approval outbox.
//! - Session identities are the phase-4 vault's ephemeral Courier
//!   `ed25519:` subjects
//!   ([`SessionIdentityVault`](lumen_core::session_identity::SessionIdentityVault));
//!   the supervisor destroys root and descendant identities through
//!   [`SessionIdentityAuthority`](crate::kernel_client::SessionIdentityAuthority),
//!   which this client implements against the same vault the kernel
//!   authorizes against.
//! - Authority state is durable in `lumen-db` (leases, revocations,
//!   nonces, one-shot uses, budgets, audit events) via the checked-in
//!   migrations; the in-memory structures (`SessionRegistry`,
//!   `RevocationIndex`, `NonceStore`, `BudgetLedger`) are hot caches
//!   hydrated at startup.
//!
//! ## Async boundary
//!
//! The kernel is synchronous by design (the phase-1 evaluation functions
//! take `&self`, not `&mut self`, and never block on IO). The async
//! [`KernelClient`] methods therefore run every kernel operation inside
//! [`tokio::task::spawn_blocking`], so the host's async runtime is never
//! stalled by SQLite IO. Durable calls run on the kernel's own private
//! multi-thread Tokio runtime (`block_on` from the blocking worker), never
//! on the ambient runtime: this client works under any ambient runtime as
//! long as `spawn_blocking` is available (the private runtime is created
//! and driven off the async context, and is shut down via
//! `shutdown_background` so the client may be dropped from async code).
//!
//! ## Budget settlement
//!
//! `authorize_envelope` enforces the budget *admission* check (the leaf
//! lease's remaining budget must cover one execution) but does not
//! reserve or debit: there is no settle signal in the pipeline (nothing
//! reports execution usage back to the kernel), and reserving without a
//! release path would leak budget. Child-lease mints reserve against
//! their parent. Wiring a debit-on-commit settle step is a coordinator
//! design decision; it needs a `KernelClient` settle method and a policy
//! for failed executions, so it is deliberately not invented here.
//!
//! The ledger is a write-through cache of the durable `kernel_budget_accounts`
//! rows: mint writes both, and a future settle path must write both. At open
//! the ledger restores the full account state (caps, held reservations,
//! consumed spend) via [`BudgetLedger::restore_account`], so settled spend
//! is never forgotten by a restart and admission cannot over-authorize.
//! Reservation *objects* are not restored into the ledger — only the
//! aggregate held amounts admission needs; per-reservation reconciliation
//! stays at the store level (`active_kernel_reservations`).
//!
//! ## Key custody
//!
//! [`KernelKeys`](lumen_core::lease::KernelKeys) holds the issuer and host
//! private keys in memory and zeroizes them on drop (via `ed25519-dalek`'s
//! `ZeroizeOnDrop`, enabled by the `zeroize` feature in
//! `lumen-core/Cargo.toml`; the `kernel_keys_zeroize_on_drop` test pins the
//! feature so it cannot be silently removed). They are never written to disk
//! or logs. A kernel restart generates fresh keys, which the host must treat
//! as a key rotation: **retired generations' verifying keys are retained
//! durably in `kernel_key_generations`, so leases minted under a retired
//! issuer keep verifying after restart**; only the private keys die with the
//! boot (zeroized on drop at rotation).
//!
//! Signatures that must survive a restart are keyed to their generation:
//! every boot records its issuer/host verifying keys in the durable
//! `kernel_key_generations` table, and lease validation resolves each root
//! document's `issuer_key_id` through the [`IssuerKeyResolver`]
//! implementation over the in-memory generation index (hydrated at open),
//! with the kill-list checked first. A generation that was killed
//! (`kernel_killed_generations`) fails closed even though its verifying key
//! remains recorded. [`AuthorityKernelClient::verify_kernel_audit`]
//! resolves each checkpoint's signing key from those recorded generations,
//! so retired generations' checkpoints keep verifying. A checkpoint or lease
//! that references an unknown generation fails closed.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::VerifyingKey;
use lumen_core::budget::{Budget, BudgetLedger};
use lumen_core::canonical::{RealFsResolver, ResourceScope};
use lumen_core::identity::{PrincipalId, WorkspaceId};
use lumen_core::kernel_audit::{AuditLink, verify_event_chain};
use lumen_core::lease::{
    AuthorizeParams, CanonicalAction, DEFAULT_SESSION_MAX_LIFETIME_MS, IssuerKeyResolver,
    KernelKeys, LeaseDocument as CoreLeaseDocument, LeaseError,
    LeaseLimits as CoreLeaseLimits, LeaseResolver, OneShotGrant as CoreOneShotGrant,
    OneShotTracker, RevocationIndex, RootLeaseParams, SessionRegistry, VhlRequest,
    authorize_envelope, mint_one_shot_lease, mint_root_lease, validate_chain,
};
};
use lumen_core::nonce::NonceStore;
use lumen_core::operator::{AuthorityRequest, OperatorAuthorityPort, OperatorOperation};
use lumen_core::pi_boundary;
use lumen_core::pi_boundary::{
    ActionEnvelope as FrozenEnvelope, AuditEventKind, DecisionOutcome, DenyReason,
    PolicyDecision as FrozenDecision,
};
use lumen_core::session_identity::{SessionIdentityVault, session_address};
use lumen_core::vhl::{ApprovalKind, VhlApprovalRequest};
use lumen_db::lease::{KernelAuditAppend, KernelAuditQuery, KillGenerationRequest, PurgeOutcome};
use lumen_db::{Database, RepositoryError};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::kernel_client::{
    ActionEnvelope, AuditEvent, AuditRef, KernelClient, KernelError, KernelFuture, KeyPurgeReport,
    KeyRotationReport, LeaseDocument, LeaseLimits, LeaseVerification, OneShotGrant, PolicyDecision,
    SessionEndReport, SessionIdentityAuthority, SessionIdentityInfo, now_ms,
};
use crate::kernel_convert::{to_frozen_envelope, to_host_decision};

/// Which SQLite database the authority engine uses.
#[derive(Debug, Clone)]
pub enum AuthorityDb {
    /// Durable file database (migrations run on open).
    Path(PathBuf),
    /// Ephemeral in-memory database (migrations run on open). Used by
    /// tests; authority state does not survive the process.
    Memory,
}

/// Configuration for [`AuthorityKernelClient::open`].
pub struct AuthorityKernelConfig {
    pub db: AuthorityDb,
    /// The workspace whose authority rows this kernel owns. The row is
    /// created (`INSERT OR IGNORE`) on open; full workspace bootstrap
    /// (owner identity, membership) stays with the orchestration layer.
    pub workspace: WorkspaceId,
    /// Enrolled human VHL keys, `signer_key_id -> verifying key`.
    /// Enrollment itself is an operator/coordinator concern; the kernel
    /// only verifies grants against this map.
    pub vhl_keys: HashMap<String, VerifyingKey>,
    /// TTL for approval requests created by the no-covering-lease path.
    pub approval_ttl_ms: i64,
    /// Whether the filesystem is case-insensitive (macOS/Windows
    /// canonicalization).
    pub case_insensitive_fs: bool,
    /// Operator authority for key-custody control-plane operations
    /// (rotation, kill, purge). `None` denies all of them.
    pub operator_authority: Option<std::sync::Arc<dyn OperatorAuthorityPort>>,
    /// Session max lifetime: sessions older than this are destroyed
    /// durably at open (spec §6.3). Defaults to 24h.
    pub session_max_lifetime_ms: Option<i64>,
}

impl AuthorityKernelConfig {
    /// Test/development config: in-memory DB, no VHL keys enrolled, a
    /// fresh random workspace.
    pub fn test_config() -> Self {
        Self {
            db: AuthorityDb::Memory,
            workspace: WorkspaceId::new(),
            vhl_keys: HashMap::new(),
            approval_ttl_ms: 15 * 60 * 1000,
            case_insensitive_fs: false,
            operator_authority: None,
            session_max_lifetime_ms: Some(DEFAULT_SESSION_MAX_LIFETIME_MS),
        }
    }
}

/// A pending human approval: the kernel remembers the exact
/// [`CanonicalAction`] behind each [`VhlRequest`] it emitted so a later
/// [`KernelClient::request_one_shot_lease`] can bind the human's grant to
/// the approved action digest without trusting the host's copy.
struct PendingApproval {
    action: CanonicalAction,
    session_subject: String,
    expires_at_ms: i64,
}

/// Durable approval request awaiting a human decision (host/VHL poller
/// view). Read from the database, not the in-memory outbox mirror, so a
/// poller sees requests that survived a restart.
#[derive(Clone, Debug)]
pub struct PendingApprovalView {
    pub request_id: String,
    pub session_subject: String,
    pub action_digest: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Recorded kernel key generations, hydrated from
/// `kernel_key_generations` at open plus every boot's fresh generation.
/// All recorded generations (current and retired) live here so lease
/// validation can resolve retired issuers; only the *current* generation's
/// private keys exist (in [`KernelMutable::keys`], never persisted).
#[derive(Clone, Debug, Default)]
pub struct GenerationIndex {
    /// ALL recorded issuer generations including the current one,
    /// `key_id -> verifying key`.
    pub issuer: HashMap<String, VerifyingKey>,
    /// ALL recorded host generations including the current one.
    pub host: HashMap<String, VerifyingKey>,
    /// Killed generation ids (compromise response; fail closed).
    pub killed: HashSet<String>,
    /// `key_id -> created_at_ms` for every recorded generation.
    pub created_at_ms: HashMap<String, i64>,
}

/// Point-in-time issuer-key view for lease validation: the resolver the
/// phase-1 `validate_chain` and the envelope path consult so retired
/// generations keep verifying after a restart.
#[derive(Clone, Default)]
struct IssuerKeySnapshot {
    keys: HashMap<String, VerifyingKey>,
    killed: HashSet<String>,
}

impl IssuerKeyResolver for IssuerKeySnapshot {
    fn issuer_verifying_key(&self, key_id: &str) -> Option<VerifyingKey> {
        self.keys.get(key_id).cloned()
    }
    fn is_generation_killed(&self, key_id: &str) -> bool {
        self.killed.contains(key_id)
    }
}

/// Backward-clock tolerance for the boot rollback check: the wall clock
/// may lag the durable time anchor by up to five minutes (ordinary NTP
/// slew, VM clock wobble) without failing the open. A larger lag means
/// the clock moved backward past authority the kernel already acted on —
/// expired leases, sessions, and nonces could resurrect — so the kernel
/// refuses to open until the clock is corrected. There is no silent
/// forward clamp: a forward jump only shortens lifetimes, which is safe.
pub const CLOCK_ROLLBACK_TOLERANCE_MS: i64 = 5 * 60 * 1000;

/// Durable-write throttle for the time anchor: `effective_now_sync`
/// advances the in-memory mark on every authority decision, but only
/// writes it to the database when it has moved at least this far past
/// the last durable write. The anchor exists to detect a backward clock
/// jump across restarts; a staleness far below the five-minute rollback
/// tolerance is irrelevant to that check, and a database write on every
/// single decision would be pure IO amplification.
const TIME_ANCHOR_PERSIST_INTERVAL_MS: i64 = 30_000;

/// Write-ahead anchor: the ceiling of `t` to the next persist-interval
/// boundary. Persisting the ceiling (rather than the mark) keeps the
/// durable anchor >= the greatest effective time the kernel has acted
/// on, so a crash can never reopen an already-observed expiry.
fn anchor_ceiling(t: i64) -> i64 {
    (t + TIME_ANCHOR_PERSIST_INTERVAL_MS - 1) / TIME_ANCHOR_PERSIST_INTERVAL_MS
        * TIME_ANCHOR_PERSIST_INTERVAL_MS
}

/// SHA-256 hex fingerprint of a verifying key (public fingerprint for
/// audit correlation, not key material).
fn verifying_key_sha256_hex(vk: &VerifyingKey) -> String {
    let mut hasher = Sha256::new();
    hasher.update(vk.as_bytes());
    hex::encode(hasher.finalize())
}

/// Parse one recorded verifying key (a key generation row or a session
/// row). Any malformed key (bad hex, wrong length, bad point) fails the
/// open: hydrating an index with a corrupt key would silently break
/// verification (startup tamper detection, spec §8.13).
fn parse_recorded_verifying_key(
    what: &str,
    id: &str,
    verifying_key_hex: &str,
) -> Result<VerifyingKey, KernelError> {
    let corrupt = |detail: String| {
        KernelError::Unavailable(format!(
            "recorded {what} '{id}' verifying key is corrupt ({detail}); refusing to hydrate"
        ))
    };
    let bytes = hex::decode(verifying_key_hex).map_err(|e| corrupt(e.to_string()))?;
    let raw: [u8; 32] = bytes
        .try_into()
        .map_err(|_| corrupt("bad length".to_string()))?;
    VerifyingKey::from_bytes(&raw).map_err(|e| corrupt(e.to_string()))
}

/// Mutable kernel state behind one mutex. The mutex is held across
/// `authorize_envelope` (which also performs durable IO through the
/// adapters below on the kernel's private runtime): the adapters never
/// touch this mutex, so there is no lock cycle.
///
/// `keys` lives here (not on [`AuthorityKernel`]) so rotation can swap it
/// under the same lock that guards the generation index — no second lock,
/// no lock-ordering hazards.
struct KernelMutable {
    /// The current boot's (or the latest rotation's) kernel keys. The
    /// private keys exist only here; dropping replaces them (zeroized).
    keys: KernelKeys,
    /// Recorded issuer/host generations (current + retired) and the
    /// kill set.
    generations: GenerationIndex,
    sessions: SessionRegistry,
    vault: SessionIdentityVault,
    revocations: RevocationIndex,
    /// Hot cache of consumed one-shot lease ids; the durable set is
    /// `kernel_one_shot_uses` (see [`DbOneShotTracker`]).
    one_shot_mem: HashSet<String>,
    pending: HashMap<String, PendingApproval>,
    /// Emitted approval requests awaiting VHL delivery.
    outbox: Vec<VhlRequest>,
    /// Subjects destroyed by the vault, kept so a retried terminate can
    /// still revoke the right leases after the vault reports the session
    /// as already destroyed. Each entry records the affected subjects and
    /// whether the durable destroy+revoke transition committed: a retry
    /// after a failed durable write must rerun the transition, not
    /// report success.
    destroyed: HashMap<String, (Vec<String>, bool)>,
    /// Monotonic authority-time anchor: the greatest effective time the
    /// kernel has acted on. Every authority decision runs at
    /// `max(wall clock, this mark)` and advances it, so a backward
    /// wall-clock jump (VM snapshot restore, NTP step, operator error)
    /// cannot resurrect expired leases, sessions, or nonces. The mark is
    /// durable (`kernel_time_high_water`); the boot sequence fails closed
    /// when the wall clock lags it by more than
    /// [`CLOCK_ROLLBACK_TOLERANCE_MS`].
    time_high_water_ms: i64,
    /// The last anchor value actually written to the database. The
    /// in-memory mark advances on every decision; the durable write
    /// persists the *ceiling* of the mark to the next
    /// [`TIME_ANCHOR_PERSIST_INTERVAL_MS`] boundary, throttled to one
    /// write per interval of movement, so the durable anchor never lags
    /// the latest decision (write-ahead: a crash cannot reopen an
    /// already-observed expiry).
    time_high_water_persisted_ms: i64,
}

impl KernelMutable {
    /// Build the point-in-time issuer view validation uses. The maps are
    /// cloned so the resolver never holds the state lock.
    fn issuer_snapshot(&self) -> IssuerKeySnapshot {
        IssuerKeySnapshot {
            keys: self.generations.issuer.clone(),
            killed: self.generations.killed.clone(),
        }
    }
}

/// The synchronous authority core. All public async entry points funnel
/// through `spawn_blocking` into these `*_sync` methods.
pub struct AuthorityKernel {
    fs: RealFsResolver,
    nonces: NonceStore,
    ledger: BudgetLedger,
    state: Mutex<KernelMutable>,
    db: Database,
    /// Private runtime for the synchronous `*_sync` methods, which run
    /// on blocking workers outside any async context. `None` after the
    /// kernel is dropped (see `Drop`).
    rt: Option<tokio::runtime::Runtime>,
    config: AuthorityKernelConfig,
}

impl Drop for AuthorityKernel {
    fn drop(&mut self) {
        // Shutting a multi-thread runtime down the normal way blocks
        // joining worker threads, which panics inside an async context —
        // and the client is routinely dropped there (e.g. at the end of
        // a request handler or test). `shutdown_background` does not
        // block. This is safe because the runtime is only dropped with
        // the last `Arc`, at which point no `*_sync` worker can still
        // hold a clone.
        if let Some(rt) = self.rt.take() {
            rt.shutdown_background();
        }
    }
}

impl AuthorityKernel {
    /// Run a fallible database future on the kernel's private runtime.
    /// Must only be called from a blocking worker (the `*_sync` methods),
    /// never from inside an async context.
    fn db_run<'s, F, Fut, T>(&'s self, make: F) -> Result<T, KernelError>
    where
        F: FnOnce(&'s Database, &'s WorkspaceId) -> Fut,
        Fut: Future<Output = Result<T, RepositoryError>> + 's,
    {
        self.db_run_typed(make)
            .map_err(|e| KernelError::Unavailable(format!("kernel store: {e}")))
    }

    /// The kernel's authority time: `max(wall clock, time high-water)`.
    /// Every authority decision (expiry, TTL, nonce windows, mint
    /// timestamps) runs at this time. The in-memory mark advances on
    /// every call; the durable write persists the *ceiling* of the mark
    /// to the next [`TIME_ANCHOR_PERSIST_INTERVAL_MS`] boundary, so the
    /// durable anchor can never lag the latest authority decision — a
    /// crash followed by a clock rollback (or VM snapshot restore)
    /// resumes at a mark >= every decision time, and a lease already
    /// observed as expired can never appear live again. The write still
    /// happens at most once per interval of movement, and the ceiling is
    /// at most one interval ahead of the decision time — far below the
    /// boot rollback tolerance, so the boot check is unaffected. A
    /// backward clock therefore cannot move authority time: the mark only
    /// ever rises, and the boot sequence fails closed on a material
    /// backward jump before any decision runs. The in-memory update is
    /// max-guarded so concurrent advances cannot regress it.
    fn effective_now_sync(&self) -> Result<i64, KernelError> {
        let wall = now_ms();
        let mark = {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            state.time_high_water_ms
        };
        let effective = wall.max(mark);
        if effective > mark {
            // Write-ahead: persist the ceiling, not the mark. The anchor
            // is then always >= the greatest effective time the kernel
            // has acted on (the boot comment's invariant), while the
            // write stays throttled to one per interval of movement.
            // The in-memory mark advances only after the durable write
            // succeeds, so a failed write is retried on the next call
            // even if the clock has not moved.
            let ceiling = anchor_ceiling(effective);
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            // Re-read under the second lock: another thread may have
            // advanced (and persisted) further in the window between the
            // two locks. Persist only when this thread's ceiling exceeds
            // the current durable mark, and max-guard the in-memory mark
            // so a concurrent advance can never regress it.
            if ceiling > state.time_high_water_persisted_ms {
                self.db_run(|db, ws| db.record_time_high_water(ws, ceiling))?;
                state.time_high_water_persisted_ms = ceiling;
            }
            state.time_high_water_ms = state.time_high_water_ms.max(effective);
        }
        Ok(effective)
    }

    /// Run a database future, preserving the typed [`RepositoryError`] so
    /// callers can distinguish state conflicts (replay, double-claim)
    /// from store failures without string-matching on error text.
    fn db_run_typed<'s, F, Fut, T>(&'s self, make: F) -> Result<T, RepositoryError>
    where
        F: FnOnce(&'s Database, &'s WorkspaceId) -> Fut,
        Fut: Future<Output = Result<T, RepositoryError>> + 's,
    {
        let fut = make(&self.db, &self.config.workspace);
        self.rt
            .as_ref()
            .expect("kernel runtime used after drop")
            .block_on(fut)
    }

    fn authorize_params(&self, now: i64) -> AuthorizeParams {
        AuthorizeParams {
            now_ms: now,
            case_insensitive_fs: self.config.case_insensitive_fs,
            allow_approval_fallback: true,
            approval_ttl_ms: self.config.approval_ttl_ms,
        }
    }

    /// Gate a key-custody control-plane operation on the configured
    /// operator authority. No authority configured, or a deny, fails
    /// closed with [`KernelError::OperatorDenied`].
    async fn authorize_operator(
        &self,
        actor: &PrincipalId,
        op: OperatorOperation,
    ) -> Result<(), KernelError> {
        let authority = self.config.operator_authority.clone().ok_or_else(|| {
            KernelError::OperatorDenied("no operator authority configured".into())
        })?;
        let req = AuthorityRequest {
            workspace_id: self.config.workspace,
            actor: actor.clone(),
            operation: op,
            orchestration_id: None,
        };
        if authority
            .authorize(&req)
            .await
            .map_err(|e| KernelError::Unavailable(e.to_string()))?
        {
            Ok(())
        } else {
            Err(KernelError::OperatorDenied(format!(
                "operator {:?} denied {op:?}",
                req.actor
            )))
        }
    }

    /// Boot tail (spec §4.2): generation hydration, fresh-generation
    /// recording, session TTL expiry, session hydration, boot audit, the
    /// re-validation self-check, and the purge pass. Runs on a blocking
    /// worker; the state mutex is never held across audit or db calls.
    fn boot_sequence_sync(&self) -> Result<(), KernelError> {
        // 0. Wall-clock rollback check, before any authority decision.
        //    The durable time anchor is the greatest effective time the
        //    kernel has acted on; if the wall clock now lags it by more
        //    than the tolerance, the clock moved backward past live
        //    authority (snapshot restore, NTP step) and opening would
        //    resurrect expired leases, sessions, and nonces. Fail closed
        //    until the clock is corrected. Otherwise the boot runs at
        //    max(wall, anchor) and the anchor advances to the boot time.
        let wall = now_ms();
        let persisted = self.db_run(|db, ws| db.time_high_water(ws))?;
        if wall < persisted - CLOCK_ROLLBACK_TOLERANCE_MS {
            return Err(KernelError::Unavailable(format!(
                "wall clock {wall} lags the durable time anchor {persisted} by more than \
                 {tolerance} ms: refusing to open with a backward clock; \
                 correct the clock and restart",
                tolerance = CLOCK_ROLLBACK_TOLERANCE_MS,
            )));
        }
        let now = wall.max(persisted);
        // The workspace row must exist before any authority table is
        // touched (they FK to it). It is created here — AFTER the clock
        // check — so a refused open writes nothing at all. The birth
        // timestamp is the boot's effective time, like every other
        // kernel-written timestamp.
        self.db_run(|db, ws| db.ensure_workspace(ws, "lumen-kernel", now))?;
        self.db_run(|db, ws| db.record_time_high_water(ws, now))?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            state.time_high_water_ms = now;
            state.time_high_water_persisted_ms = now;
        }
        let boot_id = format!("boot-{}", Uuid::new_v4());
        let max_lifetime = self.config.session_max_lifetime_ms;
        let ttl = max_lifetime.unwrap_or(DEFAULT_SESSION_MAX_LIFETIME_MS);

        // 1. Load recorded generations + kill set into the in-memory
        //    index. A malformed recorded key fails the open rather than
        //    hydrating a corrupt index.
        let rows = self.db_run(|db, ws| db.kernel_key_generations(ws))?;
        let killed = self.db_run(|db, ws| db.killed_key_generation_ids(ws))?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            for row in &rows {
                let vk = parse_recorded_verifying_key(
                    "generation",
                    &row.key_id,
                    &row.verifying_key_hex,
                )?;
                match row.role.as_str() {
                    "issuer" => {
                        state.generations.issuer.insert(row.key_id.clone(), vk);
                    }
                    "host" => {
                        state.generations.host.insert(row.key_id.clone(), vk);
                    }
                    other => {
                        return Err(KernelError::Unavailable(format!(
                            "recorded key generation '{}' has unknown role {other:?}; refusing to hydrate",
                            row.key_id
                        )));
                    }
                }
                state
                    .generations
                    .created_at_ms
                    .insert(row.key_id.clone(), row.created_at_ms);
            }
            state.generations.killed = killed;
        }

        // 2. Record this boot's fresh generation and insert it into the
        //    index. The previous issuer generation is the recorded issuer
        //    row (excluding the new id) with the latest created_at_ms;
        //    count its live refs for the retirement audit event.
        let (new_issuer_id, new_host_id, new_issuer_vk, new_host_vk, prev_issuer) = {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            let new_issuer_id = state.keys.issuer_key_id.clone();
            let prev_issuer = state
                .generations
                .issuer
                .keys()
                .filter(|id| id.as_str() != new_issuer_id)
                .max_by_key(|id| {
                    state
                        .generations
                        .created_at_ms
                        .get(*id)
                        .copied()
                        .unwrap_or(0)
                })
                .cloned();
            (
                new_issuer_id,
                state.keys.host_key_id.clone(),
                state.keys.issuer_verifying(),
                state.keys.host_verifying(),
                prev_issuer,
            )
        };
        let new_issuer_hex = hex::encode(new_issuer_vk.to_bytes());
        let new_host_hex = hex::encode(new_host_vk.to_bytes());
        self.db_run(|db, ws| {
            db.record_kernel_key_generation(ws, &new_issuer_id, "issuer", &new_issuer_hex, now)
        })?;
        self.db_run(|db, ws| {
            db.record_kernel_key_generation(ws, &new_host_id, "host", &new_host_hex, now)
        })?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            state
                .generations
                .issuer
                .insert(new_issuer_id.clone(), new_issuer_vk);
            state
                .generations
                .host
                .insert(new_host_id.clone(), new_host_vk);
            state
                .generations
                .created_at_ms
                .insert(new_issuer_id.clone(), now);
            state
                .generations
                .created_at_ms
                .insert(new_host_id.clone(), now);
        }
        let prev_issuer_live_refs = match &prev_issuer {
            Some(id) => self.db_run(|db, ws| db.live_lease_refs_to_generation(ws, id, now))?,
            None => 0,
        };

        // 3. Session TTL: destroy-transition every session older than the
        //    max lifetime, and revoke its leases durably (spec §6.3). The
        //    expiry and the revocations commit in ONE transaction: a crash
        //    between them would leave destroyed sessions with live,
        //    unrevoked leases, and the next boot's re-validation
        //    self-check would fail the open on `SubjectInactive` (the
        //    expiry finds nothing — the rows are already inactive — so the
        //    leases would never be revoked).
        let (expired, revoked_ids) = self.db_run(|db, ws| {
            db.expire_kernel_sessions_and_revoke(ws, ttl, now, "session TTL expired")
        })?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            for id in &revoked_ids {
                state.revocations.revoke(id);
            }
            for subject in &expired {
                state.sessions.deactivate(subject);
            }
        }

        // 4. Hydrate the session registry from active rows
        //    (validating-only: the vault stays empty, D2). Every row is
        //    verified before registration:
        //    - subject == session_address(verifying_key): the subject is
        //      *derived from* the key, so a tampered row (subject/key
        //      mismatch) cannot hydrate a session the key doesn't own.
        //    - the parent graph resolves to live sessions with no cycles:
        //      a dangling or cyclic parent fails the open rather than
        //      hydrating a session whose ancestry can't authorize.
        //    TTL expiry was already destroy-transitioned in step 3 with
        //    the same `now`, so every row here is within its lifetime.
        let active = self.db_run(|db, ws| db.active_kernel_sessions(ws))?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            state.sessions.set_max_lifetime(max_lifetime);
            for row in &active {
                let vk =
                    parse_recorded_verifying_key("session", &row.subject, &row.verifying_key_hex)?;
                if session_address(&vk) != row.subject {
                    return Err(KernelError::Unavailable(format!(
                        "session row '{}' verifying key does not derive its subject; \
                         refusing to hydrate a mismatched identity",
                        row.subject
                    )));
                }
                state.sessions.register(
                    row.subject.clone(),
                    row.parent_subject.clone(),
                    vk,
                    row.created_at_ms,
                );
            }
            for row in &active {
                let mut current = row.subject.clone();
                let mut seen = HashSet::new();
                loop {
                    if !seen.insert(current.clone()) {
                        return Err(KernelError::Unavailable(format!(
                            "session ancestry cycle at '{current}'; refusing to hydrate"
                        )));
                    }
                    if seen.len() > 256 {
                        return Err(KernelError::Unavailable(format!(
                            "session ancestry of '{}' exceeds 256 hops; refusing to hydrate",
                            row.subject
                        )));
                    }
                    let record = state.sessions.get(&current).ok_or_else(|| {
                        KernelError::Unavailable(format!(
                            "session '{current}' has no hydrated record; refusing to hydrate"
                        ))
                    })?;
                    if !record.active {
                        return Err(KernelError::Unavailable(format!(
                            "session '{current}' is not active; refusing to hydrate"
                        )));
                    }
                    match &record.parent_subject {
                        Some(parent) => match state.sessions.get(parent) {
                            Some(p) if p.active => current = parent.clone(),
                            _ => {
                                return Err(KernelError::Unavailable(format!(
                                    "session '{}' names unknown or inactive parent '{parent}'; \
                                     refusing to hydrate",
                                    row.subject
                                )));
                            }
                        },
                        None => break,
                    }
                }
            }
        }

        // 5. Boot audit events (signed by the new host key).
        let recorded = |key_id: &str, role: &str, vk: &VerifyingKey| {
            serde_json::json!({
                "host_kind": "kernel.key_generation.recorded",
                "key_id": key_id,
                "role": role,
                "verifying_key_sha256": verifying_key_sha256_hex(vk),
                "boot_id": boot_id,
                "at_ms": now,
            })
        };
        self.audit_event_sync(
            "kernel",
            AuditEventKind::ActionProposed,
            "kernel",
            "kernel.key_generation.recorded",
            None,
            now,
            recorded(&new_issuer_id, "issuer", &new_issuer_vk),
        )
        .map(|_| ())?;
        self.audit_event_sync(
            "kernel",
            AuditEventKind::ActionProposed,
            "kernel",
            "kernel.key_generation.recorded",
            None,
            now,
            recorded(&new_host_id, "host", &new_host_vk),
        )
        .map(|_| ())?;
        if let Some(prev_id) = &prev_issuer {
            self.audit_event_sync(
                "kernel",
                AuditEventKind::ActionProposed,
                "kernel",
                "kernel.key_generation.retired",
                None,
                now,
                serde_json::json!({
                    "host_kind": "kernel.key_generation.retired",
                    "key_id": prev_id,
                    "role": "issuer",
                    "live_lease_refs": prev_issuer_live_refs,
                    "at_ms": now,
                }),
            )
            .map(|_| ())?;
        }
        self.audit_event_sync(
            "kernel",
            AuditEventKind::ActionProposed,
            "kernel",
            "kernel.session.restored",
            None,
            now,
            serde_json::json!({
                "host_kind": "kernel.session.restored",
                "count": active.len(),
                "at_ms": now,
            }),
        )
        .map(|_| ())?;

        // 6. Re-validation self-check: every live lease's chain must
        //    verify against the generation snapshot. Failure classes:
        //    - UnknownIssuerGeneration: counted, open proceeds. These are
        //      pre-migration leases (spec §7): issued before generations
        //      were recorded, so no verifying key exists. They are NOT
        //      treated as tamper, but they also never authorize — any
        //      decision path re-validates and fails closed on them.
        //    - Legacy pre-migration leases (subject has no
        //      `kernel_sessions` row: sessions were not durably recorded
        //      before migration 0025): counted, open proceeds. Like
        //      unknown-generation leases they never authorize — decision
        //      paths re-validate and fail closed on `SubjectInactive`.
        //    - AlreadyConsumed / KilledIssuerGeneration: counted as
        //      verified_ok for the self-check's liveness purpose (a
        //      consumed one-shot or a killed generation is a *decided*
        //      state, not corruption); both still deny at decision time.
        //    - Anything else (signature mismatch against a known
        //      generation, unknown session key, inactive session,
        //      revocation, chain break): tamper or corruption evidence —
        //      fails the open. A live lease naming a subject WITH a
        //      session row that is inactive is corruption (or crash
        //      residue the repair pass below missed), not migration:
        //      sessions are always recorded at creation once migration
        //      0025 has run.
        //
        //    Crash-residue repair (before the lease fetch): a crash in the
        //    pre-atomicity window between the session destroy transition
        //    and the lease revocation leaves live leases for destroyed
        //    sessions. Those leases must never authorize, so they are
        //    durably revoked here; without the repair the self-check
        //    would fail the open on `SubjectInactive` and the kernel
        //    would stay down until the database is repaired by hand.
        let repaired_ids = self.db_run(|db, ws| {
            db.revoke_leases_for_inactive_sessions(
                ws,
                now,
                "boot repair: session destroyed without revocation",
            )
        })?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            for id in &repaired_ids {
                state.revocations.revoke(id);
            }
        }
        if !repaired_ids.is_empty() {
            self.audit_event_sync(
                "kernel",
                AuditEventKind::ActionProposed,
                "kernel",
                "kernel.session.residue_repaired",
                None,
                now,
                serde_json::json!({
                    "host_kind": "kernel.session.residue_repaired",
                    "revoked_leases": repaired_ids.len(),
                    "at_ms": now,
                }),
            )
            .map(|_| ())?;
        }
        let leases = self.db_run(|db, ws| db.kernel_live_leases(ws, now))?;
        // Preserve the total live-lease count for the audit BEFORE the
        // legacy filter below narrows the re-validation set: the audit
        // must record every live lease, not just the ones we re-walk.
        let total_live_leases = leases.len() as u64;
        let session_subjects = self.db_run(|db, ws| db.kernel_session_subjects(ws))?;
        let mut legacy_leases: u64 = 0;
        let leases: Vec<_> = leases
            .into_iter()
            .filter(|lease| {
                if session_subjects.contains(&lease.subject) {
                    true
                } else {
                    legacy_leases += 1;
                    false
                }
            })
            .collect();
        let mut verified_ok: u64 = 0;
        let mut unknown_generation: u64 = 0;
        {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            let snapshot = state.issuer_snapshot();
            let db_resolver = DbLeaseResolver {
                kernel: self,
                store_error: Cell::new(None),
            };
            let one_shot: HashSet<String> = HashSet::new();
            for lease in &leases {
                // Walk the chain to the root via the resolver (cap 64
                // hops against corrupt data); `validate_chain` re-walks
                // and requires the presented chain to match exactly.
                let mut chain_ids = vec![lease.lease_id.clone()];
                let mut parent = lease.parent_id.clone();
                for _ in 0..64 {
                    let Some(pid) = parent else { break };
                    chain_ids.push(pid.clone());
                    parent = db_resolver.lease(&pid).and_then(|d| d.parent_id);
                }
                match validate_chain(
                    &db_resolver,
                    &chain_ids,
                    &state.revocations,
                    &state.sessions,
                    &snapshot,
                    &one_shot,
                    now,
                ) {
                    Ok(_)
                    | Err(LeaseError::AlreadyConsumed(_))
                    | Err(LeaseError::KilledIssuerGeneration(_)) => {
                        verified_ok += 1;
                    }
                    Err(LeaseError::UnknownIssuerGeneration(_)) => {
                        unknown_generation += 1;
                    }
                    Err(e) => {
                        return Err(KernelError::Unavailable(format!(
                            "startup re-validation failed for lease {}: {e}",
                            lease.lease_id
                        )));
                    }
                }
            }
            if let Some(store_error) = db_resolver.take_store_error() {
                return Err(KernelError::Unavailable(format!(
                    "startup re-validation hit a store failure: {store_error}"
                )));
            }
        }
        self.audit_event_sync(
            "kernel",
            AuditEventKind::ActionProposed,
            "kernel",
            "kernel.restart.revalidation",
            None,
            now,
            serde_json::json!({
                "host_kind": "kernel.restart.revalidation",
                "live_leases": total_live_leases,
                "verified_ok": verified_ok,
                "unknown_generation": unknown_generation,
                "legacy_leases": legacy_leases,
                "tamper_failures": 0,
                "at_ms": now,
            }),
        )
        .map(|_| ())?;

        // 7. Purge pass for eligible retired generations.
        let _ = self.purge_pass_sync(now)?;
        Ok(())
    }

    /// Purge retired generations: every recorded generation except the
    /// current issuer/host ids is a candidate. Issuer generations need
    /// zero live lease refs; host generations additionally need zero
    /// retained checkpoints (the store refuses host generations while any
    /// checkpoint references them, of any age — checkpoints are
    /// immutable and never deleted, so an age window would let a host key
    /// be purged while its old checkpoints still need it). The delete
    /// runs through the store's guarded permit path, which also refuses
    /// the live generations itself as a second line of defense; the
    /// in-memory index is kept in sync and each purge is audited.
    fn purge_pass_sync(&self, now: i64) -> Result<KeyPurgeReport, KernelError> {
        // Snapshot the candidates and the live ids under the lock; the db
        // calls run lock-free.
        let (candidates, live): (Vec<(String, String)>, [String; 2]) = {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            let live = [
                state.keys.issuer_key_id.clone(),
                state.keys.host_key_id.clone(),
            ];
            let mut candidates = Vec::new();
            for id in state.generations.issuer.keys() {
                if *id != live[0] {
                    candidates.push((id.clone(), "issuer".to_string()));
                }
            }
            for id in state.generations.host.keys() {
                if *id != live[1] {
                    candidates.push((id.clone(), "host".to_string()));
                }
            }
            (candidates, live)
        };
        let live_refs: [&str; 2] = [&live[0], &live[1]];
        let mut report = KeyPurgeReport::default();
        for (key_id, role) in candidates {
            let refs = self.db_run(|db, ws| db.live_lease_refs_to_generation(ws, &key_id, now))?;
            if refs != 0 {
                report.skipped_live.push(key_id);
                continue;
            }
            match self.db_run_typed(|db, ws| db.purge_key_generation(ws, &key_id, now, &live_refs))
            {
                Ok(PurgeOutcome::Purged) => {
                    {
                        let mut state = self.state.lock().expect("kernel state mutex poisoned");
                        if role == "issuer" {
                            state.generations.issuer.remove(&key_id);
                        } else {
                            state.generations.host.remove(&key_id);
                        }
                        state.generations.created_at_ms.remove(&key_id);
                    }
                    // The purge timestamp is authority time: the audit chain
                    // must stay monotonic even across a (tolerated) small
                    // clock rollback.
                    let at = self.effective_now_sync()?;
                    self.audit_event_sync(
                        "kernel",
                        AuditEventKind::ActionProposed,
                        "kernel",
                        "kernel.key_generation.purged",
                        None,
                        at,
                        serde_json::json!({
                            "host_kind": "kernel.key_generation.purged",
                            "key_id": key_id,
                            "role": role,
                            "at_ms": at,
                        }),
                    )
                    .map(|_| ())?;
                    report.purged.push(key_id);
                }
                Ok(
                    PurgeOutcome::StillReferenced
                    | PurgeOutcome::NotFound
                    | PurgeOutcome::CurrentGeneration,
                ) => {}
                // Host retention refusal (retained checkpoints): the
                // generation stays; not an open failure.
                Err(RepositoryError::InvalidKernelLeaseState(_)) => {}
                Err(e) => {
                    return Err(KernelError::Unavailable(format!(
                        "kernel store: purge of generation {key_id} failed: {e}"
                    )));
                }
            }
        }
        Ok(report)
    }

    /// Mid-boot emergency rotation: generate fresh keys, record both
    /// generations, swap them in (the old `KernelKeys` drops here, its
    /// private keys zeroized), update the index, and audit. Retired
    /// generations' verifying keys stay recorded, so outstanding leases
    /// keep verifying.
    fn rotate_issuer_keys_sync(&self, reason: &str) -> Result<KeyRotationReport, KernelError> {
        let now = self.effective_now_sync()?;
        let new_keys = KernelKeys::generate();
        let new_issuer_id = new_keys.issuer_key_id.clone();
        let new_host_id = new_keys.host_key_id.clone();
        let new_issuer_vk = new_keys.issuer_verifying();
        let new_host_vk = new_keys.host_verifying();
        let new_issuer_hex = hex::encode(new_issuer_vk.to_bytes());
        let new_host_hex = hex::encode(new_host_vk.to_bytes());
        self.db_run(|db, ws| {
            db.record_kernel_key_generation(ws, &new_issuer_id, "issuer", &new_issuer_hex, now)
        })?;
        self.db_run(|db, ws| {
            db.record_kernel_key_generation(ws, &new_host_id, "host", &new_host_hex, now)
        })?;
        // Swap under the state lock: the old KernelKeys drops here and
        // its private keys are zeroized by ZeroizeOnDrop.
        let (old_issuer_id, old_host_id) = {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            let old_issuer_id = state.keys.issuer_key_id.clone();
            let old_host_id = state.keys.host_key_id.clone();
            state.keys = new_keys;
            state
                .generations
                .issuer
                .insert(new_issuer_id.clone(), new_issuer_vk);
            state
                .generations
                .host
                .insert(new_host_id.clone(), new_host_vk);
            state
                .generations
                .created_at_ms
                .insert(new_issuer_id.clone(), now);
            state
                .generations
                .created_at_ms
                .insert(new_host_id.clone(), now);
            (old_issuer_id, old_host_id)
        };
        let live_refs =
            self.db_run(|db, ws| db.live_lease_refs_to_generation(ws, &old_issuer_id, now))?;
        let rotation_id = format!("rotation-{}", Uuid::new_v4());
        for (key_id, role, vk) in [
            (&new_issuer_id, "issuer", new_issuer_vk),
            (&new_host_id, "host", new_host_vk),
        ] {
            self.audit_event_sync(
                "kernel",
                AuditEventKind::ActionProposed,
                "kernel",
                "kernel.key_generation.recorded",
                None,
                now,
                serde_json::json!({
                    "host_kind": "kernel.key_generation.recorded",
                    "key_id": key_id,
                    "role": role,
                    "verifying_key_sha256": verifying_key_sha256_hex(&vk),
                    "boot_id": rotation_id,
                    "reason": reason,
                    "at_ms": now,
                }),
            )
            .map(|_| ())?;
        }
        self.audit_event_sync(
            "kernel",
            AuditEventKind::ActionProposed,
            "kernel",
            "kernel.key_generation.retired",
            None,
            now,
            serde_json::json!({
                "host_kind": "kernel.key_generation.retired",
                "key_id": old_issuer_id,
                "role": "issuer",
                "live_lease_refs": live_refs,
                "reason": reason,
                "at_ms": now,
            }),
        )
        .map(|_| ())?;
        Ok(KeyRotationReport {
            old_issuer_key_id: old_issuer_id,
            new_issuer_key_id: new_issuer_id,
            old_host_key_id: old_host_id,
            new_host_key_id: new_host_id,
            live_lease_refs_on_old_issuer: live_refs,
        })
    }

    /// Kill a generation (compromise response): record it in the durable
    /// kill-list and the in-memory kill set; verification fails closed
    /// for it from here on. The current generation cannot be killed
    /// (rotate first).
    fn kill_key_generation_sync(
        &self,
        key_id: &str,
        role: &str,
        reason: &str,
        killed_by: &str,
    ) -> Result<bool, KernelError> {
        if role != "issuer" && role != "host" {
            return Err(KernelError::Unavailable(format!(
                "kill_key_generation: invalid role {role:?}"
            )));
        }
        {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            if key_id == state.keys.issuer_key_id || key_id == state.keys.host_key_id {
                return Err(KernelError::Unavailable(
                    "cannot kill the current generation; rotate first".to_string(),
                ));
            }
        }
        let now = self.effective_now_sync()?;
        let details = serde_json::json!({
            "host_kind": "kernel.key_generation.killed",
            "key_id": key_id,
            "role": role,
            "reason": reason,
            "killed_by": killed_by,
            "at_ms": now,
        });
        let key_id_owned = key_id.to_string();
        let role_owned = role.to_string();
        let reason_owned = reason.to_string();
        let killed_by_owned = killed_by.to_string();
        let (killed, _event) = self.db_run(|db, ws| async move {
            let action_digest = format!("{:064x}", 0);
            let audit = KernelAuditAppend {
                actor: "kernel",
                kind: AuditEventKind::ActionProposed,
                session_id: "kernel",
                action_digest: &action_digest,
                decision: None,
                timestamp_ms: now,
                details,
            };
            db.kill_key_generation_with_audit(
                ws,
                &KillGenerationRequest {
                    key_id: &key_id_owned,
                    role: &role_owned,
                    killed_at_ms: now,
                    reason: &reason_owned,
                    killed_by: &killed_by_owned,
                    audit: &audit,
                },
            )
            .await
        })?;
        if killed {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            state.generations.killed.insert(key_id.to_string());
        }
        Ok(killed)
    }

    /// Evaluate one envelope against the real phase-1 kernel and audit
    /// the decision durably.
    fn decide_sync(&self, envelope: &ActionEnvelope) -> Result<PolicyDecision, KernelError> {
        let frozen = to_frozen_envelope(envelope)?;
        let now = self.effective_now_sync()?;

        // Canonicalize before touching the replay gate so malformed
        // envelopes never burn a nonce (mirrors authorize_envelope's own
        // ordering: canonicalization, expiry, then the nonce check). A
        // canonicalization failure is a deny, not a kernel error.
        let action = match CanonicalAction::from_envelope(
            &frozen,
            &self.fs,
            self.config.case_insensitive_fs,
        ) {
            Ok(action) => action,
            Err(e) => {
                let reason = DenyReason::invalid_envelope(e.to_string());
                let _ = self.audit_decision(&frozen, "deny", &reason);
                return to_host_decision(&FrozenDecision::deny(reason), envelope);
            }
        };
        if frozen.expires_at_ms <= now {
            let reason = DenyReason::expired_action("action expired".to_string());
            let _ = self.audit_decision(&frozen, "deny", &reason);
            return to_host_decision(&FrozenDecision::deny(reason), envelope);
        }

        // Durable replay gate: the nonce row commits before evaluation,
        // so a crash between gate and decision still fails closed on
        // retry (the retry sees the replay, not a fresh envelope).
        let nonce_key = format!("{}:{}", frozen.action_id, frozen.nonce);
        let nonce_ttl = frozen.expires_at_ms.saturating_sub(now).max(1);
        let _ = self.db_run(|db, ws| db.purge_kernel_nonces(ws, now))?;
        let fresh = self.db_run(|db, ws| {
            db.record_kernel_nonce(ws, &nonce_key, now, now.saturating_add(nonce_ttl))
        })?;
        if !fresh {
            let reason = DenyReason::replay_detected(format!("envelope nonce replay: {nonce_key}"));
            let _ = self.audit_decision(&frozen, "deny", &reason);
            return to_host_decision(&FrozenDecision::deny(reason), envelope);
        }

        // Evaluate against the real kernel. The resolver and one-shot
        // tracker consult the durable store; the in-memory structures are
        // hot caches over the same rows. Issuer keys resolve through the
        // point-in-time generation snapshot (current + retired), not the
        // live keys: retired generations keep verifying after restart.
        let issuer_snapshot = {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            state.issuer_snapshot()
        };
        let decision = {
            let mut guard = self.state.lock().expect("kernel state mutex poisoned");
            // Split the state into disjoint borrows up front: the
            // one-shot tracker needs `&mut one_shot_mem` while the
            // evaluator needs `&revocations` / `&sessions`.
            let KernelMutable {
                revocations,
                sessions,
                one_shot_mem,
                outbox,
                ..
            } = &mut *guard;
            let mut one_shot = DbOneShotTracker {
                kernel: self,
                mem: one_shot_mem,
                now_ms: now,
                store_error: None,
            };
            // `Vec<VhlRequest>` implements `ApprovalOutbox`; requests
            // emitted by this call are moved into the kernel outbox below.
            let mut call_outbox: Vec<VhlRequest> = Vec::new();
            let lease_resolver = DbLeaseResolver {
                kernel: self,
                store_error: Cell::new(None),
            };
            let decision = authorize_envelope(
                &frozen,
                &self.fs,
                &lease_resolver,
                revocations,
                sessions,
                &issuer_snapshot,
                &mut one_shot,
                &self.nonces,
                &self.ledger,
                &mut call_outbox,
                &self.authorize_params(now),
            );
            // A store failure during chain resolution means the decision
            // was made with an incomplete view of authority: fail closed
            // as kernel-unavailable rather than reporting a policy
            // outcome. (The audit below runs for the fault too.)
            let store_error = lease_resolver
                .take_store_error()
                .or_else(|| one_shot.take_store_error());
            drop(one_shot);
            outbox.extend(call_outbox.iter().cloned());
            (decision, store_error)
        };
        let (decision, store_error) = decision;

        // The lease store failed mid-authorization: the decision above was
        // made with an incomplete view of authority and must not be
        // reported as a policy outcome. Audit the fault and fail closed.
        if let Some(store_error) = store_error {
            let reason = DenyReason::no_lease(format!("kernel store failure: {store_error}"));
            self.audit_decision(&frozen, "fault", &reason)?;
            return Err(KernelError::Unavailable(format!(
                "kernel store unavailable during authorization: {store_error}"
            )));
        }

        // Persist the exact action behind any emitted approval request
        // through the phase-4 VHL state machine BEFORE the host learns
        // the request id. The database row is the durable request (with
        // the exact `ApprovalView` the human reviews); the in-memory
        // outbox is a hot mirror for polling, and the pending map caches
        // the exact canonical action for the later one-shot mint.
        if let DecisionOutcome::PendingApproval { approval_id, .. } = &decision.outcome {
            let mut approval = VhlApprovalRequest::new(
                ApprovalKind::OneShot,
                &action,
                &frozen,
                1,
                self.config.approval_ttl_ms,
                now,
            )
            .map_err(|e| KernelError::Unavailable(format!("approval request: {e}")))?;
            // Correlate with the kernel's request: the host, the outbox
            // mirror, and the durable row share one id, one envelope
            // nonce, and one expiry.
            approval.request_id = approval_id.clone();
            approval.nonce = frozen.nonce.clone();
            approval.expires_at_ms = now.saturating_add(self.config.approval_ttl_ms);
            let expires_at_ms = approval.expires_at_ms;
            self.db_run(|db, ws| db.vhl_insert_request(ws, &approval))?;
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            state.pending.insert(
                approval_id.clone(),
                PendingApproval {
                    action,
                    session_subject: frozen.session_id.clone(),
                    expires_at_ms,
                },
            );
            // Keep the pending map bounded: drop expired entries.
            state
                .pending
                .retain(|_, pending| pending.expires_at_ms > now);
        }

        let decision_str = match &decision.outcome {
            DecisionOutcome::Allow { .. } => "allow",
            DecisionOutcome::Deny { .. } => "deny",
            DecisionOutcome::PendingApproval { .. } => "pending",
        };
        let reason = match &decision.outcome {
            DecisionOutcome::Allow { .. } => DenyReason::no_lease(String::new()),
            DecisionOutcome::Deny { reason } => reason.clone(),
            DecisionOutcome::PendingApproval { reason, .. } => DenyReason::no_lease(reason.clone()),
        };
        self.audit_decision(&frozen, decision_str, &reason)?;
        to_host_decision(&decision, envelope)
    }

    /// Append the kernel's own decision event to the durable audit log,
    /// then anchor it with a host-key checkpoint.
    ///
    /// Fail-closed: the decision has been computed but not acted on; if
    /// the audit trail cannot record it, the whole authorization fails
    /// rather than returning an unaudited decision.
    fn audit_decision(
        &self,
        frozen: &FrozenEnvelope,
        decision: &str,
        reason: &DenyReason,
    ) -> Result<(), KernelError> {
        let kind = match decision {
            "allow" => AuditEventKind::PolicyAllowed,
            "pending" => AuditEventKind::ApprovalRequested,
            _ => AuditEventKind::PolicyDenied,
        };
        let digest = frozen
            .digest()
            .map_err(|e| KernelError::Unavailable(format!("digest failed: {e}")))?;
        let details = serde_json::json!({
            "host_kind": format!("policy_{decision}"),
            "action_id": frozen.action_id.to_string(),
            "tool": frozen.tool.name,
            "reason_code": reason.code,
            "reason_detail": reason.detail,
        });
        let detail = lumen_core::kernel_audit::render_detail(&details)
            .map_err(|e| KernelError::Unavailable(format!("audit detail: {e}")))?;
        self.audit_event_sync(
            &frozen.session_id,
            kind,
            &frozen.session_id,
            &digest,
            Some(decision),
            // Authority time: the decision record is part of the
            // monotonic audit chain.
            self.effective_now_sync()?,
            serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
        )
        .map(|_| ())
    }

    /// Append an audit event and anchor it with a host-key checkpoint.
    ///
    /// Every kernel audit event is checkpointed: the host key signs the
    /// chain head, so [`Database::verify_kernel_audit`] can prove the log
    /// the host acted on. Fail-closed: any failure returns
    /// [`KernelError::AuditFailed`] and the caller must treat the whole
    /// operation as failed.
    // Pre-existing signature (8 args); refactoring the call sites is out of
    // scope for the integration work. The args are all distinct audit
    // fields with no natural grouping.
    #[allow(clippy::too_many_arguments)]
    fn audit_event_sync(
        &self,
        actor: &str,
        kind: AuditEventKind,
        session_id: &str,
        action_digest: &str,
        decision: Option<&str>,
        timestamp_ms: i64,
        details: serde_json::Value,
    ) -> Result<pi_boundary::AuditEvent, KernelError> {
        let actor = actor.to_string();
        let session_id = session_id.to_string();
        let action_digest = action_digest.to_string();
        let decision = decision.map(str::to_string);
        self.db_run(|db, ws| async move {
            let event = db
                .append_kernel_audit_event(
                    ws,
                    &KernelAuditAppend {
                        actor: &actor,
                        kind,
                        session_id: &session_id,
                        action_digest: &action_digest,
                        decision: decision.as_deref(),
                        timestamp_ms,
                        details,
                    },
                )
                .await?;
            let mut link = AuditLink {
                key_id: String::new(),
                through_seq: event.sequence,
                chain_hash: event.hash.clone(),
                signature: String::new(),
            };
            // Sign under the state lock (keys live in KernelMutable);
            // the guard is dropped before the checkpoint write below.
            {
                let state = self.state.lock().expect("kernel state mutex poisoned");
                link.sign(&state.keys);
            }
            db.checkpoint_kernel_audit(ws, &link, timestamp_ms).await?;
            Ok(event)
        })
        .map_err(|e| KernelError::AuditFailed(e.to_string()))
    }

    fn verify_lease_sync(&self, lease: &LeaseDocument) -> Result<LeaseVerification, KernelError> {
        if lease.protocol_version != lumen_core::lease::LEASE_PROTOCOL_VERSION {
            return Err(KernelError::Protocol(format!(
                "unsupported lease version {}",
                lease.protocol_version
            )));
        }
        let now = self.effective_now_sync()?;
        let stored = self
            .db_run(|db, ws| db.kernel_lease(ws, &lease.lease_id))?
            .ok_or_else(|| {
                KernelError::VerificationFailed(format!("unknown lease {}", lease.lease_id))
            })?;
        // Convert the presented host document into the kernel's typed
        // form, failing closed when the opaque scope/budget JSON does not
        // parse into the kernel grammar. The host never re-invents the
        // scope grammar; unparseable scope is a verification failure, not
        // a bypass.
        let presented = to_core_lease(lease).map_err(|e| {
            KernelError::VerificationFailed(format!("lease {} is malformed: {e}", lease.lease_id))
        })?;
        // The presented document must be identical to the kernel's
        // durable record: the signature covers every field except
        // `signature` itself, so any altered field (scope, limits,
        // timestamps, parent/depth, nonce) is forgery, not a lookup
        // miss. Full equality also lets the signature check below run
        // over the presented document itself, so a valid signature
        // necessarily covers the presented contents.
        if stored != presented {
            return Err(KernelError::VerificationFailed(format!(
                "lease {} does not match the kernel's record",
                lease.lease_id
            )));
        }
        // D4 ordering: time and revocation before key resolution and
        // signature. An expired or revoked lease is dead regardless of
        // which generation signed it, so those checks come first and
        // their reasons are never masked by key-retention state.
        if !stored.live_at(now) {
            return Err(KernelError::VerificationFailed(format!(
                "lease {} is not live",
                lease.lease_id
            )));
        }
        let revoked_mem = {
            self.state
                .lock()
                .expect("kernel state mutex poisoned")
                .revocations
                .is_revoked(&lease.lease_id)
        };
        let revoked_db = self.db_run(|db, ws| db.is_kernel_revoked(ws, &lease.lease_id))?;
        if revoked_mem || revoked_db {
            return Err(KernelError::Revoked(lease.lease_id.clone()));
        }
        // Signature: root and VHL one-shot leases verify under the
        // issuer generation named in `issuer_key_id` (current or
        // retired), resolved through the generation snapshot with the
        // kill-list checked first; child leases under the parent
        // session's key.
        let key: VerifyingKey = if stored.is_root() {
            let snapshot = {
                let state = self.state.lock().expect("kernel state mutex poisoned");
                state.issuer_snapshot()
            };
            if snapshot.is_generation_killed(&stored.issuer_key_id) {
                return Err(KernelError::VerificationFailed(format!(
                    "issuer generation {} was killed",
                    stored.issuer_key_id
                )));
            }
            snapshot
                .issuer_verifying_key(&stored.issuer_key_id)
                .ok_or_else(|| {
                    KernelError::VerificationFailed(format!(
                        "unknown issuer generation {}",
                        stored.issuer_key_id
                    ))
                })?
        } else {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            let record = state.sessions.get(&stored.issuer_key_id).ok_or_else(|| {
                KernelError::VerificationFailed(format!(
                    "unknown session key for {}",
                    stored.issuer_key_id
                ))
            })?;
            // Same full active-ancestry rule as `validate_chain`, at the
            // same effective-time snapshot: the issuing session and every
            // ancestor must be live (active, within TTL). A destroyed
            // ancestor fails closed even when the revocation row was lost.
            if !state.sessions.is_subject_live(&stored.issuer_key_id, now) {
                return Err(KernelError::VerificationFailed(format!(
                    "issuing session {} is not live",
                    stored.issuer_key_id
                )));
            }
            record.verifying_key
        };
        presented
            .verify_signature(&key)
            .map_err(|e| KernelError::VerificationFailed(format!("bad signature: {e}")))?;
        Ok(LeaseVerification {
            lease_id: lease.lease_id.clone(),
            subject: lease.subject.clone(),
            verified_at_ms: now,
            revoked: false,
        })
    }

    fn revoke_session_sync(&self, subject: &str) -> Result<(), KernelError> {
        let now = self.effective_now_sync()?;
        // Durable first: every lease id for the subject, in issue order.
        let ids = self.db_run(|db, ws| db.kernel_lease_ids_for_subject(ws, subject))?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            for id in &ids {
                state.revocations.revoke(id);
            }
        }
        for id in &ids {
            self.db_run(|db, ws| db.record_kernel_revocation(ws, id, now, "session terminated"))?;
        }
        Ok(())
    }

    /// Restore a cached pending action after a failed mint, for retry.
    /// Uses `entry().or_insert()` so a re-propose racing the failure
    /// (which installed a newer entry) is never clobbered.
    fn restore_pending(&self, approval_id: &str, pending: PendingApproval) {
        self.state
            .lock()
            .expect("kernel state mutex poisoned")
            .pending
            .entry(approval_id.to_string())
            .or_insert(pending);
    }

    /// Mint a one-shot lease from a human VHL grant.
    ///
    /// Durable transaction boundary (all-or-nothing in one SQLite
    /// transaction): the grant-nonce replay gate, the `approved → minted`
    /// approval claim (recording the minted lease id), and the lease +
    /// budget-account insert commit together. Either the approval is
    /// claimed AND the lease is durable, or nothing happened and a retry
    /// is safe.
    ///
    /// Failure semantics, explicitly:
    /// - Grant/approval validation fails (bad signature, wrong digest,
    ///   unknown/expired approval): no state changes at all.
    /// - In-memory mint fails (session dead, budget): the in-memory grant
    ///   nonce is consumed but nothing is durable; the approval stays
    ///   `approved`, the cached action is restored, and the human may
    ///   re-grant with a fresh nonce.
    /// - The durable transaction fails: the in-memory grant nonce is
    ///   rolled back (`forget`) so a retry is not blocked in-memory; the
    ///   approval stays `approved`, the durable nonce is unburned (the
    ///   transaction rolled back), and the cached action is restored.
    /// - The mint audit fails after the transaction committed: the lease
    ///   IS durable and the approval IS `minted` (the approval row carries
    ///   the lease id for recovery), but the caller gets an error and no
    ///   lease document — fail-closed for the host, which never learns a
    ///   lease id it cannot audit.
    fn request_one_shot_lease_sync(
        &self,
        grant: &OneShotGrant,
    ) -> Result<LeaseDocument, KernelError> {
        let now = self.effective_now_sync()?;
        let core_grant = to_core_grant(grant);
        // 1. The durable approval row is the source of truth: it must
        //    exist and be `approved`, and the grant must bind the exact
        //    approved action digest. The host's copy of the action is
        //    never trusted. Read-only: no state changes yet.
        let row = self
            .db_run(|db, ws| db.vhl_request(ws, &grant.approval_id))?
            .ok_or_else(|| {
                KernelError::OneShotRejected(format!("unknown approval {}", grant.approval_id))
            })?;
        if row.state != "approved" {
            return Err(KernelError::OneShotRejected(format!(
                "approval {} is not approved (state {})",
                grant.approval_id, row.state
            )));
        }
        if row.action_digest != grant.action_digest {
            return Err(KernelError::OneShotRejected(
                "grant does not bind the approved action".to_string(),
            ));
        }
        // 2. The grant signature must verify against an enrolled human
        //    VHL key.
        let vhl_key = self
            .config
            .vhl_keys
            .get(&core_grant.signer_key_id)
            .ok_or_else(|| {
                KernelError::OneShotRejected(format!(
                    "unknown VHL signer key {}",
                    core_grant.signer_key_id
                ))
            })?;
        core_grant
            .verify(vhl_key)
            .map_err(|e| KernelError::OneShotRejected(format!("grant signature invalid: {e}")))?;
        // 3. Take the exact canonical action cached at authorize time.
        //    A restart drops the cache: minting then fails closed until
        //    the action is re-proposed. The entry is restored below if
        //    the mint fails, so a transient failure never destroys the
        //    cached action.
        let pending = {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            state.pending.remove(&grant.approval_id).ok_or_else(|| {
                KernelError::OneShotRejected(format!(
                    "approval {} has no cached action (restart or expiry); re-propose",
                    grant.approval_id
                ))
            })?
        };
        if pending.expires_at_ms <= now {
            self.restore_pending(&grant.approval_id, pending);
            return Err(KernelError::OneShotRejected(format!(
                "approval {} expired",
                grant.approval_id
            )));
        }
        if core_grant.session_subject != pending.session_subject {
            self.restore_pending(&grant.approval_id, pending);
            return Err(KernelError::OneShotRejected(
                "grant does not bind the approved session".to_string(),
            ));
        }
        // 4. Mint through the real kernel: exact-action binding, session
        //    liveness, budget admission, and the in-memory grant-nonce
        //    gate are all checked inside. On failure the in-memory grant
        //    nonce is rolled back (`forget`) and the cached action is
        //    restored, so the human may re-grant with a fresh nonce.
        //    (`register_lease` is infallible and signing is in-memory, so
        //    a mint failure never leaves a ledger account behind; the
        //    only side effect to undo is the consumed nonce.)
        let doc = {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            match mint_one_shot_lease(
                &core_grant,
                vhl_key,
                &pending.action,
                &state.keys,
                &state.sessions,
                &self.ledger,
                &self.nonces,
                now,
            ) {
                Ok(doc) => doc,
                Err(e) => {
                    drop(state);
                    self.nonces.forget(&grant.nonce);
                    self.restore_pending(&grant.approval_id, pending);
                    return Err(KernelError::OneShotRejected(e.to_string()));
                }
            }
        };
        // 5. The durable boundary: nonce gate + approval claim + lease
        //    insert in one transaction. On failure, roll back ALL
        //    in-memory side effects of the successful mint: the grant
        //    nonce (`forget`), the cached action (restore), AND the
        //    budget account the mint registered (`remove_account`). The
        //    lease was never persisted, so its account must not linger —
        //    a retry mints fresh. A state conflict (replay or
        //    double-claim) is a rejection; any other store failure is
        //    unavailability.
        if let Err(e) = self.db_run_typed(|db, ws| {
            db.claim_approval_and_insert_one_shot(
                ws,
                &grant.approval_id,
                &grant.nonce,
                now,
                grant.expires_at_ms,
                &doc,
            )
        }) {
            self.ledger.remove_account(&doc.lease_id);
            self.nonces.forget(&grant.nonce);
            self.restore_pending(&grant.approval_id, pending);
            return Err(match e {
                RepositoryError::VhlStateConflict => KernelError::OneShotRejected(format!(
                    "approval {} already claimed or grant replayed",
                    grant.approval_id
                )),
                other => KernelError::Unavailable(format!("kernel store: {other}")),
            });
        }
        // 6. Durable: audit the mint (the cached action stays removed).
        //    The audit is fail-closed — if it fails, the caller gets an
        //    error and never learns the lease id (see the doc comment
        //    above).
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            // Keep the pending map bounded: drop expired entries.
            state
                .pending
                .retain(|_, pending| pending.expires_at_ms > now);
        }
        self.audit_mint(&doc, grant, now)?;
        Ok(to_host_lease(&doc))
    }

    fn audit_mint(
        &self,
        doc: &CoreLeaseDocument,
        grant: &OneShotGrant,
        now: i64,
    ) -> Result<(), KernelError> {
        let details = serde_json::json!({
            "host_kind": "approval.minted",
            "approval_id": grant.approval_id,
            "lease_id": doc.lease_id,
            "signer_key_id": grant.signer_key_id,
        });
        let detail = lumen_core::kernel_audit::render_detail(&details)
            .map_err(|e| KernelError::Unavailable(format!("audit detail: {e}")))?;
        self.audit_event_sync(
            &doc.subject,
            AuditEventKind::PolicyAllowed,
            &doc.subject,
            &grant.action_digest,
            Some("allow"),
            now,
            serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
        )?;
        Ok(())
    }

    fn append_audit_sync(&self, event: &AuditEvent) -> Result<AuditRef, KernelError> {
        let kind = map_host_audit_kind(&event.kind);
        let details = serde_json::json!({
            "host_kind": event.kind,
            "payload": event.payload,
        });
        let detail = lumen_core::kernel_audit::render_detail(&details)
            .map_err(|e| KernelError::AuditFailed(format!("audit detail: {e}")))?;
        let stored = self.audit_event_sync(
            &event.session_id,
            kind,
            &event.session_id,
            event.action_digest.as_deref().unwrap_or("none"),
            None,
            // Authority time: ingested host events join the same
            // monotonic audit chain.
            self.effective_now_sync()?,
            serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
        )?;
        Ok(AuditRef {
            event_id: stored.event_id.to_string(),
            chain_hash: stored.hash,
        })
    }

    /// Mint a root lease for a live session subject (test/operator
    /// helper; standing issuance policy belongs to the coordinator).
    /// The lease and its budget account are persisted before return.
    fn issue_root_lease_sync(&self, params: RootLeaseParams) -> Result<LeaseDocument, KernelError> {
        let now = self.effective_now_sync()?;
        let doc = {
            let state = self.state.lock().expect("kernel state mutex poisoned");
            mint_root_lease(
                params,
                &state.keys,
                &state.sessions,
                &self.ledger,
                &self.nonces,
                now,
            )
            .map_err(|e| KernelError::Unavailable(format!("mint failed: {e}")))?
        };
        self.db_run(|db, ws| db.insert_kernel_lease_with_budget(ws, &doc, now))?;
        Ok(to_host_lease(&doc))
    }

    fn start_session_identity_sync(
        &self,
        parent: Option<&str>,
    ) -> Result<SessionIdentityInfo, KernelError> {
        let now = self.effective_now_sync()?;
        let receipt = {
            let mut guard = self.state.lock().expect("kernel state mutex poisoned");
            let KernelMutable {
                vault, sessions, ..
            } = &mut *guard;
            vault
                .start_session(sessions, parent.map(str::to_string), now)
                .map_err(|e| KernelError::Unavailable(format!("identity mint failed: {e}")))?
        };
        // Durable session registry: public identity only (subject,
        // parent, verifying key, liveness). Private keys stay in the
        // vault. On a store failure the vault session is rolled back
        // (best-effort) so memory and store cannot disagree about the
        // session's existence.
        if let Err(e) = self.db_run(|db, ws| {
            db.insert_kernel_session(
                ws,
                &receipt.subject,
                receipt.parent_subject.as_deref(),
                &receipt.verifying_key_hex,
                receipt.created_at_ms,
            )
        }) {
            let mut guard = self.state.lock().expect("kernel state mutex poisoned");
            let KernelMutable {
                vault, sessions, ..
            } = &mut *guard;
            let _ = vault.end_session(sessions, &receipt.subject, now);
            return Err(KernelError::Unavailable(format!(
                "kernel store: session record insert failed: {e}"
            )));
        }
        let _ = self.audit_identity_event(
            "session_started",
            &receipt.subject,
            &serde_json::json!({ "parent": parent }),
            now,
        );
        Ok(SessionIdentityInfo {
            subject: receipt.subject,
            verifying_key_hex: receipt.verifying_key_hex,
        })
    }

    /// Destroy a session identity through the three paths, all ending in
    /// ONE durable destroy+revoke transition:
    /// - **Vault path:** `end_session` succeeds (normal case).
    /// - **Remembered path:** `end_session` errs but the kernel remembers
    ///   the subject (idempotent retry): the durable transition already
    ///   applied, so it is skipped.
    /// - **Durable-only path (post-restart):** `end_session` errs and the
    ///   subject is not remembered, but the hydrated registry still has
    ///   active descendants — those lose authority now.
    ///   Anything else is an unknown session.
    fn destroy_session_identity_sync(
        &self,
        subject: &str,
    ) -> Result<SessionEndReport, KernelError> {
        let now = self.effective_now_sync()?;
        // Idempotent across terminate retries: the vault forgets
        // destroyed subjects, so the kernel remembers the affected list.
        // Entries are (affected_subjects, committed): a retry after a
        // failed durable transition finds the entry uncommitted and
        // reruns the durable work instead of reporting success.
        let affected_subjects: Vec<String> = {
            let mut guard = self.state.lock().expect("kernel state mutex poisoned");
            let KernelMutable {
                vault,
                sessions,
                destroyed,
                ..
            } = &mut *guard;
            match vault.end_session(sessions, subject, now) {
                Ok(receipt) => {
                    destroyed.insert(
                        subject.to_string(),
                        (receipt.affected_subjects.clone(), false),
                    );
                    receipt.affected_subjects
                }
                Err(_) => {
                    if let Some((remembered, committed)) = destroyed.get(subject).cloned() {
                        if committed {
                            // Idempotent retry: the durable destroy+revoke
                            // already applied; nothing left to do.
                            return Ok(SessionEndReport {
                                subject: subject.to_string(),
                                affected_subjects: remembered,
                            });
                        }
                        // A previous attempt failed before the durable
                        // transition committed: rerun it now.
                        remembered
                    } else {
                        // Post-restart: the vault holds no private key, but
                        // the hydrated registry may still have active
                        // descendants whose authority dies with this subject.
                        let descendants = sessions.active_descendants_inclusive(subject, now);
                        if descendants.is_empty() {
                            return Err(KernelError::Unavailable(format!(
                                "unknown session identity {subject}"
                            )));
                        }
                        for descendant in &descendants {
                            sessions.deactivate(descendant);
                        }
                        destroyed.insert(subject.to_string(), (descendants.clone(), false));
                        descendants
                    }
                }
            }
        };
        // The durable counterpart of termination: destroy the session
        // records AND revoke every lease any affected subject could
        // present, in ONE transaction. A restart can never resurrect a
        // destroyed session nor lose the revocations termination
        // requires.
        let mut lease_ids: Vec<String> = Vec::new();
        for affected in &affected_subjects {
            lease_ids.extend(self.db_run(|db, ws| db.kernel_lease_ids_for_subject(ws, affected))?);
        }
        // Delegations orphaned by chain: any live lease whose
        // verification needs a destroyed session's key — i.e. some
        // document in its ancestor chain was signed by an affected
        // subject — can never verify again. Revoke those leases now;
        // otherwise the next boot's re-validation would fail the open
        // on a permanently-unverifiable lease. (Leases held directly by
        // affected subjects are already in `lease_ids` above.)
        let affected_set: HashSet<String> = affected_subjects.iter().cloned().collect();
        let live = self.db_run(|db, ws| db.kernel_live_leases(ws, now))?;
        for doc in &live {
            if lease_ids.iter().any(|id| id == &doc.lease_id) {
                continue;
            }
            let mut current: Option<CoreLeaseDocument> = Some(doc.clone());
            let mut orphaned = false;
            for _ in 0..64 {
                let d = match current.take() {
                    Some(d) => d,
                    None => break,
                };
                if d.parent_id.is_some() && affected_set.contains(&d.issuer_key_id) {
                    orphaned = true;
                    break;
                }
                current = match &d.parent_id {
                    Some(pid) => self.db_run(|db, ws| db.kernel_lease(ws, pid))?,
                    None => None,
                };
            }
            if orphaned {
                lease_ids.push(doc.lease_id.clone());
            }
        }
        lease_ids.sort();
        lease_ids.dedup();
        self.db_run(|db, ws| {
            db.destroy_sessions_and_revoke(
                ws,
                &affected_subjects,
                &lease_ids,
                now,
                "session terminated",
            )
        })?;
        {
            let mut state = self.state.lock().expect("kernel state mutex poisoned");
            // The durable transition committed: a later retry is a true
            // idempotent no-op.
            if let Some(entry) = state.destroyed.get_mut(subject) {
                entry.1 = true;
            }
            for id in &lease_ids {
                state.revocations.revoke(id);
            }
        }
        let _ = self.audit_identity_event(
            "session_ended",
            subject,
            &serde_json::json!({ "affected": affected_subjects }),
            now,
        );
        Ok(SessionEndReport {
            subject: subject.to_string(),
            affected_subjects,
        })
    }

    fn audit_identity_event(
        &self,
        host_kind: &str,
        subject: &str,
        payload: &serde_json::Value,
        now: i64,
    ) -> Result<(), KernelError> {
        let details = serde_json::json!({ "host_kind": host_kind, "payload": payload });
        let detail = lumen_core::kernel_audit::render_detail(&details)
            .map_err(|e| KernelError::Unavailable(format!("audit detail: {e}")))?;
        self.audit_event_sync(
            "kernel",
            AuditEventKind::ActionProposed,
            subject,
            "none",
            None,
            now,
            serde_json::from_str(&detail).unwrap_or(serde_json::Value::Null),
        )?;
        Ok(())
    }

    /// Drain the approval requests the kernel emitted (for the VHL
    /// delivery path and tests).
    fn drain_approval_requests_sync(&self) -> Vec<VhlRequest> {
        std::mem::take(
            &mut self
                .state
                .lock()
                .expect("kernel state mutex poisoned")
                .outbox,
        )
    }

    /// List durable approval requests still awaiting a human decision.
    fn pending_approvals_sync(&self) -> Result<Vec<PendingApprovalView>, KernelError> {
        let rows = self.db_run(|db, ws| db.vhl_list_requests(ws, "requested"))?;
        Ok(rows
            .into_iter()
            .map(|row| PendingApprovalView {
                request_id: row.request_id,
                session_subject: row.session_subject,
                action_digest: row.action_digest,
                created_at_ms: row.created_at_ms,
                expires_at_ms: row.expires_at_ms,
            })
            .collect())
    }

    /// Test/ops inspection: is this subject's identity still live in the
    /// vault?
    fn identity_is_live_sync(&self, subject: &str) -> bool {
        self.state
            .lock()
            .expect("kernel state mutex poisoned")
            .vault
            .is_live(subject)
    }

    /// Verify the durable audit chain and host-key checkpoints. Each
    /// checkpoint is verified against the recorded verifying key for the
    /// key generation that signed it, so a restart (fresh keys) does not
    /// invalidate checkpoints made by retired generations. A checkpoint
    /// referencing an unknown generation fails closed.
    fn verify_kernel_audit_sync(&self) -> Result<(), KernelError> {
        self.db_run(|db, ws| async move {
            let events = db
                .kernel_audit_events(ws, &KernelAuditQuery::default())
                .await?;
            verify_event_chain(&events)
                .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
            let checkpoints = db.kernel_audit_checkpoints(ws).await?;
            let generations = db.kernel_key_generations(ws).await?;
            let killed = db.killed_key_generation_ids(ws).await?;
            let mut host_keys: HashMap<String, VerifyingKey> = HashMap::new();
            for g in &generations {
                if g.role != "host" {
                    continue;
                }
                if killed.contains(&g.key_id) {
                    // Fail closed: a checkpoint signed by a killed host
                    // generation must not verify — otherwise the
                    // compromise-response kill has no effect here.
                    continue;
                }
                let bytes = hex::decode(&g.verifying_key_hex).map_err(|e| {
                    RepositoryError::KernelAuditBreak(format!(
                        "bad recorded host key for generation '{}': {e}",
                        g.key_id
                    ))
                })?;
                let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| {
                    RepositoryError::KernelAuditBreak(format!(
                        "bad recorded host key length for generation '{}'",
                        g.key_id
                    ))
                })?;
                let vk = VerifyingKey::from_bytes(&key_bytes).map_err(|e| {
                    RepositoryError::KernelAuditBreak(format!(
                        "bad recorded host key for generation '{}': {e}",
                        g.key_id
                    ))
                })?;
                host_keys.insert(g.key_id.clone(), vk);
            }
            for link in &checkpoints {
                let anchored = events
                    .iter()
                    .any(|e| e.sequence == link.through_seq && e.hash == link.chain_hash);
                if !anchored {
                    return Err(RepositoryError::KernelAuditBreak(format!(
                        "checkpoint at seq {} is not anchored to the chain",
                        link.through_seq
                    )));
                }
                let vk = host_keys.get(&link.key_id).ok_or_else(|| {
                    RepositoryError::KernelAuditBreak(format!(
                        "checkpoint signed by unknown key generation '{}'",
                        link.key_id
                    ))
                })?;
                link.verify(vk, &link.key_id)
                    .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
            }
            Ok(())
        })
    }
}

/// [`LeaseResolver`] backed by the durable lease table.
///
/// The trait can only return `Option`, so a store failure cannot be
/// propagated through it directly. Instead the resolver records the
/// failure in `store_error`, and the caller converts any decision made
/// with an incomplete view into a fail-closed fault: a kernel-store
/// outage must surface as kernel-unavailable, never as a policy deny
/// (which would misreport the outage) or an allow.
struct DbLeaseResolver<'a> {
    kernel: &'a AuthorityKernel,
    store_error: Cell<Option<String>>,
}

impl DbLeaseResolver<'_> {
    /// The first store failure seen during resolution, if any.
    fn take_store_error(&self) -> Option<String> {
        self.store_error.take()
    }
}

impl LeaseResolver for DbLeaseResolver<'_> {
    fn lease(&self, id: &str) -> Option<CoreLeaseDocument> {
        match self.kernel.db_run(|db, ws| db.kernel_lease(ws, id)) {
            Ok(doc) => doc,
            Err(e) => {
                // Keep the FIRST error: it is the root cause; later
                // lookups would just repeat the outage.
                let prev = self.store_error.take();
                if prev.is_none() {
                    self.store_error.set(Some(e.to_string()));
                } else {
                    self.store_error.set(prev);
                }
                None
            }
        }
    }
}

/// [`OneShotTracker`] that consumes against the durable
/// `kernel_one_shot_uses` table (plus a memory hot cache). A consumed
/// lease stays consumed across restarts; a store failure fails closed
/// (recorded in `store_error` for the caller to convert into a fault —
/// the trait's `bool` return cannot distinguish "already consumed" from
/// "store unavailable").
struct DbOneShotTracker<'a> {
    kernel: &'a AuthorityKernel,
    mem: &'a mut HashSet<String>,
    now_ms: i64,
    store_error: Option<String>,
}

impl DbOneShotTracker<'_> {
    fn take_store_error(&mut self) -> Option<String> {
        self.store_error.take()
    }
}

impl OneShotTracker for DbOneShotTracker<'_> {
    fn consume(&mut self, lease_id: &str) -> bool {
        if !self.mem.insert(lease_id.to_string()) {
            return false;
        }
        let now = self.now_ms;
        match self
            .kernel
            .db_run(|db, ws| db.consume_kernel_one_shot(ws, lease_id, now))
        {
            Ok(true) => true,
            Ok(false) => {
                // Cross-restart replay: the durable row is already
                // present, so this lease is genuinely consumed.
                self.mem.remove(lease_id);
                false
            }
            Err(e) => {
                // Store failure: roll back the memory insert and record
                // the outage. Returning false denies this use (fail-closed
                // for the action); the caller converts the recorded error
                // into a kernel-unavailable fault.
                self.mem.remove(lease_id);
                if self.store_error.is_none() {
                    self.store_error = Some(e.to_string());
                }
                false
            }
        }
    }

    fn is_consumed(&self, lease_id: &str) -> bool {
        self.mem.contains(lease_id)
    }
}

/// Map a host audit kind onto the frozen closed enum. The original kind
/// is preserved verbatim at the front of `detail`.
fn map_host_audit_kind(kind: &str) -> AuditEventKind {
    match kind {
        "tool_committed" => AuditEventKind::ToolExecuted,
        "approval_requested" => AuditEventKind::ApprovalRequested,
        "policy_allowed" => AuditEventKind::PolicyAllowed,
        "policy_denied" => AuditEventKind::PolicyDenied,
        _ => AuditEventKind::ActionProposed,
    }
}

/// Kernel `LeaseDocument` -> host `LeaseDocument`. The typed scope is
/// rendered back to opaque JSON; the host never re-invents the grammar.
fn to_host_lease(doc: &CoreLeaseDocument) -> LeaseDocument {
    LeaseDocument {
        protocol_version: doc.protocol_version,
        lease_id: doc.lease_id.clone(),
        parent_id: doc.parent_id.clone(),
        subject: doc.subject.clone(),
        issuer_key_id: doc.issuer_key_id.clone(),
        issued_at_ms: doc.issued_at_ms,
        scope: serde_json::to_value(&doc.scope).unwrap_or(serde_json::Value::Null),
        limits: LeaseLimits {
            not_before_ms: doc.limits.not_before_ms,
            expires_at_ms: doc.limits.expires_at_ms,
            budget: serde_json::to_value(&doc.limits.budget).unwrap_or(serde_json::Value::Null),
            max_executions: doc.limits.max_executions,
            single_use: doc.limits.single_use,
        },
        depth: doc.depth,
        depth_limit: doc.depth_limit,
        lease_nonce: doc.lease_nonce.clone(),
        signature: doc.signature.clone(),
    }
}

/// Host `LeaseDocument` -> kernel `LeaseDocument`. The opaque scope and
/// budget JSON are parsed into the kernel's typed grammar; anything that
/// does not parse is an error (fail closed). This is the inverse of
/// [`to_host_lease`]; the two mappings must stay field-identical so a
/// document that round-trips compares equal to the durable record.
fn to_core_lease(lease: &LeaseDocument) -> Result<CoreLeaseDocument, String> {
    let scope: ResourceScope = serde_json::from_value(lease.scope.clone())
        .map_err(|e| format!("unparseable scope: {e}"))?;
    let budget: Budget = serde_json::from_value(lease.limits.budget.clone())
        .map_err(|e| format!("unparseable budget: {e}"))?;
    Ok(CoreLeaseDocument {
        protocol_version: lease.protocol_version,
        lease_id: lease.lease_id.clone(),
        parent_id: lease.parent_id.clone(),
        subject: lease.subject.clone(),
        issuer_key_id: lease.issuer_key_id.clone(),
        issued_at_ms: lease.issued_at_ms,
        scope,
        limits: CoreLeaseLimits {
            not_before_ms: lease.limits.not_before_ms,
            expires_at_ms: lease.limits.expires_at_ms,
            budget,
            max_executions: lease.limits.max_executions,
            single_use: lease.limits.single_use,
        },
        depth: lease.depth,
        depth_limit: lease.depth_limit,
        lease_nonce: lease.lease_nonce.clone(),
        signature: lease.signature.clone(),
        // The host lease document predates the approved-action digest;
        // it is not present to convert.
        approved_action_digest: None,
    })
}

/// Host `OneShotGrant` -> kernel `OneShotGrant` (field-for-field).
/// Convert the host one-shot grant into the core grant minted by
/// [`mint_one_shot_lease`]. The two types are field-identical by
/// construction (the host type mirrors the kernel type); the conversion
/// is infallible field mapping.
fn to_core_grant(grant: &OneShotGrant) -> CoreOneShotGrant {
    CoreOneShotGrant {
        approval_id: grant.approval_id.clone(),
        action_digest: grant.action_digest.clone(),
        session_subject: grant.session_subject.clone(),
        signer_key_id: grant.signer_key_id.clone(),
        nonce: grant.nonce.clone(),
        created_at_ms: grant.created_at_ms,
        expires_at_ms: grant.expires_at_ms,
        signature: grant.signature.clone(),
    }
}

/// Run a closure on the blocking pool and convert a join failure into a
/// kernel error.
async fn blocking<F, T>(f: F) -> Result<T, KernelError>
where
    F: FnOnce() -> Result<T, KernelError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| KernelError::Unavailable(format!("kernel worker failed: {e}")))?
}

/// The public client: `Arc`-shared, `Send + Sync`, object-safe.
#[derive(Clone)]
pub struct AuthorityKernelClient {
    kernel: Arc<AuthorityKernel>,
}

impl AuthorityKernelClient {
    /// Open the kernel: connect the database (running migrations),
    /// ensure the workspace row, generate fresh kernel keys, and hydrate
    /// the in-memory caches (revocations, budget ledger) from durable
    /// state.
    pub async fn open(config: AuthorityKernelConfig) -> Result<Self, KernelError> {
        let db = match &config.db {
            AuthorityDb::Path(path) => Database::connect(path)
                .await
                .map_err(|e| KernelError::Unavailable(format!("kernel database: {e}")))?,
            AuthorityDb::Memory => Database::connect_in_memory()
                .await
                .map_err(|e| KernelError::Unavailable(format!("kernel database: {e}")))?,
        };
        // The workspace row is created inside `boot_sequence_sync`, after
        // the clock rollback check — a refused open writes nothing.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("lumen-kernel")
            .enable_all()
            .build()
            .map_err(|e| KernelError::Unavailable(format!("kernel runtime: {e}")))?;

        // Hydrate the hot caches from durable state. `open` is async, so
        // these await directly on the caller's runtime; the private
        // runtime below is only for the synchronous `*_sync` methods,
        // which run on blocking workers and must never touch an async
        // context.
        let revoked: HashSet<String> = db
            .kernel_revoked_ids(&config.workspace)
            .await
            .map_err(|e| KernelError::Unavailable(format!("kernel revocation hydration: {e}")))?;

        let mut revocations = RevocationIndex::new();
        for id in revoked {
            revocations.revoke(&id);
        }
        // Restore the full budget account state (caps, held reservations,
        // consumed spend) from durable storage. Leases that predate the
        // budget-accounts table fall back to their declared caps at zero
        // consumption. A corrupt account fails the open rather than
        // hydrating an impossible ledger that would over-authorize.
        let declared = db
            .kernel_lease_budgets(&config.workspace)
            .await
            .map_err(|e| KernelError::Unavailable(format!("kernel budget hydration: {e}")))?;
        let accounts = db
            .kernel_budget_account_states(&config.workspace)
            .await
            .map_err(|e| KernelError::Unavailable(format!("kernel budget hydration: {e}")))?;
        let account_state: HashMap<String, (Budget, Budget, Budget)> = accounts
            .into_iter()
            .map(|(id, caps, reserved, consumed)| (id, (caps, reserved, consumed)))
            .collect();
        let ledger = BudgetLedger::new();
        for (lease_id, caps) in declared {
            if let Some((caps, reserved, consumed)) = account_state.get(&lease_id) {
                ledger.restore_account(&lease_id, caps, reserved, consumed)
            } else {
                ledger.register_lease(&lease_id, &caps)
            }
            .map_err(|e| KernelError::Unavailable(format!("kernel budget restore: {e}")))?;
        }

        // Fresh key generation for this boot. The generation is recorded
        // durably (verifying keys only) inside `boot_sequence_sync` below,
        // so signatures made by this generation — audit checkpoints and
        // lease documents — remain verifiable after the next restart
        // retires these keys. The private keys are never persisted; they
        // are zeroized on drop.
        let keys = KernelKeys::generate();

        let kernel = AuthorityKernel {
            fs: RealFsResolver,
            nonces: NonceStore::new(),
            ledger,
            state: Mutex::new(KernelMutable {
                keys,
                generations: GenerationIndex::default(),
                sessions: SessionRegistry::new(),
                vault: SessionIdentityVault::new(),
                revocations,
                one_shot_mem: HashSet::new(),
                pending: HashMap::new(),
                outbox: Vec::new(),
                destroyed: HashMap::new(),
                // The boot sequence sets the real mark after the
                // rollback check; zero until then.
                time_high_water_ms: 0,
                time_high_water_persisted_ms: 0,
            }),
            db,
            rt: Some(rt),
            config,
        };
        let kernel = Arc::new(kernel);
        // The boot tail runs synchronously on a blocking worker (it does
        // database IO through the kernel's private runtime): generation
        // hydration, session TTL expiry, session hydration, audit, the
        // re-validation self-check, and the purge pass.
        let boot = Arc::clone(&kernel);
        blocking(move || boot.boot_sequence_sync()).await?;
        Ok(Self { kernel })
    }

    /// Mint a root lease for a live session subject (test/operator
    /// helper; standing issuance policy belongs to the coordinator).
    pub async fn issue_root_lease(
        &self,
        params: RootLeaseParams,
    ) -> Result<LeaseDocument, KernelError> {
        let kernel = Arc::clone(&self.kernel);
        blocking(move || kernel.issue_root_lease_sync(params)).await
    }

    /// Drain the approval requests the kernel emitted since the last
    /// drain (VHL delivery path / tests).
    pub async fn drain_approval_requests(&self) -> Vec<VhlRequest> {
        let kernel = Arc::clone(&self.kernel);
        // Infallible; unwrap is safe.
        blocking(move || Ok(kernel.drain_approval_requests_sync()))
            .await
            .unwrap_or_default()
    }

    /// Durable approval request view, for the host/VHL poller.
    pub async fn pending_approvals(&self) -> Result<Vec<PendingApprovalView>, KernelError> {
        let kernel = Arc::clone(&self.kernel);
        blocking(move || kernel.pending_approvals_sync()).await
    }

    /// Test/ops inspection: is this subject's identity live in the vault?
    pub async fn identity_is_live(&self, subject: &str) -> bool {
        let kernel = Arc::clone(&self.kernel);
        let subject = subject.to_string();
        blocking(move || Ok(kernel.identity_is_live_sync(&subject)))
            .await
            .unwrap_or(false)
    }

    /// Verify the durable kernel audit chain and its host-key
    /// checkpoints: every decision the kernel made must be present and
    /// anchored.
    pub async fn verify_kernel_audit(&self) -> Result<(), KernelError> {
        let kernel = Arc::clone(&self.kernel);
        blocking(move || kernel.verify_kernel_audit_sync()).await
    }

    /// Remaining budget for a lease from the kernel's ledger.
    pub async fn budget_remaining(&self, lease_id: &str) -> Result<Budget, KernelError> {
        let kernel = Arc::clone(&self.kernel);
        let lease_id = lease_id.to_string();
        blocking(move || {
            kernel
                .ledger
                .remaining(&lease_id)
                .map_err(|e| KernelError::Unavailable(format!("budget state: {e}")))
        })
        .await
    }

    /// Record the human's decision on a pending approval request
    /// (`requested → approved` or `requested → denied`). The human
    /// reviews the [`PendingApprovalView`]; only an `approved` request
    /// can later mint a one-shot lease via
    /// [`KernelClient::request_one_shot_lease`]. The state guard makes
    /// the decision idempotent-safe: deciding an already-decided request
    /// fails rather than overwriting history.
    pub async fn decide_approval(
        &self,
        approval_id: &str,
        approved: bool,
        decided_by: &str,
    ) -> Result<(), KernelError> {
        let kernel = Arc::clone(&self.kernel);
        let approval_id = approval_id.to_string();
        let decided_by = decided_by.to_string();
        blocking(move || {
            // Authority time: the decision timestamp is a kernel-written
            // record and must stay monotonic with the audit chain.
            let now = kernel.effective_now_sync()?;
            let new_state = if approved { "approved" } else { "denied" };
            kernel
                .db_run(|db, ws| {
                    db.vhl_transition(
                        ws,
                        &approval_id,
                        "requested",
                        new_state,
                        Some(now),
                        Some(&decided_by),
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                })
                .map_err(|e| KernelError::Unavailable(format!("approval decision failed: {e}")))
        })
        .await
    }

    /// Emergency rotation (control-plane, operator-gated): mint a
    /// mid-boot issuer/host generation, record both, zeroize the
    /// superseded private keys by drop. Outstanding leases keep verifying
    /// via the retired generation's recorded verifying key.
    pub async fn rotate_issuer_keys(
        &self,
        reason: &str,
        actor: &PrincipalId,
    ) -> Result<KeyRotationReport, KernelError> {
        self.kernel
            .authorize_operator(actor, OperatorOperation::KeyManagement)
            .await?;
        let kernel = Arc::clone(&self.kernel);
        let reason = reason.to_string();
        blocking(move || kernel.rotate_issuer_keys_sync(&reason)).await
    }

    /// Kill a key generation (compromise response, operator-gated):
    /// verification fails closed for it immediately, even though its
    /// verifying key stays recorded. The current generation cannot be
    /// killed — rotate first. Returns true when the kill was recorded.
    pub async fn kill_key_generation(
        &self,
        key_id: &str,
        role: &str,
        reason: &str,
        actor: &PrincipalId,
    ) -> Result<bool, KernelError> {
        self.kernel
            .authorize_operator(actor, OperatorOperation::KeyManagement)
            .await?;
        let kernel = Arc::clone(&self.kernel);
        let key_id = key_id.to_string();
        let role = role.to_string();
        let reason = reason.to_string();
        let killed_by = format!("{}:{}", actor.provider(), actor.subject());
        blocking(move || kernel.kill_key_generation_sync(&key_id, &role, &reason, &killed_by)).await
    }

    /// Purge retired generations eligible under the retention rules
    /// (operator-gated): the same pass the boot tail runs — unreferenced
    /// retired generations are deleted, generations with live lease refs
    /// are retained.
    pub async fn purge_key_generations(
        &self,
        actor: &PrincipalId,
    ) -> Result<KeyPurgeReport, KernelError> {
        self.kernel
            .authorize_operator(actor, OperatorOperation::KeyManagement)
            .await?;
        let kernel = Arc::clone(&self.kernel);
        blocking(move || {
            let now = kernel.effective_now_sync()?;
            kernel.purge_pass_sync(now)
        })
        .await
    }
}

impl KernelClient for AuthorityKernelClient {
    fn decide<'a>(&'a self, envelope: &'a ActionEnvelope) -> KernelFuture<'a, PolicyDecision> {
        let kernel = Arc::clone(&self.kernel);
        let envelope = envelope.clone();
        Box::pin(async move { blocking(move || kernel.decide_sync(&envelope)).await })
    }

    fn verify_lease<'a>(&'a self, lease: &'a LeaseDocument) -> KernelFuture<'a, LeaseVerification> {
        let kernel = Arc::clone(&self.kernel);
        let lease = lease.clone();
        Box::pin(async move { blocking(move || kernel.verify_lease_sync(&lease)).await })
    }

    fn request_one_shot_lease<'a>(
        &'a self,
        grant: &'a OneShotGrant,
    ) -> KernelFuture<'a, LeaseDocument> {
        let kernel = Arc::clone(&self.kernel);
        let grant = grant.clone();
        Box::pin(async move { blocking(move || kernel.request_one_shot_lease_sync(&grant)).await })
    }

    fn revoke_session<'a>(&'a self, session_subject: &'a str) -> KernelFuture<'a, ()> {
        let kernel = Arc::clone(&self.kernel);
        let subject = session_subject.to_string();
        Box::pin(async move { blocking(move || kernel.revoke_session_sync(&subject)).await })
    }

    fn append_audit<'a>(&'a self, event: &'a AuditEvent) -> KernelFuture<'a, AuditRef> {
        let kernel = Arc::clone(&self.kernel);
        let event = event.clone();
        Box::pin(async move { blocking(move || kernel.append_audit_sync(&event)).await })
    }
}

impl SessionIdentityAuthority for AuthorityKernelClient {
    fn start_session_identity<'a>(
        &'a self,
        parent: Option<&'a str>,
    ) -> KernelFuture<'a, SessionIdentityInfo> {
        let kernel = Arc::clone(&self.kernel);
        let parent = parent.map(str::to_string);
        Box::pin(async move {
            blocking(move || kernel.start_session_identity_sync(parent.as_deref())).await
        })
    }

    fn destroy_session_identity<'a>(
        &'a self,
        subject: &'a str,
    ) -> KernelFuture<'a, SessionEndReport> {
        let kernel = Arc::clone(&self.kernel);
        let subject = subject.to_string();
        Box::pin(
            async move { blocking(move || kernel.destroy_session_identity_sync(&subject)).await },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The write-ahead invariant: the persisted anchor is always >= the
    /// decision time, a multiple of the interval, and less than one
    /// full interval ahead (so the boot rollback check is unaffected).
    #[test]
    fn anchor_ceiling_never_lags() {
        for t in [
            0,
            1,
            29_999,
            30_000,
            30_001,
            1_700_000_000_000,
            i64::MAX / 2,
        ] {
            let c = anchor_ceiling(t);
            assert!(c >= t, "ceiling {c} lags t={t}");
            assert_eq!(c % TIME_ANCHOR_PERSIST_INTERVAL_MS, 0);
            assert!(
                c - t < TIME_ANCHOR_PERSIST_INTERVAL_MS,
                "ceiling {c} too far ahead of {t}"
            );
        }
        // Exact boundaries are fixed points.
        assert_eq!(anchor_ceiling(60_000), 60_000);
        assert_eq!(anchor_ceiling(60_001), 90_000);
    }
}
