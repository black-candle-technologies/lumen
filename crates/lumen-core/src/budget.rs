//! Budgets and usage (Phase 1C): reservation-based budget narrowing.
//!
//! Checking `child.budget < parent.budget` is insufficient: a parent could
//! issue many individually valid children whose combined budgets exceed its
//! authority. Instead, at issuance the kernel **reserves** the child's maximum
//! budget against the parent's remaining balance. Consumption debits the
//! reservation; unused capacity returns only on explicit revocation or expiry.
//!
//! The ledger is atomic: every mutation holds one mutex, so concurrent
//! issuance and debit from many threads cannot overspend a parent cap.
//! Debits are idempotent on caller-supplied keys, so retries and crashes
//! never double-charge.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// Budget dimensions tracked by the kernel. All values are integers —
/// monetary spend is micro-dollars (µ$) so no floating point ever crosses
/// the trust boundary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetDimension {
    /// Micro-dollars of provider/model spend.
    SpendMicros,
    /// Model tokens (input + output).
    Tokens,
    /// Action executions.
    Executions,
    /// Wall-clock milliseconds.
    WallTimeMs,
    /// CPU milliseconds.
    CpuMs,
    /// Ingress bytes.
    BytesIn,
    /// Egress bytes.
    BytesOut,
    /// Concurrent in-flight actions.
    Concurrency,
}

impl BudgetDimension {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpendMicros => "spend_micros",
            Self::Tokens => "tokens",
            Self::Executions => "executions",
            Self::WallTimeMs => "wall_time_ms",
            Self::CpuMs => "cpu_ms",
            Self::BytesIn => "bytes_in",
            Self::BytesOut => "bytes_out",
            Self::Concurrency => "concurrency",
        }
    }

    pub const ALL: [Self; 8] = [
        Self::SpendMicros,
        Self::Tokens,
        Self::Executions,
        Self::WallTimeMs,
        Self::CpuMs,
        Self::BytesIn,
        Self::BytesOut,
        Self::Concurrency,
    ];
}

/// A per-dimension budget: missing dimensions are zero (no grant).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Budget(BTreeMap<BudgetDimension, u64>);

impl Budget {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, dim: BudgetDimension, amount: u64) -> Self {
        if amount > 0 {
            self.0.insert(dim, amount);
        }
        self
    }

    pub fn get(&self, dim: BudgetDimension) -> u64 {
        self.0.get(&dim).copied().unwrap_or(0)
    }

    pub fn is_zero(&self) -> bool {
        self.0.values().all(|v| *v == 0)
    }

    /// `self` covers `other` iff every dimension of `other` fits in `self`.
    pub fn covers(&self, other: &Budget) -> bool {
        other.0.iter().all(|(d, v)| self.get(*d) >= *v)
    }

    pub fn checked_add(&self, other: &Budget) -> Option<Budget> {
        let mut out = self.0.clone();
        for (d, v) in &other.0 {
            let sum = out.get(d).copied().unwrap_or(0).checked_add(*v)?;
            out.insert(*d, sum);
        }
        Some(Budget(out))
    }

    pub fn saturating_sub(&self, other: &Budget) -> Budget {
        let mut out = self.0.clone();
        for (d, v) in &other.0 {
            let cur = out.get(d).copied().unwrap_or(0);
            if cur <= *v {
                out.remove(d);
            } else {
                out.insert(*d, cur - v);
            }
        }
        Budget(out)
    }

    pub fn iter(&self) -> impl Iterator<Item = (BudgetDimension, u64)> + '_ {
        self.0.iter().map(|(d, v)| (*d, *v))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BudgetError {
    #[error(
        "insufficient budget on {lease}: dimension {dimension} needs {needed}, {remaining} remaining"
    )]
    Insufficient {
        lease: String,
        dimension: &'static str,
        needed: u64,
        remaining: u64,
    },
    #[error("unknown lease in ledger: {0}")]
    UnknownLease(String),
    #[error("lease {0} is already registered in the ledger")]
    DuplicateLease(String),
    #[error("unknown reservation: {0}")]
    UnknownReservation(String),
    #[error("reservation {0} is not active")]
    ReservationNotActive(String),
    #[error("execution reservation {0} is not held")]
    ExecutionNotHeld(String),
    #[error("debit of {0:?} exceeds reservation {1}: {2}")]
    DebitExceedsHeld(Budget, String, String),
    #[error("idempotency key {0} was already used with a different debit")]
    IdempotencyConflict(String),
    #[error("budget overflow")]
    Overflow,
    #[error("store error: {0}")]
    Store(String),
    #[error("cannot roll back lease {0}: {1}")]
    RollbackFailed(String, String),
}

/// A held reservation of a child's maximum budget against its parent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    pub id: String,
    pub child_lease_id: String,
    pub parent_lease_id: String,
    /// The child's maximum budget, held against the parent at issuance.
    pub held: Budget,
    /// Actual consumption debited so far (≤ held per dimension).
    pub consumed: Budget,
    pub state: ReservationState,
    pub created_at_ms: i64,
    pub released_at_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationState {
    Active,
    Released,
}

/// Lifecycle of an execution reservation: held at authorize time, then
/// exactly one of settled (the action dispatched) or released (dispatch
/// never happened, or failed before any effect).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Held,
    Settled,
    Released,
}

/// A held execution against a lease's own budget caps: the atomic
/// reserve-before-dispatch half of the execution lifecycle.
///
/// Authorizing an action atomically reserves the estimated maximum (`held`,
/// one execution at authorize time) against the leaf lease's remaining
/// balance. The dispatcher settles the reservation after dispatch —
/// converting the hold into measured consumption — or releases it when
/// dispatch never happened or failed before any effect. Crash recovery
/// reconciles held reservations at boot against the durable action log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReservation {
    /// `exec_<uuid>`.
    pub id: String,
    /// The leaf lease charged for this execution.
    pub lease_id: String,
    /// The envelope's action id: correlates the hold with the durable
    /// action log during crash recovery.
    pub action_id: String,
    /// Estimated maximum held at authorize time (one execution).
    pub held: Budget,
    pub state: ExecutionState,
    /// The envelope nonce: authorizing the same envelope twice returns the
    /// existing reservation instead of double-holding.
    pub idempotency_key: String,
    pub created_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    /// Measured consumption, recorded at settle time (durable receipt).
    pub actual: Option<Budget>,
}

/// Receipt for one debit, stored under the idempotency key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebitReceipt {
    pub reservation_id: String,
    pub actual: Budget,
    pub debited_at_ms: i64,
}

struct LeaseAccount {
    caps: Budget,
    /// Sum of held budgets of active child reservations.
    reserved_out: Budget,
    /// Executions held by authorized-but-unsettled actions.
    exec_held: Budget,
    /// Consumption debited directly against this lease (root spend).
    consumed: Budget,
}

impl LeaseAccount {
    fn remaining(&self) -> Option<Budget> {
        let held_total = self.reserved_out.checked_add(&self.exec_held)?;
        let reserved_total = held_total.checked_add(&self.consumed)?;
        Some(self.caps.saturating_sub(&reserved_total))
    }
}

struct LedgerInner {
    accounts: HashMap<String, LeaseAccount>,
    reservations: HashMap<String, Reservation>,
    debit_keys: HashMap<String, DebitReceipt>,
    executions: HashMap<String, ExecutionReservation>,
    /// Envelope nonce -> execution reservation id (authorize idempotency).
    exec_reserve_keys: HashMap<String, String>,
    /// Settle idempotency key -> receipt.
    exec_settle_keys: HashMap<String, DebitReceipt>,
}

/// The atomic budget ledger. All mutations hold a single mutex, so the
/// fan-out invariant — Σ active child reservations + consumption ≤ parent cap,
/// per dimension — holds under arbitrary concurrency.
pub struct BudgetLedger {
    inner: Mutex<LedgerInner>,
}

impl BudgetLedger {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(LedgerInner {
                accounts: HashMap::new(),
                reservations: HashMap::new(),
                debit_keys: HashMap::new(),
                executions: HashMap::new(),
                exec_reserve_keys: HashMap::new(),
                exec_settle_keys: HashMap::new(),
            }),
        }
    }

    /// Register a lease's budget caps. Called for root leases at issuance
    /// (caps are policy-granted) and for child leases after their reservation
    /// succeeds (the child's own caps are its held maximum).
    ///
    /// Rejects duplicate ids: silently replacing an account would reset its
    /// `reserved_out`/`exec_held`/`consumed` books to zero and resurrect
    /// spent budget (e.g. a child minted with its parent's id). Defense in
    /// depth with [`BudgetLedger::reserve`], which already rejects an
    /// already-registered child id before taking the hold; this guard
    /// covers direct callers that skip `reserve`.
    pub fn register_lease(&self, lease_id: &str, caps: &Budget) -> Result<(), BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        if inner.accounts.contains_key(lease_id) {
            return Err(BudgetError::DuplicateLease(lease_id.to_string()));
        }
        inner.accounts.insert(
            lease_id.to_string(),
            LeaseAccount {
                caps: caps.clone(),
                reserved_out: Budget::new(),
                exec_held: Budget::new(),
                consumed: Budget::new(),
            },
        );
        Ok(())
    }

    /// Whether the ledger already holds an account for `lease_id`. Used by
    /// boot reconciliation (register-if-absent) and exposed for callers
    /// that need to probe before acting; [`BudgetLedger::reserve`] and
    /// [`BudgetLedger::register_lease`] enforce uniqueness themselves.
    pub fn is_lease_registered(&self, lease_id: &str) -> bool {
        self.inner
            .lock()
            .expect("ledger mutex poisoned")
            .accounts
            .contains_key(lease_id)
    }

    /// Undo a lease mint's ledger effects after the mint's durable step
    /// failed: remove the failed issuance's reservation (standing-lease
    /// mints reserve the child's maximum against the parent) and the
    /// lease's own budget account, restoring the parent's held balance.
    ///
    /// The rollback is atomic: every check and mutation holds the single
    /// ledger lock, so it either fully undoes the mint or fails closed
    /// with the ledger untouched.
    ///
    /// Fails closed when the ledger does not look like a fresh, unused
    /// mint: the child account is missing (the mint always registers it),
    /// the child account shows any consumption, the child has reserved-out
    /// budget or an active reservation naming it as parent (descendants
    /// were granted — the lease escaped the failed mint), a reservation
    /// naming this child exists but is not active, is consumed, or appears
    /// more than once, or the parent account is missing / its held balance
    /// would underflow.
    ///
    /// Rollback-only: called on the mint's error path, before the grant
    /// nonce is forgotten, so a failed audit can never strand held parent
    /// budget or a phantom account — and a failed rollback never forgets
    /// the nonce for ledger state that is still in place.
    pub fn rollback_lease_registration(&self, lease_id: &str) -> Result<(), BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        let fail =
            |reason: &str| BudgetError::RollbackFailed(lease_id.to_string(), reason.to_string());

        // Phase 1: checks. The mint always registers the child's account,
        // so a missing account is inconsistent, not "already rolled back".
        let account = inner
            .accounts
            .get(lease_id)
            .ok_or_else(|| fail("child account missing"))?;
        if !account.consumed.is_zero() {
            return Err(fail("child account shows consumption"));
        }
        if !account.reserved_out.is_zero() {
            return Err(fail("child account has reserved descendants"));
        }
        if inner
            .reservations
            .values()
            .any(|r| r.parent_lease_id == lease_id && r.state == ReservationState::Active)
        {
            return Err(fail("child lease has active descendant reservations"));
        }
        // The mint creates exactly one reservation for a standing child and
        // none for a one-shot; more than one is inconsistent.
        let matching: Vec<(String, Budget, Budget, ReservationState, String)> = inner
            .reservations
            .iter()
            .filter(|(_, r)| r.child_lease_id == lease_id)
            .map(|(id, r)| {
                (
                    id.clone(),
                    r.held.clone(),
                    r.consumed.clone(),
                    r.state,
                    r.parent_lease_id.clone(),
                )
            })
            .collect();
        if matching.len() > 1 {
            return Err(fail("multiple reservations name this child"));
        }
        // If a reservation exists, validate it — and the parent restore it
        // implies — before mutating anything.
        let restore: Option<(String, String, Budget)> = match matching.first() {
            None => None,
            Some((res_id, held, consumed, state, parent_id)) => {
                if *state != ReservationState::Active {
                    return Err(fail("issuance reservation is not active"));
                }
                if !consumed.is_zero() {
                    return Err(fail("issuance reservation shows consumption"));
                }
                let parent = inner
                    .accounts
                    .get(parent_id)
                    .ok_or_else(|| fail("parent account missing"))?;
                let restored = parent
                    .reserved_out
                    .checked_sub(held)
                    .ok_or_else(|| fail("parent held balance would underflow"))?;
                Some((res_id.clone(), parent_id.clone(), restored))
            }
        };

        // Phase 2: mutations. All checks passed; nothing below can fail.
        if let Some((res_id, parent_id, restored)) = restore {
            // Remove the failed issuance reservation entirely — no Released
            // phantom is retained.
            inner.reservations.remove(&res_id);
            if let Some(parent) = inner.accounts.get_mut(&parent_id) {
                parent.reserved_out = restored;
            }
        }
        inner.accounts.remove(lease_id);
        Ok(())
    }

    /// Reserve `child_max` against the parent's remaining balance. Fails
    /// atomically (no partial reservation) when any dimension is short.
    ///
    /// Also fails — before taking any hold — when `child_lease_id` is
    /// already registered: re-reserving for a live account would strand a
    /// second reservation against one account (a duplicate mint must never
    /// leak a hold; the lease layer relies on this ordering).
    pub fn reserve(
        &self,
        parent_lease_id: &str,
        child_lease_id: &str,
        child_max: &Budget,
        now_ms: i64,
    ) -> Result<Reservation, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        // Check before mutating: a failed mint must not leave a hold behind.
        if inner.accounts.contains_key(child_lease_id) {
            return Err(BudgetError::DuplicateLease(child_lease_id.to_string()));
        }
        let parent = inner
            .accounts
            .get_mut(parent_lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(parent_lease_id.to_string()))?;
        let remaining = parent.remaining().ok_or(BudgetError::Overflow)?;
        for (dim, need) in child_max.iter() {
            let have = remaining.get(dim);
            if have < need {
                return Err(BudgetError::Insufficient {
                    lease: parent_lease_id.to_string(),
                    dimension: dim.as_str(),
                    needed: need,
                    remaining: have,
                });
            }
        }
        parent.reserved_out = parent
            .reserved_out
            .checked_add(child_max)
            .ok_or(BudgetError::Overflow)?;
        let reservation = Reservation {
            id: format!("res_{}", Uuid::new_v4()),
            child_lease_id: child_lease_id.to_string(),
            parent_lease_id: parent_lease_id.to_string(),
            held: child_max.clone(),
            consumed: Budget::new(),
            state: ReservationState::Active,
            created_at_ms: now_ms,
            released_at_ms: None,
        };
        inner
            .reservations
            .insert(reservation.id.clone(), reservation.clone());
        Ok(reservation)
    }

    /// Debit actual usage against a reservation. Idempotent on
    /// `idempotency_key`: repeating the same key returns the stored receipt
    /// without double-charging; reusing a key with a *different* debit fails
    /// closed.
    pub fn debit(
        &self,
        reservation_id: &str,
        actual: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<DebitReceipt, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        if let Some(receipt) = inner.debit_keys.get(idempotency_key) {
            if receipt.actual == *actual && receipt.reservation_id == reservation_id {
                return Ok(receipt.clone());
            }
            return Err(BudgetError::IdempotencyConflict(
                idempotency_key.to_string(),
            ));
        }
        let reservation = inner
            .reservations
            .get_mut(reservation_id)
            .ok_or_else(|| BudgetError::UnknownReservation(reservation_id.to_string()))?;
        if reservation.state != ReservationState::Active {
            return Err(BudgetError::ReservationNotActive(
                reservation_id.to_string(),
            ));
        }
        let available = reservation.held.saturating_sub(&reservation.consumed);
        if !available.covers(actual) {
            return Err(BudgetError::DebitExceedsHeld(
                actual.clone(),
                reservation_id.to_string(),
                format!("{available:?} available"),
            ));
        }
        reservation.consumed = reservation
            .consumed
            .checked_add(actual)
            .ok_or(BudgetError::Overflow)?;
        let receipt = DebitReceipt {
            reservation_id: reservation_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        };
        inner
            .debit_keys
            .insert(idempotency_key.to_string(), receipt.clone());
        Ok(receipt)
    }

    /// Debit spend directly against a lease's own caps (root-lease spend, not
    /// mediated by a child reservation).
    pub fn debit_lease(
        &self,
        lease_id: &str,
        actual: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<DebitReceipt, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        if let Some(receipt) = inner.debit_keys.get(idempotency_key) {
            if receipt.actual == *actual && receipt.reservation_id == lease_id {
                return Ok(receipt.clone());
            }
            return Err(BudgetError::IdempotencyConflict(
                idempotency_key.to_string(),
            ));
        }
        let account = inner
            .accounts
            .get_mut(lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(lease_id.to_string()))?;
        let remaining = account.remaining().ok_or(BudgetError::Overflow)?;
        if !remaining.covers(actual) {
            return Err(BudgetError::Insufficient {
                lease: lease_id.to_string(),
                dimension: "multiple",
                needed: 0,
                remaining: 0,
            });
        }
        account.consumed = account
            .consumed
            .checked_add(actual)
            .ok_or(BudgetError::Overflow)?;
        let receipt = DebitReceipt {
            reservation_id: lease_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        };
        inner
            .debit_keys
            .insert(idempotency_key.to_string(), receipt.clone());
        Ok(receipt)
    }

    /// Release a reservation: the unspent held amount returns to the parent.
    /// Only called on explicit revocation or expiry — never implicitly.
    ///
    /// Conservation: the child's total spend moves into the parent's
    /// `consumed`, and the full hold leaves the parent's `reserved_out`.
    /// Child spend is the debits recorded on the reservation *plus* the
    /// child account's settled consumption and outstanding execution holds
    /// (child spend via [`BudgetLedger::settle_execution`] /
    /// [`BudgetLedger::debit_lease`] never touches the reservation's
    /// `consumed` field, so ignoring the child account would refund spent
    /// budget). Outstanding holds count as spent: they are authorized
    /// dispatches whose effects may still land, so this errs toward the
    /// parent keeping less — spent budget is never resurrected.
    /// Returns `held − spent` (saturating) to the caller.
    pub fn release(&self, reservation_id: &str, now_ms: i64) -> Result<Budget, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        // Scope the reservation borrow so it ends before the accounts are
        // borrowed below.
        let (held, consumed, parent_id, child_id) = {
            let reservation = inner
                .reservations
                .get_mut(reservation_id)
                .ok_or_else(|| BudgetError::UnknownReservation(reservation_id.to_string()))?;
            if reservation.state != ReservationState::Active {
                return Err(BudgetError::ReservationNotActive(
                    reservation_id.to_string(),
                ));
            }
            reservation.state = ReservationState::Released;
            reservation.released_at_ms = Some(now_ms);
            (
                reservation.held.clone(),
                reservation.consumed.clone(),
                reservation.parent_lease_id.clone(),
                reservation.child_lease_id.clone(),
            )
        };
        // The child's total spend: reservation-level debits plus whatever
        // the child account itself settled or still holds.
        let mut spent = consumed;
        if let Some(child) = inner.accounts.get(&child_id) {
            spent = spent
                .checked_add(&child.consumed)
                .and_then(|s| s.checked_add(&child.exec_held))
                .ok_or(BudgetError::Overflow)?;
        }
        let returned = held.saturating_sub(&spent);
        let parent = inner
            .accounts
            .get_mut(&parent_id)
            .ok_or_else(|| BudgetError::UnknownLease(parent_id.clone()))?;
        parent.reserved_out = parent.reserved_out.saturating_sub(&held);
        parent.consumed = parent
            .consumed
            .checked_add(&spent)
            .ok_or(BudgetError::Overflow)?;
        Ok(returned)
    }

    /// Rehydrate one durable active reservation after a crash (boot
    /// recovery). Restores the parent's `reserved_out` hold and the
    /// reservation's recorded consumption without re-running admission —
    /// the hold was admitted before the crash. Idempotent: a reservation id
    /// already present is left untouched, so repeated reconciliations never
    /// double-count the hold. The parent account must already be registered.
    pub fn rehydrate_reservation(&self, reservation: &Reservation) -> Result<(), BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        if inner.reservations.contains_key(&reservation.id) {
            return Ok(());
        }
        if reservation.state != ReservationState::Active {
            return Err(BudgetError::ReservationNotActive(reservation.id.clone()));
        }
        let parent = inner
            .accounts
            .get_mut(&reservation.parent_lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(reservation.parent_lease_id.clone()))?;
        parent.reserved_out = parent
            .reserved_out
            .checked_add(&reservation.held)
            .ok_or(BudgetError::Overflow)?;
        inner
            .reservations
            .insert(reservation.id.clone(), reservation.clone());
        Ok(())
    }

    /// Atomically reserve execution capacity against the lease's remaining
    /// balance, before dispatch.
    ///
    /// The admission check and the hold are a single mutex acquisition: two
    /// concurrent authorizations cannot both pass on the last execution.
    /// Idempotent on `idempotency_key` (the envelope nonce): authorizing the
    /// same envelope twice returns the existing reservation instead of
    /// double-holding.
    pub fn reserve_execution(
        &self,
        lease_id: &str,
        action_id: &str,
        need: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<ExecutionReservation, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        if let Some(id) = inner.exec_reserve_keys.get(idempotency_key) {
            return inner
                .executions
                .get(id)
                .cloned()
                .ok_or_else(|| BudgetError::UnknownReservation(id.clone()));
        }
        let account = inner
            .accounts
            .get_mut(lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(lease_id.to_string()))?;
        let remaining = account.remaining().ok_or(BudgetError::Overflow)?;
        for (dim, want) in need.iter() {
            let have = remaining.get(dim);
            if have < want {
                return Err(BudgetError::Insufficient {
                    lease: lease_id.to_string(),
                    dimension: dim.as_str(),
                    needed: want,
                    remaining: have,
                });
            }
        }
        account.exec_held = account
            .exec_held
            .checked_add(need)
            .ok_or(BudgetError::Overflow)?;
        let reservation = ExecutionReservation {
            id: format!("exec_{}", Uuid::new_v4()),
            lease_id: lease_id.to_string(),
            action_id: action_id.to_string(),
            held: need.clone(),
            state: ExecutionState::Held,
            idempotency_key: idempotency_key.to_string(),
            created_at_ms: now_ms,
            completed_at_ms: None,
            actual: None,
        };
        inner
            .exec_reserve_keys
            .insert(idempotency_key.to_string(), reservation.id.clone());
        inner
            .executions
            .insert(reservation.id.clone(), reservation.clone());
        Ok(reservation)
    }

    /// Settle a held execution after dispatch: the hold dissolves and the
    /// measured `actual` consumption is debited, exactly once.
    ///
    /// Idempotent on `idempotency_key`: a retried settle with the same key
    /// and actuals returns the stored receipt; a different actual under the
    /// same key fails closed. Only `Held` reservations settle — double
    /// settle and settle-after-release are rejected.
    ///
    /// Actuals are recorded truthfully: if concurrent exhaustion left the
    /// account short, the debit still lands (the effect already happened)
    /// and the account saturates at zero remaining. Such an overrun surfaces
    /// in [`BudgetLedger::check_invariants`], never as silent
    /// under-accounting.
    pub fn settle_execution(
        &self,
        reservation_id: &str,
        actual: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<DebitReceipt, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        if let Some(receipt) = inner.exec_settle_keys.get(idempotency_key) {
            if receipt.actual == *actual && receipt.reservation_id == reservation_id {
                return Ok(receipt.clone());
            }
            return Err(BudgetError::IdempotencyConflict(
                idempotency_key.to_string(),
            ));
        }
        let (held, lease_id) = {
            let r = inner
                .executions
                .get_mut(reservation_id)
                .ok_or_else(|| BudgetError::UnknownReservation(reservation_id.to_string()))?;
            if r.state != ExecutionState::Held {
                return Err(BudgetError::ExecutionNotHeld(reservation_id.to_string()));
            }
            r.state = ExecutionState::Settled;
            r.completed_at_ms = Some(now_ms);
            r.actual = Some(actual.clone());
            (r.held.clone(), r.lease_id.clone())
        };
        let account = inner
            .accounts
            .get_mut(&lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(lease_id.clone()))?;
        account.exec_held = account.exec_held.saturating_sub(&held);
        account.consumed = account
            .consumed
            .checked_add(actual)
            .ok_or(BudgetError::Overflow)?;
        let receipt = DebitReceipt {
            reservation_id: reservation_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        };
        inner
            .exec_settle_keys
            .insert(idempotency_key.to_string(), receipt.clone());
        Ok(receipt)
    }

    /// Release a held execution that was never dispatched, or failed before
    /// any effect: the hold returns to the lease's remaining balance.
    /// Settled reservations cannot be released (fail closed).
    pub fn release_execution(
        &self,
        reservation_id: &str,
        now_ms: i64,
    ) -> Result<Budget, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        let (held, lease_id) = {
            let r = inner
                .executions
                .get_mut(reservation_id)
                .ok_or_else(|| BudgetError::UnknownReservation(reservation_id.to_string()))?;
            if r.state != ExecutionState::Held {
                return Err(BudgetError::ExecutionNotHeld(reservation_id.to_string()));
            }
            r.state = ExecutionState::Released;
            r.completed_at_ms = Some(now_ms);
            (r.held.clone(), r.lease_id.clone())
        };
        let account = inner
            .accounts
            .get_mut(&lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(lease_id.clone()))?;
        account.exec_held = account.exec_held.saturating_sub(&held);
        Ok(held)
    }

    /// Fetch an execution reservation by id.
    pub fn get_execution(&self, id: &str) -> Option<ExecutionReservation> {
        self.inner
            .lock()
            .expect("ledger mutex poisoned")
            .executions
            .get(id)
            .cloned()
    }

    /// Snapshot of all held execution reservations (for persistence at
    /// dispatch time and inspection).
    pub fn active_executions(&self) -> Vec<ExecutionReservation> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        inner
            .executions
            .values()
            .filter(|r| r.state == ExecutionState::Held)
            .cloned()
            .collect()
    }

    /// Snapshot of every execution reservation, held or terminal (for boot
    /// rehydration).
    pub fn all_executions(&self) -> Vec<ExecutionReservation> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        inner.executions.values().cloned().collect()
    }

    /// Remaining balance of a lease: caps − active reservations − consumption.
    pub fn remaining(&self, lease_id: &str) -> Result<Budget, BudgetError> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        let account = inner
            .accounts
            .get(lease_id)
            .ok_or_else(|| BudgetError::UnknownLease(lease_id.to_string()))?;
        account.remaining().ok_or(BudgetError::Overflow)
    }

    /// Crash-safe reconciliation: release every active reservation whose
    /// child lease is no longer live (expired or revoked). `is_live` is
    /// supplied by the lease layer. Returns the released reservation ids.
    pub fn reconcile(&self, is_live: &dyn Fn(&str) -> bool, now_ms: i64) -> Vec<String> {
        let ids: Vec<String> = {
            let inner = self.inner.lock().expect("ledger mutex poisoned");
            inner
                .reservations
                .values()
                .filter(|r| r.state == ReservationState::Active && !is_live(&r.child_lease_id))
                .map(|r| r.id.clone())
                .collect()
        };
        let mut released = Vec::new();
        for id in ids {
            if self.release(&id, now_ms).is_ok() {
                released.push(id);
            }
        }
        released
    }

    /// Snapshot of all active reservations (for persistence / inspection).
    pub fn active_reservations(&self) -> Vec<Reservation> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        inner
            .reservations
            .values()
            .filter(|r| r.state == ReservationState::Active)
            .cloned()
            .collect()
    }

    /// (cap, reserved_out, exec_held, consumed) for a lease account. Used by
    /// property tests to assert conservation: remaining + reserved_out +
    /// exec_held + consumed == cap.
    pub fn account_summary(&self, lease_id: &str) -> Option<(Budget, Budget, Budget, Budget)> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        inner.accounts.get(lease_id).map(|a| {
            (
                a.caps.clone(),
                a.reserved_out.clone(),
                a.exec_held.clone(),
                a.consumed.clone(),
            )
        })
    }

    /// Check the fan-out invariant for every lease: for each dimension,
    /// Σ active child held + held executions + consumption ≤ caps. Used by
    /// property tests. A settle that truthfully recorded more consumption
    /// than the account held (concurrent exhaustion) surfaces here as a
    /// violation for operators to investigate — the ledger records what
    /// happened rather than silently under-accounting.
    pub fn check_invariants(&self) -> Result<(), BudgetError> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        for (lease_id, account) in &inner.accounts {
            let total = account
                .reserved_out
                .checked_add(&account.exec_held)
                .and_then(|t| t.checked_add(&account.consumed))
                .ok_or(BudgetError::Overflow)?;
            if !account.caps.covers(&total) {
                return Err(BudgetError::Insufficient {
                    lease: lease_id.clone(),
                    dimension: "invariant",
                    needed: 0,
                    remaining: 0,
                });
            }
        }
        Ok(())
    }
}

impl Default for BudgetLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn micros(n: u64) -> Budget {
        Budget::new().set(BudgetDimension::SpendMicros, n)
    }

    #[test]
    fn reserve_and_debit_flow() {
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        let res = ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        // Second child cannot exceed the remainder.
        assert!(ledger.reserve("parent", "child2", &micros(50), 1).is_err());
        let res2 = ledger.reserve("parent", "child2", &micros(40), 1).unwrap();
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            0
        );
        // Debit within held.
        let r1 = ledger.debit(&res.id, &micros(25), "key-1", 2).unwrap();
        assert_eq!(r1.actual.get(BudgetDimension::SpendMicros), 25);
        // Idempotent retry: same key, same debit → same receipt, no double charge.
        let r1b = ledger.debit(&res.id, &micros(25), "key-1", 3).unwrap();
        assert_eq!(r1, r1b);
        // Same key, different debit → conflict.
        assert!(matches!(
            ledger.debit(&res.id, &micros(26), "key-1", 4),
            Err(BudgetError::IdempotencyConflict(_))
        ));
        // Debit beyond held fails.
        assert!(ledger.debit(&res.id, &micros(40), "key-2", 5).is_err());
        // Release returns the unspent remainder.
        let returned = ledger.release(&res2.id, 6).unwrap();
        assert_eq!(returned.get(BudgetDimension::SpendMicros), 40);
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn rollback_lease_registration_undoes_a_fresh_mint() {
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        // Standing-mint ledger effects: reservation + child account.
        ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.register_lease("child", &micros(60)).unwrap();

        ledger.rollback_lease_registration("child").unwrap();

        // The issuance reservation is removed entirely (no Released
        // phantom), the parent's held balance is restored, and the child
        // account is gone.
        assert!(ledger.active_reservations().is_empty());
        assert!(ledger.account_summary("child").is_none());
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            100
        );
        ledger.check_invariants().unwrap();
        // One-shot mints (no reservation) roll back to just the account
        // removal.
        ledger.register_lease("oneshot", &micros(1)).unwrap();
        ledger.rollback_lease_registration("oneshot").unwrap();
        assert!(ledger.account_summary("oneshot").is_none());
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn rollback_lease_registration_fails_closed_on_used_state() {
        // Consumption against the child account blocks rollback.
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.register_lease("child", &micros(60)).unwrap();
        ledger
            .debit_lease("child", &micros(10), "spend-1", 2)
            .unwrap();
        let before = ledger.account_summary("parent").unwrap();
        assert!(matches!(
            ledger.rollback_lease_registration("child"),
            Err(BudgetError::RollbackFailed(_, _))
        ));
        // Fail-closed: the ledger is untouched.
        assert_eq!(ledger.account_summary("parent").unwrap(), before);
        assert!(ledger.account_summary("child").is_some());
        assert_eq!(ledger.active_reservations().len(), 1);

        // Reserved descendants block rollback too.
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.register_lease("child", &micros(60)).unwrap();
        ledger
            .reserve("child", "grandchild", &micros(10), 2)
            .unwrap();
        assert!(matches!(
            ledger.rollback_lease_registration("child"),
            Err(BudgetError::RollbackFailed(_, _))
        ));
        assert_eq!(ledger.active_reservations().len(), 2);

        // A consumed issuance reservation blocks rollback.
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        let res = ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.register_lease("child", &micros(60)).unwrap();
        ledger.debit(&res.id, &micros(5), "debit-1", 2).unwrap();
        assert!(matches!(
            ledger.rollback_lease_registration("child"),
            Err(BudgetError::RollbackFailed(_, _))
        ));

        // A missing child account is inconsistent, not "already done".
        let ledger = BudgetLedger::new();
        assert!(matches!(
            ledger.rollback_lease_registration("ghost"),
            Err(BudgetError::RollbackFailed(_, _))
        ));
    }


    #[test]
    fn register_lease_rejects_duplicate_ids() {
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        assert!(ledger.is_lease_registered("parent"));
        assert!(!ledger.is_lease_registered("ghost"));

        // A duplicate mint (child id collides with an existing account)
        // fails at reserve time, before any hold is taken: nothing leaks.
        assert!(matches!(
            ledger.reserve("parent", "parent", &micros(60), 1),
            Err(BudgetError::DuplicateLease(_))
        ));
        // The parent's books are untouched and no reservation was recorded.
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            100
        );
        assert!(ledger.active_reservations().is_empty());

        // register_lease is the second layer: re-registering an id whose
        // spend is already recorded must fail instead of resetting its
        // books to zero (which would resurrect spent budget).
        ledger.register_lease("sibling", &micros(10)).unwrap();
        ledger
            .debit_lease("sibling", &micros(4), "sib-key", 1)
            .unwrap();
        assert!(matches!(
            ledger.register_lease("sibling", &micros(10)),
            Err(BudgetError::DuplicateLease(_))
        ));
        assert_eq!(
            ledger
                .remaining("sibling")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            6
        );
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn release_debit_then_release_conserves_budget() {
        // The finding's exact scenario: cap 100, child reserves 60, debit
        // records 25. After release the parent must hold 75 remaining — the
        // spent 25 moves into parent.consumed instead of becoming spendable
        // again.
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        let res = ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.debit(&res.id, &micros(25), "key-1", 2).unwrap();

        let returned = ledger.release(&res.id, 3).unwrap();
        assert_eq!(returned.get(BudgetDimension::SpendMicros), 35);
        let (caps, reserved_out, exec_held, consumed) = ledger.account_summary("parent").unwrap();
        assert_eq!(consumed.get(BudgetDimension::SpendMicros), 25);
        assert_eq!(reserved_out.get(BudgetDimension::SpendMicros), 0);
        let remaining = ledger.remaining("parent").unwrap();
        assert_eq!(remaining.get(BudgetDimension::SpendMicros), 75);
        // Conservation: remaining + reserved_out + exec_held + consumed == cap.
        let total = remaining.get(BudgetDimension::SpendMicros)
            + reserved_out.get(BudgetDimension::SpendMicros)
            + exec_held.get(BudgetDimension::SpendMicros)
            + consumed.get(BudgetDimension::SpendMicros);
        assert_eq!(total, caps.get(BudgetDimension::SpendMicros));
        ledger.check_invariants().unwrap();

        // Releasing twice fails closed.
        assert!(matches!(
            ledger.release(&res.id, 4),
            Err(BudgetError::ReservationNotActive(_))
        ));
    }

    #[test]
    fn release_moves_child_account_spend_to_parent() {
        // The larger leak: child spend via settle_execution / debit_lease
        // lands on the child account, never on Reservation.consumed.
        // Release must move all of it — settled consumption and outstanding
        // execution holds — into the parent, or mint → spend → expire →
        // mint again would exceed the parent cap every cycle.
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        let res = ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.register_lease("child", &micros(60)).unwrap();

        // Spend through every path: reservation-level debit, the child
        // account's own settle, and an outstanding execution hold.
        ledger.debit(&res.id, &micros(25), "key-1", 2).unwrap();
        let exec = ledger
            .reserve_execution("child", "a1", &micros(10), "n1", 3)
            .unwrap();
        ledger
            .settle_execution(&exec.id, &micros(10), "s1", 4)
            .unwrap();
        ledger
            .reserve_execution("child", "a2", &micros(5), "n2", 5)
            .unwrap();

        // Child spend = 25 (reservation) + 10 (settled) + 5 (held) = 40.
        let returned = ledger.release(&res.id, 6).unwrap();
        assert_eq!(returned.get(BudgetDimension::SpendMicros), 20);
        let (caps, reserved_out, exec_held, consumed) = ledger.account_summary("parent").unwrap();
        assert_eq!(consumed.get(BudgetDimension::SpendMicros), 40);
        assert_eq!(reserved_out.get(BudgetDimension::SpendMicros), 0);
        let remaining = ledger.remaining("parent").unwrap();
        assert_eq!(remaining.get(BudgetDimension::SpendMicros), 60);
        let total = remaining.get(BudgetDimension::SpendMicros)
            + reserved_out.get(BudgetDimension::SpendMicros)
            + exec_held.get(BudgetDimension::SpendMicros)
            + consumed.get(BudgetDimension::SpendMicros);
        assert_eq!(total, caps.get(BudgetDimension::SpendMicros));
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn rehydrate_reservation_restores_hold_idempotently() {
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        let mut res = ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        ledger.debit(&res.id, &micros(25), "key-1", 2).unwrap();
        res = ledger
            .active_reservations()
            .into_iter()
            .find(|r| r.id == res.id)
            .unwrap();

        // Simulate the crash: a fresh ledger with only the parent's caps.
        let fresh = BudgetLedger::new();
        fresh.register_lease("parent", &micros(100)).unwrap();
        fresh.rehydrate_reservation(&res).unwrap();
        assert_eq!(
            fresh
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        // Re-running is a no-op: the hold is never double-counted.
        fresh.rehydrate_reservation(&res).unwrap();
        assert_eq!(
            fresh
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        // The recorded consumption survived and is charged at release.
        let rehydrated = fresh.active_reservations();
        assert_eq!(rehydrated.len(), 1);
        assert_eq!(rehydrated[0].consumed.get(BudgetDimension::SpendMicros), 25);
        fresh.release(&rehydrated[0].id, 3).unwrap();
        assert_eq!(
            fresh
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            75
        );
        fresh.check_invariants().unwrap();

        // Non-active reservations and unknown parents fail closed. (Note: the
        // idempotency check runs first, so a re-submitted id is Ok even if
        // the caller mutated its state copy — use fresh ids here.)
        let mut released = res.clone();
        released.id = "res_released".to_string();
        released.state = ReservationState::Released;
        assert!(matches!(
            fresh.rehydrate_reservation(&released),
            Err(BudgetError::ReservationNotActive(_))
        ));
        let mut orphan = res.clone();
        orphan.id = "res_orphan".to_string();
        orphan.parent_lease_id = "ghost".to_string();
        assert!(matches!(
            fresh.rehydrate_reservation(&orphan),
            Err(BudgetError::UnknownLease(_))
        ));
    }

    #[test]
    fn reconcile_releases_dead_children() {
        let ledger = BudgetLedger::new();
        ledger.register_lease("parent", &micros(100)).unwrap();
        let res = ledger.reserve("parent", "child", &micros(60), 1).unwrap();
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        let released = ledger.reconcile(&|id| id != "child", 2);
        assert_eq!(released, vec![res.id]);
        assert_eq!(
            ledger
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            100
        );
    }

    #[test]
    fn multi_dimension_atomicity() {
        let ledger = BudgetLedger::new();
        let caps = Budget::new()
            .set(BudgetDimension::SpendMicros, 100)
            .set(BudgetDimension::Tokens, 10);
        ledger.register_lease("parent", &caps).unwrap();
        // Tokens short → the whole reservation fails, spend untouched.
        let want = Budget::new()
            .set(BudgetDimension::SpendMicros, 50)
            .set(BudgetDimension::Tokens, 11);
        assert!(ledger.reserve("parent", "child", &want, 1).is_err());
        assert_eq!(ledger.remaining("parent").unwrap(), caps);
    }

    fn one_exec() -> Budget {
        Budget::new().set(BudgetDimension::Executions, 1)
    }

    #[test]
    fn execution_reserve_is_atomic_with_admission() {
        let ledger = BudgetLedger::new();
        ledger
            .register_lease("lease", &Budget::new().set(BudgetDimension::Executions, 1))
            .unwrap();
        // First reserve takes the last execution; the hold is visible immediately.
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        assert_eq!(r.state, ExecutionState::Held);
        assert!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions)
                == 0
        );
        // A second authorization on the same finite budget is refused.
        assert!(matches!(
            ledger.reserve_execution("lease", "action-2", &one_exec(), "nonce-2", 2),
            Err(BudgetError::Insufficient { .. })
        ));
        // Conservation still holds with the execution hold counted.
        let (caps, reserved_out, exec_held, consumed) = ledger.account_summary("lease").unwrap();
        assert_eq!(exec_held.get(BudgetDimension::Executions), 1);
        let total = ledger
            .remaining("lease")
            .unwrap()
            .get(BudgetDimension::Executions)
            + reserved_out.get(BudgetDimension::Executions)
            + exec_held.get(BudgetDimension::Executions)
            + consumed.get(BudgetDimension::Executions);
        assert_eq!(total, caps.get(BudgetDimension::Executions));
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn execution_reserve_idempotent_on_envelope_nonce() {
        let ledger = BudgetLedger::new();
        ledger
            .register_lease("lease", &Budget::new().set(BudgetDimension::Executions, 2))
            .unwrap();
        let r1 = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        // Authorizing the same envelope twice returns the same reservation:
        // no double hold.
        let r2 = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 2)
            .unwrap();
        assert_eq!(r1.id, r2.id);
        assert_eq!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );
    }

    #[test]
    fn execution_settle_converts_hold_to_consumption() {
        let ledger = BudgetLedger::new();
        ledger
            .register_lease("lease", &Budget::new().set(BudgetDimension::Executions, 1))
            .unwrap();
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        let receipt = ledger
            .settle_execution(&r.id, &one_exec(), "settle-1", 2)
            .unwrap();
        assert_eq!(receipt.actual, one_exec());
        assert_eq!(
            ledger.get_execution(&r.id).unwrap().state,
            ExecutionState::Settled
        );
        // The execution is consumed: remaining stays zero, no double spend.
        assert_eq!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            0
        );
        let (_, _, exec_held, consumed) = ledger.account_summary("lease").unwrap();
        assert_eq!(exec_held.get(BudgetDimension::Executions), 0);
        assert_eq!(consumed.get(BudgetDimension::Executions), 1);
        // Idempotent retry: same key and actuals → same receipt.
        let receipt2 = ledger
            .settle_execution(&r.id, &one_exec(), "settle-1", 3)
            .unwrap();
        assert_eq!(receipt, receipt2);
        // Same key, different actuals → conflict, fail closed.
        assert!(matches!(
            ledger.settle_execution(
                &r.id,
                &Budget::new().set(BudgetDimension::Executions, 2),
                "settle-1",
                4
            ),
            Err(BudgetError::IdempotencyConflict(_))
        ));
        // Settling twice is rejected even with a fresh key.
        assert!(matches!(
            ledger.settle_execution(&r.id, &one_exec(), "settle-2", 5),
            Err(BudgetError::ExecutionNotHeld(_))
        ));
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn execution_release_returns_the_hold() {
        let ledger = BudgetLedger::new();
        ledger
            .register_lease("lease", &Budget::new().set(BudgetDimension::Executions, 1))
            .unwrap();
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        // Dispatch never happened: the hold returns to the balance.
        let returned = ledger.release_execution(&r.id, 2).unwrap();
        assert_eq!(returned, one_exec());
        assert_eq!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );
        assert_eq!(
            ledger.get_execution(&r.id).unwrap().state,
            ExecutionState::Released
        );
        // Double release fails closed; release-then-settle fails closed.
        assert!(matches!(
            ledger.release_execution(&r.id, 3),
            Err(BudgetError::ExecutionNotHeld(_))
        ));
        assert!(matches!(
            ledger.settle_execution(&r.id, &one_exec(), "settle-1", 4),
            Err(BudgetError::ExecutionNotHeld(_))
        ));
        ledger.check_invariants().unwrap();
    }

    #[test]
    fn execution_reserve_on_unknown_lease_fails_closed() {
        let ledger = BudgetLedger::new();
        assert!(matches!(
            ledger.reserve_execution("nope", "a", &one_exec(), "n", 1),
            Err(BudgetError::UnknownLease(_))
        ));
    }
}
