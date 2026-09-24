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
    #[error("unknown reservation: {0}")]
    UnknownReservation(String),
    #[error("reservation {0} is not active")]
    ReservationNotActive(String),
    #[error("debit of {0:?} exceeds reservation {1}: {2}")]
    DebitExceedsHeld(Budget, String, String),
    #[error("idempotency key {0} was already used with a different debit")]
    IdempotencyConflict(String),
    #[error("budget overflow")]
    Overflow,
    #[error("store error: {0}")]
    Store(String),
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
    /// Consumption debited directly against this lease (root spend).
    consumed: Budget,
}

impl LeaseAccount {
    fn remaining(&self) -> Option<Budget> {
        let reserved_total = self.reserved_out.checked_add(&self.consumed)?;
        Some(self.caps.saturating_sub(&reserved_total))
    }
}

struct LedgerInner {
    accounts: HashMap<String, LeaseAccount>,
    reservations: HashMap<String, Reservation>,
    debit_keys: HashMap<String, DebitReceipt>,
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
            }),
        }
    }

    /// Register a lease's budget caps. Called for root leases at issuance
    /// (caps are policy-granted) and for child leases after their reservation
    /// succeeds (the child's own caps are its held maximum).
    pub fn register_lease(&self, lease_id: &str, caps: &Budget) -> Result<(), BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        inner.accounts.insert(
            lease_id.to_string(),
            LeaseAccount {
                caps: caps.clone(),
                reserved_out: Budget::new(),
                consumed: Budget::new(),
            },
        );
        Ok(())
    }

    /// Reserve `child_max` against the parent's remaining balance. Fails
    /// atomically (no partial reservation) when any dimension is short.
    pub fn reserve(
        &self,
        parent_lease_id: &str,
        child_lease_id: &str,
        child_max: &Budget,
        now_ms: i64,
    ) -> Result<Reservation, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
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
    pub fn release(&self, reservation_id: &str, now_ms: i64) -> Result<Budget, BudgetError> {
        let mut inner = self.inner.lock().expect("ledger mutex poisoned");
        // Scope the reservation borrow so it ends before the parent account
        // is borrowed mutably below.
        let (held, consumed, parent_id) = {
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
            )
        };
        let returned = held.saturating_sub(&consumed);
        let parent = inner
            .accounts
            .get_mut(&parent_id)
            .ok_or_else(|| BudgetError::UnknownLease(parent_id.clone()))?;
        parent.reserved_out = parent.reserved_out.saturating_sub(&held);
        Ok(returned)
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

    /// (cap, reserved_out, consumed) for a lease account. Used by property
    /// tests to assert conservation: remaining + reserved_out + consumed == cap.
    pub fn account_summary(&self, lease_id: &str) -> Option<(Budget, Budget, Budget)> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        inner
            .accounts
            .get(lease_id)
            .map(|a| (a.caps.clone(), a.reserved_out.clone(), a.consumed.clone()))
    }

    /// Check the fan-out invariant for every lease: for each dimension,
    /// Σ active child held + consumed ≤ caps. Used by property tests.
    pub fn check_invariants(&self) -> Result<(), BudgetError> {
        let inner = self.inner.lock().expect("ledger mutex poisoned");
        for (lease_id, account) in &inner.accounts {
            let total = account
                .reserved_out
                .checked_add(&account.consumed)
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
}
