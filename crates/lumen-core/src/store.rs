//! Kernel repository traits (Phase 1): the persistence boundary.
//!
//! The pure lease/budget/audit logic operates on these traits. The in-memory
//! implementations back unit and property tests; `lumen-db` implements the
//! same traits against SQLite (migrations 0022+).
//!
//! All traits are async because the durable implementation is I/O-bound.
//! Pure functions that need synchronous access (e.g. [`crate::lease::validate_chain`])
//! take a [`crate::lease::LeaseResolver`] over already-loaded documents.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use thiserror::Error;

use crate::{
    budget::{Budget, BudgetError, DebitReceipt, ExecutionReservation, Reservation},
    lease::LeaseDocument,
};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum StoreError {
    #[error("lease not found: {0}")]
    NotFound(String),
    #[error("duplicate: {0}")]
    Duplicate(String),
    #[error("budget error: {0}")]
    Budget(#[from] BudgetError),
    #[error("backend error: {0}")]
    Backend(String),
}

/// Persistent lease documents.
#[async_trait]
pub trait LeaseStore: Send + Sync {
    async fn insert_lease(&self, doc: &LeaseDocument) -> Result<(), StoreError>;
    async fn get_lease(&self, id: &str) -> Result<Option<LeaseDocument>, StoreError>;
    /// Load a full chain, leaf first, following parent links.
    async fn get_chain(&self, leaf_id: &str) -> Result<Vec<LeaseDocument>, StoreError> {
        let mut chain = Vec::new();
        let mut current = leaf_id.to_string();
        for _ in 0..128 {
            let doc = self
                .get_lease(&current)
                .await?
                .ok_or_else(|| StoreError::NotFound(current.clone()))?;
            let parent = doc.parent_id.clone();
            chain.push(doc);
            match parent {
                Some(p) => current = p,
                None => break,
            }
        }
        Ok(chain)
    }
}

/// Revocation records. Revoking a parent transitively invalidates descendants
/// at validation time; no cascade writes are needed.
#[async_trait]
pub trait RevocationStore: Send + Sync {
    async fn record_revocation(
        &self,
        lease_id: &str,
        at_ms: i64,
        reason: &str,
        by: &str,
    ) -> Result<(), StoreError>;
    async fn is_revoked(&self, lease_id: &str) -> Result<bool, StoreError>;
    async fn revoked_ids(&self) -> Result<HashSet<String>, StoreError>;
}

/// Durable one-shot consumption (replay protection across restarts).
#[async_trait]
pub trait OneShotStore: Send + Sync {
    /// Returns `true` if newly consumed, `false` if this is a replay.
    async fn consume_one_shot(&self, lease_id: &str, at_ms: i64) -> Result<bool, StoreError>;
    async fn is_consumed(&self, lease_id: &str) -> Result<bool, StoreError>;
}

/// Durable nonce record (envelope replay protection across restarts).
#[async_trait]
pub trait NonceStoreBackend: Send + Sync {
    /// Returns `true` if the nonce was newly recorded, `false` on replay.
    async fn record_nonce(
        &self,
        nonce: &str,
        at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool, StoreError>;
    async fn purge_expired_nonces(&self, now_ms: i64) -> Result<usize, StoreError>;
}

/// Durable budget reservations and debits.
#[async_trait]
pub trait BudgetStore: Send + Sync {
    async fn insert_reservation(&self, reservation: &Reservation) -> Result<(), StoreError>;
    async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>, StoreError>;
    async fn update_reservation(&self, reservation: &Reservation) -> Result<(), StoreError>;
    /// Active reservations whose child lease is dead (expired or revoked):
    /// the crash-safe reconciliation set.
    async fn active_reservations(&self) -> Result<Vec<Reservation>, StoreError>;
    async fn insert_debit(
        &self,
        debit_id: &str,
        reservation_id: &str,
        idempotency_key: &str,
        actual: &Budget,
        at_ms: i64,
    ) -> Result<(), StoreError>;
    async fn find_debit_by_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<DebitReceipt>, StoreError>;
    /// Record a lease's budget caps (idempotent: first write wins). Needed
    /// to rehydrate the in-memory ledger after a crash.
    async fn record_lease_caps(&self, lease_id: &str, caps: &Budget) -> Result<(), StoreError>;
    async fn lease_caps(&self, lease_id: &str) -> Result<Option<Budget>, StoreError>;
    /// Durable execution reservations: the crash-recovery side of the
    /// reserve → dispatch → settle/release lifecycle. The row's state
    /// machine is held -> settled | released; the settled row carries the
    /// measured actuals as the durable debit receipt.
    async fn insert_execution(&self, reservation: &ExecutionReservation) -> Result<(), StoreError>;
    async fn get_execution(&self, id: &str) -> Result<Option<ExecutionReservation>, StoreError>;
    async fn update_execution(&self, reservation: &ExecutionReservation) -> Result<(), StoreError>;
    /// Every execution reservation, held or terminal (for boot rehydration).
    async fn all_executions(&self) -> Result<Vec<ExecutionReservation>, StoreError>;
}

// ---------------------------------------------------------------------------
// In-memory implementations (tests)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MemoryInner {
    leases: HashMap<String, LeaseDocument>,
    revocations: HashSet<String>,
    one_shot: HashSet<String>,
    nonces: HashMap<String, (i64, i64)>,
    reservations: HashMap<String, Reservation>,
    debit_keys: HashMap<String, DebitReceipt>,
    debit_reservation: HashMap<String, String>,
    lease_caps: HashMap<String, Budget>,
    executions: HashMap<String, ExecutionReservation>,
}

#[derive(Clone, Default)]
pub struct MemoryStores {
    inner: Arc<Mutex<MemoryInner>>,
}

#[async_trait]
impl LeaseStore for MemoryStores {
    async fn insert_lease(&self, doc: &LeaseDocument) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if inner.leases.contains_key(&doc.lease_id) {
            return Err(StoreError::Duplicate(doc.lease_id.clone()));
        }
        inner.leases.insert(doc.lease_id.clone(), doc.clone());
        Ok(())
    }

    async fn get_lease(&self, id: &str) -> Result<Option<LeaseDocument>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .leases
            .get(id)
            .cloned())
    }
}

#[async_trait]
impl RevocationStore for MemoryStores {
    async fn record_revocation(
        &self,
        lease_id: &str,
        _at_ms: i64,
        _reason: &str,
        _by: &str,
    ) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("store mutex poisoned")
            .revocations
            .insert(lease_id.to_string());
        Ok(())
    }

    async fn is_revoked(&self, lease_id: &str) -> Result<bool, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .revocations
            .contains(lease_id))
    }

    async fn revoked_ids(&self) -> Result<HashSet<String>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .revocations
            .clone())
    }
}

#[async_trait]
impl OneShotStore for MemoryStores {
    async fn consume_one_shot(&self, lease_id: &str, _at_ms: i64) -> Result<bool, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .one_shot
            .insert(lease_id.to_string()))
    }

    async fn is_consumed(&self, lease_id: &str) -> Result<bool, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .one_shot
            .contains(lease_id))
    }
}

#[async_trait]
impl NonceStoreBackend for MemoryStores {
    async fn record_nonce(
        &self,
        nonce: &str,
        at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool, StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if let Some((_, exp)) = inner.nonces.get(nonce)
            && at_ms < *exp
        {
            return Ok(false);
        }
        inner
            .nonces
            .insert(nonce.to_string(), (at_ms, expires_at_ms));
        Ok(true)
    }

    async fn purge_expired_nonces(&self, now_ms: i64) -> Result<usize, StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        let before = inner.nonces.len();
        inner.nonces.retain(|_, (_, exp)| now_ms < *exp);
        Ok(before - inner.nonces.len())
    }
}

#[async_trait]
impl BudgetStore for MemoryStores {
    async fn insert_reservation(&self, reservation: &Reservation) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if inner.reservations.contains_key(&reservation.id) {
            return Err(StoreError::Duplicate(reservation.id.clone()));
        }
        inner
            .reservations
            .insert(reservation.id.clone(), reservation.clone());
        Ok(())
    }

    async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .reservations
            .get(id)
            .cloned())
    }

    async fn update_reservation(&self, reservation: &Reservation) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if !inner.reservations.contains_key(&reservation.id) {
            return Err(StoreError::NotFound(reservation.id.clone()));
        }
        inner
            .reservations
            .insert(reservation.id.clone(), reservation.clone());
        Ok(())
    }

    async fn active_reservations(&self) -> Result<Vec<Reservation>, StoreError> {
        use crate::budget::ReservationState;
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .reservations
            .values()
            .filter(|r| r.state == ReservationState::Active)
            .cloned()
            .collect())
    }

    async fn insert_debit(
        &self,
        debit_id: &str,
        reservation_id: &str,
        idempotency_key: &str,
        actual: &Budget,
        at_ms: i64,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if inner.debit_keys.contains_key(idempotency_key) {
            return Err(StoreError::Duplicate(idempotency_key.to_string()));
        }
        let _ = debit_id;
        inner.debit_keys.insert(
            idempotency_key.to_string(),
            DebitReceipt {
                reservation_id: reservation_id.to_string(),
                actual: actual.clone(),
                debited_at_ms: at_ms,
            },
        );
        inner
            .debit_reservation
            .insert(debit_id.to_string(), reservation_id.to_string());
        Ok(())
    }

    async fn find_debit_by_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<DebitReceipt>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .debit_keys
            .get(idempotency_key)
            .cloned())
    }

    async fn record_lease_caps(&self, lease_id: &str, caps: &Budget) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("store mutex poisoned")
            .lease_caps
            .entry(lease_id.to_string())
            .or_insert_with(|| caps.clone());
        Ok(())
    }

    async fn lease_caps(&self, lease_id: &str) -> Result<Option<Budget>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .lease_caps
            .get(lease_id)
            .cloned())
    }

    async fn insert_execution(&self, reservation: &ExecutionReservation) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if inner.executions.contains_key(&reservation.id) {
            return Err(StoreError::Duplicate(reservation.id.clone()));
        }
        inner
            .executions
            .insert(reservation.id.clone(), reservation.clone());
        Ok(())
    }

    async fn get_execution(&self, id: &str) -> Result<Option<ExecutionReservation>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .executions
            .get(id)
            .cloned())
    }

    async fn update_execution(&self, reservation: &ExecutionReservation) -> Result<(), StoreError> {
        let mut inner = self.inner.lock().expect("store mutex poisoned");
        if !inner.executions.contains_key(&reservation.id) {
            return Err(StoreError::NotFound(reservation.id.clone()));
        }
        inner
            .executions
            .insert(reservation.id.clone(), reservation.clone());
        Ok(())
    }

    async fn all_executions(&self) -> Result<Vec<ExecutionReservation>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("store mutex poisoned")
            .executions
            .values()
            .cloned()
            .collect())
    }
}
