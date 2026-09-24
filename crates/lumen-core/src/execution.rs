//! Execution budget lifecycle driver: reserve → dispatch → settle/release.
//!
//! [`authorize_envelope`](crate::lease::authorize_envelope) performs the
//! in-memory atomic reserve and hands the dispatcher the reservation id in
//! the `Allow` obligations. This driver is the dispatcher's companion: it
//! persists the reservation before dispatch (so a crash can't lose the
//! hold), settles or releases it afterwards, and reconciles held
//! reservations at boot against the durable action log.
//!
//! # Call sequence
//!
//! 1. `authorize_envelope(...)` → `Allow` + `settle_budget` obligation
//!    (in-memory atomic hold; no durable write yet).
//! 2. `driver.persist_reservation(&reservation)` — durable insert,
//!    idempotent. Must complete before dispatch.
//! 3. Dispatch the action.
//! 4. On success: `driver.settle(reservation_id, &actual,
//!    idempotency_key, now)` — converts the hold into measured consumption,
//!    exactly once.
//! 5. When dispatch never happened, or failed before any effect:
//!    `driver.release(reservation_id, now)` — returns the hold.
//! 6. At boot: `driver.reconcile_at_boot(&is_completed, now)` — rebuilds
//!    the in-memory ledger from the store, settles holds whose actions
//!    completed (charging the held estimate; measured actuals died with the
//!    crashed process), and releases the rest.
//!
//! The durable store row is the authority; the in-memory ledger is a
//! write-through cache. Every transition is idempotent, so retries and
//! crashes never double-charge or lose a hold.

use std::collections::{HashMap, HashSet};

use crate::{
    budget::{Budget, BudgetError, BudgetLedger, DebitReceipt, ExecutionState},
    store::{BudgetStore, StoreError},
};

fn store_err(e: StoreError) -> BudgetError {
    BudgetError::Store(e.to_string())
}

/// Outcome of [`ExecutionDriver::reconcile_at_boot`].
#[derive(Clone, Debug, Default)]
pub struct BootReconciliation {
    /// Leases whose accounts were rehydrated from the store.
    pub rehydrated_leases: usize,
    /// Execution ids settled because their actions completed pre-crash.
    pub settled: Vec<String>,
    /// Execution ids released because their actions never completed.
    pub released: Vec<String>,
    /// (execution id, reason) for rows that could not be reconciled.
    pub errors: Vec<(String, String)>,
}

/// Drives the durable side of the execution budget lifecycle.
pub struct ExecutionDriver<'a> {
    pub ledger: &'a BudgetLedger,
    pub store: &'a dyn BudgetStore,
}

impl<'a> ExecutionDriver<'a> {
    pub fn new(ledger: &'a BudgetLedger, store: &'a dyn BudgetStore) -> Self {
        Self { ledger, store }
    }

    /// Record a lease's budget caps durably (mint path; idempotent, first
    /// write wins). Required so boot reconciliation can rebuild the ledger.
    pub async fn record_caps(&self, lease_id: &str, caps: &Budget) -> Result<(), StoreError> {
        self.store.record_lease_caps(lease_id, caps).await
    }

    /// Persist an in-memory execution reservation before dispatch.
    /// Idempotent: re-persisting the same reservation is a no-op.
    pub async fn persist_reservation(
        &self,
        reservation: &crate::budget::ExecutionReservation,
    ) -> Result<(), StoreError> {
        if self.store.get_execution(&reservation.id).await?.is_some() {
            return Ok(());
        }
        self.store.insert_execution(reservation).await
    }

    /// Settle after dispatch: durable `Held → Settled` transition first,
    /// then the in-memory ledger follows idempotently.
    ///
    /// A retried settle returns the stored receipt; settling with different
    /// actuals under the same key, or settling a released reservation,
    /// fails closed.
    pub async fn settle(
        &self,
        reservation_id: &str,
        actual: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<DebitReceipt, BudgetError> {
        let mut stored = self
            .store
            .get_execution(reservation_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| BudgetError::UnknownReservation(reservation_id.to_string()))?;
        match stored.state {
            ExecutionState::Settled => {
                // Idempotent replay: the durable row is authoritative.
                if stored.actual.as_ref() != Some(actual) {
                    return Err(BudgetError::IdempotencyConflict(
                        idempotency_key.to_string(),
                    ));
                }
            }
            ExecutionState::Held => {
                stored.state = ExecutionState::Settled;
                stored.actual = Some(actual.clone());
                stored.completed_at_ms = Some(now_ms);
                self.store
                    .update_execution(&stored)
                    .await
                    .map_err(store_err)?;
            }
            ExecutionState::Released => {
                return Err(BudgetError::ExecutionNotHeld(reservation_id.to_string()));
            }
        }
        // The ledger follows; idempotent on the key, so a crash between the
        // store write and this call is repaired by replay or at boot.
        match self
            .ledger
            .settle_execution(reservation_id, actual, idempotency_key, now_ms)
        {
            Ok(receipt) => Ok(receipt),
            Err(BudgetError::UnknownReservation(_)) | Err(BudgetError::ExecutionNotHeld(_)) => {
                Ok(DebitReceipt {
                    reservation_id: reservation_id.to_string(),
                    actual: stored.actual.clone().unwrap_or_default(),
                    debited_at_ms: stored.completed_at_ms.unwrap_or(now_ms),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Release a held execution that was never dispatched, or failed before
    /// any effect: durable `Held → Released` first, then the ledger follows.
    /// Releasing an already-released reservation is a no-op success;
    /// releasing a settled one fails closed.
    pub async fn release(&self, reservation_id: &str, now_ms: i64) -> Result<Budget, BudgetError> {
        let mut stored = self
            .store
            .get_execution(reservation_id)
            .await
            .map_err(store_err)?
            .ok_or_else(|| BudgetError::UnknownReservation(reservation_id.to_string()))?;
        if stored.state == ExecutionState::Settled {
            return Err(BudgetError::ExecutionNotHeld(reservation_id.to_string()));
        }
        if stored.state == ExecutionState::Held {
            stored.state = ExecutionState::Released;
            stored.completed_at_ms = Some(now_ms);
            self.store
                .update_execution(&stored)
                .await
                .map_err(store_err)?;
        }
        match self.ledger.release_execution(reservation_id, now_ms) {
            Ok(held) => Ok(held),
            Err(BudgetError::UnknownReservation(_)) | Err(BudgetError::ExecutionNotHeld(_)) => {
                Ok(stored.held.clone())
            }
            Err(e) => Err(e),
        }
    }

    /// Boot reconciliation: rebuild the in-memory ledger from the durable
    /// store, then settle-or-release every held execution.
    ///
    /// `is_completed(action_id)` answers from the durable action log whether
    /// the action dispatched before the crash. Completed actions are settled,
    /// charging the held estimate (measured actuals died with the crashed
    /// process); the rest release their holds. Settled rows are re-applied
    /// as consumption so a crash can never resurrect spent budget.
    pub async fn reconcile_at_boot(
        &self,
        is_completed: &dyn Fn(&str) -> bool,
        now_ms: i64,
    ) -> Result<BootReconciliation, StoreError> {
        let mut report = BootReconciliation::default();
        let mut by_lease: HashMap<String, Vec<crate::budget::ExecutionReservation>> =
            HashMap::new();
        for exec in self.store.all_executions().await? {
            by_lease
                .entry(exec.lease_id.clone())
                .or_default()
                .push(exec);
        }
        let mut registered: HashSet<String> = HashSet::new();
        for (lease_id, execs) in &by_lease {
            let caps = match self.store.lease_caps(lease_id).await? {
                Some(c) => c,
                None => {
                    for exec in execs {
                        report.errors.push((
                            exec.id.clone(),
                            format!("no recorded caps for lease {lease_id}"),
                        ));
                    }
                    continue;
                }
            };
            if registered.insert(lease_id.clone()) {
                self.ledger
                    .register_lease(lease_id, &caps)
                    .map_err(|e| StoreError::Backend(e.to_string()))?;
                report.rehydrated_leases += 1;
            }
            // Settled rows first: re-apply measured consumption so spent
            // budget is never resurrected by a crash.
            for exec in execs.iter().filter(|e| e.state == ExecutionState::Settled) {
                let actual = exec.actual.clone().unwrap_or_else(|| exec.held.clone());
                if let Err(e) =
                    self.ledger
                        .debit_lease(lease_id, &actual, &format!("boot:{}", exec.id), now_ms)
                {
                    report
                        .errors
                        .push((exec.id.clone(), format!("re-apply settle: {e}")));
                }
            }
            // Held rows: re-establish the hold, then settle or release.
            for exec in execs.iter().filter(|e| e.state == ExecutionState::Held) {
                let reserved = match self.ledger.reserve_execution(
                    lease_id,
                    &exec.action_id,
                    &exec.held,
                    &exec.idempotency_key,
                    now_ms,
                ) {
                    Ok(r) => r,
                    Err(e) => {
                        report
                            .errors
                            .push((exec.id.clone(), format!("re-apply hold: {e}")));
                        continue;
                    }
                };
                // Re-reserving always mints a fresh in-memory id bound to the
                // durable row's idempotency key; an existing live reservation
                // under the key means this reconcile is racing live traffic.
                if reserved.state != ExecutionState::Held {
                    report.errors.push((
                        exec.id.clone(),
                        "hold collided with a live reservation".to_string(),
                    ));
                    continue;
                }
                let ledger_id = reserved.id;
                if is_completed(&exec.action_id) {
                    let mut row = exec.clone();
                    row.state = ExecutionState::Settled;
                    row.actual = Some(exec.held.clone());
                    row.completed_at_ms = Some(now_ms);
                    if let Err(e) = self.store.update_execution(&row).await {
                        report.errors.push((exec.id.clone(), e.to_string()));
                        continue;
                    }
                    match self.ledger.settle_execution(
                        &ledger_id,
                        &exec.held,
                        &format!("boot-settle:{}", exec.id),
                        now_ms,
                    ) {
                        Ok(_) => report.settled.push(exec.id.clone()),
                        Err(e) => report
                            .errors
                            .push((exec.id.clone(), format!("boot settle: {e}"))),
                    }
                } else {
                    let mut row = exec.clone();
                    row.state = ExecutionState::Released;
                    row.completed_at_ms = Some(now_ms);
                    if let Err(e) = self.store.update_execution(&row).await {
                        report.errors.push((exec.id.clone(), e.to_string()));
                        continue;
                    }
                    match self.ledger.release_execution(&ledger_id, now_ms) {
                        Ok(_) => report.released.push(exec.id.clone()),
                        Err(e) => report
                            .errors
                            .push((exec.id.clone(), format!("boot release: {e}"))),
                    }
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::BudgetDimension;
    use crate::store::MemoryStores;

    fn caps() -> Budget {
        Budget::new().set(BudgetDimension::Executions, 2)
    }

    fn one_exec() -> Budget {
        Budget::new().set(BudgetDimension::Executions, 1)
    }

    fn reserve<'a>(
        ledger: &'a BudgetLedger,
        store: &'a MemoryStores,
        lease: &str,
        action: &str,
        nonce: &str,
    ) -> (ExecutionDriver<'a>, crate::budget::ExecutionReservation) {
        let driver = ExecutionDriver::new(ledger, store);
        let r = ledger
            .reserve_execution(lease, action, &one_exec(), nonce, 1)
            .unwrap();
        (driver, r)
    }

    #[tokio::test]
    async fn driver_settle_full_lifecycle() {
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        ledger.register_lease("lease", &caps()).unwrap();
        let (driver, r) = reserve(&ledger, &store, "lease", "action-1", "nonce-1");
        driver.record_caps("lease", &caps()).await.unwrap();
        driver.persist_reservation(&r).await.unwrap();
        // Persisting twice is a no-op, not a conflict.
        driver.persist_reservation(&r).await.unwrap();

        let receipt = driver
            .settle(&r.id, &one_exec(), "settle-1", 2)
            .await
            .unwrap();
        assert_eq!(receipt.actual, one_exec());
        let stored = store.get_execution(&r.id).await.unwrap().unwrap();
        assert_eq!(stored.state, ExecutionState::Settled);
        assert_eq!(stored.actual, Some(one_exec()));
        // Budget is spent: one execution remains of two.
        assert_eq!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );

        // Idempotent retry: same key and actuals → same receipt.
        let again = driver
            .settle(&r.id, &one_exec(), "settle-1", 3)
            .await
            .unwrap();
        assert_eq!(receipt, again);
        // Same key, different actuals → conflict, fail closed.
        assert!(matches!(
            driver
                .settle(
                    &r.id,
                    &Budget::new().set(BudgetDimension::Executions, 2),
                    "settle-1",
                    4
                )
                .await,
            Err(BudgetError::IdempotencyConflict(_))
        ));
        ledger.check_invariants().unwrap();
    }

    #[tokio::test]
    async fn driver_release_returns_hold() {
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        ledger.register_lease("lease", &caps()).unwrap();
        let (driver, r) = reserve(&ledger, &store, "lease", "action-1", "nonce-1");
        driver.persist_reservation(&r).await.unwrap();

        let returned = driver.release(&r.id, 2).await.unwrap();
        assert_eq!(returned, one_exec());
        assert_eq!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            2
        );
        // Releasing twice is a no-op success; settling after release fails.
        assert_eq!(driver.release(&r.id, 3).await.unwrap(), one_exec());
        assert!(matches!(
            driver.settle(&r.id, &one_exec(), "settle-1", 4).await,
            Err(BudgetError::ExecutionNotHeld(_))
        ));
        ledger.check_invariants().unwrap();
    }

    #[tokio::test]
    async fn driver_settle_unknown_reservation_fails_closed() {
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        let driver = ExecutionDriver::new(&ledger, &store);
        assert!(matches!(
            driver.settle("exec_nope", &one_exec(), "k", 1).await,
            Err(BudgetError::UnknownReservation(_))
        ));
        assert!(matches!(
            driver.release("exec_nope", 1).await,
            Err(BudgetError::UnknownReservation(_))
        ));
    }

    #[tokio::test]
    async fn boot_reconcile_releases_incomplete_and_settles_completed() {
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        ledger.register_lease("lease", &caps()).unwrap();
        let driver = ExecutionDriver::new(&ledger, &store);
        driver.record_caps("lease", &caps()).await.unwrap();

        // Crash between persist and settle: two held reservations survive.
        let r1 = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        let r2 = ledger
            .reserve_execution("lease", "action-2", &one_exec(), "nonce-2", 1)
            .unwrap();
        driver.persist_reservation(&r1).await.unwrap();
        driver.persist_reservation(&r2).await.unwrap();

        // Simulate the crash: a fresh ledger, empty of everything.
        let fresh = BudgetLedger::new();
        let driver = ExecutionDriver::new(&fresh, &store);
        // The action log says action-1 dispatched, action-2 never did.
        let report = driver
            .reconcile_at_boot(&|action_id| action_id == "action-1", 10)
            .await
            .unwrap();
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
        assert_eq!(report.rehydrated_leases, 1);
        assert_eq!(report.settled, vec![r1.id.clone()]);
        assert_eq!(report.released, vec![r2.id.clone()]);

        // action-1 was charged its held estimate; action-2's hold returned.
        assert_eq!(
            fresh
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );
        let (_, _, exec_held, consumed) = fresh.account_summary("lease").unwrap();
        assert_eq!(exec_held.get(BudgetDimension::Executions), 0);
        assert_eq!(consumed.get(BudgetDimension::Executions), 1);
        fresh.check_invariants().unwrap();

        // Reconciliation is idempotent: running it again changes nothing.
        let report2 = driver
            .reconcile_at_boot(&|action_id| action_id == "action-1", 11)
            .await
            .unwrap();
        assert!(report2.settled.is_empty());
        assert!(report2.released.is_empty());
        assert!(report2.errors.is_empty());
        assert_eq!(
            fresh
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );
    }

    #[tokio::test]
    async fn boot_reconcile_reapplies_settled_consumption() {
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        ledger.register_lease("lease", &caps()).unwrap();
        let driver = ExecutionDriver::new(&ledger, &store);
        driver.record_caps("lease", &caps()).await.unwrap();
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        driver.persist_reservation(&r).await.unwrap();
        // Settle fully, then crash before any further work.
        driver
            .settle(&r.id, &one_exec(), "settle-1", 2)
            .await
            .unwrap();

        let fresh = BudgetLedger::new();
        let driver = ExecutionDriver::new(&fresh, &store);
        let report = driver.reconcile_at_boot(&|_| false, 10).await.unwrap();
        assert!(report.errors.is_empty());
        assert!(
            report.settled.is_empty(),
            "already settled: no double charge"
        );
        // The spent execution is still spent after the crash.
        assert_eq!(
            fresh
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );
        fresh.check_invariants().unwrap();
    }

    #[tokio::test]
    async fn boot_reconcile_missing_caps_reports_error() {
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        ledger.register_lease("lease", &caps()).unwrap();
        // Caps were never recorded: the reservation persists but the ledger
        // cannot be rebuilt without them.
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        store.insert_execution(&r).await.unwrap();

        let fresh = BudgetLedger::new();
        let driver = ExecutionDriver::new(&fresh, &store);
        let report = driver.reconcile_at_boot(&|_| false, 10).await.unwrap();
        assert_eq!(report.errors.len(), 1);
        assert!(report.errors[0].1.contains("no recorded caps"));
    }
}
