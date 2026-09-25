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

use std::collections::HashMap;

use crate::{
    budget::{Budget, BudgetError, BudgetLedger, DebitReceipt, ExecutionState},
    store::{BudgetStore, StoreError},
};

fn store_err(e: StoreError) -> BudgetError {
    BudgetError::Store(e.to_string())
}

/// Shared outcome for "the durable row is already settled": `Ok(())` when
/// `actual` matches the recorded receipt (idempotent replay), fail closed
/// with [`BudgetError::IdempotencyConflict`] otherwise.
fn check_settled_replay(
    stored: &crate::budget::ExecutionReservation,
    actual: &Budget,
    idempotency_key: &str,
) -> Result<(), BudgetError> {
    if stored.actual.as_ref() != Some(actual) {
        return Err(BudgetError::IdempotencyConflict(
            idempotency_key.to_string(),
        ));
    }
    Ok(())
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
    ///
    /// The store update is effectively conditional on the row being held:
    /// the SQL guard trigger aborts any update to a settled or released
    /// row, so two concurrent settles cannot both win. A settle that loses
    /// the race sees its update rejected, re-reads the authoritative row,
    /// and replays it — an idempotent settle of the same id returns `Ok`
    /// with the existing actuals, never an error.
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
                check_settled_replay(&stored, actual, idempotency_key)?;
            }
            ExecutionState::Held => {
                stored.state = ExecutionState::Settled;
                stored.actual = Some(actual.clone());
                stored.completed_at_ms = Some(now_ms);
                if let Err(update_err) = self.store.update_execution(&stored).await {
                    // Lost a race: a concurrent settle or release moved the
                    // row out of `held` between our read and our write. The
                    // SQL guard trigger aborts any update to a non-held row,
                    // so re-read the authoritative row and replay it instead
                    // of failing the idempotent settle.
                    stored = self
                        .store
                        .get_execution(reservation_id)
                        .await
                        .map_err(store_err)?
                        .ok_or_else(|| {
                            BudgetError::UnknownReservation(reservation_id.to_string())
                        })?;
                    match stored.state {
                        ExecutionState::Settled => {
                            check_settled_replay(&stored, actual, idempotency_key)?;
                        }
                        ExecutionState::Released => {
                            return Err(BudgetError::ExecutionNotHeld(reservation_id.to_string()));
                        }
                        ExecutionState::Held => {
                            // Still held: the update failed for a genuine
                            // backend reason, not a race. Fail closed with
                            // the original error.
                            return Err(store_err(update_err));
                        }
                    }
                }
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

    /// Register `lease_id` with `caps` unless the ledger already holds an
    /// account for it. Never resets an existing account, so repeated
    /// reconciliations — and a race with a live registration — cannot wipe
    /// the books. Counts the lease as rehydrated only when this call
    /// registered it.
    fn register_if_absent(
        &self,
        lease_id: &str,
        caps: &Budget,
        report: &mut BootReconciliation,
    ) -> Result<(), StoreError> {
        if self.ledger.is_lease_registered(lease_id) {
            return Ok(());
        }
        match self.ledger.register_lease(lease_id, caps) {
            Ok(()) => {
                report.rehydrated_leases += 1;
                Ok(())
            }
            // Lost a race with a live registration between the check and
            // the insert: the account exists, which is what we wanted.
            Err(BudgetError::DuplicateLease(_)) => Ok(()),
            Err(e) => Err(StoreError::Backend(e.to_string())),
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
    ///
    /// Active child-lease reservations are rehydrated too: each parent's
    /// `reserved_out` hold is restored with the reservation's recorded
    /// consumption, and parents that have reservations but no executions
    /// are registered — otherwise a restart would zero their outstanding
    /// holds and let the parent over-reserve.
    ///
    /// Safe to run repeatedly on the same ledger: leases register only when
    /// absent, reservations rehydrate idempotently, and the `boot:{id}`
    /// debit keys dedupe re-applied consumption. Must still run at boot,
    /// before live traffic: it is not designed to race live authorizations.
    pub async fn reconcile_at_boot(
        &self,
        is_completed: &dyn Fn(&str) -> bool,
        now_ms: i64,
    ) -> Result<BootReconciliation, StoreError> {
        let mut report = BootReconciliation::default();
        // Child-lease reservations first: restore the parents' outstanding
        // holds before execution rehydration debits anything.
        for res in self.store.active_reservations().await? {
            let parent_caps = match self.store.lease_caps(&res.parent_lease_id).await? {
                Some(c) => c,
                None => {
                    report.errors.push((
                        res.id.clone(),
                        format!("no recorded caps for parent lease {}", res.parent_lease_id),
                    ));
                    continue;
                }
            };
            if let Err(e) = self.register_if_absent(&res.parent_lease_id, &parent_caps, &mut report)
            {
                report
                    .errors
                    .push((res.id.clone(), format!("register parent: {e}")));
                continue;
            }
            // The child's caps are exactly its held maximum: mint registers
            // the child account with the reserved budget.
            if let Err(e) = self.register_if_absent(&res.child_lease_id, &res.held, &mut report) {
                report
                    .errors
                    .push((res.id.clone(), format!("register child: {e}")));
                continue;
            }
            if let Err(e) = self.ledger.rehydrate_reservation(&res) {
                report
                    .errors
                    .push((res.id.clone(), format!("rehydrate reservation: {e}")));
            }
        }
        let mut by_lease: HashMap<String, Vec<crate::budget::ExecutionReservation>> =
            HashMap::new();
        for exec in self.store.all_executions().await? {
            by_lease
                .entry(exec.lease_id.clone())
                .or_default()
                .push(exec);
        }
        for (lease_id, execs) in &by_lease {
            // Register only when the ledger has no account for the lease:
            // repeated runs must not reset existing books. A lease already
            // rehydrated from its reservations keeps those caps; recorded
            // caps are consulted only for genuinely unknown leases.
            if !self.ledger.is_lease_registered(lease_id) {
                match self.store.lease_caps(lease_id).await? {
                    Some(caps) => {
                        if let Err(e) = self.register_if_absent(lease_id, &caps, &mut report) {
                            for exec in execs {
                                report
                                    .errors
                                    .push((exec.id.clone(), format!("register lease: {e}")));
                            }
                            continue;
                        }
                    }
                    None => {
                        for exec in execs {
                            report.errors.push((
                                exec.id.clone(),
                                format!("no recorded caps for lease {lease_id}"),
                            ));
                        }
                        continue;
                    }
                }
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
            // Held rows: settle or release based on the action log. The
            // pre-crash hold died with the crashed process, so the fresh
            // ledger never held it — no re-reserve is needed. Completed
            // actions charge the held estimate through the same
            // `boot:{id}` debit key the settled-row path uses; the key must
            // match, otherwise a second reconciliation would charge the
            // execution twice (the old `boot-settle:{id}` key lived in the
            // settle idempotency map, invisible to this path's debit map).
            for exec in execs.iter().filter(|e| e.state == ExecutionState::Held) {
                if is_completed(&exec.action_id) {
                    let mut row = exec.clone();
                    row.state = ExecutionState::Settled;
                    row.actual = Some(exec.held.clone());
                    row.completed_at_ms = Some(now_ms);
                    if let Err(e) = self.store.update_execution(&row).await {
                        report.errors.push((exec.id.clone(), e.to_string()));
                        continue;
                    }
                    match self.ledger.debit_lease(
                        lease_id,
                        &exec.held,
                        &format!("boot:{}", exec.id),
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
                    report.released.push(exec.id.clone());
                }
            }
        }
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::budget::{BudgetDimension, Reservation};
    use crate::store::MemoryStores;
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    fn caps() -> Budget {
        Budget::new().set(BudgetDimension::Executions, 2)
    }

    fn one_exec() -> Budget {
        Budget::new().set(BudgetDimension::Executions, 1)
    }

    fn micros(n: u64) -> Budget {
        Budget::new().set(BudgetDimension::SpendMicros, n)
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

        // A third run must not resurrect spent budget either: the account is
        // not reset (register-if-absent) and the boot debit keys dedupe the
        // re-applied consumption.
        let report3 = driver
            .reconcile_at_boot(&|action_id| action_id == "action-1", 12)
            .await
            .unwrap();
        assert!(report3.settled.is_empty());
        assert!(report3.released.is_empty());
        assert!(report3.errors.is_empty());
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

    #[tokio::test]
    async fn boot_reconcile_restores_child_reservation_holds() {
        // A parent whose budget is held for active children — but which has
        // no executions of its own — must still be rehydrated: otherwise a
        // restart zeroes its reserved_out and it can over-reserve.
        let ledger = BudgetLedger::new();
        let store = MemoryStores::default();
        let parent_caps = micros(100);
        let child_max = micros(60);
        ledger.register_lease("parent", &parent_caps).unwrap();
        let res = ledger.reserve("parent", "child", &child_max, 1).unwrap();
        ledger.register_lease("child", &child_max).unwrap();
        ledger.debit(&res.id, &micros(25), "key-1", 2).unwrap();

        // Persist the durable side: caps plus the active reservation row
        // with its recorded consumption.
        let driver = ExecutionDriver::new(&ledger, &store);
        driver.record_caps("parent", &parent_caps).await.unwrap();
        driver.record_caps("child", &child_max).await.unwrap();
        let live: Vec<Reservation> = ledger.active_reservations();
        assert_eq!(live.len(), 1);
        store.insert_reservation(&live[0]).await.unwrap();

        // Crash: a fresh ledger, empty of everything.
        let fresh = BudgetLedger::new();
        let driver = ExecutionDriver::new(&fresh, &store);
        let report = driver.reconcile_at_boot(&|_| false, 10).await.unwrap();
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);

        // The parent's hold survived the restart: 40 remains, and the
        // reservation — with its recorded 25 consumption — is back.
        assert_eq!(
            fresh
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        let rehydrated = fresh.active_reservations();
        assert_eq!(rehydrated.len(), 1);
        assert_eq!(rehydrated[0].child_lease_id, "child");
        assert_eq!(rehydrated[0].consumed.get(BudgetDimension::SpendMicros), 25);
        // The child account is back too, with its held maximum as caps.
        assert!(fresh.is_lease_registered("child"));

        // Reconciliation is idempotent for reservations: a second run does
        // not double-count the hold.
        let report2 = driver.reconcile_at_boot(&|_| false, 11).await.unwrap();
        assert!(report2.errors.is_empty());
        assert_eq!(
            fresh
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            40
        );
        assert_eq!(fresh.active_reservations().len(), 1);

        // Releasing now charges the recorded consumption to the parent:
        // 100 - 25 = 75 remaining (conservation across the crash).
        let returned = fresh.release(&rehydrated[0].id, 12).unwrap();
        assert_eq!(returned.get(BudgetDimension::SpendMicros), 35);
        assert_eq!(
            fresh
                .remaining("parent")
                .unwrap()
                .get(BudgetDimension::SpendMicros),
            75
        );
        fresh.check_invariants().unwrap();
    }

    /// Test double over [`MemoryStores`] that deterministically simulates a
    /// concurrent settle winning the race: the first `update_execution`
    /// applies the winner's held→settled transition out-of-band, then
    /// rejects the caller's own update exactly as the SQL guard trigger
    /// would (the row is no longer held).
    #[derive(Clone)]
    struct RaceLoserStore {
        inner: MemoryStores,
        winner_actual: Budget,
        raced: Arc<AtomicBool>,
    }

    impl RaceLoserStore {
        fn new(winner_actual: Budget) -> Self {
            Self {
                inner: MemoryStores::default(),
                winner_actual,
                raced: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    #[async_trait]
    impl BudgetStore for RaceLoserStore {
        async fn update_execution(
            &self,
            reservation: &crate::budget::ExecutionReservation,
        ) -> Result<(), StoreError> {
            if !self.raced.swap(true, Ordering::SeqCst) {
                let mut winner = self
                    .inner
                    .get_execution(&reservation.id)
                    .await?
                    .ok_or_else(|| StoreError::NotFound(reservation.id.clone()))?;
                winner.state = ExecutionState::Settled;
                winner.actual = Some(self.winner_actual.clone());
                winner.completed_at_ms = Some(99);
                self.inner.update_execution(&winner).await?;
                // The caller's own update now hits a settled row: the guard
                // trigger aborts it.
                return Err(StoreError::Backend(
                    "illegal execution reservation mutation".to_string(),
                ));
            }
            self.inner.update_execution(reservation).await
        }

        async fn insert_reservation(&self, reservation: &Reservation) -> Result<(), StoreError> {
            self.inner.insert_reservation(reservation).await
        }

        async fn get_reservation(&self, id: &str) -> Result<Option<Reservation>, StoreError> {
            self.inner.get_reservation(id).await
        }

        async fn update_reservation(&self, reservation: &Reservation) -> Result<(), StoreError> {
            self.inner.update_reservation(reservation).await
        }

        async fn active_reservations(&self) -> Result<Vec<Reservation>, StoreError> {
            self.inner.active_reservations().await
        }

        async fn insert_debit(
            &self,
            debit_id: &str,
            reservation_id: &str,
            idempotency_key: &str,
            actual: &Budget,
            at_ms: i64,
        ) -> Result<(), StoreError> {
            self.inner
                .insert_debit(debit_id, reservation_id, idempotency_key, actual, at_ms)
                .await
        }

        async fn find_debit_by_key(
            &self,
            idempotency_key: &str,
        ) -> Result<Option<DebitReceipt>, StoreError> {
            self.inner.find_debit_by_key(idempotency_key).await
        }

        async fn record_lease_caps(&self, lease_id: &str, caps: &Budget) -> Result<(), StoreError> {
            self.inner.record_lease_caps(lease_id, caps).await
        }

        async fn lease_caps(&self, lease_id: &str) -> Result<Option<Budget>, StoreError> {
            self.inner.lease_caps(lease_id).await
        }

        async fn insert_execution(
            &self,
            reservation: &crate::budget::ExecutionReservation,
        ) -> Result<(), StoreError> {
            self.inner.insert_execution(reservation).await
        }

        async fn get_execution(
            &self,
            id: &str,
        ) -> Result<Option<crate::budget::ExecutionReservation>, StoreError> {
            self.inner.get_execution(id).await
        }

        async fn all_executions(
            &self,
        ) -> Result<Vec<crate::budget::ExecutionReservation>, StoreError> {
            self.inner.all_executions().await
        }
    }

    #[tokio::test]
    async fn driver_settle_losing_race_replays_receipt() {
        // Two concurrent settles, same actuals: the loser's update is
        // rejected by the guard, but the idempotent settle still returns Ok
        // with the existing actuals — not an error.
        let ledger = BudgetLedger::new();
        let store = RaceLoserStore::new(one_exec());
        ledger.register_lease("lease", &caps()).unwrap();
        let driver = ExecutionDriver::new(&ledger, &store);
        driver.record_caps("lease", &caps()).await.unwrap();
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        driver.persist_reservation(&r).await.unwrap();

        let receipt = driver
            .settle(&r.id, &one_exec(), "settle-1", 2)
            .await
            .unwrap();
        assert_eq!(receipt.reservation_id, r.id);
        assert_eq!(receipt.actual, one_exec());
        let stored = store.get_execution(&r.id).await.unwrap().unwrap();
        assert_eq!(stored.state, ExecutionState::Settled);
        assert_eq!(stored.actual, Some(one_exec()));
        // The ledger charged exactly once: one execution remains of two.
        assert_eq!(
            ledger
                .remaining("lease")
                .unwrap()
                .get(BudgetDimension::Executions),
            1
        );
        ledger.check_invariants().unwrap();
    }

    #[tokio::test]
    async fn driver_settle_losing_race_with_conflict_fails_closed() {
        // Same race, but the winner settled different actuals: fail closed
        // with a conflict, never silently accept the mismatch.
        let ledger = BudgetLedger::new();
        let store = RaceLoserStore::new(Budget::new().set(BudgetDimension::Executions, 2));
        ledger.register_lease("lease", &caps()).unwrap();
        let driver = ExecutionDriver::new(&ledger, &store);
        let r = ledger
            .reserve_execution("lease", "action-1", &one_exec(), "nonce-1", 1)
            .unwrap();
        driver.persist_reservation(&r).await.unwrap();

        assert!(matches!(
            driver.settle(&r.id, &one_exec(), "settle-1", 2).await,
            Err(BudgetError::IdempotencyConflict(_))
        ));
        // The loser's actuals were not applied anywhere: the durable row
        // keeps the winner's receipt and the ledger still holds the
        // reservation.
        let stored = store.get_execution(&r.id).await.unwrap().unwrap();
        assert_eq!(
            stored.actual,
            Some(Budget::new().set(BudgetDimension::Executions, 2))
        );
        assert_eq!(
            ledger.get_execution(&r.id).unwrap().state,
            ExecutionState::Held
        );
    }
}
