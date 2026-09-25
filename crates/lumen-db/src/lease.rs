//! Durable authority-kernel persistence (migration 0022).
//!
//! This module is the SQL counterpart of the kernel's in-memory authorities:
//! signed leases, revocations, nonces, one-shot uses, the reservation-based
//! budget ledger, and the hash-chained audit log. Every balance-changing
//! operation runs in a single SQLite transaction that re-checks the
//! invariants in SQL — the database never trusts the caller's arithmetic, so
//! a crashed or buggy host cannot overspend through this layer.

use std::collections::HashSet;
use std::time::Duration;

use lumen_core::{
    budget::{
        Budget, DebitReceipt, ExecutionReservation, ExecutionState, Reservation, ReservationState,
    },
    identity::WorkspaceId,
    kernel_audit::{
        AuditLink, GENESIS_PREV_HASH, actor_to_string, parse_actor, render_detail, seal_event,
        verify_event_chain,
    },
    lease::{LeaseDocument, LeaseLimits},
    pi_boundary::{AUDIT_EVENT_VERSION, AuditEvent, AuditEventKind},
};
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::{Database, RepositoryError};

fn ws(workspace_id: &WorkspaceId) -> String {
    workspace_id.to_string()
}

fn budget_json(b: &Budget) -> Result<String, RepositoryError> {
    serde_json::to_string(b).map_err(RepositoryError::Serialization)
}

fn parse_budget(s: &str) -> Result<Budget, RepositoryError> {
    serde_json::from_str(s).map_err(RepositoryError::Serialization)
}

fn insufficient(what: &str) -> RepositoryError {
    RepositoryError::KernelBudgetInsufficient(what.to_string())
}

fn execution_state_str(state: ExecutionState) -> &'static str {
    match state {
        ExecutionState::Held => "held",
        ExecutionState::Settled => "settled",
        ExecutionState::Released => "released",
    }
}

fn parse_execution_state(s: &str) -> Result<ExecutionState, RepositoryError> {
    match s {
        "held" => Ok(ExecutionState::Held),
        "settled" => Ok(ExecutionState::Settled),
        "released" => Ok(ExecutionState::Released),
        other => Err(RepositoryError::InvalidKernelLeaseState(format!(
            "unknown execution state {other}"
        ))),
    }
}

fn parse_execution_row(
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ExecutionReservation, RepositoryError> {
    let actual_json: Option<String> = row.get("actual_json");
    Ok(ExecutionReservation {
        id: row.get("id"),
        lease_id: row.get("lease_id"),
        action_id: row.get("action_id"),
        held: parse_budget(row.get::<String, _>("held_json").as_str())?,
        state: parse_execution_state(row.get::<String, _>("state").as_str())?,
        idempotency_key: row.get("idempotency_key"),
        created_at_ms: row.get("created_at_ms"),
        completed_at_ms: row.get("completed_at_ms"),
        actual: actual_json.as_deref().map(parse_budget).transpose()?,
    })
}

impl Database {
    // ------------------------------------------------------------------
    // Leases
    // ------------------------------------------------------------------

    /// Persist a signed lease document. The scope digest is recomputed and
    /// compared before insert: a serialization bug fails closed here rather
    /// than poisoning the durable record.
    pub async fn insert_kernel_lease(
        &self,
        workspace_id: &WorkspaceId,
        doc: &LeaseDocument,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        insert_lease_tx(&mut tx, workspace_id, doc).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Insert a lease row and register its budget account in ONE
    /// transaction. A crash can never leave a lease without its budget
    /// account (an unbacked budget) or an account without its lease.
    /// Prefer this over `insert_kernel_lease` + `register_kernel_budget`
    /// whenever the caller mints the lease.
    pub async fn insert_kernel_lease_with_budget(
        &self,
        workspace_id: &WorkspaceId,
        doc: &LeaseDocument,
        now_ms: i64,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        insert_lease_tx(&mut tx, workspace_id, doc).await?;
        register_budget_tx(
            &mut tx,
            workspace_id,
            &doc.lease_id,
            &doc.limits.budget,
            now_ms,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Atomically claim a VHL approval and persist its minted one-shot
    /// lease: the grant-nonce replay gate, the `approved → minted`
    /// compare-and-swap (recording the minted lease id), and the lease +
    /// budget-account insert commit in ONE transaction.
    ///
    /// This is the durable boundary for one-shot minting. Either the
    /// approval is claimed AND the lease is durable, or nothing happened:
    /// the approval stays `approved`, the grant nonce is unburned, and a
    /// retry is safe. A crash can never leave a claimed approval without
    /// its lease, a lease without its approval claim, or a burned nonce
    /// for a lease that was never minted.
    pub async fn claim_approval_and_insert_one_shot(
        &self,
        workspace_id: &WorkspaceId,
        approval_id: &str,
        grant_nonce: &str,
        now_ms: i64,
        nonce_expires_at_ms: i64,
        doc: &LeaseDocument,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        // 1. Grant-nonce replay gate (durable). A replay means this grant
        //    was already presented: the approval must already be claimed
        //    (or the first attempt is still in flight, which the state
        //    guard below will serialize).
        let nonce_rows = sqlx::query(
            "INSERT OR IGNORE INTO kernel_nonces(workspace_id,nonce,used_at_ms,expires_at_ms)
             VALUES(?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(grant_nonce)
        .bind(now_ms)
        .bind(nonce_expires_at_ms)
        .execute(&mut *tx)
        .await?;
        if nonce_rows.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(RepositoryError::VhlStateConflict);
        }
        // 2. The minted lease and its budget account, together. Inserted
        //    BEFORE the approval claim because
        //    `vhl_approval_requests.lease_id` FK-references
        //    `kernel_leases(lease_id)`: claiming first would violate the
        //    foreign key. All four steps commit atomically, so a failed
        //    claim below rolls the lease back — no orphan is possible.
        insert_lease_tx(&mut tx, workspace_id, doc).await?;
        register_budget_tx(
            &mut tx,
            workspace_id,
            &doc.lease_id,
            &doc.limits.budget,
            now_ms,
        )
        .await?;
        // 3. Claim the approval. The state guard trigger enforces the
        //    `approved → minted` edge; zero rows means it was already
        //    claimed (or never approved).
        let claim_rows = sqlx::query(
            "UPDATE vhl_approval_requests SET state='minted',lease_id=?,minted_at_ms=?
             WHERE workspace_id=? AND request_id=? AND state='approved'",
        )
        .bind(&doc.lease_id)
        .bind(now_ms)
        .bind(ws(workspace_id))
        .bind(approval_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(db) if db.message().contains("illegal state transition") => {
                RepositoryError::VhlStateConflict
            }
            other => RepositoryError::from(other),
        })?;
        if claim_rows.rows_affected() != 1 {
            tx.rollback().await?;
            return Err(RepositoryError::VhlStateConflict);
        }
        tx.commit().await?;
        Ok(())
    }

    /// Mint a child lease durably in a single transaction: the child lease
    /// row, the parent's budget reservation, and the child's budget account
    /// commit together. A crash can never leave a child lease without its
    /// reservation (an unbacked budget) or a reservation without its lease.
    ///
    /// The child's budget caps are its declared limits; the reservation
    /// holds exactly those limits against the parent. Fails closed when the
    /// parent cannot cover the limits, when the document is not a child
    /// (no parent id), or when any digest check fails. Returns the
    /// reservation id.
    pub async fn mint_kernel_child_lease(
        &self,
        workspace_id: &WorkspaceId,
        doc: &LeaseDocument,
        now_ms: i64,
    ) -> Result<String, RepositoryError> {
        let parent_id = doc.parent_id.clone().ok_or_else(|| {
            RepositoryError::InvalidKernelLeaseState(
                "mint_kernel_child_lease requires a child document with a parent id".to_string(),
            )
        })?;
        let mut tx = self.pool().begin().await?;
        insert_lease_tx(&mut tx, workspace_id, doc).await?;
        let reservation_id = reserve_budget_tx(
            &mut tx,
            workspace_id,
            &parent_id,
            &doc.lease_id,
            &doc.limits.budget,
            now_ms,
        )
        .await?;
        register_budget_tx(
            &mut tx,
            workspace_id,
            &doc.lease_id,
            &doc.limits.budget,
            now_ms,
        )
        .await?;
        tx.commit().await?;
        Ok(reservation_id)
    }

    pub async fn kernel_lease(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
    ) -> Result<Option<LeaseDocument>, RepositoryError> {
        let row = sqlx::query(
            "SELECT lease_id,parent_id,subject,issuer_key_id,issued_at_ms,protocol_version,
             scope_json,limits_json,depth,depth_limit,lease_nonce,signature,approved_action_digest
             FROM kernel_leases WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| lease_from_row(&r)).transpose()
    }

    /// Load a full chain, leaf first, following parent links (max 128 hops).
    ///
    /// Fails closed when traversal does not reach a root within 128 hops
    /// (a cycle, or a chain deeper than the protocol supports): returning a
    /// truncated chain would let a caller validate against the wrong anchor.
    pub async fn kernel_lease_chain(
        &self,
        workspace_id: &WorkspaceId,
        leaf_id: &str,
    ) -> Result<Vec<LeaseDocument>, RepositoryError> {
        let mut chain = Vec::new();
        let mut current = leaf_id.to_string();
        for _ in 0..128 {
            let doc = self
                .kernel_lease(workspace_id, &current)
                .await?
                .ok_or_else(|| {
                    RepositoryError::InvalidKernelLeaseState(format!("missing lease {current}"))
                })?;
            let parent = doc.parent_id.clone();
            chain.push(doc);
            match parent {
                Some(p) => current = p,
                None => return Ok(chain),
            }
        }
        Err(RepositoryError::InvalidKernelLeaseState(format!(
            "lease chain for {leaf_id} exceeds 128 hops"
        )))
    }

    // ------------------------------------------------------------------
    // Revocations
    // ------------------------------------------------------------------

    /// Lease ids whose subject is exactly `subject`, in issue order.
    /// Used by session termination to revoke every lease a destroyed
    /// identity (or its vault-known descendants) could present.
    pub async fn kernel_lease_ids_for_subject(
        &self,
        workspace_id: &WorkspaceId,
        subject: &str,
    ) -> Result<Vec<String>, RepositoryError> {
        let ids: Vec<String> = sqlx::query_scalar(
            "SELECT lease_id FROM kernel_leases WHERE workspace_id=? AND subject=? ORDER BY issued_at_ms",
        )
        .bind(ws(workspace_id))
        .bind(subject)
        .fetch_all(self.pool())
        .await?;
        Ok(ids)
    }

    /// (lease_id, budget caps) for every lease in the workspace. Used at
    /// kernel startup to hydrate the in-memory [`BudgetLedger`] so budget
    /// admission checks keep working across restarts. Consumed spend is
    /// not tracked (there is no settle path yet); hydration starts every
    /// account at zero consumption.
    pub async fn kernel_lease_budgets(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<(String, Budget)>, RepositoryError> {
        let rows: Vec<(String, String)> =
            sqlx::query_as("SELECT lease_id, limits_json FROM kernel_leases WHERE workspace_id=?")
                .bind(ws(workspace_id))
                .fetch_all(self.pool())
                .await?;
        rows.into_iter()
            .map(|(lease_id, limits_json)| {
                let limits: LeaseLimits =
                    serde_json::from_str(&limits_json).map_err(RepositoryError::Serialization)?;
                Ok((lease_id, limits.budget))
            })
            .collect()
    }

    /// Record a revocation. Idempotent: revoking twice is a no-op.
    pub async fn record_kernel_revocation(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        at_ms: i64,
        reason: &str,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT OR IGNORE INTO kernel_revocations(lease_id,workspace_id,revoked_at_ms,reason)
             VALUES(?,?,?,?)",
        )
        .bind(lease_id)
        .bind(ws(workspace_id))
        .bind(at_ms)
        .bind(reason)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn is_kernel_revoked(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
    ) -> Result<bool, RepositoryError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_revocations WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_one(self.pool())
        .await?;
        Ok(n > 0)
    }

    pub async fn kernel_revoked_ids(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<HashSet<String>, RepositoryError> {
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT lease_id FROM kernel_revocations WHERE workspace_id=?")
                .bind(ws(workspace_id))
                .fetch_all(self.pool())
                .await?;
        Ok(ids.into_iter().collect())
    }

    // ------------------------------------------------------------------
    // Nonces
    // ------------------------------------------------------------------

    /// Record a nonce. Returns `true` if newly recorded, `false` on replay.
    pub async fn record_kernel_nonce(
        &self,
        workspace_id: &WorkspaceId,
        nonce: &str,
        used_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<bool, RepositoryError> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO kernel_nonces(workspace_id,nonce,used_at_ms,expires_at_ms)
             VALUES(?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(nonce)
        .bind(used_at_ms)
        .bind(expires_at_ms)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Purge expired nonces. Only rows with `expires_at_ms < now_ms` are
    /// deleted; live replay protection is never touched.
    pub async fn purge_kernel_nonces(
        &self,
        workspace_id: &WorkspaceId,
        now_ms: i64,
    ) -> Result<u64, RepositoryError> {
        let res = sqlx::query("DELETE FROM kernel_nonces WHERE workspace_id=? AND expires_at_ms<?")
            .bind(ws(workspace_id))
            .bind(now_ms)
            .execute(self.pool())
            .await?;
        Ok(res.rows_affected())
    }

    // ------------------------------------------------------------------
    // One-shot uses
    // ------------------------------------------------------------------

    /// Consume a one-shot lease. Returns `true` if newly consumed, `false`
    /// if this is a replay (no second effect).
    pub async fn consume_kernel_one_shot(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        at_ms: i64,
    ) -> Result<bool, RepositoryError> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO kernel_one_shot_uses(lease_id,workspace_id,consumed_at_ms)
             VALUES(?,?,?)",
        )
        .bind(lease_id)
        .bind(ws(workspace_id))
        .bind(at_ms)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() == 1)
    }

    pub async fn is_kernel_one_shot_consumed(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
    ) -> Result<bool, RepositoryError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_one_shot_uses WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_one(self.pool())
        .await?;
        Ok(n > 0)
    }

    /// Consume a one-shot lease and durably record the authorization outcome
    /// in a single transaction: the consumption row and the audit event
    /// commit together, so a crash can never leave a consumed lease without
    /// its audit trail, nor an audit "allow" for a lease that was not
    /// consumed.
    ///
    /// Returns `(consumed, event)`: `consumed` is true when this call
    /// performed the consumption, false on replay. The `on_consumed` audit
    /// parameters describe the allow event; `on_replay` the deny event, so
    /// every authorization attempt is audited exactly once, atomically tied
    /// to its outcome. A bounded retry loop resolves audit-sequence races
    /// with concurrent writers.
    pub async fn consume_kernel_one_shot_and_audit(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        on_consumed: &KernelAuditAppend<'_>,
        on_replay: &KernelAuditAppend<'_>,
    ) -> Result<(bool, AuditEvent), RepositoryError> {
        for attempt in 0..AUDIT_APPEND_RETRIES {
            let mut tx = self.pool().begin().await?;
            let res = sqlx::query(
                "INSERT OR IGNORE INTO kernel_one_shot_uses(lease_id,workspace_id,consumed_at_ms)
                 VALUES(?,?,?)",
            )
            .bind(lease_id)
            .bind(ws(workspace_id))
            .bind(on_consumed.timestamp_ms)
            .execute(&mut *tx)
            .await?;
            // The consumption row is idempotent, so retrying a rolled-back
            // attempt is safe: a rolled-back INSERT OR IGNORE left no row.
            let consumed = res.rows_affected() == 1;
            let params = if consumed { on_consumed } else { on_replay };
            match append_audit_attempt(&mut tx, workspace_id, params).await {
                Ok(event) => {
                    tx.commit().await?;
                    return Ok((consumed, event));
                }
                Err(e) if is_retryable(&e) => {
                    audit_retry_backoff(attempt).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(RepositoryError::KernelAuditBreak(
            "one-shot consume lost too many audit sequence races".to_string(),
        ))
    }

    // ------------------------------------------------------------------
    // Budget ledger (transactional)
    // ------------------------------------------------------------------

    /// Register a lease's budget caps. Called once at mint; re-registering
    /// the same lease is a conflict (fail closed).
    pub async fn register_kernel_budget(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        caps: &Budget,
        now_ms: i64,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        register_budget_tx(&mut tx, workspace_id, lease_id, caps, now_ms).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Reserve `requested` against the parent's remaining balance, atomically.
    /// Returns the reservation id. Fails closed on insufficient balance.
    pub async fn reserve_kernel_budget(
        &self,
        workspace_id: &WorkspaceId,
        parent_lease_id: &str,
        child_lease_id: &str,
        requested: &Budget,
        now_ms: i64,
    ) -> Result<String, RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let id = reserve_budget_tx(
            &mut tx,
            workspace_id,
            parent_lease_id,
            child_lease_id,
            requested,
            now_ms,
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Debit actual usage against a reservation, atomically and idempotently.
    /// Repeating the same idempotency key returns the original receipt;
    /// reusing a key with different parameters is a conflict.
    pub async fn debit_kernel_budget(
        &self,
        workspace_id: &WorkspaceId,
        reservation_id: &str,
        actual: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<DebitReceipt, RepositoryError> {
        let pool = self.pool();
        let mut tx = pool.begin().await?;
        if let Some(existing) = sqlx::query(
            "SELECT reservation_id,amounts_json,debited_at_ms FROM kernel_debits
             WHERE workspace_id=? AND idempotency_key=?",
        )
        .bind(ws(workspace_id))
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            let prev_res: String = existing.get("reservation_id");
            let prev_amounts = parse_budget(existing.get::<String, _>("amounts_json").as_str())?;
            if prev_res == reservation_id && prev_amounts == *actual {
                let at: i64 = existing.get("debited_at_ms");
                tx.commit().await?;
                return Ok(DebitReceipt {
                    reservation_id: reservation_id.to_string(),
                    actual: actual.clone(),
                    debited_at_ms: at,
                });
            }
            return Err(RepositoryError::KernelDebitConflict);
        }
        let row = sqlx::query(
            "SELECT parent_lease_id,child_lease_id,held_json,consumed_json,state
             FROM kernel_reservations WHERE workspace_id=? AND reservation_id=?",
        )
        .bind(ws(workspace_id))
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RepositoryError::KernelReservationConflict)?;
        if row.get::<String, _>("state") != "active" {
            return Err(RepositoryError::KernelReservationConflict);
        }
        let parent_lease_id: String = row.get("parent_lease_id");
        let child_lease_id: String = row.get("child_lease_id");
        let held = parse_budget(row.get::<String, _>("held_json").as_str())?;
        let consumed = parse_budget(row.get::<String, _>("consumed_json").as_str())?;
        let available = held.saturating_sub(&consumed);
        if !available.covers(actual) {
            return Err(insufficient(&format!(
                "debit exceeds held amount on reservation {reservation_id}"
            )));
        }
        sqlx::query(
            "INSERT INTO kernel_debits(workspace_id,idempotency_key,reservation_id,
             amounts_json,debited_at_ms) VALUES(?,?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(idempotency_key)
        .bind(reservation_id)
        .bind(budget_json(actual)?)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
        let new_consumed = consumed
            .checked_add(actual)
            .ok_or_else(|| insufficient("reservation consumed overflow"))?;
        sqlx::query(
            "UPDATE kernel_reservations SET consumed_json=?
             WHERE workspace_id=? AND reservation_id=?",
        )
        .bind(budget_json(&new_consumed)?)
        .bind(ws(workspace_id))
        .bind(reservation_id)
        .execute(&mut *tx)
        .await?;
        // The spend moves from the parent's reserved_out to its consumed,
        // counted exactly once (see post_parent_debit_tx).
        post_parent_debit_tx(&mut tx, workspace_id, &parent_lease_id, actual, now_ms).await?;
        // Mirror the spend into the child's own budget account when the
        // mint flow registered one: otherwise the child's remaining would
        // overstate its budget after a reservation-side debit, weakening
        // the child's own caps.
        if child_lease_id != parent_lease_id
            && let Some(child_acct) = sqlx::query(
                "SELECT caps_json,reserved_out_json,consumed_json FROM kernel_budget_accounts
                 WHERE workspace_id=? AND lease_id=?",
            )
            .bind(ws(workspace_id))
            .bind(&child_lease_id)
            .fetch_optional(&mut *tx)
            .await?
        {
            let child_caps = parse_budget(child_acct.get::<String, _>("caps_json").as_str())?;
            let child_reserved =
                parse_budget(child_acct.get::<String, _>("reserved_out_json").as_str())?;
            let child_consumed =
                parse_budget(child_acct.get::<String, _>("consumed_json").as_str())?;
            let child_remaining = child_caps
                .saturating_sub(&child_reserved)
                .saturating_sub(&child_consumed);
            if !child_remaining.covers(actual) {
                return Err(insufficient(&format!(
                    "child lease {child_lease_id} cannot cover debit"
                )));
            }
            let child_new = child_consumed
                .checked_add(actual)
                .ok_or_else(|| insufficient("child account consumed overflow"))?;
            sqlx::query(
                "UPDATE kernel_budget_accounts SET consumed_json=?,updated_at=?
                 WHERE workspace_id=? AND lease_id=?",
            )
            .bind(budget_json(&child_new)?)
            .bind(now_ms)
            .bind(ws(workspace_id))
            .bind(&child_lease_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(DebitReceipt {
            reservation_id: reservation_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        })
    }

    /// Debit spend directly against a lease's own caps (root-lease spend).
    ///
    /// When the lease is a reservation-backed child, the spend is posted to
    /// the reservation ledger atomically as well: the active reservation's
    /// consumed grows and the parent's reserved_out/consumed move with it.
    /// Without this, release_kernel_budget would refund spend that already
    /// happened, double-spending the parent's budget.
    pub async fn debit_kernel_lease(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        actual: &Budget,
        idempotency_key: &str,
        now_ms: i64,
    ) -> Result<DebitReceipt, RepositoryError> {
        let pool = self.pool();
        let mut tx = pool.begin().await?;
        if let Some(existing) = sqlx::query(
            "SELECT lease_id_link,amounts_json,debited_at_ms FROM kernel_lease_debits
             WHERE workspace_id=? AND idempotency_key=?",
        )
        .bind(ws(workspace_id))
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await?
        {
            let prev_lease: String = existing.get("lease_id_link");
            let prev_amounts = parse_budget(existing.get::<String, _>("amounts_json").as_str())?;
            if prev_lease == lease_id && prev_amounts == *actual {
                let at: i64 = existing.get("debited_at_ms");
                tx.commit().await?;
                return Ok(DebitReceipt {
                    reservation_id: lease_id.to_string(),
                    actual: actual.clone(),
                    debited_at_ms: at,
                });
            }
            return Err(RepositoryError::KernelDebitConflict);
        }
        let row = sqlx::query(
            "SELECT caps_json,reserved_out_json,consumed_json FROM kernel_budget_accounts
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| insufficient(&format!("unknown lease {lease_id}")))?;
        let caps = parse_budget(row.get::<String, _>("caps_json").as_str())?;
        let reserved_out = parse_budget(row.get::<String, _>("reserved_out_json").as_str())?;
        let consumed = parse_budget(row.get::<String, _>("consumed_json").as_str())?;
        let remaining = caps.saturating_sub(&reserved_out).saturating_sub(&consumed);
        if !remaining.covers(actual) {
            return Err(insufficient(&format!(
                "lease {lease_id} cannot cover direct debit"
            )));
        }
        // A reservation-backed child also spends against its reservation:
        // check the reservation's available hold before writing anything, so
        // a desynchronized ledger fails closed instead of half-applying.
        let child_reservation = sqlx::query(
            "SELECT reservation_id,parent_lease_id,held_json,consumed_json
             FROM kernel_reservations
             WHERE workspace_id=? AND child_lease_id=? AND state='active'
             ORDER BY created_at_ms LIMIT 1",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_optional(&mut *tx)
        .await?;
        if let Some(res) = &child_reservation {
            let held = parse_budget(res.get::<String, _>("held_json").as_str())?;
            let res_consumed = parse_budget(res.get::<String, _>("consumed_json").as_str())?;
            let available = held.saturating_sub(&res_consumed);
            if !available.covers(actual) {
                return Err(insufficient(&format!(
                    "reservation for child lease {lease_id} cannot cover direct debit"
                )));
            }
        }
        sqlx::query(
            "INSERT INTO kernel_lease_debits(workspace_id,idempotency_key,lease_id_link,
             amounts_json,debited_at_ms) VALUES(?,?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(idempotency_key)
        .bind(lease_id)
        .bind(budget_json(actual)?)
        .bind(now_ms)
        .execute(&mut *tx)
        .await?;
        let new_consumed = consumed
            .checked_add(actual)
            .ok_or_else(|| insufficient("account consumed overflow"))?;
        sqlx::query(
            "UPDATE kernel_budget_accounts SET consumed_json=?,updated_at=?
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(budget_json(&new_consumed)?)
        .bind(now_ms)
        .bind(ws(workspace_id))
        .bind(lease_id)
        .execute(&mut *tx)
        .await?;
        // Post the child's spend to the reservation ledger in the same
        // transaction: the reservation's consumed grows, and the parent's
        // reserved_out shrinks by `actual` while its consumed grows by
        // `actual` (counted exactly once — see post_parent_debit_tx).
        if let Some(res) = &child_reservation {
            let reservation_id: String = res.get("reservation_id");
            let parent_lease_id: String = res.get("parent_lease_id");
            let res_consumed = parse_budget(res.get::<String, _>("consumed_json").as_str())?;
            let res_new = res_consumed
                .checked_add(actual)
                .ok_or_else(|| insufficient("reservation consumed overflow"))?;
            sqlx::query(
                "UPDATE kernel_reservations SET consumed_json=?
                 WHERE workspace_id=? AND reservation_id=?",
            )
            .bind(budget_json(&res_new)?)
            .bind(ws(workspace_id))
            .bind(&reservation_id)
            .execute(&mut *tx)
            .await?;
            post_parent_debit_tx(&mut tx, workspace_id, &parent_lease_id, actual, now_ms).await?;
        }
        tx.commit().await?;
        Ok(DebitReceipt {
            reservation_id: lease_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        })
    }

    /// Release a reservation: the unspent held amount returns to the parent.
    /// Returns the amount returned. Only on explicit revocation/expiry.
    ///
    /// Conservation: each debit already moved its actual from the parent's
    /// reserved_out to consumed, so release subtracts only the unspent
    /// remainder (held − consumed) from reserved_out; the spent part stays
    /// consumed on the parent's books exactly once.
    pub async fn release_kernel_budget(
        &self,
        workspace_id: &WorkspaceId,
        reservation_id: &str,
        now_ms: i64,
    ) -> Result<Budget, RepositoryError> {
        let pool = self.pool();
        let mut tx = pool.begin().await?;
        let row = sqlx::query(
            "SELECT parent_lease_id,held_json,consumed_json,state FROM kernel_reservations
             WHERE workspace_id=? AND reservation_id=?",
        )
        .bind(ws(workspace_id))
        .bind(reservation_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RepositoryError::KernelReservationConflict)?;
        if row.get::<String, _>("state") != "active" {
            return Err(RepositoryError::KernelReservationConflict);
        }
        let parent_lease_id: String = row.get("parent_lease_id");
        let held = parse_budget(row.get::<String, _>("held_json").as_str())?;
        let consumed = parse_budget(row.get::<String, _>("consumed_json").as_str())?;
        let returned = held.saturating_sub(&consumed);
        sqlx::query(
            "UPDATE kernel_reservations SET state='released',released_at_ms=?
             WHERE workspace_id=? AND reservation_id=?",
        )
        .bind(now_ms)
        .bind(ws(workspace_id))
        .bind(reservation_id)
        .execute(&mut *tx)
        .await?;
        let acct = sqlx::query(
            "SELECT reserved_out_json FROM kernel_budget_accounts
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(&parent_lease_id)
        .fetch_one(&mut *tx)
        .await?;
        let reserved_out = parse_budget(acct.get::<String, _>("reserved_out_json").as_str())?;
        // Only the unspent remainder of the hold returns: every debit
        // already moved its actual from reserved_out to consumed, so
        // subtracting the full hold would release the spent part a second
        // time.
        let unspent = held.saturating_sub(&consumed);
        let new_reserved = reserved_out.saturating_sub(&unspent);
        sqlx::query(
            "UPDATE kernel_budget_accounts SET reserved_out_json=?,updated_at=?
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(budget_json(&new_reserved)?)
        .bind(now_ms)
        .bind(ws(workspace_id))
        .bind(&parent_lease_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(returned)
    }

    /// Remaining balance for a lease: caps − reserved_out − consumed −
    /// held execution reservations. Durable execution holds
    /// (authorized-but-unsettled dispatches) encumber the lease exactly
    /// like the in-memory ledger's `exec_held`; omitting them would let a
    /// crash-recovered dispatcher over-admit against budget that is
    /// already spoken for.
    pub async fn kernel_budget_remaining(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
    ) -> Result<Budget, RepositoryError> {
        let row = sqlx::query(
            "SELECT caps_json,reserved_out_json,consumed_json FROM kernel_budget_accounts
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or_else(|| insufficient(&format!("unknown lease {lease_id}")))?;
        let caps = parse_budget(row.get::<String, _>("caps_json").as_str())?;
        let reserved_out = parse_budget(row.get::<String, _>("reserved_out_json").as_str())?;
        let consumed = parse_budget(row.get::<String, _>("consumed_json").as_str())?;
        let held_rows = sqlx::query(
            "SELECT held_json FROM kernel_executions
             WHERE workspace_id=? AND lease_id=? AND state='held'",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_all(self.pool())
        .await?;
        let mut exec_held = Budget::new();
        for held_row in &held_rows {
            let held = parse_budget(held_row.get::<String, _>("held_json").as_str())?;
            exec_held = exec_held
                .checked_add(&held)
                .ok_or_else(|| insufficient("execution held overflow"))?;
        }
        Ok(caps
            .saturating_sub(&reserved_out)
            .saturating_sub(&consumed)
            .saturating_sub(&exec_held))
    }

    /// Full budget account state per lease (caps, held reservations,
    /// consumed spend): the durable counterpart the in-memory ledger
    /// hydrates from at open, so settled spend survives a restart.
    pub async fn kernel_budget_account_states(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<(String, Budget, Budget, Budget)>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT lease_id, caps_json, reserved_out_json, consumed_json
             FROM kernel_budget_accounts WHERE workspace_id = ?",
        )
        .bind(ws(workspace_id))
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                let lease_id: String = r.get("lease_id");
                let caps = parse_budget(r.get::<String, _>("caps_json").as_str())?;
                let reserved_out = parse_budget(r.get::<String, _>("reserved_out_json").as_str())?;
                let consumed = parse_budget(r.get::<String, _>("consumed_json").as_str())?;
                Ok((lease_id, caps, reserved_out, consumed))
            })
            .collect()
    }

    /// Active reservations (for crash-safe reconciliation: reservations whose
    /// child lease is dead must be released explicitly).
    pub async fn active_kernel_reservations(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<Reservation>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT reservation_id,parent_lease_id,child_lease_id,held_json,consumed_json,
             created_at_ms FROM kernel_reservations
             WHERE workspace_id=? AND state='active' ORDER BY created_at_ms",
        )
        .bind(ws(workspace_id))
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(Reservation {
                    id: r.get("reservation_id"),
                    child_lease_id: r.get("child_lease_id"),
                    parent_lease_id: r.get("parent_lease_id"),
                    held: parse_budget(r.get::<String, _>("held_json").as_str())?,
                    consumed: parse_budget(r.get::<String, _>("consumed_json").as_str())?,
                    state: ReservationState::Active,
                    created_at_ms: r.get("created_at_ms"),
                    released_at_ms: None,
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Execution reservations (dispatch-side budget lifecycle)
    // ------------------------------------------------------------------

    /// Record a lease's budget caps. First write wins; re-recording is a
    /// no-op so mint retries stay idempotent.
    pub async fn record_kernel_lease_caps(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        caps: &Budget,
        now_ms: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT OR IGNORE INTO kernel_lease_caps(lease_id,workspace_id,caps_json,recorded_at_ms)
             VALUES(?,?,?,?)",
        )
        .bind(lease_id)
        .bind(ws(workspace_id))
        .bind(budget_json(caps)?)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// The caps recorded for a lease, if any (boot rehydration).
    pub async fn kernel_lease_caps(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
    ) -> Result<Option<Budget>, RepositoryError> {
        let row = sqlx::query(
            "SELECT caps_json FROM kernel_lease_caps WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| parse_budget(r.get::<String, _>("caps_json").as_str()))
            .transpose()
    }

    /// Persist an execution reservation taken at authorize time. The
    /// reservation id and idempotency key are unique: a duplicate insert is
    /// a conflict (fail closed).
    pub async fn insert_kernel_execution(
        &self,
        workspace_id: &WorkspaceId,
        exec: &ExecutionReservation,
    ) -> Result<(), RepositoryError> {
        let res = sqlx::query(
            "INSERT OR IGNORE INTO kernel_executions(id,workspace_id,lease_id,action_id,
             held_json,state,idempotency_key,created_at_ms,completed_at_ms,actual_json)
             VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&exec.id)
        .bind(ws(workspace_id))
        .bind(&exec.lease_id)
        .bind(&exec.action_id)
        .bind(budget_json(&exec.held)?)
        .bind(execution_state_str(exec.state))
        .bind(&exec.idempotency_key)
        .bind(exec.created_at_ms)
        .bind(exec.completed_at_ms)
        .bind(
            exec.actual
                .as_ref()
                .map(budget_json)
                .transpose()?
                .as_deref(),
        )
        .execute(self.pool())
        .await?;
        if res.rows_affected() == 0 {
            return Err(RepositoryError::KernelReservationConflict);
        }
        Ok(())
    }

    /// Fetch an execution reservation by id.
    pub async fn get_kernel_execution(
        &self,
        workspace_id: &WorkspaceId,
        id: &str,
    ) -> Result<Option<ExecutionReservation>, RepositoryError> {
        let row = sqlx::query(
            "SELECT id,lease_id,action_id,held_json,state,idempotency_key,
             created_at_ms,completed_at_ms,actual_json
             FROM kernel_executions WHERE workspace_id=? AND id=?",
        )
        .bind(ws(workspace_id))
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| parse_execution_row(&r)).transpose()
    }

    /// Apply the terminal transition of an execution reservation:
    /// held → settled (with measured actuals) or held → released. The SQL
    /// guard trigger rejects any other mutation; a zero-row update means the
    /// row is missing or already terminal (fail closed).
    pub async fn update_kernel_execution(
        &self,
        workspace_id: &WorkspaceId,
        exec: &ExecutionReservation,
    ) -> Result<(), RepositoryError> {
        let res = sqlx::query(
            "UPDATE kernel_executions
             SET state=?,completed_at_ms=?,actual_json=?
             WHERE workspace_id=? AND id=?",
        )
        .bind(execution_state_str(exec.state))
        .bind(exec.completed_at_ms)
        .bind(
            exec.actual
                .as_ref()
                .map(budget_json)
                .transpose()?
                .as_deref(),
        )
        .bind(ws(workspace_id))
        .bind(&exec.id)
        .execute(self.pool())
        .await?;
        if res.rows_affected() == 0 {
            return Err(RepositoryError::InvalidKernelLeaseState(format!(
                "unknown or terminal execution reservation {}",
                exec.id
            )));
        }
        Ok(())
    }

    /// Every execution reservation in the workspace, held or terminal, for
    /// boot rehydration.
    pub async fn all_kernel_executions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<ExecutionReservation>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT id,lease_id,action_id,held_json,state,idempotency_key,
             created_at_ms,completed_at_ms,actual_json
             FROM kernel_executions WHERE workspace_id=? ORDER BY created_at_ms",
        )
        .bind(ws(workspace_id))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(parse_execution_row).collect()
    }

    // ------------------------------------------------------------------
    // Audit log
    // ------------------------------------------------------------------

    /// Append an event to the workspace's hash-chained audit log, sealed
    /// against the frozen v1 [`AuditEvent`] contract. Details are redacted
    /// deterministically before sealing, and the chain link is computed in
    /// the same transaction that inserts the row.
    ///
    /// Concurrent writers are handled by a bounded retry loop: when two
    /// writers race, the loser fails the gapless-sequence trigger, rolls
    /// back, re-reads the tip, and appends after it. Concurrent appends
    /// from multiple connections therefore never fork the chain.
    pub async fn append_kernel_audit_event(
        &self,
        workspace_id: &WorkspaceId,
        params: &KernelAuditAppend<'_>,
    ) -> Result<AuditEvent, RepositoryError> {
        for attempt in 0..AUDIT_APPEND_RETRIES {
            let mut tx = self.pool().begin().await?;
            match append_audit_attempt(&mut tx, workspace_id, params).await {
                Ok(event) => {
                    tx.commit().await?;
                    return Ok(event);
                }
                Err(e) if is_retryable(&e) => {
                    audit_retry_backoff(attempt).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(RepositoryError::KernelAuditBreak(
            "audit append lost too many sequence races".to_string(),
        ))
    }

    /// Store a host-key checkpoint. The checkpoint is anchored to a real
    /// event: the db refuses a link whose hash does not match the event at
    /// `through_seq` in this workspace. Signature verification happens in
    /// [`Database::verify_kernel_audit`], which holds the host key.
    pub async fn checkpoint_kernel_audit(
        &self,
        workspace_id: &WorkspaceId,
        link: &AuditLink,
        created_at_ms: i64,
    ) -> Result<(), RepositoryError> {
        let event_hash: Option<String> = sqlx::query_scalar(
            "SELECT hash FROM kernel_audit_events WHERE workspace_id=? AND seq=?",
        )
        .bind(ws(workspace_id))
        .bind(link.through_seq as i64)
        .fetch_optional(self.pool())
        .await?;
        match event_hash {
            Some(h) if h == link.chain_hash => {}
            _ => {
                return Err(RepositoryError::KernelAuditBreak(format!(
                    "checkpoint references unknown event seq {}",
                    link.through_seq
                )));
            }
        }
        sqlx::query(
            "INSERT INTO kernel_audit_checkpoints(workspace_id,seq,hash,signature,key_id,created_at)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(link.through_seq as i64)
        .bind(&link.chain_hash)
        .bind(&link.signature)
        .bind(&link.key_id)
        .bind(created_at_ms)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Query events by provenance: action digest, actor, decision, and/or
    /// sequence range. Newest last.
    pub async fn kernel_audit_events(
        &self,
        workspace_id: &WorkspaceId,
        query: &KernelAuditQuery,
    ) -> Result<Vec<AuditEvent>, RepositoryError> {
        use sqlx::QueryBuilder;
        let mut qb: QueryBuilder<sqlx::Sqlite> = QueryBuilder::new(
            "SELECT workspace_id,seq,version,event_id,kind,actor,session_id,action_digest,
             decision,detail,prev_hash,hash,timestamp_ms
             FROM kernel_audit_events WHERE workspace_id=",
        );
        qb.push_bind(ws(workspace_id));
        if let Some(v) = &query.action_digest {
            qb.push(" AND action_digest=").push_bind(v);
        }
        if let Some(v) = &query.actor {
            qb.push(" AND actor=").push_bind(v);
        }
        if let Some(v) = &query.decision {
            qb.push(" AND decision=").push_bind(v);
        }
        if let Some(v) = query.min_seq {
            qb.push(" AND seq>=").push_bind(v as i64);
        }
        if let Some(v) = query.max_seq {
            qb.push(" AND seq<=").push_bind(v as i64);
        }
        qb.push(" ORDER BY seq");
        if let Some(limit) = query.limit {
            qb.push(" LIMIT ").push_bind(limit as i64);
        }
        let rows = qb.build().fetch_all(self.pool()).await?;
        rows.iter().map(audit_event_from_row).collect()
    }

    pub async fn kernel_audit_checkpoints(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<AuditLink>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT seq,hash,signature,key_id FROM kernel_audit_checkpoints
             WHERE workspace_id=? ORDER BY seq",
        )
        .bind(ws(workspace_id))
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(AuditLink {
                    key_id: r.get("key_id"),
                    through_seq: r.get::<i64, _>("seq") as u64,
                    chain_hash: r.get("hash"),
                    signature: r.get("signature"),
                })
            })
            .collect()
    }

    /// Verify the workspace's audit chain and every checkpoint against the
    /// host verifying key, requiring a trusted checkpoint anchor. Each
    /// checkpoint must be anchored to a real event (matching sequence and
    /// hash) and carry a valid host-key signature. Reports the first break
    /// found.
    ///
    /// `min_checkpoint_seq` is the caller's trusted minimum signed
    /// through-sequence: the host asserts it has signed a checkpoint
    /// covering at least this event. Verification fails closed when no
    /// checkpoint that is both anchored to the chain and signed by the host
    /// key reaches the anchor — so a store writer that rewrites events and
    /// strips checkpoints cannot produce a verifying log. Events appended
    /// after the newest checkpoint still verify (the log grows between
    /// checkpoints); raise the anchor after each checkpoint to bind recent
    /// history to host-key evidence.
    pub async fn verify_kernel_audit(
        &self,
        workspace_id: &WorkspaceId,
        host_key: &ed25519_dalek::VerifyingKey,
        expected_key_id: &str,
        min_checkpoint_seq: u64,
    ) -> Result<(), RepositoryError> {
        let events = self
            .kernel_audit_events(workspace_id, &KernelAuditQuery::default())
            .await?;
        verify_event_chain(&events)
            .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
        let checkpoints = self.kernel_audit_checkpoints(workspace_id).await?;
        let mut anchored_through: Option<u64> = None;
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
            link.verify(host_key, expected_key_id)
                .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
            anchored_through =
                Some(anchored_through.map_or(link.through_seq, |max| max.max(link.through_seq)));
        }
        match anchored_through {
            Some(through) if through >= min_checkpoint_seq => Ok(()),
            _ => Err(RepositoryError::KernelAuditBreak(format!(
                "no valid checkpoint reaches trusted anchor seq {min_checkpoint_seq}"
            ))),
        }
    }

    /// Record one kernel key generation's verifying key. Idempotent per
    /// `(workspace_id, key_id)`: a generation's key material never changes,
    /// and the immutability triggers enforce that at the store level.
    pub async fn record_kernel_key_generation(
        &self,
        workspace_id: &WorkspaceId,
        key_id: &str,
        role: &str,
        verifying_key_hex: &str,
        created_at_ms: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT OR IGNORE INTO kernel_key_generations
             (workspace_id, key_id, role, verifying_key_hex, created_at_ms)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(workspace_id.to_string())
        .bind(key_id)
        .bind(role)
        .bind(verifying_key_hex)
        .bind(created_at_ms)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// List every recorded key generation for the workspace, oldest first.
    pub async fn kernel_key_generations(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<KernelKeyGenerationRow>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT key_id, role, verifying_key_hex, created_at_ms
             FROM kernel_key_generations
             WHERE workspace_id = ?
             ORDER BY created_at_ms ASC, key_id ASC",
        )
        .bind(workspace_id.to_string())
        .fetch_all(self.pool())
        .await?;
        rows.iter()
            .map(|r| {
                Ok(KernelKeyGenerationRow {
                    key_id: r.get("key_id"),
                    role: r.get("role"),
                    verifying_key_hex: r.get("verifying_key_hex"),
                    created_at_ms: r.get("created_at_ms"),
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Kernel sessions (migration 0027)
    // ------------------------------------------------------------------

    /// Insert a session record: public identity only (subject, parent,
    /// verifying key, liveness). Fails closed on a duplicate subject: a
    /// session row is created once, at session start.
    pub async fn insert_kernel_session(
        &self,
        workspace_id: &WorkspaceId,
        subject: &str,
        parent_subject: Option<&str>,
        verifying_key_hex: &str,
        created_at_ms: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO kernel_sessions(workspace_id,subject,parent_subject,verifying_key_hex,
             active,created_at_ms,destroyed_at_ms)
             VALUES(?,?,?,?,1,?,NULL)",
        )
        .bind(ws(workspace_id))
        .bind(subject)
        .bind(parent_subject)
        .bind(verifying_key_hex)
        .bind(created_at_ms)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Perform the destroy transition (active 1 -> 0 with a destroy
    /// timestamp). The `kernel_sessions_destroy_only` trigger enforces the
    /// transition shape; the `active=1` predicate makes a repeated destroy
    /// a no-op instead of an error. Returns true when a row changed.
    pub async fn destroy_kernel_session(
        &self,
        workspace_id: &WorkspaceId,
        subject: &str,
        destroyed_at_ms: i64,
    ) -> Result<bool, RepositoryError> {
        let res = sqlx::query(
            "UPDATE kernel_sessions SET active=0,destroyed_at_ms=?
             WHERE workspace_id=? AND subject=? AND active=1",
        )
        .bind(destroyed_at_ms)
        .bind(ws(workspace_id))
        .bind(subject)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// One session row by subject, or None.
    pub async fn kernel_session(
        &self,
        workspace_id: &WorkspaceId,
        subject: &str,
    ) -> Result<Option<KernelSessionRow>, RepositoryError> {
        let row = sqlx::query(
            "SELECT subject,parent_subject,verifying_key_hex,active,created_at_ms,destroyed_at_ms
             FROM kernel_sessions WHERE workspace_id=? AND subject=?",
        )
        .bind(ws(workspace_id))
        .bind(subject)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| session_from_row(&r)).transpose()
    }

    /// Every active session, oldest first: the set the kernel hydrates its
    /// validating-only registry from at open.
    pub async fn active_kernel_sessions(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<Vec<KernelSessionRow>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT subject,parent_subject,verifying_key_hex,active,created_at_ms,destroyed_at_ms
             FROM kernel_sessions WHERE workspace_id=? AND active=1
             ORDER BY created_at_ms,subject",
        )
        .bind(ws(workspace_id))
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(session_from_row).collect()
    }

    /// Destroy-transition for every active session older than `ttl_ms`
    /// (`created_at_ms <= now_ms - ttl_ms`), **plus the complete active
    /// descendant subtree of each expired session**: the durable
    /// session-TTL rotation that bounds the stolen-session-key window.
    /// A child of a TTL-expired parent is destroyed even if the child
    /// itself is within its TTL — its authority derives from the parent,
    /// and the hydration pass would otherwise reject the dangling child
    /// and fail the open until the database is manually repaired.
    /// Returns every destroyed subject (expired roots and descendants).
    ///
    /// NOTE: this commits the destroy transitions on its own. Prefer
    /// [`Database::expire_kernel_sessions_and_revoke`] when the expired
    /// subjects' leases must be revoked too: the destroy and the
    /// revocations commit in ONE transaction, so a crash can never leave
    /// destroyed sessions with live, unrevoked leases (which would fail
    /// the next boot's re-validation self-check).
    pub async fn expire_kernel_sessions(
        &self,
        workspace_id: &WorkspaceId,
        ttl_ms: i64,
        now_ms: i64,
    ) -> Result<Vec<String>, RepositoryError> {
        // Overflow-safe expiry cutoff computed in Rust: `created_at_ms <=
        // now_ms - ttl_ms` (SQLite integer arithmetic wraps on overflow,
        // so `created_at_ms + ttl_ms` must not be computed in SQL).
        let cutoff = now_ms.saturating_sub(ttl_ms);
        let subjects: Vec<String> = sqlx::query_scalar(
            "WITH RECURSIVE expired_subtree(subject) AS (
                 SELECT subject FROM kernel_sessions
                 WHERE workspace_id=? AND active=1 AND created_at_ms<=?
                 UNION
                 SELECT ks.subject FROM kernel_sessions ks
                 JOIN expired_subtree e ON ks.parent_subject=e.subject
                 WHERE ks.workspace_id=? AND ks.active=1
             )
             UPDATE kernel_sessions SET active=0,destroyed_at_ms=?
             WHERE workspace_id=? AND subject IN (SELECT subject FROM expired_subtree)
             RETURNING subject",
        )
        .bind(ws(workspace_id))
        .bind(cutoff)
        .bind(ws(workspace_id))
        .bind(now_ms)
        .bind(ws(workspace_id))
        .fetch_all(self.pool())
        .await?;
        Ok(subjects)
    }

    /// Atomic session-TTL expiry: select the expired subtree, collect the
    /// lease ids for those subjects, destroy-transition the sessions, and
    /// revoke the leases — all in ONE transaction. Either every destroy
    /// transition and every revocation commits, or none do. A crash
    /// between expiry and revocation would otherwise leave destroyed
    /// sessions with live, unrevoked leases; the next boot's expiry finds
    /// nothing (the rows are already inactive), the leases stay live, and
    /// the re-validation self-check fails the open on `SubjectInactive`
    /// until the database is repaired by hand.
    /// Returns `(destroyed subjects, revoked lease ids)`.
    pub async fn expire_kernel_sessions_and_revoke(
        &self,
        workspace_id: &WorkspaceId,
        ttl_ms: i64,
        now_ms: i64,
        reason: &str,
    ) -> Result<(Vec<String>, Vec<String>), RepositoryError> {
        // Overflow-safe expiry cutoff computed in Rust: `created_at_ms <=
        // now_ms - ttl_ms` (SQLite integer arithmetic wraps on overflow,
        // so `created_at_ms + ttl_ms` must not be computed in SQL).
        let cutoff = now_ms.saturating_sub(ttl_ms);
        let mut tx = self.pool().begin().await?;
        let subjects: Vec<String> = sqlx::query_scalar(
            "WITH RECURSIVE expired_subtree(subject) AS (
                 SELECT subject FROM kernel_sessions
                 WHERE workspace_id=? AND active=1 AND created_at_ms<=?
                 UNION
                 SELECT ks.subject FROM kernel_sessions ks
                 JOIN expired_subtree e ON ks.parent_subject=e.subject
                 WHERE ks.workspace_id=? AND ks.active=1
             )
             SELECT subject FROM expired_subtree",
        )
        .bind(ws(workspace_id))
        .bind(cutoff)
        .bind(ws(workspace_id))
        .fetch_all(&mut *tx)
        .await?;
        let mut lease_ids: Vec<String> = Vec::new();
        if !subjects.is_empty() {
            use sqlx::QueryBuilder;
            let mut qb: QueryBuilder<sqlx::Sqlite> =
                QueryBuilder::new("SELECT lease_id FROM kernel_leases WHERE workspace_id=");
            qb.push_bind(ws(workspace_id));
            qb.push(" AND subject IN (");
            let mut separated = qb.separated(", ");
            for subject in &subjects {
                separated.push_bind(subject);
            }
            separated.push_unseparated(") ORDER BY issued_at_ms");
            lease_ids = qb.build_query_scalar().fetch_all(&mut *tx).await?;
            let mut qb: QueryBuilder<sqlx::Sqlite> =
                QueryBuilder::new("UPDATE kernel_sessions SET active=0,destroyed_at_ms=");
            qb.push_bind(now_ms);
            qb.push(" WHERE workspace_id=");
            qb.push_bind(ws(workspace_id));
            qb.push(" AND active=1 AND subject IN (");
            let mut separated = qb.separated(", ");
            for subject in &subjects {
                separated.push_bind(subject);
            }
            separated.push_unseparated(")");
            qb.build().execute(&mut *tx).await?;
        }
        for lease_id in &lease_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO kernel_revocations(lease_id,workspace_id,revoked_at_ms,reason)
                 VALUES(?,?,?,?)",
            )
            .bind(lease_id)
            .bind(ws(workspace_id))
            .bind(now_ms)
            .bind(reason)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok((subjects, lease_ids))
    }

    /// Destroy the named sessions AND revoke the named leases in ONE
    /// transaction: the durable counterpart of session termination. Either
    /// every destroy transition and every revocation commits, or none do —
    /// a restart can never resurrect a destroyed session nor lose the
    /// revocations that termination requires.
    pub async fn destroy_sessions_and_revoke(
        &self,
        workspace_id: &WorkspaceId,
        subjects: &[String],
        lease_ids: &[String],
        at_ms: i64,
        reason: &str,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        if !subjects.is_empty() {
            use sqlx::QueryBuilder;
            let mut qb: QueryBuilder<sqlx::Sqlite> =
                QueryBuilder::new("UPDATE kernel_sessions SET active=0,destroyed_at_ms=");
            qb.push_bind(at_ms);
            qb.push(" WHERE workspace_id=");
            qb.push_bind(ws(workspace_id));
            qb.push(" AND active=1 AND subject IN (");
            let mut separated = qb.separated(", ");
            for subject in subjects {
                separated.push_bind(subject);
            }
            separated.push_unseparated(")");
            qb.build().execute(&mut *tx).await?;
        }
        for lease_id in lease_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO kernel_revocations(lease_id,workspace_id,revoked_at_ms,reason)
                 VALUES(?,?,?,?)",
            )
            .bind(lease_id)
            .bind(ws(workspace_id))
            .bind(at_ms)
            .bind(reason)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Boot repair for the pre-atomicity crash window: durably revoke
    /// every live (unexpired, unrevoked) lease whose subject has a
    /// *destroyed* session row, in ONE transaction. A crash between the
    /// session destroy transition and the lease revocation leaves exactly
    /// this residue; without the repair the next boot's re-validation
    /// self-check fails the open on `SubjectInactive` and the kernel
    /// stays down until the database is repaired by hand. A destroyed
    /// session's leases must never authorize, so revoking them here is
    /// fail-closed. Returns the revoked lease ids.
    pub async fn revoke_leases_for_inactive_sessions(
        &self,
        workspace_id: &WorkspaceId,
        now_ms: i64,
        reason: &str,
    ) -> Result<Vec<String>, RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let lease_ids: Vec<String> = sqlx::query_scalar(
            "SELECT l.lease_id FROM kernel_leases l
             JOIN kernel_sessions s
               ON s.workspace_id = l.workspace_id AND s.subject = l.subject
             WHERE l.workspace_id = ?
               AND s.active = 0
               AND json_extract(l.limits_json, '$.expires_at_ms') > ?
               AND NOT EXISTS (
                 SELECT 1 FROM kernel_revocations r
                 WHERE r.workspace_id = l.workspace_id AND r.lease_id = l.lease_id
               )
             ORDER BY l.issued_at_ms, l.lease_id",
        )
        .bind(ws(workspace_id))
        .bind(now_ms)
        .fetch_all(&mut *tx)
        .await?;
        for lease_id in &lease_ids {
            sqlx::query(
                "INSERT OR IGNORE INTO kernel_revocations(lease_id,workspace_id,revoked_at_ms,reason)
                 VALUES(?,?,?,?)",
            )
            .bind(lease_id)
            .bind(ws(workspace_id))
            .bind(now_ms)
            .bind(reason)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(lease_ids)
    }

    /// Every subject with a `kernel_sessions` row (active or destroyed).
    /// Used at boot to distinguish legacy pre-migration leases (subject
    /// has no session row: sessions were not recorded before migration
    /// 0025) from corruption (subject has a row). One query, not one per
    /// lease.
    pub async fn kernel_session_subjects(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<HashSet<String>, RepositoryError> {
        let subjects: Vec<String> =
            sqlx::query_scalar("SELECT subject FROM kernel_sessions WHERE workspace_id=?")
                .bind(ws(workspace_id))
                .fetch_all(self.pool())
                .await?;
        Ok(subjects.into_iter().collect())
    }

    // ------------------------------------------------------------------
    // Kill-list and generation purge (migration 0027)
    // ------------------------------------------------------------------

    /// Record a generation kill: the compromise-response primitive.
    /// Verification fails closed for a killed generation even though its
    /// verifying key stays recorded. Idempotent: killing twice is a no-op.
    /// `role` must be `issuer` or `host` (validated in Rust; the CHECK would
    /// also reject anything else, but the caller deserves a clear error).
    /// `killed_by` is the authorizing operator principal
    /// (`provider:subject`): durable actor evidence for the kill-list.
    pub async fn kill_key_generation(
        &self,
        workspace_id: &WorkspaceId,
        key_id: &str,
        role: &str,
        killed_at_ms: i64,
        reason: &str,
        killed_by: &str,
    ) -> Result<bool, RepositoryError> {
        if role != "issuer" && role != "host" {
            return Err(RepositoryError::InvalidKernelLeaseState(format!(
                "kill_key_generation: invalid role {role:?}"
            )));
        }
        let res = sqlx::query(
            "INSERT OR IGNORE INTO kernel_killed_generations
             (workspace_id,key_id,role,killed_at_ms,reason,killed_by)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(key_id)
        .bind(role)
        .bind(killed_at_ms)
        .bind(reason)
        .bind(killed_by)
        .execute(self.pool())
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Kill a generation AND append its audit event in ONE transaction
    /// (with the audit sequence-race retry around the whole unit): either
    /// the kill and its audit record both commit, or neither does. A kill
    /// without a durable audit record would be a forensic gap; an audit
    /// record without the kill row would be worse (the kill would not
    /// take effect), so the two share one atomic unit. Returns
    /// `(killed, audit_event)`: when the generation was already on the
    /// kill-list nothing is written and the event is `None`.
    pub async fn kill_key_generation_with_audit(
        &self,
        workspace_id: &WorkspaceId,
        request: &KillGenerationRequest<'_>,
    ) -> Result<(bool, Option<AuditEvent>), RepositoryError> {
        let role = request.role;
        if role != "issuer" && role != "host" {
            return Err(RepositoryError::InvalidKernelLeaseState(format!(
                "kill_key_generation: invalid role {role:?}"
            )));
        }
        for attempt in 0..AUDIT_APPEND_RETRIES {
            let mut tx = self.pool().begin().await?;
            let killed = sqlx::query(
                "INSERT OR IGNORE INTO kernel_killed_generations
                 (workspace_id,key_id,role,killed_at_ms,reason,killed_by)
                 VALUES(?,?,?,?,?,?)",
            )
            .bind(ws(workspace_id))
            .bind(request.key_id)
            .bind(role)
            .bind(request.killed_at_ms)
            .bind(request.reason)
            .bind(request.killed_by)
            .execute(&mut *tx)
            .await?
            .rows_affected()
                == 1;
            if !killed {
                tx.rollback().await?;
                return Ok((false, None));
            }
            match append_audit_attempt(&mut tx, workspace_id, request.audit).await {
                Ok(event) => {
                    tx.commit().await?;
                    return Ok((true, Some(event)));
                }
                Err(e) if is_retryable(&e) => {
                    tx.rollback().await?;
                    audit_retry_backoff(attempt).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(RepositoryError::KernelAuditBreak(
            "kill+audit lost too many sequence races".to_string(),
        ))
    }

    /// Every killed generation id for the workspace: the set the kernel
    /// loads into its in-memory kill set at open.
    pub async fn killed_key_generation_ids(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<HashSet<String>, RepositoryError> {
        let ids: Vec<String> =
            sqlx::query_scalar("SELECT key_id FROM kernel_killed_generations WHERE workspace_id=?")
                .bind(ws(workspace_id))
                .fetch_all(self.pool())
                .await?;
        Ok(ids.into_iter().collect())
    }

    // ------------------------------------------------------------------
    // Monotonic time anchor (migration 0028)
    // ------------------------------------------------------------------

    /// The greatest effective time the kernel has acted on, or 0 when the
    /// workspace has no recorded mark yet. Read at open to detect a
    /// backward wall-clock jump before any authority decision runs.
    pub async fn time_high_water(
        &self,
        workspace_id: &WorkspaceId,
    ) -> Result<i64, RepositoryError> {
        let mark: Option<i64> = sqlx::query_scalar(
            "SELECT high_water_ms FROM kernel_time_high_water WHERE workspace_id=?",
        )
        .bind(ws(workspace_id))
        .fetch_optional(self.pool())
        .await?;
        Ok(mark.unwrap_or(0))
    }

    /// Advance the time anchor. Only ever moves forward: a smaller value
    /// is ignored, so a stray call can never lower the mark a rollback
    /// check depends on.
    pub async fn record_time_high_water(
        &self,
        workspace_id: &WorkspaceId,
        high_water_ms: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO kernel_time_high_water(workspace_id, high_water_ms)
             VALUES(?, ?)
             ON CONFLICT(workspace_id) DO UPDATE
             SET high_water_ms = max(high_water_ms, excluded.high_water_ms)",
        )
        .bind(ws(workspace_id))
        .bind(high_water_ms)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Live references to a generation: leases with `issuer_key_id=key_id`
    /// that are neither revoked nor expired (`expires_at_ms > now_ms`).
    /// This is the purge gate: a nonzero count means deleting the
    /// generation would orphan outstanding leases, so the purge refuses.
    pub async fn live_lease_refs_to_generation(
        &self,
        workspace_id: &WorkspaceId,
        key_id: &str,
        now_ms: i64,
    ) -> Result<u64, RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let n = live_lease_refs_tx(&mut tx, workspace_id, key_id, now_ms).await?;
        tx.commit().await?;
        Ok(n)
    }

    /// Every live lease document (unexpired, unrevoked): the set the
    /// re-validation self-check walks at open.
    pub async fn kernel_live_leases(
        &self,
        workspace_id: &WorkspaceId,
        now_ms: i64,
    ) -> Result<Vec<LeaseDocument>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT lease_id,parent_id,subject,issuer_key_id,issued_at_ms,protocol_version,
             scope_json,limits_json,depth,depth_limit,lease_nonce,signature,approved_action_digest
             FROM kernel_leases l
             WHERE l.workspace_id=?
               AND json_extract(l.limits_json,'$.expires_at_ms')>?
               AND NOT EXISTS (
                 SELECT 1 FROM kernel_revocations r
                 WHERE r.workspace_id=l.workspace_id AND r.lease_id=l.lease_id
               )
             ORDER BY l.issued_at_ms,l.lease_id",
        )
        .bind(ws(workspace_id))
        .bind(now_ms)
        .fetch_all(self.pool())
        .await?;
        rows.iter().map(lease_from_row).collect()
    }

    /// True when any audit checkpoint in the workspace references `key_id`.
    /// Host generations with retained checkpoints must not be purged, or
    /// audit history would become unverifiable (`verify_kernel_audit`
    /// fails closed on a checkpoint whose host key is unknown). The check
    /// covers checkpoints of ANY age: checkpoints are immutable and are
    /// never deleted by the kernel, so an age-bounded check would let an
    /// old host key be purged while its old checkpoints still need it.
    /// Host-key accumulation is therefore bounded only by rotation
    /// frequency until an authenticated archive/compaction protocol
    /// exists (spec §8.4, open).
    pub async fn host_generation_has_checkpoints(
        &self,
        workspace_id: &WorkspaceId,
        key_id: &str,
    ) -> Result<bool, RepositoryError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_audit_checkpoints
             WHERE workspace_id=? AND key_id=?",
        )
        .bind(ws(workspace_id))
        .bind(key_id)
        .fetch_one(self.pool())
        .await?;
        Ok(n > 0)
    }

    /// Purge one generation row, atomically gated on the live-lease
    /// predicate and a purge permit.
    ///
    /// The purge runs on a single pooled connection: the permit row is
    /// inserted, the predicate re-verified, and the generation row deleted
    /// inside one transaction, and the permit row is removed before commit
    /// (a lease minted between check and delete would otherwise be
    /// orphaned). The permit is therefore never visible outside the
    /// purging transaction — a crashed purge rolls it back, and it cannot
    /// leak onto a reused pooled connection to authorize an unrelated
    /// delete. Host generations are refused while any checkpoint
    /// references them ([`Database::host_generation_has_checkpoints`]):
    /// purging those would make audit history unverifiable.
    ///
    /// `current_key_ids` carries the live generations (the current issuer
    /// and host ids): purging one of those is refused with
    /// [`PurgeOutcome::CurrentGeneration`] even when it has no live lease
    /// references yet. The boot purge pass already excludes them, but the
    /// store refuses too, so no caller can orphan the signing key the
    /// kernel is actively using.
    pub async fn purge_key_generation(
        &self,
        workspace_id: &WorkspaceId,
        key_id: &str,
        now_ms: i64,
        current_key_ids: &[&str],
    ) -> Result<PurgeOutcome, RepositoryError> {
        if current_key_ids.contains(&key_id) {
            return Ok(PurgeOutcome::CurrentGeneration);
        }
        let role: Option<String> = sqlx::query_scalar(
            "SELECT role FROM kernel_key_generations WHERE workspace_id=? AND key_id=?",
        )
        .bind(ws(workspace_id))
        .bind(key_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(role) = role else {
            return Ok(PurgeOutcome::NotFound);
        };
        if role == "host"
            && self
                .host_generation_has_checkpoints(workspace_id, key_id)
                .await?
        {
            return Err(RepositoryError::InvalidKernelLeaseState(format!(
                "purge refused: host generation {key_id} has retained checkpoints"
            )));
        }
        let mut conn = self.pool().acquire().await?;
        // Defensive: a reused pooled connection must never carry a
        // leftover permit row into the purge.
        sqlx::query("DELETE FROM _kernel_key_purge_permit")
            .execute(&mut *conn)
            .await?;
        let outcome = purge_key_generation_permitted(&mut conn, workspace_id, key_id, now_ms).await;
        // Belt-and-braces: the permit row is inserted and removed inside
        // the purge transaction, so it is never visible outside it; this
        // guarantees no residue on the pooled connection whatever path the
        // purge took.
        sqlx::query("DELETE FROM _kernel_key_purge_permit")
            .execute(&mut *conn)
            .await?;
        outcome
    }
}

/// One recorded kernel key generation: a retired or live generation's
/// public key, keyed by the `key_id` that signatures reference.
#[derive(Clone, Debug)]
pub struct KernelKeyGenerationRow {
    pub key_id: String,
    pub role: String,
    pub verifying_key_hex: String,
    pub created_at_ms: i64,
}

/// One durable session registry row: public identity only — subject,
/// parent, verifying key, liveness. Private keys are never persisted.
#[derive(Clone, Debug)]
pub struct KernelSessionRow {
    pub subject: String,
    pub parent_subject: Option<String>,
    pub verifying_key_hex: String,
    pub active: bool,
    pub created_at_ms: i64,
    pub destroyed_at_ms: Option<i64>,
}

/// Outcome of [`Database::purge_key_generation`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PurgeOutcome {
    /// The generation row was deleted.
    Purged,
    /// The row was kept: at least one live lease still references it.
    StillReferenced,
    /// The row was kept: it is one of the kernel's live generations
    /// (current issuer/host). Purging it would orphan the signing key in
    /// active use.
    CurrentGeneration,
    /// No row exists for (workspace_id, key_id).
    NotFound,
}

/// Parameters for [`Database::kill_key_generation_with_audit`]: the kill
/// row fields plus the audit event that must commit in the same
/// transaction.
#[derive(Clone, Copy, Debug)]
pub struct KillGenerationRequest<'a> {
    /// Generation id to kill.
    pub key_id: &'a str,
    /// `"issuer"` or `"host"`.
    pub role: &'a str,
    /// Kill timestamp (also the audit event's timestamp).
    pub killed_at_ms: i64,
    /// Human-readable reason (durable).
    pub reason: &'a str,
    /// Authorizing operator principal (`provider:subject`).
    pub killed_by: &'a str,
    /// The audit event appended atomically with the kill row.
    pub audit: &'a KernelAuditAppend<'a>,
}

fn session_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<KernelSessionRow, RepositoryError> {
    Ok(KernelSessionRow {
        subject: r.get("subject"),
        parent_subject: r.get("parent_subject"),
        verifying_key_hex: r.get("verifying_key_hex"),
        active: r.get::<i64, _>("active") != 0,
        created_at_ms: r.get("created_at_ms"),
        destroyed_at_ms: r.get("destroyed_at_ms"),
    })
}

/// Live references to a generation inside `tx`: leases with
/// `issuer_key_id=key_id` that are neither revoked nor expired. Shared by
/// [`Database::live_lease_refs_to_generation`] and the purge path, which
/// must re-verify the predicate on the same connection that deletes.
async fn live_lease_refs_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    key_id: &str,
    now_ms: i64,
) -> Result<u64, RepositoryError> {
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_leases l
         WHERE l.workspace_id=? AND l.issuer_key_id=?
           AND json_extract(l.limits_json,'$.expires_at_ms')>?
           AND NOT EXISTS (
             SELECT 1 FROM kernel_revocations r
             WHERE r.workspace_id=l.workspace_id AND r.lease_id=l.lease_id
           )",
    )
    .bind(ws(workspace_id))
    .bind(key_id)
    .bind(now_ms)
    .fetch_one(&mut **tx)
    .await?;
    Ok(n as u64)
}

/// Run the guarded delete: re-verify the live-lease predicate, insert the
/// permit row, delete the generation row, and remove the permit row in one
/// transaction. The trigger authorizes the delete because the permit row is
/// visible inside this transaction — and only inside it, so the permit can
/// never authorize a delete from any other transaction or connection.
async fn purge_key_generation_permitted(
    conn: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    key_id: &str,
    now_ms: i64,
) -> Result<PurgeOutcome, RepositoryError> {
    use sqlx::Acquire;
    let mut tx = (&mut *conn).begin().await?;
    if live_lease_refs_tx(&mut tx, workspace_id, key_id, now_ms).await? != 0 {
        tx.rollback().await?;
        return Ok(PurgeOutcome::StillReferenced);
    }
    sqlx::query("INSERT INTO _kernel_key_purge_permit(key_id) VALUES(?)")
        .bind(key_id)
        .execute(&mut *tx)
        .await?;
    let deleted =
        sqlx::query("DELETE FROM kernel_key_generations WHERE workspace_id=? AND key_id=?")
            .bind(ws(workspace_id))
            .bind(key_id)
            .execute(&mut *tx)
            .await?;
    if deleted.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(PurgeOutcome::NotFound);
    }
    // Remove the permit before commit: it must never be visible outside
    // this transaction.
    sqlx::query("DELETE FROM _kernel_key_purge_permit WHERE key_id=?")
        .bind(key_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(PurgeOutcome::Purged)
}

/// Parameters for one audit event append, mirroring the frozen v1
/// [`AuditEvent`]: `actor` is the kernel actor string (`"kernel"`,
/// `"ed25519:<session-id>"`, or a human subject); `decision` is `"allow"` |
/// `"deny"` | `"pending"`, or `None` when the event records no decision.
#[derive(Clone, Debug)]
pub struct KernelAuditAppend<'a> {
    pub actor: &'a str,
    pub kind: AuditEventKind,
    pub session_id: &'a str,
    pub action_digest: &'a str,
    pub decision: Option<&'a str>,
    pub timestamp_ms: i64,
    pub details: Value,
}

/// Provenance query filters for the kernel audit log.
#[derive(Clone, Debug, Default)]
pub struct KernelAuditQuery {
    pub action_digest: Option<String>,
    pub actor: Option<String>,
    pub decision: Option<String>,
    pub min_seq: Option<u64>,
    pub max_seq: Option<u64>,
    pub limit: Option<u64>,
}

/// Attempts for [`Database::append_kernel_audit_event`]: with jittered
/// backoff between attempts, this is far beyond any plausible burst of
/// concurrent writers.
const AUDIT_APPEND_RETRIES: u32 = 32;

/// Backoff between audit-append retries: exponential with full jitter, so
/// colliding writers decorrelate instead of retrying in lockstep.
async fn audit_retry_backoff(attempt: u32) {
    use rand::Rng;
    let cap_ms = 5u64.saturating_mul(1 << attempt.min(6));
    let delay_ms = rand::thread_rng().gen_range(0..cap_ms.max(1));
    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
}

/// One append attempt inside an already-open transaction: read the tip,
/// seal the event, insert it. On a sequence race with a concurrent writer
/// the gapless-sequence trigger aborts the insert and the caller retries.
async fn append_audit_attempt(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    params: &KernelAuditAppend<'_>,
) -> Result<AuditEvent, RepositoryError> {
    if params.action_digest.is_empty() {
        return Err(RepositoryError::KernelAuditBreak(
            "action_digest must not be empty".to_string(),
        ));
    }
    let actor =
        parse_actor(params.actor).map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
    let detail = render_detail(&params.details)
        .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
    let tip: Option<(i64, String)> = sqlx::query_as(
        "SELECT seq,hash FROM kernel_audit_events WHERE workspace_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(ws(workspace_id))
    .fetch_optional(&mut **tx)
    .await?;
    let (sequence, prev_hash) = match tip {
        Some((seq, hash)) => (seq as u64 + 1, hash),
        None => (0, GENESIS_PREV_HASH.to_string()),
    };
    let event = AuditEvent {
        version: AUDIT_EVENT_VERSION,
        event_id: Uuid::new_v4(),
        sequence,
        timestamp_ms: params.timestamp_ms,
        actor,
        kind: params.kind,
        session_id: params.session_id.to_string(),
        action_digest: params.action_digest.to_string(),
        decision: params.decision.map(str::to_string),
        detail,
        prev_hash: String::new(),
        hash: String::new(),
    };
    let sealed = seal_event(event, &prev_hash)
        .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
    sqlx::query(
        "INSERT INTO kernel_audit_events(workspace_id,seq,version,event_id,kind,actor,
         session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(ws(workspace_id))
    .bind(sealed.sequence as i64)
    .bind(sealed.version as i64)
    .bind(sealed.event_id.to_string())
    .bind(sealed.kind.as_str())
    .bind(actor_to_string(&sealed.actor))
    .bind(&sealed.session_id)
    .bind(&sealed.action_digest)
    .bind(sealed.decision.as_deref())
    .bind(&sealed.detail)
    .bind(&sealed.prev_hash)
    .bind(&sealed.hash)
    .bind(sealed.timestamp_ms)
    .execute(&mut **tx)
    .await?;
    Ok(sealed)
}

/// True when `e` is a transient write conflict the caller should retry:
/// the gapless-sequence trigger aborting a lost sequence race, or SQLite
/// reporting the database locked/busy under WAL concurrency (including
/// `SQLITE_BUSY_SNAPSHOT`, which the busy timeout does not cover). The
/// transaction rolled back; the retry re-reads the tip and appends after it.
fn is_retryable(e: &RepositoryError) -> bool {
    match e {
        RepositoryError::Sqlx(sqlx::Error::Database(d)) => {
            let msg = d.message();
            msg.contains("audit seq must be gapless") || msg.contains("database is locked")
        }
        _ => false,
    }
}

/// Insert one lease row inside `tx`, recomputing and comparing the scope and
/// document digests first. Shared by [`Database::insert_kernel_lease`] and
/// [`Database::mint_kernel_child_lease`].
async fn insert_lease_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    doc: &LeaseDocument,
) -> Result<(), RepositoryError> {
    let scope_digest = doc
        .scope
        .canonical_digest()
        .map_err(|e| RepositoryError::InvalidKernelLeaseState(e.to_string()))?;
    let scope_json = serde_json::to_string(&doc.scope).map_err(RepositoryError::Serialization)?;
    let limits_json = serde_json::to_string(&doc.limits).map_err(RepositoryError::Serialization)?;
    let document_digest = doc
        .digest()
        .map_err(|e| RepositoryError::InvalidKernelLeaseState(e.to_string()))?;
    sqlx::query(
        "INSERT INTO kernel_leases(lease_id,workspace_id,parent_id,subject,issuer_key_id,
         issued_at_ms,protocol_version,scope_digest,scope_json,limits_json,depth,depth_limit,
         lease_nonce,signature,document_digest,created_at,approved_action_digest)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&doc.lease_id)
    .bind(ws(workspace_id))
    .bind(doc.parent_id.as_deref())
    .bind(&doc.subject)
    .bind(&doc.issuer_key_id)
    .bind(doc.issued_at_ms)
    .bind(doc.protocol_version as i64)
    .bind(&scope_digest)
    .bind(&scope_json)
    .bind(&limits_json)
    .bind(doc.depth as i64)
    .bind(doc.depth_limit as i64)
    .bind(&doc.lease_nonce)
    .bind(&doc.signature)
    .bind(&document_digest)
    .bind(doc.issued_at_ms)
    .bind(doc.approved_action_digest.as_deref())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Carve a reservation for `child_lease_id` out of the parent's account
/// inside `tx`, returning the reservation id. The parent's remaining balance
/// is re-checked in SQL-visible state, so concurrent reservations against
/// the same parent cannot overspend. Shared by
/// [`Database::reserve_kernel_budget`] and [`Database::mint_kernel_child_lease`].
async fn reserve_budget_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    parent_lease_id: &str,
    child_lease_id: &str,
    requested: &Budget,
    now_ms: i64,
) -> Result<String, RepositoryError> {
    let row = sqlx::query(
        "SELECT caps_json,reserved_out_json,consumed_json FROM kernel_budget_accounts
         WHERE workspace_id=? AND lease_id=?",
    )
    .bind(ws(workspace_id))
    .bind(parent_lease_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| insufficient(&format!("unknown parent lease {parent_lease_id}")))?;
    let caps = parse_budget(row.get::<String, _>("caps_json").as_str())?;
    let reserved_out = parse_budget(row.get::<String, _>("reserved_out_json").as_str())?;
    let consumed = parse_budget(row.get::<String, _>("consumed_json").as_str())?;
    let remaining = caps.saturating_sub(&reserved_out).saturating_sub(&consumed);
    if !remaining.covers(requested) {
        return Err(insufficient(&format!(
            "parent {parent_lease_id} cannot cover reservation for {child_lease_id}"
        )));
    }
    let reservation_id = format!("res_{}", Uuid::new_v4().simple());
    let held_json = budget_json(requested)?;
    let zero = budget_json(&Budget::new())?;
    sqlx::query(
        "INSERT INTO kernel_reservations(reservation_id,workspace_id,parent_lease_id,
         child_lease_id,held_json,consumed_json,state,created_at_ms,released_at_ms)
         VALUES(?,?,?,?,?,?,'active',?,NULL)",
    )
    .bind(&reservation_id)
    .bind(ws(workspace_id))
    .bind(parent_lease_id)
    .bind(child_lease_id)
    .bind(&held_json)
    .bind(&zero)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    let new_reserved = reserved_out
        .checked_add(requested)
        .ok_or_else(|| insufficient("reserved_out overflow"))?;
    sqlx::query(
        "UPDATE kernel_budget_accounts SET reserved_out_json=?,updated_at=?
         WHERE workspace_id=? AND lease_id=?",
    )
    .bind(budget_json(&new_reserved)?)
    .bind(now_ms)
    .bind(ws(workspace_id))
    .bind(parent_lease_id)
    .execute(&mut **tx)
    .await?;
    Ok(reservation_id)
}

/// Register a lease's budget caps inside `tx`. Re-registering the same
/// lease is a conflict (fail closed). Shared by
/// [`Database::register_kernel_budget`] and [`Database::mint_kernel_child_lease`].
async fn register_budget_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    lease_id: &str,
    caps: &Budget,
    now_ms: i64,
) -> Result<(), RepositoryError> {
    let zero = budget_json(&Budget::new())?;
    let res = sqlx::query(
        "INSERT OR IGNORE INTO kernel_budget_accounts(lease_id,workspace_id,caps_json,
         reserved_out_json,consumed_json,updated_at) VALUES(?,?,?,?,?,?)",
    )
    .bind(lease_id)
    .bind(ws(workspace_id))
    .bind(budget_json(caps)?)
    .bind(&zero)
    .bind(&zero)
    .bind(now_ms)
    .execute(&mut **tx)
    .await?;
    if res.rows_affected() == 0 {
        return Err(RepositoryError::KernelReservationConflict);
    }
    Ok(())
}

/// Move `actual` from a parent account's reserved_out into its consumed,
/// atomically. A reservation debit reclassifies the spend: it was reserved
/// at reserve time and is consumed now. Shrinking reserved_out by `actual`
/// while growing consumed by `actual` keeps the parent's remaining balance
/// (caps − reserved_out − consumed) exact — counting the spend in both
/// would shrink it twice. Shared by [`Database::debit_kernel_budget`] and
/// the child-lease post-through in [`Database::debit_kernel_lease`].
async fn post_parent_debit_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    workspace_id: &WorkspaceId,
    parent_lease_id: &str,
    actual: &Budget,
    now_ms: i64,
) -> Result<(), RepositoryError> {
    let acct = sqlx::query(
        "SELECT reserved_out_json,consumed_json FROM kernel_budget_accounts
         WHERE workspace_id=? AND lease_id=?",
    )
    .bind(ws(workspace_id))
    .bind(parent_lease_id)
    .fetch_one(&mut **tx)
    .await?;
    let reserved_out = parse_budget(acct.get::<String, _>("reserved_out_json").as_str())?;
    let acct_consumed = parse_budget(acct.get::<String, _>("consumed_json").as_str())?;
    let reserved_new = reserved_out.saturating_sub(actual);
    let acct_new = acct_consumed
        .checked_add(actual)
        .ok_or_else(|| insufficient("account consumed overflow"))?;
    sqlx::query(
        "UPDATE kernel_budget_accounts
         SET reserved_out_json=?,consumed_json=?,updated_at=?
         WHERE workspace_id=? AND lease_id=?",
    )
    .bind(budget_json(&reserved_new)?)
    .bind(budget_json(&acct_new)?)
    .bind(now_ms)
    .bind(ws(workspace_id))
    .bind(parent_lease_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn lease_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<LeaseDocument, RepositoryError> {
    Ok(LeaseDocument {
        protocol_version: r.get::<i64, _>("protocol_version") as u32,
        lease_id: r.get("lease_id"),
        parent_id: r.get("parent_id"),
        subject: r.get("subject"),
        issuer_key_id: r.get("issuer_key_id"),
        issued_at_ms: r.get("issued_at_ms"),
        scope: serde_json::from_str(r.get::<String, _>("scope_json").as_str())
            .map_err(RepositoryError::Serialization)?,
        limits: serde_json::from_str(r.get::<String, _>("limits_json").as_str())
            .map_err(RepositoryError::Serialization)?,
        depth: r.get::<i64, _>("depth") as u32,
        depth_limit: r.get::<i64, _>("depth_limit") as u32,
        lease_nonce: r.get("lease_nonce"),
        signature: r.get("signature"),
        // NULL marks a standing lease or a legacy one-shot row minted before
        // digest binding. Legacy one-shot rows fail closed at authorization:
        // the kernel denies any single-use lease whose recorded digest does
        // not match the presented action, and NULL never matches.
        approved_action_digest: r.get("approved_action_digest"),
    })
}

fn audit_event_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<AuditEvent, RepositoryError> {
    let version = r.get::<i64, _>("version") as u32;
    if version != AUDIT_EVENT_VERSION {
        return Err(RepositoryError::KernelAuditBreak(format!(
            "unsupported audit event version {version}"
        )));
    }
    let kind = match r.get::<String, _>("kind").as_str() {
        "action_proposed" => AuditEventKind::ActionProposed,
        "policy_allowed" => AuditEventKind::PolicyAllowed,
        "policy_denied" => AuditEventKind::PolicyDenied,
        "approval_requested" => AuditEventKind::ApprovalRequested,
        "transport_rejected" => AuditEventKind::TransportRejected,
        "tool_executed" => AuditEventKind::ToolExecuted,
        other => {
            return Err(RepositoryError::KernelAuditBreak(format!(
                "unknown audit event kind {other}"
            )));
        }
    };
    let event_id = Uuid::parse_str(r.get::<String, _>("event_id").as_str())
        .map_err(|e| RepositoryError::KernelAuditBreak(format!("bad audit event_id: {e}")))?;
    let actor = parse_actor(r.get::<String, _>("actor").as_str())
        .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
    Ok(AuditEvent {
        version,
        event_id,
        sequence: r.get::<i64, _>("seq") as u64,
        timestamp_ms: r.get("timestamp_ms"),
        actor,
        kind,
        session_id: r.get("session_id"),
        action_digest: r.get("action_digest"),
        decision: r.get("decision"),
        detail: r.get("detail"),
        prev_hash: r.get("prev_hash"),
        hash: r.get("hash"),
    })
}
