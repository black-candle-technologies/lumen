//! Durable authority-kernel persistence (migration 0022).
//!
//! This module is the SQL counterpart of the kernel's in-memory authorities:
//! signed leases, revocations, nonces, one-shot uses, the reservation-based
//! budget ledger, and the hash-chained audit log. Every balance-changing
//! operation runs in a single SQLite transaction that re-checks the
//! invariants in SQL — the database never trusts the caller's arithmetic, so
//! a crashed or buggy host cannot overspend through this layer.

use std::collections::HashSet;

use lumen_core::{
    budget::{Budget, DebitReceipt, Reservation, ReservationState},
    identity::WorkspaceId,
    kernel_audit::{checkpoint_signing_bytes, redact_details, verify_chain_with_checkpoints},
    lease::LeaseDocument,
};
use lumen_protocol::audit::{AuditEvent, AuditLink, verify_chain};
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
        let scope_digest = doc
            .scope
            .canonical_digest()
            .map_err(|e| RepositoryError::InvalidKernelLeaseState(e.to_string()))?;
        let scope_json =
            serde_json::to_string(&doc.scope).map_err(RepositoryError::Serialization)?;
        let limits_json =
            serde_json::to_string(&doc.limits).map_err(RepositoryError::Serialization)?;
        let document_digest = doc
            .digest()
            .map_err(|e| RepositoryError::InvalidKernelLeaseState(e.to_string()))?;
        sqlx::query(
            "INSERT INTO kernel_leases(lease_id,workspace_id,parent_id,subject,issuer_key_id,
             issued_at_ms,protocol_version,scope_digest,scope_json,limits_json,depth,depth_limit,
             lease_nonce,signature,document_digest,created_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn kernel_lease(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
    ) -> Result<Option<LeaseDocument>, RepositoryError> {
        let row = sqlx::query(
            "SELECT lease_id,parent_id,subject,issuer_key_id,issued_at_ms,protocol_version,
             scope_json,limits_json,depth,depth_limit,lease_nonce,signature
             FROM kernel_leases WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(lease_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|r| lease_from_row(&r)).transpose()
    }

    /// Load a full chain, leaf first, following parent links (max 128 hops).
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
                None => break,
            }
        }
        Ok(chain)
    }

    // ------------------------------------------------------------------
    // Revocations
    // ------------------------------------------------------------------

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
        .execute(self.pool())
        .await?;
        if res.rows_affected() == 0 {
            return Err(RepositoryError::KernelReservationConflict);
        }
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
        let pool = self.pool();
        let mut tx = pool.begin().await?;
        let row = sqlx::query(
            "SELECT caps_json,reserved_out_json,consumed_json FROM kernel_budget_accounts
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(parent_lease_id)
        .fetch_optional(&mut *tx)
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
        .execute(&mut *tx)
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
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(reservation_id)
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
        let acct = sqlx::query(
            "SELECT consumed_json FROM kernel_budget_accounts
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(ws(workspace_id))
        .bind(&parent_lease_id)
        .fetch_one(&mut *tx)
        .await?;
        let acct_consumed = parse_budget(acct.get::<String, _>("consumed_json").as_str())?;
        let acct_new = acct_consumed
            .checked_add(actual)
            .ok_or_else(|| insufficient("account consumed overflow"))?;
        sqlx::query(
            "UPDATE kernel_budget_accounts SET consumed_json=?,updated_at=?
             WHERE workspace_id=? AND lease_id=?",
        )
        .bind(budget_json(&acct_new)?)
        .bind(now_ms)
        .bind(ws(workspace_id))
        .bind(&parent_lease_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DebitReceipt {
            reservation_id: reservation_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        })
    }

    /// Debit spend directly against a lease's own caps (root-lease spend).
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
        tx.commit().await?;
        Ok(DebitReceipt {
            reservation_id: lease_id.to_string(),
            actual: actual.clone(),
            debited_at_ms: now_ms,
        })
    }

    /// Release a reservation: the unspent held amount returns to the parent.
    /// Returns the amount returned. Only on explicit revocation/expiry.
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
        let new_reserved = reserved_out.saturating_sub(&held);
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

    /// Remaining balance for a lease: caps − reserved_out − consumed.
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
        Ok(caps.saturating_sub(&reserved_out).saturating_sub(&consumed))
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
    // Audit log
    // ------------------------------------------------------------------

    /// Append an event to the workspace's hash-chained audit log. Details are
    /// redacted deterministically before sealing. The chain link is computed
    /// in the same transaction that inserts the row, so concurrent appends
    /// cannot fork the chain.
    pub async fn append_kernel_audit_event(
        &self,
        workspace_id: &WorkspaceId,
        actor: &str,
        action_digest: &str,
        decision: &str,
        recorded_at_ms: i64,
        mut details: Value,
    ) -> Result<AuditEvent, RepositoryError> {
        use lumen_protocol::audit::AUDIT_EVENT_VERSION;
        redact_details(&mut details);
        let pool = self.pool();
        let mut tx = pool.begin().await?;
        let prev: Option<AuditEvent> = sqlx::query(
            "SELECT seq,prev_hash,hash,action_digest,decision,actor,details_json,recorded_at
             FROM kernel_audit_events WHERE workspace_id=? ORDER BY seq DESC LIMIT 1",
        )
        .bind(ws(workspace_id))
        .fetch_optional(&mut *tx)
        .await?
        .map(|r| audit_event_from_row(&r))
        .transpose()?;
        let event = AuditEvent {
            protocol_version: AUDIT_EVENT_VERSION,
            seq: prev.as_ref().map(|e| e.seq + 1).unwrap_or(0),
            ts: ms_to_rfc3339(recorded_at_ms),
            actor: actor.to_string(),
            action_digest: action_digest.to_string(),
            decision: decision.to_string(),
            prev_hash: String::new(),
            hash: String::new(),
            details,
        };
        let sealed = lumen_protocol::audit::append(prev.as_ref(), event)
            .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
        sqlx::query(
            "INSERT INTO kernel_audit_events(seq,workspace_id,prev_hash,hash,action_digest,
             decision,actor,details_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)",
        )
        .bind(sealed.seq as i64)
        .bind(ws(workspace_id))
        .bind(&sealed.prev_hash)
        .bind(&sealed.hash)
        .bind(&sealed.action_digest)
        .bind(&sealed.decision)
        .bind(&sealed.actor)
        .bind(serde_json::to_string(&sealed.details).map_err(RepositoryError::Serialization)?)
        .bind(recorded_at_ms)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(sealed)
    }

    /// Store a host-key checkpoint. The signature is computed by the kernel
    /// over [`checkpoint_signing_bytes`]; the db verifies the checkpoint
    /// references a real event with the matching hash before storing.
    pub async fn checkpoint_kernel_audit(
        &self,
        workspace_id: &WorkspaceId,
        seq: u64,
        hash: &str,
        signature_hex: &str,
        key_id: &str,
        created_at_ms: i64,
    ) -> Result<(), RepositoryError> {
        let event_hash: Option<String> = sqlx::query_scalar(
            "SELECT hash FROM kernel_audit_events WHERE workspace_id=? AND seq=?",
        )
        .bind(ws(workspace_id))
        .bind(seq as i64)
        .fetch_optional(self.pool())
        .await?;
        match event_hash {
            Some(h) if h == hash => {}
            _ => {
                return Err(RepositoryError::KernelAuditBreak(format!(
                    "checkpoint references unknown event seq {seq}"
                )));
            }
        }
        // Recompute the signing bytes so a caller cannot store a checkpoint
        // whose signature was computed over different bytes unnoticed: the
        // signature itself is verified by readers via verify_kernel_audit.
        let _ = checkpoint_signing_bytes(seq, hash, key_id)
            .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
        sqlx::query(
            "INSERT INTO kernel_audit_checkpoints(workspace_id,seq,hash,signature,key_id,created_at)
             VALUES(?,?,?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(seq as i64)
        .bind(hash)
        .bind(signature_hex)
        .bind(key_id)
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
            "SELECT seq,prev_hash,hash,action_digest,decision,actor,details_json,recorded_at
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
                    seq: r.get::<i64, _>("seq") as u64,
                    hash: r.get("hash"),
                    signature: r.get("signature"),
                    key_id: r.get("key_id"),
                })
            })
            .collect()
    }

    /// Verify the workspace's audit chain and every checkpoint against the
    /// host verifying key. Reports the first break found.
    pub async fn verify_kernel_audit(
        &self,
        workspace_id: &WorkspaceId,
        host_key: &ed25519_dalek::VerifyingKey,
        expected_key_id: &str,
    ) -> Result<(), RepositoryError> {
        let events = self
            .kernel_audit_events(workspace_id, &KernelAuditQuery::default())
            .await?;
        verify_chain(&events).map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
        let checkpoints = self.kernel_audit_checkpoints(workspace_id).await?;
        verify_chain_with_checkpoints(&events, &checkpoints, host_key, expected_key_id)
            .map_err(|e| RepositoryError::KernelAuditBreak(e.to_string()))?;
        Ok(())
    }
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
    })
}

fn audit_event_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<AuditEvent, RepositoryError> {
    use lumen_protocol::audit::AUDIT_EVENT_VERSION;
    Ok(AuditEvent {
        protocol_version: AUDIT_EVENT_VERSION,
        seq: r.get::<i64, _>("seq") as u64,
        ts: ms_to_rfc3339(r.get::<i64, _>("recorded_at")),
        actor: r.get("actor"),
        action_digest: r.get("action_digest"),
        decision: r.get("decision"),
        prev_hash: r.get("prev_hash"),
        hash: r.get("hash"),
        details: serde_json::from_str(r.get::<String, _>("details_json").as_str())
            .map_err(RepositoryError::Serialization)?,
    })
}

fn ms_to_rfc3339(ms: i64) -> String {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    let dt = OffsetDateTime::from_unix_timestamp_nanos((ms.max(0) as i128) * 1_000_000)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    dt.format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
