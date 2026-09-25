//! Durable Phase 4 human-authority state (migration 0025).
//!
//! Stores VHL approval requests, their decisions, and hold-and-release
//! challenges. Replay uses the 0022 `kernel_nonces` table (attestation id as
//! nonce); one-shot consumption uses `kernel_one_shot_uses`; audit events go
//! through the standard kernel audit path. No session private keys are ever
//! persisted — the identity vault is kernel memory only.

use lumen_core::{
    identity::WorkspaceId,
    vhl::{ApprovalKind, VhlApprovalRequest, VhlCourierMessage, VhlRequestState},
};
use sqlx::Row;

use crate::{Database, RepositoryError};

fn ws(workspace_id: &WorkspaceId) -> String {
    workspace_id.to_string()
}

fn view_kind_to_state_column(request: &VhlApprovalRequest) -> &'static str {
    match request.state {
        VhlRequestState::Requested => "requested",
        VhlRequestState::Approved { .. } => "approved",
        VhlRequestState::Denied { .. } => "denied",
        VhlRequestState::Expired { .. } => "expired",
        VhlRequestState::Minted { .. } => "minted",
        VhlRequestState::Consumed { .. } => "consumed",
    }
}

/// Row read back from `vhl_approval_requests` — a snapshot of the durable
/// state machine plus the immutable request body.
#[derive(Clone, Debug)]
pub struct VhlRequestRow {
    pub request_id: String,
    pub kind: ApprovalKind,
    pub state: String,
    pub action_digest: String,
    pub session_subject: String,
    pub nonce: String,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub decided_at_ms: Option<i64>,
    pub decided_by: Option<String>,
    pub decision_reason: Option<String>,
    pub attestation_id: Option<String>,
    pub lease_id: Option<String>,
    pub minted_at_ms: Option<i64>,
    pub consumed_at_ms: Option<i64>,
}

impl Database {
    /// Persist a newly opened approval request. The `UNIQUE(workspace_id,
    /// nonce)` guard makes a duplicate open fail closed instead of
    /// shadowing the original request.
    pub async fn vhl_insert_request(
        &self,
        workspace_id: &WorkspaceId,
        request: &VhlApprovalRequest,
    ) -> Result<(), RepositoryError> {
        let view_json =
            serde_json::to_value(&request.view).map_err(RepositoryError::Serialization)?;
        let view_json =
            serde_json::to_string(&view_json).map_err(RepositoryError::Serialization)?;
        let input_hashes =
            serde_json::to_string(&request.input_hashes).map_err(RepositoryError::Serialization)?;
        sqlx::query(
            "INSERT INTO vhl_approval_requests(request_id,workspace_id,action_digest,input_hashes_json,\
            session_subject,nonce,created_at_ms,expires_at_ms,state,view_json) \
            VALUES(?,?,?,?,?,?,?,?,?,?)",
        )
        .bind(&request.request_id)
        .bind(ws(workspace_id))
        .bind(&request.action_digest)
        .bind(&input_hashes)
        .bind(&request.session_subject)
        .bind(&request.nonce)
        .bind(request.created_at_ms)
        .bind(request.expires_at_ms)
        .bind(view_kind_to_state_column(request))
        .bind(&view_json)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Read back an approval request's durable state.
    pub async fn vhl_request(
        &self,
        workspace_id: &WorkspaceId,
        request_id: &str,
    ) -> Result<Option<VhlRequestRow>, RepositoryError> {
        let row = sqlx::query(
            "SELECT request_id,state,action_digest,session_subject,nonce,created_at_ms,expires_at_ms, \
            decided_at_ms,decided_by,decision_reason,attestation_id,lease_id,minted_at_ms,consumed_at_ms, \
            view_json FROM vhl_approval_requests WHERE workspace_id=? AND request_id=?",
        )
        .bind(ws(workspace_id))
        .bind(request_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(r) = row else {
            return Ok(None);
        };
        // The kind is part of the immutable request body (ApprovalView).
        let view_json: String = r.try_get("view_json")?;
        let view: serde_json::Value =
            serde_json::from_str(&view_json).map_err(RepositoryError::Serialization)?;
        let kind = match view.get("kind").and_then(serde_json::Value::as_str) {
            Some("standing_lease") => ApprovalKind::StandingLease,
            Some("one_shot") | None => ApprovalKind::OneShot,
            Some(other) => {
                return Err(RepositoryError::InvalidVhlState(format!(
                    "unknown approval kind {other:?}"
                )));
            }
        };
        Ok(Some(VhlRequestRow {
            request_id: r.try_get("request_id")?,
            kind,
            state: r.try_get("state")?,
            action_digest: r.try_get("action_digest")?,
            session_subject: r.try_get("session_subject")?,
            nonce: r.try_get("nonce")?,
            created_at_ms: r.try_get("created_at_ms")?,
            expires_at_ms: r.try_get("expires_at_ms")?,
            decided_at_ms: r.try_get("decided_at_ms")?,
            decided_by: r.try_get("decided_by")?,
            decision_reason: r.try_get("decision_reason")?,
            attestation_id: r.try_get("attestation_id")?,
            lease_id: r.try_get("lease_id")?,
            minted_at_ms: r.try_get("minted_at_ms")?,
            consumed_at_ms: r.try_get("consumed_at_ms")?,
        }))
    }

    /// Atomically transition a request along a post-decision edge. The
    /// compare-and-swap on the current state (plus the SQL trigger's
    /// forward-only guard) makes concurrent or repeated transitions fail
    /// closed with `VhlStateConflict` instead of silently winning twice.
    ///
    /// Only the `approved → minted` and `minted → consumed` edges are
    /// allowed here. Recording a decision (`requested → approved/denied`)
    /// must go through [`Self::vhl_record_decision`], which writes the
    /// `vhl_decisions` row atomically with the transition — this method
    /// cannot, so permitting a decision edge here would silently skip the
    /// decision row the module documents as atomic.
    /// List approval requests in a given durable state, newest last (for
    /// the host/VHL poller). Reads the database, not any in-memory
    /// mirror, so a poller sees requests that survived a restart.
    pub async fn vhl_list_requests(
        &self,
        workspace_id: &WorkspaceId,
        state: &str,
    ) -> Result<Vec<VhlRequestRow>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT request_id,action_digest,session_subject,nonce,created_at_ms,expires_at_ms, \
            decided_at_ms,decided_by,decision_reason,attestation_id,lease_id,minted_at_ms,consumed_at_ms, \
            view_json FROM vhl_approval_requests WHERE workspace_id=? AND state=? \
            ORDER BY created_at_ms ASC",
        )
        .bind(ws(workspace_id))
        .bind(state)
        .fetch_all(self.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in rows {
            let view_json: String = r.try_get("view_json")?;
            let view: serde_json::Value =
                serde_json::from_str(&view_json).map_err(RepositoryError::Serialization)?;
            let kind = match view.get("kind").and_then(serde_json::Value::as_str) {
                Some("standing_lease") => ApprovalKind::StandingLease,
                Some("one_shot") | None => ApprovalKind::OneShot,
                Some(other) => {
                    return Err(RepositoryError::InvalidVhlState(format!(
                        "unknown approval kind {other:?}"
                    )));
                }
            };
            out.push(VhlRequestRow {
                request_id: r.try_get("request_id")?,
                kind,
                state: state.to_string(),
                action_digest: r.try_get("action_digest")?,
                session_subject: r.try_get("session_subject")?,
                nonce: r.try_get("nonce")?,
                created_at_ms: r.try_get("created_at_ms")?,
                expires_at_ms: r.try_get("expires_at_ms")?,
                decided_at_ms: r.try_get("decided_at_ms")?,
                decided_by: r.try_get("decided_by")?,
                decision_reason: r.try_get("decision_reason")?,
                attestation_id: r.try_get("attestation_id")?,
                lease_id: r.try_get("lease_id")?,
                minted_at_ms: r.try_get("minted_at_ms")?,
                consumed_at_ms: r.try_get("consumed_at_ms")?,
            });
        }
        Ok(out)
    }

    /// Atomically transition a request. The compare-and-swap on the current
    /// state (plus the SQL trigger's forward-only guard) makes concurrent or
    /// repeated decisions fail closed with `VhlStateConflict` instead of
    /// silently winning twice.
    #[allow(clippy::too_many_arguments)]
    pub async fn vhl_transition(
        &self,
        workspace_id: &WorkspaceId,
        request_id: &str,
        expected_state: &str,
        new_state: &str,
        decided_at_ms: Option<i64>,
        decided_by: Option<&str>,
        decision_reason: Option<&str>,
        attestation_id: Option<&str>,
        lease_id: Option<&str>,
        minted_at_ms: Option<i64>,
        consumed_at_ms: Option<i64>,
    ) -> Result<(), RepositoryError> {
        if !matches!(
            (expected_state, new_state),
            ("approved", "minted") | ("minted", "consumed")
        ) {
            return Err(RepositoryError::VhlStateConflict);
        }
        let rows = sqlx::query(
            "UPDATE vhl_approval_requests SET state=?,decided_at_ms=COALESCE(?,decided_at_ms), \
            decided_by=COALESCE(?,decided_by),decision_reason=COALESCE(?,decision_reason), \
            attestation_id=COALESCE(?,attestation_id),lease_id=COALESCE(?,lease_id), \
            minted_at_ms=COALESCE(?,minted_at_ms),consumed_at_ms=COALESCE(?,consumed_at_ms) \
            WHERE workspace_id=? AND request_id=? AND state=?",
        )
        .bind(new_state)
        .bind(decided_at_ms)
        .bind(decided_by)
        .bind(decision_reason)
        .bind(attestation_id)
        .bind(lease_id)
        .bind(minted_at_ms)
        .bind(consumed_at_ms)
        .bind(ws(workspace_id))
        .bind(request_id)
        .bind(expected_state)
        .execute(self.pool())
        .await
        .map_err(|e| match e {
            // The trigger rejected the state edge or a set-once rewrite:
            // a semantic conflict, not a database fault.
            sqlx::Error::Database(db)
                if db.message().contains("illegal state transition")
                    || db.message().contains("decision column rewritten") =>
            {
                RepositoryError::VhlStateConflict
            }
            other => RepositoryError::from(other),
        })?;
        if rows.rows_affected() == 0 {
            return Err(RepositoryError::VhlStateConflict);
        }
        Ok(())
    }

    /// Append an immutable decision event. The decision row and the request
    /// transition are written in one transaction so the audit trail can
    /// never observe a decision without the state, or vice versa.
    #[allow(clippy::too_many_arguments)]
    pub async fn vhl_record_decision(
        &self,
        workspace_id: &WorkspaceId,
        request_id: &str,
        decision: &str,
        approver: &str,
        attestation_id: Option<&str>,
        reason: &str,
        decided_at_ms: i64,
        expected_state: &str,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let rows = sqlx::query(
            "UPDATE vhl_approval_requests SET state=?,decided_at_ms=?,decided_by=?,decision_reason=?, \
            attestation_id=COALESCE(?,attestation_id) \
            WHERE workspace_id=? AND request_id=? AND state=?",
        )
        .bind(decision)
        .bind(decided_at_ms)
        .bind(approver)
        .bind(reason)
        .bind(attestation_id)
        .bind(ws(workspace_id))
        .bind(request_id)
        .bind(expected_state)
        .execute(&mut *tx)
        .await?;
        if rows.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(RepositoryError::VhlStateConflict);
        }
        sqlx::query(
            "INSERT INTO vhl_decisions(workspace_id,request_id,decision,approver,attestation_id,reason,decided_at_ms) \
            VALUES(?,?,?,?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(request_id)
        .bind(decision)
        .bind(approver)
        .bind(attestation_id)
        .bind(reason)
        .bind(decided_at_ms)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Claim an attestation id in `kernel_nonces`. The nonce is namespaced
    /// (`vhl-attestation:<id>`) so it cannot collide with other nonce uses.
    /// Returns `Ok(true)` on first use; `Ok(false)` means this exact
    /// attestation already authorized something — replay, fail closed.
    pub async fn vhl_claim_attestation(
        &self,
        workspace_id: &WorkspaceId,
        attestation_id: &str,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<bool, RepositoryError> {
        let namespaced = format!("vhl-attestation:{attestation_id}");
        let res = sqlx::query(
            "INSERT INTO kernel_nonces(workspace_id,nonce,used_at_ms,expires_at_ms) \
            VALUES(?,?,?,?)",
        )
        .bind(ws(workspace_id))
        .bind(&namespaced)
        .bind(now_ms)
        .bind(now_ms.saturating_add(ttl_ms))
        .execute(self.pool())
        .await;
        match res {
            Ok(_) => Ok(true),
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Mark a one-shot lease consumed in `kernel_one_shot_uses`. Returns
    /// `Ok(true)` on first consumption; `Ok(false)` on a replayed use.
    pub async fn vhl_claim_one_shot_use(
        &self,
        workspace_id: &WorkspaceId,
        lease_id: &str,
        now_ms: i64,
    ) -> Result<bool, RepositoryError> {
        let res = sqlx::query(
            "INSERT INTO kernel_one_shot_uses(lease_id,workspace_id,consumed_at_ms) VALUES(?,?,?)",
        )
        .bind(lease_id)
        .bind(ws(workspace_id))
        .bind(now_ms)
        .execute(self.pool())
        .await;
        match res {
            Ok(_) => Ok(true),
            Err(sqlx::Error::Database(db)) if db.is_unique_violation() => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    // ------------------------------------------------------------------
    // Hold-and-release challenges
    // ------------------------------------------------------------------

    /// Store a challenge. Only the SHA-256 of the one-time code is stored —
    /// the code itself never touches the database.
    pub async fn vhl_insert_challenge(
        &self,
        workspace_id: &WorkspaceId,
        challenge_id: &str,
        action_digest: &str,
        code_hash: &str,
        issued_at_ms: i64,
        expires_at_ms: i64,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO vhl_challenges(challenge_id,workspace_id,action_digest,code_hash, \
            issued_at_ms,expires_at_ms) VALUES(?,?,?,?,?,?)",
        )
        .bind(challenge_id)
        .bind(ws(workspace_id))
        .bind(action_digest)
        .bind(code_hash)
        .bind(issued_at_ms)
        .bind(expires_at_ms)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    /// Submit the out-of-band code for a challenge. A correct code completes
    /// the ceremony (`ceremony_complete=1`); it does *not* authorize anything
    /// by itself — the authorization is consumed exactly once by
    /// [`Self::vhl_consume_challenge`] during decision verification.
    /// Returns false for unknown, used, expired, or action-mismatched
    /// challenges and for wrong codes.
    pub async fn vhl_complete_challenge(
        &self,
        workspace_id: &WorkspaceId,
        challenge_id: &str,
        code: &str,
        action_digest: &str,
        now_ms: i64,
    ) -> Result<bool, RepositoryError> {
        use sha2::{Digest, Sha256};
        let mut tx = self.pool().begin().await?;
        let row: Option<(String, String, i64, i64, i64)> = sqlx::query_as(
            "SELECT code_hash,action_digest,expires_at_ms,attempts,used FROM vhl_challenges \
            WHERE workspace_id=? AND challenge_id=?",
        )
        .bind(ws(workspace_id))
        .bind(challenge_id)
        .fetch_optional(&mut *tx)
        .await?;
        let Some((code_hash, stored_digest, expires_at_ms, attempts, used)) = row else {
            tx.rollback().await?;
            return Ok(false);
        };
        if used != 0 {
            tx.rollback().await?;
            return Ok(false);
        }
        if now_ms >= expires_at_ms {
            sqlx::query("UPDATE vhl_challenges SET used=1 WHERE challenge_id=? AND used=0")
                .bind(challenge_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(false);
        }
        // Hash construction matches the core `ChallengeRegistry`: plain
        // SHA-256 over the code bytes. Only the hash is stored.
        let candidate = hex::encode(Sha256::digest(code.as_bytes()));
        let digest_ok =
            subtle::ConstantTimeEq::ct_eq(stored_digest.as_bytes(), action_digest.as_bytes())
                .unwrap_u8()
                == 1;
        let code_ok = subtle::ConstantTimeEq::ct_eq(code_hash.as_bytes(), candidate.as_bytes())
            .unwrap_u8()
            == 1;
        if !digest_ok || attempts >= 5 || !code_ok {
            // Wrong code (or wrong action): count the attempt; five wrong
            // attempts burn the challenge.
            let _ = sqlx::query(
                "UPDATE vhl_challenges SET attempts=attempts+1,used=CASE WHEN attempts+1>=5 THEN 1 ELSE used END WHERE challenge_id=?",
            )
            .bind(challenge_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            return Ok(false);
        }
        let rows = sqlx::query(
            "UPDATE vhl_challenges SET ceremony_complete=1 WHERE challenge_id=? AND used=0 AND ceremony_complete=0",
        )
        .bind(challenge_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(rows.rows_affected() == 1)
    }

    /// Consume a completed challenge ceremony for exactly this action. The
    /// compare-and-swap on `(used, ceremony_complete)` makes each ceremony
    /// authorize at most one decision, even under concurrency.
    pub async fn vhl_consume_challenge(
        &self,
        workspace_id: &WorkspaceId,
        challenge_id: &str,
        action_digest: &str,
        now_ms: i64,
    ) -> Result<bool, RepositoryError> {
        // The action digest is public (it identifies the reviewed action),
        // so it can live in the WHERE clause; the code hash never leaves
        // the row.
        let rows = sqlx::query(
            "UPDATE vhl_challenges SET used=1 WHERE workspace_id=? AND challenge_id=? \
            AND action_digest=? AND used=0 AND ceremony_complete=1 AND expires_at_ms>?",
        )
        .bind(ws(workspace_id))
        .bind(challenge_id)
        .bind(action_digest)
        .bind(now_ms)
        .execute(self.pool())
        .await?;
        Ok(rows.rows_affected() == 1)
    }

    // ------------------------------------------------------------------
    // Courier message seam (TODO(INTEGRATION))
    // ------------------------------------------------------------------

    /// Encode a VHL native Courier message payload for the phase-5
    /// `lumen-messaging` adapter. This crate never wires the transport.
    pub fn vhl_encode_courier_message(
        message: &VhlCourierMessage,
    ) -> Result<Vec<u8>, RepositoryError> {
        message
            .encode()
            .map_err(|e| RepositoryError::InvalidVhlState(e.to_string()))
    }
}
