use lumen_core::{
    action::{ActionEnvelope, ActionFingerprint, ActionId},
    approval::{ApprovalId, ApprovalRequest, ExecutionAttemptId, TimestampMillis},
    identity::WorkspaceId,
    policy::PolicyVersion,
};

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Debug)]
pub struct DispatchReservation {
    attempt_id: ExecutionAttemptId,
    action_id: ActionId,
    approval_id: ApprovalId,
    action_fingerprint: ActionFingerprint,
    policy_version: PolicyVersion,
    reserved_at: TimestampMillis,
}

impl DispatchReservation {
    pub const fn new(
        attempt_id: ExecutionAttemptId,
        action_id: ActionId,
        approval_id: ApprovalId,
        action_fingerprint: ActionFingerprint,
        policy_version: PolicyVersion,
        reserved_at: TimestampMillis,
    ) -> Self {
        Self {
            attempt_id,
            action_id,
            approval_id,
            action_fingerprint,
            policy_version,
            reserved_at,
        }
    }
}

impl Database {
    pub async fn insert_workspace(
        &self,
        id: WorkspaceId,
        name: &str,
        created_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)")
            .bind(id.to_string())
            .bind(name)
            .bind(timestamp_to_i64(created_at)?)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn insert_action(
        &self,
        action: &ActionEnvelope,
        created_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(created_at)?;
        let mut transaction = self.pool.begin().await?;

        sqlx::query(
            "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
        )
        .bind(action.actor().provider())
        .bind(action.actor().subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT OR IGNORE INTO agent_runs (
                id, workspace_id, actor_provider, actor_subject, state, created_at
             ) VALUES (?, ?, ?, ?, 'running', ?)",
        )
        .bind(action.run_id().to_string())
        .bind(action.workspace_id().to_string())
        .bind(action.actor().provider())
        .bind(action.actor().subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;

        sqlx::query(
            "INSERT INTO actions (
                id, run_id, workspace_id, actor_provider, actor_subject,
                requesting_component, kind, arguments_json, capabilities_json,
                fingerprint, state, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'normalized', ?)",
        )
        .bind(action.id().to_string())
        .bind(action.run_id().to_string())
        .bind(action.workspace_id().to_string())
        .bind(action.actor().provider())
        .bind(action.actor().subject())
        .bind(action.requesting_component().as_str())
        .bind(action.kind().as_str())
        .bind(serde_json::to_string(action.arguments())?)
        .bind(serde_json::to_string(action.required_capabilities())?)
        .bind(action.fingerprint().to_string())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn insert_approval(&self, approval: &ApprovalRequest) -> Result<(), RepositoryError> {
        let mut transaction = self.pool.begin().await?;
        if let Some(approver) = approval.decided_by() {
            sqlx::query(
                "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
            )
            .bind(approver.provider())
            .bind(approver.subject())
            .bind(timestamp_to_i64(
                approval.decided_at().unwrap_or(approval.created_at()),
            )?)
            .execute(&mut *transaction)
            .await?;
        }

        let result = sqlx::query(
            "INSERT INTO approval_requests (
                id, action_id, action_fingerprint, policy_version, state,
                created_at, expires_at, decided_by_provider, decided_by_subject,
                decided_at, consumed_at
             )
             SELECT ?, id, ?, ?, ?, ?, ?, ?, ?, ?, ?
             FROM actions WHERE fingerprint = ?",
        )
        .bind(approval.id().to_string())
        .bind(approval.action_fingerprint().as_str())
        .bind(approval.policy_version().as_str())
        .bind(approval.state().as_str())
        .bind(timestamp_to_i64(approval.created_at())?)
        .bind(timestamp_to_i64(approval.expires_at())?)
        .bind(approval.decided_by().map(|principal| principal.provider()))
        .bind(approval.decided_by().map(|principal| principal.subject()))
        .bind(approval.decided_at().map(timestamp_to_i64).transpose()?)
        .bind(approval.consumed_at().map(timestamp_to_i64).transpose()?)
        .bind(approval.action_fingerprint().as_str())
        .execute(&mut *transaction)
        .await?;

        if result.rows_affected() != 1 {
            return Err(RepositoryError::MissingAction);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn reserve_execution(
        &self,
        reservation: DispatchReservation,
    ) -> Result<(), RepositoryError> {
        let reserved_at = timestamp_to_i64(reservation.reserved_at)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let updated = sqlx::query(
            "UPDATE approval_requests
             SET state = 'consumed', consumed_at = ?
             WHERE id = ?
               AND action_id = ?
               AND action_fingerprint = ?
               AND policy_version = ?
               AND state = 'granted'
               AND expires_at > ?",
        )
        .bind(reserved_at)
        .bind(reservation.approval_id.to_string())
        .bind(reservation.action_id.to_string())
        .bind(reservation.action_fingerprint.as_str())
        .bind(reservation.policy_version.as_str())
        .bind(reserved_at)
        .execute(&mut *transaction)
        .await?;

        if updated.rows_affected() != 1 {
            return Err(RepositoryError::ApprovalNotAvailable);
        }

        sqlx::query(
            "INSERT INTO execution_attempts (
                id, action_id, approval_id, state, reserved_at
             ) VALUES (?, ?, ?, 'reserved', ?)",
        )
        .bind(reservation.attempt_id.to_string())
        .bind(reservation.action_id.to_string())
        .bind(reservation.approval_id.to_string())
        .bind(reserved_at)
        .execute(&mut *transaction)
        .await?;

        transaction.commit().await?;
        Ok(())
    }
}
