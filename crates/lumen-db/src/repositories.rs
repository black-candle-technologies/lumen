use std::path::Path;

use lumen_core::{
    action::{ActionEnvelope, ActionFingerprint, ActionId, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, ExecutionAttemptId, TimestampMillis},
    identity::PrincipalId,
    identity::WorkspaceId,
    policy::PolicyVersion,
    secret::SecretRefId,
};
use sqlx::Row;
use thiserror::Error;
use uuid::Uuid;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretReference {
    id: SecretRefId,
    workspace_id: WorkspaceId,
    label: String,
    keychain_account: String,
    executable: String,
    environment_name: String,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl SecretReference {
    pub fn new(
        id: SecretRefId,
        workspace_id: WorkspaceId,
        label: impl Into<String>,
        executable: impl Into<String>,
        environment_name: impl Into<String>,
        created_at: TimestampMillis,
    ) -> Result<Self, SecretReferenceError> {
        let label = label.into();
        let executable = executable.into();
        let environment_name = environment_name.into();
        if label.is_empty()
            || label.len() > 128
            || label.trim() != label
            || label.chars().any(char::is_control)
        {
            return Err(SecretReferenceError::InvalidLabel);
        }
        if executable.len() > 4096
            || !Path::new(&executable).is_absolute()
            || executable.chars().any(char::is_control)
        {
            return Err(SecretReferenceError::InvalidExecutable);
        }
        if !valid_environment_name(&environment_name) {
            return Err(SecretReferenceError::InvalidEnvironmentName);
        }
        Ok(Self {
            id,
            workspace_id,
            label,
            keychain_account: format!("{workspace_id}:{id}"),
            executable,
            environment_name,
            created_at,
            updated_at: created_at,
        })
    }

    pub const fn id(&self) -> SecretRefId {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn keychain_account(&self) -> &str {
        &self.keychain_account
    }

    pub fn executable(&self) -> &str {
        &self.executable
    }

    pub fn environment_name(&self) -> &str {
        &self.environment_name
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }

    pub fn allows(&self, workspace_id: WorkspaceId, executable: &str, environment: &str) -> bool {
        self.workspace_id == workspace_id
            && self.executable == executable
            && self.environment_name == environment
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SecretReferenceError {
    #[error("secret label must be trimmed, bounded, and free of control characters")]
    InvalidLabel,
    #[error("secret executable scope must be a bounded absolute path")]
    InvalidExecutable,
    #[error("secret environment scope must be a portable environment name")]
    InvalidEnvironmentName,
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 256
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingApprovalView {
    approval_id: ApprovalId,
    run_id: RunId,
    kind: String,
    arguments: CanonicalValue,
    capabilities: Vec<CanonicalValue>,
    fingerprint: String,
    created_at: TimestampMillis,
    expires_at: TimestampMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveredExecution {
    attempt_id: ExecutionAttemptId,
    action_id: ActionId,
    run_id: RunId,
    workspace_id: WorkspaceId,
}

impl RecoveredExecution {
    pub const fn attempt_id(&self) -> ExecutionAttemptId {
        self.attempt_id
    }

    pub const fn action_id(&self) -> ActionId {
        self.action_id
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
}

impl PendingApprovalView {
    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub const fn arguments(&self) -> &CanonicalValue {
        &self.arguments
    }

    pub fn capabilities(&self) -> &[CanonicalValue] {
        &self.capabilities
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn expires_at(&self) -> TimestampMillis {
        self.expires_at
    }
}

impl Database {
    pub async fn insert_secret_reference(
        &self,
        reference: &SecretReference,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO secret_references (
                id, workspace_id, label, keychain_account, executable,
                environment_name, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(reference.id.to_string())
        .bind(reference.workspace_id.to_string())
        .bind(&reference.label)
        .bind(&reference.keychain_account)
        .bind(&reference.executable)
        .bind(&reference.environment_name)
        .bind(timestamp_to_i64(reference.created_at)?)
        .bind(timestamp_to_i64(reference.updated_at)?)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn get_secret_reference(
        &self,
        workspace_id: WorkspaceId,
        id: SecretRefId,
    ) -> Result<Option<SecretReference>, RepositoryError> {
        let row = sqlx::query(
            "SELECT id, workspace_id, label, keychain_account, executable,
                    environment_name, created_at, updated_at
             FROM secret_references WHERE workspace_id = ? AND id = ?",
        )
        .bind(workspace_id.to_string())
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.map(secret_reference_from_row).transpose()
    }

    pub async fn list_secret_references(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<SecretReference>, RepositoryError> {
        sqlx::query(
            "SELECT id, workspace_id, label, keychain_account, executable,
                    environment_name, created_at, updated_at
             FROM secret_references WHERE workspace_id = ? ORDER BY label, id",
        )
        .bind(workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(secret_reference_from_row)
        .collect()
    }

    pub async fn delete_secret_reference(
        &self,
        workspace_id: WorkspaceId,
        id: SecretRefId,
    ) -> Result<bool, RepositoryError> {
        let result = sqlx::query("DELETE FROM secret_references WHERE workspace_id = ? AND id = ?")
            .bind(workspace_id.to_string())
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() == 1)
    }

    pub async fn recover_incomplete_executions(
        &self,
        recovered_at: TimestampMillis,
    ) -> Result<Vec<RecoveredExecution>, RepositoryError> {
        let recovered_at = timestamp_to_i64(recovered_at)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let rows = sqlx::query(
            "SELECT attempts.id AS attempt_id, actions.id AS action_id,
                    actions.run_id, actions.workspace_id
             FROM execution_attempts AS attempts
             JOIN actions ON actions.id = attempts.action_id
             WHERE attempts.state IN ('reserved', 'running')
             ORDER BY attempts.reserved_at, attempts.id",
        )
        .fetch_all(&mut *transaction)
        .await?;
        let recovered = rows
            .into_iter()
            .map(|row| {
                Ok(RecoveredExecution {
                    attempt_id: parse_uuid(
                        row.try_get::<String, _>("attempt_id")?,
                        ExecutionAttemptId::from_uuid,
                    )?,
                    action_id: parse_uuid(
                        row.try_get::<String, _>("action_id")?,
                        ActionId::from_uuid,
                    )?,
                    run_id: parse_uuid(row.try_get::<String, _>("run_id")?, RunId::from_uuid)?,
                    workspace_id: parse_uuid(
                        row.try_get::<String, _>("workspace_id")?,
                        WorkspaceId::from_uuid,
                    )?,
                })
            })
            .collect::<Result<Vec<_>, RepositoryError>>()?;
        if !recovered.is_empty() {
            sqlx::query(
                "UPDATE agent_runs SET state = 'failed', completed_at = ?
                 WHERE id IN (
                     SELECT actions.run_id FROM actions
                     JOIN execution_attempts ON execution_attempts.action_id = actions.id
                     WHERE execution_attempts.state IN ('reserved', 'running')
                 )",
            )
            .bind(recovered_at)
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE actions SET state = 'unknown'
                 WHERE id IN (
                     SELECT action_id FROM execution_attempts
                     WHERE state IN ('reserved', 'running')
                 )",
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "UPDATE execution_attempts
                 SET state = 'unknown', completed_at = ?
                 WHERE state IN ('reserved', 'running')",
            )
            .bind(recovered_at)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(recovered)
    }

    pub async fn bootstrap_workspace(
        &self,
        id: WorkspaceId,
        name: &str,
        administrator: &PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(created_at)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(id.to_string())
        .bind(name)
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO identities (provider, subject, created_at) VALUES (?, ?, ?)
             ON CONFLICT(provider, subject) DO NOTHING",
        )
        .bind(administrator.provider())
        .bind(administrator.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO workspace_memberships (
                workspace_id, identity_provider, identity_subject, role, created_at
             ) VALUES (?, ?, ?, 'owner', ?)
             ON CONFLICT(workspace_id, identity_provider, identity_subject) DO NOTHING",
        )
        .bind(id.to_string())
        .bind(administrator.provider())
        .bind(administrator.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn create_run(
        &self,
        run_id: lumen_core::action::RunId,
        workspace_id: WorkspaceId,
        actor: &PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(created_at)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
        )
        .bind(actor.provider())
        .bind(actor.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO agent_runs (
                id, workspace_id, actor_provider, actor_subject, state, created_at
             ) VALUES (?, ?, ?, ?, 'created', ?)",
        )
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .bind(actor.provider())
        .bind(actor.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn update_run_state(
        &self,
        run_id: lumen_core::action::RunId,
        state: &str,
        completed_at: Option<TimestampMillis>,
    ) -> Result<(), RepositoryError> {
        if !matches!(
            state,
            "running" | "awaiting_approval" | "completed" | "failed" | "cancelled"
        ) {
            return Err(RepositoryError::InvalidRunState(state.to_owned()));
        }
        sqlx::query("UPDATE agent_runs SET state = ?, completed_at = ? WHERE id = ?")
            .bind(state)
            .bind(completed_at.map(timestamp_to_i64).transpose()?)
            .bind(run_id.to_string())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

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
                extension_provenance_json, fingerprint, state, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'normalized', ?)",
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
        .bind(
            action
                .extension_provenance()
                .map(serde_json::to_string)
                .transpose()?,
        )
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

    pub async fn update_approval_decision(
        &self,
        workspace_id: WorkspaceId,
        approval: &ApprovalRequest,
    ) -> Result<(), RepositoryError> {
        let approver = approval
            .decided_by()
            .ok_or(RepositoryError::ApprovalDecisionConflict)?;
        let decided_at = approval
            .decided_at()
            .ok_or(RepositoryError::ApprovalDecisionConflict)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
        )
        .bind(approver.provider())
        .bind(approver.subject())
        .bind(timestamp_to_i64(decided_at)?)
        .execute(&mut *transaction)
        .await?;
        let result = sqlx::query(
            "UPDATE approval_requests
             SET state = ?, decided_by_provider = ?, decided_by_subject = ?, decided_at = ?
             WHERE id = ? AND state = 'pending'
               AND EXISTS (
                   SELECT 1 FROM actions
                   WHERE actions.id = approval_requests.action_id
                     AND actions.workspace_id = ?
               )",
        )
        .bind(approval.state().as_str())
        .bind(approver.provider())
        .bind(approver.subject())
        .bind(timestamp_to_i64(decided_at)?)
        .bind(approval.id().to_string())
        .bind(workspace_id.to_string())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::ApprovalDecisionConflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn list_pending_approvals(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<PendingApprovalView>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT approvals.id AS approval_id, actions.run_id, actions.kind,
                    actions.arguments_json, actions.capabilities_json,
                    approvals.action_fingerprint, approvals.created_at, approvals.expires_at
             FROM approval_requests AS approvals
             JOIN actions ON actions.id = approvals.action_id
             WHERE actions.workspace_id = ? AND approvals.state = 'pending'
             ORDER BY approvals.created_at, approvals.id",
        )
        .bind(workspace_id.to_string())
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                let approval_id = parse_uuid(
                    row.try_get::<String, _>("approval_id")?,
                    ApprovalId::from_uuid,
                )?;
                let run_id = parse_uuid(row.try_get::<String, _>("run_id")?, RunId::from_uuid)?;
                let created_at = u64::try_from(row.try_get::<i64, _>("created_at")?)
                    .map_err(|_| RepositoryError::TimestampOutOfRange)?;
                let expires_at = u64::try_from(row.try_get::<i64, _>("expires_at")?)
                    .map_err(|_| RepositoryError::TimestampOutOfRange)?;
                Ok(PendingApprovalView {
                    approval_id,
                    run_id,
                    kind: row.try_get("kind")?,
                    arguments: serde_json::from_str(&row.try_get::<String, _>("arguments_json")?)?,
                    capabilities: serde_json::from_str(
                        &row.try_get::<String, _>("capabilities_json")?,
                    )?,
                    fingerprint: row.try_get("action_fingerprint")?,
                    created_at: TimestampMillis::new(created_at),
                    expires_at: TimestampMillis::new(expires_at),
                })
            })
            .collect()
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

        sqlx::query("UPDATE actions SET state = 'running' WHERE id = ?")
            .bind(reservation.action_id.to_string())
            .execute(&mut *transaction)
            .await?;

        transaction.commit().await?;
        Ok(())
    }

    pub async fn reserve_allowed_execution(
        &self,
        attempt_id: ExecutionAttemptId,
        action_id: ActionId,
        reserved_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let reserved_at = timestamp_to_i64(reserved_at)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "INSERT INTO execution_attempts (
                id, action_id, approval_id, state, reserved_at
             ) SELECT ?, id, NULL, 'reserved', ? FROM actions
               WHERE id = ? AND state = 'normalized'",
        )
        .bind(attempt_id.to_string())
        .bind(reserved_at)
        .bind(action_id.to_string())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        sqlx::query("UPDATE actions SET state = 'running' WHERE id = ?")
            .bind(action_id.to_string())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn complete_execution(
        &self,
        attempt_id: ExecutionAttemptId,
        action_id: ActionId,
        state: &str,
        completed_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        if !matches!(
            state,
            "succeeded" | "failed" | "cancelled" | "timed_out" | "unknown"
        ) {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let completed_at = timestamp_to_i64(completed_at)?;
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE execution_attempts SET state = ?, completed_at = ?
             WHERE id = ? AND action_id = ? AND state IN ('reserved', 'running')",
        )
        .bind(state)
        .bind(completed_at)
        .bind(attempt_id.to_string())
        .bind(action_id.to_string())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        sqlx::query("UPDATE actions SET state = ? WHERE id = ?")
            .bind(state)
            .bind(action_id.to_string())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mark_action_denied(
        &self,
        action_id: ActionId,
        _denied_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let result = sqlx::query(
            "UPDATE actions SET state = 'denied' WHERE id = ? AND state = 'normalized'",
        )
        .bind(action_id.to_string())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        Ok(())
    }
}

fn secret_reference_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<SecretReference, RepositoryError> {
    let created_at = TimestampMillis::new(
        u64::try_from(row.try_get::<i64, _>("created_at")?)
            .map_err(|_| RepositoryError::TimestampOutOfRange)?,
    );
    let updated_at = TimestampMillis::new(
        u64::try_from(row.try_get::<i64, _>("updated_at")?)
            .map_err(|_| RepositoryError::TimestampOutOfRange)?,
    );
    let id = parse_uuid(row.try_get::<String, _>("id")?, SecretRefId::from_uuid)?;
    let workspace_id = parse_uuid(
        row.try_get::<String, _>("workspace_id")?,
        WorkspaceId::from_uuid,
    )?;
    let stored_account: String = row.try_get("keychain_account")?;
    let mut reference = SecretReference::new(
        id,
        workspace_id,
        row.try_get::<String, _>("label")?,
        row.try_get::<String, _>("executable")?,
        row.try_get::<String, _>("environment_name")?,
        created_at,
    )
    .map_err(|error| RepositoryError::InvalidSecretReference(error.to_string()))?;
    if stored_account != reference.keychain_account || updated_at < created_at {
        return Err(RepositoryError::InvalidSecretReference(
            "stored account or timestamps do not match canonical metadata".to_owned(),
        ));
    }
    reference.updated_at = updated_at;
    Ok(reference)
}

fn parse_uuid<T>(value: String, constructor: impl FnOnce(Uuid) -> T) -> Result<T, RepositoryError> {
    Uuid::parse_str(&value)
        .map(constructor)
        .map_err(|error| RepositoryError::Sqlx(sqlx::Error::Protocol(error.to_string())))
}
