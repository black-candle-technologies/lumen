use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::TimestampMillis,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditHash, AuditOutcome, AuditRecord},
    identity::WorkspaceId,
};
use sqlx::Row;
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectCertainty {
    NoEffect,
    Known,
    Unknown,
}

impl EffectCertainty {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEffect => "no_effect",
            Self::Known => "known",
            Self::Unknown => "unknown",
        }
    }

    fn from_stored(value: &str) -> Result<Self, RepositoryError> {
        match value {
            "no_effect" => Ok(Self::NoEffect),
            "known" => Ok(Self::Known),
            "unknown" => Ok(Self::Unknown),
            _ => Err(RepositoryError::ExecutionStateConflict),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalState {
    Completed,
    Failed,
    Cancelled,
}

impl TerminalState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    const fn occurrence(self, certainty: EffectCertainty) -> &'static str {
        if matches!(certainty, EffectCertainty::Unknown) {
            return "unknown";
        }
        match self {
            Self::Completed => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalSpec {
    state: TerminalState,
    certainty: EffectCertainty,
    code: &'static str,
    primary_diagnostic: Option<String>,
}

impl TerminalSpec {
    pub fn new(
        state: TerminalState,
        certainty: EffectCertainty,
        code: &'static str,
        redacted_diagnostic: Option<String>,
    ) -> Result<Self, RepositoryError> {
        if (state == TerminalState::Completed && certainty == EffectCertainty::Unknown)
            || code.is_empty()
            || code.len() > 64
            || !code
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        Ok(Self {
            state,
            certainty,
            code,
            primary_diagnostic: redacted_diagnostic.map(|value| truncate_utf8(value, 1024)),
        })
    }

    pub const fn state(&self) -> TerminalState {
        self.state
    }
    pub const fn certainty(&self) -> EffectCertainty {
        self.certainty
    }
    pub const fn code(&self) -> &'static str {
        self.code
    }
    pub fn primary_diagnostic(&self) -> Option<&str> {
        self.primary_diagnostic.as_deref()
    }
}

fn truncate_utf8(mut value: String, max_bytes: usize) -> String {
    if value.len() > max_bytes {
        let mut end = max_bytes;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunLifecycleView {
    phase: String,
    effect_certainty: EffectCertainty,
    terminal_code: Option<String>,
    primary_diagnostic: Option<String>,
    secondary_diagnostic: Option<String>,
    terminal_audit_pending: bool,
}

impl RunLifecycleView {
    pub fn phase(&self) -> &str {
        &self.phase
    }
    pub const fn effect_certainty(&self) -> EffectCertainty {
        self.effect_certainty
    }
    pub fn terminal_code(&self) -> Option<&str> {
        self.terminal_code.as_deref()
    }
    pub fn primary_diagnostic(&self) -> Option<&str> {
        self.primary_diagnostic.as_deref()
    }
    pub fn secondary_diagnostic(&self) -> Option<&str> {
        self.secondary_diagnostic.as_deref()
    }
    pub const fn terminal_audit_pending(&self) -> bool {
        self.terminal_audit_pending
    }
}

impl Database {
    pub async fn start_owned_run(
        &self,
        run_id: RunId,
        workspace_id: WorkspaceId,
        owner_instance_id: Uuid,
        resume_approval: bool,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let (expected_state, expected_phase) = if resume_approval {
            ("awaiting_approval", "awaiting_approval")
        } else {
            ("created", "admitted")
        };
        self.transition_owned_active_run(
            run_id,
            workspace_id,
            owner_instance_id,
            expected_state,
            expected_phase,
            "running",
            "running",
            now,
        )
        .await
    }

    pub async fn pause_owned_run_for_approval(
        &self,
        run_id: RunId,
        workspace_id: WorkspaceId,
        owner_instance_id: Uuid,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        self.transition_owned_active_run(
            run_id,
            workspace_id,
            owner_instance_id,
            "running",
            "running",
            "awaiting_approval",
            "awaiting_approval",
            now,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn transition_owned_active_run(
        &self,
        run_id: RunId,
        workspace_id: WorkspaceId,
        owner_instance_id: Uuid,
        expected_state: &str,
        expected_phase: &str,
        next_state: &str,
        next_phase: &str,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let run = sqlx::query(
            "UPDATE agent_runs SET state = ? WHERE id = ? AND workspace_id = ? AND state = ?",
        )
        .bind(next_state)
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .bind(expected_state)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let lifecycle = sqlx::query(
            "UPDATE run_lifecycle SET phase = ?, updated_at = ?
             WHERE run_id = ? AND workspace_id = ? AND owner_instance_id = ? AND phase = ?",
        )
        .bind(next_phase)
        .bind(timestamp_to_i64(now)?)
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .bind(owner_instance_id.to_string())
        .bind(expected_phase)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if run != 1 || lifecycle != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get_run_lifecycle(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> Result<Option<RunLifecycleView>, RepositoryError> {
        let row = sqlx::query(
            "SELECT phase, effect_certainty, terminal_code, primary_diagnostic,
                    secondary_diagnostic, terminal_audit_pending
             FROM run_lifecycle WHERE workspace_id = ? AND run_id = ?",
        )
        .bind(workspace_id.to_string())
        .bind(run_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let certainty: String = row.try_get("effect_certainty")?;
            Ok(RunLifecycleView {
                phase: row.try_get("phase")?,
                effect_certainty: EffectCertainty::from_stored(&certainty)?,
                terminal_code: row.try_get("terminal_code")?,
                primary_diagnostic: row.try_get("primary_diagnostic")?,
                secondary_diagnostic: row.try_get("secondary_diagnostic")?,
                terminal_audit_pending: row.try_get::<i64, _>("terminal_audit_pending")? == 1,
            })
        })
        .transpose()
    }

    pub async fn terminalize_owned_run(
        &self,
        run_id: RunId,
        workspace_id: WorkspaceId,
        owner_instance_id: Uuid,
        spec: &TerminalSpec,
        audit_id: AuditEventId,
        occurred_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let occurred_at = timestamp_to_i64(occurred_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let current = sqlx::query(
            "SELECT lifecycle.phase, lifecycle.effect_certainty, lifecycle.terminal_code,
                    lifecycle.primary_diagnostic, lifecycle.terminal_audit_id,
                    lifecycle.terminal_audit_occurred_at, run.state
             FROM run_lifecycle lifecycle JOIN agent_runs run ON run.id = lifecycle.run_id
             WHERE lifecycle.run_id = ? AND lifecycle.workspace_id = ?
               AND lifecycle.owner_instance_id = ? AND run.workspace_id = ?",
        )
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .bind(owner_instance_id.to_string())
        .bind(workspace_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(RepositoryError::ExecutionStateConflict)?;
        let phase: String = current.try_get("phase")?;
        if matches!(phase.as_str(), "terminal" | "reconciliation_required") {
            let matching = current.try_get::<String, _>("state")? == spec.state.as_str()
                && current.try_get::<String, _>("effect_certainty")? == spec.certainty.as_str()
                && current
                    .try_get::<Option<String>, _>("terminal_code")?
                    .as_deref()
                    == Some(spec.code)
                && current
                    .try_get::<Option<String>, _>("primary_diagnostic")?
                    .as_deref()
                    == spec.primary_diagnostic()
                && current
                    .try_get::<Option<String>, _>("terminal_audit_id")?
                    .as_deref()
                    == Some(audit_id.to_string().as_str())
                && current.try_get::<Option<i64>, _>("terminal_audit_occurred_at")?
                    == Some(occurred_at);
            return if matching {
                Ok(())
            } else {
                Err(RepositoryError::ExecutionStateConflict)
            };
        }
        if !matches!(
            phase.as_str(),
            "admitted" | "preparing" | "running" | "awaiting_approval" | "reserving_effect"
        ) {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let attempt_state: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(CASE
                 WHEN attempts.state IN ('reserved', 'running', 'unknown') THEN 2
                 ELSE 1 END)
             FROM execution_attempts attempts JOIN actions ON actions.id = attempts.action_id
             WHERE actions.run_id = ?",
        )
        .bind(run_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        let certainty = match (spec.certainty, attempt_state.unwrap_or(0)) {
            (EffectCertainty::Unknown, _) | (_, 2) => EffectCertainty::Unknown,
            (EffectCertainty::Known, _) | (_, 1) => EffectCertainty::Known,
            _ => EffectCertainty::NoEffect,
        };
        if spec.state == TerminalState::Completed && certainty == EffectCertainty::Unknown {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let updated = sqlx::query(
            "UPDATE agent_runs SET state = ?, completed_at = ?
             WHERE id = ? AND workspace_id = ?
               AND state IN ('created', 'running', 'awaiting_approval')",
        )
        .bind(spec.state.as_str())
        .bind(occurred_at)
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let scheduled: Option<String> =
            sqlx::query_scalar("SELECT state FROM scheduled_job_runs WHERE run_id = ?")
                .bind(run_id.to_string())
                .fetch_optional(&mut *transaction)
                .await?;
        if let Some(scheduled) = scheduled {
            if scheduled != "running" {
                return Err(RepositoryError::ExecutionStateConflict);
            }
            let changed = sqlx::query(
                "UPDATE scheduled_job_runs SET state = ?, updated_at = ?
                 WHERE run_id = ? AND state = 'running'",
            )
            .bind(spec.state.occurrence(certainty))
            .bind(occurred_at)
            .bind(run_id.to_string())
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if changed != 1 {
                return Err(RepositoryError::ExecutionStateConflict);
            }
        }
        sqlx::query(
            "UPDATE approval_requests SET state = 'invalidated'
             WHERE action_id IN (SELECT id FROM actions WHERE run_id = ?)
               AND state IN ('pending', 'granted')",
        )
        .bind(run_id.to_string())
        .execute(&mut *transaction)
        .await?;
        let payload = serde_json::json!({
            "run_id": run_id.to_string(),
            "terminal_code": spec.code,
            "effect_certainty": certainty.as_str(),
            "primary_diagnostic": spec.primary_diagnostic(),
        })
        .to_string();
        let next_phase = if certainty == EffectCertainty::Unknown {
            "reconciliation_required"
        } else {
            "terminal"
        };
        let changed = sqlx::query(
            "UPDATE run_lifecycle SET phase = ?, effect_certainty = ?, terminal_code = ?,
                primary_diagnostic = ?, terminal_audit_id = ?, terminal_audit_pending = 1,
                terminal_audit_occurred_at = ?, terminal_audit_payload_json = ?, updated_at = ?
             WHERE run_id = ? AND workspace_id = ? AND owner_instance_id = ?
               AND phase = ?",
        )
        .bind(next_phase)
        .bind(certainty.as_str())
        .bind(spec.code)
        .bind(spec.primary_diagnostic())
        .bind(audit_id.to_string())
        .bind(occurred_at)
        .bind(payload)
        .bind(occurred_at)
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .bind(owner_instance_id.to_string())
        .bind(&phase)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn flush_terminal_audit(
        &self,
        workspace_id: WorkspaceId,
        run_id: RunId,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let row = sqlx::query(
            "SELECT lifecycle.phase, lifecycle.terminal_audit_id,
                    lifecycle.terminal_audit_pending, lifecycle.terminal_audit_occurred_at,
                    lifecycle.terminal_audit_payload_json, run.state
             FROM run_lifecycle lifecycle JOIN agent_runs run ON run.id = lifecycle.run_id
             WHERE lifecycle.workspace_id = ? AND lifecycle.run_id = ?
               AND run.workspace_id = ?",
        )
        .bind(workspace_id.to_string())
        .bind(run_id.to_string())
        .bind(workspace_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(RepositoryError::ExecutionStateConflict)?;
        let phase: String = row.try_get("phase")?;
        if !matches!(phase.as_str(), "terminal" | "reconciliation_required") {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let audit_id: String = row
            .try_get::<Option<String>, _>("terminal_audit_id")?
            .ok_or(RepositoryError::ExecutionStateConflict)?;
        let occurred_at: i64 = row
            .try_get::<Option<i64>, _>("terminal_audit_occurred_at")?
            .ok_or(RepositoryError::ExecutionStateConflict)?;
        let payload_json: String = row
            .try_get::<Option<String>, _>("terminal_audit_payload_json")?
            .ok_or(RepositoryError::ExecutionStateConflict)?;
        let state: String = row.try_get("state")?;
        let (kind, outcome) = if phase == "reconciliation_required" {
            (
                AuditEventKind::RunReconciliationRequired,
                AuditOutcome::Unknown,
            )
        } else {
            match state.as_str() {
                "completed" => (AuditEventKind::RunCompleted, AuditOutcome::Success),
                "failed" => (AuditEventKind::RunFailed, AuditOutcome::Failure),
                "cancelled" => (AuditEventKind::RunCancelled, AuditOutcome::Failure),
                _ => return Err(RepositoryError::ExecutionStateConflict),
            }
        };
        let existing = sqlx::query(
            "SELECT timestamp, event_type, outcome, workspace_id, payload_json
             FROM audit_events WHERE event_id = ?",
        )
        .bind(&audit_id)
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(existing) = existing {
            if existing.try_get::<i64, _>("timestamp")? != occurred_at
                || existing.try_get::<String, _>("event_type")? != kind.as_str()
                || existing.try_get::<String, _>("outcome")? != outcome.as_str()
                || existing
                    .try_get::<Option<String>, _>("workspace_id")?
                    .as_deref()
                    != Some(workspace_id.to_string().as_str())
                || existing.try_get::<String, _>("payload_json")? != payload_json
            {
                return Err(RepositoryError::ExecutionStateConflict);
            }
        } else {
            if row.try_get::<i64, _>("terminal_audit_pending")? != 1 {
                return Err(RepositoryError::ExecutionStateConflict);
            }
            let event_id =
                Uuid::parse_str(&audit_id).map_err(|_| RepositoryError::ExecutionStateConflict)?;
            let timestamp =
                u64::try_from(occurred_at).map_err(|_| RepositoryError::ExecutionStateConflict)?;
            let payload: CanonicalValue = serde_json::from_str(&payload_json)?;
            let event = AuditEvent::new(
                AuditEventId::from_uuid(event_id),
                TimestampMillis::new(timestamp),
                kind,
                outcome,
                Some(workspace_id),
                payload,
            );
            let previous: Option<(i64, String)> = sqlx::query_as(
                "SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1",
            )
            .fetch_optional(&mut *transaction)
            .await?;
            let (sequence, previous_hash) = match previous {
                Some((sequence, hash)) => (
                    sequence + 1,
                    AuditHash::parse(hash).map_err(|_| RepositoryError::ExecutionStateConflict)?,
                ),
                None => (1, AuditHash::genesis()),
            };
            let record = AuditRecord::chain(sequence, event, previous_hash);
            sqlx::query(
                "INSERT INTO audit_events (
                    sequence, event_id, timestamp, event_type, outcome, workspace_id,
                    payload_json, previous_hash, event_hash
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(record.sequence())
            .bind(&audit_id)
            .bind(occurred_at)
            .bind(kind.as_str())
            .bind(outcome.as_str())
            .bind(workspace_id.to_string())
            .bind(payload_json)
            .bind(record.previous_hash().as_str())
            .bind(record.hash().as_str())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "UPDATE run_lifecycle SET terminal_audit_pending = 0
             WHERE workspace_id = ? AND run_id = ? AND terminal_audit_id = ?",
        )
        .bind(workspace_id.to_string())
        .bind(run_id.to_string())
        .bind(audit_id)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}
