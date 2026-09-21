use std::collections::BTreeSet;

use lumen_core::{
    action::{ActionId, RunId},
    approval::TimestampMillis,
    artifact::{
        ArtifactId, ArtifactKind, ArtifactProvenance, ArtifactReference, ArtifactValidation,
        ArtifactValidationState, EffectRisk, FailureClass, RetryDecision, RetryDecisionId,
        RetryMode, WorkerArtifact, WorkerFailure, retry_disposition,
    },
    context::{CompartmentId, ContextDigest, ProjectionId, parse_data_class},
    egress::ProviderId,
    identity::{PrincipalId, WorkspaceId},
    orchestration::{OrchestrationId, TaskNodeId, TaskNodeState, TaskStateRevision},
    provider::ModelProfileId,
    worker::{WorkerAttemptId, WorkerAttemptState},
};
use sqlx::{Row, Sqlite, sqlite::SqliteRow};
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

impl Database {
    pub async fn artifact_provenance_for_attempt(
        &self,
        attempt_id: WorkerAttemptId,
    ) -> Result<ArtifactProvenance, RepositoryError> {
        let attempt = self
            .worker_attempt(attempt_id)
            .await?
            .ok_or(RepositoryError::InvalidArtifactState)?;
        let assignment = attempt.assignment();
        let action_ids = sqlx::query_scalar::<_, String>(
            "SELECT DISTINCT actions.id FROM actions JOIN execution_attempts ON execution_attempts.action_id=actions.id WHERE actions.run_id=? ORDER BY actions.id",
        ).bind(attempt.run_id().to_string()).fetch_all(self.pool()).await?
            .into_iter().map(action_id).collect::<Result<Vec<_>, _>>()?;
        ArtifactProvenance::new(
            assignment.orchestration_id(),
            assignment.graph_revision(),
            assignment.task_node_id(),
            attempt_id,
            attempt.run_id(),
            assignment.provider_id().clone(),
            assignment.provider_revision(),
            assignment.model_profile_id().clone(),
            assignment.model_profile_revision(),
            None,
            assignment.policy_revision(),
            assignment.projection_id(),
            assignment.projection_digest().clone(),
            action_ids,
        )
        .map_err(|_| RepositoryError::InvalidArtifactState)
    }

    pub async fn append_worker_artifact(
        &self,
        artifact: &WorkerArtifact,
    ) -> Result<(), RepositoryError> {
        artifact
            .verify()
            .map_err(|_| RepositoryError::InvalidArtifactState)?;
        let attempt = self
            .worker_attempt(artifact.provenance.worker_attempt_id)
            .await?
            .ok_or(RepositoryError::InvalidArtifactState)?;
        if attempt.state() != WorkerAttemptState::Running
            || artifact.workspace_id != attempt.assignment().workspace_id()
            || artifact.provenance
                != self
                    .artifact_provenance_for_attempt(attempt.attempt_id())
                    .await?
        {
            return Err(RepositoryError::InvalidArtifactState);
        }
        let output: String = sqlx::query_scalar("SELECT expected_output FROM orchestration_task_nodes WHERE orchestration_id=? AND graph_revision=? AND task_node_id=?")
            .bind(artifact.provenance.orchestration_id.to_string()).bind(pos(artifact.provenance.graph_revision)?)
            .bind(artifact.provenance.task_node_id.to_string()).fetch_optional(self.pool()).await?
            .ok_or(RepositoryError::InvalidArtifactState)?;
        if artifact.kind.as_str() != task_artifact_kind(&output) {
            return Err(RepositoryError::InvalidArtifactState);
        }
        sqlx::query("INSERT INTO worker_artifacts(artifact_id,workspace_id,orchestration_id,graph_revision,task_node_id,attempt_id,run_id,artifact_kind,media_type,content,content_hash,classification,compartments_json,provider_id,provider_revision,profile_id,profile_revision,reasoning_profile,policy_revision,projection_id,projection_digest,tool_action_ids_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(artifact.id.to_string()).bind(artifact.workspace_id.to_string()).bind(artifact.provenance.orchestration_id.to_string()).bind(pos(artifact.provenance.graph_revision)?)
            .bind(artifact.provenance.task_node_id.to_string()).bind(artifact.provenance.worker_attempt_id.to_string()).bind(artifact.provenance.run_id.to_string()).bind(artifact.kind.as_str())
            .bind(&artifact.media_type).bind(&artifact.content).bind(artifact.content_hash.as_str()).bind(data_class(artifact.classification)).bind(serde_json::to_string(&artifact.compartments)?)
            .bind(artifact.provenance.provider_id.as_str()).bind(pos(artifact.provenance.provider_revision)?).bind(artifact.provenance.model_profile_id.as_str()).bind(pos(artifact.provenance.model_profile_revision)?)
            .bind(artifact.provenance.reasoning_profile.map(|value| format!("{value:?}").to_lowercase())).bind(pos(artifact.provenance.policy_revision)?)
            .bind(artifact.provenance.projection_id.to_string()).bind(artifact.provenance.projection_digest.as_str()).bind(serde_json::to_string(&artifact.provenance.tool_action_ids)?)
            .bind(timestamp_to_i64(artifact.created_at)?).execute(self.pool()).await?;
        Ok(())
    }

    pub async fn worker_artifact(
        &self,
        id: ArtifactId,
    ) -> Result<Option<WorkerArtifact>, RepositoryError> {
        sqlx::query("SELECT * FROM worker_artifacts WHERE artifact_id=?")
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?
            .map(artifact_row)
            .transpose()
    }

    pub async fn append_artifact_validation(
        &self,
        validation: &ArtifactValidation,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let prior: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(revision),0) FROM artifact_validation_revisions WHERE artifact_id=?")
            .bind(validation.artifact_id.to_string()).fetch_one(&mut *tx).await?;
        if u64::try_from(prior)
            .ok()
            .and_then(|value| value.checked_add(1))
            != Some(validation.revision)
        {
            return Err(RepositoryError::InvalidArtifactState);
        }
        ensure_identity(&mut tx, &validation.validator, validation.created_at).await?;
        let result = sqlx::query("INSERT INTO artifact_validation_revisions(artifact_id,revision,state,method,validator_provider,validator_subject,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(validation.artifact_id.to_string()).bind(pos(validation.revision)?).bind(validation.state.as_str()).bind(&validation.method)
            .bind(validation.validator.provider()).bind(validation.validator.subject()).bind(timestamp_to_i64(validation.created_at)?).execute(&mut *tx).await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::InvalidArtifactState);
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn artifact_reference_for_handoff(
        &self,
        id: ArtifactId,
        max: usize,
    ) -> Result<Option<ArtifactReference>, RepositoryError> {
        let Some(artifact) = self.worker_artifact(id).await? else {
            return Ok(None);
        };
        let state: Option<String> =
            sqlx::query_scalar("SELECT state FROM worker_attempts WHERE attempt_id=?")
                .bind(artifact.provenance.worker_attempt_id.to_string())
                .fetch_optional(self.pool())
                .await?;
        if state.as_deref() != Some("completed") {
            return Ok(None);
        }
        let validation = sqlx::query("SELECT state FROM artifact_validation_revisions WHERE artifact_id=? ORDER BY revision DESC LIMIT 1")
            .bind(id.to_string()).fetch_optional(self.pool()).await?.map(|row| ArtifactValidationState::parse(&row.try_get::<String, _>("state")?).ok_or(RepositoryError::InvalidArtifactState)).transpose()?;
        if validation == Some(ArtifactValidationState::Rejected) {
            return Ok(None);
        }
        artifact
            .reference(max)
            .map(|reference| Some(reference.with_validation(validation)))
            .map_err(|_| RepositoryError::InvalidArtifactState)
    }

    pub async fn effect_risk_for_run(&self, run: RunId) -> Result<EffectRisk, RepositoryError> {
        let states = sqlx::query_scalar::<_, String>("SELECT execution_attempts.state FROM execution_attempts JOIN actions ON actions.id=execution_attempts.action_id WHERE actions.run_id=?")
            .bind(run.to_string()).fetch_all(self.pool()).await?;
        Ok(if states.is_empty() {
            EffectRisk::NoEffect
        } else if states.iter().all(|state| state == "succeeded") {
            EffectRisk::KnownEffect
        } else {
            EffectRisk::UnknownEffect
        })
    }

    pub async fn record_worker_failure(
        &self,
        failure: &WorkerFailure,
    ) -> Result<(), RepositoryError> {
        let attempt = self
            .worker_attempt(failure.attempt_id)
            .await?
            .ok_or(RepositoryError::InvalidArtifactState)?;
        if attempt.state().is_terminal()
            || self.effect_risk_for_run(attempt.run_id()).await? != failure.effect_risk
        {
            return Err(RepositoryError::InvalidArtifactState);
        }
        let result = sqlx::query("INSERT INTO worker_attempt_failures(attempt_id,failure_class,effect_risk,diagnostic,created_at) VALUES(?,?,?,?,?) ON CONFLICT(attempt_id) DO NOTHING")
            .bind(failure.attempt_id.to_string()).bind(failure.failure_class.as_str()).bind(failure.effect_risk.as_str()).bind(failure.diagnostic.as_deref()).bind(timestamp_to_i64(failure.created_at)?).execute(self.pool()).await?;
        if result.rows_affected() == 0 {
            return Err(RepositoryError::InvalidArtifactState);
        }
        Ok(())
    }

    pub async fn reconcile_unknown_retry(
        &self,
        attempt: WorkerAttemptId,
        actor: &PrincipalId,
        safe: bool,
        note: &str,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        if note.trim().is_empty() || note.len() > 1024 {
            return Err(RepositoryError::InvalidArtifactState);
        }
        let worker = self
            .worker_attempt(attempt)
            .await?
            .ok_or(RepositoryError::InvalidArtifactState)?;
        if worker.state() != WorkerAttemptState::Unknown
            || self.effect_risk_for_run(worker.run_id()).await? != EffectRisk::UnknownEffect
        {
            return Err(RepositoryError::InvalidArtifactState);
        }
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        ensure_identity(&mut tx, actor, now).await?;
        sqlx::query("INSERT INTO worker_retry_reconciliations(attempt_id,safe_to_retry,reconciled_by_provider,reconciled_by_subject,note,created_at) VALUES(?,?,?,?,?,?)")
            .bind(attempt.to_string()).bind(safe).bind(actor.provider()).bind(actor.subject()).bind(note).bind(timestamp_to_i64(now)?).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn authorize_worker_retry(
        &self,
        attempt_id: WorkerAttemptId,
        mode: RetryMode,
        actor: &PrincipalId,
        now: TimestampMillis,
    ) -> Result<RetryDecision, RepositoryError> {
        let attempt = self
            .worker_attempt(attempt_id)
            .await?
            .ok_or(RepositoryError::InvalidArtifactState)?;
        let failure = sqlx::query(
            "SELECT failure_class,effect_risk FROM worker_attempt_failures WHERE attempt_id=?",
        )
        .bind(attempt_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        let failure_class = failure
            .as_ref()
            .and_then(|row| FailureClass::parse(&row.try_get::<String, _>("failure_class").ok()?))
            .unwrap_or(FailureClass::UnknownFailure);
        let risk = failure
            .as_ref()
            .and_then(|row| EffectRisk::parse(&row.try_get::<String, _>("effect_risk").ok()?))
            .unwrap_or(self.effect_risk_for_run(attempt.run_id()).await?);
        let reconciled = risk == EffectRisk::UnknownEffect
            && sqlx::query_scalar::<_, i64>(
                "SELECT safe_to_retry FROM worker_retry_reconciliations WHERE attempt_id=?",
            )
            .bind(attempt_id.to_string())
            .fetch_optional(self.pool())
            .await?
                == Some(1);
        let disposition = retry_disposition(failure_class, risk, reconciled);
        let allowed = attempt.state().is_terminal() && disposition.allows(mode);
        let decision = RetryDecision::new(
            RetryDecisionId::new(),
            attempt_id,
            attempt.assignment().orchestration_id(),
            attempt.assignment().graph_revision(),
            attempt.assignment().task_node_id(),
            mode,
            failure_class,
            risk,
            disposition,
            allowed,
            actor.clone(),
            attempt.assignment().provider_id().clone(),
            attempt.assignment().provider_revision(),
            attempt.assignment().model_profile_id().clone(),
            attempt.assignment().model_profile_revision(),
            now,
        )
        .map_err(|_| RepositoryError::InvalidArtifactState)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        ensure_identity(&mut tx, actor, now).await?;
        sqlx::query("INSERT INTO worker_retry_decisions(decision_id,prior_attempt_id,orchestration_id,graph_revision,task_node_id,mode,failure_class,effect_risk,disposition,allowed,requested_by_provider,requested_by_subject,previous_provider_id,previous_provider_revision,previous_profile_id,previous_profile_revision,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(decision.id.to_string()).bind(attempt_id.to_string()).bind(decision.orchestration_id.to_string()).bind(pos(decision.graph_revision)?).bind(decision.task_node_id.to_string()).bind(decision.mode.as_str()).bind(decision.failure_class.as_str()).bind(decision.effect_risk.as_str()).bind(decision.disposition.as_str()).bind(decision.allowed).bind(actor.provider()).bind(actor.subject()).bind(decision.previous_provider_id.as_str()).bind(pos(decision.previous_provider_revision)?).bind(decision.previous_profile_id.as_str()).bind(pos(decision.previous_profile_revision)?).bind(timestamp_to_i64(now)?).execute(&mut *tx).await?;
        if allowed {
            retry_task_state(&mut tx, &attempt, reconciled, now).await?;
        }
        tx.commit().await?;
        Ok(decision)
    }
}

async fn retry_task_state(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    attempt: &crate::WorkerAttemptRecord,
    reconciled: bool,
    now: TimestampMillis,
) -> Result<(), RepositoryError> {
    let a = attempt.assignment();
    let row = sqlx::query("SELECT s.state_revision,s.state,s.attempt_count,n.max_attempts FROM orchestration_task_state_revisions s JOIN orchestration_task_nodes n ON n.orchestration_id=s.orchestration_id AND n.graph_revision=s.graph_revision AND n.task_node_id=s.task_node_id WHERE s.orchestration_id=? AND s.graph_revision=? AND s.task_node_id=? ORDER BY s.state_revision DESC LIMIT 1")
        .bind(a.orchestration_id().to_string()).bind(pos(a.graph_revision())?).bind(a.task_node_id().to_string()).fetch_one(&mut **tx).await?;
    let state = TaskNodeState::parse(&row.try_get::<String, _>("state")?)
        .ok_or(RepositoryError::InvalidArtifactState)?;
    let current = TaskStateRevision::from_stored_parts(
        a.orchestration_id(),
        a.graph_revision(),
        a.task_node_id(),
        positive_row(&row, "state_revision")?,
        state,
        u32::try_from(row.try_get::<i64, _>("attempt_count")?)
            .map_err(|_| RepositoryError::InvalidArtifactState)?,
        u32::try_from(row.try_get::<i64, _>("max_attempts")?)
            .map_err(|_| RepositoryError::InvalidArtifactState)?,
        now,
    )
    .map_err(|_| RepositoryError::InvalidArtifactState)?;
    let next = current
        .retry(
            u32::try_from(row.try_get::<i64, _>("max_attempts")?)
                .map_err(|_| RepositoryError::InvalidArtifactState)?,
            reconciled,
            now,
        )
        .map_err(|_| RepositoryError::InvalidArtifactState)?;
    sqlx::query("INSERT INTO orchestration_task_state_revisions(orchestration_id,graph_revision,task_node_id,state_revision,state,attempt_count,created_at) VALUES(?,?,?,?,?,?,?)")
        .bind(next.orchestration_id().to_string()).bind(pos(next.graph_revision())?).bind(next.task_node_id().to_string()).bind(pos(next.revision())?).bind(next.state().as_str()).bind(i64::from(next.attempt_count())).bind(timestamp_to_i64(now)?).execute(&mut **tx).await?;
    Ok(())
}

fn artifact_row(row: SqliteRow) -> Result<WorkerArtifact, RepositoryError> {
    let action_ids =
        serde_json::from_str::<Vec<String>>(&row.try_get::<String, _>("tool_action_ids_json")?)?
            .into_iter()
            .map(action_id)
            .collect::<Result<Vec<_>, _>>()?;
    let provenance = ArtifactProvenance::new(
        orchestration_id(row.try_get("orchestration_id")?)?,
        positive_row(&row, "graph_revision")?,
        task_id(row.try_get("task_node_id")?)?,
        attempt_id(row.try_get("attempt_id")?)?,
        run_id(row.try_get("run_id")?)?,
        ProviderId::parse(row.try_get::<String, _>("provider_id")?)
            .map_err(|_| RepositoryError::InvalidArtifactState)?,
        positive_row(&row, "provider_revision")?,
        ModelProfileId::parse(row.try_get::<String, _>("profile_id")?)
            .map_err(|_| RepositoryError::InvalidArtifactState)?,
        positive_row(&row, "profile_revision")?,
        None,
        positive_row(&row, "policy_revision")?,
        ProjectionId::from_uuid(
            Uuid::parse_str(&row.try_get::<String, _>("projection_id")?)
                .map_err(|_| RepositoryError::InvalidArtifactState)?,
        ),
        ContextDigest::parse(row.try_get::<String, _>("projection_digest")?)
            .map_err(|_| RepositoryError::InvalidArtifactState)?,
        action_ids,
    )
    .map_err(|_| RepositoryError::InvalidArtifactState)?;
    WorkerArtifact::from_stored_parts(
        ArtifactId::from_uuid(
            Uuid::parse_str(&row.try_get::<String, _>("artifact_id")?)
                .map_err(|_| RepositoryError::InvalidArtifactState)?,
        ),
        workspace_id(row.try_get("workspace_id")?)?,
        ArtifactKind::parse(&row.try_get::<String, _>("artifact_kind")?)
            .ok_or(RepositoryError::InvalidArtifactState)?,
        row.try_get::<String, _>("media_type")?,
        row.try_get::<Vec<u8>, _>("content")?,
        ContextDigest::parse(row.try_get::<String, _>("content_hash")?)
            .map_err(|_| RepositoryError::InvalidArtifactState)?,
        parse_data_class(&row.try_get::<String, _>("classification")?)
            .ok_or(RepositoryError::InvalidArtifactState)?,
        serde_json::from_str::<BTreeSet<CompartmentId>>(
            &row.try_get::<String, _>("compartments_json")?,
        )?,
        provenance,
        TimestampMillis::new(positive_or_zero(&row, "created_at")?),
    )
    .map_err(|_| RepositoryError::InvalidArtifactState)
}
async fn ensure_identity(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    actor: &PrincipalId,
    now: TimestampMillis,
) -> Result<(), RepositoryError> {
    sqlx::query("INSERT OR IGNORE INTO identities(provider,subject,created_at) VALUES(?,?,?)")
        .bind(actor.provider())
        .bind(actor.subject())
        .bind(timestamp_to_i64(now)?)
        .execute(&mut **tx)
        .await?;
    Ok(())
}
fn pos(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidArtifactState)
}
fn positive_row(row: &SqliteRow, name: &str) -> Result<u64, RepositoryError> {
    u64::try_from(row.try_get::<i64, _>(name)?)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidArtifactState)
}
fn positive_or_zero(row: &SqliteRow, name: &str) -> Result<u64, RepositoryError> {
    u64::try_from(row.try_get::<i64, _>(name)?).map_err(|_| RepositoryError::InvalidArtifactState)
}
fn action_id(value: String) -> Result<ActionId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(ActionId::from_uuid)
        .map_err(|_| RepositoryError::InvalidArtifactState)
}
fn attempt_id(value: String) -> Result<WorkerAttemptId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(WorkerAttemptId::from_uuid)
        .map_err(|_| RepositoryError::InvalidArtifactState)
}
fn orchestration_id(value: String) -> Result<OrchestrationId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(OrchestrationId::from_uuid)
        .map_err(|_| RepositoryError::InvalidArtifactState)
}
fn task_id(value: String) -> Result<TaskNodeId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(TaskNodeId::from_uuid)
        .map_err(|_| RepositoryError::InvalidArtifactState)
}
fn run_id(value: String) -> Result<RunId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(RunId::from_uuid)
        .map_err(|_| RepositoryError::InvalidArtifactState)
}
fn workspace_id(value: String) -> Result<WorkspaceId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| RepositoryError::InvalidArtifactState)
}
fn data_class(value: lumen_core::egress::DataClass) -> &'static str {
    match value {
        lumen_core::egress::DataClass::Public => "public",
        lumen_core::egress::DataClass::Workspace => "workspace",
        lumen_core::egress::DataClass::Sensitive => "sensitive",
        lumen_core::egress::DataClass::Secret => "secret",
    }
}
fn task_artifact_kind(output: &str) -> &'static str {
    match output {
        "text" => "text",
        "patch" => "patch",
        "design" => "design",
        "test" => "test",
        "plan" => "task_plan",
        "review" => "code_review",
        "diagnostic" => "diagnostic_report",
        _ => "blob",
    }
}
