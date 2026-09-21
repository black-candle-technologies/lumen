use lumen_core::{
    approval::TimestampMillis,
    artifact::{ArtifactId, ArtifactKind, EffectRisk, FailureClass, WorkerArtifact, WorkerFailure},
    context::{ContextSource, ContextSourceId, most_restrictive},
    identity::PrincipalId,
    run::{RunError, RunOutcome},
};
use lumen_db::WorkerAttemptRecord;

use crate::{WorkerRuntimeError, WorkerScheduler};

impl WorkerScheduler {
    pub(crate) async fn persist_completed_artifact(
        &self,
        record: &WorkerAttemptRecord,
        text: &str,
        now: TimestampMillis,
    ) -> Result<ArtifactId, WorkerRuntimeError> {
        let assignment = record.assignment();
        let snapshot = self
            .db
            .latest_orchestration_snapshot(assignment.orchestration_id())
            .await?
            .ok_or(WorkerRuntimeError::Stale)?;
        let node = snapshot
            .graph()
            .node(assignment.task_node_id())
            .ok_or(WorkerRuntimeError::Stale)?;
        let projection = self
            .db
            .task_projection(assignment.projection_id())
            .await?
            .ok_or(WorkerRuntimeError::Stale)?;
        if snapshot.graph().revision() != assignment.graph_revision()
            || projection.digest() != assignment.projection_digest()
        {
            return Err(WorkerRuntimeError::Stale);
        }
        let artifact = WorkerArtifact::from_text(
            ArtifactId::new(),
            assignment.workspace_id(),
            ArtifactKind::from_task_output(node.expected_output()),
            text,
            most_restrictive(assignment.data_class(), projection.classification()),
            projection.compartments().clone(),
            self.db
                .artifact_provenance_for_attempt(record.attempt_id())
                .await?,
            now,
        )
        .map_err(|error| WorkerRuntimeError::Artifact(error.to_string()))?;
        let id = artifact.id;
        self.db.append_worker_artifact(&artifact).await?;
        Ok(id)
    }
    pub async fn artifact_context_source(
        &self,
        artifact_id: ArtifactId,
        source_id: ContextSourceId,
        created_by: PrincipalId,
        now: TimestampMillis,
    ) -> Result<Option<ContextSource>, WorkerRuntimeError> {
        let Some(reference) = self
            .db
            .artifact_reference_for_handoff(
                artifact_id,
                lumen_core::artifact::MAX_ARTIFACT_PREVIEW_BYTES,
            )
            .await?
        else {
            return Ok(None);
        };
        let artifact = self
            .db
            .worker_artifact(artifact_id)
            .await?
            .ok_or(WorkerRuntimeError::Stale)?;
        reference
            .to_context_source(source_id, artifact.workspace_id, created_by, now)
            .map(Some)
            .map_err(|error| WorkerRuntimeError::Artifact(error.to_string()))
    }
    pub(crate) async fn record_outcome_failure(
        &self,
        record: &WorkerAttemptRecord,
        outcome: &RunOutcome,
        now: TimestampMillis,
    ) -> Result<Option<EffectRisk>, WorkerRuntimeError> {
        let class = match outcome {
            RunOutcome::Completed { .. } | RunOutcome::AwaitingApproval { .. } => return Ok(None),
            RunOutcome::ApprovalRejected { .. } => FailureClass::ApprovalRejected,
            RunOutcome::Denied { .. } => FailureClass::PolicyDenied,
            RunOutcome::BudgetExhausted(_) => FailureClass::BudgetExhausted,
            RunOutcome::Cancelled => FailureClass::Cancelled,
            RunOutcome::ExecutionTimedOut => FailureClass::ExecutionTimedOut,
            RunOutcome::RequiredSkillUnavailable { .. } => FailureClass::RequiredSkillUnavailable,
            RunOutcome::ExecutionFailed { .. } | RunOutcome::ExecutionUnknown { .. } => {
                FailureClass::ExecutorFailure
            }
        };
        self.record_failure(record, class, None, now)
            .await
            .map(Some)
    }
    pub(crate) async fn record_run_error(
        &self,
        record: &WorkerAttemptRecord,
        error: &RunError,
        now: TimestampMillis,
    ) -> Result<EffectRisk, WorkerRuntimeError> {
        let class = match error {
            RunError::Model(_) => FailureClass::ModelFailure,
            RunError::Normalization(_) => FailureClass::InvalidModelOutput,
            RunError::ApprovalPort(_) | RunError::ApprovalIdentityMismatch => {
                FailureClass::ApprovalInfrastructure
            }
            RunError::Audit(_) => FailureClass::AuditFailure,
            RunError::ActionPort(_) => FailureClass::PersistenceFailure,
            RunError::Dispatch(_) => FailureClass::DispatchFailure,
            RunError::Executor(_) => FailureClass::ExecutorFailure,
        };
        self.record_failure(record, class, Some(error.to_string()), now)
            .await
    }
    pub(crate) async fn record_pre_dispatch_cancel(
        &self,
        record: &WorkerAttemptRecord,
        now: TimestampMillis,
    ) -> Result<EffectRisk, WorkerRuntimeError> {
        self.record_failure(
            record,
            FailureClass::Cancelled,
            Some("cancelled before dispatch".into()),
            now,
        )
        .await
    }
    pub(crate) async fn record_persistence_failure(
        &self,
        record: &WorkerAttemptRecord,
        diagnostic: String,
        now: TimestampMillis,
    ) -> Result<EffectRisk, WorkerRuntimeError> {
        self.record_failure(
            record,
            FailureClass::PersistenceFailure,
            Some(diagnostic),
            now,
        )
        .await
    }
    async fn record_failure(
        &self,
        record: &WorkerAttemptRecord,
        class: FailureClass,
        diagnostic: Option<String>,
        now: TimestampMillis,
    ) -> Result<EffectRisk, WorkerRuntimeError> {
        let risk = self.db.effect_risk_for_run(record.run_id()).await?;
        self.db
            .record_worker_failure(
                &WorkerFailure::new(
                    record.attempt_id(),
                    class,
                    risk,
                    diagnostic.map(|value| value.chars().take(1024).collect()),
                    now,
                )
                .map_err(|error| WorkerRuntimeError::Artifact(error.to_string()))?,
            )
            .await?;
        Ok(risk)
    }
}
