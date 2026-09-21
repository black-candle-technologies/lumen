use crate::{Database, RepositoryError, timestamp_to_i64};
use lumen_core::{
    action::CanonicalValue,
    approval::TimestampMillis,
    artifact::{ArtifactValidationState, FailureClass, WorkerFailure},
    context::{
        ContextSource, ContextSourceId, SourceProvenance, SourceProvenanceKind, most_restrictive,
    },
    identity::WorkspaceId,
    orchestration::{OrchestrationId, TaskGraph, TaskNode},
    provider::ModelTrustZone,
    trust_gate::{GateSource, IntegrityIssue, OrchestrationIntegrityReport, TrustGateEvaluation},
    worker::{WorkerAssignment, WorkerAttemptState},
};
use serde_json::{Value, json};
use sqlx::{Row, Sqlite};
use std::collections::BTreeSet;
use uuid::Uuid;
impl Database {
    pub async fn gate_sources_for_task(
        &self,
        g: &TaskGraph,
        n: &TaskNode,
        actor: &lumen_core::identity::PrincipalId,
        now: TimestampMillis,
    ) -> Result<Vec<GateSource>, RepositoryError> {
        let inputs = self
            .orchestration_input_sources(g.orchestration_id())
            .await?;
        if inputs.is_empty() {
            return Err(RepositoryError::InvalidTrustGateState);
        }
        let class = inputs
            .iter()
            .map(ContextSource::classification)
            .reduce(most_restrictive)
            .ok_or(RepositoryError::InvalidTrustGateState)?;
        let compartments = inputs
            .iter()
            .flat_map(|s| s.compartments().iter().cloned())
            .collect::<BTreeSet<_>>();
        let instruction = ContextSource::new(
            ContextSourceId::new(),
            g.workspace_id(),
            class,
            compartments,
            SourceProvenance::new(
                SourceProvenanceKind::Generated,
                format!(
                    "orchestration:{}:task:{}:instruction",
                    g.orchestration_id(),
                    n.id()
                ),
            )
            .map_err(|_| RepositoryError::InvalidTrustGateState)?,
            CanonicalValue::from(n.description()),
            actor.clone(),
            now,
        )
        .map_err(|_| RepositoryError::InvalidTrustGateState)?;
        self.append_context_source(&instruction).await?;
        let mut out = vec![GateSource::instruction(instruction)];
        out.extend(inputs.into_iter().map(GateSource::input));
        for (child, dep) in g.dependency_edges() {
            if child != n.id() {
                continue;
            }
            for id in self
                .handoff_artifact_ids(g.orchestration_id(), g.revision(), dep)
                .await?
            {
                let artifact = self
                    .worker_artifact(id)
                    .await?
                    .ok_or(RepositoryError::InvalidTrustGateState)?;
                let validation = self.latest_artifact_validation(id).await?;
                if validation.as_ref().map(|v| v.state) != Some(ArtifactValidationState::Accepted) {
                    continue;
                }
                let profile = self
                    .model_profile_revision(
                        &artifact.provenance.model_profile_id,
                        artifact.provenance.model_profile_revision,
                    )
                    .await?
                    .ok_or(RepositoryError::InvalidTrustGateState)?;
                let reference = self
                    .artifact_reference_for_handoff(
                        id,
                        lumen_core::artifact::MAX_ARTIFACT_PREVIEW_BYTES,
                    )
                    .await?
                    .ok_or(RepositoryError::InvalidTrustGateState)?;
                let source = reference
                    .to_context_source(ContextSourceId::new(), g.workspace_id(), actor.clone(), now)
                    .map_err(|_| RepositoryError::InvalidTrustGateState)?;
                self.append_context_source(&source).await?;
                out.push(
                    GateSource::artifact(
                        source,
                        id,
                        artifact.content_hash.clone(),
                        artifact.provenance.model_profile_id.clone(),
                        artifact.provenance.model_profile_revision,
                        profile.trust_zone(),
                        validation.map(|v| v.state),
                    )
                    .map_err(|_| RepositoryError::InvalidTrustGateState)?,
                );
            }
        }
        Ok(out)
    }
    pub async fn append_trust_gate_evaluation(
        &self,
        e: &TrustGateEvaluation,
    ) -> Result<(), RepositoryError> {
        e.verify_digest()
            .map_err(|_| RepositoryError::InvalidTrustGateState)?;
        if e.allowed != (e.projection_id.is_some() && e.projection_digest.is_some()) {
            return Err(RepositoryError::InvalidTrustGateState);
        }
        sqlx::query("INSERT INTO mixed_trust_gate_evaluations(evaluation_id,workspace_id,orchestration_id,graph_revision,task_node_id,profile_id,profile_revision,policy_revision,destination_trust_zone,mixed_trust,allowed,decision_digest,decision_json,projection_id,projection_digest,created_at)VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)").bind(e.id.to_string()).bind(e.workspace_id.to_string()).bind(e.orchestration_id.to_string()).bind(pos(e.graph_revision)?).bind(e.task_node_id.to_string()).bind(e.destination_profile_id.as_str()).bind(pos(e.destination_profile_revision)?).bind(pos(e.policy_revision)?).bind(trust(e.destination_trust_zone)).bind(e.mixed_trust).bind(e.allowed).bind(e.decision_digest.as_str()).bind(serde_json::to_string(e)?).bind(e.projection_id.as_deref()).bind(e.projection_digest.as_deref()).bind(timestamp_to_i64(e.created_at)?).execute(self.pool()).await?;
        Ok(())
    }
    pub async fn trust_gate_evaluations(
        &self,
        id: OrchestrationId,
    ) -> Result<Vec<Value>, RepositoryError> {
        sqlx::query_scalar::<_,String>("SELECT decision_json FROM mixed_trust_gate_evaluations WHERE orchestration_id=? ORDER BY created_at,evaluation_id").bind(id.to_string()).fetch_all(self.pool()).await?.into_iter().map(|v|serde_json::from_str(&v).map_err(Into::into)).collect()
    }
    pub async fn orchestration_quarantine(
        &self,
        id: OrchestrationId,
    ) -> Result<Option<Value>, RepositoryError> {
        sqlx::query("SELECT check_id,reason_digest,created_at FROM orchestration_security_quarantine WHERE orchestration_id=?").bind(id.to_string()).fetch_optional(self.pool()).await?.map(|r|Ok(json!({"check_id":r.try_get::<String,_>("check_id")?,"reason_digest":r.try_get::<String,_>("reason_digest")?,"created_at":u64v(&r,"created_at")?}))).transpose()
    }
    pub async fn verify_orchestration_integrity(
        &self,
        id: OrchestrationId,
        now: TimestampMillis,
    ) -> Result<OrchestrationIntegrityReport, RepositoryError> {
        let raw: Option<String> =
            sqlx::query_scalar("SELECT workspace_id FROM orchestrations WHERE orchestration_id=?")
                .bind(id.to_string())
                .fetch_optional(self.pool())
                .await?;
        let w = WorkspaceId::from_uuid(
            Uuid::parse_str(
                raw.as_deref()
                    .ok_or(RepositoryError::InvalidTrustGateState)?,
            )
            .map_err(|_| RepositoryError::InvalidTrustGateState)?,
        );
        let mut issues = BTreeSet::new();
        let snap = match self.latest_orchestration_snapshot(id).await {
            Ok(Some(v)) => v,
            _ => {
                issues.insert(IntegrityIssue::GraphDigest);
                return OrchestrationIntegrityReport::new(id, w, issues, now)
                    .map_err(|_| RepositoryError::InvalidTrustGateState);
            }
        };
        if snap.graph().verify_digest().is_err() {
            issues.insert(IntegrityIssue::GraphDigest);
        }
        let attempts = match self.worker_attempts_for_orchestration(id).await {
            Ok(v) => v,
            Err(_) => {
                issues.insert(IntegrityIssue::WorkerBinding);
                Vec::new()
            }
        };
        for attempt in attempts {
            let a = attempt.assignment();
            let node = snap.graph().node(a.task_node_id());
            let provider = self
                .provider_config_revision(a.provider_id(), a.provider_revision())
                .await
                .ok()
                .flatten();
            let profile = self
                .model_profile_revision(a.model_profile_id(), a.model_profile_revision())
                .await
                .ok()
                .flatten();
            let policy = self
                .model_data_policy_revision(
                    a.workspace_id(),
                    a.model_profile_id(),
                    a.policy_revision(),
                )
                .await
                .ok()
                .flatten();
            let projection = self.task_projection(a.projection_id()).await.ok().flatten();
            if node.is_none() || provider.is_none() || profile.is_none() || policy.is_none() {
                issues.insert(IntegrityIssue::WorkerBinding);
            }
            if let (Some(n), Some(p), Some(m), Some(pol), Some(proj)) = (
                node,
                provider.as_ref(),
                profile.as_ref(),
                policy.as_ref(),
                projection.as_ref(),
            ) {
                if proj.digest() != a.projection_digest() || proj.verify_digest().is_err() {
                    issues.insert(IntegrityIssue::ProjectionBinding);
                }
                if a.validate_materialized(snap.graph(), n, p, m, pol, proj)
                    .is_err()
                {
                    issues.insert(IntegrityIssue::WorkerBinding);
                }
            } else if projection.is_none() {
                issues.insert(IntegrityIssue::ProjectionBinding);
            }
            if !self.trust_gate_matches_assignment(a).await.unwrap_or(false) {
                issues.insert(IntegrityIssue::TrustGateMissing);
            }
            let routing: Option<i64> = sqlx::query_scalar(
                "SELECT 1 FROM worker_attempt_routing_bindings WHERE attempt_id=?",
            )
            .bind(attempt.attempt_id().to_string())
            .fetch_optional(self.pool())
            .await?;
            if routing.is_none() {
                issues.insert(IntegrityIssue::RoutingBinding);
            }
            if attempt.state() == WorkerAttemptState::Completed {
                let ids = sqlx::query_scalar::<_, String>(
                    "SELECT artifact_id FROM worker_artifacts WHERE attempt_id=?",
                )
                .bind(attempt.attempt_id().to_string())
                .fetch_all(self.pool())
                .await?;
                if ids.len() != 1 {
                    issues.insert(IntegrityIssue::ArtifactBinding);
                } else {
                    match Uuid::parse_str(&ids[0])
                        .ok()
                        .map(lumen_core::artifact::ArtifactId::from_uuid)
                    {
                        Some(aid) => {
                            if self.worker_artifact(aid).await.ok().flatten().is_none() {
                                issues.insert(IntegrityIssue::ArtifactBinding);
                            }
                        }
                        None => {
                            issues.insert(IntegrityIssue::ArtifactBinding);
                        }
                    }
                }
            }
            if attempt.state() == WorkerAttemptState::Unknown
                && self
                    .worker_failure(attempt.attempt_id())
                    .await
                    .ok()
                    .flatten()
                    .is_none()
            {
                issues.insert(IntegrityIssue::UnknownFailureMetadata);
            }
        }
        OrchestrationIntegrityReport::new(id, w, issues, now)
            .map_err(|_| RepositoryError::InvalidTrustGateState)
    }
    pub async fn record_recovery_integrity(
        &self,
        r: &OrchestrationIntegrityReport,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO orchestration_recovery_checks(check_id,orchestration_id,workspace_id,ok,report_digest,report_json,checked_at)VALUES(?,?,?,?,?,?,?)").bind(r.check_id.to_string()).bind(r.orchestration_id.to_string()).bind(r.workspace_id.to_string()).bind(r.ok()).bind(r.digest.as_str()).bind(serde_json::to_string(r)?).bind(timestamp_to_i64(r.checked_at)?).execute(self.pool()).await?;
        if !r.ok() {
            sqlx::query("INSERT INTO orchestration_security_quarantine(orchestration_id,check_id,reason_digest,created_at)VALUES(?,?,?,?) ON CONFLICT(orchestration_id) DO NOTHING").bind(r.orchestration_id.to_string()).bind(r.check_id.to_string()).bind(r.digest.as_str()).bind(timestamp_to_i64(r.checked_at)?).execute(self.pool()).await?;
        }
        Ok(())
    }
    pub async fn ensure_recovered_unknown_failure_metadata(
        &self,
        id: OrchestrationId,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        for a in self.worker_attempts_for_orchestration(id).await? {
            if a.state() == WorkerAttemptState::Unknown
                && self.worker_failure(a.attempt_id()).await?.is_none()
            {
                let risk = self.effect_risk_for_run(a.run_id()).await?;
                let f = WorkerFailure::new(
                    a.attempt_id(),
                    FailureClass::UnknownFailure,
                    risk,
                    Some("worker recovered after lease loss".into()),
                    now,
                )
                .map_err(|_| RepositoryError::InvalidTrustGateState)?;
                self.record_worker_failure(&f).await?;
            }
        }
        Ok(())
    }
    async fn trust_gate_matches_assignment(
        &self,
        a: &WorkerAssignment,
    ) -> Result<bool, RepositoryError> {
        Ok(sqlx::query_scalar::<_,i64>("SELECT 1 FROM mixed_trust_gate_evaluations WHERE allowed=1 AND workspace_id=? AND orchestration_id=? AND graph_revision=? AND task_node_id=? AND profile_id=? AND profile_revision=? AND policy_revision=? AND projection_id=? AND projection_digest=?").bind(a.workspace_id().to_string()).bind(a.orchestration_id().to_string()).bind(pos(a.graph_revision())?).bind(a.task_node_id().to_string()).bind(a.model_profile_id().as_str()).bind(pos(a.model_profile_revision())?).bind(pos(a.policy_revision())?).bind(a.projection_id().to_string()).bind(a.projection_digest().as_str()).fetch_optional(self.pool()).await?.is_some())
    }
}
pub(crate) async fn verify_trust_gate_binding_tx(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    a: &WorkerAssignment,
) -> Result<(), RepositoryError> {
    let ok=sqlx::query_scalar::<_,i64>("SELECT 1 FROM mixed_trust_gate_evaluations WHERE allowed=1 AND workspace_id=? AND orchestration_id=? AND graph_revision=? AND task_node_id=? AND profile_id=? AND profile_revision=? AND policy_revision=? AND projection_id=? AND projection_digest=?").bind(a.workspace_id().to_string()).bind(a.orchestration_id().to_string()).bind(pos(a.graph_revision())?).bind(a.task_node_id().to_string()).bind(a.model_profile_id().as_str()).bind(pos(a.model_profile_revision())?).bind(pos(a.policy_revision())?).bind(a.projection_id().to_string()).bind(a.projection_digest().as_str()).fetch_optional(&mut**tx).await?;
    if ok.is_none() {
        return Err(RepositoryError::InvalidTrustGateState);
    }
    Ok(())
}
fn trust(v: ModelTrustZone) -> &'static str {
    match v {
        ModelTrustZone::LocalTrusted => "local_trusted",
        ModelTrustZone::LocalRestricted => "local_restricted",
        ModelTrustZone::RemoteApproved => "remote_approved",
        ModelTrustZone::RemoteUntrusted => "remote_untrusted",
    }
}
fn pos(v: u64) -> Result<i64, RepositoryError> {
    i64::try_from(v)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(RepositoryError::InvalidTrustGateState)
}
fn u64v(r: &sqlx::sqlite::SqliteRow, k: &str) -> Result<u64, RepositoryError> {
    u64::try_from(r.try_get::<i64, _>(k)?).map_err(|_| RepositoryError::InvalidTrustGateState)
}
