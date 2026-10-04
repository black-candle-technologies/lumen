use crate::{RoutedWorkerCandidate, WorkerRuntimeError, WorkerScheduler};
use lumen_core::{
    approval::TimestampMillis,
    artifact::{RetryDecision, RetryMode},
    identity::PrincipalId,
    model::ReasoningProfile,
    orchestration::{TaskGraph, TaskNode},
    routing::RoutingPolicy,
    worker::WorkerAttemptId,
};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct RetryDispatch {
    pub decision: RetryDecision,
    pub attempt_id: WorkerAttemptId,
}
impl WorkerScheduler {
    #[allow(clippy::too_many_arguments)]
    pub async fn retry_task(
        self: &Arc<Self>,
        graph: &TaskGraph,
        node: &TaskNode,
        prior_attempt_id: WorkerAttemptId,
        requested_by: PrincipalId,
        mut candidates: Vec<RoutedWorkerCandidate>,
        reasoning: ReasoningProfile,
        policy: RoutingPolicy,
        mode: RetryMode,
        now: TimestampMillis,
    ) -> Result<RetryDispatch, WorkerRuntimeError> {
        let decision = self
            .authorize_retry(
                graph,
                node,
                prior_attempt_id,
                requested_by.clone(),
                &mut candidates,
                mode,
                now,
            )
            .await?;
        let attempt_id = self
            .route_and_dispatch(
                graph,
                node,
                requested_by,
                candidates,
                reasoning,
                policy,
                now,
            )
            .await?;
        Ok(RetryDispatch {
            decision,
            attempt_id,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn authorize_retry(
        &self,
        graph: &TaskGraph,
        node: &TaskNode,
        prior_attempt_id: WorkerAttemptId,
        requested_by: PrincipalId,
        candidates: &mut Vec<RoutedWorkerCandidate>,
        mode: RetryMode,
        now: TimestampMillis,
    ) -> Result<RetryDecision, WorkerRuntimeError> {
        let prior = self
            .db
            .worker_attempt(prior_attempt_id)
            .await?
            .ok_or(WorkerRuntimeError::Stale)?;
        if prior.assignment().orchestration_id() != graph.orchestration_id()
            || prior.assignment().graph_revision() != graph.revision()
            || prior.assignment().task_node_id() != node.id()
        {
            return Err(WorkerRuntimeError::Stale);
        }
        let decision = self
            .db
            .authorize_worker_retry(prior_attempt_id, mode, &requested_by, now)
            .await?;
        if !decision.allowed {
            return Err(WorkerRuntimeError::RetryDenied(
                decision.disposition.as_str().to_owned(),
            ));
        }
        candidates.retain(|candidate| match mode {
            RetryMode::SameWorker => {
                candidate.provider.id() == &decision.previous_provider_id
                    && candidate.provider.revision() == decision.previous_provider_revision
                    && candidate.profile.id() == &decision.previous_profile_id
                    && candidate.profile.revision() == decision.previous_profile_revision
            }
            RetryMode::Reassign => {
                candidate.profile.id() != &decision.previous_profile_id
                    || candidate.profile.revision() != decision.previous_profile_revision
            }
        });
        if candidates.is_empty() {
            return Err(WorkerRuntimeError::RetryDenied(
                "no candidate satisfies the retry mode".into(),
            ));
        }
        Ok(decision)
    }
    pub async fn filter_retry_candidates(
        &self,
        graph: &TaskGraph,
        node: &TaskNode,
        candidates: &mut Vec<RoutedWorkerCandidate>,
    ) -> Result<(), WorkerRuntimeError> {
        if let Some((mode, prior)) = self
            .db
            .pending_worker_retry(graph.orchestration_id(), graph.revision(), node.id())
            .await?
        {
            let prior = self
                .db
                .worker_attempt(prior)
                .await?
                .ok_or(WorkerRuntimeError::Stale)?;
            let previous = prior.assignment();
            candidates.retain(|candidate| match mode {
                RetryMode::SameWorker => {
                    candidate.provider.id() == previous.provider_id()
                        && candidate.provider.revision() == previous.provider_revision()
                        && candidate.profile.id() == previous.model_profile_id()
                        && candidate.profile.revision() == previous.model_profile_revision()
                }
                RetryMode::Reassign => {
                    candidate.profile.id() != previous.model_profile_id()
                        || candidate.profile.revision() != previous.model_profile_revision()
                }
            });
        }
        Ok(())
    }
}
