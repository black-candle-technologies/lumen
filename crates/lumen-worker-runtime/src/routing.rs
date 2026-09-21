use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use lumen_core::{
    approval::TimestampMillis,
    context::{ModelDataPolicy, TaskProjection},
    identity::PrincipalId,
    model::ReasoningProfile,
    orchestration::{TaskGraph, TaskNode},
    provider::{
        ModelProfile, ProviderConfig, ProviderError, ProviderUsageEvent, ProviderUsageSink,
        ProviderUsageSinkFuture,
    },
    routing::{HealthObservation, HealthState, RoutingCandidate, RoutingPolicy, route},
    worker::{WorkerAssignment, WorkerCapabilityGrant, WorkerRunBudget},
};
use lumen_db::RepositoryError;

use crate::{WorkerRuntimeError, WorkerScheduler};

#[derive(Clone)]
pub struct RoutedWorkerCandidate {
    pub provider: ProviderConfig,
    pub profile: ModelProfile,
    pub policy: ModelDataPolicy,
    pub projection: TaskProjection,
    pub grants: Vec<WorkerCapabilityGrant>,
    pub worker_budget: WorkerRunBudget,
}
pub struct DatabaseUsageSink {
    db: lumen_db::Database,
    reservation: lumen_core::routing::BudgetReservationId,
}
impl DatabaseUsageSink {
    pub const fn new(
        db: lumen_db::Database,
        reservation: lumen_core::routing::BudgetReservationId,
    ) -> Self {
        Self { db, reservation }
    }
}
impl ProviderUsageSink for DatabaseUsageSink {
    fn record<'a>(&'a self, event: ProviderUsageEvent) -> ProviderUsageSinkFuture<'a> {
        Box::pin(async move {
            self.db
                .record_provider_usage(
                    self.reservation,
                    &event,
                    now().map_err(|error| ProviderError::transport(error.to_string()))?,
                )
                .await
                .map_err(|error| ProviderError::transport(format!("persist model usage: {error}")))
        })
    }
}

impl WorkerScheduler {
    #[allow(clippy::too_many_arguments)]
    pub async fn route_and_dispatch(
        self: &Arc<Self>,
        graph: &TaskGraph,
        node: &TaskNode,
        actor: PrincipalId,
        candidates: Vec<RoutedWorkerCandidate>,
        reasoning: ReasoningProfile,
        policy: RoutingPolicy,
        now: TimestampMillis,
    ) -> Result<lumen_core::worker::WorkerAttemptId, WorkerRuntimeError> {
        self.db
            .reconcile_task_readiness(graph.orchestration_id(), now)
            .await?;
        let budget = self
            .db
            .budget_snapshot(graph.orchestration_id(), now)
            .await?
            .ok_or_else(|| {
                WorkerRuntimeError::Routing("orchestration budget is not configured".into())
            })?;
        let routes = self.db.model_provider_routes(graph.workspace_id()).await?;
        let worker_budget = candidates
            .first()
            .map(|candidate| candidate.worker_budget)
            .ok_or_else(|| WorkerRuntimeError::Routing("no routing candidates".into()))?;
        if candidates
            .iter()
            .any(|candidate| candidate.worker_budget != worker_budget)
        {
            return Err(WorkerRuntimeError::Routing(
                "candidate worker budgets differ".into(),
            ));
        }
        let mut material = Vec::new();
        let mut routable = Vec::new();
        for candidate in candidates {
            let metadata = self
                .db
                .latest_model_routing_metadata(candidate.profile.id(), candidate.profile.revision())
                .await?
                .ok_or_else(|| WorkerRuntimeError::Routing("routing metadata missing".into()))?;
            let provider_health = self
                .db
                .latest_provider_health(candidate.provider.id(), candidate.provider.revision())
                .await?
                .unwrap_or(
                    HealthObservation::new(
                        HealthState::Unavailable,
                        0,
                        now,
                        TimestampMillis::new(now.as_u64().saturating_add(1)),
                    )
                    .map_err(|error| WorkerRuntimeError::Routing(error.to_string()))?,
                );
            let model_health = self
                .db
                .latest_model_health(candidate.profile.id(), candidate.profile.revision())
                .await?
                .unwrap_or(
                    HealthObservation::new(
                        HealthState::Unavailable,
                        0,
                        now,
                        TimestampMillis::new(now.as_u64().saturating_add(1)),
                    )
                    .map_err(|error| WorkerRuntimeError::Routing(error.to_string()))?,
                );
            let (provider_active, profile_active) = self
                .db
                .active_worker_counts(
                    candidate.provider.id(),
                    candidate.profile.id(),
                    candidate.profile.revision(),
                )
                .await?;
            let capacity = self
                .config
                .providers
                .get(candidate.provider.id().as_str())
                .copied()
                .unwrap_or(0);
            let egress_allowed = routes
                .iter()
                .find(|route| route.provider() == candidate.provider.id())
                .is_some_and(|route| route.allows_data_class(node.requirements().data_class()));
            routable.push(RoutingCandidate {
                provider: candidate.provider.clone(),
                profile: candidate.profile.clone(),
                policy: candidate.policy.clone(),
                metadata,
                provider_health,
                model_health,
                egress_allowed,
                provider_active,
                provider_capacity: u32::try_from(capacity).unwrap_or(u32::MAX),
                profile_active,
            });
            material.push(candidate);
        }
        let request = lumen_core::routing::RoutingRequest::from_task(
            graph.orchestration_id(),
            graph.revision(),
            node,
            reasoning,
            worker_budget,
            policy,
            now,
        );
        let plan = route(node, &request, &budget, routable)
            .map_err(|error| WorkerRuntimeError::Routing(error.to_string()))?;
        let selected = material
            .into_iter()
            .find(|candidate| {
                candidate.provider.id() == plan.provider_id()
                    && candidate.provider.revision() == plan.provider_revision()
                    && candidate.profile.id() == plan.profile_id()
                    && candidate.profile.revision() == plan.profile_revision()
            })
            .ok_or_else(|| WorkerRuntimeError::Routing("selected candidate disappeared".into()))?;
        self.db
            .persist_route_and_reserve(
                graph.orchestration_id(),
                graph.revision(),
                node.id(),
                &plan,
                now,
            )
            .await?;
        let assignment = WorkerAssignment::new(
            graph,
            node,
            actor,
            &selected.provider,
            &selected.profile,
            &selected.policy,
            &selected.projection,
            selected.grants,
            selected.worker_budget,
        )?;
        match Arc::clone(self).reserve_and_start(assignment, now).await {
            Ok(id) => Ok(id),
            Err(error) => {
                let _ = self
                    .db
                    .release_active_routing_for_task(
                        graph.orchestration_id(),
                        graph.revision(),
                        node.id(),
                        now,
                    )
                    .await;
                Err(error)
            }
        }
    }
}
fn now() -> Result<TimestampMillis, RepositoryError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| RepositoryError::InvalidRoutingState)?
        .as_millis();
    Ok(TimestampMillis::new(
        u64::try_from(millis).unwrap_or(u64::MAX),
    ))
}
