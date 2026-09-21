//! Bounded orchestration worker execution over Lumen's existing run kernel.
mod routing;
pub use routing::{DatabaseUsageSink, RoutedWorkerCandidate};
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc, time::Duration};

use lumen_core::{
    capability::CapabilitySet,
    model::ModelGenerationConfig,
    orchestration::OrchestrationId,
    policy::{Policy, PolicyVersion},
    provider::{ModelProfileId, ProviderUsageSink},
    run::{
        ActionNormalizer, ActionPort, ApprovalPort, AuditPort, Clock, RunOrchestrator, RunOutcome,
        RunState,
    },
    worker::{ToolRestrictedNormalizer, WorkerAssignment, WorkerAttemptId, WorkerAttemptState},
};
use lumen_db::{Database, RepositoryError, WorkerAttemptRecord};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct MaterializedWorker {
    pub model: Arc<dyn lumen_core::model::ModelPort>,
    pub profile_id: ModelProfileId,
    pub profile_revision: u64,
    pub profile_concurrency_limit: u32,
}
pub type MaterializeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<MaterializedWorker, WorkerRuntimeError>> + Send + 'a>>;
pub trait WorkerMaterializer: Send + Sync {
    fn materialize<'a>(
        &'a self,
        assignment: &'a WorkerAssignment,
        generation: Option<ModelGenerationConfig>,
        usage_sink: Option<Arc<dyn ProviderUsageSink>>,
        cancellation: CancellationToken,
    ) -> MaterializeFuture<'a>;
}
#[derive(Clone)]
pub struct WorkerKernelPorts {
    pub normalizer: Arc<dyn ActionNormalizer>,
    pub executor: Arc<dyn lumen_core::executor::ExecutorPort>,
    pub approvals: Arc<dyn ApprovalPort>,
    pub audit: Arc<dyn AuditPort>,
    pub actions: Arc<dyn ActionPort>,
    pub clock: Arc<dyn Clock>,
    pub policy: Policy,
    pub policy_version: PolicyVersion,
    pub ambient_capabilities: CapabilitySet,
}
#[derive(Clone, Debug)]
pub struct WorkerSchedulerConfig {
    global: usize,
    providers: BTreeMap<String, usize>,
    lease: Duration,
}
impl WorkerSchedulerConfig {
    pub fn new(
        global: usize,
        providers: BTreeMap<String, usize>,
        lease: Duration,
    ) -> Result<Self, WorkerRuntimeError> {
        if global == 0
            || lease < Duration::from_secs(3)
            || providers.values().any(|value| *value == 0)
        {
            return Err(WorkerRuntimeError::Configuration(
                "invalid concurrency or lease".into(),
            ));
        }
        Ok(Self {
            global,
            providers,
            lease,
        })
    }
}
struct Active {
    record: WorkerAttemptRecord,
    state: RunState,
    model: Arc<dyn lumen_core::model::ModelPort>,
    profile_limit: u32,
    cancellation: CancellationToken,
}
pub struct WorkerScheduler {
    db: Database,
    materializer: Arc<dyn WorkerMaterializer>,
    ports: WorkerKernelPorts,
    config: WorkerSchedulerConfig,
    owner: Uuid,
    global: Arc<Semaphore>,
    providers: BTreeMap<String, Arc<Semaphore>>,
    profiles: Mutex<BTreeMap<(String, u64), Arc<Semaphore>>>,
    active: Mutex<BTreeMap<WorkerAttemptId, Active>>,
    cancellations: Mutex<BTreeMap<OrchestrationId, CancellationToken>>,
}
impl WorkerScheduler {
    pub fn new(
        db: Database,
        materializer: Arc<dyn WorkerMaterializer>,
        ports: WorkerKernelPorts,
        config: WorkerSchedulerConfig,
        owner: Uuid,
    ) -> Arc<Self> {
        let providers = config
            .providers
            .iter()
            .map(|(id, limit)| (id.clone(), Arc::new(Semaphore::new(*limit))))
            .collect();
        Arc::new(Self {
            db,
            materializer,
            ports,
            global: Arc::new(Semaphore::new(config.global)),
            config,
            owner,
            providers,
            profiles: Mutex::new(BTreeMap::new()),
            active: Mutex::new(BTreeMap::new()),
            cancellations: Mutex::new(BTreeMap::new()),
        })
    }
    pub async fn dispatch_ready(
        self: &Arc<Self>,
        assignments: Vec<WorkerAssignment>,
        now: lumen_core::approval::TimestampMillis,
    ) -> Result<Vec<WorkerAttemptId>, WorkerRuntimeError> {
        let mut result = Vec::new();
        for assignment in assignments {
            result.push(self.reserve_and_start(assignment, now).await?);
        }
        Ok(result)
    }
    pub(crate) async fn reserve_and_start(
        self: &Arc<Self>,
        assignment: WorkerAssignment,
        now: lumen_core::approval::TimestampMillis,
    ) -> Result<WorkerAttemptId, WorkerRuntimeError> {
        if self
            .db
            .orchestration_cancelled(assignment.orchestration_id())
            .await?
        {
            return Err(WorkerRuntimeError::Cancelled);
        }
        let id = WorkerAttemptId::new();
        let record = self
            .db
            .reserve_worker_attempt(
                &assignment,
                id,
                lumen_core::action::RunId::new(),
                self.owner,
                add(now, self.config.lease),
                now,
            )
            .await?;
        self.start(record, now).await?;
        Ok(id)
    }
    async fn start(
        self: &Arc<Self>,
        record: WorkerAttemptRecord,
        now: lumen_core::approval::TimestampMillis,
    ) -> Result<(), WorkerRuntimeError> {
        let assignment = record.assignment().clone();
        let token = self.token(assignment.orchestration_id()).await;
        if token.is_cancelled()
            || self
                .db
                .orchestration_cancelled(assignment.orchestration_id())
                .await?
        {
            self.db
                .terminalize_worker_attempt(
                    record.attempt_id(),
                    Some(self.owner),
                    WorkerAttemptState::Cancelled,
                    Some("cancelled before dispatch"),
                    now,
                )
                .await?;
            return Ok(());
        }
        let dispatch = self
            .db
            .active_routing_dispatch(
                assignment.orchestration_id(),
                assignment.graph_revision(),
                assignment.task_node_id(),
            )
            .await?;
        let (generation, usage_sink) = match dispatch {
            Some(dispatch) => (
                Some(dispatch.generation),
                Some(Arc::new(routing::DatabaseUsageSink::new(
                    self.db.clone(),
                    dispatch.reservation_id,
                )) as Arc<dyn ProviderUsageSink>),
            ),
            None => (None, None),
        };
        let material = self
            .materializer
            .materialize(&assignment, generation, usage_sink, token.child_token())
            .await?;
        if material.profile_id != *assignment.model_profile_id()
            || material.profile_revision != assignment.model_profile_revision()
            || material.profile_concurrency_limit == 0
        {
            return Err(WorkerRuntimeError::Stale);
        }
        self.db
            .start_worker_attempt(
                record.attempt_id(),
                self.owner,
                add(now, self.config.lease),
                now,
            )
            .await?;
        let current = self
            .db
            .worker_attempt(record.attempt_id())
            .await?
            .ok_or(WorkerRuntimeError::Stale)?;
        self.active.lock().await.insert(
            record.attempt_id(),
            Active {
                state: RunState::new(
                    assignment.run_context(record.run_id()),
                    assignment.prompt(),
                    assignment.budget().as_run_budget(),
                )
                .with_data_class(assignment.data_class()),
                record: current,
                model: material.model,
                profile_limit: material.profile_concurrency_limit,
                cancellation: token.child_token(),
            },
        );
        self.advance(record.attempt_id()).await
    }
    pub async fn resume_after_approval(
        self: &Arc<Self>,
        id: WorkerAttemptId,
        now: lumen_core::approval::TimestampMillis,
    ) -> Result<(), WorkerRuntimeError> {
        self.db
            .resume_worker_attempt_from_approval(id, self.owner, add(now, self.config.lease), now)
            .await?;
        self.advance(id).await
    }
    async fn advance(self: &Arc<Self>, id: WorkerAttemptId) -> Result<(), WorkerRuntimeError> {
        let mut active = self
            .active
            .lock()
            .await
            .remove(&id)
            .ok_or(WorkerRuntimeError::Stale)?;
        if active.cancellation.is_cancelled() {
            active.state.cancel();
        }
        let permits = self
            .limits(
                active.record.assignment(),
                active.profile_limit,
                &active.cancellation,
            )
            .await?;
        let normalizer = ToolRestrictedNormalizer::new(
            self.ports.normalizer.as_ref(),
            active.record.assignment().allowed_tools(),
        );
        let capabilities = active
            .record
            .assignment()
            .effective_capabilities(self.ports.ambient_capabilities.clone())?;
        let runner = RunOrchestrator::new(
            active.model.as_ref(),
            &normalizer,
            self.ports.executor.as_ref(),
            self.ports.approvals.as_ref(),
            self.ports.audit.as_ref(),
            self.ports.actions.as_ref(),
            self.ports.clock.as_ref(),
            self.ports.policy.clone(),
            self.ports.policy_version.clone(),
        )
        .with_cancellation(active.cancellation.clone());
        let outcome = runner
            .run_until_blocked(&mut active.state, &capabilities)
            .await;
        drop(permits);
        let now = self.ports.clock.now();
        match outcome {
            Ok(RunOutcome::AwaitingApproval { .. }) => {
                self.db
                    .pause_worker_attempt_for_approval(
                        id,
                        self.owner,
                        add(now, self.config.lease),
                        now,
                    )
                    .await?;
                active.record = self
                    .db
                    .worker_attempt(id)
                    .await?
                    .ok_or(WorkerRuntimeError::Stale)?;
                self.active.lock().await.insert(id, active);
                Ok(())
            }
            Ok(outcome) => {
                self.db
                    .terminalize_worker_attempt(
                        id,
                        Some(self.owner),
                        state(&outcome),
                        diagnostic(&outcome).as_deref(),
                        now,
                    )
                    .await?;
                let _ = self
                    .db
                    .settle_active_routing_for_task(
                        active.record.assignment().orchestration_id(),
                        active.record.assignment().graph_revision(),
                        active.record.assignment().task_node_id(),
                        now,
                    )
                    .await?;
                self.db
                    .reconcile_task_readiness(active.record.assignment().orchestration_id(), now)
                    .await?;
                Ok(())
            }
            Err(error) => {
                self.db
                    .terminalize_worker_attempt(
                        id,
                        Some(self.owner),
                        WorkerAttemptState::Unknown,
                        Some(&bounded(&error.to_string())),
                        now,
                    )
                    .await?;
                let _ = self
                    .db
                    .settle_active_routing_for_task(
                        active.record.assignment().orchestration_id(),
                        active.record.assignment().graph_revision(),
                        active.record.assignment().task_node_id(),
                        now,
                    )
                    .await?;
                self.db
                    .reconcile_task_readiness(active.record.assignment().orchestration_id(), now)
                    .await?;
                Ok(())
            }
        }
    }
    pub async fn cancel_orchestration(
        self: &Arc<Self>,
        id: OrchestrationId,
        actor: &lumen_core::identity::PrincipalId,
        now: lumen_core::approval::TimestampMillis,
    ) -> Result<(), WorkerRuntimeError> {
        self.db
            .request_orchestration_cancellation(id, actor, now)
            .await?;
        self.token(id).await.cancel();
        let ids = self
            .active
            .lock()
            .await
            .iter()
            .filter_map(|(attempt, active)| {
                (active.record.assignment().orchestration_id() == id).then_some(*attempt)
            })
            .collect::<Vec<_>>();
        for attempt in ids {
            let _ = self.advance(attempt).await;
        }
        Ok(())
    }
    pub async fn recover_once(
        self: &Arc<Self>,
        now: lumen_core::approval::TimestampMillis,
    ) -> Result<Vec<WorkerAttemptId>, WorkerRuntimeError> {
        let (reserved, touched) = self.db.recover_expired_worker_attempts(now).await?;
        for orchestration in touched {
            self.db.reconcile_task_readiness(orchestration, now).await?;
        }
        let mut out = Vec::new();
        for id in reserved {
            if self
                .db
                .claim_reserved_worker_attempt(id, self.owner, add(now, self.config.lease), now)
                .await?
            {
                let record = self
                    .db
                    .worker_attempt(id)
                    .await?
                    .ok_or(WorkerRuntimeError::Stale)?;
                self.start(record, now).await?;
                out.push(id);
            }
        }
        Ok(out)
    }
    async fn token(&self, id: OrchestrationId) -> CancellationToken {
        let mut tokens = self.cancellations.lock().await;
        tokens
            .entry(id)
            .or_insert_with(CancellationToken::new)
            .clone()
    }
    async fn limits(
        &self,
        assignment: &WorkerAssignment,
        profile_limit: u32,
        cancellation: &CancellationToken,
    ) -> Result<Permits, WorkerRuntimeError> {
        let global = acquire(self.global.clone(), cancellation).await?;
        let provider = acquire(
            self.providers
                .get(assignment.provider_id().as_str())
                .cloned()
                .ok_or_else(|| {
                    WorkerRuntimeError::Configuration("provider concurrency missing".into())
                })?,
            cancellation,
        )
        .await?;
        let key = (
            assignment.model_profile_id().as_str().to_owned(),
            assignment.model_profile_revision(),
        );
        let profile = {
            let mut profiles = self.profiles.lock().await;
            profiles
                .entry(key)
                .or_insert_with(|| Arc::new(Semaphore::new(profile_limit as usize)))
                .clone()
        };
        let profile = acquire(profile, cancellation).await?;
        Ok(Permits {
            _global: global,
            _provider: provider,
            _profile: profile,
        })
    }
}
struct Permits {
    _global: OwnedSemaphorePermit,
    _provider: OwnedSemaphorePermit,
    _profile: OwnedSemaphorePermit,
}
async fn acquire(
    permit: Arc<Semaphore>,
    cancellation: &CancellationToken,
) -> Result<OwnedSemaphorePermit, WorkerRuntimeError> {
    tokio::select! { biased; _=cancellation.cancelled()=>Err(WorkerRuntimeError::Cancelled), permit=permit.acquire_owned()=>permit.map_err(|_|WorkerRuntimeError::Internal("semaphore closed".into())) }
}
fn state(outcome: &RunOutcome) -> WorkerAttemptState {
    match outcome {
        RunOutcome::Completed { .. } => WorkerAttemptState::Completed,
        RunOutcome::Cancelled => WorkerAttemptState::Cancelled,
        RunOutcome::ExecutionUnknown { .. } => WorkerAttemptState::Unknown,
        RunOutcome::AwaitingApproval { .. } => unreachable!(),
        _ => WorkerAttemptState::Failed,
    }
}
fn diagnostic(outcome: &RunOutcome) -> Option<String> {
    match outcome {
        RunOutcome::ExecutionFailed { message } | RunOutcome::ExecutionUnknown { message } => {
            Some(bounded(message))
        }
        RunOutcome::BudgetExhausted(kind) => Some(format!("budget exhausted: {}", kind.as_str())),
        _ => None,
    }
}
fn bounded(value: &str) -> String {
    value.chars().take(512).collect()
}
fn add(
    now: lumen_core::approval::TimestampMillis,
    duration: Duration,
) -> lumen_core::approval::TimestampMillis {
    lumen_core::approval::TimestampMillis::new(
        now.as_u64()
            .saturating_add(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
    )
}
#[derive(Debug, Error)]
pub enum WorkerRuntimeError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Worker(#[from] lumen_core::worker::WorkerError),
    #[error("stale worker assignment")]
    Stale,
    #[error("worker cancelled")]
    Cancelled,
    #[error("worker configuration: {0}")]
    Configuration(String),
    #[error("worker routing: {0}")]
    Routing(String),
    #[error("worker internal: {0}")]
    Internal(String),
}
