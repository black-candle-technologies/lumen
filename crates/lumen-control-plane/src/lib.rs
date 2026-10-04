pub mod provider_runtime;
use lumen_core::{
    approval::TimestampMillis,
    artifact::RetryMode,
    context::{
        ContextDigest, ContextSource, ContextSourceId, ModelDataPolicy, ProjectionId,
        ProjectionTaskKey, SourceProvenance, SourceProvenanceKind, TaskProjection,
    },
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
    model::{ModelInput, ModelMessage, ModelOutput, ModelPort, ModelRole},
    operator::{
        AuthorityRequest, OperatorAuthorityPort, OperatorOperation, OrchestrationControlPolicy,
    },
    orchestration::{OrchestrationId, TaskGraph, TaskGraphProposal, TaskNode, TaskNodeState},
    provider::ModelProfile,
    routing::{OrchestrationBudget, RoutingPolicy},
    trust_gate::evaluate_exact_projection,
    worker::{OwnedProjectedModel, WorkerAssignment, WorkerCapabilityGrant, WorkerRunBudget},
};
use lumen_db::{ControlEvent, Database, RepositoryError};
use lumen_server::{
    ControlAction, ControlOrchestrationCommand, CreateOrchestrationCommand, DispatchTick,
    OrchestrationEvent, OrchestrationFuture, OrchestrationService, ServiceError,
    WorkerDispatchDriver, WorkerDispatchFuture,
};
use lumen_worker_runtime::{
    MaterializeFuture, MaterializedWorker, RoutedWorkerCandidate, WorkerMaterializer,
    WorkerRuntimeError, WorkerScheduler,
};
use serde_json::{Value, json};
use std::{future::Future, pin::Pin, sync::Arc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
#[derive(Clone)]
pub struct BootstrapOperatorAuthority {
    principal: PrincipalId,
    workspace: WorkspaceId,
}
impl BootstrapOperatorAuthority {
    pub fn new(principal: PrincipalId, workspace: WorkspaceId) -> Self {
        Self {
            principal,
            workspace,
        }
    }
}
impl OperatorAuthorityPort for BootstrapOperatorAuthority {
    fn authorize<'a>(
        &'a self,
        r: &'a AuthorityRequest,
    ) -> lumen_core::operator::AuthorityFuture<'a> {
        Box::pin(async move { Ok(r.workspace_id == self.workspace && r.actor == self.principal) })
    }
}
pub type PlannerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<TaskGraphProposal, ControlPlaneError>> + Send + 'a>>;
pub trait PlannerPort: Send + Sync {
    fn plan<'a>(&'a self, prompt: &'a str, class: DataClass) -> PlannerFuture<'a>;
}
pub struct JsonModelPlanner {
    model: Arc<dyn ModelPort>,
}
impl JsonModelPlanner {
    pub fn new(model: Arc<dyn ModelPort>) -> Self {
        Self { model }
    }
}
fn task_graph_planner_prompt(prompt: &str) -> String {
    format!(
        concat!(
            "Return ONLY TaskGraphProposal JSON, no markdown/tools. ",
            "The top-level object must be exactly {{\"nodes\":[...]}}. ",
            "Each element of nodes must include ",
            "key,description,expected_output,depends_on,requirements,limits,deadline_at. ",
            "Return at most 256 nodes. Do not add any other top-level fields. ",
            "Request: {prompt}"
        ),
        prompt = prompt
    )
}
impl PlannerPort for JsonModelPlanner {
    fn plan<'a>(&'a self, prompt: &'a str, class: DataClass) -> PlannerFuture<'a> {
        Box::pin(async move {
            if prompt.is_empty() || prompt.len() > 65536 {
                return Err(ControlPlaneError::Planner("invalid prompt".into()));
            }
            let q = task_graph_planner_prompt(prompt);
            match self
                .model
                .generate(
                    ModelInput::new(vec![ModelMessage::new(ModelRole::User, q.into())])
                        .with_data_class(class),
                )
                .await
                .map_err(|e| ControlPlaneError::Planner(e.to_string()))?
            {
                ModelOutput::FinalText(v) => {
                    serde_json::from_str(&v).map_err(|e| ControlPlaneError::Planner(e.to_string()))
                }
                ModelOutput::Action(_) => Err(ControlPlaneError::Planner(
                    "planner tool call denied".into(),
                )),
            }
        })
    }
}
pub struct DatabaseWorkerMaterializer {
    db: Database,
    factory: Arc<provider_runtime::DatabaseProviderFactory>,
}
impl DatabaseWorkerMaterializer {
    pub fn new(db: Database, factory: Arc<provider_runtime::DatabaseProviderFactory>) -> Self {
        Self { db, factory }
    }
}
impl WorkerMaterializer for DatabaseWorkerMaterializer {
    fn materialize<'a>(
        &'a self,
        a: &'a WorkerAssignment,
        g: Option<lumen_core::model::ModelGenerationConfig>,
        sink: Option<Arc<dyn lumen_core::provider::ProviderUsageSink>>,
        cancel: CancellationToken,
    ) -> MaterializeFuture<'a> {
        Box::pin(async move {
            let p = self
                .db
                .provider_config_revision(a.provider_id(), a.provider_revision())
                .await?
                .ok_or(WorkerRuntimeError::Stale)?;
            let m = self
                .db
                .model_profile_revision(a.model_profile_id(), a.model_profile_revision())
                .await?
                .ok_or(WorkerRuntimeError::Stale)?;
            let policy = self
                .db
                .model_data_policy_revision(
                    a.workspace_id(),
                    a.model_profile_id(),
                    a.policy_revision(),
                )
                .await?
                .ok_or(WorkerRuntimeError::Stale)?;
            let projection = self
                .db
                .task_projection(a.projection_id())
                .await?
                .ok_or(WorkerRuntimeError::Stale)?;
            if p.id() != a.provider_id()
                || m.provider_id() != p.id()
                || projection.digest() != a.projection_digest()
            {
                return Err(WorkerRuntimeError::Stale);
            }
            let model = OwnedProjectedModel::new(
                self.factory.lazy_with_execution(
                    a.workspace_id(),
                    p.clone(),
                    lumen_integrations::providers::ProviderHttpOptions::default(),
                    g,
                    sink,
                ),
                m.clone(),
                policy,
                projection,
                cancel,
            )?;
            Ok(MaterializedWorker {
                model: Arc::new(model),
                profile_id: m.id().clone(),
                profile_revision: m.revision(),
                profile_concurrency_limit: m.concurrency_limit(),
            })
        })
    }
}
#[derive(Clone)]
pub struct DatabaseCandidateCatalog {
    db: Database,
    grants: Vec<WorkerCapabilityGrant>,
    budget: WorkerRunBudget,
}
impl DatabaseCandidateCatalog {
    pub fn new(db: Database, grants: Vec<WorkerCapabilityGrant>, budget: WorkerRunBudget) -> Self {
        Self { db, grants, budget }
    }
    pub async fn catalog(
        &self,
        w: WorkspaceId,
    ) -> Result<(Vec<ModelProfile>, Vec<ModelDataPolicy>), ControlPlaneError> {
        let ps = self.db.list_latest_model_profiles().await?;
        let mut policies = Vec::new();
        for p in &ps {
            if let Some(v) = self.db.latest_model_data_policy(w, p.id()).await?
                && v.model_profile_revision() == p.revision()
            {
                policies.push(v)
            }
        }
        Ok((ps, policies))
    }
    pub async fn candidates(
        &self,
        g: &TaskGraph,
        n: &TaskNode,
        actor: &PrincipalId,
        now: TimestampMillis,
    ) -> Result<Vec<RoutedWorkerCandidate>, ControlPlaneError> {
        let sources = self.db.gate_sources_for_task(g, n, actor, now).await?;
        let mut out = Vec::new();
        for m in self.db.list_latest_model_profiles().await? {
            let Some(policy) = self
                .db
                .latest_model_data_policy(g.workspace_id(), m.id())
                .await?
            else {
                continue;
            };
            if policy.model_profile_revision() != m.revision() {
                continue;
            }
            let Some(p) = self
                .db
                .provider_config_revision(m.provider_id(), m.provider_revision())
                .await?
            else {
                continue;
            };
            let selection = evaluate_exact_projection(
                g.workspace_id(),
                g.orchestration_id(),
                g.revision(),
                n,
                &m,
                &policy,
                sources.clone(),
                now,
            )
            .map_err(|e| ControlPlaneError::Control(e.to_string()))?;
            let mut evaluation = selection.evaluation;
            if !evaluation.allowed {
                self.db.append_trust_gate_evaluation(&evaluation).await?;
                continue;
            }
            let proj = TaskProjection::build(
                ProjectionId::new(),
                ProjectionTaskKey::parse(n.key().as_str())
                    .map_err(|e| ControlPlaneError::Control(e.to_string()))?,
                &m,
                &policy,
                selection.selected_sources,
                now,
            )
            .map_err(|e| ControlPlaneError::Control(e.to_string()))?;
            self.db.insert_task_projection(&proj).await?;
            evaluation = evaluation
                .bind_projection(proj.id(), proj.digest())
                .map_err(|e| ControlPlaneError::Control(e.to_string()))?;
            self.db.append_trust_gate_evaluation(&evaluation).await?;
            out.push(RoutedWorkerCandidate {
                provider: p,
                profile: m,
                policy,
                projection: proj,
                grants: self.grants.clone(),
                worker_budget: self.budget,
            })
        }
        Ok(out)
    }
}
#[derive(Clone)]
pub struct OrchestrationControl {
    db: Database,
    scheduler: Arc<WorkerScheduler>,
    planner: Arc<dyn PlannerPort>,
    authority: Arc<dyn OperatorAuthorityPort>,
    catalog: DatabaseCandidateCatalog,
    workspace: WorkspaceId,
}
impl OrchestrationControl {
    pub fn new(
        db: Database,
        scheduler: Arc<WorkerScheduler>,
        planner: Arc<dyn PlannerPort>,
        authority: Arc<dyn OperatorAuthorityPort>,
        catalog: DatabaseCandidateCatalog,
        workspace: WorkspaceId,
    ) -> Self {
        Self {
            db,
            scheduler,
            planner,
            authority,
            catalog,
            workspace,
        }
    }
    async fn auth(
        &self,
        w: WorkspaceId,
        a: &PrincipalId,
        op: OperatorOperation,
        id: Option<OrchestrationId>,
    ) -> Result<(), ServiceError> {
        if self
            .authority
            .authorize(&AuthorityRequest {
                workspace_id: w,
                actor: a.clone(),
                operation: op,
                orchestration_id: id,
            })
            .await
            .map_err(|e| ServiceError::Internal(e.to_string()))?
        {
            Ok(())
        } else {
            Err(ServiceError::Conflict("operator authority denied".into()))
        }
    }
    async fn snap(
        &self,
        w: WorkspaceId,
        id: OrchestrationId,
    ) -> Result<lumen_core::orchestration::OrchestrationSnapshot, ServiceError> {
        let s = self
            .db
            .latest_orchestration_snapshot(id)
            .await
            .map_err(map)?
            .ok_or(ServiceError::NotFound)?;
        if s.graph().workspace_id() != w {
            return Err(ServiceError::NotFound);
        }
        Ok(s)
    }
    pub async fn dispatch_workspace_once(
        &self,
        now: TimestampMillis,
        stop: &CancellationToken,
    ) -> Result<DispatchTick, ControlPlaneError> {
        let mut tick = DispatchTick::default();
        for id in self
            .db
            .orchestration_ids_for_workspace(self.workspace)
            .await?
        {
            if stop.is_cancelled() {
                break;
            }
            match self.dispatch_orchestration_once(id, now, stop).await {
                Ok(launched) => tick.launched += launched,
                Err(_) => eprintln!(
                    "event=worker_dispatch_orchestration_failed orchestration_id={id} diagnostic=dispatch_failed"
                ),
            }
        }
        Ok(tick)
    }
    async fn dispatch_orchestration_once(
        &self,
        id: OrchestrationId,
        now: TimestampMillis,
        stop: &CancellationToken,
    ) -> Result<usize, ControlPlaneError> {
        if self.db.orchestration_quarantine(id).await?.is_some()
            || self.db.orchestration_cancelled(id).await?
        {
            return Ok(0);
        }
        self.db.reconcile_task_readiness(id, now).await?;
        let Some(s) = self.db.latest_orchestration_snapshot(id).await? else {
            return Ok(0);
        };
        let Some(budget) = self.db.budget_snapshot(id, now).await? else {
            return Ok(0);
        };
        let control = self
            .db
            .latest_control_policy(id)
            .await?
            .ok_or_else(|| ControlPlaneError::Control("missing control policy".into()))?;
        let ready = s
            .states()
            .filter(|state| state.state() == TaskNodeState::Ready)
            .collect::<Vec<_>>();
        if budget.expired {
            for state in ready {
                if stop.is_cancelled() {
                    break;
                }
                self.db
                    .transition_task_state(
                        id,
                        s.graph().revision(),
                        state.task_node_id(),
                        state.revision(),
                        TaskNodeState::Blocked,
                        now,
                    )
                    .await?;
            }
            return Ok(0);
        }
        let mut launched = 0;
        for state in ready
            .into_iter()
            .take(budget.remaining_concurrency as usize)
        {
            if stop.is_cancelled() {
                break;
            }
            let n = s
                .graph()
                .node(state.task_node_id())
                .ok_or_else(|| ControlPlaneError::Control("task missing".into()))?;
            // Ready may still have a committed reservation while admission runs.
            if self
                .db
                .active_routing_dispatch(id, s.graph().revision(), n.id())
                .await?
                .is_some()
            {
                continue;
            }
            let mut cs = self
                .catalog
                .candidates(s.graph(), n, s.graph().created_by(), now)
                .await?;
            self.scheduler
                .filter_retry_candidates(s.graph(), n, &mut cs)
                .await?;
            if cs.is_empty() {
                self.db
                    .transition_task_state(
                        id,
                        s.graph().revision(),
                        n.id(),
                        state.revision(),
                        TaskNodeState::Blocked,
                        now,
                    )
                    .await?;
                continue;
            }
            let assignment = match self
                .scheduler
                .prepare_routed_assignment(
                    s.graph(),
                    n,
                    s.graph().created_by().clone(),
                    cs,
                    control.reasoning,
                    RoutingPolicy::new(control.remote_allowed, control.prefer_local),
                    now,
                )
                .await
            {
                Ok(assignment) => assignment,
                Err(WorkerRuntimeError::Repository(
                    RepositoryError::RoutingBudgetConflict | RepositoryError::RoutingTaskConflict,
                )) => continue,
                // Health and capacity may recover. Leave these tasks Ready.
                Err(WorkerRuntimeError::Route(
                    lumen_core::routing::RoutingError::NoEligibleModel,
                )) => continue,
                Err(_) => {
                    eprintln!(
                        "event=worker_route_prepare_failed orchestration_id={id} task_node_id={} diagnostic=route_failed",
                        n.id()
                    );
                    continue;
                }
            };
            if stop.is_cancelled() {
                self.db
                    .release_active_routing_for_task(id, s.graph().revision(), n.id(), now)
                    .await?;
                break;
            }
            match self.scheduler.dispatch_prepared(assignment, now).await {
                Ok(_) => launched += 1,
                Err(_) => eprintln!(
                    "event=worker_dispatch_failed orchestration_id={id} task_node_id={} diagnostic=admission_failed",
                    n.id()
                ),
            }
        }
        Ok(launched)
    }
    pub async fn recover(&self, now: TimestampMillis) -> Result<(), ControlPlaneError> {
        // Verify durable bindings before allowing recovered reservations to run.
        for id in self
            .db
            .orchestration_ids_for_workspace(self.workspace)
            .await?
        {
            self.db
                .ensure_recovered_unknown_failure_metadata(id, now)
                .await?;
            let report = self.db.verify_orchestration_integrity(id, now).await?;
            self.db.record_recovery_integrity(&report).await?;
        }
        self.scheduler.recover_once(now).await?;
        for id in self
            .db
            .orchestration_ids_for_workspace(self.workspace)
            .await?
        {
            self.db
                .ensure_recovered_unknown_failure_metadata(id, now)
                .await?;
            let report = self.db.verify_orchestration_integrity(id, now).await?;
            self.db.record_recovery_integrity(&report).await?;
        }
        Ok(())
    }
    async fn view(&self, w: WorkspaceId, id: OrchestrationId) -> Result<Value, ServiceError> {
        let mut v = self
            .db
            .orchestration_view(w, id, clock())
            .await
            .map_err(map)?
            .ok_or(ServiceError::NotFound)?;
        if let Some(o) = v.as_object_mut() {
            o.insert(
                "trust_gate".into(),
                Value::Array(self.db.trust_gate_evaluations(id).await.map_err(map)?),
            );
            o.insert(
                "quarantine".into(),
                self.db
                    .orchestration_quarantine(id)
                    .await
                    .map_err(map)?
                    .unwrap_or(Value::Null),
            );
        }
        Ok(v)
    }
}
impl WorkerDispatchDriver for OrchestrationControl {
    fn stop_dispatches(&self) {
        self.scheduler.stop_accepting();
    }
    fn dispatch_tick<'a>(
        &'a self,
        now: TimestampMillis,
        stop: &'a CancellationToken,
    ) -> WorkerDispatchFuture<'a> {
        Box::pin(async move {
            self.dispatch_workspace_once(now, stop)
                .await
                .map_err(internal)
        })
    }
}
impl OrchestrationService for OrchestrationControl {
    fn create(&self, c: CreateOrchestrationCommand) -> OrchestrationFuture<'_, Value> {
        Box::pin(async move {
            self.auth(c.workspace_id, &c.actor, OperatorOperation::Create, None)
                .await?;
            if c.data_class == DataClass::Secret {
                return Err(ServiceError::Conflict("secret planner input denied".into()));
            }
            let id = OrchestrationId::new();
            let proposal = self
                .planner
                .plan(&c.prompt, c.data_class)
                .await
                .map_err(|e| ServiceError::Conflict(e.to_string()))?;
            let (ps, policies) = self
                .catalog
                .catalog(c.workspace_id)
                .await
                .map_err(|e| ServiceError::Internal(e.to_string()))?;
            let now = clock();
            let g = TaskGraph::from_proposal(
                id,
                c.workspace_id,
                1,
                c.actor.clone(),
                proposal.clone(),
                now,
            )
            .map_err(conflict)?;
            g.validate_against_catalog(&ps, &policies)
                .map_err(conflict)?;
            self.db
                .append_task_graph(&g, &ps, &policies)
                .await
                .map_err(map)?;
            let src = ContextSource::new(
                ContextSourceId::new(),
                c.workspace_id,
                c.data_class,
                c.compartments,
                SourceProvenance::new(
                    SourceProvenanceKind::UserMessage,
                    format!("orchestration:{id}:request"),
                )
                .map_err(conflict)?,
                c.prompt.clone().into(),
                c.actor.clone(),
                now,
            )
            .map_err(conflict)?;
            self.db.append_context_source(&src).await.map_err(map)?;
            self.db
                .link_orchestration_input_source(id, src.id(), now)
                .await
                .map_err(map)?;
            self.db
                .append_orchestration_budget(
                    &OrchestrationBudget::new(
                        id,
                        1,
                        c.max_model_calls,
                        c.max_input_tokens,
                        c.max_output_tokens,
                        c.max_remote_cost_micros,
                        c.max_concurrent_workers,
                        c.max_wall_time_millis,
                        now,
                        now,
                    )
                    .map_err(conflict)?,
                )
                .await
                .map_err(map)?;
            self.db
                .append_control_policy(
                    &OrchestrationControlPolicy::new(
                        id,
                        1,
                        c.remote_allowed,
                        c.prefer_local,
                        c.reasoning,
                        now,
                    )
                    .map_err(conflict)?,
                )
                .await
                .map_err(map)?;
            self.db
                .record_planner_invocation(
                    Uuid::new_v4(),
                    id,
                    c.workspace_id,
                    &ContextDigest::from_bytes(c.prompt.as_bytes()),
                    &proposal,
                    now,
                )
                .await
                .map_err(map)?;
            self.view(c.workspace_id, id).await
        })
    }
    fn list(&self, w: WorkspaceId, a: PrincipalId) -> OrchestrationFuture<'_, Vec<Value>> {
        Box::pin(async move {
            self.auth(w, &a, OperatorOperation::Read, None).await?;
            let mut v = Vec::new();
            for id in self
                .db
                .orchestration_ids_for_workspace(w)
                .await
                .map_err(map)?
            {
                if let Some(x) = self
                    .db
                    .orchestration_view(w, id, clock())
                    .await
                    .map_err(map)?
                {
                    v.push(x)
                }
            }
            Ok(v)
        })
    }
    fn get(
        &self,
        w: WorkspaceId,
        a: PrincipalId,
        id: OrchestrationId,
    ) -> OrchestrationFuture<'_, Value> {
        Box::pin(async move {
            self.auth(w, &a, OperatorOperation::Read, Some(id)).await?;
            self.view(w, id).await
        })
    }
    fn control(&self, c: ControlOrchestrationCommand) -> OrchestrationFuture<'_, Value> {
        Box::pin(async move {
            let op = match &c.action {
                ControlAction::Cancel => OperatorOperation::Cancel,
                ControlAction::Retry { mode, .. } => {
                    if *mode == RetryMode::Reassign {
                        OperatorOperation::Reassign
                    } else {
                        OperatorOperation::Retry
                    }
                }
                ControlAction::Narrow { .. } => OperatorOperation::Narrow,
                ControlAction::Pin { .. } => OperatorOperation::Pin,
            };
            self.auth(c.workspace_id, &c.actor, op, Some(c.orchestration_id))
                .await?;
            let snap = self.snap(c.workspace_id, c.orchestration_id).await?;
            if self
                .db
                .orchestration_quarantine(c.orchestration_id)
                .await
                .map_err(map)?
                .is_some()
                && !matches!(&c.action, ControlAction::Cancel)
            {
                return Err(ServiceError::Conflict(
                    "orchestration is security-quarantined".into(),
                ));
            }
            match c.action {
                ControlAction::Cancel => self
                    .scheduler
                    .cancel_orchestration(c.orchestration_id, &c.actor, clock())
                    .await
                    .map_err(worker)?,
                ControlAction::Retry {
                    task_node_id,
                    prior_attempt_id,
                    mode,
                } => {
                    self.auth(
                        c.workspace_id,
                        &c.actor,
                        if mode == RetryMode::Reassign {
                            OperatorOperation::Reassign
                        } else {
                            OperatorOperation::Retry
                        },
                        Some(c.orchestration_id),
                    )
                    .await?;
                    let n = snap
                        .graph()
                        .node(task_node_id)
                        .cloned()
                        .ok_or(ServiceError::NotFound)?;
                    let mut candidates = self
                        .catalog
                        .candidates(snap.graph(), &n, &c.actor, clock())
                        .await
                        .map_err(internal)?;
                    self.scheduler
                        .authorize_retry(
                            snap.graph(),
                            &n,
                            prior_attempt_id,
                            c.actor.clone(),
                            &mut candidates,
                            mode,
                            clock(),
                        )
                        .await
                        .map_err(worker)?;
                }
                ControlAction::Pin {
                    task_node_id,
                    profiles,
                } => {
                    let prop = snap
                        .graph()
                        .proposal_with_profile_pin(task_node_id, profiles)
                        .map_err(conflict)?;
                    let (ps, policies) = self
                        .catalog
                        .catalog(c.workspace_id)
                        .await
                        .map_err(internal)?;
                    let g = TaskGraph::from_proposal(
                        c.orchestration_id,
                        c.workspace_id,
                        snap.graph().revision() + 1,
                        c.actor.clone(),
                        prop,
                        clock(),
                    )
                    .map_err(conflict)?;
                    g.validate_against_catalog(&ps, &policies)
                        .map_err(conflict)?;
                    self.db
                        .append_task_graph(&g, &ps, &policies)
                        .await
                        .map_err(map)?;
                }
                ControlAction::Narrow {
                    remote_allowed,
                    max_model_calls,
                    max_input_tokens,
                    max_output_tokens,
                    max_remote_cost_micros,
                    max_concurrent_workers,
                    max_wall_time_millis,
                } => {
                    let now = clock();
                    let p = self
                        .db
                        .latest_control_policy(c.orchestration_id)
                        .await
                        .map_err(map)?
                        .ok_or(ServiceError::NotFound)?;
                    self.db
                        .append_control_policy(
                            &OrchestrationControlPolicy::new(
                                c.orchestration_id,
                                p.revision + 1,
                                remote_allowed.unwrap_or(p.remote_allowed),
                                p.prefer_local,
                                p.reasoning,
                                now,
                            )
                            .map_err(conflict)?,
                        )
                        .await
                        .map_err(map)?;
                    let b = self
                        .db
                        .budget_snapshot(c.orchestration_id, now)
                        .await
                        .map_err(map)?
                        .ok_or(ServiceError::NotFound)?
                        .budget;
                    self.db
                        .append_orchestration_budget(
                            &OrchestrationBudget::new(
                                c.orchestration_id,
                                b.revision + 1,
                                max_model_calls.unwrap_or(b.max_model_calls),
                                max_input_tokens.unwrap_or(b.max_input_tokens),
                                max_output_tokens.unwrap_or(b.max_output_tokens),
                                max_remote_cost_micros.unwrap_or(b.max_remote_cost_micros),
                                max_concurrent_workers.unwrap_or(b.max_concurrent_workers),
                                max_wall_time_millis.unwrap_or(b.max_wall_time_millis),
                                b.window_started_at,
                                now,
                            )
                            .map_err(conflict)?,
                        )
                        .await
                        .map_err(map)?
                }
            }
            self.view(c.workspace_id, c.orchestration_id).await
        })
    }
    fn events(
        &self,
        w: WorkspaceId,
        a: PrincipalId,
        id: OrchestrationId,
        after: u64,
        limit: u16,
    ) -> OrchestrationFuture<'_, Vec<OrchestrationEvent>> {
        Box::pin(async move {
            self.auth(w, &a, OperatorOperation::Read, Some(id)).await?;
            Ok(self
                .db
                .control_events(w, id, after, limit)
                .await
                .map_err(map)?
                .into_iter()
                .map(event)
                .collect())
        })
    }
    fn providers(&self, w: WorkspaceId, a: PrincipalId) -> OrchestrationFuture<'_, Vec<Value>> {
        Box::pin(async move {
            self.auth(w, &a, OperatorOperation::Read, None).await?;
            let mut v = Vec::new();
            for p in self.db.list_latest_provider_configs().await.map_err(map)? {
                v.push(json!({"provider_id":p.id().as_str(),"revision":p.revision(),"kind":p.kind().as_str(),"endpoint_class":format!("{:?}",p.endpoint_class()).to_lowercase(),"endpoint":p.endpoint().as_str(),"enabled":p.enabled()}))
            }
            Ok(v)
        })
    }
    fn models(&self, w: WorkspaceId, a: PrincipalId) -> OrchestrationFuture<'_, Vec<Value>> {
        Box::pin(async move {
            self.auth(w, &a, OperatorOperation::Read, None).await?;
            let mut v = Vec::new();
            for m in self.db.list_latest_model_profiles().await.map_err(map)? {
                v.push(json!({"profile_id":m.id().as_str(),"revision":m.revision(),"provider_id":m.provider_id().as_str(),"model_name":m.model_name(),"enabled":m.enabled(),"context_window_tokens":m.context_window_tokens(),"trust_zone":m.trust_zone().as_str(),"concurrency_limit":m.concurrency_limit(),"priority":m.priority(),"routing_metadata":self.db.latest_model_routing_metadata(m.id(),m.revision()).await.map_err(map)?}))
            }
            Ok(v)
        })
    }
    fn artifacts(
        &self,
        w: WorkspaceId,
        a: PrincipalId,
        id: OrchestrationId,
    ) -> OrchestrationFuture<'_, Vec<Value>> {
        Box::pin(async move {
            self.auth(w, &a, OperatorOperation::Read, Some(id)).await?;
            let v = self.view(w, id).await?;
            Ok(v.get("artifacts")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default())
        })
    }
}
fn event(v: ControlEvent) -> OrchestrationEvent {
    OrchestrationEvent {
        sequence: v.sequence,
        kind: v.kind,
        payload: v.payload,
        created_at: v.created_at.as_u64(),
    }
}
fn map(e: RepositoryError) -> ServiceError {
    ServiceError::Internal(e.to_string())
}
fn worker(e: WorkerRuntimeError) -> ServiceError {
    ServiceError::Conflict(e.to_string())
}
fn conflict(e: impl std::fmt::Display) -> ServiceError {
    ServiceError::Conflict(e.to_string())
}
fn internal(e: impl std::fmt::Display) -> ServiceError {
    ServiceError::Internal(e.to_string())
}
fn clock() -> TimestampMillis {
    use std::time::{SystemTime, UNIX_EPOCH};
    TimestampMillis::new(
        u64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
        )
        .unwrap_or(u64::MAX),
    )
}
#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneError {
    #[error(transparent)]
    Repository(#[from] RepositoryError),
    #[error(transparent)]
    Worker(#[from] WorkerRuntimeError),
    #[error("planner: {0}")]
    Planner(String),
    #[error("control: {0}")]
    Control(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn planner_prompt_names_the_strict_graph_schema() {
        let prompt = task_graph_planner_prompt("build a plan");
        assert!(prompt.contains(r#"{"nodes":[...]}"#));
        assert!(prompt.contains("at most 256 nodes"));
        assert!(!prompt.contains("tasks"));
        assert!(serde_json::from_str::<TaskGraphProposal>(r#"{"tasks":[]}"#).is_err());
        assert!(serde_json::from_str::<TaskGraphProposal>(r#"{"nodes":[],"extra":0}"#).is_err());
        assert!(serde_json::from_str::<TaskGraphProposal>(r#"{"nodes":[]}"#).is_ok());
    }
    #[tokio::test]
    async fn bootstrap_authority_is_workspace_and_principal_exact() {
        let principal = PrincipalId::new("local", "owner").unwrap();
        let workspace = WorkspaceId::new();
        let authority = BootstrapOperatorAuthority::new(principal.clone(), workspace);
        assert!(
            authority
                .authorize(&AuthorityRequest {
                    workspace_id: workspace,
                    actor: principal,
                    operation: OperatorOperation::Create,
                    orchestration_id: None
                })
                .await
                .unwrap()
        );
        assert!(
            !authority
                .authorize(&AuthorityRequest {
                    workspace_id: WorkspaceId::new(),
                    actor: PrincipalId::new("local", "owner").unwrap(),
                    operation: OperatorOperation::Read,
                    orchestration_id: None
                })
                .await
                .unwrap()
        );
    }
}
