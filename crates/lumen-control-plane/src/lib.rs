use lumen_core::{
    approval::TimestampMillis,
    artifact::{MAX_ARTIFACT_PREVIEW_BYTES, RetryMode},
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
    provider::{ModelProfile, ProviderAdapter, ProviderConfig, ProviderKind},
    routing::{OrchestrationBudget, RoutingPolicy},
    worker::{OwnedProjectedModel, WorkerAssignment, WorkerCapabilityGrant, WorkerRunBudget},
};
use lumen_db::{ControlEvent, Database, RepositoryError};
use lumen_integrations::{
    providers::{
        anthropic::AnthropicAdapter, openai::OpenAiAdapter,
        openai_compatible::LocalOpenAiCompatibleAdapter,
    },
    secrets::SecretStore,
};
use lumen_server::{
    ControlAction, ControlOrchestrationCommand, CreateOrchestrationCommand, OrchestrationEvent,
    OrchestrationFuture, OrchestrationService, ServiceError,
};
use lumen_worker_runtime::{
    MaterializeFuture, MaterializedWorker, RoutedWorkerCandidate, WorkerMaterializer,
    WorkerRuntimeError, WorkerScheduler,
};
use serde_json::{Value, json};
use std::{collections::BTreeSet, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Mutex;
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
impl PlannerPort for JsonModelPlanner {
    fn plan<'a>(&'a self, prompt: &'a str, class: DataClass) -> PlannerFuture<'a> {
        Box::pin(async move {
            if prompt.is_empty() || prompt.len() > 65536 {
                return Err(ControlPlaneError::Planner("invalid prompt".into()));
            }
            let q = format!(
                "Return ONLY TaskGraphProposal JSON, no markdown/tools. <=256 tasks; include key,description,expected_output,depends_on,requirements,limits,deadline_at. Request: {prompt}"
            );
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
    secrets: Arc<dyn SecretStore>,
}
impl DatabaseWorkerMaterializer {
    pub fn new(db: Database, secrets: Arc<dyn SecretStore>) -> Self {
        Self { db, secrets }
    }
    async fn adapter(
        &self,
        a: &WorkerAssignment,
        p: &ProviderConfig,
    ) -> Result<Arc<dyn ProviderAdapter>, WorkerRuntimeError> {
        let key = if let Some(id) = p.credential_secret_ref() {
            let r = self
                .db
                .get_secret_reference(a.workspace_id(), id)
                .await?
                .ok_or(WorkerRuntimeError::Stale)?;
            Some(
                String::from_utf8(
                    self.secrets
                        .resolve(r.keychain_account())
                        .await
                        .map_err(|e| WorkerRuntimeError::Configuration(e.to_string()))?,
                )
                .map_err(|_| WorkerRuntimeError::Configuration("credential encoding".into()))?,
            )
        } else {
            None
        };
        Ok(match p.kind() {
            ProviderKind::OpenAi => Arc::new(
                OpenAiAdapter::new(
                    p.clone(),
                    key.ok_or_else(|| {
                        WorkerRuntimeError::Configuration("OpenAI credential missing".into())
                    })?,
                )
                .map_err(|e| WorkerRuntimeError::Configuration(e.to_string()))?,
            ),
            ProviderKind::Anthropic => Arc::new(
                AnthropicAdapter::new(
                    p.clone(),
                    key.ok_or_else(|| {
                        WorkerRuntimeError::Configuration("Anthropic credential missing".into())
                    })?,
                )
                .map_err(|e| WorkerRuntimeError::Configuration(e.to_string()))?,
            ),
            ProviderKind::OpenAiCompatible => Arc::new(
                LocalOpenAiCompatibleAdapter::new(p.clone(), key)
                    .map_err(|e| WorkerRuntimeError::Configuration(e.to_string()))?,
            ),
        })
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
                self.adapter(a, &p).await?,
                m.clone(),
                policy,
                projection,
                cancel,
            )?;
            let _ = (g, sink); // Routing metadata is enforced before materialization.
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
        let mut sources = self
            .db
            .orchestration_input_sources(g.orchestration_id())
            .await?;
        for (child, dep) in g.dependency_edges() {
            if child == n.id() {
                for id in self
                    .db
                    .handoff_artifact_ids(g.orchestration_id(), g.revision(), dep)
                    .await?
                {
                    if let Some(r) = self
                        .db
                        .artifact_reference_for_handoff(id, MAX_ARTIFACT_PREVIEW_BYTES)
                        .await?
                    {
                        let s = r
                            .to_context_source(
                                ContextSourceId::new(),
                                g.workspace_id(),
                                actor.clone(),
                                now,
                            )
                            .map_err(|e| ControlPlaneError::Control(e.to_string()))?;
                        self.db.append_context_source(&s).await?;
                        sources.push(s)
                    }
                }
            }
        }
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
            let Ok(proj) = TaskProjection::build(
                ProjectionId::new(),
                ProjectionTaskKey::parse(n.key().as_str())
                    .map_err(|e| ControlPlaneError::Control(e.to_string()))?,
                &m,
                &policy,
                sources.clone(),
                now,
            ) else {
                continue;
            };
            self.db.insert_task_projection(&proj).await?;
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
    drivers: Arc<Mutex<BTreeSet<OrchestrationId>>>,
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
            drivers: Arc::new(Mutex::new(BTreeSet::new())),
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
    fn kick(&self, id: OrchestrationId) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut d = this.drivers.lock().await;
            if !d.insert(id) {
                return;
            }
            drop(d);
            let _ = this.drive(id).await;
            this.drivers.lock().await.remove(&id);
        });
    }
    async fn drive(&self, id: OrchestrationId) -> Result<(), ControlPlaneError> {
        loop {
            let now = clock();
            self.db.reconcile_task_readiness(id, now).await?;
            let Some(s) = self.db.latest_orchestration_snapshot(id).await? else {
                return Ok(());
            };
            if self.db.orchestration_cancelled(id).await? {
                return Ok(());
            }
            let states = s.states().map(|x| x.state()).collect::<Vec<_>>();
            if states.iter().all(|x| {
                matches!(
                    x,
                    TaskNodeState::Completed
                        | TaskNodeState::Failed
                        | TaskNodeState::Cancelled
                        | TaskNodeState::Unknown
                        | TaskNodeState::Blocked
                )
            }) {
                return Ok(());
            }
            let control = self
                .db
                .latest_control_policy(id)
                .await?
                .ok_or_else(|| ControlPlaneError::Control("missing control policy".into()))?;
            let ready = s
                .states()
                .filter(|x| x.state() == TaskNodeState::Ready)
                .map(|x| x.task_node_id())
                .collect::<Vec<_>>();
            if ready.is_empty() {
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
            let mut jobs = tokio::task::JoinSet::new();
            for tid in ready {
                let n = s
                    .graph()
                    .node(tid)
                    .cloned()
                    .ok_or_else(|| ControlPlaneError::Control("task missing".into()))?;
                let cs = self
                    .catalog
                    .candidates(s.graph(), &n, s.graph().created_by(), now)
                    .await?;
                let scheduler = Arc::clone(&self.scheduler);
                let g = s.graph().clone();
                let actor = s.graph().created_by().clone();
                jobs.spawn(async move {
                    scheduler
                        .route_and_dispatch(
                            &g,
                            &n,
                            actor,
                            cs,
                            control.reasoning,
                            RoutingPolicy::new(control.remote_allowed, control.prefer_local),
                            now,
                        )
                        .await
                });
            }
            while let Some(v) = jobs.join_next().await {
                let _ = v
                    .map_err(|e| ControlPlaneError::Control(e.to_string()))?
                    .map_err(|e| ControlPlaneError::Control(e.to_string()))?;
            }
        }
    }
    pub async fn recover(&self, now: TimestampMillis) -> Result<(), ControlPlaneError> {
        let _ = self.scheduler.recover_once(now).await?;
        for id in self
            .db
            .orchestration_ids_for_workspace(self.workspace)
            .await?
        {
            if let Some(s) = self.db.latest_orchestration_snapshot(id).await?
                && s.states().any(|x| {
                    !matches!(
                        x.state(),
                        TaskNodeState::Completed
                            | TaskNodeState::Failed
                            | TaskNodeState::Cancelled
                            | TaskNodeState::Unknown
                            | TaskNodeState::Blocked
                    )
                })
            {
                self.kick(id)
            }
        }
        Ok(())
    }
    async fn view(&self, w: WorkspaceId, id: OrchestrationId) -> Result<Value, ServiceError> {
        self.db
            .orchestration_view(w, id, clock())
            .await
            .map_err(map)?
            .ok_or(ServiceError::NotFound)
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
            self.kick(id);
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
                    let p = self
                        .db
                        .latest_control_policy(c.orchestration_id)
                        .await
                        .map_err(map)?
                        .ok_or(ServiceError::NotFound)?;
                    let cs = self
                        .catalog
                        .candidates(snap.graph(), &n, &c.actor, clock())
                        .await
                        .map_err(internal)?;
                    self.scheduler
                        .retry_task(
                            snap.graph(),
                            &n,
                            prior_attempt_id,
                            c.actor.clone(),
                            cs,
                            p.reasoning,
                            RoutingPolicy::new(p.remote_allowed, p.prefer_local),
                            mode,
                            clock(),
                        )
                        .await
                        .map_err(worker)?;
                    self.kick(c.orchestration_id)
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
                    self.kick(c.orchestration_id)
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
