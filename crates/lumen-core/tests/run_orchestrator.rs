use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    approval::{ApprovalError, ApprovalId, ApprovalRequest, DispatchError, TimestampMillis},
    audit::{AuditEvent, AuditEventKind},
    capability::{
        Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope,
        WorkspacePath,
    },
    egress::DataClass,
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorFuture, ExecutorPort},
    extension::{
        AttributedActionProposal, ExtensionProvenance, PluginComponentId, PluginId, PluginRuntime,
        PluginVersion, ProtocolVersion, Sha256Digest,
    },
    identity::{ComponentId, PrincipalId, WorkspaceId},
    model::{
        ActionProposal, ModelError, ModelFuture, ModelInput, ModelOutput, ModelPort, ModelRole,
        ModelTool, ModelToolCall,
    },
    policy::{DenialReason, Policy, PolicyVersion},
    run::{
        ActionFuture, ActionNormalizer, ActionPort, ApprovalFuture, ApprovalPort,
        ApprovalResolution, AuditFuture, AuditPort, AuditPortError, BudgetKind, Clock,
        NormalizationError, RunBudget, RunContext, RunError, RunOrchestrator, RunOutcome, RunState,
    },
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const NOW: TimestampMillis = TimestampMillis::new(10_000);

struct FixedClock;

static CLOCK: FixedClock = FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> TimestampMillis {
        NOW
    }
}

struct TestClock(AtomicU64);

impl TestClock {
    fn new(now: u64) -> Self {
        Self(AtomicU64::new(now))
    }

    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> TimestampMillis {
        TimestampMillis::new(self.0.load(Ordering::SeqCst))
    }
}

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(
        Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("valid UUID"),
    )
}

fn run_context() -> RunContext {
    RunContext::new(
        RunId::from_uuid(
            Uuid::parse_str("f553a2c1-ee86-4c66-af7f-8e913a08ff17").expect("valid UUID"),
        ),
        workspace_id(),
        PrincipalId::new("local", "riley").expect("valid principal"),
    )
}

fn policy_version() -> PolicyVersion {
    PolicyVersion::new("policy-v1").expect("valid policy version")
}

fn capabilities(name: CapabilityName) -> EffectiveCapabilities {
    EffectiveCapabilities::new([CapabilitySet::new([Capability::new(
        name,
        ResourceScope::workspace(workspace_id()),
    )])])
}

fn proposal(kind: &str) -> ModelOutput {
    ModelOutput::Action(ActionProposal::new(
        kind,
        CanonicalValue::object([("path", CanonicalValue::from("notes/today.md"))]),
    ))
}

struct FakeModel {
    outputs: Mutex<VecDeque<Result<ModelOutput, ModelError>>>,
    inputs: Mutex<Vec<ModelInput>>,
    calls: AtomicUsize,
}

impl FakeModel {
    fn new(outputs: impl IntoIterator<Item = ModelOutput>) -> Self {
        Self {
            outputs: Mutex::new(outputs.into_iter().map(Ok).collect()),
            inputs: Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn inputs(&self) -> Vec<ModelInput> {
        self.inputs.lock().expect("model input lock").clone()
    }
}

impl ModelPort for FakeModel {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inputs.lock().expect("model input lock").push(input);
        Box::pin(async move {
            self.outputs
                .lock()
                .expect("model queue lock")
                .pop_front()
                .unwrap_or_else(|| Err(ModelError::new("no fake model output")))
        })
    }
}

struct ClockedModel {
    inner: FakeModel,
    clock: Arc<TestClock>,
    completion_times: Mutex<VecDeque<u64>>,
}

impl ClockedModel {
    fn new(
        outputs: impl IntoIterator<Item = ModelOutput>,
        clock: Arc<TestClock>,
        completion_times: impl IntoIterator<Item = u64>,
    ) -> Self {
        Self {
            inner: FakeModel::new(outputs),
            clock,
            completion_times: Mutex::new(completion_times.into_iter().collect()),
        }
    }
}

impl ModelPort for ClockedModel {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        let generation = self.inner.generate(input);
        Box::pin(async move {
            let output = generation.await;
            let timestamp = self
                .completion_times
                .lock()
                .expect("model completion times lock")
                .pop_front()
                .expect("model completion time");
            self.clock.set(timestamp);
            output
        })
    }
}

struct FakeNormalizer;

static NORMALIZER: FakeNormalizer = FakeNormalizer;

impl ActionNormalizer for FakeNormalizer {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError> {
        let (kind, capability) = match proposal.kind() {
            "filesystem.read" => ("filesystem.read", CapabilityName::FsRead),
            "filesystem.write" => ("filesystem.write", CapabilityName::FsWrite),
            value => return Err(NormalizationError::new(format!("unknown action: {value}"))),
        };
        Ok(ActionEnvelope::new(
            ActionId::new(),
            context.run_id(),
            context.workspace_id(),
            context.actor().clone(),
            ComponentId::new("builtin.filesystem").expect("valid component"),
            ActionKind::new(kind).expect("valid action kind"),
            proposal.into_arguments(),
            vec![Capability::new(
                capability,
                ResourceScope::path(
                    context.workspace_id(),
                    WorkspacePath::parse("notes/today.md").expect("valid path"),
                ),
            )],
        ))
    }

    fn model_tools(&self, _context: &RunContext) -> Vec<ModelTool> {
        [
            ("filesystem_read", "filesystem.read"),
            ("filesystem_write", "filesystem.write"),
        ]
        .into_iter()
        .map(|(name, kind)| {
            ModelTool::new(
                name,
                "Workspace file operation.",
                kind,
                CanonicalValue::object([("type", CanonicalValue::from("object"))]),
            )
        })
        .collect()
    }
}

struct FakeExecutor {
    outcomes: Mutex<VecDeque<Result<ExecutionOutcome, ExecutorError>>>,
    calls: AtomicUsize,
}

impl FakeExecutor {
    fn succeeding() -> Self {
        Self::new([Ok(ExecutionOutcome::Succeeded(CanonicalValue::from(
            "written",
        )))])
    }

    fn new(outcomes: impl IntoIterator<Item = Result<ExecutionOutcome, ExecutorError>>) -> Self {
        Self {
            outcomes: Mutex::new(outcomes.into_iter().collect()),
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExecutorPort for FakeExecutor {
    fn execute(
        &self,
        _action: &AuthorizedAction,
        _cancellation: CancellationToken,
    ) -> ExecutorFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.outcomes
                .lock()
                .expect("executor queue lock")
                .pop_front()
                .unwrap_or_else(|| Err(ExecutorError::new("no fake executor output")))
        })
    }
}

struct ClockedExecutor {
    inner: FakeExecutor,
    clock: Arc<TestClock>,
    completion_time: u64,
}

struct UnresponsiveExecutor {
    calls: AtomicUsize,
    cancellation: Mutex<Option<CancellationToken>>,
}

impl ExecutorPort for UnresponsiveExecutor {
    fn execute(
        &self,
        _action: &AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.cancellation.lock().expect("cancellation lock") = Some(cancellation);
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn unresponsive_execution_is_bounded_and_never_reported_as_known_failure() {
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = UnresponsiveExecutor {
        calls: AtomicUsize::new(0),
        cancellation: Mutex::new(None),
    };
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(
        run_context(),
        "read",
        RunBudget::limited(3, 2, Duration::from_millis(10), 1024),
    );
    let outcome = tokio::time::timeout(
        Duration::from_secs(1),
        orchestrator(&model, &executor, &approvals, &audit)
            .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead)),
    )
    .await
    .expect("bounded resolution")
    .expect("run outcome");
    assert!(matches!(outcome, RunOutcome::ExecutionUnknown { .. }));
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert!(
        executor
            .cancellation
            .lock()
            .expect("cancellation lock")
            .as_ref()
            .expect("token")
            .is_cancelled()
    );
    assert!(audit.events().contains(&AuditEventKind::ExecutionUnknown));
}

#[tokio::test]
async fn cancellation_precedes_a_required_skill_failure() {
    let model = FakeModel::new([ModelOutput::FinalText("unused".into())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let context =
        run_context().with_skill_loads(vec![lumen_core::run::SkillLoadMetadata::excluded(
            "required-skill",
            "1",
            "expected-digest",
            "source_unavailable",
            true,
        )]);
    let mut state = RunState::new(context, "cancelled", RunBudget::unlimited(3, 2));
    state.cancel();
    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("cancellation outcome");
    assert_eq!(outcome, RunOutcome::Cancelled);
    assert_eq!(model.call_count(), 0);
    assert!(audit.events().contains(&AuditEventKind::RunCancelled));
    assert!(!audit.events().contains(&AuditEventKind::RunFailed));
}

impl ExecutorPort for ClockedExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        let execution = self.inner.execute(action, cancellation);
        Box::pin(async move {
            let outcome = execution.await;
            self.clock.set(self.completion_time);
            outcome
        })
    }
}

enum ApprovalBehavior {
    PendingThenGrant { id: ApprovalId, calls: AtomicUsize },
    AlwaysPending(ApprovalId),
}

struct FakeApprovals(ApprovalBehavior);

impl FakeApprovals {
    fn pending_then_grant() -> Self {
        Self(ApprovalBehavior::PendingThenGrant {
            id: ApprovalId::new(),
            calls: AtomicUsize::new(0),
        })
    }

    fn always_pending() -> Self {
        Self(ApprovalBehavior::AlwaysPending(ApprovalId::new()))
    }
}

impl ApprovalPort for FakeApprovals {
    fn resolve<'a>(
        &'a self,
        action: &'a ActionEnvelope,
        version: &'a PolicyVersion,
        _now: TimestampMillis,
    ) -> ApprovalFuture<'a> {
        Box::pin(async move {
            match &self.0 {
                ApprovalBehavior::AlwaysPending(id) => Ok(ApprovalResolution::Pending(*id)),
                ApprovalBehavior::PendingThenGrant { id, calls } => {
                    if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                        return Ok(ApprovalResolution::Pending(*id));
                    }
                    let mut request = ApprovalRequest::new(
                        *id,
                        action.fingerprint(),
                        version.clone(),
                        TimestampMillis::new(9_000),
                        TimestampMillis::new(11_000),
                    )
                    .expect("valid approval");
                    request
                        .grant(
                            PrincipalId::new("local", "admin").expect("valid approver"),
                            TimestampMillis::new(9_500),
                        )
                        .expect("approval grants");
                    Ok(ApprovalResolution::Granted(request))
                }
            }
        })
    }
}

struct ExpiringApprovals {
    clock: Arc<TestClock>,
}

impl ApprovalPort for ExpiringApprovals {
    fn resolve<'a>(
        &'a self,
        action: &'a ActionEnvelope,
        version: &'a PolicyVersion,
        now: TimestampMillis,
    ) -> ApprovalFuture<'a> {
        Box::pin(async move {
            let mut request = ApprovalRequest::new(
                ApprovalId::new(),
                action.fingerprint(),
                version.clone(),
                TimestampMillis::new(9_000),
                TimestampMillis::new(11_000),
            )
            .expect("valid approval");
            request
                .grant(
                    PrincipalId::new("local", "admin").expect("valid approver"),
                    now,
                )
                .expect("approval grants");
            self.clock.set(11_000);
            Ok(ApprovalResolution::Granted(request))
        })
    }
}

#[derive(Default)]
struct FakeAudit {
    events: Mutex<Vec<AuditEvent>>,
    fail_on: Mutex<Option<AuditEventKind>>,
}

impl FakeAudit {
    fn failing_on(kind: AuditEventKind) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            fail_on: Mutex::new(Some(kind)),
        }
    }

    fn events(&self) -> Vec<AuditEventKind> {
        self.events
            .lock()
            .expect("audit events lock")
            .iter()
            .map(AuditEvent::kind)
            .collect()
    }

    fn payload(&self, kind: AuditEventKind) -> CanonicalValue {
        self.events
            .lock()
            .expect("audit events lock")
            .iter()
            .find(|event| event.kind() == kind)
            .expect("audit event")
            .payload()
            .clone()
    }

    fn recorded(&self) -> Vec<(AuditEventKind, TimestampMillis)> {
        self.events
            .lock()
            .expect("audit events lock")
            .iter()
            .map(|event| (event.kind(), event.timestamp()))
            .collect()
    }
}

impl AuditPort for FakeAudit {
    fn record(&self, event: AuditEvent) -> AuditFuture<'_> {
        Box::pin(async move {
            if self.fail_on.lock().expect("audit failure lock").as_ref() == Some(&event.kind()) {
                return Err(AuditPortError::new("audit unavailable"));
            }
            self.events.lock().expect("audit events lock").push(event);
            Ok(())
        })
    }
}

struct NoopActions;

static ACTIONS: NoopActions = NoopActions;

impl ActionPort for NoopActions {
    fn persist<'a>(
        &'a self,
        _action: &'a ActionEnvelope,
        _now: TimestampMillis,
    ) -> ActionFuture<'a> {
        Box::pin(async { Ok(()) })
    }

    fn deny<'a>(
        &'a self,
        _action: &'a ActionEnvelope,
        _reason: &'a lumen_core::policy::DenialReason,
        _now: TimestampMillis,
    ) -> ActionFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
struct CountingActions(AtomicUsize);

impl ActionPort for CountingActions {
    fn persist<'a>(
        &'a self,
        _action: &'a ActionEnvelope,
        _now: TimestampMillis,
    ) -> ActionFuture<'a> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(()) })
    }

    fn deny<'a>(
        &'a self,
        _action: &'a ActionEnvelope,
        _reason: &'a lumen_core::policy::DenialReason,
        _now: TimestampMillis,
    ) -> ActionFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

#[derive(Default)]
struct RecordingActions(Mutex<Vec<ActionEnvelope>>);

impl ActionPort for RecordingActions {
    fn persist<'a>(
        &'a self,
        action: &'a ActionEnvelope,
        _now: TimestampMillis,
    ) -> ActionFuture<'a> {
        self.0
            .lock()
            .expect("recorded actions lock")
            .push(action.clone());
        Box::pin(async { Ok(()) })
    }

    fn deny<'a>(
        &'a self,
        _action: &'a ActionEnvelope,
        _reason: &'a lumen_core::policy::DenialReason,
        _now: TimestampMillis,
    ) -> ActionFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::parse(byte.to_string().repeat(64)).expect("digest")
}

fn child_provenance(parent: ActionId) -> ExtensionProvenance {
    ExtensionProvenance::new(
        PluginId::parse("dev.example.fixture").expect("plugin"),
        PluginVersion::parse("1.0.0").expect("version"),
        PluginComponentId::parse("writer").expect("component"),
        PluginRuntime::WasmComponent,
        digest('1'),
        digest('2'),
        digest('3'),
        digest('4'),
        digest('5'),
        ProtocolVersion::new(1).expect("protocol"),
        Some(parent),
    )
}

#[tokio::test]
async fn extension_proposal_reenters_action_budget_policy_approval_and_audit() {
    let parent = ActionId::new();
    let child = AttributedActionProposal::new(
        ActionProposal::new(
            "filesystem.write",
            CanonicalValue::object([("path", CanonicalValue::from("notes/today.md"))]),
        ),
        child_provenance(parent),
        vec![ActionKind::new("filesystem.write").expect("kind")],
        vec![Capability::new(
            CapabilityName::FsWrite,
            ResourceScope::path(
                workspace_id(),
                WorkspacePath::parse("notes/today.md").expect("path"),
            ),
        )],
    )
    .expect("attributed proposal");
    let model = FakeModel::new([
        proposal("filesystem.read"),
        ModelOutput::FinalText("done".into()),
    ]);
    let executor = FakeExecutor::new([
        Ok(ExecutionOutcome::Proposed(Box::new(child))),
        Ok(ExecutionOutcome::Succeeded(CanonicalValue::from("written"))),
    ]);
    let approvals = FakeApprovals::pending_then_grant();
    let audit = FakeAudit::default();
    let actions = RecordingActions::default();
    let mut state = RunState::new(run_context(), "invoke", RunBudget::unlimited(3, 2));
    let capabilities = EffectiveCapabilities::new([CapabilitySet::new([
        Capability::new(
            CapabilityName::FsRead,
            ResourceScope::workspace(workspace_id()),
        ),
        Capability::new(
            CapabilityName::FsWrite,
            ResourceScope::workspace(workspace_id()),
        ),
    ])]);
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &actions,
        &CLOCK,
        Policy::default(),
        policy_version(),
    );

    assert!(matches!(
        orchestrator
            .run_until_blocked(&mut state, &capabilities)
            .await
            .expect("first advance"),
        RunOutcome::AwaitingApproval { .. }
    ));
    assert_eq!(executor.call_count(), 1);
    let outcome = orchestrator
        .run_until_blocked(&mut state, &capabilities)
        .await
        .expect("second advance");
    assert_eq!(
        outcome,
        RunOutcome::Completed {
            text: "done".into()
        }
    );
    assert_eq!(executor.call_count(), 2);
    assert_eq!(model.call_count(), 2);
    let actions = actions.0.lock().expect("actions lock");
    assert_eq!(actions.len(), 2);
    let child = &actions[1];
    assert_eq!(child.kind().as_str(), "filesystem.write");
    assert_eq!(child.requesting_component().as_str(), "runtime.extensions");
    assert_eq!(
        child
            .extension_provenance()
            .expect("child provenance")
            .parent_action_id(),
        Some(parent)
    );
    assert!(audit.events().contains(&AuditEventKind::ApprovalCreated));
    assert!(audit.events().contains(&AuditEventKind::ApprovalConsumed));
}

#[test]
fn extension_proposal_rejects_undeclared_action_kind() {
    let result = AttributedActionProposal::new(
        ActionProposal::new(
            "filesystem.write",
            CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        ),
        child_provenance(ActionId::new()),
        vec![ActionKind::new("filesystem.read").expect("kind")],
        Vec::new(),
    );
    assert_eq!(
        result.expect_err("undeclared proposal must fail"),
        lumen_core::extension::InvocationContractError::UndeclaredActionKind
    );
}

#[tokio::test]
async fn extension_child_broader_than_effective_grants_is_persisted_but_not_executed() {
    let child = AttributedActionProposal::new(
        ActionProposal::new(
            "filesystem.write",
            CanonicalValue::object([("path", CanonicalValue::from("notes/today.md"))]),
        ),
        child_provenance(ActionId::new()),
        vec![ActionKind::new("filesystem.write").expect("kind")],
        vec![Capability::new(
            CapabilityName::FsRead,
            ResourceScope::workspace(workspace_id()),
        )],
    )
    .expect("attributed proposal");
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = FakeExecutor::new([Ok(ExecutionOutcome::Proposed(Box::new(child)))]);
    let approvals = FakeApprovals::pending_then_grant();
    let audit = FakeAudit::default();
    let actions = RecordingActions::default();
    let mut state = RunState::new(run_context(), "invoke", RunBudget::unlimited(2, 2));
    let capabilities = EffectiveCapabilities::new([CapabilitySet::new([
        Capability::new(
            CapabilityName::FsRead,
            ResourceScope::workspace(workspace_id()),
        ),
        Capability::new(
            CapabilityName::FsWrite,
            ResourceScope::workspace(workspace_id()),
        ),
    ])]);
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &actions,
        &CLOCK,
        Policy::default(),
        policy_version(),
    );

    let outcome = orchestrator
        .run_until_blocked(&mut state, &capabilities)
        .await
        .expect("run outcome");
    assert!(matches!(
        outcome,
        RunOutcome::Denied {
            reason: DenialReason::MissingCapability(_)
        }
    ));
    assert_eq!(executor.call_count(), 1);
    let actions = actions.0.lock().expect("actions lock");
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[1].kind().as_str(), "filesystem.write");
    assert!(audit.events().contains(&AuditEventKind::PolicyDenied));
}

fn orchestrator<'a>(
    model: &'a dyn ModelPort,
    executor: &'a dyn ExecutorPort,
    approvals: &'a dyn ApprovalPort,
    audit: &'a dyn AuditPort,
) -> RunOrchestrator<'a> {
    RunOrchestrator::new(
        model,
        &NORMALIZER,
        executor,
        approvals,
        audit,
        &ACTIONS,
        &CLOCK,
        Policy::default(),
        policy_version(),
    )
}

#[tokio::test]
async fn text_completion_finishes_without_executing_an_action() {
    let model = FakeModel::new([ModelOutput::FinalText("done".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::unlimited(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("run succeeds");

    assert_eq!(
        outcome,
        RunOutcome::Completed {
            text: "done".into()
        }
    );
    assert_eq!(model.call_count(), 1);
    assert_eq!(executor.call_count(), 0);
    assert_eq!(
        audit.events(),
        vec![AuditEventKind::RunCreated, AuditEventKind::RunCompleted]
    );
}

#[tokio::test]
async fn audit_events_read_fresh_wall_time_after_async_boundaries() {
    let clock = Arc::new(TestClock::new(1_000));
    let model = ClockedModel::new(
        [
            proposal("filesystem.read"),
            ModelOutput::FinalText("done".into()),
        ],
        clock.clone(),
        [2_000, 4_000],
    );
    let executor = ClockedExecutor {
        inner: FakeExecutor::succeeding(),
        clock: clock.clone(),
        completion_time: 3_000,
    };
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &ACTIONS,
        clock.as_ref(),
        Policy::default(),
        policy_version(),
    );

    assert_eq!(
        orchestrator
            .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead))
            .await
            .expect("run outcome"),
        RunOutcome::Completed {
            text: "done".into()
        }
    );
    let recorded = audit.recorded();
    assert_eq!(
        recorded[0],
        (AuditEventKind::RunCreated, TimestampMillis::new(1_000))
    );
    assert!(recorded.contains(&(AuditEventKind::ActionProposed, TimestampMillis::new(2_000))));
    assert!(recorded.contains(&(
        AuditEventKind::ExecutionSucceeded,
        TimestampMillis::new(3_000)
    )));
    assert_eq!(
        recorded.last(),
        Some(&(AuditEventKind::RunCompleted, TimestampMillis::new(4_000)))
    );
}

#[tokio::test]
async fn backward_wall_clock_does_not_control_the_monotonic_budget() {
    let clock = Arc::new(TestClock::new(10_000));
    let model = ClockedModel::new(
        [ModelOutput::FinalText("done".into())],
        clock.clone(),
        [9_000],
    );
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(
        run_context(),
        "hello",
        RunBudget::limited(1, 0, Duration::from_secs(1), 1024),
    );
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &ACTIONS,
        clock.as_ref(),
        Policy::default(),
        policy_version(),
    );

    assert!(matches!(
        orchestrator
            .run_until_blocked(&mut state, &EffectiveCapabilities::default())
            .await
            .expect("run outcome"),
        RunOutcome::Completed { .. }
    ));
    assert_eq!(
        audit.recorded(),
        vec![
            (AuditEventKind::RunCreated, TimestampMillis::new(10_000)),
            (AuditEventKind::RunCompleted, TimestampMillis::new(9_000)),
        ]
    );
}

#[tokio::test]
async fn model_input_from_run_state_is_workspace_classified() {
    let model = FakeModel::new([ModelOutput::FinalText("done".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::unlimited(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("run succeeds");

    assert_eq!(
        outcome,
        RunOutcome::Completed {
            text: "done".into()
        }
    );
    let inputs = model.inputs();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].data_class(), DataClass::Workspace);
}

#[tokio::test]
async fn model_input_from_run_state_can_be_public_classified() {
    let model = FakeModel::new([ModelOutput::FinalText("done".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::unlimited(3, 2))
        .with_data_class(DataClass::Public);

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("run succeeds");

    assert_eq!(
        outcome,
        RunOutcome::Completed {
            text: "done".into()
        }
    );
    let inputs = model.inputs();
    assert_eq!(inputs.len(), 1);
    assert_eq!(inputs[0].data_class(), DataClass::Public);
}

#[tokio::test]
async fn terminal_run_outcome_is_sticky_and_does_not_repeat_work() {
    let model = FakeModel::new([ModelOutput::FinalText("done".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::unlimited(3, 2));
    let orchestrator = orchestrator(&model, &executor, &approvals, &audit);

    let first = orchestrator
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("first call completes");
    let second = orchestrator
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("terminal state can be inspected");

    assert_eq!(second, first);
    assert_eq!(model.call_count(), 1);
    assert_eq!(
        audit.events(),
        vec![AuditEventKind::RunCreated, AuditEventKind::RunCompleted]
    );
}

#[tokio::test]
async fn denied_action_never_reaches_the_executor() {
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("denial is a run outcome");

    assert!(matches!(
        outcome,
        RunOutcome::Denied {
            reason: DenialReason::MissingCapability(_)
        }
    ));
    assert_eq!(executor.call_count(), 0);
    assert!(audit.events().contains(&AuditEventKind::PolicyDenied));
}

#[tokio::test]
async fn normalized_action_is_persisted_before_policy_denial() {
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let actions = CountingActions::default();
    let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &actions,
        &CLOCK,
        Policy::default(),
        policy_version(),
    );

    let outcome = orchestrator
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("denial is recorded");

    assert!(matches!(outcome, RunOutcome::Denied { .. }));
    assert_eq!(actions.0.load(Ordering::SeqCst), 1);
    assert_eq!(executor.call_count(), 0);
    let payload =
        serde_json::to_string(&audit.payload(AuditEventKind::PolicyDenied)).expect("audit payload");
    assert!(payload.contains(r#""actor_provider":"local""#));
    assert!(payload.contains(r#""action_id":""#));
    assert!(payload.contains(r#""action_kind":"filesystem.read""#));
    assert!(payload.contains(r#""required_capabilities""#));
    assert!(payload.contains(r#""denial_reason""#));
}

#[tokio::test]
async fn pending_approval_pauses_and_resume_does_not_repeat_the_model_call() {
    let clock = TestClock::new(9_000);
    let model = FakeModel::new([
        proposal("filesystem.write"),
        ModelOutput::FinalText("saved".to_owned()),
    ]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::pending_then_grant();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "write", RunBudget::unlimited(3, 2));
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &ACTIONS,
        &clock,
        Policy::default(),
        policy_version(),
    );

    let first = orchestrator
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsWrite))
        .await
        .expect("run pauses");
    assert!(matches!(first, RunOutcome::AwaitingApproval { .. }));
    assert!(state.has_pending_action());
    assert_eq!(model.call_count(), 1);
    assert_eq!(executor.call_count(), 0);

    clock.set(10_000);
    let resumed = orchestrator
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsWrite))
        .await
        .expect("run resumes");
    assert_eq!(
        resumed,
        RunOutcome::Completed {
            text: "saved".into()
        }
    );
    assert!(!state.has_pending_action());
    assert_eq!(model.call_count(), 2);
    assert_eq!(executor.call_count(), 1);
    let recorded = audit.recorded();
    assert!(recorded.contains(&(AuditEventKind::ApprovalCreated, TimestampMillis::new(9_000))));
    assert!(recorded.contains(&(
        AuditEventKind::ApprovalGranted,
        TimestampMillis::new(10_000)
    )));
    assert!(recorded.contains(&(
        AuditEventKind::ApprovalConsumed,
        TimestampMillis::new(10_000)
    )));
}

#[tokio::test]
async fn approval_expiry_is_rechecked_with_fresh_time_before_dispatch() {
    let clock = Arc::new(TestClock::new(10_000));
    let model = FakeModel::new([proposal("filesystem.write")]);
    let executor = FakeExecutor::succeeding();
    let approvals = ExpiringApprovals {
        clock: clock.clone(),
    };
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "write", RunBudget::unlimited(1, 1));
    let orchestrator = RunOrchestrator::new(
        &model,
        &NORMALIZER,
        &executor,
        &approvals,
        &audit,
        &ACTIONS,
        clock.as_ref(),
        Policy::default(),
        policy_version(),
    );

    assert_eq!(
        orchestrator
            .run_until_blocked(&mut state, &capabilities(CapabilityName::FsWrite))
            .await,
        Err(RunError::Dispatch(DispatchError::Approval(
            ApprovalError::Expired
        )))
    );
    assert_eq!(executor.call_count(), 0);
}

#[tokio::test]
async fn tool_call_identity_and_result_are_preserved_after_approval() {
    let arguments = CanonicalValue::object([
        ("path", CanonicalValue::from("notes/today.md")),
        ("content", CanonicalValue::from("written")),
    ]);
    let model = FakeModel::new([
        ModelOutput::Action(
            ActionProposal::new("filesystem.write", arguments.clone())
                .with_tool_call(ModelToolCall::new("call-1", "filesystem_write", arguments)),
        ),
        ModelOutput::FinalText("saved".to_owned()),
    ]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::pending_then_grant();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "write", RunBudget::unlimited(3, 2));
    let orchestrator = orchestrator(&model, &executor, &approvals, &audit);
    let capabilities = capabilities(CapabilityName::FsWrite);

    assert!(matches!(
        orchestrator
            .run_until_blocked(&mut state, &capabilities)
            .await
            .expect("run pauses"),
        RunOutcome::AwaitingApproval { .. }
    ));
    let outcome = orchestrator
        .run_until_blocked(&mut state, &capabilities)
        .await
        .expect("run resumes");

    assert_eq!(
        outcome,
        RunOutcome::Completed {
            text: "saved".into()
        }
    );
    let inputs = model.inputs();
    assert!(
        inputs[0]
            .tools()
            .iter()
            .any(|tool| tool.name() == "filesystem_write")
    );
    let messages = inputs[1].messages();
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[1].role(), ModelRole::Assistant);
    assert_eq!(
        messages[1].tool_call().expect("assistant tool call").id(),
        "call-1"
    );
    assert_eq!(messages[2].role(), ModelRole::Tool);
    assert_eq!(messages[2].tool_call_id(), Some("call-1"));
    assert_eq!(messages[2].content(), &CanonicalValue::from("written"));
}

#[tokio::test]
async fn exhausted_model_budget_stops_before_calling_the_model() {
    let model = FakeModel::new([ModelOutput::FinalText("unused".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::unlimited(0, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("budget exhaustion is a run outcome");

    assert_eq!(outcome, RunOutcome::BudgetExhausted(BudgetKind::ModelTurns));
    assert_eq!(model.call_count(), 0);
}

#[test]
fn job_step_limits_preserve_runtime_quotas_and_only_tighten() {
    let runtime = RunBudget::limited(4, 3, Duration::from_secs(5), 128);

    assert_eq!(
        runtime.with_step_limits(2, 8),
        RunBudget::limited(2, 3, Duration::from_secs(5), 128)
    );
}

#[tokio::test]
async fn approval_waiting_counts_toward_the_wall_clock_budget() {
    let model = FakeModel::new([proposal("filesystem.write")]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::pending_then_grant();
    let audit = FakeAudit::default();
    let budget = RunBudget::limited(3, 2, Duration::from_millis(10), 1024);
    let mut state = RunState::new(run_context(), "write", budget);
    let orchestrator = orchestrator(&model, &executor, &approvals, &audit);
    let capabilities = capabilities(CapabilityName::FsWrite);

    assert!(matches!(
        orchestrator
            .run_until_blocked(&mut state, &capabilities)
            .await
            .expect("run pauses"),
        RunOutcome::AwaitingApproval { .. }
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert_eq!(
        orchestrator
            .run_until_blocked(&mut state, &capabilities)
            .await
            .expect("budget exhaustion is a run outcome"),
        RunOutcome::BudgetExhausted(BudgetKind::WallClock)
    );
    assert_eq!(executor.call_count(), 0);
}

#[tokio::test]
async fn cancelled_run_stops_before_model_or_executor_work() {
    let model = FakeModel::new([ModelOutput::FinalText("unused".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::unlimited(3, 2));
    state.cancel();

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("cancellation is a run outcome");

    assert_eq!(outcome, RunOutcome::Cancelled);
    assert_eq!(model.call_count(), 0);
    assert_eq!(executor.call_count(), 0);
}

#[tokio::test]
async fn executor_failure_is_distinct_from_an_unknown_outcome() {
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = FakeExecutor::new([Ok(ExecutionOutcome::Failed("exit 1".into()))]);
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead))
        .await
        .expect("known failure is a run outcome");

    assert_eq!(
        outcome,
        RunOutcome::ExecutionFailed {
            message: "exit 1".into()
        }
    );
    assert!(audit.events().contains(&AuditEventKind::ExecutionFailed));
}

#[tokio::test]
async fn executor_unknown_outcome_is_preserved_for_reconciliation() {
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = FakeExecutor::new([Ok(ExecutionOutcome::Unknown("connection lost".into()))]);
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead))
        .await
        .expect("unknown execution is a run outcome");

    assert_eq!(
        outcome,
        RunOutcome::ExecutionUnknown {
            message: "connection lost".into()
        }
    );
    assert!(audit.events().contains(&AuditEventKind::ExecutionUnknown));
}

#[tokio::test]
async fn audit_failure_before_dispatch_fails_closed() {
    let model = FakeModel::new([proposal("filesystem.read")]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::failing_on(AuditEventKind::ExecutionStarted);
    let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));

    let result = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead))
        .await;

    assert_eq!(
        result,
        Err(RunError::Audit(AuditPortError::new("audit unavailable")))
    );
    assert_eq!(executor.call_count(), 0);
}

#[tokio::test]
async fn elapsed_wall_clock_budget_stops_before_model_or_executor_work() {
    let model = FakeModel::new([ModelOutput::FinalText("unused".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let budget = RunBudget::limited(3, 2, Duration::from_millis(1), 1024);
    let mut state = RunState::new(run_context(), "hello", budget);
    tokio::time::sleep(Duration::from_millis(5)).await;

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default())
        .await
        .expect("wall-clock exhaustion is a run outcome");

    assert_eq!(outcome, RunOutcome::BudgetExhausted(BudgetKind::WallClock));
    assert_eq!(model.call_count(), 0);
    assert_eq!(executor.call_count(), 0);
    assert!(audit.events().contains(&AuditEventKind::RunBudgetExhausted));
    assert!(
        serde_json::to_string(&audit.payload(AuditEventKind::RunBudgetExhausted))
            .expect("budget payload")
            .contains(r#""budget":"wall_clock""#)
    );
}

#[tokio::test]
async fn cumulative_captured_result_budget_stops_before_another_model_turn() {
    let model = FakeModel::new([
        proposal("filesystem.read"),
        ModelOutput::FinalText("must not run".to_owned()),
    ]);
    let executor = FakeExecutor::new([Ok(ExecutionOutcome::Succeeded(CanonicalValue::from(
        "oversized-result",
    )))]);
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let budget = RunBudget::limited(3, 2, Duration::from_secs(10), 4);
    let mut state = RunState::new(run_context(), "read", budget);

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead))
        .await
        .expect("result-byte exhaustion is a run outcome");

    assert_eq!(
        outcome,
        RunOutcome::BudgetExhausted(BudgetKind::CapturedResultBytes)
    );
    assert_eq!(model.call_count(), 1);
    assert_eq!(executor.call_count(), 1);
    assert!(audit.events().contains(&AuditEventKind::RunBudgetExhausted));
    assert!(
        serde_json::to_string(&audit.payload(AuditEventKind::RunBudgetExhausted))
            .expect("budget payload")
            .contains(r#""budget":"captured_result_bytes""#)
    );
}

#[tokio::test]
async fn executor_cancellation_and_timeout_remain_distinct_run_outcomes() {
    for (execution, expected) in [
        (ExecutionOutcome::Cancelled, RunOutcome::Cancelled),
        (ExecutionOutcome::TimedOut, RunOutcome::ExecutionTimedOut),
    ] {
        let model = FakeModel::new([proposal("filesystem.read")]);
        let executor = FakeExecutor::new([Ok(execution)]);
        let approvals = FakeApprovals::always_pending();
        let audit = FakeAudit::default();
        let mut state = RunState::new(run_context(), "read", RunBudget::unlimited(3, 2));

        let outcome = orchestrator(&model, &executor, &approvals, &audit)
            .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead))
            .await
            .expect("execution terminal outcome");

        assert_eq!(outcome, expected);
    }
}
