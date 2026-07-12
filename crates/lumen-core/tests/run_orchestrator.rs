use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, TimestampMillis},
    audit::{AuditEvent, AuditEventKind},
    capability::{
        Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope,
        WorkspacePath,
    },
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorFuture, ExecutorPort},
    identity::{ComponentId, PrincipalId, WorkspaceId},
    model::{ActionProposal, ModelError, ModelFuture, ModelInput, ModelOutput, ModelPort},
    policy::{DenialReason, Policy, PolicyVersion},
    run::{
        ActionNormalizer, ApprovalFuture, ApprovalPort, ApprovalResolution, AuditFuture, AuditPort,
        AuditPortError, BudgetKind, NormalizationError, RunBudget, RunContext, RunError,
        RunOrchestrator, RunOutcome, RunState,
    },
};
use uuid::Uuid;

const NOW: TimestampMillis = TimestampMillis::new(10_000);

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
    calls: AtomicUsize,
}

impl FakeModel {
    fn new(outputs: impl IntoIterator<Item = ModelOutput>) -> Self {
        Self {
            outputs: Mutex::new(outputs.into_iter().map(Ok).collect()),
            calls: AtomicUsize::new(0),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ModelPort for FakeModel {
    fn generate(&self, _input: ModelInput) -> ModelFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            self.outputs
                .lock()
                .expect("model queue lock")
                .pop_front()
                .unwrap_or_else(|| Err(ModelError::new("no fake model output")))
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
    fn execute(&self, _action: &AuthorizedAction) -> ExecutorFuture<'_> {
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

#[derive(Default)]
struct FakeAudit {
    events: Mutex<Vec<AuditEventKind>>,
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
        self.events.lock().expect("audit events lock").clone()
    }
}

impl AuditPort for FakeAudit {
    fn record(&self, event: AuditEvent) -> AuditFuture<'_> {
        Box::pin(async move {
            if self.fail_on.lock().expect("audit failure lock").as_ref() == Some(&event.kind()) {
                return Err(AuditPortError::new("audit unavailable"));
            }
            self.events
                .lock()
                .expect("audit events lock")
                .push(event.kind());
            Ok(())
        })
    }
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
    let mut state = RunState::new(run_context(), "hello", RunBudget::new(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default(), NOW)
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
async fn terminal_run_outcome_is_sticky_and_does_not_repeat_work() {
    let model = FakeModel::new([ModelOutput::FinalText("done".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::new(3, 2));
    let orchestrator = orchestrator(&model, &executor, &approvals, &audit);

    let first = orchestrator
        .run_until_blocked(&mut state, &EffectiveCapabilities::default(), NOW)
        .await
        .expect("first call completes");
    let second = orchestrator
        .run_until_blocked(&mut state, &EffectiveCapabilities::default(), NOW)
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
    let mut state = RunState::new(run_context(), "read", RunBudget::new(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default(), NOW)
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
async fn pending_approval_pauses_and_resume_does_not_repeat_the_model_call() {
    let model = FakeModel::new([
        proposal("filesystem.write"),
        ModelOutput::FinalText("saved".to_owned()),
    ]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::pending_then_grant();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "write", RunBudget::new(3, 2));
    let orchestrator = orchestrator(&model, &executor, &approvals, &audit);

    let first = orchestrator
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsWrite), NOW)
        .await
        .expect("run pauses");
    assert!(matches!(first, RunOutcome::AwaitingApproval { .. }));
    assert!(state.has_pending_action());
    assert_eq!(model.call_count(), 1);
    assert_eq!(executor.call_count(), 0);

    let resumed = orchestrator
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsWrite), NOW)
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
    assert!(audit.events().contains(&AuditEventKind::ApprovalConsumed));
}

#[tokio::test]
async fn exhausted_model_budget_stops_before_calling_the_model() {
    let model = FakeModel::new([ModelOutput::FinalText("unused".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::new(0, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default(), NOW)
        .await
        .expect("budget exhaustion is a run outcome");

    assert_eq!(outcome, RunOutcome::BudgetExhausted(BudgetKind::ModelTurns));
    assert_eq!(model.call_count(), 0);
}

#[tokio::test]
async fn cancelled_run_stops_before_model_or_executor_work() {
    let model = FakeModel::new([ModelOutput::FinalText("unused".to_owned())]);
    let executor = FakeExecutor::succeeding();
    let approvals = FakeApprovals::always_pending();
    let audit = FakeAudit::default();
    let mut state = RunState::new(run_context(), "hello", RunBudget::new(3, 2));
    state.cancel();

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &EffectiveCapabilities::default(), NOW)
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
    let mut state = RunState::new(run_context(), "read", RunBudget::new(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead), NOW)
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
    let mut state = RunState::new(run_context(), "read", RunBudget::new(3, 2));

    let outcome = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead), NOW)
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
    let mut state = RunState::new(run_context(), "read", RunBudget::new(3, 2));

    let result = orchestrator(&model, &executor, &approvals, &audit)
        .run_until_blocked(&mut state, &capabilities(CapabilityName::FsRead), NOW)
        .await;

    assert_eq!(
        result,
        Err(RunError::Audit(AuditPortError::new("audit unavailable")))
    );
    assert_eq!(executor.call_count(), 0);
}
