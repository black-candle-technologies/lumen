use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant},
};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    action::{ActionEnvelope, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, DispatchError, TimestampMillis, authorize_dispatch},
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    capability::{Capability, CapabilitySet, EffectiveCapabilities},
    egress::DataClass,
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorPort},
    extension::{AttributedActionProposal, ExtensionProvenance},
    identity::{ComponentId, PrincipalId, WorkspaceId},
    model::{
        ActionProposal, ModelError, ModelInput, ModelMessage, ModelOutput, ModelPort, ModelRole,
    },
    policy::{DenialReason, Policy, PolicyDecision, PolicyVersion},
};

pub type ApprovalFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ApprovalResolution, ApprovalPortError>> + Send + 'a>>;
pub type AuditFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AuditPortError>> + Send + 'a>>;
pub type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ActionPortError>> + Send + 'a>>;

pub trait ActionNormalizer: Send + Sync {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError>;
}

pub trait ApprovalPort: Send + Sync {
    fn resolve<'a>(
        &'a self,
        action: &'a ActionEnvelope,
        policy_version: &'a PolicyVersion,
        now: TimestampMillis,
    ) -> ApprovalFuture<'a>;
}

pub trait AuditPort: Send + Sync {
    fn record(&self, event: AuditEvent) -> AuditFuture<'_>;
}

pub trait ActionPort: Send + Sync {
    fn persist<'a>(&'a self, action: &'a ActionEnvelope, now: TimestampMillis) -> ActionFuture<'a>;
}

#[derive(Debug)]
pub enum ApprovalResolution {
    Pending(ApprovalId),
    Granted(ApprovalRequest),
    Rejected(ApprovalId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunContext {
    run_id: RunId,
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl RunContext {
    pub const fn new(run_id: RunId, workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            run_id,
            workspace_id,
            actor,
        }
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RunBudget {
    max_model_turns: u32,
    max_actions: u32,
    max_wall_time: Option<Duration>,
    max_captured_result_bytes: usize,
}

impl RunBudget {
    pub const fn new(max_model_turns: u32, max_actions: u32) -> Self {
        Self {
            max_model_turns,
            max_actions,
            max_wall_time: None,
            max_captured_result_bytes: usize::MAX,
        }
    }

    pub const fn with_quotas(
        mut self,
        max_wall_time: Duration,
        max_captured_result_bytes: usize,
    ) -> Self {
        self.max_wall_time = Some(max_wall_time);
        self.max_captured_result_bytes = max_captured_result_bytes;
        self
    }
}

#[derive(Debug)]
pub struct RunState {
    context: RunContext,
    messages: Vec<ModelMessage>,
    data_class: DataClass,
    budget: RunBudget,
    model_turns: u32,
    actions: u32,
    pending_action: Option<PendingAction>,
    pending_extension_proposal: Option<AttributedActionProposal>,
    terminal_outcome: Option<RunOutcome>,
    started: bool,
    cancelled: bool,
    started_at: Instant,
    captured_result_bytes: usize,
}

impl RunState {
    pub fn new(context: RunContext, prompt: impl Into<String>, budget: RunBudget) -> Self {
        Self {
            context,
            messages: vec![ModelMessage::new(
                ModelRole::User,
                CanonicalValue::from(prompt.into()),
            )],
            data_class: DataClass::Workspace,
            budget,
            model_turns: 0,
            actions: 0,
            pending_action: None,
            pending_extension_proposal: None,
            terminal_outcome: None,
            started: false,
            cancelled: false,
            started_at: Instant::now(),
            captured_result_bytes: 0,
        }
    }

    pub const fn with_data_class(mut self, data_class: DataClass) -> Self {
        self.data_class = data_class;
        self
    }

    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    pub fn has_pending_action(&self) -> bool {
        self.pending_action.is_some()
    }

    fn finish(&mut self, outcome: RunOutcome) -> RunOutcome {
        self.terminal_outcome = Some(outcome.clone());
        outcome
    }
}

#[derive(Debug)]
struct PendingAction {
    action: ActionEnvelope,
    approval_id: ApprovalId,
}

struct ChildAttribution {
    provenance: ExtensionProvenance,
    effective_grants: Vec<Capability>,
}

enum NextOutput {
    FinalText(String),
    Action {
        proposal: ActionProposal,
        attribution: Option<Box<ChildAttribution>>,
    },
}

pub struct RunOrchestrator<'a> {
    model: &'a dyn ModelPort,
    normalizer: &'a dyn ActionNormalizer,
    executor: &'a dyn ExecutorPort,
    approvals: &'a dyn ApprovalPort,
    audit: &'a dyn AuditPort,
    actions: &'a dyn ActionPort,
    policy: Policy,
    policy_version: PolicyVersion,
    cancellation: CancellationToken,
}

impl<'a> RunOrchestrator<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        model: &'a dyn ModelPort,
        normalizer: &'a dyn ActionNormalizer,
        executor: &'a dyn ExecutorPort,
        approvals: &'a dyn ApprovalPort,
        audit: &'a dyn AuditPort,
        actions: &'a dyn ActionPort,
        policy: Policy,
        policy_version: PolicyVersion,
    ) -> Self {
        Self {
            model,
            normalizer,
            executor,
            approvals,
            audit,
            actions,
            policy,
            policy_version,
            cancellation: CancellationToken::new(),
        }
    }

    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }

    pub async fn run_until_blocked(
        &self,
        state: &mut RunState,
        capabilities: &EffectiveCapabilities,
        now: TimestampMillis,
    ) -> Result<RunOutcome, RunError> {
        if let Some(outcome) = &state.terminal_outcome {
            return Ok(outcome.clone());
        }

        if !state.started {
            self.audit(
                state,
                AuditEventKind::RunCreated,
                AuditOutcome::Success,
                now,
            )
            .await?;
            state.started = true;
        }

        loop {
            if state.cancelled {
                self.audit(
                    state,
                    AuditEventKind::RunCancelled,
                    AuditOutcome::Failure,
                    now,
                )
                .await?;
                return Ok(state.finish(RunOutcome::Cancelled));
            }

            if self
                .wall_time_remaining(state)
                .is_some_and(|remaining| remaining.is_zero())
            {
                return self.exhaust_budget(state, BudgetKind::WallClock, now).await;
            }

            if let Some(pending) = state.pending_action.take() {
                match self
                    .resolve_approval(state, pending.action, pending.approval_id, now)
                    .await?
                {
                    ActionProgress::Ready(action) => {
                        if let Some(outcome) = self.execute(state, action, now).await? {
                            return Ok(outcome);
                        }
                        continue;
                    }
                    ActionProgress::Blocked(outcome, pending) => {
                        state.pending_action = Some(pending);
                        return Ok(outcome);
                    }
                    ActionProgress::Terminal(outcome) => return Ok(state.finish(outcome)),
                }
            }

            let output = if let Some(proposal) = state.pending_extension_proposal.take() {
                let (proposal, provenance, _declared_action_kinds, effective_grants) =
                    proposal.into_parts();
                NextOutput::Action {
                    proposal,
                    attribution: Some(Box::new(ChildAttribution {
                        provenance,
                        effective_grants,
                    })),
                }
            } else {
                if state.model_turns >= state.budget.max_model_turns {
                    return self
                        .exhaust_budget(state, BudgetKind::ModelTurns, now)
                        .await;
                }
                let generation = self.model.generate(
                    ModelInput::new(state.messages.clone()).with_data_class(state.data_class),
                );
                let output = match self.wall_time_remaining(state) {
                    Some(remaining) => match tokio::time::timeout(remaining, generation).await {
                        Ok(output) => output?,
                        Err(_) => {
                            return self.exhaust_budget(state, BudgetKind::WallClock, now).await;
                        }
                    },
                    None => generation.await?,
                };
                state.model_turns += 1;
                match output {
                    ModelOutput::FinalText(text) => NextOutput::FinalText(text),
                    ModelOutput::Action(proposal) => NextOutput::Action {
                        proposal,
                        attribution: None,
                    },
                }
            };

            match output {
                NextOutput::FinalText(text) => {
                    self.audit(
                        state,
                        AuditEventKind::RunCompleted,
                        AuditOutcome::Success,
                        now,
                    )
                    .await?;
                    return Ok(state.finish(RunOutcome::Completed { text }));
                }
                NextOutput::Action {
                    proposal,
                    attribution,
                } => {
                    if state.actions >= state.budget.max_actions {
                        return self.exhaust_budget(state, BudgetKind::Actions, now).await;
                    }
                    self.audit(
                        state,
                        AuditEventKind::ActionProposed,
                        AuditOutcome::Pending,
                        now,
                    )
                    .await?;
                    let action = self.normalizer.normalize(&state.context, proposal)?;
                    let (action, evaluation_capabilities) = match attribution {
                        Some(attribution) => (
                            action
                                .with_requesting_component(
                                    ComponentId::new("runtime.extensions")
                                        .expect("static component ID"),
                                )
                                .with_extension_provenance(attribution.provenance),
                            capabilities
                                .clone()
                                .with_layer(CapabilitySet::new(attribution.effective_grants)),
                        ),
                        None => (action, capabilities.clone()),
                    };
                    state.actions += 1;
                    self.actions.persist(&action, now).await?;
                    self.audit(
                        state,
                        AuditEventKind::ActionNormalized,
                        AuditOutcome::Success,
                        now,
                    )
                    .await?;

                    let decision = self.policy.evaluate(&action, &evaluation_capabilities);
                    match &decision {
                        PolicyDecision::Deny(reason) => {
                            self.audit(
                                state,
                                AuditEventKind::PolicyDenied,
                                AuditOutcome::Denied,
                                now,
                            )
                            .await?;
                            return Ok(state.finish(RunOutcome::Denied {
                                reason: reason.clone(),
                            }));
                        }
                        PolicyDecision::Allow => {
                            self.audit(
                                state,
                                AuditEventKind::PolicyAllowed,
                                AuditOutcome::Success,
                                now,
                            )
                            .await?;
                            let authorization = authorize_dispatch(
                                &decision,
                                &action,
                                &self.policy_version,
                                None,
                                now,
                            )?;
                            if let Some(outcome) = self
                                .execute(state, AuthorizedAction::new(action, authorization), now)
                                .await?
                            {
                                return Ok(outcome);
                            }
                        }
                        PolicyDecision::RequireApproval => {
                            match self
                                .approvals
                                .resolve(&action, &self.policy_version, now)
                                .await?
                            {
                                ApprovalResolution::Pending(approval_id) => {
                                    self.audit(
                                        state,
                                        AuditEventKind::ApprovalCreated,
                                        AuditOutcome::Pending,
                                        now,
                                    )
                                    .await?;
                                    state.pending_action = Some(PendingAction {
                                        action,
                                        approval_id,
                                    });
                                    return Ok(RunOutcome::AwaitingApproval { approval_id });
                                }
                                ApprovalResolution::Granted(mut approval) => {
                                    let authorization = self
                                        .consume_approval(state, &action, &mut approval, now)
                                        .await?;
                                    if let Some(outcome) = self
                                        .execute(
                                            state,
                                            AuthorizedAction::new(action, authorization),
                                            now,
                                        )
                                        .await?
                                    {
                                        return Ok(outcome);
                                    }
                                }
                                ApprovalResolution::Rejected(approval_id) => {
                                    self.audit(
                                        state,
                                        AuditEventKind::ApprovalRejected,
                                        AuditOutcome::Denied,
                                        now,
                                    )
                                    .await?;
                                    return Ok(
                                        state.finish(RunOutcome::ApprovalRejected { approval_id })
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn resolve_approval(
        &self,
        state: &RunState,
        action: ActionEnvelope,
        expected_id: ApprovalId,
        now: TimestampMillis,
    ) -> Result<ActionProgress, RunError> {
        match self
            .approvals
            .resolve(&action, &self.policy_version, now)
            .await?
        {
            ApprovalResolution::Pending(approval_id) => {
                if approval_id != expected_id {
                    return Err(RunError::ApprovalIdentityMismatch);
                }
                Ok(ActionProgress::Blocked(
                    RunOutcome::AwaitingApproval { approval_id },
                    PendingAction {
                        action,
                        approval_id,
                    },
                ))
            }
            ApprovalResolution::Granted(mut approval) => {
                if approval.id() != expected_id {
                    return Err(RunError::ApprovalIdentityMismatch);
                }
                let authorization = self
                    .consume_approval(state, &action, &mut approval, now)
                    .await?;
                Ok(ActionProgress::Ready(AuthorizedAction::new(
                    action,
                    authorization,
                )))
            }
            ApprovalResolution::Rejected(approval_id) => {
                if approval_id != expected_id {
                    return Err(RunError::ApprovalIdentityMismatch);
                }
                self.audit(
                    state,
                    AuditEventKind::ApprovalRejected,
                    AuditOutcome::Denied,
                    now,
                )
                .await?;
                Ok(ActionProgress::Terminal(RunOutcome::ApprovalRejected {
                    approval_id,
                }))
            }
        }
    }

    async fn consume_approval(
        &self,
        state: &RunState,
        action: &ActionEnvelope,
        approval: &mut ApprovalRequest,
        now: TimestampMillis,
    ) -> Result<crate::approval::DispatchAuthorization, RunError> {
        self.audit(
            state,
            AuditEventKind::ApprovalGranted,
            AuditOutcome::Success,
            now,
        )
        .await?;
        let authorization = authorize_dispatch(
            &PolicyDecision::RequireApproval,
            action,
            &self.policy_version,
            Some(approval),
            now,
        )?;
        self.audit(
            state,
            AuditEventKind::ApprovalConsumed,
            AuditOutcome::Success,
            now,
        )
        .await?;
        Ok(authorization)
    }

    async fn execute(
        &self,
        state: &mut RunState,
        action: AuthorizedAction,
        now: TimestampMillis,
    ) -> Result<Option<RunOutcome>, RunError> {
        self.audit(
            state,
            AuditEventKind::ExecutionStarted,
            AuditOutcome::Pending,
            now,
        )
        .await?;
        let cancellation = self.cancellation.clone();
        let mut execution = self.executor.execute(&action, cancellation.clone());
        let outcome = match self.wall_time_remaining(state) {
            Some(remaining) => {
                tokio::select! {
                    outcome = &mut execution => outcome?,
                    () = tokio::time::sleep(remaining) => {
                        cancellation.cancel();
                        let _ = execution.await;
                        return Ok(Some(
                            self.exhaust_budget(state, BudgetKind::WallClock, now)
                                .await?,
                        ));
                    }
                }
            }
            None => execution.await?,
        };
        match outcome {
            ExecutionOutcome::Succeeded(result) => {
                self.audit(
                    state,
                    AuditEventKind::ExecutionSucceeded,
                    AuditOutcome::Success,
                    now,
                )
                .await?;
                let captured = serde_json::to_vec(&result)
                    .expect("canonical tool result serialization cannot fail")
                    .len();
                if captured
                    > state
                        .budget
                        .max_captured_result_bytes
                        .saturating_sub(state.captured_result_bytes)
                {
                    return Ok(Some(
                        self.exhaust_budget(state, BudgetKind::CapturedResultBytes, now)
                            .await?,
                    ));
                }
                state.captured_result_bytes += captured;
                state
                    .messages
                    .push(ModelMessage::new(ModelRole::Tool, result));
                Ok(None)
            }
            ExecutionOutcome::Proposed(proposal) => {
                self.audit(
                    state,
                    AuditEventKind::ExecutionSucceeded,
                    AuditOutcome::Success,
                    now,
                )
                .await?;
                let captured = serde_json::to_vec(&proposal)
                    .expect("attributed extension proposal serialization cannot fail")
                    .len();
                if captured
                    > state
                        .budget
                        .max_captured_result_bytes
                        .saturating_sub(state.captured_result_bytes)
                {
                    return Ok(Some(
                        self.exhaust_budget(state, BudgetKind::CapturedResultBytes, now)
                            .await?,
                    ));
                }
                state.captured_result_bytes += captured;
                state.pending_extension_proposal = Some(*proposal);
                Ok(None)
            }
            ExecutionOutcome::Failed(message) => {
                self.audit(
                    state,
                    AuditEventKind::ExecutionFailed,
                    AuditOutcome::Failure,
                    now,
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::ExecutionFailed { message })))
            }
            ExecutionOutcome::Cancelled => {
                self.audit(
                    state,
                    AuditEventKind::ExecutionCancelled,
                    AuditOutcome::Failure,
                    now,
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::Cancelled)))
            }
            ExecutionOutcome::TimedOut => {
                self.audit(
                    state,
                    AuditEventKind::ExecutionTimedOut,
                    AuditOutcome::Failure,
                    now,
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::ExecutionTimedOut)))
            }
            ExecutionOutcome::Unknown(message) => {
                self.audit(
                    state,
                    AuditEventKind::ExecutionUnknown,
                    AuditOutcome::Unknown,
                    now,
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::ExecutionUnknown { message })))
            }
        }
    }

    fn wall_time_remaining(&self, state: &RunState) -> Option<Duration> {
        state
            .budget
            .max_wall_time
            .map(|limit| limit.saturating_sub(state.started_at.elapsed()))
    }

    async fn exhaust_budget(
        &self,
        state: &mut RunState,
        kind: BudgetKind,
        now: TimestampMillis,
    ) -> Result<RunOutcome, RunError> {
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                now,
                AuditEventKind::RunBudgetExhausted,
                AuditOutcome::Failure,
                Some(state.context.workspace_id()),
                CanonicalValue::object([
                    (
                        "run_id",
                        CanonicalValue::from(state.context.run_id().to_string()),
                    ),
                    (
                        "actor",
                        CanonicalValue::from(state.context.actor().subject()),
                    ),
                    ("budget", CanonicalValue::from(kind.as_str())),
                    (
                        "captured_result_bytes",
                        CanonicalValue::from(
                            i64::try_from(state.captured_result_bytes).unwrap_or(i64::MAX),
                        ),
                    ),
                ]),
            ))
            .await?;
        Ok(state.finish(RunOutcome::BudgetExhausted(kind)))
    }

    async fn audit(
        &self,
        state: &RunState,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        now: TimestampMillis,
    ) -> Result<(), AuditPortError> {
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                now,
                kind,
                outcome,
                Some(state.context.workspace_id()),
                CanonicalValue::object([
                    (
                        "run_id",
                        CanonicalValue::from(state.context.run_id().to_string()),
                    ),
                    (
                        "actor",
                        CanonicalValue::from(state.context.actor().subject()),
                    ),
                ]),
            ))
            .await
    }
}

enum ActionProgress {
    Ready(AuthorizedAction),
    Blocked(RunOutcome, PendingAction),
    Terminal(RunOutcome),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Completed { text: String },
    AwaitingApproval { approval_id: ApprovalId },
    ApprovalRejected { approval_id: ApprovalId },
    Denied { reason: DenialReason },
    BudgetExhausted(BudgetKind),
    Cancelled,
    ExecutionFailed { message: String },
    ExecutionTimedOut,
    ExecutionUnknown { message: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetKind {
    ModelTurns,
    Actions,
    WallClock,
    CapturedResultBytes,
}

impl BudgetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelTurns => "model_turns",
            Self::Actions => "actions",
            Self::WallClock => "wall_clock",
            Self::CapturedResultBytes => "captured_result_bytes",
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("action normalization failed: {message}")]
pub struct NormalizationError {
    message: String,
}

impl NormalizationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("approval port failed: {message}")]
pub struct ApprovalPortError {
    message: String,
}

impl ApprovalPortError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("audit port failed: {message}")]
pub struct AuditPortError {
    message: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("action persistence failed: {message}")]
pub struct ActionPortError {
    message: String,
}

impl ActionPortError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl AuditPortError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RunError {
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Normalization(#[from] NormalizationError),
    #[error(transparent)]
    ApprovalPort(#[from] ApprovalPortError),
    #[error(transparent)]
    Audit(#[from] AuditPortError),
    #[error(transparent)]
    ActionPort(#[from] ActionPortError),
    #[error(transparent)]
    Dispatch(#[from] DispatchError),
    #[error(transparent)]
    Executor(#[from] ExecutorError),
    #[error("approval response did not match the pending approval")]
    ApprovalIdentityMismatch,
}
