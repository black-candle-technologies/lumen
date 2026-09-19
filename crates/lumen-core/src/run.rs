use std::{
    future::Future,
    pin::Pin,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    action::{ActionEnvelope, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, DispatchError, TimestampMillis, authorize_dispatch},
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    automation::JobOrigin,
    capability::{Capability, CapabilitySet, EffectiveCapabilities},
    egress::DataClass,
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorPort},
    extension::{AttributedActionProposal, ExtensionProvenance},
    identity::{ComponentId, PrincipalId, WorkspaceId},
    model::{
        ActionProposal, ModelError, ModelInput, ModelMessage, ModelOutput, ModelPort, ModelRole,
        ModelTool,
    },
    policy::{DenialReason, Policy, PolicyDecision, PolicyVersion},
};

pub type ApprovalFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ApprovalResolution, ApprovalPortError>> + Send + 'a>>;
pub type AuditFuture<'a> = Pin<Box<dyn Future<Output = Result<(), AuditPortError>> + Send + 'a>>;
pub type ActionFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ActionPortError>> + Send + 'a>>;

fn executor_error_unknown(error: ExecutorError) -> ExecutionOutcome {
    ExecutionOutcome::Unknown(format!(
        "executor did not provide a definitive result: {error}"
    ))
}

/// Supplies wall-clock timestamps for persisted lifecycle facts. Elapsed run
/// budgets remain based on `Instant` and are unaffected by clock adjustments.
pub trait Clock: Send + Sync {
    fn now(&self) -> TimestampMillis;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> TimestampMillis {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        TimestampMillis::new(u64::try_from(millis).unwrap_or(u64::MAX))
    }
}

pub trait ActionNormalizer: Send + Sync {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError>;

    fn model_tools(&self, _context: &RunContext) -> Vec<ModelTool> {
        Vec::new()
    }
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

    fn deny<'a>(
        &'a self,
        action: &'a ActionEnvelope,
        reason: &'a DenialReason,
        now: TimestampMillis,
    ) -> ActionFuture<'a>;
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
    job_origin: Option<JobOrigin>,
    loaded_skills: Vec<LoadedSkillMetadata>,
    skill_loads: Vec<SkillLoadMetadata>,
}

impl RunContext {
    pub const fn new(run_id: RunId, workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            run_id,
            workspace_id,
            actor,
            job_origin: None,
            loaded_skills: Vec::new(),
            skill_loads: Vec::new(),
        }
    }

    pub fn with_job_origin(mut self, origin: JobOrigin) -> Self {
        self.job_origin = Some(origin);
        self
    }

    pub fn with_loaded_skills(mut self, loaded_skills: Vec<LoadedSkillMetadata>) -> Self {
        self.loaded_skills = loaded_skills;
        self
    }

    pub fn with_skill_loads(mut self, skill_loads: Vec<SkillLoadMetadata>) -> Self {
        self.skill_loads = skill_loads;
        self
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

    pub const fn job_origin(&self) -> Option<&JobOrigin> {
        self.job_origin.as_ref()
    }

    pub fn loaded_skills(&self) -> &[LoadedSkillMetadata] {
        &self.loaded_skills
    }

    pub fn skill_loads(&self) -> &[SkillLoadMetadata] {
        &self.skill_loads
    }

    fn required_skill_failure(&self) -> Option<&SkillLoadMetadata> {
        self.skill_loads
            .iter()
            .find(|skill| skill.required && skill.status != "loaded")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedSkillMetadata {
    skill_id: String,
    version: String,
    digest: String,
}

impl LoadedSkillMetadata {
    pub fn new(
        skill_id: impl Into<String>,
        version: impl Into<String>,
        digest: impl Into<String>,
    ) -> Self {
        Self {
            skill_id: skill_id.into(),
            version: version.into(),
            digest: digest.into(),
        }
    }

    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillLoadMetadata {
    skill_id: String,
    version: String,
    expected_digest: String,
    status: &'static str,
    reason: Option<&'static str>,
    required: bool,
}

impl SkillLoadMetadata {
    pub fn loaded(
        skill_id: impl Into<String>,
        version: impl Into<String>,
        expected_digest: impl Into<String>,
        required: bool,
    ) -> Self {
        Self {
            skill_id: skill_id.into(),
            version: version.into(),
            expected_digest: expected_digest.into(),
            status: "loaded",
            reason: None,
            required,
        }
    }

    pub fn excluded(
        skill_id: impl Into<String>,
        version: impl Into<String>,
        expected_digest: impl Into<String>,
        reason: &'static str,
        required: bool,
    ) -> Self {
        Self {
            skill_id: skill_id.into(),
            version: version.into(),
            expected_digest: expected_digest.into(),
            status: "excluded",
            reason: Some(reason),
            required,
        }
    }

    pub fn skill_id(&self) -> &str {
        &self.skill_id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn expected_digest(&self) -> &str {
        &self.expected_digest
    }
    pub const fn status(&self) -> &'static str {
        self.status
    }
    pub const fn reason(&self) -> Option<&'static str> {
        self.reason
    }
    pub const fn required(&self) -> bool {
        self.required
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
    /// Sets whole-run quotas. Wall time starts with `RunState` and includes approval waits.
    pub const fn limited(
        max_model_turns: u32,
        max_actions: u32,
        max_wall_time: Duration,
        max_captured_result_bytes: usize,
    ) -> Self {
        Self {
            max_model_turns,
            max_actions,
            max_wall_time: Some(max_wall_time),
            max_captured_result_bytes,
        }
    }

    pub const fn unlimited(max_model_turns: u32, max_actions: u32) -> Self {
        Self {
            max_model_turns,
            max_actions,
            max_wall_time: None,
            max_captured_result_bytes: usize::MAX,
        }
    }

    pub fn with_step_limits(self, max_model_turns: u32, max_actions: u32) -> Self {
        Self {
            max_model_turns: self.max_model_turns.min(max_model_turns),
            max_actions: self.max_actions.min(max_actions),
            ..self
        }
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

    pub fn is_awaiting_approval(&self, approval_id: ApprovalId) -> bool {
        self.terminal_outcome.is_none()
            && self
                .pending_action
                .as_ref()
                .is_some_and(|pending| pending.approval_id == approval_id)
    }

    pub fn renew_pending_approval(
        &mut self,
        previous: ApprovalId,
        replacement: ApprovalId,
    ) -> bool {
        if self.terminal_outcome.is_some() {
            return false;
        }
        let Some(pending) = self.pending_action.as_mut() else {
            return false;
        };
        if pending.approval_id != previous {
            return false;
        }
        pending.approval_id = replacement;
        true
    }

    pub const fn context(&self) -> &RunContext {
        &self.context
    }

    fn finish(&mut self, outcome: RunOutcome) -> RunOutcome {
        self.terminal_outcome = Some(outcome.clone());
        outcome
    }
}

#[derive(Clone, Debug)]
struct PendingAction {
    action: ActionEnvelope,
    approval_id: ApprovalId,
    tool_call_id: Option<String>,
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
    clock: &'a dyn Clock,
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
        clock: &'a dyn Clock,
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
            clock,
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
    ) -> Result<RunOutcome, RunError> {
        if let Some(outcome) = &state.terminal_outcome {
            return Ok(outcome.clone());
        }

        if !state.started {
            self.audit(state, AuditEventKind::RunCreated, AuditOutcome::Success)
                .await?;
            state.started = true;
            if state.cancelled || self.cancellation.is_cancelled() {
                self.audit(state, AuditEventKind::RunCancelled, AuditOutcome::Failure)
                    .await?;
                return Ok(state.finish(RunOutcome::Cancelled));
            }
            if let Some(skill) = state.context.required_skill_failure() {
                let outcome = RunOutcome::RequiredSkillUnavailable {
                    skill_id: skill.skill_id().to_owned(),
                    version: skill.version().to_owned(),
                    reason: skill.reason().unwrap_or("unavailable"),
                };
                self.audit(state, AuditEventKind::RunFailed, AuditOutcome::Failure)
                    .await?;
                return Ok(state.finish(outcome));
            }
        }

        loop {
            if state.cancelled || self.cancellation.is_cancelled() {
                self.audit(state, AuditEventKind::RunCancelled, AuditOutcome::Failure)
                    .await?;
                return Ok(state.finish(RunOutcome::Cancelled));
            }

            if self
                .wall_time_remaining(state)
                .is_some_and(|remaining| remaining.is_zero())
            {
                return self.exhaust_budget(state, BudgetKind::WallClock).await;
            }

            if let Some(pending) = state.pending_action.clone() {
                // Approval is not a permanent authorization grant. A parked
                // action must still fit the current capability ceiling.
                if let PolicyDecision::Deny(reason) =
                    self.policy.evaluate(&pending.action, capabilities)
                {
                    self.actions
                        .deny(&pending.action, &reason, self.clock.now())
                        .await?;
                    self.audit_action_with_denial(
                        state,
                        AuditEventKind::PolicyDenied,
                        AuditOutcome::Denied,
                        &pending.action,
                        &reason,
                    )
                    .await?;
                    state.pending_action = None;
                    return Ok(state.finish(RunOutcome::Denied { reason }));
                }
                match self
                    .resolve_approval(
                        state,
                        pending.action.clone(),
                        pending.approval_id,
                        pending.tool_call_id.clone(),
                    )
                    .await?
                {
                    ActionProgress::Ready(action, tool_call_id) => {
                        state.pending_action = None;
                        if let Some(outcome) = self.execute(state, action, tool_call_id).await? {
                            return Ok(outcome);
                        }
                        continue;
                    }
                    ActionProgress::Blocked(outcome, pending) => {
                        state.pending_action = Some(pending);
                        return Ok(outcome);
                    }
                    ActionProgress::Terminal(outcome) => {
                        state.pending_action = None;
                        return Ok(state.finish(outcome));
                    }
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
                    return self.exhaust_budget(state, BudgetKind::ModelTurns).await;
                }
                let generation = self.model.generate(
                    ModelInput::new(state.messages.clone())
                        .with_data_class(state.data_class)
                        .with_tools(self.normalizer.model_tools(&state.context)),
                );
                let output = match self.wall_time_remaining(state) {
                    Some(remaining) => match tokio::time::timeout(remaining, generation).await {
                        Ok(output) => output?,
                        Err(_) => {
                            return self.exhaust_budget(state, BudgetKind::WallClock).await;
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
                    self.audit(state, AuditEventKind::RunCompleted, AuditOutcome::Success)
                        .await?;
                    return Ok(state.finish(RunOutcome::Completed { text }));
                }
                NextOutput::Action {
                    proposal,
                    attribution,
                } => {
                    if state.actions >= state.budget.max_actions {
                        return self.exhaust_budget(state, BudgetKind::Actions).await;
                    }
                    self.audit(state, AuditEventKind::ActionProposed, AuditOutcome::Pending)
                        .await?;
                    let tool_call = proposal.tool_call().cloned();
                    let action = self.normalizer.normalize(&state.context, proposal)?;
                    let tool_call_id = tool_call.as_ref().map(|call| call.id().to_owned());
                    if let Some(tool_call) = tool_call {
                        state
                            .messages
                            .push(ModelMessage::assistant_tool_call(tool_call));
                    }
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
                    self.actions.persist(&action, self.clock.now()).await?;
                    self.audit_action(
                        state,
                        AuditEventKind::ActionNormalized,
                        AuditOutcome::Success,
                        &action,
                    )
                    .await?;

                    let decision = self.policy.evaluate(&action, &evaluation_capabilities);
                    match &decision {
                        PolicyDecision::Deny(reason) => {
                            self.actions.deny(&action, reason, self.clock.now()).await?;
                            self.audit_action_with_denial(
                                state,
                                AuditEventKind::PolicyDenied,
                                AuditOutcome::Denied,
                                &action,
                                reason,
                            )
                            .await?;
                            return Ok(state.finish(RunOutcome::Denied {
                                reason: reason.clone(),
                            }));
                        }
                        PolicyDecision::Allow => {
                            self.audit_action(
                                state,
                                AuditEventKind::PolicyAllowed,
                                AuditOutcome::Success,
                                &action,
                            )
                            .await?;
                            let authorization = authorize_dispatch(
                                &decision,
                                &action,
                                &self.policy_version,
                                None,
                                self.clock.now(),
                            )?;
                            if let Some(outcome) = self
                                .execute(
                                    state,
                                    AuthorizedAction::new(action, authorization),
                                    tool_call_id,
                                )
                                .await?
                            {
                                return Ok(outcome);
                            }
                        }
                        PolicyDecision::RequireApproval => {
                            match self
                                .approvals
                                .resolve(&action, &self.policy_version, self.clock.now())
                                .await?
                            {
                                ApprovalResolution::Pending(approval_id) => {
                                    self.audit_action(
                                        state,
                                        AuditEventKind::ApprovalCreated,
                                        AuditOutcome::Pending,
                                        &action,
                                    )
                                    .await?;
                                    state.pending_action = Some(PendingAction {
                                        action,
                                        approval_id,
                                        tool_call_id,
                                    });
                                    return Ok(RunOutcome::AwaitingApproval { approval_id });
                                }
                                ApprovalResolution::Granted(mut approval) => {
                                    let authorization = self
                                        .consume_approval(state, &action, &mut approval)
                                        .await?;
                                    if let Some(outcome) = self
                                        .execute(
                                            state,
                                            AuthorizedAction::new(action, authorization),
                                            tool_call_id,
                                        )
                                        .await?
                                    {
                                        return Ok(outcome);
                                    }
                                }
                                ApprovalResolution::Rejected(approval_id) => {
                                    self.audit_action(
                                        state,
                                        AuditEventKind::ApprovalRejected,
                                        AuditOutcome::Denied,
                                        &action,
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
        tool_call_id: Option<String>,
    ) -> Result<ActionProgress, RunError> {
        match self
            .approvals
            .resolve(&action, &self.policy_version, self.clock.now())
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
                        tool_call_id,
                    },
                ))
            }
            ApprovalResolution::Granted(mut approval) => {
                if approval.id() != expected_id {
                    return Err(RunError::ApprovalIdentityMismatch);
                }
                let authorization = self.consume_approval(state, &action, &mut approval).await?;
                Ok(ActionProgress::Ready(
                    AuthorizedAction::new(action, authorization),
                    tool_call_id,
                ))
            }
            ApprovalResolution::Rejected(approval_id) => {
                if approval_id != expected_id {
                    return Err(RunError::ApprovalIdentityMismatch);
                }
                self.audit_action(
                    state,
                    AuditEventKind::ApprovalRejected,
                    AuditOutcome::Denied,
                    &action,
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
    ) -> Result<crate::approval::DispatchAuthorization, RunError> {
        let authorization = authorize_dispatch(
            &PolicyDecision::RequireApproval,
            action,
            &self.policy_version,
            Some(approval),
            self.clock.now(),
        )?;
        self.audit_action(
            state,
            AuditEventKind::ApprovalGranted,
            AuditOutcome::Success,
            action,
        )
        .await?;
        self.audit_action(
            state,
            AuditEventKind::ApprovalConsumed,
            AuditOutcome::Success,
            action,
        )
        .await?;
        Ok(authorization)
    }

    async fn execute(
        &self,
        state: &mut RunState,
        action: AuthorizedAction,
        tool_call_id: Option<String>,
    ) -> Result<Option<RunOutcome>, RunError> {
        self.audit_action(
            state,
            AuditEventKind::ExecutionStarted,
            AuditOutcome::Pending,
            action.action(),
        )
        .await?;
        let cancellation = self.cancellation.clone();
        let mut execution = self.executor.execute(&action, cancellation.clone());
        let outcome = match self.wall_time_remaining(state) {
            Some(remaining) => {
                tokio::select! {
                    outcome = &mut execution => match outcome {
                        Ok(outcome) => outcome,
                        Err(error) => executor_error_unknown(error),
                    },
                    () = tokio::time::sleep(remaining) => {
                        cancellation.cancel();
                        match tokio::time::timeout(Duration::from_millis(250), &mut execution).await {
                            Ok(Ok(ExecutionOutcome::Succeeded(_)
                                | ExecutionOutcome::Proposed(_))) => {
                                self.audit_action(
                                    state,
                                    AuditEventKind::ExecutionSucceeded,
                                    AuditOutcome::Success,
                                    action.action(),
                                ).await?;
                                return Ok(Some(self.exhaust_budget(state, BudgetKind::WallClock)
                                    .await?));
                            }
                            Ok(Ok(outcome)) => outcome,
                            Ok(Err(error)) => executor_error_unknown(error),
                            Err(_) => ExecutionOutcome::Unknown(
                                "executor did not provide a definitive result after cancellation".into(),
                            ),
                        }
                    }
                }
            }
            None => match execution.await {
                Ok(outcome) => outcome,
                Err(error) => executor_error_unknown(error),
            },
        };
        match outcome {
            ExecutionOutcome::Succeeded(result) => {
                self.audit_action(
                    state,
                    AuditEventKind::ExecutionSucceeded,
                    AuditOutcome::Success,
                    action.action(),
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
                        self.exhaust_budget(state, BudgetKind::CapturedResultBytes)
                            .await?,
                    ));
                }
                state.captured_result_bytes += captured;
                state.messages.push(match tool_call_id {
                    Some(call_id) => ModelMessage::tool_result(call_id, result),
                    None => ModelMessage::new(ModelRole::Tool, result),
                });
                Ok(None)
            }
            ExecutionOutcome::Proposed(proposal) => {
                self.audit_action(
                    state,
                    AuditEventKind::ExecutionSucceeded,
                    AuditOutcome::Success,
                    action.action(),
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
                        self.exhaust_budget(state, BudgetKind::CapturedResultBytes)
                            .await?,
                    ));
                }
                state.captured_result_bytes += captured;
                state.pending_extension_proposal = Some(*proposal);
                Ok(None)
            }
            ExecutionOutcome::Failed(message) => {
                self.audit_action(
                    state,
                    AuditEventKind::ExecutionFailed,
                    AuditOutcome::Failure,
                    action.action(),
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::ExecutionFailed { message })))
            }
            ExecutionOutcome::Cancelled => {
                self.audit_action(
                    state,
                    AuditEventKind::ExecutionCancelled,
                    AuditOutcome::Failure,
                    action.action(),
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::Cancelled)))
            }
            ExecutionOutcome::TimedOut => {
                self.audit_action(
                    state,
                    AuditEventKind::ExecutionTimedOut,
                    AuditOutcome::Failure,
                    action.action(),
                )
                .await?;
                Ok(Some(state.finish(RunOutcome::ExecutionTimedOut)))
            }
            ExecutionOutcome::Unknown(message) => {
                self.audit_action(
                    state,
                    AuditEventKind::ExecutionUnknown,
                    AuditOutcome::Unknown,
                    action.action(),
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
    ) -> Result<RunOutcome, RunError> {
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                self.clock.now(),
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
    ) -> Result<(), AuditPortError> {
        self.audit_with_action(state, kind, outcome, None, None)
            .await
    }

    async fn audit_action(
        &self,
        state: &RunState,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        action: &ActionEnvelope,
    ) -> Result<(), AuditPortError> {
        self.audit_with_action(state, kind, outcome, Some(action), None)
            .await
    }

    async fn audit_action_with_denial(
        &self,
        state: &RunState,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        action: &ActionEnvelope,
        reason: &DenialReason,
    ) -> Result<(), AuditPortError> {
        self.audit_with_action(state, kind, outcome, Some(action), Some(reason))
            .await
    }

    async fn audit_with_action(
        &self,
        state: &RunState,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        action: Option<&ActionEnvelope>,
        denial_reason: Option<&DenialReason>,
    ) -> Result<(), AuditPortError> {
        let mut payload = vec![
            (
                "run_id",
                CanonicalValue::from(state.context.run_id().to_string()),
            ),
            (
                "actor",
                CanonicalValue::from(state.context.actor().subject()),
            ),
            (
                "actor_provider",
                CanonicalValue::from(state.context.actor().provider()),
            ),
        ];
        if let Some(action) = action {
            payload.extend([
                ("action_id", CanonicalValue::from(action.id().to_string())),
                ("action_kind", CanonicalValue::from(action.kind().as_str())),
                (
                    "required_capabilities",
                    CanonicalValue::Array(
                        action
                            .required_capabilities()
                            .iter()
                            .map(|capability| {
                                CanonicalValue::from(
                                    serde_json::to_string(capability)
                                        .expect("capability serialization cannot fail"),
                                )
                            })
                            .collect(),
                    ),
                ),
            ]);
        }
        if let Some(reason) = denial_reason {
            payload.push((
                "denial_reason",
                CanonicalValue::from(
                    serde_json::to_string(reason).expect("denial reason serialization cannot fail"),
                ),
            ));
        }
        if let Some(origin) = state.context.job_origin() {
            payload.extend([
                ("job_id", CanonicalValue::from(origin.job_id().to_string())),
                (
                    "job_revision",
                    CanonicalValue::from(
                        i64::try_from(origin.revision().as_u64()).unwrap_or(i64::MAX),
                    ),
                ),
                (
                    "scheduled_for",
                    CanonicalValue::from(
                        i64::try_from(origin.scheduled_for().as_u64()).unwrap_or(i64::MAX),
                    ),
                ),
                (
                    "occurrence_key",
                    CanonicalValue::from(origin.occurrence_key().as_str()),
                ),
            ]);
        }
        if !state.context.loaded_skills().is_empty() {
            payload.push((
                "loaded_skills",
                CanonicalValue::Array(
                    state
                        .context
                        .loaded_skills()
                        .iter()
                        .map(|skill| {
                            CanonicalValue::object([
                                ("skill_id", CanonicalValue::from(skill.skill_id())),
                                ("version", CanonicalValue::from(skill.version())),
                                ("digest", CanonicalValue::from(skill.digest())),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        if !state.context.skill_loads().is_empty() {
            payload.push((
                "skill_loads",
                CanonicalValue::Array(
                    state
                        .context
                        .skill_loads()
                        .iter()
                        .map(|skill| {
                            CanonicalValue::object([
                                ("skill_id", CanonicalValue::from(skill.skill_id())),
                                ("version", CanonicalValue::from(skill.version())),
                                (
                                    "expected_digest",
                                    CanonicalValue::from(skill.expected_digest()),
                                ),
                                ("status", CanonicalValue::from(skill.status())),
                                (
                                    "reason",
                                    skill
                                        .reason()
                                        .map_or(CanonicalValue::Null, CanonicalValue::from),
                                ),
                                ("required", CanonicalValue::from(skill.required())),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                self.clock.now(),
                kind,
                outcome,
                Some(state.context.workspace_id()),
                CanonicalValue::object(payload),
            ))
            .await
    }
}

enum ActionProgress {
    Ready(AuthorizedAction, Option<String>),
    Blocked(RunOutcome, PendingAction),
    Terminal(RunOutcome),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    Completed {
        text: String,
    },
    AwaitingApproval {
        approval_id: ApprovalId,
    },
    ApprovalRejected {
        approval_id: ApprovalId,
    },
    Denied {
        reason: DenialReason,
    },
    BudgetExhausted(BudgetKind),
    Cancelled,
    ExecutionFailed {
        message: String,
    },
    ExecutionTimedOut,
    ExecutionUnknown {
        message: String,
    },
    RequiredSkillUnavailable {
        skill_id: String,
        version: String,
        reason: &'static str,
    },
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
