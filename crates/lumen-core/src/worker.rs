//! Pinned worker assignments.  This module deliberately contains no executor:
//! callers must run an assignment through `RunOrchestrator`.
use std::{collections::BTreeSet, fmt, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    action::{ActionKind, RunId},
    capability::{
        Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope,
        WorkspacePath,
    },
    context::{
        ContextDigest, ModelDataPolicy, ProjectedProviderModelPort, ProjectionId, TaskProjection,
    },
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
    model::{ActionProposal, ModelFuture, ModelInput, ModelPort, ModelTool},
    orchestration::{OrchestrationId, TaskGraph, TaskNode, TaskNodeId},
    provider::{ModelCapability, ModelProfile, ModelProfileId, ProviderAdapter, ProviderConfig},
    run::{ActionNormalizer, NormalizationError, RunBudget, RunContext},
};

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
uuid_id!(WorkerAttemptId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerAttemptState {
    Reserved,
    Running,
    AwaitingApproval,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}
impl WorkerAttemptState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Running => "running",
            Self::AwaitingApproval => "awaiting_approval",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "reserved" => Self::Reserved,
            "running" => Self::Running,
            "awaiting_approval" => Self::AwaitingApproval,
            "completed" => Self::Completed,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "unknown" => Self::Unknown,
            _ => return None,
        })
    }
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Unknown
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRunBudget {
    max_model_turns: u32,
    max_actions: u32,
    max_wall_time_millis: u64,
    max_captured_result_bytes: usize,
}
impl WorkerRunBudget {
    pub fn new(
        max_model_turns: u32,
        max_actions: u32,
        max_wall_time_millis: u64,
        max_captured_result_bytes: usize,
    ) -> Result<Self, WorkerError> {
        if max_model_turns == 0
            || max_actions == 0
            || max_wall_time_millis == 0
            || max_captured_result_bytes == 0
        {
            return Err(WorkerError::InvalidBudget);
        }
        Ok(Self {
            max_model_turns,
            max_actions,
            max_wall_time_millis,
            max_captured_result_bytes,
        })
    }
    pub const fn max_model_turns(self) -> u32 {
        self.max_model_turns
    }
    pub const fn max_actions(self) -> u32 {
        self.max_actions
    }
    pub const fn max_wall_time_millis(self) -> u64 {
        self.max_wall_time_millis
    }
    pub const fn max_captured_result_bytes(self) -> usize {
        self.max_captured_result_bytes
    }
    pub fn as_run_budget(self) -> RunBudget {
        RunBudget::limited(
            self.max_model_turns,
            self.max_actions,
            Duration::from_millis(self.max_wall_time_millis),
            self.max_captured_result_bytes,
        )
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WorkerCapabilityScope {
    Workspace,
    Path {
        path: String,
    },
    Exact {
        resource_type: String,
        value: String,
    },
}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerCapabilityGrant {
    name: CapabilityName,
    scope: WorkerCapabilityScope,
}
impl WorkerCapabilityGrant {
    pub const fn workspace(name: CapabilityName) -> Self {
        Self {
            name,
            scope: WorkerCapabilityScope::Workspace,
        }
    }
    pub fn path(name: CapabilityName, path: impl Into<String>) -> Result<Self, WorkerError> {
        let path = path.into();
        WorkspacePath::parse(&path).map_err(|_| WorkerError::InvalidCapabilityGrant)?;
        Ok(Self {
            name,
            scope: WorkerCapabilityScope::Path { path },
        })
    }
    pub fn exact(
        name: CapabilityName,
        resource_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, WorkerError> {
        let resource_type = resource_type.into();
        let value = value.into();
        ResourceScope::exact(&resource_type, &value)
            .map_err(|_| WorkerError::InvalidCapabilityGrant)?;
        Ok(Self {
            name,
            scope: WorkerCapabilityScope::Exact {
                resource_type,
                value,
            },
        })
    }
    pub const fn name(&self) -> CapabilityName {
        self.name
    }
    pub fn to_capability(&self, workspace_id: WorkspaceId) -> Result<Capability, WorkerError> {
        let scope = match &self.scope {
            WorkerCapabilityScope::Workspace => ResourceScope::workspace(workspace_id),
            WorkerCapabilityScope::Path { path } => ResourceScope::path(
                workspace_id,
                WorkspacePath::parse(path).map_err(|_| WorkerError::InvalidCapabilityGrant)?,
            ),
            WorkerCapabilityScope::Exact {
                resource_type,
                value,
            } => ResourceScope::exact(resource_type, value)
                .map_err(|_| WorkerError::InvalidCapabilityGrant)?,
        };
        Ok(Capability::new(self.name, scope))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerAssignment {
    orchestration_id: OrchestrationId,
    graph_revision: u64,
    task_node_id: TaskNodeId,
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    provider_id: crate::egress::ProviderId,
    provider_revision: u64,
    model_profile_id: ModelProfileId,
    model_profile_revision: u64,
    policy_revision: u64,
    projection_id: ProjectionId,
    projection_digest: ContextDigest,
    data_class: DataClass,
    prompt: String,
    grants: BTreeSet<WorkerCapabilityGrant>,
    allowed_tools: BTreeSet<String>,
    budget: WorkerRunBudget,
}
impl WorkerAssignment {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        graph: &TaskGraph,
        node: &TaskNode,
        actor: PrincipalId,
        provider: &ProviderConfig,
        profile: &ModelProfile,
        policy: &ModelDataPolicy,
        projection: &TaskProjection,
        grants: impl IntoIterator<Item = WorkerCapabilityGrant>,
        budget: WorkerRunBudget,
    ) -> Result<Self, WorkerError> {
        let value = Self {
            orchestration_id: graph.orchestration_id(),
            graph_revision: graph.revision(),
            task_node_id: node.id(),
            workspace_id: graph.workspace_id(),
            actor,
            provider_id: provider.id().clone(),
            provider_revision: provider.revision(),
            model_profile_id: profile.id().clone(),
            model_profile_revision: profile.revision(),
            policy_revision: policy.revision(),
            projection_id: projection.id(),
            projection_digest: projection.digest().clone(),
            data_class: node.requirements().data_class(),
            prompt: "Execute the task described in the verified projection.".to_owned(),
            grants: grants.into_iter().collect(),
            allowed_tools: node
                .requirements()
                .required_tools()
                .iter()
                .map(|tool| tool.as_str().to_owned())
                .collect(),
            budget,
        };
        value.validate_materialized(graph, node, provider, profile, policy, projection)?;
        value.capability_set()?;
        Ok(value)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        provider_id: crate::egress::ProviderId,
        provider_revision: u64,
        model_profile_id: ModelProfileId,
        model_profile_revision: u64,
        policy_revision: u64,
        projection_id: ProjectionId,
        projection_digest: ContextDigest,
        data_class: DataClass,
        prompt: String,
        grants: BTreeSet<WorkerCapabilityGrant>,
        allowed_tools: BTreeSet<String>,
        budget: WorkerRunBudget,
    ) -> Result<Self, WorkerError> {
        if graph_revision == 0
            || provider_revision == 0
            || model_profile_revision == 0
            || policy_revision == 0
            || prompt.is_empty()
            || prompt.len() > 8192
            || prompt.trim() != prompt
            || prompt
                .chars()
                .any(|c| c.is_control() && c != '\n' && c != '\t')
            || data_class == DataClass::Secret
            || allowed_tools
                .iter()
                .any(|tool| ActionKind::new(tool).is_err())
        {
            return Err(WorkerError::InvalidAssignment);
        }
        let value = Self {
            orchestration_id,
            graph_revision,
            task_node_id,
            workspace_id,
            actor,
            provider_id,
            provider_revision,
            model_profile_id,
            model_profile_revision,
            policy_revision,
            projection_id,
            projection_digest,
            data_class,
            prompt,
            grants,
            allowed_tools,
            budget,
        };
        value.capability_set()?;
        Ok(value)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn validate_materialized(
        &self,
        graph: &TaskGraph,
        node: &TaskNode,
        provider: &ProviderConfig,
        profile: &ModelProfile,
        policy: &ModelDataPolicy,
        projection: &TaskProjection,
    ) -> Result<(), WorkerError> {
        if graph.orchestration_id() != self.orchestration_id
            || graph.revision() != self.graph_revision
            || graph.workspace_id() != self.workspace_id
            || node.id() != self.task_node_id
            || self.prompt != "Execute the task described in the verified projection."
            || provider.id() != &self.provider_id
            || provider.revision() != self.provider_revision
            || profile.id() != &self.model_profile_id
            || profile.revision() != self.model_profile_revision
            || profile.provider_id() != &self.provider_id
            || profile.provider_revision() != self.provider_revision
            || policy.workspace_id() != self.workspace_id
            || policy.model_profile_id() != &self.model_profile_id
            || policy.model_profile_revision() != self.model_profile_revision
            || policy.revision() != self.policy_revision
            || projection.id() != self.projection_id
            || projection.workspace_id() != self.workspace_id
            || projection.task_key() != node.key()
            || projection.model_profile_id() != &self.model_profile_id
            || projection.model_profile_revision() != self.model_profile_revision
            || projection.policy_revision() != self.policy_revision
            || projection.digest() != &self.projection_digest
            || self.data_class != node.requirements().data_class()
        {
            return Err(WorkerError::BindingMismatch);
        }
        if !provider.enabled() || !profile.enabled() {
            return Err(WorkerError::DisabledProviderOrProfile);
        }
        policy
            .validate_profile(profile)
            .map_err(|_| WorkerError::BindingMismatch)?;
        projection
            .validate_for(profile, policy)
            .map_err(|_| WorkerError::BindingMismatch)?;
        let requirements = node.requirements();
        if !requirements.allowed_model_profiles().is_empty()
            && !requirements
                .allowed_model_profiles()
                .iter()
                .any(|allowed| allowed.matches(profile))
            || !requirements
                .required_model_capabilities()
                .iter()
                .all(|capability| profile.capabilities().contains(capability))
            || (!self.allowed_tools.is_empty()
                && !profile
                    .capabilities()
                    .contains(ModelCapability::ToolCalling))
        {
            return Err(WorkerError::ProfileNotEligible);
        }
        let expected: BTreeSet<String> = requirements
            .required_tools()
            .iter()
            .map(|tool| tool.as_str().to_owned())
            .collect();
        if expected != self.allowed_tools {
            return Err(WorkerError::ToolSetMismatch);
        }
        if !requirements
            .required_compartments()
            .iter()
            .all(|compartment| projection.compartments().contains(compartment))
            || rank(projection.classification()) > rank(self.data_class)
        {
            return Err(WorkerError::ProjectionTooBroad);
        }
        Ok(())
    }
    pub const fn orchestration_id(&self) -> OrchestrationId {
        self.orchestration_id
    }
    pub const fn graph_revision(&self) -> u64 {
        self.graph_revision
    }
    pub const fn task_node_id(&self) -> TaskNodeId {
        self.task_node_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
    pub const fn provider_id(&self) -> &crate::egress::ProviderId {
        &self.provider_id
    }
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    pub const fn model_profile_id(&self) -> &ModelProfileId {
        &self.model_profile_id
    }
    pub const fn model_profile_revision(&self) -> u64 {
        self.model_profile_revision
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub const fn projection_id(&self) -> ProjectionId {
        self.projection_id
    }
    pub fn projection_digest(&self) -> &ContextDigest {
        &self.projection_digest
    }
    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }
    pub fn prompt(&self) -> &str {
        &self.prompt
    }
    pub fn grants(&self) -> &BTreeSet<WorkerCapabilityGrant> {
        &self.grants
    }
    pub fn allowed_tools(&self) -> &BTreeSet<String> {
        &self.allowed_tools
    }
    pub const fn budget(&self) -> WorkerRunBudget {
        self.budget
    }
    pub fn capability_set(&self) -> Result<CapabilitySet, WorkerError> {
        self.grants
            .iter()
            .map(|grant| grant.to_capability(self.workspace_id))
            .collect::<Result<Vec<_>, _>>()
            .map(CapabilitySet::new)
    }
    pub fn effective_capabilities(
        &self,
        parent: CapabilitySet,
    ) -> Result<EffectiveCapabilities, WorkerError> {
        Ok(EffectiveCapabilities::new([parent, self.capability_set()?]))
    }
    pub fn run_context(&self, run_id: RunId) -> RunContext {
        RunContext::new(run_id, self.workspace_id, self.actor.clone())
    }
}

pub struct ToolRestrictedNormalizer<'a> {
    inner: &'a dyn ActionNormalizer,
    allowed_tools: &'a BTreeSet<String>,
}
impl<'a> ToolRestrictedNormalizer<'a> {
    pub const fn new(inner: &'a dyn ActionNormalizer, allowed_tools: &'a BTreeSet<String>) -> Self {
        Self {
            inner,
            allowed_tools,
        }
    }
}
impl ActionNormalizer for ToolRestrictedNormalizer<'_> {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<crate::action::ActionEnvelope, NormalizationError> {
        if !self.allowed_tools.contains(proposal.kind()) {
            return Err(NormalizationError::new(
                "worker proposed an action outside its assigned tool set",
            ));
        }
        self.inner.normalize(context, proposal)
    }
    fn model_tools(&self, context: &RunContext) -> Vec<ModelTool> {
        self.inner
            .model_tools(context)
            .into_iter()
            .filter(|tool| self.allowed_tools.contains(tool.action_kind()))
            .collect()
    }
}

pub struct OwnedProjectedModel {
    provider: Arc<dyn ProviderAdapter>,
    profile: ModelProfile,
    policy: ModelDataPolicy,
    projection: TaskProjection,
    cancellation: CancellationToken,
}
impl OwnedProjectedModel {
    pub fn new(
        provider: Arc<dyn ProviderAdapter>,
        profile: ModelProfile,
        policy: ModelDataPolicy,
        projection: TaskProjection,
        cancellation: CancellationToken,
    ) -> Result<Self, WorkerError> {
        ProjectedProviderModelPort::new(provider.as_ref(), &profile, &policy, &projection)
            .map_err(|_| WorkerError::BindingMismatch)?;
        Ok(Self {
            provider,
            profile,
            policy,
            projection,
            cancellation,
        })
    }
}
impl ModelPort for OwnedProjectedModel {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        Box::pin(async move {
            ProjectedProviderModelPort::new(
                self.provider.as_ref(),
                &self.profile,
                &self.policy,
                &self.projection,
            )
            .map_err(|error| crate::model::ModelError::new(error.to_string()))?
            .with_cancellation(self.cancellation.child_token())
            .generate(input)
            .await
        })
    }
}
const fn rank(value: DataClass) -> u8 {
    match value {
        DataClass::Public => 0,
        DataClass::Workspace => 1,
        DataClass::Sensitive => 2,
        DataClass::Secret => 3,
    }
}
#[derive(Debug, Error)]
pub enum WorkerError {
    #[error("worker assignment is invalid")]
    InvalidAssignment,
    #[error("worker run budget is invalid")]
    InvalidBudget,
    #[error("worker capability grant is invalid")]
    InvalidCapabilityGrant,
    #[error("worker assignment does not match its pinned graph/model/policy/projection")]
    BindingMismatch,
    #[error("worker provider or model profile is disabled")]
    DisabledProviderOrProfile,
    #[error("selected model profile cannot satisfy this task")]
    ProfileNotEligible,
    #[error("worker tool set does not equal the task's required tool set")]
    ToolSetMismatch,
    #[error("worker projection is broader than the task's declared context requirements")]
    ProjectionTooBroad,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_budget_and_capability_grants_fail_closed() {
        assert!(WorkerRunBudget::new(0, 1, 1, 1).is_err());
        assert!(WorkerCapabilityGrant::path(CapabilityName::FsRead, "../escape").is_err());
        assert!(WorkerCapabilityGrant::exact(CapabilityName::FsRead, "", "file").is_err());
        assert_eq!(
            WorkerAttemptState::parse("unknown"),
            Some(WorkerAttemptState::Unknown)
        );
        assert!(WorkerAttemptState::Unknown.is_terminal());
        assert_eq!(WorkerAttemptState::parse("other"), None);
    }
}
