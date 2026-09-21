use crate::{
    action::ActionKind,
    approval::TimestampMillis,
    context::{CompartmentId, ContextDigest, ModelDataPolicy, ProjectionTaskKey},
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
    provider::{ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
use thiserror::Error;
use uuid::Uuid;
pub const MAX_TASK_NODES: usize = 256;
pub const MAX_DEPENDENCIES_PER_NODE: usize = 32;
pub const MAX_TASK_DESCRIPTION_BYTES: usize = 8 * 1024;
macro_rules!uuid_id{($name:ident)=>{#[derive(Clone,Copy,Debug,Eq,Hash,Ord,PartialEq,PartialOrd,Serialize)]#[serde(transparent)]pub struct$name(Uuid);impl$name{pub fn new()->Self{Self(Uuid::new_v4())}pub const fn from_uuid(value:Uuid)->Self{Self(value)}pub const fn as_uuid(&self)->&Uuid{&self.0}}impl Default for$name{fn default()->Self{Self::new()}}impl fmt::Display for$name{fn fmt(&self,formatter:&mut fmt::Formatter<'_>)->fmt::Result{self.0.fmt(formatter)}}};}
uuid_id!(OrchestrationId);
uuid_id!(TaskNodeId);
pub type TaskNodeKey = ProjectionTaskKey;
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskOutputKind {
    Text,
    Patch,
    Design,
    Test,
    Plan,
    Review,
    Diagnostic,
    Artifact,
}
impl TaskOutputKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Patch => "patch",
            Self::Design => "design",
            Self::Test => "test",
            Self::Plan => "plan",
            Self::Review => "review",
            Self::Diagnostic => "diagnostic",
            Self::Artifact => "artifact",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "text" => Some(Self::Text),
            "patch" => Some(Self::Patch),
            "design" => Some(Self::Design),
            "test" => Some(Self::Test),
            "plan" => Some(Self::Plan),
            "review" => Some(Self::Review),
            "diagnostic" => Some(Self::Diagnostic),
            "artifact" => Some(Self::Artifact),
            _ => None,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskNodeState {
    Pending,
    Ready,
    Running,
    Blocked,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}
impl TaskNodeState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Running => "running",
            Self::Blocked => "blocked",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "ready" => Some(Self::Ready),
            "running" => Some(Self::Running),
            "blocked" => Some(Self::Blocked),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
    pub const fn is_readiness_managed(self) -> bool {
        matches!(self, Self::Pending | Self::Ready | Self::Blocked)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ModelProfileRef {
    id: ModelProfileId,
    revision: u64,
}
impl ModelProfileRef {
    pub fn new(id: ModelProfileId, revision: u64) -> Result<Self, OrchestrationError> {
        if revision == 0 {
            return Err(OrchestrationError::InvalidModelReference);
        }
        Ok(Self { id, revision })
    }
    pub fn from_profile(profile: &ModelProfile) -> Self {
        Self {
            id: profile.id().clone(),
            revision: profile.revision(),
        }
    }
    pub fn matches(&self, profile: &ModelProfile) -> bool {
        self.id == *profile.id() && self.revision == profile.revision()
    }
    fn validate(&self) -> Result<(), OrchestrationError> {
        if self.revision == 0 {
            return Err(OrchestrationError::InvalidModelReference);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskRequirements {
    #[serde(default)]
    required_model_capabilities: ModelCapabilities,
    #[serde(default)]
    allowed_model_profiles: BTreeSet<ModelProfileRef>,
    data_class: DataClass,
    #[serde(default)]
    required_compartments: BTreeSet<CompartmentId>,
    #[serde(default)]
    required_tools: BTreeSet<ActionKind>,
}
impl TaskRequirements {
    pub fn new(
        required_model_capabilities: ModelCapabilities,
        allowed_model_profiles: impl IntoIterator<Item = ModelProfileRef>,
        data_class: DataClass,
        required_compartments: impl IntoIterator<Item = CompartmentId>,
        required_tools: impl IntoIterator<Item = ActionKind>,
    ) -> Result<Self, OrchestrationError> {
        let value = Self {
            required_model_capabilities,
            allowed_model_profiles: allowed_model_profiles.into_iter().collect(),
            data_class,
            required_compartments: required_compartments.into_iter().collect(),
            required_tools: required_tools.into_iter().collect(),
        };
        value.validate()?;
        Ok(value)
    }
    pub fn required_model_capabilities(&self) -> &ModelCapabilities {
        &self.required_model_capabilities
    }
    pub fn allowed_model_profiles(&self) -> &BTreeSet<ModelProfileRef> {
        &self.allowed_model_profiles
    }
    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }
    pub fn required_compartments(&self) -> &BTreeSet<CompartmentId> {
        &self.required_compartments
    }
    pub fn required_tools(&self) -> &BTreeSet<ActionKind> {
        &self.required_tools
    }
    fn validate(&self) -> Result<(), OrchestrationError> {
        if self.data_class == DataClass::Secret {
            return Err(OrchestrationError::SecretModelContextDenied);
        }
        for profile in &self.allowed_model_profiles {
            profile.validate()?;
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskNodeLimits {
    max_input_tokens: u64,
    max_output_tokens: u64,
    max_attempts: u32,
}
impl TaskNodeLimits {
    pub fn new(
        max_input_tokens: u64,
        max_output_tokens: u64,
        max_attempts: u32,
    ) -> Result<Self, OrchestrationError> {
        let value = Self {
            max_input_tokens,
            max_output_tokens,
            max_attempts,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn max_input_tokens(self) -> u64 {
        self.max_input_tokens
    }
    pub const fn max_output_tokens(self) -> u64 {
        self.max_output_tokens
    }
    pub const fn max_attempts(self) -> u32 {
        self.max_attempts
    }
    fn validate(self) -> Result<(), OrchestrationError> {
        if self.max_input_tokens == 0 || self.max_output_tokens == 0 || self.max_attempts == 0 {
            return Err(OrchestrationError::InvalidLimits);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskNodeProposal {
    key: TaskNodeKey,
    description: String,
    expected_output: TaskOutputKind,
    #[serde(default)]
    depends_on: Vec<TaskNodeKey>,
    requirements: TaskRequirements,
    limits: TaskNodeLimits,
    #[serde(default)]
    deadline_at: Option<TimestampMillis>,
}
impl TaskNodeProposal {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        key: TaskNodeKey,
        description: impl Into<String>,
        expected_output: TaskOutputKind,
        depends_on: impl IntoIterator<Item = TaskNodeKey>,
        requirements: TaskRequirements,
        limits: TaskNodeLimits,
        deadline_at: Option<TimestampMillis>,
    ) -> Result<Self, OrchestrationError> {
        let value = Self {
            key,
            description: description.into(),
            expected_output,
            depends_on: depends_on.into_iter().collect(),
            requirements,
            limits,
            deadline_at,
        };
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<(), OrchestrationError> {
        validate_description(&self.description)?;
        self.requirements.validate()?;
        self.limits.validate()?;
        if self.depends_on.len() > MAX_DEPENDENCIES_PER_NODE {
            return Err(OrchestrationError::TooManyDependencies {
                task_key: self.key.clone(),
            });
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TaskGraphProposal {
    nodes: Vec<TaskNodeProposal>,
}
impl TaskGraphProposal {
    pub fn new(nodes: Vec<TaskNodeProposal>) -> Self {
        Self { nodes }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskNode {
    id: TaskNodeId,
    key: TaskNodeKey,
    description: String,
    expected_output: TaskOutputKind,
    requirements: TaskRequirements,
    limits: TaskNodeLimits,
    deadline_at: Option<TimestampMillis>,
}
impl TaskNode {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: TaskNodeId,
        key: TaskNodeKey,
        description: impl Into<String>,
        expected_output: TaskOutputKind,
        requirements: TaskRequirements,
        limits: TaskNodeLimits,
        deadline_at: Option<TimestampMillis>,
    ) -> Result<Self, OrchestrationError> {
        let description = description.into();
        validate_description(&description)?;
        requirements.validate()?;
        limits.validate()?;
        Ok(Self {
            id,
            key,
            description,
            expected_output,
            requirements,
            limits,
            deadline_at,
        })
    }
    pub const fn id(&self) -> TaskNodeId {
        self.id
    }
    pub fn key(&self) -> &TaskNodeKey {
        &self.key
    }
    pub fn description(&self) -> &str {
        &self.description
    }
    pub const fn expected_output(&self) -> TaskOutputKind {
        self.expected_output
    }
    pub fn requirements(&self) -> &TaskRequirements {
        &self.requirements
    }
    pub const fn limits(&self) -> TaskNodeLimits {
        self.limits
    }
    pub const fn deadline_at(&self) -> Option<TimestampMillis> {
        self.deadline_at
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskGraph {
    orchestration_id: OrchestrationId,
    workspace_id: WorkspaceId,
    revision: u64,
    created_by: PrincipalId,
    created_at: TimestampMillis,
    nodes: BTreeMap<TaskNodeId, TaskNode>,
    dependencies: BTreeMap<TaskNodeId, BTreeSet<TaskNodeId>>,
    digest: ContextDigest,
}
impl TaskGraph {
    pub fn from_proposal(
        orchestration_id: OrchestrationId,
        workspace_id: WorkspaceId,
        revision: u64,
        created_by: PrincipalId,
        proposal: TaskGraphProposal,
        created_at: TimestampMillis,
    ) -> Result<Self, OrchestrationError> {
        if revision == 0 {
            return Err(OrchestrationError::InvalidGraphRevision);
        }
        if proposal.nodes.is_empty() || proposal.nodes.len() > MAX_TASK_NODES {
            return Err(OrchestrationError::InvalidTaskCount);
        }
        let mut ids_by_key = BTreeMap::new();
        for node in &proposal.nodes {
            node.validate()?;
            if node
                .deadline_at
                .is_some_and(|deadline| deadline.as_u64() <= created_at.as_u64())
            {
                return Err(OrchestrationError::InvalidDeadline {
                    task_key: node.key.clone(),
                });
            }
            if ids_by_key
                .insert(node.key.clone(), TaskNodeId::new())
                .is_some()
            {
                return Err(OrchestrationError::DuplicateTaskKey(node.key.clone()));
            }
        }
        let mut nodes = BTreeMap::new();
        let mut edges = Vec::new();
        for proposal_node in proposal.nodes {
            let node_id = *ids_by_key
                .get(&proposal_node.key)
                .expect("task key was indexed in the first pass");
            let mut seen_dependencies = BTreeSet::new();
            for dependency_key in &proposal_node.depends_on {
                let dependency_id = *ids_by_key.get(dependency_key).ok_or_else(|| {
                    OrchestrationError::UnknownDependency {
                        task_key: proposal_node.key.clone(),
                        dependency: dependency_key.clone(),
                    }
                })?;
                if dependency_id == node_id {
                    return Err(OrchestrationError::SelfDependency {
                        task_key: proposal_node.key.clone(),
                    });
                }
                if !seen_dependencies.insert(dependency_id) {
                    return Err(OrchestrationError::DuplicateDependency {
                        task_key: proposal_node.key.clone(),
                        dependency: dependency_key.clone(),
                    });
                }
                edges.push((node_id, dependency_id));
            }
            let node = TaskNode::new(
                node_id,
                proposal_node.key,
                proposal_node.description,
                proposal_node.expected_output,
                proposal_node.requirements,
                proposal_node.limits,
                proposal_node.deadline_at,
            )?;
            nodes.insert(node_id, node);
        }
        Self::from_materialized(
            orchestration_id,
            workspace_id,
            revision,
            created_by,
            created_at,
            nodes,
            edges,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        orchestration_id: OrchestrationId,
        workspace_id: WorkspaceId,
        revision: u64,
        created_by: PrincipalId,
        created_at: TimestampMillis,
        nodes: Vec<TaskNode>,
        dependency_edges: Vec<(TaskNodeId, TaskNodeId)>,
        expected_digest: ContextDigest,
    ) -> Result<Self, OrchestrationError> {
        let node_count = nodes.len();
        let nodes = nodes
            .into_iter()
            .map(|node| (node.id(), node))
            .collect::<BTreeMap<_, _>>();
        if nodes.len() != node_count {
            return Err(OrchestrationError::DuplicateTaskNodeId);
        }
        Self::from_materialized(
            orchestration_id,
            workspace_id,
            revision,
            created_by,
            created_at,
            nodes,
            dependency_edges,
            Some(expected_digest),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn from_materialized(
        orchestration_id: OrchestrationId,
        workspace_id: WorkspaceId,
        revision: u64,
        created_by: PrincipalId,
        created_at: TimestampMillis,
        nodes: BTreeMap<TaskNodeId, TaskNode>,
        dependency_edges: Vec<(TaskNodeId, TaskNodeId)>,
        expected_digest: Option<ContextDigest>,
    ) -> Result<Self, OrchestrationError> {
        if revision == 0 {
            return Err(OrchestrationError::InvalidGraphRevision);
        }
        if nodes.is_empty() || nodes.len() > MAX_TASK_NODES {
            return Err(OrchestrationError::InvalidTaskCount);
        }
        let mut keys = BTreeSet::new();
        for node in nodes.values() {
            validate_description(node.description())?;
            node.requirements.validate()?;
            node.limits.validate()?;
            if !keys.insert(node.key.clone()) {
                return Err(OrchestrationError::DuplicateTaskKey(node.key.clone()));
            }
            if node
                .deadline_at
                .is_some_and(|deadline| deadline.as_u64() <= created_at.as_u64())
            {
                return Err(OrchestrationError::InvalidDeadline {
                    task_key: node.key.clone(),
                });
            }
        }
        let mut dependencies = nodes
            .keys()
            .copied()
            .map(|id| (id, BTreeSet::new()))
            .collect::<BTreeMap<_, _>>();
        for (node_id, dependency_id) in dependency_edges {
            let node = nodes
                .get(&node_id)
                .ok_or(OrchestrationError::UnknownTaskNode(node_id))?;
            if !nodes.contains_key(&dependency_id) {
                return Err(OrchestrationError::UnknownDependencyId {
                    task_key: node.key.clone(),
                    dependency_id,
                });
            }
            if node_id == dependency_id {
                return Err(OrchestrationError::SelfDependency {
                    task_key: node.key.clone(),
                });
            }
            let node_dependencies = dependencies
                .get_mut(&node_id)
                .expect("dependency map is initialized for every task node");
            if node_dependencies.len() >= MAX_DEPENDENCIES_PER_NODE {
                return Err(OrchestrationError::TooManyDependencies {
                    task_key: node.key.clone(),
                });
            }
            if !node_dependencies.insert(dependency_id) {
                return Err(OrchestrationError::DuplicateDependencyId {
                    task_key: node.key.clone(),
                    dependency_id,
                });
            }
        }
        let order = topological_order(&nodes, &dependencies)?;
        if order.len() != nodes.len() {
            return Err(OrchestrationError::CycleDetected);
        }
        let serialized = serialize_graph(
            orchestration_id,
            workspace_id,
            revision,
            &created_by,
            created_at,
            &nodes,
            &dependencies,
        )?;
        let digest = ContextDigest::from_bytes(serialized.as_bytes());
        if expected_digest
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(OrchestrationError::DigestMismatch);
        }
        Ok(Self {
            orchestration_id,
            workspace_id,
            revision,
            created_by,
            created_at,
            nodes,
            dependencies,
            digest,
        })
    }
    pub const fn orchestration_id(&self) -> OrchestrationId {
        self.orchestration_id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn created_by(&self) -> &PrincipalId {
        &self.created_by
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub const fn digest(&self) -> &ContextDigest {
        &self.digest
    }
    pub fn nodes(&self) -> impl Iterator<Item = &TaskNode> {
        self.nodes.values()
    }
    pub fn node(&self, id: TaskNodeId) -> Option<&TaskNode> {
        self.nodes.get(&id)
    }
    pub fn dependency_edges(&self) -> impl Iterator<Item = (TaskNodeId, TaskNodeId)> + '_ {
        self.dependencies
            .iter()
            .flat_map(|(node_id, dependencies)| {
                dependencies
                    .iter()
                    .map(move |dependency_id| (*node_id, *dependency_id))
            })
    }
    pub fn verify_digest(&self) -> Result<(), OrchestrationError> {
        let serialized = serialize_graph(
            self.orchestration_id,
            self.workspace_id,
            self.revision,
            &self.created_by,
            self.created_at,
            &self.nodes,
            &self.dependencies,
        )?;
        if ContextDigest::from_bytes(serialized.as_bytes()) != self.digest {
            return Err(OrchestrationError::DigestMismatch);
        }
        Ok(())
    }
    pub fn validate_against_catalog(
        &self,
        profiles: &[ModelProfile],
        policies: &[ModelDataPolicy],
    ) -> Result<(), OrchestrationError> {
        self.verify_digest()?;
        for node in self.nodes.values() {
            let eligible = profiles
                .iter()
                .any(|profile| profile_is_eligible(self.workspace_id, node, profile, policies));
            if !eligible {
                return Err(OrchestrationError::NoEligibleModel {
                    task_key: node.key.clone(),
                });
            }
        }
        Ok(())
    }
    pub fn initial_state_revisions(&self, created_at: TimestampMillis) -> Vec<TaskStateRevision> {
        topological_order(&self.nodes, &self.dependencies)
            .expect("validated graph remains acyclic")
            .into_iter()
            .map(|node_id| {
                let initial_state = if self
                    .dependencies
                    .get(&node_id)
                    .is_some_and(BTreeSet::is_empty)
                {
                    TaskNodeState::Ready
                } else {
                    TaskNodeState::Pending
                };
                TaskStateRevision::initial(
                    self.orchestration_id,
                    self.revision,
                    node_id,
                    initial_state,
                    created_at,
                )
            })
            .collect()
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskStateRevision {
    orchestration_id: OrchestrationId,
    graph_revision: u64,
    task_node_id: TaskNodeId,
    revision: u64,
    state: TaskNodeState,
    attempt_count: u32,
    created_at: TimestampMillis,
}
impl TaskStateRevision {
    pub fn initial(
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        state: TaskNodeState,
        created_at: TimestampMillis,
    ) -> Self {
        debug_assert!(graph_revision > 0);
        debug_assert!(matches!(
            state,
            TaskNodeState::Pending | TaskNodeState::Ready
        ));
        Self {
            orchestration_id,
            graph_revision,
            task_node_id,
            revision: 1,
            state,
            attempt_count: 0,
            created_at,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        revision: u64,
        state: TaskNodeState,
        attempt_count: u32,
        max_attempts: u32,
        created_at: TimestampMillis,
    ) -> Result<Self, OrchestrationError> {
        if graph_revision == 0
            || revision == 0
            || attempt_count > max_attempts
            || (state == TaskNodeState::Running && attempt_count == 0)
        {
            return Err(OrchestrationError::InvalidTaskState);
        }
        Ok(Self {
            orchestration_id,
            graph_revision,
            task_node_id,
            revision,
            state,
            attempt_count,
            created_at,
        })
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
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn state(&self) -> TaskNodeState {
        self.state
    }
    pub const fn attempt_count(&self) -> u32 {
        self.attempt_count
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub fn transition(
        &self,
        next_state: TaskNodeState,
        max_attempts: u32,
        created_at: TimestampMillis,
    ) -> Result<Self, OrchestrationError> {
        if !transition_allowed(self.state, next_state) {
            return Err(OrchestrationError::InvalidStateTransition {
                from: self.state,
                to: next_state,
            });
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(OrchestrationError::RevisionOverflow)?;
        let attempt_count = if next_state == TaskNodeState::Running {
            let next_attempt = self
                .attempt_count
                .checked_add(1)
                .ok_or(OrchestrationError::AttemptOverflow)?;
            if next_attempt > max_attempts {
                return Err(OrchestrationError::AttemptLimitExceeded);
            }
            next_attempt
        } else {
            self.attempt_count
        };
        Ok(Self {
            orchestration_id: self.orchestration_id,
            graph_revision: self.graph_revision,
            task_node_id: self.task_node_id,
            revision,
            state: next_state,
            attempt_count,
            created_at,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrchestrationSnapshot {
    graph: TaskGraph,
    states: BTreeMap<TaskNodeId, TaskStateRevision>,
}
impl OrchestrationSnapshot {
    pub fn new(
        graph: TaskGraph,
        states: Vec<TaskStateRevision>,
    ) -> Result<Self, OrchestrationError> {
        graph.verify_digest()?;
        if states.len() != graph.nodes.len() {
            return Err(OrchestrationError::IncompleteStateSnapshot);
        }
        let mut indexed = BTreeMap::new();
        for state in states {
            let node = graph
                .node(state.task_node_id)
                .ok_or(OrchestrationError::UnknownTaskNode(state.task_node_id))?;
            if state.orchestration_id != graph.orchestration_id
                || state.graph_revision != graph.revision
                || state.attempt_count > node.limits.max_attempts
                || indexed.insert(state.task_node_id, state).is_some()
            {
                return Err(OrchestrationError::InvalidTaskState);
            }
        }
        Ok(Self {
            graph,
            states: indexed,
        })
    }
    pub const fn graph(&self) -> &TaskGraph {
        &self.graph
    }
    pub fn states(&self) -> impl Iterator<Item = &TaskStateRevision> {
        self.states.values()
    }
    pub fn state(&self, node_id: TaskNodeId) -> Option<&TaskStateRevision> {
        self.states.get(&node_id)
    }
    pub fn readiness_updates(
        &self,
        created_at: TimestampMillis,
    ) -> Result<Vec<TaskStateRevision>, OrchestrationError> {
        let mut updates = Vec::new();
        for node in self.graph.nodes.values() {
            let current = self
                .states
                .get(&node.id)
                .ok_or(OrchestrationError::IncompleteStateSnapshot)?;
            if !current.state.is_readiness_managed() {
                continue;
            }
            let dependencies = self
                .graph
                .dependencies
                .get(&node.id)
                .ok_or(OrchestrationError::IncompleteStateSnapshot)?;
            let desired = desired_readiness_state(dependencies, &self.states)?;
            if desired != current.state {
                updates.push(current.transition(desired, node.limits.max_attempts, created_at)?);
            }
        }
        Ok(updates)
    }
}
#[derive(Serialize)]
struct GraphDigestMaterial<'a> {
    schema_version: u16,
    orchestration_id: String,
    workspace_id: String,
    revision: u64,
    created_by_provider: &'a str,
    created_by_subject: &'a str,
    created_at: u64,
    nodes: Vec<NodeDigestMaterial<'a>>,
}
#[derive(Serialize)]
struct NodeDigestMaterial<'a> {
    node_id: String,
    task_key: &'a str,
    description: &'a str,
    expected_output: &'static str,
    dependencies: Vec<String>,
    requirements: &'a TaskRequirements,
    limits: TaskNodeLimits,
    deadline_at: Option<u64>,
}
fn serialize_graph(
    orchestration_id: OrchestrationId,
    workspace_id: WorkspaceId,
    revision: u64,
    created_by: &PrincipalId,
    created_at: TimestampMillis,
    nodes: &BTreeMap<TaskNodeId, TaskNode>,
    dependencies: &BTreeMap<TaskNodeId, BTreeSet<TaskNodeId>>,
) -> Result<String, OrchestrationError> {
    let material = GraphDigestMaterial {
        schema_version: 1,
        orchestration_id: orchestration_id.to_string(),
        workspace_id: workspace_id.to_string(),
        revision,
        created_by_provider: created_by.provider(),
        created_by_subject: created_by.subject(),
        created_at: created_at.as_u64(),
        nodes: nodes
            .values()
            .map(|node| NodeDigestMaterial {
                node_id: node.id.to_string(),
                task_key: node.key.as_str(),
                description: &node.description,
                expected_output: node.expected_output.as_str(),
                dependencies: dependencies
                    .get(&node.id)
                    .expect("validated graph has a dependency set for every node")
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                requirements: &node.requirements,
                limits: node.limits,
                deadline_at: node.deadline_at.map(TimestampMillis::as_u64),
            })
            .collect(),
    };
    Ok(serde_json::to_string(&material)?)
}
fn topological_order(
    nodes: &BTreeMap<TaskNodeId, TaskNode>,
    dependencies: &BTreeMap<TaskNodeId, BTreeSet<TaskNodeId>>,
) -> Result<Vec<TaskNodeId>, OrchestrationError> {
    let mut indegree = dependencies
        .iter()
        .map(|(node_id, node_dependencies)| (*node_id, node_dependencies.len()))
        .collect::<BTreeMap<_, _>>();
    if indegree.len() != nodes.len() {
        return Err(OrchestrationError::InvalidDependencyMap);
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(node_id, degree)| (*degree == 0).then_some(*node_id))
        .collect::<BTreeSet<_>>();
    let mut order = Vec::with_capacity(nodes.len());
    while let Some(node_id) = ready.iter().next().copied() {
        ready.remove(&node_id);
        order.push(node_id);
        for (candidate_id, candidate_dependencies) in dependencies {
            if candidate_dependencies.contains(&node_id) {
                let degree = indegree
                    .get_mut(candidate_id)
                    .ok_or(OrchestrationError::InvalidDependencyMap)?;
                *degree = degree
                    .checked_sub(1)
                    .ok_or(OrchestrationError::InvalidDependencyMap)?;
                if *degree == 0 {
                    ready.insert(*candidate_id);
                }
            }
        }
    }
    if order.len() != nodes.len() {
        return Err(OrchestrationError::CycleDetected);
    }
    Ok(order)
}
fn profile_is_eligible(
    workspace_id: WorkspaceId,
    node: &TaskNode,
    profile: &ModelProfile,
    policies: &[ModelDataPolicy],
) -> bool {
    let requirements = node.requirements();
    if !profile.enabled() {
        return false;
    }
    if !requirements.allowed_model_profiles.is_empty()
        && !requirements
            .allowed_model_profiles
            .iter()
            .any(|allowed| allowed.matches(profile))
    {
        return false;
    }
    if !requirements
        .required_model_capabilities
        .iter()
        .all(|required| profile.capabilities().contains(required))
        || (!requirements.required_tools.is_empty()
            && !profile
                .capabilities()
                .contains(ModelCapability::ToolCalling))
    {
        return false;
    }
    let requested_tokens = node
        .limits
        .max_input_tokens
        .checked_add(node.limits.max_output_tokens);
    if requested_tokens.is_none_or(|tokens| tokens > u64::from(profile.context_window_tokens())) {
        return false;
    }
    let Some(policy) = policies
        .iter()
        .filter(|policy| {
            policy.workspace_id() == workspace_id
                && policy.model_profile_id() == profile.id()
                && policy.model_profile_revision() == profile.revision()
        })
        .max_by_key(|policy| policy.revision())
    else {
        return false;
    };
    if policy.validate_profile(profile).is_err()
        || !policy
            .allowed_data_classes()
            .contains(&requirements.data_class)
        || !requirements
            .required_compartments
            .iter()
            .all(|compartment| policy.allowed_compartments().contains(compartment))
    {
        return false;
    }
    true
}
fn desired_readiness_state(
    dependencies: &BTreeSet<TaskNodeId>,
    states: &BTreeMap<TaskNodeId, TaskStateRevision>,
) -> Result<TaskNodeState, OrchestrationError> {
    if dependencies.is_empty() {
        return Ok(TaskNodeState::Ready);
    }
    let dependency_states = dependencies
        .iter()
        .map(|dependency_id| {
            states
                .get(dependency_id)
                .map(TaskStateRevision::state)
                .ok_or(OrchestrationError::IncompleteStateSnapshot)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if dependency_states.iter().any(|state| {
        matches!(
            state,
            TaskNodeState::Failed
                | TaskNodeState::Cancelled
                | TaskNodeState::Unknown
                | TaskNodeState::Blocked
        )
    }) {
        return Ok(TaskNodeState::Blocked);
    }
    if dependency_states
        .iter()
        .all(|state| *state == TaskNodeState::Completed)
    {
        return Ok(TaskNodeState::Ready);
    }
    Ok(TaskNodeState::Pending)
}
const fn transition_allowed(from: TaskNodeState, to: TaskNodeState) -> bool {
    matches!(
        (from, to),
        (TaskNodeState::Pending, TaskNodeState::Ready)
            | (TaskNodeState::Pending, TaskNodeState::Blocked)
            | (TaskNodeState::Pending, TaskNodeState::Cancelled)
            | (TaskNodeState::Ready, TaskNodeState::Pending)
            | (TaskNodeState::Ready, TaskNodeState::Blocked)
            | (TaskNodeState::Ready, TaskNodeState::Running)
            | (TaskNodeState::Ready, TaskNodeState::Cancelled)
            | (TaskNodeState::Blocked, TaskNodeState::Pending)
            | (TaskNodeState::Blocked, TaskNodeState::Ready)
            | (TaskNodeState::Blocked, TaskNodeState::Cancelled)
            | (TaskNodeState::Running, TaskNodeState::Completed)
            | (TaskNodeState::Running, TaskNodeState::Failed)
            | (TaskNodeState::Running, TaskNodeState::Cancelled)
            | (TaskNodeState::Running, TaskNodeState::Unknown)
    )
}
fn validate_description(value: &str) -> Result<(), OrchestrationError> {
    if value.is_empty()
        || value.len() > MAX_TASK_DESCRIPTION_BYTES
        || value.trim().is_empty()
        || value
            .chars()
            .any(|character| character.is_control() && character != '\n' && character != '\t')
    {
        return Err(OrchestrationError::InvalidDescription);
    }
    Ok(())
}
#[derive(Debug, Error)]
pub enum OrchestrationError {
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("graph digest does not match immutable graph content")]
    DigestMismatch,
    #[error("graph revision must be greater than zero")]
    InvalidGraphRevision,
    #[error("task graph must contain between 1 and 256 nodes")]
    InvalidTaskCount,
    #[error("task description is invalid")]
    InvalidDescription,
    #[error("model profile reference is invalid")]
    InvalidModelReference,
    #[error("task limits must be greater than zero")]
    InvalidLimits,
    #[error("secret-class data may not be requested as model context")]
    SecretModelContextDenied,
    #[error("duplicate task key: {0:?}")]
    DuplicateTaskKey(TaskNodeKey),
    #[error("unknown dependency {dependency:?} referenced by {task_key:?}")]
    UnknownDependency {
        task_key: TaskNodeKey,
        dependency: TaskNodeKey,
    },
    #[error("task {task_key:?} depends on itself")]
    SelfDependency { task_key: TaskNodeKey },
    #[error("duplicate dependency {dependency:?} referenced by {task_key:?}")]
    DuplicateDependency {
        task_key: TaskNodeKey,
        dependency: TaskNodeKey,
    },
    #[error("duplicate task-node ID in stored graph")]
    DuplicateTaskNodeId,
    #[error("unknown task-node ID: {0}")]
    UnknownTaskNode(TaskNodeId),
    #[error("unknown dependency ID {dependency_id} referenced by {task_key:?}")]
    UnknownDependencyId {
        task_key: TaskNodeKey,
        dependency_id: TaskNodeId,
    },
    #[error("duplicate dependency ID {dependency_id} referenced by {task_key:?}")]
    DuplicateDependencyId {
        task_key: TaskNodeKey,
        dependency_id: TaskNodeId,
    },
    #[error("task {task_key:?} exceeds the dependency limit")]
    TooManyDependencies { task_key: TaskNodeKey },
    #[error("task {task_key:?} has a deadline at or before graph creation")]
    InvalidDeadline { task_key: TaskNodeKey },
    #[error("task graph contains a dependency cycle")]
    CycleDetected,
    #[error("task graph dependency map is invalid")]
    InvalidDependencyMap,
    #[error("no configured model/profile policy can satisfy task {task_key:?}")]
    NoEligibleModel { task_key: TaskNodeKey },
    #[error("task state is invalid")]
    InvalidTaskState,
    #[error("task-state transition {from:?} -> {to:?} is invalid")]
    InvalidStateTransition {
        from: TaskNodeState,
        to: TaskNodeState,
    },
    #[error("task-state revision overflow")]
    RevisionOverflow,
    #[error("task attempt counter overflow")]
    AttemptOverflow,
    #[error("task attempt limit exceeded")]
    AttemptLimitExceeded,
    #[error("task-state snapshot is incomplete or contains extra state")]
    IncompleteStateSnapshot,
}
