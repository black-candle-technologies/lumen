use crate::{
    approval::TimestampMillis,
    artifact::{ArtifactId, ArtifactValidationState},
    context::{
        CompartmentId, ContextDigest, ContextError, ContextSource, ModelDataPolicy,
        SourceProvenanceKind,
    },
    egress::DataClass,
    identity::WorkspaceId,
    orchestration::{OrchestrationId, TaskNode, TaskNodeId},
    provider::{ModelProfile, ModelProfileId, ModelTrustZone},
};
use serde::Serialize;
use std::{collections::BTreeSet, fmt};
use thiserror::Error;
use uuid::Uuid;
macro_rules!uid{($n:ident)=>{#[derive(Clone,Copy,Debug,Eq,Hash,Ord,PartialEq,PartialOrd,Serialize)]#[serde(transparent)]pub struct$n(Uuid);impl$n{pub fn new()->Self{Self(Uuid::new_v4())}pub const fn from_uuid(v:Uuid)->Self{Self(v)}}impl Default for$n{fn default()->Self{Self::new()}}impl fmt::Display for$n{fn fmt(&self,f:&mut fmt::Formatter<'_>)->fmt::Result{self.0.fmt(f)}}};}
uid!(TrustGateEvaluationId);
uid!(RecoveryCheckId);
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOmissionReason {
    WorkspaceMismatch,
    Secret,
    DataClass,
    Compartment,
    TaskClassification,
    ArtifactNotAccepted,
}
impl GateOmissionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkspaceMismatch => "workspace_mismatch",
            Self::Secret => "secret",
            Self::DataClass => "data_class",
            Self::Compartment => "compartment",
            Self::TaskClassification => "task_classification",
            Self::ArtifactNotAccepted => "artifact_not_accepted",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GateBlockReason {
    NoAllowedSources,
    MissingRequiredCompartment,
    RestrictedToolIsolationUnavailable,
    InstructionUnavailable,
}
impl GateBlockReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAllowedSources => "no_allowed_sources",
            Self::MissingRequiredCompartment => "missing_required_compartment",
            Self::RestrictedToolIsolationUnavailable => "restricted_tool_isolation_unavailable",
            Self::InstructionUnavailable => "instruction_unavailable",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GateSourceOrigin {
    Input,
    Instruction,
    Artifact {
        artifact_id: ArtifactId,
        content_hash: ContextDigest,
        origin_profile_id: ModelProfileId,
        origin_profile_revision: u64,
        origin_trust_zone: ModelTrustZone,
        validation: Option<ArtifactValidationState>,
    },
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateSource {
    source: ContextSource,
    origin: GateSourceOrigin,
}
impl GateSource {
    pub fn input(source: ContextSource) -> Self {
        Self {
            source,
            origin: GateSourceOrigin::Input,
        }
    }
    pub fn instruction(source: ContextSource) -> Self {
        Self {
            source,
            origin: GateSourceOrigin::Instruction,
        }
    }
    #[allow(clippy::too_many_arguments)]
    pub fn artifact(
        source: ContextSource,
        artifact_id: ArtifactId,
        content_hash: ContextDigest,
        origin_profile_id: ModelProfileId,
        origin_profile_revision: u64,
        origin_trust_zone: ModelTrustZone,
        validation: Option<ArtifactValidationState>,
    ) -> Result<Self, TrustGateError> {
        if source.provenance().kind() != SourceProvenanceKind::Artifact
            || source.provenance().reference() != format!("artifact://{artifact_id}")
            || origin_profile_revision == 0
        {
            return Err(TrustGateError::InvalidArtifactSource);
        }
        Ok(Self {
            source,
            origin: GateSourceOrigin::Artifact {
                artifact_id,
                content_hash,
                origin_profile_id,
                origin_profile_revision,
                origin_trust_zone,
                validation,
            },
        })
    }
    pub const fn source(&self) -> &ContextSource {
        &self.source
    }
    pub const fn origin(&self) -> &GateSourceOrigin {
        &self.origin
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GateSourceDecision {
    pub source_id: String,
    pub origin_kind: String,
    pub source_digest: String,
    pub classification: DataClass,
    pub compartments: BTreeSet<CompartmentId>,
    pub origin_artifact_id: Option<String>,
    pub origin_artifact_hash: Option<String>,
    pub origin_profile_id: Option<String>,
    pub origin_profile_revision: Option<u64>,
    pub origin_trust_zone: Option<ModelTrustZone>,
    pub selected: bool,
    pub omission: Option<GateOmissionReason>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TrustGateEvaluation {
    pub id: TrustGateEvaluationId,
    pub workspace_id: WorkspaceId,
    pub orchestration_id: OrchestrationId,
    pub graph_revision: u64,
    pub task_node_id: TaskNodeId,
    pub destination_profile_id: ModelProfileId,
    pub destination_profile_revision: u64,
    pub policy_revision: u64,
    pub destination_trust_zone: ModelTrustZone,
    pub mixed_trust: bool,
    pub allowed: bool,
    pub block_reason: Option<GateBlockReason>,
    pub missing_compartments: BTreeSet<CompartmentId>,
    pub decisions: Vec<GateSourceDecision>,
    pub projection_id: Option<String>,
    pub projection_digest: Option<String>,
    pub decision_digest: ContextDigest,
    pub created_at: TimestampMillis,
}
impl TrustGateEvaluation {
    #[allow(clippy::too_many_arguments)]
    fn new(
        workspace_id: WorkspaceId,
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        profile: &ModelProfile,
        policy_revision: u64,
        mixed_trust: bool,
        allowed: bool,
        block_reason: Option<GateBlockReason>,
        missing_compartments: BTreeSet<CompartmentId>,
        decisions: Vec<GateSourceDecision>,
        created_at: TimestampMillis,
    ) -> Result<Self, TrustGateError> {
        if graph_revision == 0 || policy_revision == 0 {
            return Err(TrustGateError::InvalidEvaluation);
        }
        let mut v = Self {
            id: TrustGateEvaluationId::new(),
            workspace_id,
            orchestration_id,
            graph_revision,
            task_node_id,
            destination_profile_id: profile.id().clone(),
            destination_profile_revision: profile.revision(),
            policy_revision,
            destination_trust_zone: profile.trust_zone(),
            mixed_trust,
            allowed,
            block_reason,
            missing_compartments,
            decisions,
            projection_id: None,
            projection_digest: None,
            decision_digest: ContextDigest::from_bytes(b""),
            created_at,
        };
        v.decision_digest = v.compute_digest()?;
        Ok(v)
    }
    pub fn bind_projection(
        mut self,
        id: impl ToString,
        digest: &ContextDigest,
    ) -> Result<Self, TrustGateError> {
        if !self.allowed || self.projection_id.is_some() {
            return Err(TrustGateError::InvalidEvaluation);
        }
        self.projection_id = Some(id.to_string());
        self.projection_digest = Some(digest.as_str().to_owned());
        self.decision_digest = self.compute_digest()?;
        Ok(self)
    }
    pub fn verify_digest(&self) -> Result<(), TrustGateError> {
        if self.compute_digest()? != self.decision_digest {
            return Err(TrustGateError::DigestMismatch);
        }
        Ok(())
    }
    fn compute_digest(&self) -> Result<ContextDigest, TrustGateError> {
        #[derive(Serialize)]
        struct M<'a> {
            workspace: String,
            orchestration: String,
            graph_revision: u64,
            task: String,
            profile: &'a str,
            profile_revision: u64,
            policy_revision: u64,
            trust: ModelTrustZone,
            mixed: bool,
            allowed: bool,
            block: Option<GateBlockReason>,
            missing: &'a BTreeSet<CompartmentId>,
            decisions: &'a [GateSourceDecision],
            projection_id: &'a Option<String>,
            projection_digest: &'a Option<String>,
            created_at: u64,
        }
        let m = M {
            workspace: self.workspace_id.to_string(),
            orchestration: self.orchestration_id.to_string(),
            graph_revision: self.graph_revision,
            task: self.task_node_id.to_string(),
            profile: self.destination_profile_id.as_str(),
            profile_revision: self.destination_profile_revision,
            policy_revision: self.policy_revision,
            trust: self.destination_trust_zone,
            mixed: self.mixed_trust,
            allowed: self.allowed,
            block: self.block_reason,
            missing: &self.missing_compartments,
            decisions: &self.decisions,
            projection_id: &self.projection_id,
            projection_digest: &self.projection_digest,
            created_at: self.created_at.as_u64(),
        };
        Ok(ContextDigest::from_bytes(&serde_json::to_vec(&m)?))
    }
}
#[derive(Clone, Debug)]
pub struct ProjectionSelection {
    pub evaluation: TrustGateEvaluation,
    pub selected_sources: Vec<ContextSource>,
}
#[allow(clippy::too_many_arguments)]
pub fn evaluate_exact_projection(
    workspace_id: WorkspaceId,
    orchestration_id: OrchestrationId,
    graph_revision: u64,
    node: &TaskNode,
    profile: &ModelProfile,
    policy: &ModelDataPolicy,
    mut sources: Vec<GateSource>,
    created_at: TimestampMillis,
) -> Result<ProjectionSelection, TrustGateError> {
    policy
        .validate_profile(profile)
        .map_err(|_| TrustGateError::BindingMismatch)?;
    if policy.workspace_id() != workspace_id {
        return Err(TrustGateError::BindingMismatch);
    }
    sources.sort_by_key(|v| v.source.id());
    let restricted_tools = profile.trust_zone() != ModelTrustZone::LocalTrusted
        && !node.requirements().required_tools().is_empty();
    let mut decisions = Vec::with_capacity(sources.len());
    let mut selected = Vec::new();
    let mut mixed = false;
    for item in sources {
        let source = item.source;
        let (
            origin_kind,
            origin_artifact_id,
            origin_artifact_hash,
            origin_profile_id,
            origin_profile_revision,
            origin_trust_zone,
            artifact_ok,
        ) = match item.origin {
            GateSourceOrigin::Input => ("input", None, None, None, None, None, true),
            GateSourceOrigin::Instruction => ("instruction", None, None, None, None, None, true),
            GateSourceOrigin::Artifact {
                artifact_id,
                content_hash,
                origin_profile_id,
                origin_profile_revision,
                origin_trust_zone,
                validation,
            } => (
                "artifact",
                Some(artifact_id.to_string()),
                Some(content_hash.as_str().to_owned()),
                Some(origin_profile_id.as_str().to_owned()),
                Some(origin_profile_revision),
                Some(origin_trust_zone),
                validation == Some(ArtifactValidationState::Accepted),
            ),
        };
        if origin_trust_zone.is_some_and(|z| z != profile.trust_zone()) {
            mixed = true
        }
        let omission = if source.workspace_id() != workspace_id {
            Some(GateOmissionReason::WorkspaceMismatch)
        } else if source.classification() == DataClass::Secret {
            Some(GateOmissionReason::Secret)
        } else if !artifact_ok {
            Some(GateOmissionReason::ArtifactNotAccepted)
        } else if class_rank(source.classification()) > class_rank(node.requirements().data_class())
        {
            Some(GateOmissionReason::TaskClassification)
        } else {
            match policy.allows_source(profile, &source) {
                Ok(()) => None,
                Err(ContextError::DataClassDenied) => Some(GateOmissionReason::DataClass),
                Err(ContextError::CompartmentDenied) => Some(GateOmissionReason::Compartment),
                Err(_) => return Err(TrustGateError::BindingMismatch),
            }
        };
        let is_selected = omission.is_none() && !restricted_tools;
        if is_selected {
            selected.push(source.clone())
        }
        decisions.push(GateSourceDecision {
            source_id: source.id().to_string(),
            origin_kind: origin_kind.into(),
            source_digest: source.digest().as_str().to_owned(),
            classification: source.classification(),
            compartments: source.compartments().clone(),
            origin_artifact_id,
            origin_artifact_hash,
            origin_profile_id,
            origin_profile_revision,
            origin_trust_zone,
            selected: is_selected,
            omission,
        })
    }
    if profile.trust_zone() != ModelTrustZone::LocalTrusted && decisions.iter().any(|d| !d.selected)
    {
        mixed = true
    }
    let covered = selected
        .iter()
        .flat_map(|s| s.compartments().iter().cloned())
        .collect::<BTreeSet<_>>();
    let missing = node
        .requirements()
        .required_compartments()
        .iter()
        .filter(|c| !covered.contains(*c))
        .cloned()
        .collect::<BTreeSet<_>>();
    let instruction_selected = decisions
        .iter()
        .any(|d| d.origin_kind == "instruction" && d.selected);
    let block = if restricted_tools {
        Some(GateBlockReason::RestrictedToolIsolationUnavailable)
    } else if !instruction_selected {
        Some(GateBlockReason::InstructionUnavailable)
    } else if selected.is_empty() {
        Some(GateBlockReason::NoAllowedSources)
    } else if !missing.is_empty() {
        Some(GateBlockReason::MissingRequiredCompartment)
    } else {
        None
    };
    let evaluation = TrustGateEvaluation::new(
        workspace_id,
        orchestration_id,
        graph_revision,
        node.id(),
        profile,
        policy.revision(),
        mixed,
        block.is_none(),
        block,
        missing,
        decisions,
        created_at,
    )?;
    Ok(ProjectionSelection {
        evaluation,
        selected_sources: selected,
    })
}
const fn class_rank(v: DataClass) -> u8 {
    match v {
        DataClass::Public => 0,
        DataClass::Workspace => 1,
        DataClass::Sensitive => 2,
        DataClass::Secret => 3,
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrityIssue {
    GraphDigest,
    WorkerBinding,
    ProjectionBinding,
    TrustGateMissing,
    RoutingBinding,
    ArtifactBinding,
    UnknownFailureMetadata,
}
impl IntegrityIssue {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::GraphDigest => "graph_digest",
            Self::WorkerBinding => "worker_binding",
            Self::ProjectionBinding => "projection_binding",
            Self::TrustGateMissing => "trust_gate_missing",
            Self::RoutingBinding => "routing_binding",
            Self::ArtifactBinding => "artifact_binding",
            Self::UnknownFailureMetadata => "unknown_failure_metadata",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrchestrationIntegrityReport {
    pub check_id: RecoveryCheckId,
    pub orchestration_id: OrchestrationId,
    pub workspace_id: WorkspaceId,
    pub issues: BTreeSet<IntegrityIssue>,
    pub digest: ContextDigest,
    pub checked_at: TimestampMillis,
}
impl OrchestrationIntegrityReport {
    pub fn new(
        orchestration_id: OrchestrationId,
        workspace_id: WorkspaceId,
        issues: BTreeSet<IntegrityIssue>,
        checked_at: TimestampMillis,
    ) -> Result<Self, TrustGateError> {
        let check_id = RecoveryCheckId::new();
        let bytes = serde_json::to_vec(&(
            orchestration_id.to_string(),
            workspace_id.to_string(),
            &issues,
            checked_at.as_u64(),
        ))?;
        Ok(Self {
            check_id,
            orchestration_id,
            workspace_id,
            issues,
            digest: ContextDigest::from_bytes(&bytes),
            checked_at,
        })
    }
    pub fn ok(&self) -> bool {
        self.issues.is_empty()
    }
}
#[derive(Debug, Error)]
pub enum TrustGateError {
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("trust gate binding mismatch")]
    BindingMismatch,
    #[error("invalid artifact gate source")]
    InvalidArtifactSource,
    #[error("invalid trust gate evaluation")]
    InvalidEvaluation,
    #[error("trust gate digest mismatch")]
    DigestMismatch,
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        action::CanonicalValue,
        context::{ContextSourceId, ProjectionTaskKey, SourceProvenance},
        egress::ProviderId,
        identity::PrincipalId,
        orchestration::{TaskNodeLimits, TaskOutputKind, TaskRequirements},
        provider::{ModelCapabilities, ModelCapability, ModelTrustZone},
    };
    fn actor() -> PrincipalId {
        PrincipalId::new("local", "op").unwrap()
    }
    fn src(w: WorkspaceId, class: DataClass, c: &str, v: &str) -> ContextSource {
        ContextSource::new(
            ContextSourceId::new(),
            w,
            class,
            [CompartmentId::parse(c).unwrap()],
            SourceProvenance::new(SourceProvenanceKind::File, format!("{c}.txt")).unwrap(),
            CanonicalValue::from(v),
            actor(),
            TimestampMillis::new(1),
        )
        .unwrap()
    }
    fn node(class: DataClass, c: &str, tools: bool) -> TaskNode {
        TaskNode::new(
            TaskNodeId::new(),
            ProjectionTaskKey::parse("t").unwrap(),
            "t",
            TaskOutputKind::Text,
            TaskRequirements::new(
                ModelCapabilities::new([ModelCapability::Text]),
                [],
                class,
                [CompartmentId::parse(c).unwrap()],
                if tools {
                    vec![crate::action::ActionKind::new("fs.read").unwrap()]
                } else {
                    vec![]
                },
            )
            .unwrap(),
            TaskNodeLimits::new(100, 100, 1).unwrap(),
            None,
        )
        .unwrap()
    }
    fn profile(zone: ModelTrustZone) -> ModelProfile {
        ModelProfile::new(
            ModelProfileId::parse("m").unwrap(),
            1,
            ProviderId::parse("p").unwrap(),
            1,
            "m",
            true,
            ModelCapabilities::new([ModelCapability::Text]),
            4096,
            zone,
            1,
            0,
        )
        .unwrap()
    }
    #[test]
    fn safe_subset_omits_forbidden_source() {
        let w = WorkspaceId::new();
        let p = profile(ModelTrustZone::RemoteApproved);
        let pol = ModelDataPolicy::new(
            w,
            p.id().clone(),
            1,
            p.trust_zone(),
            1,
            [DataClass::Workspace],
            [CompartmentId::parse("interface").unwrap()],
            false,
            TimestampMillis::new(1),
        )
        .unwrap();
        let s = evaluate_exact_projection(
            w,
            OrchestrationId::new(),
            1,
            &node(DataClass::Workspace, "interface", false),
            &p,
            &pol,
            vec![
                GateSource::instruction(src(w, DataClass::Workspace, "interface", "task")),
                GateSource::input(src(w, DataClass::Workspace, "interface", "safe")),
                GateSource::input(src(w, DataClass::Sensitive, "protected", "DO_NOT_SEND")),
            ],
            TimestampMillis::new(2),
        )
        .unwrap();
        assert!(s.evaluation.allowed);
        assert_eq!(s.selected_sources.len(), 2);
        let json = serde_json::to_string(&s.evaluation).unwrap();
        assert!(!json.contains("DO_NOT_SEND"));
        assert!(s.evaluation.mixed_trust)
    }
    #[test]
    fn required_forbidden_compartment_blocks() {
        let w = WorkspaceId::new();
        let p = profile(ModelTrustZone::RemoteApproved);
        let pol = ModelDataPolicy::new(
            w,
            p.id().clone(),
            1,
            p.trust_zone(),
            1,
            [DataClass::Workspace],
            [CompartmentId::parse("interface").unwrap()],
            false,
            TimestampMillis::new(1),
        )
        .unwrap();
        let s = evaluate_exact_projection(
            w,
            OrchestrationId::new(),
            1,
            &node(DataClass::Sensitive, "protected", false),
            &p,
            &pol,
            vec![
                GateSource::instruction(src(w, DataClass::Sensitive, "protected", "task")),
                GateSource::input(src(w, DataClass::Sensitive, "protected", "x")),
            ],
            TimestampMillis::new(2),
        )
        .unwrap();
        assert!(!s.evaluation.allowed);
        assert_eq!(
            s.evaluation.block_reason,
            Some(GateBlockReason::InstructionUnavailable)
        )
    }
    #[test]
    fn restricted_worker_tools_are_blocked_without_projection_only_execution() {
        let w = WorkspaceId::new();
        let p = profile(ModelTrustZone::RemoteApproved);
        let pol = ModelDataPolicy::new(
            w,
            p.id().clone(),
            1,
            p.trust_zone(),
            1,
            [DataClass::Workspace],
            [CompartmentId::parse("interface").unwrap()],
            false,
            TimestampMillis::new(1),
        )
        .unwrap();
        let s = evaluate_exact_projection(
            w,
            OrchestrationId::new(),
            1,
            &node(DataClass::Workspace, "interface", true),
            &p,
            &pol,
            vec![
                GateSource::instruction(src(w, DataClass::Workspace, "interface", "task")),
                GateSource::input(src(w, DataClass::Workspace, "interface", "safe")),
            ],
            TimestampMillis::new(2),
        )
        .unwrap();
        assert_eq!(
            s.evaluation.block_reason,
            Some(GateBlockReason::RestrictedToolIsolationUnavailable)
        );
    }
}
