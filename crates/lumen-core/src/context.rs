use crate::{
    action::CanonicalValue,
    approval::TimestampMillis,
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
    model::{ModelFuture, ModelInput, ModelMessage, ModelPort, ModelRole},
    provider::{ModelProfile, ModelProfileId, ModelTrustZone, ProviderAdapter, validate_binding},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
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
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}
uuid_id!(ContextSourceId);
uuid_id!(ProjectionId);
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct CompartmentId(String);
impl CompartmentId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContextError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.starts_with('/')
            || value.ends_with('/')
            || value.split('/').any(|segment| {
                segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || segment.chars().any(char::is_control)
            })
        {
            return Err(ContextError::InvalidCompartment);
        }
        Ok(Self(value))
    }
}
impl TryFrom<String> for CompartmentId {
    type Error = ContextError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct ProjectionTaskKey(String);
impl ProjectionTaskKey {
    pub fn parse(value: impl Into<String>) -> Result<Self, ContextError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(ContextError::InvalidTaskKey);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for ProjectionTaskKey {
    type Error = ContextError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct ContextDigest(String);
impl ContextDigest {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = Sha256::digest(bytes);
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
        }
        Self(encoded)
    }
    pub fn parse(value: impl Into<String>) -> Result<Self, ContextError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ContextError::InvalidDigest);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for ContextDigest {
    type Error = ContextError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceProvenanceKind {
    UserMessage,
    File,
    ToolResult,
    Skill,
    Artifact,
    Generated,
}
impl SourceProvenanceKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserMessage => "user_message",
            Self::File => "file",
            Self::ToolResult => "tool_result",
            Self::Skill => "skill",
            Self::Artifact => "artifact",
            Self::Generated => "generated",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "user_message" => Some(Self::UserMessage),
            "file" => Some(Self::File),
            "tool_result" => Some(Self::ToolResult),
            "skill" => Some(Self::Skill),
            "artifact" => Some(Self::Artifact),
            "generated" => Some(Self::Generated),
            _ => None,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceProvenance {
    kind: SourceProvenanceKind,
    reference: String,
}
impl SourceProvenance {
    pub fn new(
        kind: SourceProvenanceKind,
        reference: impl Into<String>,
    ) -> Result<Self, ContextError> {
        let reference = reference.into();
        if reference.is_empty()
            || reference.len() > 4096
            || reference.trim() != reference
            || reference.chars().any(char::is_control)
        {
            return Err(ContextError::InvalidProvenance);
        }
        Ok(Self { kind, reference })
    }
    pub const fn kind(&self) -> SourceProvenanceKind {
        self.kind
    }
    pub fn reference(&self) -> &str {
        &self.reference
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSource {
    id: ContextSourceId,
    workspace_id: WorkspaceId,
    classification: DataClass,
    compartments: BTreeSet<CompartmentId>,
    provenance: SourceProvenance,
    content: CanonicalValue,
    digest: ContextDigest,
    created_by: PrincipalId,
    created_at: TimestampMillis,
}
impl ContextSource {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ContextSourceId,
        workspace_id: WorkspaceId,
        classification: DataClass,
        compartments: impl IntoIterator<Item = CompartmentId>,
        provenance: SourceProvenance,
        content: CanonicalValue,
        created_by: PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<Self, ContextError> {
        let compartments = compartments.into_iter().collect::<BTreeSet<_>>();
        let digest = source_digest(
            id,
            workspace_id,
            classification,
            &compartments,
            &provenance,
            &content,
            &created_by,
            created_at,
        )?;
        Ok(Self {
            id,
            workspace_id,
            classification,
            compartments,
            provenance,
            content,
            digest,
            created_by,
            created_at,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        id: ContextSourceId,
        workspace_id: WorkspaceId,
        classification: DataClass,
        compartments: impl IntoIterator<Item = CompartmentId>,
        provenance: SourceProvenance,
        content: CanonicalValue,
        created_by: PrincipalId,
        created_at: TimestampMillis,
        expected_digest: ContextDigest,
    ) -> Result<Self, ContextError> {
        let source = Self::new(
            id,
            workspace_id,
            classification,
            compartments,
            provenance,
            content,
            created_by,
            created_at,
        )?;
        if source.digest != expected_digest {
            return Err(ContextError::DigestMismatch);
        }
        Ok(source)
    }
    #[allow(clippy::too_many_arguments)]
    pub fn derived(
        id: ContextSourceId,
        workspace_id: WorkspaceId,
        provenance_reference: impl Into<String>,
        inputs: &[ContextSource],
        content: CanonicalValue,
        created_by: PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<Self, ContextError> {
        if inputs.is_empty()
            || inputs
                .iter()
                .any(|source| source.workspace_id != workspace_id)
        {
            return Err(ContextError::InvalidDerivation);
        }
        let classification = inputs
            .iter()
            .map(|source| source.classification)
            .reduce(most_restrictive)
            .ok_or(ContextError::InvalidDerivation)?;
        let compartments = inputs
            .iter()
            .flat_map(|source| source.compartments.iter().cloned())
            .collect::<BTreeSet<_>>();
        Self::new(
            id,
            workspace_id,
            classification,
            compartments,
            SourceProvenance::new(SourceProvenanceKind::Generated, provenance_reference)?,
            content,
            created_by,
            created_at,
        )
    }
    pub const fn id(&self) -> ContextSourceId {
        self.id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn classification(&self) -> DataClass {
        self.classification
    }
    pub fn compartments(&self) -> &BTreeSet<CompartmentId> {
        &self.compartments
    }
    pub const fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }
    pub const fn content(&self) -> &CanonicalValue {
        &self.content
    }
    pub const fn digest(&self) -> &ContextDigest {
        &self.digest
    }
    pub const fn created_by(&self) -> &PrincipalId {
        &self.created_by
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelDataPolicy {
    workspace_id: WorkspaceId,
    model_profile_id: ModelProfileId,
    model_profile_revision: u64,
    model_trust_zone: ModelTrustZone,
    revision: u64,
    allowed_data_classes: BTreeSet<DataClass>,
    allowed_compartments: BTreeSet<CompartmentId>,
    allow_uncompartmented: bool,
    created_at: TimestampMillis,
}
impl ModelDataPolicy {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        workspace_id: WorkspaceId,
        model_profile_id: ModelProfileId,
        model_profile_revision: u64,
        model_trust_zone: ModelTrustZone,
        revision: u64,
        allowed_data_classes: impl IntoIterator<Item = DataClass>,
        allowed_compartments: impl IntoIterator<Item = CompartmentId>,
        allow_uncompartmented: bool,
        created_at: TimestampMillis,
    ) -> Result<Self, ContextError> {
        let allowed_data_classes = allowed_data_classes.into_iter().collect::<BTreeSet<_>>();
        if model_profile_revision == 0
            || revision == 0
            || allowed_data_classes.is_empty()
            || allowed_data_classes.contains(&DataClass::Secret)
        {
            return Err(ContextError::InvalidPolicy);
        }
        Ok(Self {
            workspace_id,
            model_profile_id,
            model_profile_revision,
            model_trust_zone,
            revision,
            allowed_data_classes,
            allowed_compartments: allowed_compartments.into_iter().collect(),
            allow_uncompartmented,
            created_at,
        })
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub fn model_profile_id(&self) -> &ModelProfileId {
        &self.model_profile_id
    }
    pub const fn model_profile_revision(&self) -> u64 {
        self.model_profile_revision
    }
    pub const fn model_trust_zone(&self) -> ModelTrustZone {
        self.model_trust_zone
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn allowed_data_classes(&self) -> &BTreeSet<DataClass> {
        &self.allowed_data_classes
    }
    pub fn allowed_compartments(&self) -> &BTreeSet<CompartmentId> {
        &self.allowed_compartments
    }
    pub const fn allow_uncompartmented(&self) -> bool {
        self.allow_uncompartmented
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub fn validate_profile(&self, profile: &ModelProfile) -> Result<(), ContextError> {
        if profile.id() != &self.model_profile_id
            || profile.revision() != self.model_profile_revision
            || profile.trust_zone() != self.model_trust_zone
            || !profile.enabled()
        {
            return Err(ContextError::ProfilePolicyMismatch);
        }
        Ok(())
    }
    pub fn allows_source(
        &self,
        profile: &ModelProfile,
        source: &ContextSource,
    ) -> Result<(), ContextError> {
        self.validate_profile(profile)?;
        if source.workspace_id != self.workspace_id {
            return Err(ContextError::WorkspaceMismatch);
        }
        if source.classification == DataClass::Secret
            || !self.allowed_data_classes.contains(&source.classification)
        {
            return Err(ContextError::DataClassDenied);
        }
        if source.compartments.is_empty() {
            if !self.allow_uncompartmented {
                return Err(ContextError::CompartmentDenied);
            }
        } else if !source
            .compartments
            .iter()
            .all(|compartment| self.allowed_compartments.contains(compartment))
        {
            return Err(ContextError::CompartmentDenied);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionTransform {
    Exact,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectedSource {
    source_id: ContextSourceId,
    source_digest: ContextDigest,
    classification: DataClass,
    compartments: BTreeSet<CompartmentId>,
    provenance: SourceProvenance,
    transform: ProjectionTransform,
    content: CanonicalValue,
}
impl ProjectedSource {
    pub fn exact(source: &ContextSource) -> Self {
        Self {
            source_id: source.id,
            source_digest: source.digest.clone(),
            classification: source.classification,
            compartments: source.compartments.clone(),
            provenance: source.provenance.clone(),
            transform: ProjectionTransform::Exact,
            content: source.content.clone(),
        }
    }
    pub const fn source_id(&self) -> ContextSourceId {
        self.source_id
    }
    pub const fn source_digest(&self) -> &ContextDigest {
        &self.source_digest
    }
    pub const fn provenance(&self) -> &SourceProvenance {
        &self.provenance
    }
    pub const fn content(&self) -> &CanonicalValue {
        &self.content
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskProjection {
    id: ProjectionId,
    workspace_id: WorkspaceId,
    task_key: ProjectionTaskKey,
    model_profile_id: ModelProfileId,
    model_profile_revision: u64,
    policy_revision: u64,
    sources: Vec<ProjectedSource>,
    classification: DataClass,
    compartments: BTreeSet<CompartmentId>,
    created_at: TimestampMillis,
    serialized_payload: String,
    digest: ContextDigest,
}
impl TaskProjection {
    pub fn build(
        id: ProjectionId,
        task_key: ProjectionTaskKey,
        profile: &ModelProfile,
        policy: &ModelDataPolicy,
        sources: Vec<ContextSource>,
        created_at: TimestampMillis,
    ) -> Result<Self, ContextError> {
        policy.validate_profile(profile)?;
        if sources.is_empty() {
            return Err(ContextError::EmptyProjection);
        }
        for source in &sources {
            policy.allows_source(profile, source)?;
        }
        let workspace_id = policy.workspace_id;
        if sources
            .iter()
            .any(|source| source.workspace_id != workspace_id)
        {
            return Err(ContextError::WorkspaceMismatch);
        }
        let mut projected = sources
            .iter()
            .map(ProjectedSource::exact)
            .collect::<Vec<_>>();
        projected.sort_by_key(|source| source.source_id);
        Self::from_projected_sources(
            id,
            workspace_id,
            task_key,
            profile.id().clone(),
            profile.revision(),
            policy.revision,
            projected,
            created_at,
            None,
        )
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        id: ProjectionId,
        workspace_id: WorkspaceId,
        task_key: ProjectionTaskKey,
        model_profile_id: ModelProfileId,
        model_profile_revision: u64,
        policy_revision: u64,
        sources: Vec<ContextSource>,
        created_at: TimestampMillis,
        expected_digest: ContextDigest,
    ) -> Result<Self, ContextError> {
        if sources
            .iter()
            .any(|source| source.workspace_id != workspace_id)
        {
            return Err(ContextError::WorkspaceMismatch);
        }
        let projected = sources
            .iter()
            .map(ProjectedSource::exact)
            .collect::<Vec<_>>();
        Self::from_projected_sources(
            id,
            workspace_id,
            task_key,
            model_profile_id,
            model_profile_revision,
            policy_revision,
            projected,
            created_at,
            Some(expected_digest),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn from_projected_sources(
        id: ProjectionId,
        workspace_id: WorkspaceId,
        task_key: ProjectionTaskKey,
        model_profile_id: ModelProfileId,
        model_profile_revision: u64,
        policy_revision: u64,
        sources: Vec<ProjectedSource>,
        created_at: TimestampMillis,
        expected_digest: Option<ContextDigest>,
    ) -> Result<Self, ContextError> {
        if sources.is_empty() || model_profile_revision == 0 || policy_revision == 0 {
            return Err(ContextError::InvalidProjection);
        }
        if sources
            .iter()
            .any(|source| source.classification == DataClass::Secret)
        {
            return Err(ContextError::SecretSourceDenied);
        }
        let unique_source_ids = sources
            .iter()
            .map(|source| source.source_id)
            .collect::<BTreeSet<_>>();
        if unique_source_ids.len() != sources.len() {
            return Err(ContextError::InvalidProjection);
        }
        let classification = sources
            .iter()
            .map(|source| source.classification)
            .reduce(most_restrictive)
            .ok_or(ContextError::EmptyProjection)?;
        let compartments = sources
            .iter()
            .flat_map(|source| source.compartments.iter().cloned())
            .collect::<BTreeSet<_>>();
        let serialized_payload = serialize_projection_payload(
            id,
            workspace_id,
            &task_key,
            &model_profile_id,
            model_profile_revision,
            policy_revision,
            &sources,
        )?;
        let digest = ContextDigest::from_bytes(serialized_payload.as_bytes());
        if expected_digest
            .as_ref()
            .is_some_and(|expected| expected != &digest)
        {
            return Err(ContextError::DigestMismatch);
        }
        Ok(Self {
            id,
            workspace_id,
            task_key,
            model_profile_id,
            model_profile_revision,
            policy_revision,
            sources,
            classification,
            compartments,
            created_at,
            serialized_payload,
            digest,
        })
    }
    pub const fn id(&self) -> ProjectionId {
        self.id
    }
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    pub const fn task_key(&self) -> &ProjectionTaskKey {
        &self.task_key
    }
    pub fn model_profile_id(&self) -> &ModelProfileId {
        &self.model_profile_id
    }
    pub const fn model_profile_revision(&self) -> u64 {
        self.model_profile_revision
    }
    pub const fn policy_revision(&self) -> u64 {
        self.policy_revision
    }
    pub fn sources(&self) -> &[ProjectedSource] {
        &self.sources
    }
    pub const fn classification(&self) -> DataClass {
        self.classification
    }
    pub fn compartments(&self) -> &BTreeSet<CompartmentId> {
        &self.compartments
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub fn serialized_payload(&self) -> &str {
        &self.serialized_payload
    }
    pub const fn digest(&self) -> &ContextDigest {
        &self.digest
    }
    pub fn verify_digest(&self) -> Result<(), ContextError> {
        if ContextDigest::from_bytes(self.serialized_payload.as_bytes()) != self.digest {
            return Err(ContextError::DigestMismatch);
        }
        Ok(())
    }
    pub fn validate_for(
        &self,
        profile: &ModelProfile,
        policy: &ModelDataPolicy,
    ) -> Result<(), ContextError> {
        self.verify_digest()?;
        policy.validate_profile(profile)?;
        if self.workspace_id != policy.workspace_id
            || self.model_profile_id != *profile.id()
            || self.model_profile_revision != profile.revision()
            || self.policy_revision != policy.revision
        {
            return Err(ContextError::ProjectionBindingMismatch);
        }
        for projected in &self.sources {
            if projected.classification == DataClass::Secret
                || !policy
                    .allowed_data_classes
                    .contains(&projected.classification)
            {
                return Err(ContextError::DataClassDenied);
            }
            if projected.compartments.is_empty() {
                if !policy.allow_uncompartmented {
                    return Err(ContextError::CompartmentDenied);
                }
            } else if !projected
                .compartments
                .iter()
                .all(|compartment| policy.allowed_compartments.contains(compartment))
            {
                return Err(ContextError::CompartmentDenied);
            }
        }
        Ok(())
    }
    pub fn audit_payload(&self) -> CanonicalValue {
        CanonicalValue::object([
            ("projection_id", CanonicalValue::from(self.id.to_string())),
            (
                "projection_digest",
                CanonicalValue::from(self.digest.as_str()),
            ),
            (
                "model_profile_id",
                CanonicalValue::from(self.model_profile_id.as_str()),
            ),
            (
                "model_profile_revision",
                CanonicalValue::from(
                    i64::try_from(self.model_profile_revision).unwrap_or(i64::MAX),
                ),
            ),
            (
                "policy_revision",
                CanonicalValue::from(i64::try_from(self.policy_revision).unwrap_or(i64::MAX)),
            ),
            (
                "classification",
                CanonicalValue::from(data_class_str(self.classification)),
            ),
        ])
    }
}
pub struct ProjectedProviderModelPort<'a> {
    provider: &'a dyn ProviderAdapter,
    profile: &'a ModelProfile,
    policy: &'a ModelDataPolicy,
    projection: &'a TaskProjection,
    cancellation: CancellationToken,
}
impl<'a> ProjectedProviderModelPort<'a> {
    pub fn new(
        provider: &'a dyn ProviderAdapter,
        profile: &'a ModelProfile,
        policy: &'a ModelDataPolicy,
        projection: &'a TaskProjection,
    ) -> Result<Self, ContextError> {
        validate_binding(provider.config(), profile)
            .map_err(|error| ContextError::ProviderBinding(error.to_string()))?;
        projection.validate_for(profile, policy)?;
        Ok(Self {
            provider,
            profile,
            policy,
            projection,
            cancellation: CancellationToken::new(),
        })
    }
    pub fn with_cancellation(mut self, cancellation: CancellationToken) -> Self {
        self.cancellation = cancellation;
        self
    }
    fn secure_input(&self, input: ModelInput) -> Result<ModelInput, ContextError> {
        self.projection.validate_for(self.profile, self.policy)?;
        if input.data_class() == DataClass::Secret
            || !self
                .policy
                .allowed_data_classes
                .contains(&input.data_class())
        {
            return Err(ContextError::DataClassDenied);
        }
        if !input.messages().is_empty() && !self.policy.allow_uncompartmented {
            return Err(ContextError::CompartmentDenied);
        }
        let effective_classification =
            most_restrictive(input.data_class(), self.projection.classification);
        let mut messages = Vec::with_capacity(input.messages().len().saturating_add(1));
        messages.push(ModelMessage::new(
            ModelRole::User,
            CanonicalValue::from(self.projection.serialized_payload.to_owned()),
        ));
        messages.extend(input.messages().iter().cloned());
        Ok(ModelInput::new(messages)
            .with_data_class(effective_classification)
            .with_tools(input.tools().to_vec()))
    }
}
impl ModelPort for ProjectedProviderModelPort<'_> {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        Box::pin(async move {
            let secure_input = self
                .secure_input(input)
                .map_err(|error| crate::model::ModelError::new(error.to_string()))?;
            self.provider
                .generate(self.profile, secure_input, self.cancellation.child_token())
                .await
                .map(|response| response.output)
                .map_err(|error| crate::model::ModelError::new(error.to_string()))
        })
    }
}
#[derive(Serialize)]
struct SourceDigestMaterial<'a> {
    source_id: String,
    workspace_id: String,
    classification: &'static str,
    compartments: &'a BTreeSet<CompartmentId>,
    provenance_kind: &'static str,
    provenance_reference: &'a str,
    content: &'a CanonicalValue,
    created_by_provider: &'a str,
    created_by_subject: &'a str,
    created_at: u64,
}
#[derive(Serialize)]
struct ProjectionPayload<'a> {
    schema_version: u16,
    projection_id: String,
    workspace_id: String,
    task_key: &'a str,
    model_profile_id: &'a str,
    model_profile_revision: u64,
    policy_revision: u64,
    sources: Vec<ProjectionPayloadSource<'a>>,
}
#[derive(Serialize)]
struct ProjectionPayloadSource<'a> {
    source_id: String,
    source_digest: &'a str,
    classification: &'static str,
    compartments: &'a BTreeSet<CompartmentId>,
    provenance_kind: &'static str,
    provenance_reference: &'a str,
    transform: &'static str,
    content: &'a CanonicalValue,
}
#[allow(clippy::too_many_arguments)]
fn source_digest(
    id: ContextSourceId,
    workspace_id: WorkspaceId,
    classification: DataClass,
    compartments: &BTreeSet<CompartmentId>,
    provenance: &SourceProvenance,
    content: &CanonicalValue,
    created_by: &PrincipalId,
    created_at: TimestampMillis,
) -> Result<ContextDigest, ContextError> {
    let material = SourceDigestMaterial {
        source_id: id.to_string(),
        workspace_id: workspace_id.to_string(),
        classification: data_class_str(classification),
        compartments,
        provenance_kind: provenance.kind.as_str(),
        provenance_reference: provenance.reference(),
        content,
        created_by_provider: created_by.provider(),
        created_by_subject: created_by.subject(),
        created_at: created_at.as_u64(),
    };
    let bytes = serde_json::to_vec(&material)?;
    Ok(ContextDigest::from_bytes(&bytes))
}
fn serialize_projection_payload(
    id: ProjectionId,
    workspace_id: WorkspaceId,
    task_key: &ProjectionTaskKey,
    model_profile_id: &ModelProfileId,
    model_profile_revision: u64,
    policy_revision: u64,
    sources: &[ProjectedSource],
) -> Result<String, ContextError> {
    let payload = ProjectionPayload {
        schema_version: 1,
        projection_id: id.to_string(),
        workspace_id: workspace_id.to_string(),
        task_key: task_key.as_str(),
        model_profile_id: model_profile_id.as_str(),
        model_profile_revision,
        policy_revision,
        sources: sources
            .iter()
            .map(|source| ProjectionPayloadSource {
                source_id: source.source_id.to_string(),
                source_digest: source.source_digest.as_str(),
                classification: data_class_str(source.classification),
                compartments: &source.compartments,
                provenance_kind: source.provenance.kind.as_str(),
                provenance_reference: source.provenance.reference(),
                transform: "exact",
                content: &source.content,
            })
            .collect(),
    };
    Ok(serde_json::to_string(&payload)?)
}
pub const fn data_class_str(value: DataClass) -> &'static str {
    match value {
        DataClass::Public => "public",
        DataClass::Workspace => "workspace",
        DataClass::Sensitive => "sensitive",
        DataClass::Secret => "secret",
    }
}
pub fn parse_data_class(value: &str) -> Option<DataClass> {
    match value {
        "public" => Some(DataClass::Public),
        "workspace" => Some(DataClass::Workspace),
        "sensitive" => Some(DataClass::Sensitive),
        "secret" => Some(DataClass::Secret),
        _ => None,
    }
}
pub const fn most_restrictive(left: DataClass, right: DataClass) -> DataClass {
    if data_class_rank(left) >= data_class_rank(right) {
        left
    } else {
        right
    }
}
const fn data_class_rank(value: DataClass) -> u8 {
    match value {
        DataClass::Public => 0,
        DataClass::Workspace => 1,
        DataClass::Sensitive => 2,
        DataClass::Secret => 3,
    }
}
#[derive(Debug, Error)]
pub enum ContextError {
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("context compartment is invalid")]
    InvalidCompartment,
    #[error("projection task key is invalid")]
    InvalidTaskKey,
    #[error("context digest is invalid")]
    InvalidDigest,
    #[error("context digest does not match immutable content")]
    DigestMismatch,
    #[error("source provenance is invalid")]
    InvalidProvenance,
    #[error("derived context requires same-workspace source inputs")]
    InvalidDerivation,
    #[error("model data policy is invalid")]
    InvalidPolicy,
    #[error("model profile does not match the data policy revision")]
    ProfilePolicyMismatch,
    #[error("context source belongs to another workspace")]
    WorkspaceMismatch,
    #[error("context data class is not allowed for this model profile")]
    DataClassDenied,
    #[error("context compartment is not allowed for this model profile")]
    CompartmentDenied,
    #[error("projection must contain at least one source")]
    EmptyProjection,
    #[error("projection metadata is invalid")]
    InvalidProjection,
    #[error("secret-class context may not enter model context")]
    SecretSourceDenied,
    #[error("projection binding does not match the selected model/policy")]
    ProjectionBindingMismatch,
    #[error("provider/model binding is invalid: {0}")]
    ProviderBinding(String),
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        egress::ProviderId,
        model::ModelOutput,
        provider::{
            LocalRuntimeKind, ModelCapabilities, ModelCapability, ProviderConfig, ProviderFuture,
            ProviderResponse, ProviderUsage,
        },
    };
    fn actor() -> PrincipalId {
        PrincipalId::new("local", "operator").unwrap()
    }
    fn source(workspace: WorkspaceId, class: DataClass, compartment: &str) -> ContextSource {
        ContextSource::new(
            ContextSourceId::new(),
            workspace,
            class,
            [CompartmentId::parse(compartment).unwrap()],
            SourceProvenance::new(SourceProvenanceKind::File, "src/lib.rs").unwrap(),
            CanonicalValue::from("source"),
            actor(),
            TimestampMillis::new(1),
        )
        .unwrap()
    }
    fn setup(workspace: WorkspaceId) -> (ProviderConfig, ModelProfile, ModelDataPolicy) {
        let provider = ProviderConfig::local_openai_compatible(
            ProviderId::parse("local").unwrap(),
            1,
            "http://127.0.0.1:11434/v1/",
            LocalRuntimeKind::Ollama,
            true,
            None,
        )
        .unwrap();
        let profile = ModelProfile::new(
            ModelProfileId::parse("coder").unwrap(),
            1,
            provider.id().clone(),
            1,
            "qwen-coder",
            true,
            ModelCapabilities::new([ModelCapability::Text, ModelCapability::ToolCalling]),
            32_768,
            ModelTrustZone::LocalRestricted,
            1,
            0,
        )
        .unwrap();
        let policy = ModelDataPolicy::new(
            workspace,
            profile.id().clone(),
            1,
            profile.trust_zone(),
            1,
            [DataClass::Public, DataClass::Workspace],
            [CompartmentId::parse("workspace/source-code").unwrap()],
            true,
            TimestampMillis::new(2),
        )
        .unwrap();
        (provider, profile, policy)
    }
    #[test]
    fn taint_and_policy_are_fail_closed() {
        let workspace = WorkspaceId::new();
        let a = source(workspace, DataClass::Public, "workspace/source-code");
        let b = source(workspace, DataClass::Sensitive, "workspace/customer-acme");
        let derived = ContextSource::derived(
            ContextSourceId::new(),
            workspace,
            "summary",
            &[a, b],
            CanonicalValue::from("summary"),
            actor(),
            TimestampMillis::new(3),
        )
        .unwrap();
        assert_eq!(derived.classification(), DataClass::Sensitive);
        let (_, profile, policy) = setup(workspace);
        assert!(matches!(
            policy.allows_source(&profile, &derived),
            Err(ContextError::DataClassDenied)
        ));
        assert!(matches!(
            policy.allows_source(
                &profile,
                &source(workspace, DataClass::Workspace, "workspace/payroll")
            ),
            Err(ContextError::CompartmentDenied)
        ));
    }
    struct AssertProvider {
        config: ProviderConfig,
        payload: String,
    }
    impl ProviderAdapter for AssertProvider {
        fn config(&self) -> &ProviderConfig {
            &self.config
        }
        fn generate<'a>(
            &'a self,
            profile: &'a ModelProfile,
            input: ModelInput,
            _: CancellationToken,
        ) -> ProviderFuture<'a> {
            Box::pin(async move {
                assert_eq!(
                    input.messages()[0].content(),
                    &CanonicalValue::from(self.payload.as_str())
                );
                ProviderResponse::new(
                    profile.model_name(),
                    ModelOutput::FinalText("ok".into()),
                    ProviderUsage {
                        input_tokens: Some(1),
                        output_tokens: Some(1),
                    },
                )
            })
        }
    }
    #[tokio::test]
    async fn projected_port_sends_exact_verified_projection() {
        let workspace = WorkspaceId::new();
        let (provider, profile, policy) = setup(workspace);
        let projection = TaskProjection::build(
            ProjectionId::new(),
            ProjectionTaskKey::parse("backend").unwrap(),
            &profile,
            &policy,
            vec![source(
                workspace,
                DataClass::Workspace,
                "workspace/source-code",
            )],
            TimestampMillis::new(3),
        )
        .unwrap();
        let adapter = AssertProvider {
            config: provider,
            payload: projection.serialized_payload().to_owned(),
        };
        let port =
            ProjectedProviderModelPort::new(&adapter, &profile, &policy, &projection).unwrap();
        assert_eq!(
            port.generate(ModelInput::new(vec![ModelMessage::new(
                ModelRole::User,
                CanonicalValue::from("work")
            )]))
            .await
            .unwrap(),
            ModelOutput::FinalText("ok".into())
        );
        let audit = serde_json::to_string(&projection.audit_payload()).unwrap();
        assert!(audit.contains(projection.digest().as_str()));
    }
}
