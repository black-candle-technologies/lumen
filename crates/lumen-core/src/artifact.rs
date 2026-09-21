//! Bounded worker outputs and conservative retry policy.
use crate::{
    action::{ActionId, CanonicalValue, RunId},
    approval::TimestampMillis,
    context::{
        CompartmentId, ContextDigest, ContextSource, ContextSourceId, ProjectionId,
        SourceProvenance, SourceProvenanceKind,
    },
    egress::{DataClass, ProviderId},
    identity::{PrincipalId, WorkspaceId},
    model::ReasoningProfile,
    orchestration::{OrchestrationId, TaskNodeId, TaskOutputKind},
    provider::ModelProfileId,
    worker::WorkerAttemptId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};
use thiserror::Error;
use uuid::Uuid;

pub const MAX_ARTIFACT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_ARTIFACT_PREVIEW_BYTES: usize = 4096;
macro_rules! id {
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
id!(ArtifactId);
id!(RetryDecisionId);
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Text,
    Patch,
    Design,
    Test,
    TaskPlan,
    CodeReview,
    DiagnosticReport,
    Blob,
}
impl ArtifactKind {
    pub const fn from_task_output(value: TaskOutputKind) -> Self {
        match value {
            TaskOutputKind::Text => Self::Text,
            TaskOutputKind::Patch => Self::Patch,
            TaskOutputKind::Design => Self::Design,
            TaskOutputKind::Test => Self::Test,
            TaskOutputKind::Plan => Self::TaskPlan,
            TaskOutputKind::Review => Self::CodeReview,
            TaskOutputKind::Diagnostic => Self::DiagnosticReport,
            TaskOutputKind::Artifact => Self::Blob,
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Patch => "patch",
            Self::Design => "design",
            Self::Test => "test",
            Self::TaskPlan => "task_plan",
            Self::CodeReview => "code_review",
            Self::DiagnosticReport => "diagnostic_report",
            Self::Blob => "blob",
        }
    }
    pub const fn media(self) -> &'static str {
        match self {
            Self::Patch => "text/x-diff; charset=utf-8",
            Self::Design
            | Self::Test
            | Self::TaskPlan
            | Self::CodeReview
            | Self::DiagnosticReport => "text/markdown; charset=utf-8",
            Self::Text => "text/plain; charset=utf-8",
            Self::Blob => "application/octet-stream",
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValidationState {
    Accepted,
    Rejected,
}
impl ArtifactValidationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactProvenance {
    pub orchestration_id: OrchestrationId,
    pub graph_revision: u64,
    pub task_node_id: TaskNodeId,
    pub worker_attempt_id: WorkerAttemptId,
    pub run_id: RunId,
    pub provider_id: ProviderId,
    pub provider_revision: u64,
    pub model_profile_id: ModelProfileId,
    pub model_profile_revision: u64,
    pub reasoning_profile: Option<ReasoningProfile>,
    pub policy_revision: u64,
    pub projection_id: ProjectionId,
    pub projection_digest: ContextDigest,
    pub tool_action_ids: Vec<ActionId>,
}
impl ArtifactProvenance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        worker_attempt_id: WorkerAttemptId,
        run_id: RunId,
        provider_id: ProviderId,
        provider_revision: u64,
        model_profile_id: ModelProfileId,
        model_profile_revision: u64,
        reasoning_profile: Option<ReasoningProfile>,
        policy_revision: u64,
        projection_id: ProjectionId,
        projection_digest: ContextDigest,
        mut tool_action_ids: Vec<ActionId>,
    ) -> Result<Self, ArtifactError> {
        if graph_revision == 0
            || provider_revision == 0
            || model_profile_revision == 0
            || policy_revision == 0
        {
            return Err(ArtifactError::InvalidProvenance);
        }
        tool_action_ids.sort_unstable();
        tool_action_ids.dedup();
        Ok(Self {
            orchestration_id,
            graph_revision,
            task_node_id,
            worker_attempt_id,
            run_id,
            provider_id,
            provider_revision,
            model_profile_id,
            model_profile_revision,
            reasoning_profile,
            policy_revision,
            projection_id,
            projection_digest,
            tool_action_ids,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerArtifact {
    pub id: ArtifactId,
    pub workspace_id: WorkspaceId,
    pub kind: ArtifactKind,
    pub media_type: String,
    pub content: Vec<u8>,
    pub content_hash: ContextDigest,
    pub classification: DataClass,
    pub compartments: BTreeSet<CompartmentId>,
    pub provenance: ArtifactProvenance,
    pub created_at: TimestampMillis,
}
impl WorkerArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ArtifactId,
        workspace_id: WorkspaceId,
        kind: ArtifactKind,
        media_type: impl Into<String>,
        content: Vec<u8>,
        classification: DataClass,
        compartments: impl IntoIterator<Item = CompartmentId>,
        provenance: ArtifactProvenance,
        created_at: TimestampMillis,
    ) -> Result<Self, ArtifactError> {
        let media_type = media_type.into();
        if content.is_empty() || content.len() > MAX_ARTIFACT_BYTES {
            return Err(ArtifactError::InvalidContent);
        }
        if media_type.is_empty()
            || media_type.len() > 128
            || media_type.trim() != media_type
            || media_type.chars().any(char::is_control)
        {
            return Err(ArtifactError::InvalidMediaType);
        }
        if classification == DataClass::Secret {
            return Err(ArtifactError::SecretArtifactDenied);
        }
        let content_hash = digest(&content);
        Ok(Self {
            id,
            workspace_id,
            kind,
            media_type,
            content,
            content_hash,
            classification,
            compartments: compartments.into_iter().collect(),
            provenance,
            created_at,
        })
    }
    pub fn from_text(
        id: ArtifactId,
        workspace_id: WorkspaceId,
        kind: ArtifactKind,
        text: impl Into<String>,
        classification: DataClass,
        compartments: impl IntoIterator<Item = CompartmentId>,
        provenance: ArtifactProvenance,
        created_at: TimestampMillis,
    ) -> Result<Self, ArtifactError> {
        Self::new(
            id,
            workspace_id,
            kind,
            kind.media(),
            text.into().into_bytes(),
            classification,
            compartments,
            provenance,
            created_at,
        )
    }
    pub fn verify(&self) -> Result<(), ArtifactError> {
        if digest(&self.content) != self.content_hash {
            Err(ArtifactError::DigestMismatch)
        } else {
            Ok(())
        }
    }
    pub fn reference(&self, max: usize) -> Result<ArtifactReference, ArtifactError> {
        let limit = max.min(MAX_ARTIFACT_PREVIEW_BYTES);
        if limit == 0 {
            return Err(ArtifactError::InvalidPreviewLimit);
        }
        let end = self.content.len().min(limit);
        Ok(ArtifactReference {
            artifact_id: self.id,
            uri: format!("artifact://{}", self.id),
            kind: self.kind,
            media_type: self.media_type.clone(),
            content_hash: self.content_hash.clone(),
            classification: self.classification,
            compartments: self.compartments.clone(),
            preview: String::from_utf8_lossy(&self.content[..end]).into_owned(),
            truncated: self.content.len() > end,
            validation_state: None,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ArtifactReference {
    pub artifact_id: ArtifactId,
    pub uri: String,
    pub kind: ArtifactKind,
    pub media_type: String,
    pub content_hash: ContextDigest,
    pub classification: DataClass,
    pub compartments: BTreeSet<CompartmentId>,
    pub preview: String,
    pub truncated: bool,
    pub validation_state: Option<ArtifactValidationState>,
}
impl ArtifactReference {
    pub fn with_validation(mut self, validation: Option<ArtifactValidationState>) -> Self {
        self.validation_state = validation;
        self
    }
    pub fn to_context_source(
        &self,
        id: ContextSourceId,
        workspace: WorkspaceId,
        created_by: PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<ContextSource, ArtifactError> {
        let content = CanonicalValue::object([
            (
                "artifact_id",
                CanonicalValue::from(self.artifact_id.to_string()),
            ),
            ("artifact_uri", CanonicalValue::from(self.uri.clone())),
            (
                "sha256",
                CanonicalValue::from(self.content_hash.as_str().to_owned()),
            ),
            ("preview", CanonicalValue::from(self.preview.clone())),
            (
                "validation_state",
                CanonicalValue::from(
                    self.validation_state
                        .map_or("untrusted", ArtifactValidationState::as_str),
                ),
            ),
        ]);
        ContextSource::new(
            id,
            workspace,
            self.classification,
            self.compartments.clone(),
            SourceProvenance::new(SourceProvenanceKind::Artifact, self.uri.clone())
                .map_err(|_| ArtifactError::InvalidReference)?,
            content,
            created_by,
            created_at,
        )
        .map_err(|_| ArtifactError::InvalidReference)
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectRisk {
    NoEffect,
    KnownEffect,
    UnknownEffect,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    ModelFailure,
    InvalidModelOutput,
    ApprovalInfrastructure,
    AuditFailure,
    PersistenceFailure,
    DispatchFailure,
    ExecutorFailure,
    PolicyDenied,
    ApprovalRejected,
    BudgetExhausted,
    Cancelled,
    ExecutionTimedOut,
    RequiredSkillUnavailable,
    UnknownFailure,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryMode {
    SameWorker,
    Reassign,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryDisposition {
    SameWorker,
    Reassign,
    Either,
    ReconciliationRequired,
    ManualOnly,
    NoRetry,
}
impl RetryDisposition {
    pub const fn allows(self, mode: RetryMode) -> bool {
        matches!(
            (self, mode),
            (Self::SameWorker, RetryMode::SameWorker)
                | (Self::Reassign, RetryMode::Reassign)
                | (Self::Either, _)
        )
    }
}
pub const fn retry_disposition(
    failure: FailureClass,
    risk: EffectRisk,
    reconciled: bool,
) -> RetryDisposition {
    match risk {
        EffectRisk::UnknownEffect if !reconciled => RetryDisposition::ReconciliationRequired,
        EffectRisk::KnownEffect => RetryDisposition::ManualOnly,
        EffectRisk::UnknownEffect => match failure {
            FailureClass::ModelFailure | FailureClass::InvalidModelOutput => {
                RetryDisposition::Reassign
            }
            FailureClass::PolicyDenied
            | FailureClass::ApprovalRejected
            | FailureClass::BudgetExhausted
            | FailureClass::Cancelled
            | FailureClass::RequiredSkillUnavailable => RetryDisposition::NoRetry,
            _ => RetryDisposition::Either,
        },
        EffectRisk::NoEffect => match failure {
            FailureClass::ModelFailure | FailureClass::InvalidModelOutput => {
                RetryDisposition::Reassign
            }
            FailureClass::ApprovalInfrastructure
            | FailureClass::AuditFailure
            | FailureClass::PersistenceFailure
            | FailureClass::DispatchFailure
            | FailureClass::ExecutorFailure => RetryDisposition::Either,
            FailureClass::PolicyDenied
            | FailureClass::ApprovalRejected
            | FailureClass::BudgetExhausted
            | FailureClass::Cancelled
            | FailureClass::RequiredSkillUnavailable => RetryDisposition::NoRetry,
            FailureClass::ExecutionTimedOut | FailureClass::UnknownFailure => {
                RetryDisposition::ManualOnly
            }
        },
    }
}
fn digest(content: &[u8]) -> ContextDigest {
    let hash = Sha256::digest(content);
    let mut value = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to string")
    }
    ContextDigest::parse(value).expect("sha256 is canonical")
}
#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("artifact content is empty or too large")]
    InvalidContent,
    #[error("artifact media type is invalid")]
    InvalidMediaType,
    #[error("artifact digest mismatch")]
    DigestMismatch,
    #[error("secret artifact denied")]
    SecretArtifactDenied,
    #[error("artifact provenance is invalid")]
    InvalidProvenance,
    #[error("artifact preview limit is invalid")]
    InvalidPreviewLimit,
    #[error("artifact reference is invalid")]
    InvalidReference,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_is_effect_conservative() {
        assert_eq!(
            retry_disposition(FailureClass::ModelFailure, EffectRisk::NoEffect, false),
            RetryDisposition::Reassign
        );
        assert_eq!(
            retry_disposition(FailureClass::ModelFailure, EffectRisk::UnknownEffect, false),
            RetryDisposition::ReconciliationRequired
        );
        assert_eq!(
            retry_disposition(FailureClass::ModelFailure, EffectRisk::KnownEffect, true),
            RetryDisposition::ManualOnly
        );
    }
}
