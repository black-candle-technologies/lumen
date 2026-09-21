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
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "text" => Self::Text,
            "patch" => Self::Patch,
            "design" => Self::Design,
            "test" => Self::Test,
            "task_plan" => Self::TaskPlan,
            "code_review" => Self::CodeReview,
            "diagnostic_report" => Self::DiagnosticReport,
            "blob" => Self::Blob,
            _ => return None,
        })
    }
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
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "accepted" => Self::Accepted,
            "rejected" => Self::Rejected,
            _ => return None,
        })
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Rejected => "rejected",
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactValidation {
    pub artifact_id: ArtifactId,
    pub revision: u64,
    pub state: ArtifactValidationState,
    pub method: String,
    pub validator: PrincipalId,
    pub created_at: TimestampMillis,
}
impl ArtifactValidation {
    pub fn new(
        artifact_id: ArtifactId,
        revision: u64,
        state: ArtifactValidationState,
        method: impl Into<String>,
        validator: PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<Self, ArtifactError> {
        let method = method.into();
        if revision == 0
            || method.is_empty()
            || method.len() > 128
            || method.trim() != method
            || method.chars().any(char::is_control)
        {
            return Err(ArtifactError::InvalidValidation);
        }
        Ok(Self {
            artifact_id,
            revision,
            state,
            method,
            validator,
            created_at,
        })
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
    #[allow(clippy::too_many_arguments)]
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
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        id: ArtifactId,
        workspace_id: WorkspaceId,
        kind: ArtifactKind,
        media_type: impl Into<String>,
        content: Vec<u8>,
        expected_hash: ContextDigest,
        classification: DataClass,
        compartments: impl IntoIterator<Item = CompartmentId>,
        provenance: ArtifactProvenance,
        created_at: TimestampMillis,
    ) -> Result<Self, ArtifactError> {
        let artifact = Self::new(
            id,
            workspace_id,
            kind,
            media_type,
            content,
            classification,
            compartments,
            provenance,
            created_at,
        )?;
        if artifact.content_hash != expected_hash {
            return Err(ArtifactError::DigestMismatch);
        }
        Ok(artifact)
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
impl EffectRisk {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoEffect => "no_effect",
            Self::KnownEffect => "known_effect",
            Self::UnknownEffect => "unknown_effect",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "no_effect" => Self::NoEffect,
            "known_effect" => Self::KnownEffect,
            "unknown_effect" => Self::UnknownEffect,
            _ => return None,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerFailure {
    pub attempt_id: WorkerAttemptId,
    pub failure_class: FailureClass,
    pub effect_risk: EffectRisk,
    pub diagnostic: Option<String>,
    pub created_at: TimestampMillis,
}
impl WorkerFailure {
    pub fn new(
        attempt_id: WorkerAttemptId,
        failure_class: FailureClass,
        effect_risk: EffectRisk,
        diagnostic: Option<String>,
        created_at: TimestampMillis,
    ) -> Result<Self, ArtifactError> {
        if diagnostic.as_ref().is_some_and(|value| value.len() > 1024) {
            return Err(ArtifactError::InvalidFailure);
        }
        Ok(Self {
            attempt_id,
            failure_class,
            effect_risk,
            diagnostic,
            created_at,
        })
    }
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
impl FailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelFailure => "model_failure",
            Self::InvalidModelOutput => "invalid_model_output",
            Self::ApprovalInfrastructure => "approval_infrastructure",
            Self::AuditFailure => "audit_failure",
            Self::PersistenceFailure => "persistence_failure",
            Self::DispatchFailure => "dispatch_failure",
            Self::ExecutorFailure => "executor_failure",
            Self::PolicyDenied => "policy_denied",
            Self::ApprovalRejected => "approval_rejected",
            Self::BudgetExhausted => "budget_exhausted",
            Self::Cancelled => "cancelled",
            Self::ExecutionTimedOut => "execution_timed_out",
            Self::RequiredSkillUnavailable => "required_skill_unavailable",
            Self::UnknownFailure => "unknown_failure",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "model_failure" => Self::ModelFailure,
            "invalid_model_output" => Self::InvalidModelOutput,
            "approval_infrastructure" => Self::ApprovalInfrastructure,
            "audit_failure" => Self::AuditFailure,
            "persistence_failure" => Self::PersistenceFailure,
            "dispatch_failure" => Self::DispatchFailure,
            "executor_failure" => Self::ExecutorFailure,
            "policy_denied" => Self::PolicyDenied,
            "approval_rejected" => Self::ApprovalRejected,
            "budget_exhausted" => Self::BudgetExhausted,
            "cancelled" => Self::Cancelled,
            "execution_timed_out" => Self::ExecutionTimedOut,
            "required_skill_unavailable" => Self::RequiredSkillUnavailable,
            "unknown_failure" => Self::UnknownFailure,
            _ => return None,
        })
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryMode {
    SameWorker,
    Reassign,
}
impl RetryMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameWorker => "same_worker",
            Self::Reassign => "reassign",
        }
    }
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
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SameWorker => "same_worker",
            Self::Reassign => "reassign",
            Self::Either => "either",
            Self::ReconciliationRequired => "reconciliation_required",
            Self::ManualOnly => "manual_only",
            Self::NoRetry => "no_retry",
        }
    }
    pub const fn allows(self, mode: RetryMode) -> bool {
        matches!(
            (self, mode),
            (Self::SameWorker, RetryMode::SameWorker)
                | (Self::Reassign, RetryMode::Reassign)
                | (Self::Either, _)
        )
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryDecision {
    pub id: RetryDecisionId,
    pub prior_attempt_id: WorkerAttemptId,
    pub orchestration_id: OrchestrationId,
    pub graph_revision: u64,
    pub task_node_id: TaskNodeId,
    pub mode: RetryMode,
    pub failure_class: FailureClass,
    pub effect_risk: EffectRisk,
    pub disposition: RetryDisposition,
    pub allowed: bool,
    pub requested_by: PrincipalId,
    pub previous_provider_id: ProviderId,
    pub previous_provider_revision: u64,
    pub previous_profile_id: ModelProfileId,
    pub previous_profile_revision: u64,
    pub created_at: TimestampMillis,
}
impl RetryDecision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: RetryDecisionId,
        prior_attempt_id: WorkerAttemptId,
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        mode: RetryMode,
        failure_class: FailureClass,
        effect_risk: EffectRisk,
        disposition: RetryDisposition,
        allowed: bool,
        requested_by: PrincipalId,
        previous_provider_id: ProviderId,
        previous_provider_revision: u64,
        previous_profile_id: ModelProfileId,
        previous_profile_revision: u64,
        created_at: TimestampMillis,
    ) -> Result<Self, ArtifactError> {
        if graph_revision == 0
            || previous_provider_revision == 0
            || previous_profile_revision == 0
            || (allowed && !disposition.allows(mode))
        {
            return Err(ArtifactError::InvalidRetryDecision);
        }
        Ok(Self {
            id,
            prior_attempt_id,
            orchestration_id,
            graph_revision,
            task_node_id,
            mode,
            failure_class,
            effect_risk,
            disposition,
            allowed,
            requested_by,
            previous_provider_id,
            previous_provider_revision,
            previous_profile_id,
            previous_profile_revision,
            created_at,
        })
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
    #[error("artifact validation is invalid")]
    InvalidValidation,
    #[error("retry decision is invalid")]
    InvalidRetryDecision,
    #[error("worker failure is invalid")]
    InvalidFailure,
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
