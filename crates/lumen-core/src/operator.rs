use crate::{
    approval::TimestampMillis,
    identity::{PrincipalId, WorkspaceId},
    model::ReasoningProfile,
    orchestration::OrchestrationId,
};
use serde::Serialize;
use std::{future::Future, pin::Pin};
use thiserror::Error;
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum OperatorOperation {
    Read,
    Create,
    Cancel,
    Retry,
    Reassign,
    Narrow,
    Pin,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityRequest {
    pub workspace_id: WorkspaceId,
    pub actor: PrincipalId,
    pub operation: OperatorOperation,
    pub orchestration_id: Option<OrchestrationId>,
}
pub type AuthorityFuture<'a> =
    Pin<Box<dyn Future<Output = Result<bool, OperatorError>> + Send + 'a>>;
pub trait OperatorAuthorityPort: Send + Sync {
    fn authorize<'a>(&'a self, r: &'a AuthorityRequest) -> AuthorityFuture<'a>;
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrchestrationControlPolicy {
    pub orchestration_id: OrchestrationId,
    pub revision: u64,
    pub remote_allowed: bool,
    pub prefer_local: bool,
    pub reasoning: ReasoningProfile,
    pub created_at: TimestampMillis,
}
impl OrchestrationControlPolicy {
    pub fn new(
        orchestration_id: OrchestrationId,
        revision: u64,
        remote_allowed: bool,
        prefer_local: bool,
        reasoning: ReasoningProfile,
        created_at: TimestampMillis,
    ) -> Result<Self, OperatorError> {
        if revision == 0 {
            return Err(OperatorError::InvalidPolicy);
        }
        Ok(Self {
            orchestration_id,
            revision,
            remote_allowed,
            prefer_local,
            reasoning,
            created_at,
        })
    }
    pub fn is_tightening_of(&self, o: &Self) -> bool {
        self.orchestration_id == o.orchestration_id
            && self.revision == o.revision.saturating_add(1)
            && (!self.remote_allowed || o.remote_allowed)
            && self.reasoning == o.reasoning
    }
}
#[derive(Debug, Error)]
pub enum OperatorError {
    #[error("invalid orchestration control policy")]
    InvalidPolicy,
    #[error("authority backend: {0}")]
    Backend(String),
}
