//! SQLite persistence for Lumen runtime state.

mod artifact;
mod audit;
mod automation;
mod context;
mod egress;
mod extensions;
mod lifecycle;
mod migrations;
mod model_registry;
mod orchestration;
mod repositories;
mod routing;
mod worker;

use std::path::Path;

use sqlx::{SqlitePool, migrate::MigrateError};
use thiserror::Error;

pub use automation::{
    ScheduledJobRevision, ServiceIdentity, SkillPublicationIntent, SkillVersionRecord,
    WorkflowCaptureDraft,
};
pub use egress::{
    ChannelIdentityMapping, DestinationRevision, ModelEndpointClass, ModelProviderRevision,
    WorkspaceModelEgressRevision,
};
pub use extensions::{
    InstallResult, InstalledPluginVersion, PluginGrantRevision, PluginGrantScope,
    PluginSettingRevision, PluginSettingScope, PluginWorkspaceState, StagedPluginPackage,
};
pub use lifecycle::{EffectCertainty, RunLifecycleView, TerminalSpec, TerminalState};
pub use repositories::{
    DispatchReservation, PendingApprovalView, RecoveredExecution, SecretReference,
    SecretReferenceError,
};
pub use routing::RoutingDispatchRecord;
pub use worker::WorkerAttemptRecord;

#[derive(Clone, Debug)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, RepositoryError> {
        migrations::connect(path.as_ref()).await
    }

    pub async fn connect_in_memory() -> Result<Self, RepositoryError> {
        migrations::connect_in_memory().await
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn close(self) {
        self.pool.close().await;
    }

    pub(crate) const fn from_pool(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error(transparent)]
    Sqlx(#[from] sqlx::Error),
    #[error(transparent)]
    Migration(#[from] MigrateError),
    #[error(transparent)]
    Serialization(#[from] serde_json::Error),
    #[error("timestamp exceeds SQLite's signed integer range")]
    TimestampOutOfRange,
    #[error("approval is not currently available for this dispatch")]
    ApprovalNotAvailable,
    #[error("approval does not reference a stored action")]
    MissingAction,
    #[error("approval decision conflicts with its stored state or workspace")]
    ApprovalDecisionConflict,
    #[error("approval decision uses a stale fingerprint or policy revision")]
    ApprovalStale,
    #[error("approval action changed after review")]
    ApprovalActionChanged,
    #[error("approval expired before the decision completed")]
    ApprovalExpired,
    #[error("approval was already consumed")]
    ApprovalConsumed,
    #[error("run state is invalid: {0}")]
    InvalidRunState(String),
    #[error("execution attempt conflicts with its stored action or state")]
    ExecutionStateConflict,
    #[error("stored secret reference is invalid: {0}")]
    InvalidSecretReference(String),
    #[error("staged plugin package is invalid: {0}")]
    InvalidPluginPackage(String),
    #[error("plugin ID and version are already installed with different bytes")]
    PluginVersionConflict,
    #[error("plugin lifecycle state conflicts with the requested operation")]
    PluginStateConflict,
    #[error("plugin capability grant conflicts with requests or revisions")]
    PluginGrantConflict,
    #[error("plugin setting revision conflicts with current state")]
    PluginSettingConflict,
    #[error("egress policy conflicts with repository constraints")]
    InvalidEgressPolicy,
    #[error("model registry state conflicts with repository constraints")]
    InvalidModelRegistry,
    #[error("secure context state conflicts with repository constraints")]
    InvalidContextState,
    #[error("orchestration state conflicts with repository constraints")]
    InvalidOrchestrationState,
    #[error("worker execution state conflicts with repository constraints")]
    InvalidWorkerState,
    #[error("routing/accounting state conflicts with repository constraints")]
    InvalidRoutingState,
    #[error("routing budget changed or no longer has sufficient capacity")]
    RoutingBudgetConflict,
    #[error("artifact/retry state conflicts with repository constraints")]
    InvalidArtifactState,
    #[error("automation state conflicts with repository constraints")]
    InvalidAutomationState,
    #[error("skill version metadata conflicts with the pinned skill identity")]
    SkillMetadataConflict,
}

pub(crate) fn timestamp_to_i64(
    timestamp: lumen_core::approval::TimestampMillis,
) -> Result<i64, RepositoryError> {
    i64::try_from(timestamp.as_u64()).map_err(|_| RepositoryError::TimestampOutOfRange)
}
