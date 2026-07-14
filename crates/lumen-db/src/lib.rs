//! SQLite persistence for Lumen runtime state.

mod audit;
mod extensions;
mod migrations;
mod repositories;

use std::path::Path;

use sqlx::{SqlitePool, migrate::MigrateError};
use thiserror::Error;

pub use extensions::{
    InstallResult, PluginGrantRevision, PluginGrantScope, PluginSettingRevision,
    PluginSettingScope, PluginWorkspaceState, StagedPluginPackage,
};
pub use repositories::{
    DispatchReservation, PendingApprovalView, RecoveredExecution, SecretReference,
    SecretReferenceError,
};

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
}

pub(crate) fn timestamp_to_i64(
    timestamp: lumen_core::approval::TimestampMillis,
) -> Result<i64, RepositoryError> {
    i64::try_from(timestamp.as_u64()).map_err(|_| RepositoryError::TimestampOutOfRange)
}
