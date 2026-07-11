//! SQLite persistence for Lumen runtime state.

mod audit;
mod migrations;
mod repositories;

use std::path::Path;

use sqlx::{SqlitePool, migrate::MigrateError};
use thiserror::Error;

pub use repositories::DispatchReservation;

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
}

pub(crate) fn timestamp_to_i64(
    timestamp: lumen_core::approval::TimestampMillis,
) -> Result<i64, RepositoryError> {
    i64::try_from(timestamp.as_u64()).map_err(|_| RepositoryError::TimestampOutOfRange)
}
