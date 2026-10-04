use std::{path::Path, time::Duration};

use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::{Database, RepositoryError};

// Keep this module dependent on the checked-in migration directory.
static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub(crate) async fn connect(path: &Path) -> Result<Database, RepositoryError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        // Authority holds must survive power loss after acknowledgment.
        // WAL NORMAL can lose committed transactions on an OS/power failure.
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5));
    connect_with(options, 5).await
}

pub(crate) async fn connect_in_memory() -> Result<Database, RepositoryError> {
    let options = SqliteConnectOptions::new()
        .filename(":memory:")
        .in_memory(true)
        .foreign_keys(true);
    connect_with(options, 1).await
}

async fn connect_with(
    options: SqliteConnectOptions,
    max_connections: u32,
) -> Result<Database, RepositoryError> {
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .connect_with(options)
        .await?;
    let result: Result<(), RepositoryError> = async {
        let mut connection = pool.acquire().await?;
        sqlx::query("PRAGMA foreign_keys=OFF")
            .execute(&mut *connection)
            .await?;
        let migrated = MIGRATOR.run(&mut *connection).await;
        let restored = sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&mut *connection)
            .await;
        migrated?;
        restored?;
        let enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(&mut *connection)
            .await?;
        let violations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(&mut *connection)
            .await?;
        if enabled != 1 || violations != 0 {
            return Err(RepositoryError::InvalidModelRegistry);
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        pool.close().await;
        return Err(error);
    }
    Ok(Database::from_pool(pool))
}
