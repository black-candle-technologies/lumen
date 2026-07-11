use std::{path::Path, time::Duration};

use sqlx::{
    migrate::Migrator,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
};

use crate::{Database, RepositoryError};

static MIGRATOR: Migrator = sqlx::migrate!("./migrations");

pub(crate) async fn connect(path: &Path) -> Result<Database, RepositoryError> {
    let options = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
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
    MIGRATOR.run(&pool).await?;
    Ok(Database::from_pool(pool))
}
