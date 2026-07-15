use lumen_core::{
    approval::TimestampMillis,
    egress::{DataClass, DestinationScope, ProviderId},
    identity::WorkspaceId,
    secret::SecretRefId,
};
use lumen_db::{
    Database, ModelEndpointClass, ModelProviderRevision, RepositoryError,
    WorkspaceModelEgressRevision,
};
use sqlx::Row;
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("UUID"))
}

fn provider_id() -> ProviderId {
    ProviderId::parse("openai-compatible").expect("provider")
}

fn secret_ref() -> SecretRefId {
    SecretRefId::parse("5f7cc8b4-e848-4cb4-91ef-27c5983c41a5").expect("secret")
}

async fn database() -> Database {
    let database = Database::connect_in_memory().await.expect("database");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(500))
        .await
        .expect("workspace");
    database
}

#[tokio::test]
async fn migration_adds_controlled_egress_schema() {
    let database = Database::connect_in_memory().await.expect("database");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name LIKE 'egress_%' ORDER BY name",
    )
    .fetch_all(database.pool())
    .await
    .expect("tables");

    for required in [
        "egress_channel_mappings",
        "egress_destinations",
        "egress_model_providers",
        "egress_model_provider_revisions",
        "egress_workspace_model_policies",
    ] {
        assert!(
            tables.iter().any(|table| table == required),
            "missing {required}"
        );
    }

    let migrations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(database.pool())
        .await
        .expect("migration count");
    assert_eq!(migrations, 4);
}

#[tokio::test]
async fn provider_revisions_keep_remote_policy_and_secret_references_only() {
    let database = database().await;
    let provider = provider_id();
    let first = ModelProviderRevision::new(
        provider.clone(),
        1,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://models.example.com/v1/").unwrap(),
        "gpt-compatible",
        true,
        Some(secret_ref()),
        [DataClass::Public],
        TimestampMillis::new(1_000),
    )
    .expect("provider revision");

    database
        .append_model_provider_revision(&first)
        .await
        .expect("provider stored");
    let loaded = database
        .latest_model_provider_revision(provider.clone())
        .await
        .expect("provider loaded")
        .expect("provider exists");
    assert_eq!(loaded, first);
    assert!(loaded.allows(DataClass::Public));
    assert!(!loaded.allows(DataClass::Workspace));

    let second = ModelProviderRevision::new(
        provider.clone(),
        2,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://models.example.com/v1/").unwrap(),
        "gpt-compatible",
        true,
        Some(secret_ref()),
        [DataClass::Public, DataClass::Workspace],
        TimestampMillis::new(2_000),
    )
    .expect("provider revision");
    database
        .append_model_provider_revision(&second)
        .await
        .expect("second revision stored");
    assert_eq!(
        database
            .latest_model_provider_revision(provider)
            .await
            .expect("latest query"),
        Some(second)
    );

    let columns: Vec<String> = sqlx::query("PRAGMA table_info(egress_model_provider_revisions)")
        .fetch_all(database.pool())
        .await
        .expect("columns")
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();
    assert!(!columns.iter().any(|column| column.contains("secret_value")));
    assert!(
        columns
            .iter()
            .any(|column| column == "credential_secret_ref")
    );
}

#[tokio::test]
async fn provider_revisions_reject_secret_data_class() {
    let error = ModelProviderRevision::new(
        provider_id(),
        1,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://models.example.com/v1/").unwrap(),
        "gpt-compatible",
        true,
        Some(secret_ref()),
        [DataClass::Secret],
        TimestampMillis::new(1_000),
    )
    .expect_err("secret data class must fail");

    assert!(matches!(error, RepositoryError::InvalidEgressPolicy));
}

#[tokio::test]
async fn workspace_policy_revisions_are_provider_scoped_and_versioned() {
    let database = database().await;
    let provider = provider_id();
    let provider_revision = ModelProviderRevision::new(
        provider.clone(),
        1,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://models.example.com/v1/").unwrap(),
        "gpt-compatible",
        true,
        Some(secret_ref()),
        [DataClass::Public, DataClass::Workspace],
        TimestampMillis::new(1_000),
    )
    .expect("provider");
    database
        .append_model_provider_revision(&provider_revision)
        .await
        .expect("provider stored");

    let workspace_policy = WorkspaceModelEgressRevision::new(
        workspace_id(),
        provider.clone(),
        1,
        [DataClass::Public],
        TimestampMillis::new(1_100),
    )
    .expect("workspace policy");
    database
        .append_workspace_model_egress_revision(&workspace_policy)
        .await
        .expect("workspace policy stored");

    assert_eq!(
        database
            .latest_workspace_model_egress_revision(workspace_id(), provider)
            .await
            .expect("workspace policy loaded"),
        Some(workspace_policy)
    );
}
