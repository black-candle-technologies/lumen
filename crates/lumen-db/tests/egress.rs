use lumen_core::{
    approval::TimestampMillis,
    capability::{Capability, CapabilityName, ResourceScope},
    egress::{
        DataClass, DestinationScope, EndpointClass, ProviderId, RoutingFailure,
        select_model_provider,
    },
    identity::{ChannelDestination, ExternalChannelIdentity, PrincipalId, WorkspaceId},
    secret::SecretRefId,
};
use lumen_db::{
    ChannelIdentityMapping, Database, DestinationRevision, ModelEndpointClass,
    ModelProviderRevision, RepositoryError, WorkspaceModelEgressRevision,
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

fn principal() -> PrincipalId {
    PrincipalId::new("local", "alice").expect("principal")
}

async fn database() -> Database {
    let database = Database::connect_in_memory().await.expect("database");
    database
        .bootstrap_workspace(
            workspace_id(),
            "Default",
            &principal(),
            TimestampMillis::new(500),
        )
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
    assert_eq!(migrations, 5);
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
        20,
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
    assert_eq!(loaded.priority(), 20);
    assert!(loaded.allows(DataClass::Public));
    assert!(!loaded.allows(DataClass::Workspace));

    let second = ModelProviderRevision::new(
        provider.clone(),
        2,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://models.example.com/v1/").unwrap(),
        "gpt-compatible",
        true,
        10,
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
        10,
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
        10,
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

#[tokio::test]
async fn model_provider_routes_use_latest_provider_and_workspace_revisions() {
    let database = database().await;
    let provider = provider_id();
    let endpoint = DestinationScope::parse("https://models.example.com/v1/").unwrap();
    let first_provider = ModelProviderRevision::new(
        provider.clone(),
        1,
        ModelEndpointClass::Remote,
        endpoint.clone(),
        "gpt-compatible",
        true,
        20,
        Some(secret_ref()),
        [DataClass::Public],
        TimestampMillis::new(1_000),
    )
    .expect("provider");
    let second_provider = ModelProviderRevision::new(
        provider.clone(),
        2,
        ModelEndpointClass::Remote,
        endpoint,
        "gpt-compatible",
        true,
        10,
        Some(secret_ref()),
        [DataClass::Public, DataClass::Workspace],
        TimestampMillis::new(2_000),
    )
    .expect("provider");
    database
        .append_model_provider_revision(&first_provider)
        .await
        .expect("first provider stored");
    database
        .append_model_provider_revision(&second_provider)
        .await
        .expect("second provider stored");

    for revision in [
        WorkspaceModelEgressRevision::new(
            workspace_id(),
            provider.clone(),
            1,
            [DataClass::Public],
            TimestampMillis::new(1_100),
        )
        .expect("workspace policy"),
        WorkspaceModelEgressRevision::new(
            workspace_id(),
            provider.clone(),
            2,
            [DataClass::Workspace],
            TimestampMillis::new(2_100),
        )
        .expect("workspace policy"),
    ] {
        database
            .append_workspace_model_egress_revision(&revision)
            .await
            .expect("workspace policy stored");
    }

    let routes = database
        .model_provider_routes(workspace_id())
        .await
        .expect("routes loaded");
    assert_eq!(routes.len(), 1);
    assert_eq!(routes[0].provider(), &provider);
    assert_eq!(routes[0].endpoint_class(), EndpointClass::Remote);
    assert_eq!(routes[0].priority(), 10);

    let decision =
        select_model_provider(DataClass::Workspace, routes.clone()).expect("workspace allowed");
    assert_eq!(decision.provider(), &provider);
    assert_eq!(decision.endpoint_class(), EndpointClass::Remote);
    assert!(decision.egress_occurred());

    let error = select_model_provider(DataClass::Public, routes).expect_err("public denied");
    assert_eq!(error, RoutingFailure::RemoteEgressDenied);
}

#[tokio::test]
async fn local_model_provider_route_does_not_require_workspace_egress_policy() {
    let database = database().await;
    let provider = ProviderId::parse("llama-local").expect("provider");
    let provider_revision = ModelProviderRevision::new(
        provider.clone(),
        1,
        ModelEndpointClass::Local,
        DestinationScope::parse("https://localhost.localdomain/v1/").unwrap(),
        "local-qwen",
        true,
        5,
        None,
        [DataClass::Sensitive],
        TimestampMillis::new(1_000),
    )
    .expect("provider");
    database
        .append_model_provider_revision(&provider_revision)
        .await
        .expect("provider stored");

    let routes = database
        .model_provider_routes(workspace_id())
        .await
        .expect("routes loaded");
    let decision =
        select_model_provider(DataClass::Sensitive, routes).expect("local sensitive allowed");

    assert_eq!(decision.provider(), &provider);
    assert_eq!(decision.endpoint_class(), EndpointClass::Local);
    assert!(!decision.egress_occurred());
}

#[tokio::test]
async fn disabled_provider_routes_are_loaded_but_not_eligible() {
    let database = database().await;
    let provider = provider_id();
    let provider_revision = ModelProviderRevision::new(
        provider.clone(),
        1,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://models.example.com/v1/").unwrap(),
        "gpt-compatible",
        false,
        10,
        Some(secret_ref()),
        [DataClass::Public],
        TimestampMillis::new(1_000),
    )
    .expect("provider");
    let workspace_policy = WorkspaceModelEgressRevision::new(
        workspace_id(),
        provider,
        1,
        [DataClass::Public],
        TimestampMillis::new(1_100),
    )
    .expect("workspace policy");
    database
        .append_model_provider_revision(&provider_revision)
        .await
        .expect("provider stored");
    database
        .append_workspace_model_egress_revision(&workspace_policy)
        .await
        .expect("workspace policy stored");

    let routes = database
        .model_provider_routes(workspace_id())
        .await
        .expect("routes loaded");

    assert_eq!(routes.len(), 1);
    assert!(!routes[0].enabled());
    let error = select_model_provider(DataClass::Public, routes).expect_err("disabled");
    assert_eq!(error, RoutingFailure::NoEligibleProvider);
}

#[tokio::test]
async fn destination_revisions_are_append_only_and_load_latest_policy() {
    let database = database().await;
    let destination = DestinationScope::parse("https://api.example.com/v1").unwrap();
    let first = DestinationRevision::new(
        destination.clone(),
        1,
        true,
        [DataClass::Public],
        TimestampMillis::new(1_000),
    )
    .expect("destination revision");
    database
        .append_destination_revision(&first)
        .await
        .expect("destination stored");
    assert_eq!(
        database
            .latest_destination_revision(destination.clone())
            .await
            .expect("destination loaded"),
        Some(first)
    );

    let second = DestinationRevision::new(
        destination.clone(),
        2,
        false,
        [DataClass::Public, DataClass::Workspace],
        TimestampMillis::new(2_000),
    )
    .expect("destination revision");
    database
        .append_destination_revision(&second)
        .await
        .expect("second destination stored");

    assert_eq!(
        database
            .latest_destination_revision(destination)
            .await
            .expect("destination loaded"),
        Some(second)
    );
}

#[tokio::test]
async fn enabled_destinations_load_as_exact_network_egress_capabilities() {
    let database = database().await;
    let enabled = DestinationScope::parse("https://api.example.com/v1").unwrap();
    let disabled = DestinationScope::parse("https://blocked.example.com/").unwrap();
    database
        .append_destination_revision(
            &DestinationRevision::new(
                enabled.clone(),
                1,
                true,
                [DataClass::Public],
                TimestampMillis::new(1_000),
            )
            .expect("enabled destination"),
        )
        .await
        .expect("enabled stored");
    database
        .append_destination_revision(
            &DestinationRevision::new(
                disabled.clone(),
                1,
                false,
                [DataClass::Public],
                TimestampMillis::new(1_000),
            )
            .expect("disabled destination"),
        )
        .await
        .expect("disabled stored");

    let capabilities = database
        .enabled_network_egress_capabilities()
        .await
        .expect("capabilities loaded");

    assert_eq!(
        capabilities,
        vec![Capability::new(
            CapabilityName::NetworkEgress,
            ResourceScope::exact("destination", enabled.as_str()).expect("destination scope"),
        )]
    );
    let latest = database
        .list_latest_destination_revisions()
        .await
        .expect("latest destinations");
    assert_eq!(latest.len(), 2);
    assert_eq!(latest[0].destination(), &enabled);
    assert_eq!(latest[1].destination(), &disabled);
}

#[test]
fn destination_revisions_reject_secret_data_class() {
    let error = DestinationRevision::new(
        DestinationScope::parse("https://api.example.com/v1").unwrap(),
        1,
        true,
        [DataClass::Secret],
        TimestampMillis::new(1_000),
    )
    .expect_err("secret destination policy must fail");

    assert!(matches!(error, RepositoryError::InvalidEgressPolicy));
}

#[tokio::test]
async fn external_channel_mapping_resolves_only_allowed_identities() {
    let database = database().await;
    let external =
        ExternalChannelIdentity::new("slack", "T123", "C456", "U789").expect("external identity");
    let mapping = ChannelIdentityMapping::new(
        external.clone(),
        principal(),
        workspace_id(),
        true,
        TimestampMillis::new(1_000),
        TimestampMillis::new(1_000),
    )
    .expect("channel mapping");

    assert_eq!(
        database
            .resolve_external_channel_identity(&external)
            .await
            .expect("unknown identity lookup"),
        None
    );

    database
        .upsert_channel_identity_mapping(&mapping)
        .await
        .expect("mapping stored");
    assert_eq!(
        database
            .resolve_external_channel_identity(&external)
            .await
            .expect("identity lookup"),
        Some(mapping.clone())
    );

    let disabled = ChannelIdentityMapping::new(
        external.clone(),
        principal(),
        workspace_id(),
        false,
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("disabled mapping");
    database
        .upsert_channel_identity_mapping(&disabled)
        .await
        .expect("disabled mapping stored");
    assert_eq!(
        database
            .resolve_external_channel_identity(&external)
            .await
            .expect("disabled identity lookup"),
        None
    );
}

#[tokio::test]
async fn allowed_channel_mappings_load_exact_channel_send_capabilities() {
    let database = database().await;
    let allowed =
        ExternalChannelIdentity::new("slack", "T123", "C456", "U789").expect("allowed identity");
    let disabled =
        ExternalChannelIdentity::new("slack", "T123", "C999", "U789").expect("disabled identity");
    let allowed_mapping = ChannelIdentityMapping::new(
        allowed.clone(),
        principal(),
        workspace_id(),
        true,
        TimestampMillis::new(1_000),
        TimestampMillis::new(1_000),
    )
    .expect("allowed mapping");
    let disabled_mapping = ChannelIdentityMapping::new(
        disabled,
        principal(),
        workspace_id(),
        false,
        TimestampMillis::new(1_000),
        TimestampMillis::new(1_000),
    )
    .expect("disabled mapping");
    database
        .upsert_channel_identity_mapping(&allowed_mapping)
        .await
        .expect("allowed stored");
    database
        .upsert_channel_identity_mapping(&disabled_mapping)
        .await
        .expect("disabled stored");

    let destination = ChannelDestination::new(
        allowed.provider(),
        allowed.external_workspace_id(),
        allowed.channel_id(),
    )
    .expect("channel destination");

    assert_eq!(
        database
            .allowed_channel_send_capabilities(workspace_id())
            .await
            .expect("channel capabilities"),
        vec![Capability::new(
            CapabilityName::ChannelSend,
            ResourceScope::exact("channel", destination.as_scope_value()).expect("channel scope"),
        )]
    );
    assert_eq!(
        database
            .list_channel_identity_mappings(workspace_id())
            .await
            .expect("channel mappings"),
        vec![allowed_mapping, disabled_mapping]
    );
}
