use std::collections::BTreeMap;

use lumen_core::{
    approval::TimestampMillis,
    capability::{Capability, CapabilityName, ResourceScope},
    extension::{
        ExtensionFailureClass, PluginComponentId, PluginId, PluginManifest, PluginVersion,
        Sha256Digest,
    },
    identity::{PrincipalId, WorkspaceId},
};
use lumen_db::{
    Database, InstallResult, PluginGrantScope, PluginSettingScope, PluginWorkspaceState,
    RepositoryError, StagedPluginPackage,
};
use serde_json::json;
use tempfile::tempdir;
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("UUID"))
}

fn digest(byte: char) -> Sha256Digest {
    Sha256Digest::parse(byte.to_string().repeat(64)).expect("digest")
}

fn manifest(version: &str, artifact: char) -> PluginManifest {
    toml::from_str(&format!(
        r#"manifest_version = 1
id = "dev.example.git-tools"
name = "Git Tools"
version = "{version}"
description = "Read status"

[runtime]
type = "wasm-component"
entrypoint = "plugin.wasm"
protocol_version = 1

[[components]]
id = "status"
kind = "tool"
description = "Read status"
input_schema = "schemas/input.json"
output_schema = "schemas/output.json"
action_kinds = ["filesystem.read"]

[[components.capabilities]]
name = "fs.read"
scope = "workspace"

[integrity]
algorithm = "sha256"
artifact = "{}"
"#,
        artifact.to_string().repeat(64)
    ))
    .expect("manifest")
}

fn staged(version: &str, package: char, artifact: char) -> StagedPluginPackage {
    let manifest = manifest(version, artifact);
    StagedPluginPackage::new(
        Uuid::new_v4(),
        manifest,
        format!("quarantine/{}", package.to_string().repeat(64)),
        BTreeMap::from([
            ("lumen-plugin.toml".to_owned(), digest('a')),
            ("plugin.wasm".to_owned(), digest(artifact)),
        ]),
        digest(package),
        digest('b'),
        PrincipalId::new("local", "admin").expect("principal"),
        TimestampMillis::new(1_000),
    )
    .expect("staged package")
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
async fn migration_adds_the_complete_extension_schema() {
    let database = Database::connect_in_memory().await.expect("database");
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'plugin_%' ORDER BY name",
    )
    .fetch_all(database.pool())
    .await
    .expect("tables");
    for required in [
        "plugin_capability_grants",
        "plugin_capability_requests",
        "plugin_components",
        "plugin_failures",
        "plugin_grant_revisions",
        "plugin_settings",
        "plugin_staged_packages",
        "plugin_versions",
        "plugin_workspace_versions",
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
    assert_eq!(migrations, 3);
}

#[tokio::test]
async fn milestone_two_database_upgrades_without_rewriting_existing_tables() {
    let directory = tempdir().expect("directory");
    let path = directory.path().join("upgrade.sqlite3");
    let database = Database::connect(&path).await.expect("database");
    database
        .insert_workspace(workspace_id(), "Preserved", TimestampMillis::new(500))
        .await
        .expect("workspace");
    for statement in [
        "DROP TABLE plugin_failures",
        "DROP TABLE plugin_settings",
        "DROP TABLE plugin_capability_grants",
        "DROP TABLE plugin_grant_revisions",
        "DROP TABLE plugin_workspace_versions",
        "DROP TABLE plugin_capability_requests",
        "DROP TABLE plugin_components",
        "DROP TABLE plugin_versions",
        "DROP TABLE plugins",
        "DROP TABLE plugin_staged_packages",
    ] {
        sqlx::query(statement)
            .execute(database.pool())
            .await
            .expect("drop Milestone 3 table");
    }
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 3")
        .execute(database.pool())
        .await
        .expect("remove migration marker");
    database.close().await;

    let upgraded = Database::connect(&path).await.expect("upgrade");
    let workspace_name: String = sqlx::query_scalar("SELECT name FROM workspaces WHERE id = ?")
        .bind(workspace_id().to_string())
        .fetch_one(upgraded.pool())
        .await
        .expect("workspace preserved");
    assert_eq!(workspace_name, "Preserved");
    let versions_exist: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'plugin_versions'",
    )
    .fetch_one(upgraded.pool())
    .await
    .expect("table check");
    assert_eq!(versions_exist, 1);
}

#[tokio::test]
async fn install_is_immutable_idempotent_and_disabled_without_grants() {
    let database = database().await;
    let staged_package = staged("1.2.3", '1', '2');
    database
        .insert_staged_plugin_package(&staged_package)
        .await
        .expect("stage metadata");
    assert!(
        sqlx::query("UPDATE plugin_staged_packages SET package_digest = ? WHERE id = ?")
            .bind("f".repeat(64))
            .bind(staged_package.id().to_string())
            .execute(database.pool())
            .await
            .is_err()
    );
    assert_eq!(
        database
            .install_staged_plugin(
                staged_package.id(),
                "plugins/dev.example.git-tools/1.2.3/2222",
                TimestampMillis::new(1_100),
            )
            .await
            .expect("install"),
        InstallResult::Installed
    );
    assert_eq!(
        database
            .install_staged_plugin(
                staged_package.id(),
                "plugins/dev.example.git-tools/1.2.3/2222",
                TimestampMillis::new(1_200),
            )
            .await
            .expect("idempotent install"),
        InstallResult::AlreadyInstalled
    );

    let state = database
        .plugin_workspace_state(
            workspace_id(),
            PluginId::parse("dev.example.git-tools").expect("ID"),
            PluginVersion::parse("1.2.3").expect("version"),
        )
        .await
        .expect("state");
    assert_eq!(state, None);
    let grants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_capability_grants")
        .fetch_one(database.pool())
        .await
        .expect("grant count");
    assert_eq!(grants, 0);
    assert!(
        sqlx::query(
            "UPDATE plugin_versions SET artifact_digest = ?
             WHERE plugin_id = 'dev.example.git-tools' AND version = '1.2.3'",
        )
        .bind("e".repeat(64))
        .execute(database.pool())
        .await
        .is_err()
    );

    let conflicting = staged("1.2.3", '3', '4');
    database
        .insert_staged_plugin_package(&conflicting)
        .await
        .expect("conflicting stage metadata");
    assert!(matches!(
        database
            .install_staged_plugin(
                conflicting.id(),
                "plugins/dev.example.git-tools/1.2.3/4444",
                TimestampMillis::new(1_300),
            )
            .await,
        Err(RepositoryError::PluginVersionConflict)
    ));
}

#[tokio::test]
async fn workspace_version_switch_is_atomic_and_artifact_quarantine_is_global() {
    let database = database().await;
    for (version, package, artifact) in [("1.0.0", '1', '2'), ("2.0.0", '3', '4')] {
        let staged = staged(version, package, artifact);
        database
            .insert_staged_plugin_package(&staged)
            .await
            .expect("stage");
        database
            .install_staged_plugin(
                staged.id(),
                format!("plugins/dev.example.git-tools/{version}/{artifact}"),
                TimestampMillis::new(1_100),
            )
            .await
            .expect("install");
    }
    let plugin = PluginId::parse("dev.example.git-tools").expect("ID");
    let first = PluginVersion::parse("1.0.0").expect("version");
    let second = PluginVersion::parse("2.0.0").expect("version");
    database
        .enable_plugin_version(
            workspace_id(),
            plugin.clone(),
            first.clone(),
            TimestampMillis::new(2_000),
        )
        .await
        .expect("enable first");
    database
        .enable_plugin_version(
            workspace_id(),
            plugin.clone(),
            second.clone(),
            TimestampMillis::new(2_100),
        )
        .await
        .expect("switch");
    assert_eq!(
        database
            .plugin_workspace_state(workspace_id(), plugin.clone(), first)
            .await
            .expect("first state"),
        Some(PluginWorkspaceState::Disabled)
    );
    assert_eq!(
        database
            .plugin_workspace_state(workspace_id(), plugin.clone(), second.clone())
            .await
            .expect("second state"),
        Some(PluginWorkspaceState::Enabled)
    );
    database
        .quarantine_plugin_artifact(plugin.clone(), second.clone(), TimestampMillis::new(2_200))
        .await
        .expect("artifact quarantine");
    assert!(
        database
            .enable_plugin_version(workspace_id(), plugin, second, TimestampMillis::new(2_300))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn grants_require_a_manifest_request_and_settings_are_optimistic_revisions() {
    let database = database().await;
    let staged = staged("1.2.3", '1', '2');
    database
        .insert_staged_plugin_package(&staged)
        .await
        .expect("stage");
    database
        .install_staged_plugin(
            staged.id(),
            "plugins/git/1.2.3/artifact",
            TimestampMillis::new(1_100),
        )
        .await
        .expect("install");
    let plugin = PluginId::parse("dev.example.git-tools").expect("ID");
    let version = PluginVersion::parse("1.2.3").expect("version");
    let component = PluginComponentId::parse("status").expect("component");
    let fs_read = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::workspace(workspace_id()),
    );
    let revision = database
        .append_plugin_grant_revision(
            plugin.clone(),
            version.clone(),
            component.clone(),
            PluginGrantScope::Global,
            None,
            vec![fs_read],
            digest('8'),
            TimestampMillis::new(1_200),
        )
        .await
        .expect("declared grant");
    assert_eq!(revision, 1);
    let undeclared = Capability::new(
        CapabilityName::NetConnect,
        ResourceScope::exact("host", "example.com:443").expect("scope"),
    );
    assert!(matches!(
        database
            .append_plugin_grant_revision(
                plugin.clone(),
                version.clone(),
                component,
                PluginGrantScope::Workspace(workspace_id()),
                None,
                vec![undeclared],
                digest('9'),
                TimestampMillis::new(1_300),
            )
            .await,
        Err(RepositoryError::PluginGrantConflict)
    ));

    let setting = database
        .put_plugin_setting(
            plugin.clone(),
            version.clone(),
            PluginSettingScope::Workspace(workspace_id()),
            None,
            json!({"prefix": "safe"}),
            digest('a'),
            TimestampMillis::new(1_400),
        )
        .await
        .expect("first setting");
    assert_eq!(setting.config_version(), 1);
    assert!(matches!(
        database
            .put_plugin_setting(
                plugin,
                version,
                PluginSettingScope::Workspace(workspace_id()),
                None,
                json!({"prefix": "stale"}),
                digest('a'),
                TimestampMillis::new(1_500),
            )
            .await,
        Err(RepositoryError::PluginSettingConflict)
    ));
}

#[tokio::test]
async fn rolling_failures_quarantine_one_workspace_and_survive_reopen() {
    let directory = tempdir().expect("directory");
    let path = directory.path().join("lumen.sqlite3");
    let database = Database::connect(&path).await.expect("database");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(500))
        .await
        .expect("workspace");
    let staged = staged("1.2.3", '1', '2');
    database
        .insert_staged_plugin_package(&staged)
        .await
        .expect("stage");
    database
        .install_staged_plugin(
            staged.id(),
            "plugins/git/1.2.3/artifact",
            TimestampMillis::new(1_100),
        )
        .await
        .expect("install");
    let plugin = PluginId::parse("dev.example.git-tools").expect("ID");
    let version = PluginVersion::parse("1.2.3").expect("version");
    let component = PluginComponentId::parse("status").expect("component");
    database
        .enable_plugin_version(
            workspace_id(),
            plugin.clone(),
            version.clone(),
            TimestampMillis::new(1_200),
        )
        .await
        .expect("enable");
    for timestamp in [2_000, 3_000, 4_000] {
        database
            .record_plugin_failure(
                workspace_id(),
                plugin.clone(),
                version.clone(),
                component.clone(),
                Uuid::new_v4(),
                ExtensionFailureClass::PluginFault,
                TimestampMillis::new(timestamp),
            )
            .await
            .expect("failure");
    }
    database.close().await;

    let reopened = Database::connect(&path).await.expect("reopen");
    assert_eq!(
        reopened
            .plugin_workspace_state(workspace_id(), plugin, version)
            .await
            .expect("state"),
        Some(PluginWorkspaceState::HealthQuarantine)
    );
}
