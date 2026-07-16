use std::collections::BTreeMap;

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, TimestampMillis},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    extension::{
        ExtensionFailureClass, ExtensionProvenance, PluginComponentId, PluginId, PluginManifest,
        PluginRuntime, PluginVersion, ProtocolVersion, Sha256Digest, canonical_grant_set_digest,
    },
    identity::{ComponentId, PrincipalId, WorkspaceId},
    policy::PolicyVersion,
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
action_kinds = ["filesystem.read", "process.spawn"]

[[components.capabilities]]
name = "fs.read"
scope = "workspace"

[[components.capabilities]]
name = "process.spawn"
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
    assert_eq!(migrations, 5);
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
    sqlx::query("ALTER TABLE actions DROP COLUMN extension_provenance_json")
        .execute(database.pool())
        .await
        .expect("restore Milestone 2 actions table");
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
async fn staged_and_installed_records_round_trip_exact_review_identity() {
    let database = database().await;
    let staged = staged("1.2.3", '1', '2');
    database
        .insert_staged_plugin_package(&staged)
        .await
        .expect("stage");

    let loaded = database
        .staged_plugin_package(staged.id())
        .await
        .expect("load stage")
        .expect("staged record");
    assert_eq!(loaded.id(), staged.id());
    assert_eq!(loaded.manifest(), staged.manifest());
    assert_eq!(loaded.file_hashes(), staged.file_hashes());
    assert_eq!(loaded.package_digest(), staged.package_digest());
    assert_eq!(loaded.manifest_digest(), staged.manifest_digest());

    database
        .install_staged_plugin(
            staged.id(),
            "plugins/installed/1111",
            TimestampMillis::new(1_100),
        )
        .await
        .expect("install");
    let installed = database
        .installed_plugin_version(
            PluginId::parse("dev.example.git-tools").expect("ID"),
            PluginVersion::parse("1.2.3").expect("version"),
        )
        .await
        .expect("load installed")
        .expect("installed record");
    assert_eq!(installed.manifest(), staged.manifest());
    assert_eq!(installed.artifact_path(), "plugins/installed/1111");
    assert_eq!(installed.package_digest(), staged.package_digest());
    assert_eq!(installed.manifest_digest(), staged.manifest_digest());
    assert_eq!(
        installed.artifact_digest(),
        staged.manifest().integrity().artifact()
    );
    assert!(!installed.is_artifact_quarantined());
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
async fn disable_and_quarantine_release_are_explicit_state_transitions() {
    let database = database().await;
    let staged = staged("1.2.3", '1', '2');
    database
        .insert_staged_plugin_package(&staged)
        .await
        .expect("stage");
    database
        .install_staged_plugin(
            staged.id(),
            "plugins/installed/1111",
            TimestampMillis::new(1_100),
        )
        .await
        .expect("install");
    let plugin = PluginId::parse("dev.example.git-tools").expect("ID");
    let version = PluginVersion::parse("1.2.3").expect("version");
    database
        .enable_plugin_version(
            workspace_id(),
            plugin.clone(),
            version.clone(),
            TimestampMillis::new(1_200),
        )
        .await
        .expect("enable");
    database
        .disable_plugin_version(
            workspace_id(),
            plugin.clone(),
            version.clone(),
            TimestampMillis::new(1_300),
        )
        .await
        .expect("disable");
    assert_eq!(
        database
            .plugin_workspace_state(workspace_id(), plugin.clone(), version.clone())
            .await
            .expect("state"),
        Some(PluginWorkspaceState::Disabled)
    );

    database
        .enable_plugin_version(
            workspace_id(),
            plugin.clone(),
            version.clone(),
            TimestampMillis::new(1_400),
        )
        .await
        .expect("enable");
    for timestamp in [2_000, 3_000, 4_000] {
        database
            .record_plugin_failure(
                workspace_id(),
                plugin.clone(),
                version.clone(),
                PluginComponentId::parse("status").expect("component"),
                Uuid::new_v4(),
                ExtensionFailureClass::PluginFault,
                TimestampMillis::new(timestamp),
            )
            .await
            .expect("failure");
    }
    database
        .release_plugin_health_quarantine(
            workspace_id(),
            plugin.clone(),
            version.clone(),
            TimestampMillis::new(5_000),
        )
        .await
        .expect("release health quarantine");
    assert_eq!(
        database
            .plugin_workspace_state(workspace_id(), plugin.clone(), version.clone())
            .await
            .expect("state"),
        Some(PluginWorkspaceState::Disabled)
    );

    database
        .quarantine_plugin_artifact(plugin.clone(), version.clone(), TimestampMillis::new(6_000))
        .await
        .expect("artifact quarantine");
    database
        .release_plugin_artifact_quarantine(
            plugin.clone(),
            version.clone(),
            TimestampMillis::new(7_000),
        )
        .await
        .expect("release artifact quarantine");
    assert!(
        !database
            .installed_plugin_version(plugin, version)
            .await
            .expect("installed")
            .expect("record")
            .is_artifact_quarantined()
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
    let process_spawn = Capability::new(
        CapabilityName::ProcessSpawn,
        ResourceScope::exact("executable", "/usr/bin/echo").expect("scope"),
    );
    let global_grants = vec![fs_read.clone(), process_spawn.clone()];
    let fs_read_digest = canonical_grant_set_digest(&global_grants);
    let revision = database
        .append_plugin_grant_revision(
            plugin.clone(),
            version.clone(),
            component.clone(),
            PluginGrantScope::Global,
            None,
            global_grants,
            fs_read_digest,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("declared grant");
    assert_eq!(revision, 1);
    let narrow = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::path(workspace_id(), WorkspacePath::parse("src").expect("path")),
    );
    let narrow_digest = canonical_grant_set_digest(std::slice::from_ref(&narrow));
    assert_eq!(
        database
            .append_plugin_grant_revision(
                plugin.clone(),
                version.clone(),
                component.clone(),
                PluginGrantScope::Workspace(workspace_id()),
                None,
                vec![narrow],
                narrow_digest,
                TimestampMillis::new(1_250),
            )
            .await
            .expect("narrow workspace grant"),
        1
    );
    let undeclared = Capability::new(
        CapabilityName::NetConnect,
        ResourceScope::exact("host", "example.com:443").expect("scope"),
    );
    let undeclared_digest = canonical_grant_set_digest(std::slice::from_ref(&undeclared));
    assert!(matches!(
        database
            .append_plugin_grant_revision(
                plugin.clone(),
                version.clone(),
                component,
                PluginGrantScope::Workspace(workspace_id()),
                None,
                vec![undeclared],
                undeclared_digest,
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
    assert_ne!(setting.settings_digest(), setting.schema_digest());
    let loaded_grants = database
        .latest_plugin_grants(
            plugin.clone(),
            version.clone(),
            PluginComponentId::parse("status").expect("component"),
            PluginGrantScope::Global,
        )
        .await
        .expect("load grants")
        .expect("grant revision");
    assert_eq!(loaded_grants.revision(), 1);
    assert!(loaded_grants.allows(&fs_read));
    assert!(loaded_grants.allows(&process_spawn));
    assert_eq!(
        loaded_grants.capabilities().cloned().collect::<Vec<_>>(),
        vec![fs_read.clone(), process_spawn]
    );
    let loaded_setting = database
        .latest_plugin_setting(
            plugin.clone(),
            version.clone(),
            PluginSettingScope::Workspace(workspace_id()),
        )
        .await
        .expect("load setting")
        .expect("setting revision");
    assert_eq!(loaded_setting, setting);
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
async fn grant_and_setting_revisions_invalidate_stale_pending_approvals() {
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
    let grant = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::workspace(workspace_id()),
    );
    let initial_grant_digest = canonical_grant_set_digest(std::slice::from_ref(&grant));
    database
        .append_plugin_grant_revision(
            plugin.clone(),
            version.clone(),
            component.clone(),
            PluginGrantScope::Global,
            None,
            vec![grant.clone()],
            initial_grant_digest.clone(),
            TimestampMillis::new(1_200),
        )
        .await
        .expect("grant");
    let setting = database
        .put_plugin_setting(
            plugin.clone(),
            version.clone(),
            PluginSettingScope::Workspace(workspace_id()),
            None,
            json!({"prefix": "one"}),
            digest('a'),
            TimestampMillis::new(1_250),
        )
        .await
        .expect("setting");
    let provenance = ExtensionProvenance::new(
        plugin.clone(),
        version.clone(),
        component.clone(),
        PluginRuntime::WasmComponent,
        digest('1'),
        digest('b'),
        digest('2'),
        setting.settings_digest().clone(),
        initial_grant_digest,
        ProtocolVersion::new(1).expect("protocol"),
        None,
    );
    let action = ActionEnvelope::new(
        ActionId::new(),
        RunId::new(),
        workspace_id(),
        PrincipalId::new("local", "admin").expect("principal"),
        ComponentId::new("runtime.extensions").expect("component"),
        ActionKind::new("plugin.invoke").expect("kind"),
        CanonicalValue::object([("input", CanonicalValue::from("{}"))]),
        vec![Capability::new(
            CapabilityName::PluginInvoke,
            ResourceScope::exact("plugin_component", provenance.resource_key()).expect("scope"),
        )],
    )
    .with_extension_provenance(provenance);
    database
        .insert_action(&action, TimestampMillis::new(1_300))
        .await
        .expect("action");
    let approval = ApprovalRequest::new(
        ApprovalId::new(),
        action.fingerprint(),
        PolicyVersion::new("extension-policy-v1").expect("policy"),
        TimestampMillis::new(1_300),
        TimestampMillis::new(10_000),
    )
    .expect("approval");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");

    let narrower_grant = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::path(workspace_id(), WorkspacePath::parse("src").expect("path")),
    );
    let narrower_digest = canonical_grant_set_digest(std::slice::from_ref(&narrower_grant));
    database
        .append_plugin_grant_revision(
            plugin.clone(),
            version.clone(),
            component,
            PluginGrantScope::Global,
            Some(1),
            vec![narrower_grant],
            narrower_digest,
            TimestampMillis::new(1_400),
        )
        .await
        .expect("grant revision");
    let state: String = sqlx::query_scalar("SELECT state FROM approval_requests WHERE id = ?")
        .bind(approval.id().to_string())
        .fetch_one(database.pool())
        .await
        .expect("approval state");
    assert_eq!(state, "invalidated");

    let second = ActionEnvelope::new(
        ActionId::new(),
        RunId::new(),
        workspace_id(),
        PrincipalId::new("local", "admin").expect("principal"),
        ComponentId::new("runtime.extensions").expect("component"),
        ActionKind::new("plugin.invoke").expect("kind"),
        CanonicalValue::object([("input", CanonicalValue::from("{}"))]),
        vec![Capability::new(
            CapabilityName::PluginInvoke,
            ResourceScope::exact("plugin_component", "dev.example.git-tools@1.2.3#status")
                .expect("scope"),
        )],
    )
    .with_extension_provenance(action.extension_provenance().expect("provenance").clone());
    database
        .insert_action(&second, TimestampMillis::new(1_500))
        .await
        .expect("action");
    let second_approval = ApprovalRequest::new(
        ApprovalId::new(),
        second.fingerprint(),
        PolicyVersion::new("extension-policy-v1").expect("policy"),
        TimestampMillis::new(1_500),
        TimestampMillis::new(10_000),
    )
    .expect("approval");
    database
        .insert_approval(&second_approval)
        .await
        .expect("approval");
    database
        .put_plugin_setting(
            plugin,
            version,
            PluginSettingScope::Workspace(workspace_id()),
            Some(1),
            json!({"prefix": "two"}),
            digest('a'),
            TimestampMillis::new(1_600),
        )
        .await
        .expect("setting revision");
    let state: String = sqlx::query_scalar("SELECT state FROM approval_requests WHERE id = ?")
        .bind(second_approval.id().to_string())
        .fetch_one(database.pool())
        .await
        .expect("approval state");
    assert_eq!(state, "invalidated");
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
