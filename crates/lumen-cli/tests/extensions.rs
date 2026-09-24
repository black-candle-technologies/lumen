use std::{fs, sync::Arc};

use clap::Parser;
use lumen_cli::{Cli, Command, CommandOutput, PluginCommand, execute_with_secret_store};
use lumen_db::Database;
use lumen_integrations::secrets::InMemorySecretStore;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

mod support;
use support::toml_path;

fn write_config(root: &std::path::Path) -> std::path::PathBuf {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let path = root.join("lumen.toml");
    fs::write(
        &path,
        format!(
            r#"[database]
path = {}
[model]
endpoint = "http://127.0.0.1:8080/v1/"
model = "local-model"
[runtime]
data_directory = {}
[workspace]
id = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name = "Default"
path = {}
[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
            toml_path(root.join("lumen.sqlite3")),
            toml_path(root.join("runtime")),
            toml_path(&workspace)
        ),
    )
    .expect("config");
    path
}

fn write_package(root: &std::path::Path) {
    fs::create_dir_all(root.join("schemas")).expect("schemas");
    fs::write(root.join("plugin.wasm"), b"component").expect("artifact");
    fs::write(root.join("schemas/input.json"), r#"{"type":"object"}"#).expect("schema");
    fs::write(root.join("schemas/output.json"), r#"{"type":"object"}"#).expect("schema");
    let artifact = format!("{:x}", Sha256::digest(b"component"));
    fs::write(
        root.join("lumen-plugin.toml"),
        format!(
            r#"manifest_version = 1
id = "dev.example.fixture"
name = "Fixture"
version = "1.0.0"
description = "Fixture"
[runtime]
type = "wasm-component"
entrypoint = "plugin.wasm"
protocol_version = 1
[[components]]
id = "echo"
kind = "tool"
description = "Echo"
input_schema = "schemas/input.json"
output_schema = "schemas/output.json"
[integrity]
algorithm = "sha256"
artifact = "{artifact}"
"#
        ),
    )
    .expect("manifest");
}

#[test]
fn plugin_operator_commands_have_explicit_local_grammar() {
    let cli = Cli::try_parse_from([
        "lumen",
        "plugin",
        "submit",
        "./fixture",
        "--reason",
        "operator review",
    ])
    .expect("submit");
    assert_eq!(
        cli.command,
        Command::Plugin {
            command: PluginCommand::Submit {
                directory: "./fixture".into(),
                reason: "operator review".into(),
                as_principal: None,
            },
        }
    );
    // The previous `stage`/`review` verbs remain as aliases.
    assert!(
        Cli::try_parse_from(["lumen", "plugin", "stage", "./fixture", "--reason", "r"]).is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "submit",
            "https://example.com/p",
            "--reason",
            "r"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "install",
            "26db5a31-94f0-4e92-a9c9-4cdf19d71c31",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from(["lumen", "plugin", "enable", "dev.example.fixture", "1.0.0",]).is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "test",
            "26db5a31-94f0-4e92-a9c9-4cdf19d71c31",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "approve",
            "26db5a31-94f0-4e92-a9c9-4cdf19d71c31",
            "--reason",
            "reviewed",
            "--yes",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "revoke",
            "dev.example.fixture",
            "1.0.0",
            "--reason",
            "compromised",
            "--yes",
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "invoke",
            "dev.example.fixture",
            "1.0.0",
            "echo",
            "--input",
            "input.json",
        ])
        .is_ok()
    );
    // Dangerous actions require an explicit reason.
    assert!(
        Cli::try_parse_from([
            "lumen",
            "plugin",
            "approve",
            "26db5a31-94f0-4e92-a9c9-4cdf19d71c31",
            "--yes",
        ])
        .is_err()
    );
}

#[tokio::test]
async fn submit_records_quarantine_identity_without_installing_or_enabling() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let output = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::Submit {
                    directory: package,
                    reason: "test submission".into(),
                    as_principal: None,
                },
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("submit");
    let CommandOutput::PluginSubmitted(submitted) = output else {
        panic!("unexpected submit output");
    };
    assert_eq!(submitted.admission_status, "submitted");

    let database = Database::connect(root.path().join("lumen.sqlite3"))
        .await
        .expect("database");
    let staged: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_staged_packages")
        .fetch_one(database.pool())
        .await
        .expect("staged count");
    let installed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_versions")
        .fetch_one(database.pool())
        .await
        .expect("installed count");
    let enabled: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_workspace_versions")
        .fetch_one(database.pool())
        .await
        .expect("enabled count");
    assert_eq!((staged, installed, enabled), (1, 0, 0));

    // The admission record pins the digest.
    let admissions = root.path().join("runtime/plugins/admissions/records");
    let entries: Vec<_> = fs::read_dir(&admissions)
        .expect("admissions dir")
        .collect::<Result<_, _>>()
        .expect("admission entries");
    assert_eq!(entries.len(), 1);
    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(entries[0].path()).expect("record bytes"))
            .expect("record json");
    assert_eq!(record["decisions"][0]["kind"], "submitted");
    assert_eq!(
        record["digests"]["package"].as_str().expect("digest"),
        submitted.package_digest
    );
}

#[tokio::test]
async fn inspect_returns_full_staged_identity_without_mutating_state() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let staged = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Submit {
                    directory: package,
                    reason: "test submission".into(),
                    as_principal: None,
                },
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("submit");
    let CommandOutput::PluginSubmitted(staged) = staged else {
        panic!("unexpected submit output");
    };

    let reviewed = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::Inspect {
                    stage_id: staged.stage_id,
                },
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("inspect");
    let CommandOutput::PluginInspected(review) = reviewed else {
        panic!("unexpected inspect output");
    };
    assert_eq!(review.stage_id, staged.stage_id);
    assert_eq!(review.plugin_id, "dev.example.fixture");
    assert_eq!(review.version, "1.0.0");
    assert_eq!(review.package_digest, staged.package_digest);
    assert_eq!(review.package_digest.len(), 64);
    assert_eq!(review.manifest_digest.len(), 64);
    assert_eq!(review.artifact_digest.len(), 64);
    assert!(review.file_hashes.contains_key("lumen-plugin.toml"));
    assert_eq!(review.admission_status, "submitted");
    assert_eq!(review.decisions.len(), 1);
    assert_eq!(review.decisions[0].kind, "submitted");

    let database = Database::connect(root.path().join("lumen.sqlite3"))
        .await
        .expect("database");
    let actions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions")
        .fetch_one(database.pool())
        .await
        .expect("action count");
    let installed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_versions")
        .fetch_one(database.pool())
        .await
        .expect("installed count");
    assert_eq!((actions, installed), (0, 0));
}

/// Run the submit → test → approve admission flow and return the stage id.
async fn admit_fixture(
    config: &std::path::Path,
    package: &std::path::Path,
    store: &Arc<InMemorySecretStore>,
) -> uuid::Uuid {
    let submitted = execute_with_secret_store(
        Cli {
            config: config.to_path_buf(),
            command: Command::Plugin {
                command: PluginCommand::Submit {
                    directory: package.to_path_buf(),
                    reason: "test admission".into(),
                    as_principal: None,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("submit");
    let CommandOutput::PluginSubmitted(submitted) = submitted else {
        panic!("unexpected submit output");
    };
    let tested = execute_with_secret_store(
        Cli {
            config: config.to_path_buf(),
            command: Command::Plugin {
                command: PluginCommand::Test {
                    stage_id: submitted.stage_id,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("test");
    let CommandOutput::PluginTested(tested) = tested else {
        panic!("unexpected test output");
    };
    assert!(tested.passed, "fixture admission tests must pass");
    assert_eq!(tested.admission_status, "tested_passed");
    // Approval requires an explicit reason and confirmation.
    let approved = execute_with_secret_store(
        Cli {
            config: config.to_path_buf(),
            command: Command::Plugin {
                command: PluginCommand::Approve {
                    stage_id: submitted.stage_id,
                    reason: "reviewed digests and permissions".into(),
                    yes: true,
                    as_principal: None,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("approve");
    let CommandOutput::PluginApproved(approved) = approved else {
        panic!("unexpected approve output");
    };
    assert_eq!(approved.admission_status, "approved");
    submitted.stage_id
}

#[tokio::test]
async fn install_requires_admission_approval_and_leaves_approval_pending() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let store = Arc::new(InMemorySecretStore::new());

    // Install without admission is refused: the digest was never approved.
    let submitted = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Submit {
                    directory: package.clone(),
                    reason: "test admission".into(),
                    as_principal: None,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("submit");
    let CommandOutput::PluginSubmitted(submitted) = submitted else {
        panic!("unexpected submit output");
    };
    let refused = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Install {
                    stage_id: submitted.stage_id,
                },
            },
        },
        store.clone(),
        None,
    )
    .await;
    assert!(refused.is_err(), "install without approval must be refused");

    // Complete the admission flow, then install.
    let tested = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Test {
                    stage_id: submitted.stage_id,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("test");
    assert!(matches!(tested, CommandOutput::PluginTested(_)));
    execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Approve {
                    stage_id: submitted.stage_id,
                    reason: "reviewed".into(),
                    yes: true,
                    as_principal: None,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("approve");

    let requested = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::Install {
                    stage_id: submitted.stage_id,
                },
            },
        },
        store,
        None,
    )
    .await
    .expect("request install");
    let CommandOutput::PluginActionRequested(requested) = requested else {
        panic!("unexpected install output");
    };
    assert!(
        requested.approval_id.is_some(),
        "install request must surface the pending approval"
    );

    let database = Database::connect(root.path().join("lumen.sqlite3"))
        .await
        .expect("database");
    let action: (String, String) =
        sqlx::query_as("SELECT kind, state FROM actions ORDER BY created_at DESC LIMIT 1")
            .fetch_one(database.pool())
            .await
            .expect("stored action");
    // The action is requested but not executed: nothing is installed
    // directly, and the approval survives CLI exit for the operator to
    // decide in the web UI.
    let pending: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_requests WHERE state = 'pending'")
            .fetch_one(database.pool())
            .await
            .expect("pending approval count");
    let invalidated: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_requests WHERE state = 'invalidated'")
            .fetch_one(database.pool())
            .await
            .expect("invalidated approval count");
    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts")
        .fetch_one(database.pool())
        .await
        .expect("attempt count");
    let installed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_versions")
        .fetch_one(database.pool())
        .await
        .expect("installed count");
    assert_eq!(action.0, "plugin.install");
    assert_ne!(
        action.1, "cancelled",
        "CLI exit must not cancel the request"
    );
    assert_eq!((pending, invalidated, attempts, installed), (1, 0, 0, 0));
}

#[tokio::test]
async fn revoked_digest_cannot_be_installed_or_enabled() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let store = Arc::new(InMemorySecretStore::new());
    let stage_id = admit_fixture(&config, &package, &store).await;

    let revoked = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Revoke {
                    plugin_id: "dev.example.fixture".into(),
                    version: "1.0.0".into(),
                    reason: "compromised upstream".into(),
                    yes: true,
                    as_principal: None,
                },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("revoke");
    let CommandOutput::PluginRevoked(revoked) = revoked else {
        panic!("unexpected revoke output");
    };
    assert_eq!(revoked.plugin_id, "dev.example.fixture");

    // Install of the revoked digest is refused.
    let refused = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Install { stage_id },
            },
        },
        store.clone(),
        None,
    )
    .await;
    assert!(
        refused.is_err(),
        "install of revoked digest must be refused"
    );

    // Enable of the revoked digest is refused.
    let refused = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Enable {
                    plugin_id: "dev.example.fixture".into(),
                    version: "1.0.0".into(),
                },
            },
        },
        store,
        None,
    )
    .await;
    assert!(refused.is_err(), "enable of revoked digest must be refused");

    // The revocation is terminal: the decision history is preserved.
    let listed = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::List,
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("list");
    let CommandOutput::PluginAdmissionsListed(records) = listed else {
        panic!("unexpected list output");
    };
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].status, "revoked");
}
