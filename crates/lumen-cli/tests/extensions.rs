use std::{fs, sync::Arc};

use clap::Parser;
use lumen_cli::{Cli, Command, CommandOutput, PluginCommand, execute_with_secret_store};
use lumen_db::Database;
use lumen_integrations::secrets::InMemorySecretStore;
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn write_config(root: &std::path::Path) -> std::path::PathBuf {
    let workspace = root.join("workspace");
    fs::create_dir(&workspace).expect("workspace");
    let path = root.join("lumen.toml");
    fs::write(
        &path,
        format!(
            r#"[database]
path = "{}"
[model]
endpoint = "http://127.0.0.1:8080/v1/"
model = "local-model"
[workspace]
id = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name = "Default"
path = "{}"
[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
            root.join("lumen.sqlite3").display(),
            workspace.display()
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
    let cli = Cli::try_parse_from(["lumen", "plugin", "stage", "./fixture"]).expect("stage");
    assert_eq!(
        cli.command,
        Command::Plugin {
            command: PluginCommand::Stage {
                directory: "./fixture".into(),
            },
        }
    );
    assert!(Cli::try_parse_from(["lumen", "plugin", "stage", "https://example.com/p"]).is_err());
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
            "invoke",
            "dev.example.fixture",
            "1.0.0",
            "echo",
            "--input",
            "input.json",
        ])
        .is_ok()
    );
}

#[tokio::test]
async fn stage_records_quarantine_identity_without_installing_or_enabling() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let output = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::Stage { directory: package },
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("stage");
    assert!(matches!(output, CommandOutput::PluginStaged(_)));

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
}

#[tokio::test]
async fn review_returns_full_staged_identity_without_mutating_state() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let staged = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Stage { directory: package },
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("stage");
    let CommandOutput::PluginStaged(staged) = staged else {
        panic!("unexpected stage output");
    };

    let reviewed = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::Review {
                    stage_id: staged.stage_id,
                },
            },
        },
        Arc::new(InMemorySecretStore::new()),
        None,
    )
    .await
    .expect("review");
    let CommandOutput::PluginReview(review) = reviewed else {
        panic!("unexpected review output");
    };
    assert_eq!(review.stage_id, staged.stage_id);
    assert_eq!(review.plugin_id, "dev.example.fixture");
    assert_eq!(review.version, "1.0.0");
    assert_eq!(review.package_digest, staged.package_digest);
    assert_eq!(review.package_digest.len(), 64);
    assert_eq!(review.manifest_digest.len(), 64);
    assert_eq!(review.artifact_digest.len(), 64);
    assert!(review.file_hashes.contains_key("lumen-plugin.toml"));

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

#[tokio::test]
async fn install_command_creates_approval_bound_action_without_installing_directly() {
    let root = tempdir().expect("root");
    let config = write_config(root.path());
    let package = root.path().join("fixture");
    fs::create_dir(&package).expect("package");
    write_package(&package);
    let store = Arc::new(InMemorySecretStore::new());
    let staged = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Plugin {
                command: PluginCommand::Stage { directory: package },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("stage");
    let CommandOutput::PluginStaged(staged) = staged else {
        panic!("unexpected stage output");
    };

    let requested = execute_with_secret_store(
        Cli {
            config,
            command: Command::Plugin {
                command: PluginCommand::Install {
                    stage_id: staged.stage_id,
                },
            },
        },
        store,
        None,
    )
    .await
    .expect("request install");
    assert!(matches!(requested, CommandOutput::PluginActionRequested(_)));

    let database = Database::connect(root.path().join("lumen.sqlite3"))
        .await
        .expect("database");
    let action: (String, String) =
        sqlx::query_as("SELECT kind, state FROM actions ORDER BY created_at DESC LIMIT 1")
            .fetch_one(database.pool())
            .await
            .expect("stored action");
    let approvals: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM approval_requests WHERE state = 'pending'")
            .fetch_one(database.pool())
            .await
            .expect("approval count");
    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts")
        .fetch_one(database.pool())
        .await
        .expect("attempt count");
    let installed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM plugin_versions")
        .fetch_one(database.pool())
        .await
        .expect("installed count");
    assert_eq!(
        action,
        ("plugin.install".to_owned(), "normalized".to_owned())
    );
    assert_eq!((approvals, attempts, installed), (1, 0, 0));
}
