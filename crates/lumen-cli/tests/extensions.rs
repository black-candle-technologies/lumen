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
