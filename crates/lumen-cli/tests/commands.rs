use std::sync::Arc;

use clap::Parser;
use lumen_cli::{
    AuditCommand, Cli, CliError, Command, CommandOutput, SandboxCommand, SecretCommand, execute,
    execute_with_secret_store,
};
use lumen_core::{
    action::CanonicalValue,
    approval::TimestampMillis,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
};
use lumen_db::Database;
use lumen_integrations::secrets::{InMemorySecretStore, SecretStore};
use tempfile::tempdir;

fn write_config(directory: &std::path::Path) -> std::path::PathBuf {
    let config_path = directory.join("lumen.toml");
    let database = directory.join("lumen.sqlite3");
    let workspace = directory.join("workspace");
    std::fs::create_dir(&workspace).expect("workspace directory");
    let contents = format!(
        r#"
[database]
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
        database.display(),
        workspace.display()
    );
    std::fs::write(&config_path, contents).expect("config written");
    config_path
}

#[tokio::test]
async fn migrate_creates_the_configured_database() {
    let directory = tempdir().expect("temporary directory");
    let config = write_config(directory.path());

    let output = execute(Cli {
        config,
        command: Command::Migrate,
    })
    .await
    .expect("migration succeeds");

    assert_eq!(output, CommandOutput::Migrated);
    assert!(directory.path().join("lumen.sqlite3").exists());
}

#[tokio::test]
async fn audit_verify_checks_the_persisted_chain() {
    let directory = tempdir().expect("temporary directory");
    let config_path = write_config(directory.path());
    let database = Database::connect(directory.path().join("lumen.sqlite3"))
        .await
        .expect("database opens");
    database
        .append_audit_event(AuditEvent::new(
            AuditEventId::new(),
            TimestampMillis::new(1),
            AuditEventKind::RunCreated,
            AuditOutcome::Success,
            None,
            CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        ))
        .await
        .expect("audit event");
    database.close().await;

    let output = execute(Cli {
        config: config_path,
        command: Command::Audit {
            command: AuditCommand::Verify,
        },
    })
    .await
    .expect("audit verifies");

    assert_eq!(output, CommandOutput::AuditVerified);
}

#[tokio::test]
async fn audit_verify_rejects_a_tampered_persisted_event() {
    let directory = tempdir().expect("temporary directory");
    let config_path = write_config(directory.path());
    let database = Database::connect(directory.path().join("lumen.sqlite3"))
        .await
        .expect("database opens");
    database
        .append_audit_event(AuditEvent::new(
            AuditEventId::new(),
            TimestampMillis::new(1),
            AuditEventKind::RunCreated,
            AuditOutcome::Success,
            None,
            CanonicalValue::object([("run_id", CanonicalValue::from("original"))]),
        ))
        .await
        .expect("audit event");
    sqlx::query("UPDATE audit_events SET payload_json = '{\"run_id\":\"tampered\"}'")
        .execute(database.pool())
        .await
        .expect("audit payload tampered");
    database.close().await;

    let error = execute(Cli {
        config: config_path,
        command: Command::Audit {
            command: AuditCommand::Verify,
        },
    })
    .await
    .expect_err("tampered audit must fail verification");

    assert!(matches!(error, CliError::AuditIntegrity(_)));
}

#[tokio::test]
async fn sandbox_report_describes_the_detected_platform_without_starting_runtime() {
    let directory = tempdir().expect("temporary directory");
    let config = write_config(directory.path());

    let output = execute(Cli {
        config,
        command: Command::Sandbox {
            command: SandboxCommand::Report,
        },
    })
    .await
    .expect("sandbox report succeeds");

    let CommandOutput::SandboxReport(report) = output else {
        panic!("unexpected command output");
    };
    assert!(!report.backend().is_empty());
}

#[tokio::test]
async fn secret_create_reads_only_supplied_standard_input_and_list_omits_values() {
    let directory = tempdir().expect("temporary directory");
    let config = write_config(directory.path());
    let store = Arc::new(InMemorySecretStore::new());
    let value = b"operator-stdin-secret".to_vec();

    let created = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Secret {
                command: SecretCommand::Create {
                    label: "GitHub token".to_owned(),
                    program: "/bin/echo".into(),
                    environment: "GITHUB_TOKEN".to_owned(),
                },
            },
        },
        store.clone(),
        Some(value.clone()),
    )
    .await
    .expect("secret created");
    let CommandOutput::SecretCreated(reference) = created else {
        panic!("unexpected create output");
    };
    assert_eq!(
        store
            .resolve(reference.keychain_account())
            .await
            .expect("stored secret"),
        value
    );

    let listed = execute_with_secret_store(
        Cli {
            config,
            command: Command::Secret {
                command: SecretCommand::List,
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("secrets listed");
    assert_eq!(listed, CommandOutput::SecretReferences(vec![reference]));
    assert!(!format!("{listed:?}").contains("operator-stdin-secret"));

    let CommandOutput::SecretReferences(references) = listed else {
        panic!("unexpected list output");
    };
    let reference = references.into_iter().next().expect("listed reference");
    let deleted = execute_with_secret_store(
        Cli {
            config: directory.path().join("lumen.toml"),
            command: Command::Secret {
                command: SecretCommand::Delete { id: reference.id() },
            },
        },
        store.clone(),
        None,
    )
    .await
    .expect("secret deleted");
    assert_eq!(deleted, CommandOutput::SecretDeleted(reference.id()));
    assert!(store.resolve(reference.keychain_account()).await.is_err());
}

#[tokio::test]
async fn secret_create_rejects_command_line_values_and_duplicate_labels() {
    assert!(
        Cli::try_parse_from([
            "lumen",
            "secret",
            "create",
            "--label",
            "token",
            "--program",
            "/bin/echo",
            "--environment",
            "TOKEN",
            "--value",
            "must-not-parse",
        ])
        .is_err()
    );

    let directory = tempdir().expect("temporary directory");
    let config = write_config(directory.path());
    let store = Arc::new(InMemorySecretStore::new());
    for (value, succeeds) in [("first-secret", true), ("second-secret", false)] {
        let result = execute_with_secret_store(
            Cli {
                config: config.clone(),
                command: Command::Secret {
                    command: SecretCommand::Create {
                        label: "duplicate".to_owned(),
                        program: "/bin/echo".into(),
                        environment: "TOKEN".to_owned(),
                    },
                },
            },
            store.clone(),
            Some(value.as_bytes().to_vec()),
        )
        .await;
        assert_eq!(result.is_ok(), succeeds);
    }

    let database = Database::connect(directory.path().join("lumen.sqlite3"))
        .await
        .expect("database opens");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM secret_references")
        .fetch_one(database.pool())
        .await
        .expect("reference count");
    assert_eq!(count, 1);
}

#[tokio::test]
async fn secret_delete_removes_keychain_value_before_metadata() {
    let directory = tempdir().expect("temporary directory");
    let config = write_config(directory.path());
    let store = Arc::new(InMemorySecretStore::new());
    let created = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Secret {
                command: SecretCommand::Create {
                    label: "delete me".to_owned(),
                    program: "/bin/echo".into(),
                    environment: "TOKEN".to_owned(),
                },
            },
        },
        store,
        Some(b"delete-secret".to_vec()),
    )
    .await
    .expect("secret created");
    let CommandOutput::SecretCreated(reference) = created else {
        panic!("unexpected create output");
    };

    let error = execute_with_secret_store(
        Cli {
            config: config.clone(),
            command: Command::Secret {
                command: SecretCommand::Delete { id: reference.id() },
            },
        },
        Arc::new(InMemorySecretStore::unavailable("locked")),
        None,
    )
    .await
    .expect_err("locked credential store must prevent metadata deletion");
    assert!(error.to_string().contains("locked"));

    let database = Database::connect(directory.path().join("lumen.sqlite3"))
        .await
        .expect("database opens");
    assert!(
        database
            .get_secret_reference(reference.workspace_id(), reference.id())
            .await
            .expect("reference query")
            .is_some()
    );
}
