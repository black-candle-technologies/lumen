use lumen_cli::{AuditCommand, Cli, CliError, Command, CommandOutput, execute};
use lumen_core::{
    action::CanonicalValue,
    approval::TimestampMillis,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
};
use lumen_db::Database;
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
