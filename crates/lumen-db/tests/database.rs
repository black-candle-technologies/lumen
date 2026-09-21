use std::sync::{
    Arc,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::task::Poll;

use futures_util::poll;
use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, ExecutionAttemptId, TimestampMillis},
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditIntegrityError, AuditOutcome},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    identity::{ComponentId, PrincipalId, WorkspaceId},
    policy::PolicyVersion,
};
use lumen_db::{Database, DispatchReservation, RepositoryError, SecretReference};
use lumen_db::{EffectCertainty, TerminalSpec, TerminalState};
use sqlx::Row;
use tempfile::tempdir;
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(
        Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("valid UUID"),
    )
}

fn test_executable() -> String {
    std::env::current_exe()
        .expect("current test executable")
        .to_string_lossy()
        .into_owned()
}

fn action_id() -> ActionId {
    ActionId::from_uuid(
        Uuid::parse_str("63908e55-6719-48c4-b43b-95f52264703f").expect("valid UUID"),
    )
}

fn approval_id() -> ApprovalId {
    ApprovalId::from_uuid(
        Uuid::parse_str("8e4cf97d-228d-4f63-b644-b28f24f8cd78").expect("valid UUID"),
    )
}

fn policy_version() -> PolicyVersion {
    PolicyVersion::new("policy-v1").expect("valid policy version")
}

fn action() -> ActionEnvelope {
    ActionEnvelope::new(
        action_id(),
        RunId::from_uuid(
            Uuid::parse_str("f553a2c1-ee86-4c66-af7f-8e913a08ff17").expect("valid UUID"),
        ),
        workspace_id(),
        PrincipalId::new("local", "riley").expect("valid principal"),
        ComponentId::new("builtin.filesystem").expect("valid component"),
        ActionKind::new("filesystem.write").expect("valid action kind"),
        CanonicalValue::object([("path", CanonicalValue::from("notes/today.md"))]),
        vec![Capability::new(
            CapabilityName::FsWrite,
            ResourceScope::path(
                workspace_id(),
                WorkspacePath::parse("notes/today.md").expect("valid path"),
            ),
        )],
    )
}

fn granted_approval(action: &ActionEnvelope) -> ApprovalRequest {
    let mut approval = ApprovalRequest::new(
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("valid approval request");
    approval
        .grant(
            PrincipalId::new("local", "admin").expect("valid principal"),
            TimestampMillis::new(1_200),
        )
        .expect("approval can be granted");
    approval
}

#[tokio::test]
async fn empty_database_runs_the_initial_migration() {
    let database = Database::connect_in_memory().await.expect("database opens");

    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(database.pool())
            .await
            .expect("table names load");

    for required in [
        "actions",
        "approval_requests",
        "audit_events",
        "execution_attempts",
        "identities",
        "secret_references",
        "workspaces",
    ] {
        assert!(
            tables.iter().any(|table| table == required),
            "missing required table {required}"
        );
    }

    let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(database.pool())
        .await
        .expect("migration metadata loads");
    assert_eq!(migration_count, 16);
}

#[tokio::test]
async fn file_database_reopens_without_reapplying_migrations() {
    let directory = tempdir().expect("temporary directory created");
    let path = directory.path().join("lumen.sqlite3");

    let database = Database::connect(&path).await.expect("database created");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database.close().await;

    let reopened = Database::connect(&path).await.expect("database reopened");
    let workspace_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspaces")
        .fetch_one(reopened.pool())
        .await
        .expect("workspace count loads");
    let migration_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(reopened.pool())
        .await
        .expect("migration count loads");

    assert_eq!(workspace_count, 1);
    assert_eq!(migration_count, 16);
}

#[tokio::test]
async fn previous_schema_is_upgraded_with_opaque_secret_reference_metadata() {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("upgrade.sqlite3");
    let database = Database::connect(&path)
        .await
        .expect("current database opens");
    sqlx::query("DROP TABLE secret_references")
        .execute(database.pool())
        .await
        .expect("Milestone 2 table removed");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = 2")
        .execute(database.pool())
        .await
        .expect("Milestone 2 migration marker removed");
    database.close().await;

    let upgraded = Database::connect(&path)
        .await
        .expect("previous schema upgrades");

    let table_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master
         WHERE type = 'table' AND name = 'secret_references'",
    )
    .fetch_one(upgraded.pool())
    .await
    .expect("secret table query");
    assert_eq!(table_count, 1);
}

#[tokio::test]
async fn secret_reference_repository_never_stores_secret_values() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    let executable = test_executable();
    let reference = SecretReference::new(
        lumen_core::secret::SecretRefId::parse("5f7cc8b4-e848-4cb4-91ef-27c5983c41a5")
            .expect("secret reference"),
        workspace_id(),
        "GitHub token",
        &executable,
        "GITHUB_TOKEN",
        TimestampMillis::new(1_100),
    )
    .expect("secret metadata");

    database
        .insert_secret_reference(&reference)
        .await
        .expect("reference inserted");

    let loaded = database
        .get_secret_reference(workspace_id(), reference.id())
        .await
        .expect("reference query")
        .expect("reference found");
    assert_eq!(loaded, reference);
    assert!(loaded.allows(workspace_id(), &executable, "GITHUB_TOKEN"));
    assert!(!loaded.allows(workspace_id(), "C:\\other", "GITHUB_TOKEN"));
    assert!(!loaded.allows(workspace_id(), &executable, "OTHER_TOKEN"));
    let schema: String = sqlx::query_scalar(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'secret_references'",
    )
    .fetch_one(database.pool())
    .await
    .expect("secret schema");
    assert!(!schema.to_ascii_lowercase().contains("secret_value"));
    assert!(!schema.to_ascii_lowercase().contains("credential_value"));
    let stored_columns: Vec<String> = sqlx::query("PRAGMA table_info(secret_references)")
        .fetch_all(database.pool())
        .await
        .expect("secret columns")
        .into_iter()
        .map(|row| row.get::<String, _>("name"))
        .collect();
    assert_eq!(
        stored_columns,
        vec![
            "id".to_owned(),
            "workspace_id".to_owned(),
            "label".to_owned(),
            "keychain_account".to_owned(),
            "executable".to_owned(),
            "environment_name".to_owned(),
            "created_at".to_owned(),
            "updated_at".to_owned(),
        ]
    );
}

#[tokio::test]
async fn secret_references_are_workspace_scoped_and_deletable() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    let reference = SecretReference::new(
        lumen_core::secret::SecretRefId::new(),
        workspace_id(),
        "Build token",
        test_executable(),
        "BUILD_TOKEN",
        TimestampMillis::new(1_100),
    )
    .expect("secret metadata");
    database
        .insert_secret_reference(&reference)
        .await
        .expect("reference inserted");

    assert!(
        database
            .get_secret_reference(WorkspaceId::new(), reference.id())
            .await
            .expect("other workspace query")
            .is_none()
    );
    assert_eq!(
        database
            .list_secret_references(workspace_id())
            .await
            .expect("reference list"),
        vec![reference.clone()]
    );
    assert!(
        database
            .delete_secret_reference(workspace_id(), reference.id())
            .await
            .expect("reference deleted")
    );
    assert!(
        database
            .list_secret_references(workspace_id())
            .await
            .expect("empty reference list")
            .is_empty()
    );
}

#[tokio::test]
async fn foreign_keys_are_enforced() {
    let database = Database::connect_in_memory().await.expect("database opens");

    let error = sqlx::query(
        "INSERT INTO actions (
            id, run_id, workspace_id, actor_provider, actor_subject,
            requesting_component, kind, arguments_json, capabilities_json,
            fingerprint, state, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'normalized', ?)",
    )
    .bind(action_id().to_string())
    .bind("missing-run")
    .bind(workspace_id().to_string())
    .bind("local")
    .bind("riley")
    .bind("builtin.filesystem")
    .bind("filesystem.write")
    .bind("{}")
    .bind("[]")
    .bind("0".repeat(64))
    .bind(1_000_i64)
    .execute(database.pool())
    .await
    .expect_err("unknown workspace and run must violate foreign keys");

    assert!(error.as_database_error().is_some());
}

#[tokio::test]
async fn action_attribution_must_match_its_run() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    for subject in ["alice", "bob"] {
        sqlx::query(
            "INSERT INTO identities (provider, subject, created_at) VALUES ('local', ?, 1000)",
        )
        .bind(subject)
        .execute(database.pool())
        .await
        .expect("identity stored");
    }
    sqlx::query(
        "INSERT INTO agent_runs (
            id, workspace_id, actor_provider, actor_subject, state, created_at
         ) VALUES ('run-1', ?, 'local', 'alice', 'running', 1000)",
    )
    .bind(workspace_id().to_string())
    .execute(database.pool())
    .await
    .expect("run stored");

    let error = sqlx::query(
        "INSERT INTO actions (
            id, run_id, workspace_id, actor_provider, actor_subject,
            requesting_component, kind, arguments_json, capabilities_json,
            fingerprint, state, created_at
         ) VALUES (
            'action-1', 'run-1', ?, 'local', 'bob', 'builtin.filesystem',
            'filesystem.read', '{}', '[]', ?, 'normalized', 1000
         )",
    )
    .bind(workspace_id().to_string())
    .bind("1".repeat(64))
    .execute(database.pool())
    .await
    .expect_err("action actor must match the run actor");

    assert!(error.as_database_error().is_some());
}

#[tokio::test]
async fn approval_fingerprint_must_match_its_action() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .insert_action(&action, TimestampMillis::new(1_100))
        .await
        .expect("action stored");

    let error = sqlx::query(
        "INSERT INTO approval_requests (
            id, action_id, action_fingerprint, policy_version, state, created_at, expires_at
         ) VALUES ('approval-1', ?, ?, 'policy-v1', 'pending', 1100, 2000)",
    )
    .bind(action.id().to_string())
    .bind("2".repeat(64))
    .execute(database.pool())
    .await
    .expect_err("approval fingerprint must match the action");

    assert!(error.as_database_error().is_some());
}

#[tokio::test]
async fn audit_events_are_ordered_and_hash_chained() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");

    let first = database
        .append_audit_event(AuditEvent::new(
            AuditEventId::new(),
            TimestampMillis::new(1_100),
            AuditEventKind::RunCreated,
            AuditOutcome::Success,
            Some(workspace_id()),
            CanonicalValue::object([("request", CanonicalValue::from("local"))]),
        ))
        .await
        .expect("first event appended");
    let second = database
        .append_audit_event(AuditEvent::new(
            AuditEventId::new(),
            TimestampMillis::new(1_200),
            AuditEventKind::ActionNormalized,
            AuditOutcome::Success,
            Some(workspace_id()),
            CanonicalValue::object([("action", CanonicalValue::from("filesystem.write"))]),
        ))
        .await
        .expect("second event appended");

    assert_eq!(first.sequence(), 1);
    assert_eq!(second.sequence(), 2);
    assert_eq!(second.previous_hash(), first.hash());
    database
        .verify_audit_chain()
        .await
        .expect("untampered chain verifies");
}

#[tokio::test]
async fn audit_verification_detects_payload_tampering() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let event = database
        .append_audit_event(AuditEvent::new(
            AuditEventId::new(),
            TimestampMillis::new(1_100),
            AuditEventKind::AuthenticationAccepted,
            AuditOutcome::Success,
            None,
            CanonicalValue::object([("provider", CanonicalValue::from("local"))]),
        ))
        .await
        .expect("event appended");

    sqlx::query("UPDATE audit_events SET payload_json = ? WHERE sequence = ?")
        .bind("{\"provider\":\"forged\"}")
        .bind(event.sequence())
        .execute(database.pool())
        .await
        .expect("test tampers with event");

    assert_eq!(
        database.verify_audit_chain().await,
        Err(AuditIntegrityError::HashMismatch { sequence: 1 })
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_audit_appends_form_one_contiguous_chain() {
    let directory = tempdir().expect("temporary directory created");
    let database = Database::connect(directory.path().join("audit-race.sqlite3"))
        .await
        .expect("database opens");
    let mut appends = Vec::new();

    for index in 0_u64..8 {
        let database = database.clone();
        appends.push(tokio::spawn(async move {
            database
                .append_audit_event(AuditEvent::new(
                    AuditEventId::new(),
                    TimestampMillis::new(1_000 + index),
                    AuditEventKind::ActionNormalized,
                    AuditOutcome::Success,
                    None,
                    CanonicalValue::object([(
                        "index",
                        CanonicalValue::from(i64::try_from(index).expect("small index")),
                    )]),
                ))
                .await
        }));
    }

    for append in appends {
        append
            .await
            .expect("append task completes")
            .expect("append succeeds");
    }

    database
        .verify_audit_chain()
        .await
        .expect("concurrent chain verifies");
    let sequences: Vec<i64> =
        sqlx::query_scalar("SELECT sequence FROM audit_events ORDER BY sequence")
            .fetch_all(database.pool())
            .await
            .expect("sequences load");
    assert_eq!(sequences, (1_i64..=8).collect::<Vec<_>>());
}

#[tokio::test]
async fn crash_recovery_marks_reserved_execution_unknown_without_retrying() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    let action = action();
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");
    let approval = granted_approval(&action);
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");
    let incomplete_attempt = ExecutionAttemptId::new();
    database
        .reserve_execution(DispatchReservation::new(
            incomplete_attempt,
            action.id(),
            approval.id(),
            action.fingerprint(),
            policy_version(),
            TimestampMillis::new(1_300),
        ))
        .await
        .expect("execution reserved");
    let terminal_attempt = ExecutionAttemptId::new();
    sqlx::query(
        "INSERT INTO execution_attempts (
            id, action_id, approval_id, state, reserved_at, completed_at
         ) VALUES (?, ?, NULL, 'succeeded', 1200, 1250)",
    )
    .bind(terminal_attempt.to_string())
    .bind(action.id().to_string())
    .execute(database.pool())
    .await
    .expect("terminal attempt stored");

    let recovered = database
        .recover_incomplete_executions(TimestampMillis::new(1_500))
        .await
        .expect("recovery succeeds");

    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].action_id(), action.id());
    let attempt_state: String =
        sqlx::query_scalar("SELECT state FROM execution_attempts WHERE id = ?")
            .bind(incomplete_attempt.to_string())
            .fetch_one(database.pool())
            .await
            .expect("attempt state");
    let action_state: String = sqlx::query_scalar("SELECT state FROM actions WHERE id = ?")
        .bind(action.id().to_string())
        .fetch_one(database.pool())
        .await
        .expect("action state");
    let run_state: String = sqlx::query_scalar("SELECT state FROM agent_runs WHERE id = ?")
        .bind(action.run_id().to_string())
        .fetch_one(database.pool())
        .await
        .expect("run state");
    assert_eq!(attempt_state, "unknown");
    assert_eq!(action_state, "unknown");
    assert_eq!(run_state, "failed");
    let terminal_state: String =
        sqlx::query_scalar("SELECT state FROM execution_attempts WHERE id = ?")
            .bind(terminal_attempt.to_string())
            .fetch_one(database.pool())
            .await
            .expect("terminal attempt state");
    assert_eq!(terminal_state, "succeeded");

    let second_recovery = database
        .recover_incomplete_executions(TimestampMillis::new(1_600))
        .await
        .expect("second recovery succeeds");
    assert!(second_recovery.is_empty());
}

#[tokio::test]
async fn policy_denied_actions_transition_out_of_normalized_state() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    let action = action();
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");

    database
        .mark_action_denied(action.id(), TimestampMillis::new(1_100))
        .await
        .expect("action marked denied");
    let action_state: String = sqlx::query_scalar("SELECT state FROM actions WHERE id = ?")
        .bind(action.id().to_string())
        .fetch_one(database.pool())
        .await
        .expect("action state");
    assert_eq!(action_state, "denied");
    assert!(matches!(
        database
            .mark_action_denied(action.id(), TimestampMillis::new(1_200))
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
}

#[tokio::test]
async fn stale_run_start_cannot_resurrect_a_terminal_row() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let actor = PrincipalId::new("local", "operator").expect("valid principal");
    let run_id = action().run_id();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .create_run(run_id, workspace_id(), &actor, TimestampMillis::new(1_000))
        .await
        .expect("run stored");

    database
        .terminalize_run(run_id, "cancelled", None, TimestampMillis::new(1_100))
        .await
        .expect("terminal transition succeeds");

    assert!(matches!(
        database
            .transition_run_state(run_id, &["created"], "running", None)
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));

    let row: (String, Option<i64>) =
        sqlx::query_as("SELECT state, completed_at FROM agent_runs WHERE id = ?")
            .bind(run_id.to_string())
            .fetch_one(database.pool())
            .await
            .expect("run row loads");
    assert_eq!(row.0, "cancelled");
    assert_eq!(row.1, Some(1_100));
}

#[tokio::test]
async fn owned_run_acceptance_and_lifecycle_marker_commit_together() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let run_id = RunId::new();
    let owner = Uuid::new_v4();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            &actor,
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("owned run accepted");
    let row: (String, String, String) = sqlx::query_as(
        "SELECT run.state, lifecycle.phase, lifecycle.owner_instance_id
         FROM agent_runs run JOIN run_lifecycle lifecycle ON lifecycle.run_id = run.id
         WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("paired rows");
    assert_eq!(
        row,
        ("created".into(), "admitted".into(), owner.to_string())
    );

    sqlx::query(
        "CREATE TRIGGER reject_lifecycle_insert BEFORE INSERT ON run_lifecycle
                 BEGIN SELECT RAISE(ABORT, 'injected lifecycle failure'); END",
    )
    .execute(database.pool())
    .await
    .expect("fault installed");
    let rejected_run = RunId::new();
    assert!(
        database
            .create_owned_run(
                rejected_run,
                workspace_id(),
                &actor,
                owner,
                TimestampMillis::new(1_200)
            )
            .await
            .is_err()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runs WHERE id = ?")
        .bind(rejected_run.to_string())
        .fetch_one(database.pool())
        .await
        .expect("run count");
    assert_eq!(count, 0);
}

#[tokio::test]
async fn owned_unknown_terminal_is_durable_scoped_and_idempotent() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let run_id = RunId::new();
    let owner = Uuid::new_v4();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            &actor,
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    let terminal = TerminalSpec::new(
        TerminalState::Failed,
        EffectCertainty::Unknown,
        "execution_unknown",
        Some("executor result lost".into()),
    )
    .expect("terminal");
    let audit_id = AuditEventId::new();
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            audit_id,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("terminalized");
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            audit_id,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("identical replay");
    let record = database
        .get_run_lifecycle(workspace_id(), run_id)
        .await
        .expect("lookup")
        .expect("lifecycle");
    assert_eq!(record.phase(), "reconciliation_required");
    assert_eq!(record.effect_certainty(), EffectCertainty::Unknown);
    assert_eq!(record.primary_diagnostic(), Some("executor result lost"));
    assert!(record.terminal_audit_pending());
    let foreign = WorkspaceId::new();
    assert!(
        database
            .get_run_lifecycle(foreign, run_id)
            .await
            .expect("scoped lookup")
            .is_none()
    );
    let changed = TerminalSpec::new(
        TerminalState::Completed,
        EffectCertainty::Known,
        "completed",
        None,
    )
    .expect("different terminal");
    assert!(matches!(
        database
            .terminalize_owned_run(
                run_id,
                workspace_id(),
                owner,
                &changed,
                AuditEventId::new(),
                TimestampMillis::new(1_300)
            )
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
}

#[tokio::test]
async fn terminal_audit_repair_uses_frozen_id_and_payload_exactly_once() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let run_id = RunId::new();
    let owner = Uuid::new_v4();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            &actor,
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    let terminal = TerminalSpec::new(
        TerminalState::Failed,
        EffectCertainty::Unknown,
        "execution_unknown",
        Some("redacted diagnostic".into()),
    )
    .expect("terminal");
    let audit_id = AuditEventId::new();
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            audit_id,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("terminalized");
    sqlx::query(
        "CREATE TRIGGER fail_terminal_audit BEFORE INSERT ON audit_events
                 BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",
    )
    .execute(database.pool())
    .await
    .expect("fault installed");
    assert!(
        database
            .flush_terminal_audit(workspace_id(), run_id)
            .await
            .is_err()
    );
    assert!(
        database
            .get_run_lifecycle(workspace_id(), run_id)
            .await
            .expect("lookup")
            .expect("lifecycle")
            .terminal_audit_pending()
    );
    sqlx::query("DROP TRIGGER fail_terminal_audit")
        .execute(database.pool())
        .await
        .expect("fault removed");
    database
        .flush_terminal_audit(workspace_id(), run_id)
        .await
        .expect("repaired");
    database
        .flush_terminal_audit(workspace_id(), run_id)
        .await
        .expect("idempotent replay");
    let records = database
        .list_audit_records_for_run(workspace_id(), run_id)
        .await
        .expect("audit records");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].event().id(), audit_id);
    assert_eq!(records[0].event().timestamp(), TimestampMillis::new(1_200));
    assert_eq!(
        records[0].event().kind(),
        AuditEventKind::RunReconciliationRequired
    );
    assert!(
        !database
            .get_run_lifecycle(workspace_id(), run_id)
            .await
            .expect("lookup")
            .expect("lifecycle")
            .terminal_audit_pending()
    );
    database
        .verify_audit_chain()
        .await
        .expect("chain remains valid");
}

#[tokio::test]
async fn owned_start_and_approval_pause_change_run_and_phase_atomically() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let run_id = RunId::new();
    let owner = Uuid::new_v4();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            &actor,
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    database
        .start_owned_run(
            run_id,
            workspace_id(),
            owner,
            false,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("start");
    database
        .pause_owned_run_for_approval(run_id, workspace_id(), owner, TimestampMillis::new(1_300))
        .await
        .expect("pause");
    sqlx::query(
        "CREATE TRIGGER fail_resume_phase BEFORE UPDATE ON run_lifecycle
                 WHEN NEW.phase = 'running' BEGIN SELECT RAISE(ABORT, 'phase failure'); END",
    )
    .execute(database.pool())
    .await
    .expect("fault installed");
    assert!(
        database
            .start_owned_run(
                run_id,
                workspace_id(),
                owner,
                true,
                TimestampMillis::new(1_400)
            )
            .await
            .is_err()
    );
    let states: (String, String) = sqlx::query_as(
        "SELECT run.state, lifecycle.phase FROM agent_runs run
         JOIN run_lifecycle lifecycle ON lifecycle.run_id = run.id WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("states");
    assert_eq!(
        states,
        ("awaiting_approval".into(), "awaiting_approval".into())
    );
    sqlx::query("DROP TRIGGER fail_resume_phase")
        .execute(database.pool())
        .await
        .expect("fault removed");
    database
        .start_owned_run(
            run_id,
            workspace_id(),
            owner,
            true,
            TimestampMillis::new(1_400),
        )
        .await
        .expect("resume");
    let states: (String, String) = sqlx::query_as(
        "SELECT run.state, lifecycle.phase FROM agent_runs run
         JOIN run_lifecycle lifecycle ON lifecycle.run_id = run.id WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("states");
    assert_eq!(states, ("running".into(), "running".into()));
}

#[tokio::test]
async fn owned_terminal_quarantines_an_in_flight_attempt_without_retry() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    let run_id = action.run_id();
    let owner = Uuid::new_v4();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            action.actor(),
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    database
        .start_owned_run(
            run_id,
            workspace_id(),
            owner,
            false,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("start");
    database
        .insert_action(&action, TimestampMillis::new(1_300))
        .await
        .expect("action");
    let approval = granted_approval(&action);
    database.insert_approval(&approval).await.expect("approval");
    let reservation = DispatchReservation::new(
        ExecutionAttemptId::new(),
        action.id(),
        approval.id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_400),
    );
    database
        .reserve_execution_with_clock(reservation, || TimestampMillis::new(1_400))
        .await
        .expect("reserved");
    assert_eq!(
        database
            .get_run_lifecycle(workspace_id(), run_id)
            .await
            .expect("lifecycle lookup")
            .expect("lifecycle")
            .phase(),
        "reserving_effect"
    );
    let terminal = TerminalSpec::new(
        TerminalState::Failed,
        EffectCertainty::NoEffect,
        "shutdown_forced",
        None,
    )
    .expect("terminal");
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            AuditEventId::new(),
            TimestampMillis::new(1_500),
        )
        .await
        .expect("terminalized");
    let row: (String, String) = sqlx::query_as(
        "SELECT action.state, attempt.state FROM actions action
         JOIN execution_attempts attempt ON attempt.action_id = action.id
         WHERE action.id = ?",
    )
    .bind(action.id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("states");
    assert_eq!(row, ("unknown".into(), "unknown".into()));
    let lifecycle = database
        .get_run_lifecycle(workspace_id(), run_id)
        .await
        .expect("lookup")
        .expect("lifecycle");
    assert_eq!(lifecycle.phase(), "reconciliation_required");
    assert_eq!(lifecycle.effect_certainty(), EffectCertainty::Unknown);
}

#[tokio::test]
async fn pending_terminal_audit_is_discoverable_after_reopen() {
    let directory = tempdir().expect("directory");
    let path = directory.path().join("pending-audit.sqlite3");
    let database = Database::connect(&path).await.expect("database opens");
    let run_id = RunId::new();
    let owner = Uuid::new_v4();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            &actor,
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    let terminal = TerminalSpec::new(
        TerminalState::Failed,
        EffectCertainty::NoEffect,
        "model_unavailable",
        None,
    )
    .expect("terminal");
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            AuditEventId::new(),
            TimestampMillis::new(1_200),
        )
        .await
        .expect("terminalized");
    database.close().await;

    let reopened = Database::connect(&path).await.expect("reopened");
    assert_eq!(
        reopened
            .list_pending_terminal_audits()
            .await
            .expect("pending"),
        vec![(workspace_id(), run_id)]
    );
    reopened
        .flush_terminal_audit(workspace_id(), run_id)
        .await
        .expect("repaired");
    assert!(
        reopened
            .list_pending_terminal_audits()
            .await
            .expect("pending")
            .is_empty()
    );
    reopened.verify_audit_chain().await.expect("chain valid");
}

#[tokio::test]
async fn crash_recovery_freezes_unknown_owned_lifecycle_and_audit_intent() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    let run_id = action.run_id();
    let owner = Uuid::new_v4();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            action.actor(),
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    database
        .start_owned_run(
            run_id,
            workspace_id(),
            owner,
            false,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("start");
    database
        .insert_action(&action, TimestampMillis::new(1_300))
        .await
        .expect("action");
    let approval = granted_approval(&action);
    database.insert_approval(&approval).await.expect("approval");
    database
        .reserve_execution_with_clock(
            DispatchReservation::new(
                ExecutionAttemptId::new(),
                action.id(),
                approval.id(),
                action.fingerprint(),
                policy_version(),
                TimestampMillis::new(1_400),
            ),
            || TimestampMillis::new(1_400),
        )
        .await
        .expect("reserved");
    assert_eq!(
        database
            .recover_incomplete_executions(TimestampMillis::new(1_500))
            .await
            .expect("recovered")
            .len(),
        1
    );
    let lifecycle = database
        .get_run_lifecycle(workspace_id(), run_id)
        .await
        .expect("lookup")
        .expect("lifecycle");
    assert_eq!(lifecycle.phase(), "reconciliation_required");
    assert_eq!(lifecycle.effect_certainty(), EffectCertainty::Unknown);
    assert!(lifecycle.terminal_audit_pending());
    database
        .flush_terminal_audit(workspace_id(), run_id)
        .await
        .expect("audited");
    let records = database
        .list_audit_records_for_run(workspace_id(), run_id)
        .await
        .expect("records");
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].event().kind(),
        AuditEventKind::RunReconciliationRequired
    );
    assert!(
        database
            .recover_incomplete_executions(TimestampMillis::new(1_600))
            .await
            .expect("replay")
            .is_empty()
    );
}

#[tokio::test]
async fn new_owner_reconciles_abandoned_active_run_without_touching_current_run() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let old_owner = Uuid::new_v4();
    let current_owner = Uuid::new_v4();
    let abandoned = RunId::new();
    let current = RunId::new();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            abandoned,
            workspace_id(),
            &actor,
            old_owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("old run");
    database
        .start_owned_run(
            abandoned,
            workspace_id(),
            old_owner,
            false,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("old start");
    database
        .create_owned_run(
            current,
            workspace_id(),
            &actor,
            current_owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("current run");
    assert_eq!(
        database
            .reconcile_abandoned_owned_runs(current_owner, TimestampMillis::new(1_300))
            .await
            .expect("reconciled"),
        vec![abandoned]
    );
    let lifecycle = database
        .get_run_lifecycle(workspace_id(), abandoned)
        .await
        .expect("lookup")
        .expect("lifecycle");
    assert_eq!(lifecycle.phase(), "reconciliation_required");
    assert!(lifecycle.terminal_audit_pending());
    assert_eq!(
        database
            .get_run_lifecycle(workspace_id(), current)
            .await
            .expect("lookup")
            .expect("lifecycle")
            .phase(),
        "admitted"
    );
    assert!(
        database
            .reconcile_abandoned_owned_runs(current_owner, TimestampMillis::new(1_400))
            .await
            .expect("replay")
            .is_empty()
    );
}

#[tokio::test]
async fn terminal_replay_accepts_derived_known_effect_certainty() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    let run_id = action.run_id();
    let owner = Uuid::new_v4();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            action.actor(),
            owner,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("run");
    database
        .start_owned_run(
            run_id,
            workspace_id(),
            owner,
            false,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("start");
    database
        .insert_action(&action, TimestampMillis::new(1_300))
        .await
        .expect("action");
    let approval = granted_approval(&action);
    database.insert_approval(&approval).await.expect("approval");
    database
        .reserve_execution_with_clock(
            DispatchReservation::new(
                ExecutionAttemptId::new(),
                action.id(),
                approval.id(),
                action.fingerprint(),
                policy_version(),
                TimestampMillis::new(1_400),
            ),
            || TimestampMillis::new(1_400),
        )
        .await
        .expect("reserved");
    sqlx::query(
        "UPDATE execution_attempts SET state = 'succeeded', completed_at = 1450
                 WHERE action_id = ?",
    )
    .bind(action.id().to_string())
    .execute(database.pool())
    .await
    .expect("effect known");
    sqlx::query("UPDATE actions SET state = 'succeeded' WHERE id = ?")
        .bind(action.id().to_string())
        .execute(database.pool())
        .await
        .expect("action complete");
    let terminal = TerminalSpec::new(
        TerminalState::Completed,
        EffectCertainty::NoEffect,
        "run_completed",
        None,
    )
    .expect("terminal");
    let audit_id = AuditEventId::new();
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            audit_id,
            TimestampMillis::new(1_500),
        )
        .await
        .expect("terminalized");
    database
        .terminalize_owned_run(
            run_id,
            workspace_id(),
            owner,
            &terminal,
            audit_id,
            TimestampMillis::new(1_500),
        )
        .await
        .expect("same request replay");
    assert_eq!(
        database
            .get_run_lifecycle(workspace_id(), run_id)
            .await
            .expect("lookup")
            .expect("lifecycle")
            .effect_certainty(),
        EffectCertainty::Known
    );
}

#[tokio::test]
async fn reconciliation_listing_is_workspace_scoped_and_excludes_ordinary_terminals() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let foreign = WorkspaceId::new();
    let actor = PrincipalId::new("local", "operator").expect("principal");
    let owner = Uuid::new_v4();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .insert_workspace(foreign, "Foreign", TimestampMillis::new(1_000))
        .await
        .expect("foreign workspace");
    let unknown = RunId::new();
    let completed = RunId::new();
    let foreign_unknown = RunId::new();
    for (run_id, scope) in [
        (unknown, workspace_id()),
        (completed, workspace_id()),
        (foreign_unknown, foreign),
    ] {
        database
            .create_owned_run(run_id, scope, &actor, owner, TimestampMillis::new(1_100))
            .await
            .expect("run");
    }
    let uncertain = TerminalSpec::new(
        TerminalState::Failed,
        EffectCertainty::Unknown,
        "owner_lost",
        Some("redacted".into()),
    )
    .expect("terminal");
    let finished = TerminalSpec::new(
        TerminalState::Completed,
        EffectCertainty::NoEffect,
        "run_completed",
        None,
    )
    .expect("terminal");
    for (run_id, scope, spec) in [
        (unknown, workspace_id(), &uncertain),
        (completed, workspace_id(), &finished),
        (foreign_unknown, foreign, &uncertain),
    ] {
        database
            .terminalize_owned_run(
                run_id,
                scope,
                owner,
                spec,
                AuditEventId::new(),
                TimestampMillis::new(1_200),
            )
            .await
            .expect("terminalized");
    }
    let listed = database
        .list_reconciliation_required_runs(workspace_id())
        .await
        .expect("listing");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, unknown);
    assert_eq!(listed[0].1.effect_certainty(), EffectCertainty::Unknown);
    assert_eq!(listed[0].1.primary_diagnostic(), Some("redacted"));
}

#[tokio::test]
async fn rejected_approval_terminalizes_its_normalized_action_before_run_completion() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");
    let mut approval = ApprovalRequest::new(
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("approval request");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");
    approval
        .reject(
            PrincipalId::new("local", "admin").expect("valid principal"),
            TimestampMillis::new(1_100),
        )
        .expect("approval can be rejected");

    let rejected_run = database
        .reject_approval_and_action(workspace_id(), &approval)
        .await
        .expect("rejection/action transition succeeds");
    assert_eq!(rejected_run, action.run_id());

    let approval_state: String =
        sqlx::query_scalar("SELECT state FROM approval_requests WHERE id = ?")
            .bind(approval.id().to_string())
            .fetch_one(database.pool())
            .await
            .expect("approval state");
    let action_row: (String, Option<String>) =
        sqlx::query_as("SELECT state, terminal_reason FROM actions WHERE id = ?")
            .bind(action.id().to_string())
            .fetch_one(database.pool())
            .await
            .expect("action state");
    let attempts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts WHERE action_id = ?")
            .bind(action.id().to_string())
            .fetch_one(database.pool())
            .await
            .expect("attempt count");
    assert_eq!(approval_state, "rejected");
    assert_eq!(action_row.0, "denied");
    assert_eq!(action_row.1.as_deref(), Some("approval_rejected"));
    assert_eq!(attempts, 0);
    assert!(
        sqlx::query("UPDATE actions SET state = 'normalized' WHERE id = ?")
            .bind(action.id().to_string())
            .execute(database.pool())
            .await
            .is_err()
    );
    assert!(matches!(
        database
            .reject_approval_and_action(workspace_id(), &approval)
            .await,
        Err(RepositoryError::ApprovalDecisionConflict)
    ));
}

#[tokio::test]
async fn rejected_action_update_failure_rolls_back_the_approval_decision() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action");
    let mut approval = ApprovalRequest::new(
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("approval");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");
    approval
        .reject(
            PrincipalId::new("local", "admin").expect("principal"),
            TimestampMillis::new(1_100),
        )
        .expect("rejected request");
    sqlx::query(
        "CREATE TRIGGER reject_action_update_fault BEFORE UPDATE OF state ON actions
         WHEN NEW.terminal_reason = 'approval_rejected'
         BEGIN SELECT RAISE(ABORT, 'injected action failure'); END",
    )
    .execute(database.pool())
    .await
    .expect("fault installed");

    assert!(
        database
            .reject_approval_and_action(workspace_id(), &approval)
            .await
            .is_err()
    );
    let row: (String, String, i64) = sqlx::query_as(
        "SELECT approval.state, action.state,
                (SELECT COUNT(*) FROM execution_attempts WHERE action_id = action.id)
         FROM approval_requests approval JOIN actions action ON action.id = approval.action_id
         WHERE approval.id = ?",
    )
    .bind(approval.id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("state after rollback");
    assert_eq!(row, ("pending".into(), "normalized".into(), 0));
}

#[tokio::test]
async fn foreign_workspace_cannot_reject_approval_or_change_action() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    let foreign = WorkspaceId::new();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .insert_workspace(foreign, "Foreign", TimestampMillis::new(1_000))
        .await
        .expect("foreign workspace");
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action");
    let mut approval = ApprovalRequest::new(
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("approval");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");
    approval
        .reject(
            PrincipalId::new("local", "admin").expect("principal"),
            TimestampMillis::new(1_100),
        )
        .expect("rejected request");

    assert!(matches!(
        database
            .reject_approval_and_action(foreign, &approval)
            .await,
        Err(RepositoryError::ApprovalDecisionConflict)
    ));
    let row: (String, String) = sqlx::query_as(
        "SELECT approval.state, action.state FROM approval_requests approval
         JOIN actions action ON action.id = approval.action_id WHERE approval.id = ?",
    )
    .bind(approval.id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("unchanged state");
    assert_eq!(row, ("pending".into(), "normalized".into()));
}

#[tokio::test]
async fn pending_approval_listing_expires_due_rows_without_deleting_history() {
    let database = Database::connect_in_memory().await.expect("database opens");
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    let action = action();
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");
    let approval = ApprovalRequest::new(
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("approval");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");

    assert_eq!(
        database
            .list_pending_approvals(workspace_id(), TimestampMillis::new(1_999))
            .await
            .expect("pending before expiry")
            .len(),
        1
    );
    assert!(
        database
            .list_pending_approvals(workspace_id(), TimestampMillis::new(2_000))
            .await
            .expect("pending after expiry")
            .is_empty()
    );
    let state: String = sqlx::query_scalar("SELECT state FROM approval_requests WHERE id = ?")
        .bind(approval_id().to_string())
        .fetch_one(database.pool())
        .await
        .expect("approval history");
    assert_eq!(state, "expired");
    let mut crossed_expiry = approval;
    crossed_expiry
        .grant(
            PrincipalId::new("local", "admin").expect("valid principal"),
            TimestampMillis::new(1_999),
        )
        .expect("decision began before expiry");
    assert!(matches!(
        database
            .update_approval_decision(workspace_id(), &crossed_expiry)
            .await,
        Err(RepositoryError::ApprovalExpired)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approval_consumption_and_execution_reservation_are_atomic() {
    let directory = tempdir().expect("temporary directory created");
    let database = Database::connect(directory.path().join("race.sqlite3"))
        .await
        .expect("database opens");
    let action = action();
    let approval = granted_approval(&action);
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .insert_action(&action, TimestampMillis::new(1_100))
        .await
        .expect("action stored");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");

    let first = database.clone();
    let second = database.clone();
    let first_reservation = DispatchReservation::new(
        ExecutionAttemptId::new(),
        action_id(),
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_500),
    );
    let second_reservation = DispatchReservation::new(
        ExecutionAttemptId::new(),
        action_id(),
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_500),
    );

    let (first_result, second_result) = tokio::join!(
        first.reserve_execution(first_reservation),
        second.reserve_execution(second_reservation),
    );
    let results = [first_result, second_result];

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(RepositoryError::ApprovalNotAvailable)))
            .count(),
        1
    );

    let row = sqlx::query(
        "SELECT
            (SELECT state FROM approval_requests WHERE id = ?) AS approval_state,
            (SELECT COUNT(*) FROM execution_attempts WHERE approval_id = ?) AS attempt_count",
    )
    .bind(approval_id().to_string())
    .bind(approval_id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("reservation state loads");
    assert_eq!(row.get::<String, _>("approval_state"), "consumed");
    assert_eq!(row.get::<i64, _>("attempt_count"), 1);
}

#[tokio::test]
async fn reservation_uses_the_clock_sampled_inside_its_transaction() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");
    let approval = granted_approval(&action);
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");

    let reservation = DispatchReservation::new(
        ExecutionAttemptId::new(),
        action.id(),
        approval.id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_500),
    );
    assert!(matches!(
        database
            .reserve_execution_with_clock(reservation, || TimestampMillis::new(2_000))
            .await,
        Err(RepositoryError::ApprovalNotAvailable)
    ));

    let approval_state: String =
        sqlx::query_scalar("SELECT state FROM approval_requests WHERE id = ?")
            .bind(approval.id().to_string())
            .fetch_one(database.pool())
            .await
            .expect("approval state");
    let attempts: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts WHERE action_id = ?")
            .bind(action.id().to_string())
            .fetch_one(database.pool())
            .await
            .expect("attempt count");
    assert_eq!(approval_state, "granted");
    assert_eq!(attempts, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reservation_samples_expiry_clock_after_waiting_for_a_sqlite_writer() {
    let directory = tempdir().expect("temporary directory created");
    let path = directory.path().join("reservation-clock-race.sqlite3");
    let database = Database::connect(&path).await.expect("database opens");
    let writer_database = Database::connect(&path)
        .await
        .expect("second database connection opens");
    let action = action();
    let approval = granted_approval(&action);
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");

    let mut writer = writer_database
        .pool()
        .acquire()
        .await
        .expect("writer connection acquired");
    sqlx::query("BEGIN IMMEDIATE")
        .execute(&mut *writer)
        .await
        .expect("writer lock acquired");

    let clock = Arc::new(AtomicU64::new(1_500));
    let reservation_clock = Arc::clone(&clock);
    let calls = Arc::new(AtomicUsize::new(0));
    let reservation_calls = Arc::clone(&calls);
    let reservation = DispatchReservation::new(
        ExecutionAttemptId::new(),
        action_id(),
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_500),
    );
    let pending = database.reserve_execution_with_clock(reservation, move || {
        reservation_calls.fetch_add(1, Ordering::SeqCst);
        TimestampMillis::new(reservation_clock.load(Ordering::SeqCst))
    });
    tokio::pin!(pending);
    assert!(matches!(poll!(pending.as_mut()), Poll::Pending));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    // The reservation cannot acquire its transaction while this writer is held.
    // Advancing before release therefore distinguishes a fresh post-lock sample
    // from a timestamp captured at request arrival.
    clock.store(2_000, Ordering::SeqCst);
    sqlx::query("COMMIT")
        .execute(&mut *writer)
        .await
        .expect("writer lock released");

    let result = tokio::time::timeout(std::time::Duration::from_secs(2), pending)
        .await
        .expect("reservation completes after writer release");
    assert!(matches!(result, Err(RepositoryError::ApprovalNotAvailable)));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let row = sqlx::query(
        "SELECT
            (SELECT state FROM approval_requests WHERE id = ?) AS approval_state,
            (SELECT COUNT(*) FROM execution_attempts WHERE approval_id = ?) AS attempt_count",
    )
    .bind(approval_id().to_string())
    .bind(approval_id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("reservation state loads");
    assert_eq!(row.get::<String, _>("approval_state"), "granted");
    assert_eq!(row.get::<i64, _>("attempt_count"), 0);
}

#[tokio::test]
async fn reservation_one_millisecond_before_expiry_records_the_protected_sample() {
    let database = Database::connect_in_memory().await.expect("database opens");
    let action = action();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace stored");
    database
        .insert_action(&action, TimestampMillis::new(1_000))
        .await
        .expect("action stored");
    let approval = granted_approval(&action);
    database
        .insert_approval(&approval)
        .await
        .expect("approval stored");

    let clock = AtomicU64::new(1_999);
    let reservation = DispatchReservation::new(
        ExecutionAttemptId::new(),
        action.id(),
        approval.id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_500),
    );
    let reserved_at = database
        .reserve_execution_with_clock(reservation, || {
            TimestampMillis::new(clock.load(Ordering::SeqCst))
        })
        .await
        .expect("approval is valid just before expiry");
    assert_eq!(reserved_at, TimestampMillis::new(1_999));
    let row: (String, String, i64, i64) = sqlx::query_as(
        "SELECT approval.state, action.state, attempt.reserved_at,
                (SELECT COUNT(*) FROM execution_attempts WHERE action_id = action.id)
         FROM approval_requests approval
         JOIN actions action ON action.id = approval.action_id
         JOIN execution_attempts attempt ON attempt.approval_id = approval.id
         WHERE approval.id = ?",
    )
    .bind(approval.id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("reserved state loads");
    assert_eq!(row, ("consumed".into(), "running".into(), 1_999, 1));
}

#[tokio::test]
async fn approval_renewal_is_one_durable_replacement_for_an_awaiting_run() {
    let directory = tempdir().expect("temporary database directory");
    let path = directory.path().join("renewal.db");
    let database = Database::connect(&path).await.expect("database");
    let action = action();
    let run_id = action.run_id();
    let owner = Uuid::new_v4();
    database
        .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
        .await
        .expect("workspace");
    database
        .create_owned_run(
            run_id,
            workspace_id(),
            action.actor(),
            owner,
            TimestampMillis::new(1_000),
        )
        .await
        .expect("run");
    database
        .start_owned_run(
            run_id,
            workspace_id(),
            owner,
            false,
            TimestampMillis::new(1_100),
        )
        .await
        .expect("start");
    database
        .pause_owned_run_for_approval(run_id, workspace_id(), owner, TimestampMillis::new(1_200))
        .await
        .expect("pause");
    database
        .insert_action(&action, TimestampMillis::new(1_100))
        .await
        .expect("action");
    let mut old = ApprovalRequest::new(
        approval_id(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(1_000),
        TimestampMillis::new(2_000),
    )
    .expect("old request");
    assert!(old.expire(TimestampMillis::new(2_001)));
    database.insert_approval(&old).await.expect("old approval");
    let replacement = ApprovalRequest::new(
        ApprovalId::new(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(2_001),
        TimestampMillis::new(3_001),
    )
    .expect("replacement");
    let replacement2 = ApprovalRequest::new(
        ApprovalId::new(),
        action.fingerprint(),
        policy_version(),
        TimestampMillis::new(2_001),
        TimestampMillis::new(3_001),
    )
    .expect("second replacement");
    let (first, second) = tokio::join!(
        database.renew_expired_approval(
            workspace_id(),
            run_id,
            old.id(),
            &replacement,
            TimestampMillis::new(2_001)
        ),
        database.renew_expired_approval(
            workspace_id(),
            run_id,
            old.id(),
            &replacement2,
            TimestampMillis::new(2_001)
        ),
    );
    assert_ne!(first.is_ok(), second.is_ok(), "exactly one renewal commits");
    let winner = if first.is_ok() {
        replacement.id()
    } else {
        replacement2.id()
    };
    let relation: (Option<String>, i64) = sqlx::query_as(
        "SELECT replacement_approval_id,
                (SELECT COUNT(*) FROM approval_requests other WHERE other.action_id = old.action_id AND other.state = 'pending')
         FROM approval_requests old WHERE old.id = ?",
    )
    .bind(old.id().to_string())
    .fetch_one(database.pool())
    .await
    .expect("durable relation");
    assert_eq!(relation, (Some(winner.to_string()), 1));
    drop(database);
    let restarted = Database::connect(&path).await.expect("restarted database");
    let restarted_relation: (Option<String>, i64) = sqlx::query_as(
        "SELECT replacement_approval_id,
                (SELECT COUNT(*) FROM approval_requests other WHERE other.action_id = old.action_id AND other.state = 'pending')
         FROM approval_requests old WHERE old.id = ?",
    )
    .bind(old.id().to_string())
    .fetch_one(restarted.pool())
    .await
    .expect("restarted durable relation");
    assert_eq!(restarted_relation, (Some(winner.to_string()), 1));
}

#[tokio::test]
async fn approval_renewal_refuses_invalidated_fingerprint_or_terminal_old_decision() {
    for case in [
        "invalidated_action",
        "changed_fingerprint",
        "consumed",
        "rejected",
    ] {
        let database = Database::connect_in_memory().await.expect("database");
        let action = action();
        let run_id = action.run_id();
        let owner = Uuid::new_v4();
        database
            .insert_workspace(workspace_id(), "Default", TimestampMillis::new(1_000))
            .await
            .expect("workspace");
        database
            .create_owned_run(
                run_id,
                workspace_id(),
                action.actor(),
                owner,
                TimestampMillis::new(1_000),
            )
            .await
            .expect("run");
        database
            .start_owned_run(
                run_id,
                workspace_id(),
                owner,
                false,
                TimestampMillis::new(1_100),
            )
            .await
            .expect("start");
        database
            .pause_owned_run_for_approval(
                run_id,
                workspace_id(),
                owner,
                TimestampMillis::new(1_200),
            )
            .await
            .expect("pause");
        database
            .insert_action(&action, TimestampMillis::new(1_100))
            .await
            .expect("action");
        let mut old = ApprovalRequest::new(
            approval_id(),
            action.fingerprint(),
            policy_version(),
            TimestampMillis::new(1_000),
            TimestampMillis::new(2_000),
        )
        .expect("old approval");
        assert!(old.expire(TimestampMillis::new(2_001)));
        database
            .insert_approval(&old)
            .await
            .expect("old approval stored");
        match case {
            "invalidated_action" => {
                sqlx::query("UPDATE actions SET state = 'denied', terminal_reason = 'approval_rejected' WHERE id = ?")
                    .bind(action.id().to_string()).execute(database.pool()).await.expect("invalidate action");
            }
            "changed_fingerprint" => {
                let changed = sqlx::query("UPDATE actions SET fingerprint = ? WHERE id = ?")
                    .bind("0".repeat(64))
                    .bind(action.id().to_string())
                    .execute(database.pool())
                    .await;
                assert!(
                    changed.is_err(),
                    "approval FK must prevent fingerprint mutation"
                );
            }
            "consumed" | "rejected" => {
                sqlx::query("UPDATE approval_requests SET state = ?, consumed_at = ? WHERE id = ?")
                    .bind(case)
                    .bind((case == "consumed").then_some(2_001_i64))
                    .bind(old.id().to_string())
                    .execute(database.pool())
                    .await
                    .expect("terminal old approval");
            }
            _ => unreachable!(),
        }
        let replacement_fingerprint = if case == "changed_fingerprint" {
            ActionEnvelope::new(
                ActionId::from_uuid(Uuid::new_v4()),
                run_id,
                workspace_id(),
                action.actor().clone(),
                ComponentId::new("builtin.filesystem").expect("component"),
                ActionKind::new("filesystem.write").expect("kind"),
                CanonicalValue::object([("path", CanonicalValue::from("notes/other.md"))]),
                vec![Capability::new(
                    CapabilityName::FsWrite,
                    ResourceScope::path(
                        workspace_id(),
                        WorkspacePath::parse("notes/other.md").expect("path"),
                    ),
                )],
            )
            .fingerprint()
        } else {
            action.fingerprint()
        };
        let replacement = ApprovalRequest::new(
            ApprovalId::new(),
            replacement_fingerprint,
            policy_version(),
            TimestampMillis::new(2_001),
            TimestampMillis::new(3_001),
        )
        .expect("replacement");
        assert!(
            matches!(
                database
                    .renew_expired_approval(
                        workspace_id(),
                        run_id,
                        old.id(),
                        &replacement,
                        TimestampMillis::new(2_001)
                    )
                    .await,
                Err(RepositoryError::ApprovalStale)
            ),
            "unexpected renewal for {case}"
        );
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM approval_requests WHERE action_id = ?")
                .bind(action.id().to_string())
                .fetch_one(database.pool())
                .await
                .expect("approval count");
        assert_eq!(count, 1, "replacement inserted for {case}");
    }
}
