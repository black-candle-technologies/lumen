use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, ExecutionAttemptId, TimestampMillis},
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditIntegrityError, AuditOutcome},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    identity::{ComponentId, PrincipalId, WorkspaceId},
    policy::PolicyVersion,
};
use lumen_db::{Database, DispatchReservation, RepositoryError};
use sqlx::Row;
use tempfile::tempdir;
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(
        Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("valid UUID"),
    )
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
    assert_eq!(migration_count, 1);
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
    assert_eq!(migration_count, 1);
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
    database
        .reserve_execution(DispatchReservation::new(
            ExecutionAttemptId::new(),
            action.id(),
            approval.id(),
            action.fingerprint(),
            policy_version(),
            TimestampMillis::new(1_300),
        ))
        .await
        .expect("execution reserved");

    let recovered = database
        .recover_incomplete_executions(TimestampMillis::new(1_500))
        .await
        .expect("recovery succeeds");

    assert_eq!(recovered.len(), 1);
    assert_eq!(recovered[0].action_id(), action.id());
    let attempt_state: String = sqlx::query_scalar("SELECT state FROM execution_attempts LIMIT 1")
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
