use std::{sync::Arc, time::Duration};

use lumen_core::{
    action::RunId,
    approval::TimestampMillis,
    automation::{JobId, JobRevision, OccurrenceKey, ScheduleSpec, SkillId, SkillVersion},
    capability::{Capability, CapabilityName, ResourceScope},
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
};
use lumen_db::{
    Database, RepositoryError, ScheduledJobRevision, ServiceIdentity, SkillVersionRecord,
    WorkflowCaptureDraft,
};
use sqlx::Row;
use tempfile::{TempDir, tempdir};
use tokio::sync::Barrier;
use uuid::Uuid;

fn workspace_id() -> WorkspaceId {
    WorkspaceId::from_uuid(Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").expect("UUID"))
}

fn owner() -> PrincipalId {
    PrincipalId::new("local", "alice").expect("owner")
}

fn service() -> PrincipalId {
    lumen_core::automation::service_principal("daily-brief").expect("service")
}

fn job_id() -> JobId {
    JobId::from_uuid(Uuid::parse_str("7825c2e7-1d9c-40df-ad69-209aeb02fc8d").expect("UUID"))
}

fn skill_id() -> SkillId {
    SkillId::from_uuid(Uuid::parse_str("5ed0e220-393b-42d3-9e3b-49691cf71bcf").expect("UUID"))
}

async fn database() -> Database {
    let database = Database::connect_in_memory().await.expect("database");
    database
        .bootstrap_workspace(
            workspace_id(),
            "Default",
            &owner(),
            TimestampMillis::new(500),
        )
        .await
        .expect("workspace");
    database
}

async fn file_databases() -> (TempDir, Database, Database) {
    let directory = tempdir().expect("temporary directory");
    let path = directory.path().join("automation-race.sqlite3");
    let first = Database::connect(&path).await.expect("first database");
    first
        .bootstrap_workspace(
            workspace_id(),
            "Default",
            &owner(),
            TimestampMillis::new(500),
        )
        .await
        .expect("workspace");
    let second = Database::connect(&path).await.expect("second database");
    (directory, first, second)
}

async fn insert_service_and_job(database: &Database) {
    database
        .upsert_service_identity(
            &ServiceIdentity::new(
                service(),
                workspace_id(),
                owner(),
                "Daily brief",
                true,
                TimestampMillis::new(1_000),
                TimestampMillis::new(1_000),
            )
            .expect("service"),
            [],
        )
        .await
        .expect("service stored");
    database
        .append_scheduled_job_revision(
            &ScheduledJobRevision::new(
                job_id(),
                JobRevision::new(1).expect("revision"),
                workspace_id(),
                service(),
                owner(),
                ScheduleSpec::once(TimestampMillis::new(2_000)),
                "summarize yesterday",
                DataClass::Workspace,
                4,
                2,
                true,
                Some(TimestampMillis::new(2_000)),
                false,
                TimestampMillis::new(1_000),
            )
            .expect("job revision"),
        )
        .await
        .expect("job stored");
}

#[tokio::test]
async fn migration_adds_durable_automation_schema() {
    let database = Database::connect_in_memory().await.expect("database");
    let tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .fetch_all(database.pool())
            .await
            .expect("tables");

    for required in [
        "agent_skills",
        "scheduled_job_leases",
        "scheduled_job_revisions",
        "scheduled_job_runs",
        "scheduled_jobs",
        "service_identities",
        "service_identity_grants",
        "skill_versions",
        "skill_workspace_state",
        "workflow_capture_drafts",
        "model_provider_runtime_revisions",
        "model_profiles",
        "model_profile_revisions",
        "context_sources",
        "model_data_policy_revisions",
        "task_projections",
        "task_projection_sources",
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
    assert_eq!(migrations, 17);
}

#[tokio::test]
async fn service_identities_are_owned_enabled_and_explicitly_grant_scoped() {
    let database = database().await;
    let identity = ServiceIdentity::new(
        service(),
        workspace_id(),
        owner(),
        "Daily brief",
        true,
        TimestampMillis::new(1_000),
        TimestampMillis::new(1_000),
    )
    .expect("service identity");
    let grant = Capability::new(
        CapabilityName::FsRead,
        ResourceScope::workspace(workspace_id()),
    );

    database
        .upsert_service_identity(&identity, [grant.clone()])
        .await
        .expect("service stored");

    assert_eq!(
        database
            .get_service_identity(workspace_id(), &service())
            .await
            .expect("service loaded"),
        Some(identity)
    );
    assert_eq!(
        database
            .service_identity_grants(workspace_id(), &service())
            .await
            .expect("grants loaded"),
        vec![grant]
    );
    assert_eq!(
        database
            .service_identity_grants(workspace_id(), &owner())
            .await
            .expect("owner grants loaded"),
        Vec::<Capability>::new()
    );
}

#[tokio::test]
async fn scheduled_job_revisions_are_append_only_and_load_latest() {
    let database = database().await;
    database
        .upsert_service_identity(
            &ServiceIdentity::new(
                service(),
                workspace_id(),
                owner(),
                "Daily brief",
                true,
                TimestampMillis::new(1_000),
                TimestampMillis::new(1_000),
            )
            .expect("service"),
            [],
        )
        .await
        .expect("service stored");

    let first = ScheduledJobRevision::new(
        job_id(),
        JobRevision::new(1).expect("revision"),
        workspace_id(),
        service(),
        owner(),
        ScheduleSpec::once(TimestampMillis::new(2_000)),
        "summarize yesterday",
        DataClass::Workspace,
        4,
        2,
        true,
        Some(TimestampMillis::new(2_000)),
        false,
        TimestampMillis::new(1_000),
    )
    .expect("job revision");
    let second = ScheduledJobRevision::new(
        job_id(),
        JobRevision::new(2).expect("revision"),
        workspace_id(),
        service(),
        owner(),
        ScheduleSpec::interval(TimestampMillis::new(3_000), Duration::from_millis(60_000))
            .expect("interval"),
        "summarize every hour",
        DataClass::Public,
        3,
        1,
        false,
        None,
        true,
        TimestampMillis::new(1_500),
    )
    .expect("job revision");

    database
        .append_scheduled_job_revision(&first)
        .await
        .expect("first stored");
    database
        .append_scheduled_job_revision(&second)
        .await
        .expect("second stored");

    assert_eq!(
        database
            .latest_scheduled_job_revision(job_id())
            .await
            .expect("job loaded"),
        Some(second)
    );
    let duplicate = database.append_scheduled_job_revision(&first).await;
    assert!(matches!(
        duplicate,
        Err(RepositoryError::ExecutionStateConflict)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_revision_appends_have_one_winner() {
    let (_directory, first_database, second_database) = file_databases().await;
    insert_service_and_job(&first_database).await;
    let revision = ScheduledJobRevision::new(
        job_id(),
        JobRevision::new(2).expect("revision"),
        workspace_id(),
        service(),
        owner(),
        ScheduleSpec::once(TimestampMillis::new(3_000)),
        "second revision",
        DataClass::Workspace,
        1,
        1,
        true,
        Some(TimestampMillis::new(3_000)),
        false,
        TimestampMillis::new(2_000),
    )
    .expect("revision");
    let barrier = Arc::new(Barrier::new(3));
    let first = tokio::spawn({
        let barrier = Arc::clone(&barrier);
        let revision = revision.clone();
        async move {
            barrier.wait().await;
            first_database
                .append_scheduled_job_revision(&revision)
                .await
        }
    });
    let second = tokio::spawn({
        let barrier = Arc::clone(&barrier);
        async move {
            barrier.wait().await;
            second_database
                .append_scheduled_job_revision(&revision)
                .await
        }
    });
    barrier.wait().await;
    let results = [
        first.await.expect("first task"),
        second.await.expect("second task"),
    ];

    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(RepositoryError::ExecutionStateConflict)))
            .count(),
        1
    );
}

#[tokio::test]
async fn exhausted_revision_sequence_fails_closed() {
    let database = database().await;
    insert_service_and_job(&database).await;
    sqlx::query("UPDATE scheduled_job_revisions SET revision = ? WHERE job_id = ?")
        .bind(i64::MAX)
        .bind(job_id().to_string())
        .execute(database.pool())
        .await
        .expect("revision exhausted");
    let next = ScheduledJobRevision::new(
        job_id(),
        JobRevision::new(2).expect("revision"),
        workspace_id(),
        service(),
        owner(),
        ScheduleSpec::once(TimestampMillis::new(3_000)),
        "next revision",
        DataClass::Workspace,
        1,
        1,
        true,
        Some(TimestampMillis::new(3_000)),
        false,
        TimestampMillis::new(2_000),
    )
    .expect("revision");

    assert!(matches!(
        database.append_scheduled_job_revision(&next).await,
        Err(RepositoryError::InvalidAutomationState)
    ));
}

#[tokio::test]
async fn scheduled_job_identity_cannot_move_between_workspaces() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let other_workspace = WorkspaceId::new();
    let revision = ScheduledJobRevision::new(
        job_id(),
        JobRevision::new(2).expect("revision"),
        other_workspace,
        lumen_core::automation::service_principal("other").expect("service"),
        owner(),
        ScheduleSpec::once(TimestampMillis::new(3_000)),
        "cross-workspace mutation",
        DataClass::Workspace,
        1,
        1,
        true,
        Some(TimestampMillis::new(3_000)),
        false,
        TimestampMillis::new(2_000),
    )
    .expect("job revision");

    assert!(matches!(
        database.append_scheduled_job_revision(&revision).await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
    assert_eq!(
        database
            .latest_scheduled_job_revision(job_id())
            .await
            .expect("job loaded")
            .expect("job exists")
            .workspace_id(),
        workspace_id()
    );
}

#[tokio::test]
async fn job_occurrence_leases_are_unique_and_expired_leases_recover() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let key = OccurrenceKey::new(
        job_id(),
        JobRevision::new(1).expect("revision"),
        TimestampMillis::new(2_000),
    );

    assert!(
        database
            .claim_job_occurrence(
                &key,
                Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("lease"),
                TimestampMillis::new(2_100),
                TimestampMillis::new(3_000),
            )
            .await
            .expect("first claim")
    );
    assert!(
        !database
            .claim_job_occurrence(
                &key,
                Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("lease"),
                TimestampMillis::new(2_200),
                TimestampMillis::new(3_500),
            )
            .await
            .expect("active lease blocks")
    );
    assert!(
        database
            .claim_job_occurrence(
                &key,
                Uuid::parse_str("33333333-3333-4333-8333-333333333333").expect("lease"),
                TimestampMillis::new(3_001),
                TimestampMillis::new(4_000),
            )
            .await
            .expect("expired lease recovers")
    );

    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scheduled_job_runs")
        .fetch_one(database.pool())
        .await
        .expect("run count");
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn scheduled_run_handoff_is_atomic_lease_fenced_and_terminal_idempotent() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let job = database
        .latest_scheduled_job_revision(job_id())
        .await
        .expect("job load")
        .expect("job");
    let key = OccurrenceKey::new(job_id(), job.revision(), TimestampMillis::new(2_000));
    let first_lease = Uuid::parse_str("11111111-1111-4111-8111-111111111111").expect("lease");
    let second_lease = Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("lease");
    let run_id = RunId::new();
    assert!(
        database
            .claim_job_occurrence(
                &key,
                first_lease,
                TimestampMillis::new(2_100),
                TimestampMillis::new(3_000),
            )
            .await
            .expect("claim")
    );
    database
        .persist_scheduled_run_handoff(
            &job,
            &key,
            first_lease,
            run_id,
            None,
            TimestampMillis::new(2_200),
        )
        .await
        .expect("durable handoff");

    let stored: (String, String, String, Option<i64>) = sqlx::query_as(
        "SELECT occurrence.run_id, occurrence.state, run.state, revision.next_due_at
         FROM scheduled_job_runs occurrence
         JOIN agent_runs run ON run.id = occurrence.run_id
         JOIN scheduled_job_revisions revision
           ON revision.job_id = occurrence.job_id AND revision.revision = occurrence.revision
         WHERE occurrence.occurrence_key = ?",
    )
    .bind(key.as_str())
    .fetch_one(database.pool())
    .await
    .expect("stored handoff");
    assert_eq!(
        stored,
        (run_id.to_string(), "claimed".into(), "created".into(), None)
    );
    assert!(matches!(
        database
            .start_scheduled_run(
                &key,
                second_lease,
                run_id,
                TimestampMillis::new(2_300),
                TimestampMillis::new(4_000),
            )
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
    assert!(matches!(
        database
            .start_scheduled_run(
                &key,
                first_lease,
                run_id,
                TimestampMillis::new(3_001),
                TimestampMillis::new(4_000),
            )
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
    assert!(
        database
            .claim_ready_scheduled_run(
                &key,
                second_lease,
                TimestampMillis::new(3_001),
                TimestampMillis::new(4_000),
            )
            .await
            .expect("ready claim")
    );
    database
        .start_scheduled_run(
            &key,
            second_lease,
            run_id,
            TimestampMillis::new(3_100),
            TimestampMillis::new(5_000),
        )
        .await
        .expect("fenced start");
    assert!(
        database
            .scheduled_run_lease_is_current(&key, second_lease, run_id,)
            .await
            .expect("current lease")
    );
    assert!(
        !database
            .scheduled_run_lease_is_current(&key, first_lease, run_id,)
            .await
            .expect("stale lease")
    );
    assert!(matches!(
        database
            .start_scheduled_run(
                &key,
                second_lease,
                run_id,
                TimestampMillis::new(3_200),
                TimestampMillis::new(5_000),
            )
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
    database
        .complete_scheduled_occurrence_for_run(run_id, "succeeded", TimestampMillis::new(3_300))
        .await
        .expect("completion");
    database
        .complete_scheduled_occurrence_for_run(run_id, "succeeded", TimestampMillis::new(3_400))
        .await
        .expect("idempotent completion");
    assert!(matches!(
        database
            .complete_scheduled_occurrence_for_run(run_id, "failed", TimestampMillis::new(3_500),)
            .await,
        Err(RepositoryError::ExecutionStateConflict)
    ));
}

#[tokio::test]
async fn owned_scheduled_handoff_commits_run_occurrence_and_lifecycle_together() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let job = database
        .latest_scheduled_job_revision(job_id())
        .await
        .expect("job load")
        .expect("job");
    let key = OccurrenceKey::new(job_id(), job.revision(), TimestampMillis::new(2_000));
    let lease = Uuid::new_v4();
    let owner = Uuid::new_v4();
    let run_id = RunId::new();
    assert!(
        database
            .claim_job_occurrence(
                &key,
                lease,
                TimestampMillis::new(2_100),
                TimestampMillis::new(3_000)
            )
            .await
            .expect("claim")
    );
    database
        .persist_owned_scheduled_run_handoff(
            &job,
            &key,
            lease,
            run_id,
            owner,
            None,
            TimestampMillis::new(2_200),
        )
        .await
        .expect("owned handoff");
    let row: (String, String, String) = sqlx::query_as(
        "SELECT occurrence.run_id, lifecycle.phase, lifecycle.owner_instance_id
         FROM scheduled_job_runs occurrence JOIN run_lifecycle lifecycle
         ON lifecycle.run_id = occurrence.run_id WHERE occurrence.occurrence_key = ?",
    )
    .bind(key.as_str())
    .fetch_one(database.pool())
    .await
    .expect("paired handoff");
    assert_eq!(
        row,
        (run_id.to_string(), "admitted".into(), owner.to_string())
    );
    let recovered_owner = Uuid::new_v4();
    let recovered_lease = Uuid::new_v4();
    assert!(
        database
            .claim_ready_scheduled_run(
                &key,
                recovered_lease,
                TimestampMillis::new(3_001),
                TimestampMillis::new(4_000)
            )
            .await
            .expect("recovery claim")
    );
    database
        .start_owned_scheduled_run(
            &key,
            recovered_lease,
            run_id,
            recovered_owner,
            TimestampMillis::new(3_100),
            TimestampMillis::new(5_000),
        )
        .await
        .expect("owned start");
    let started: (String, String, String) = sqlx::query_as(
        "SELECT run.state, lifecycle.phase, lifecycle.owner_instance_id
         FROM agent_runs run JOIN run_lifecycle lifecycle ON lifecycle.run_id = run.id
         WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("started state");
    assert_eq!(
        started,
        (
            "running".into(),
            "running".into(),
            recovered_owner.to_string()
        )
    );
    let next_owner = Uuid::new_v4();
    assert_eq!(
        database
            .reconcile_abandoned_owned_runs(next_owner, TimestampMillis::new(3_200))
            .await
            .expect("owner loss"),
        vec![run_id]
    );
    let reconciled: (String, String) = sqlx::query_as(
        "SELECT run.state, occurrence.state FROM agent_runs run
         JOIN scheduled_job_runs occurrence ON occurrence.run_id = run.id WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("reconciled state");
    assert_eq!(reconciled, ("failed".into(), "unknown".into()));
}

#[tokio::test]
async fn expired_started_handoff_recovers_as_unknown_without_redispatch() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let job = database
        .latest_scheduled_job_revision(job_id())
        .await
        .expect("job load")
        .expect("job");
    let key = OccurrenceKey::new(job_id(), job.revision(), TimestampMillis::new(2_000));
    let lease = Uuid::new_v4();
    let run_id = RunId::new();
    database
        .claim_job_occurrence(
            &key,
            lease,
            TimestampMillis::new(2_100),
            TimestampMillis::new(3_000),
        )
        .await
        .expect("claim");
    database
        .persist_scheduled_run_handoff(&job, &key, lease, run_id, None, TimestampMillis::new(2_200))
        .await
        .expect("handoff");
    database
        .start_scheduled_run(
            &key,
            lease,
            run_id,
            TimestampMillis::new(2_300),
            TimestampMillis::new(4_000),
        )
        .await
        .expect("start");

    assert!(
        database
            .recover_expired_running_scheduled_runs(TimestampMillis::new(3_999))
            .await
            .expect("active recovery")
            .is_empty()
    );
    assert_eq!(
        database
            .recover_expired_running_scheduled_runs(TimestampMillis::new(4_000))
            .await
            .expect("expired recovery"),
        vec![run_id]
    );
    let states: (String, String) = sqlx::query_as(
        "SELECT occurrence.state, run.state
         FROM scheduled_job_runs occurrence JOIN agent_runs run ON run.id = occurrence.run_id
         WHERE occurrence.occurrence_key = ?",
    )
    .bind(key.as_str())
    .fetch_one(database.pool())
    .await
    .expect("recovered states");
    assert_eq!(states, ("unknown".into(), "failed".into()));
    let lifecycle = database
        .get_run_lifecycle(workspace_id(), run_id)
        .await
        .expect("recovery lifecycle lookup")
        .expect("legacy active run receives durable reconciliation marker");
    assert_eq!(lifecycle.phase(), "reconciliation_required");
    assert_eq!(
        lifecycle.effect_certainty(),
        lumen_db::EffectCertainty::Unknown
    );
    assert_eq!(lifecycle.terminal_code(), Some("legacy_lease_expired"));
    assert!(lifecycle.terminal_audit_pending());
    database
        .flush_terminal_audit(workspace_id(), run_id)
        .await
        .expect("legacy recovery audit is replayable");
    assert_eq!(
        database
            .list_audit_records_for_run(workspace_id(), run_id)
            .await
            .expect("legacy audit")
            .iter()
            .filter(|record| {
                record.event().kind()
                    == lumen_core::audit::AuditEventKind::RunReconciliationRequired
            })
            .count(),
        1
    );
    assert!(
        database
            .recover_expired_running_scheduled_runs(TimestampMillis::new(4_000))
            .await
            .expect("repeat recovery")
            .is_empty()
    );
}

#[tokio::test]
async fn scheduled_terminalization_rolls_back_both_records_on_write_failure() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let job = database
        .latest_scheduled_job_revision(job_id())
        .await
        .expect("job load")
        .expect("job");
    let key = OccurrenceKey::new(job_id(), job.revision(), TimestampMillis::new(2_000));
    let lease = Uuid::new_v4();
    let run_id = RunId::new();
    database
        .claim_job_occurrence(
            &key,
            lease,
            TimestampMillis::new(2_100),
            TimestampMillis::new(3_000),
        )
        .await
        .expect("claim");
    database
        .persist_scheduled_run_handoff(&job, &key, lease, run_id, None, TimestampMillis::new(2_200))
        .await
        .expect("handoff");
    database
        .start_scheduled_run(
            &key,
            lease,
            run_id,
            TimestampMillis::new(2_300),
            TimestampMillis::new(4_000),
        )
        .await
        .expect("start");
    sqlx::query(
        "CREATE TRIGGER fail_scheduled_terminalization
         BEFORE UPDATE OF state ON scheduled_job_runs
         WHEN OLD.run_id = NEW.run_id AND NEW.state = 'failed'
         BEGIN SELECT RAISE(FAIL, 'injected terminal write failure'); END",
    )
    .execute(database.pool())
    .await
    .expect("fault trigger");

    assert!(matches!(
        database
            .terminalize_run(
                run_id,
                "failed",
                Some("failed"),
                TimestampMillis::new(2_400)
            )
            .await,
        Err(RepositoryError::Sqlx(_))
    ));
    let states: (String, String) = sqlx::query_as(
        "SELECT run.state, occurrence.state
         FROM agent_runs run JOIN scheduled_job_runs occurrence ON occurrence.run_id = run.id
         WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("rolled-back states");
    assert_eq!(states, ("running".into(), "running".into()));

    sqlx::query("DROP TRIGGER fail_scheduled_terminalization")
        .execute(database.pool())
        .await
        .expect("remove fault trigger");
    database
        .terminalize_run(
            run_id,
            "failed",
            Some("failed"),
            TimestampMillis::new(2_500),
        )
        .await
        .expect("terminalization");
    database
        .terminalize_run(
            run_id,
            "failed",
            Some("failed"),
            TimestampMillis::new(2_600),
        )
        .await
        .expect("idempotent terminalization");
}

#[tokio::test]
async fn forced_shutdown_marks_active_scheduled_work_unknown() {
    let database = database().await;
    insert_service_and_job(&database).await;
    let job = database
        .latest_scheduled_job_revision(job_id())
        .await
        .expect("job load")
        .expect("job");
    let key = OccurrenceKey::new(job_id(), job.revision(), TimestampMillis::new(2_000));
    let lease = Uuid::new_v4();
    let run_id = RunId::new();
    database
        .claim_job_occurrence(
            &key,
            lease,
            TimestampMillis::new(2_100),
            TimestampMillis::new(3_000),
        )
        .await
        .expect("claim");
    database
        .persist_scheduled_run_handoff(&job, &key, lease, run_id, None, TimestampMillis::new(2_200))
        .await
        .expect("handoff");
    database
        .start_scheduled_run(
            &key,
            lease,
            run_id,
            TimestampMillis::new(2_300),
            TimestampMillis::new(4_000),
        )
        .await
        .expect("start");

    assert!(
        database
            .force_fail_run_on_shutdown(run_id, TimestampMillis::new(2_400))
            .await
            .expect("forced shutdown")
    );
    let states: (String, String) = sqlx::query_as(
        "SELECT run.state, occurrence.state
         FROM agent_runs run JOIN scheduled_job_runs occurrence ON occurrence.run_id = run.id
         WHERE run.id = ?",
    )
    .bind(run_id.to_string())
    .fetch_one(database.pool())
    .await
    .expect("shutdown states");
    assert_eq!(states, ("failed".into(), "unknown".into()));
    assert!(
        !database
            .force_fail_run_on_shutdown(run_id, TimestampMillis::new(2_500))
            .await
            .expect("idempotent shutdown")
    );
}

#[tokio::test]
async fn scheduled_handoff_rechecks_job_and_service_after_claim() {
    for change in ["new-revision", "service-disabled"] {
        let database = database().await;
        insert_service_and_job(&database).await;
        let job = database
            .latest_scheduled_job_revision(job_id())
            .await
            .expect("job load")
            .expect("job");
        let key = OccurrenceKey::new(job_id(), job.revision(), TimestampMillis::new(2_000));
        let lease = Uuid::new_v4();
        assert!(
            database
                .claim_job_occurrence(
                    &key,
                    lease,
                    TimestampMillis::new(2_100),
                    TimestampMillis::new(3_000),
                )
                .await
                .expect("claim")
        );
        if change == "new-revision" {
            database
                .append_scheduled_job_revision(
                    &ScheduledJobRevision::new(
                        job_id(),
                        JobRevision::new(2).expect("revision"),
                        workspace_id(),
                        service(),
                        owner(),
                        ScheduleSpec::once(TimestampMillis::new(4_000)),
                        "replacement",
                        DataClass::Workspace,
                        4,
                        2,
                        true,
                        Some(TimestampMillis::new(4_000)),
                        false,
                        TimestampMillis::new(2_200),
                    )
                    .expect("replacement job"),
                )
                .await
                .expect("replacement stored");
        } else {
            sqlx::query("UPDATE service_identities SET enabled = 0")
                .execute(database.pool())
                .await
                .expect("service disabled");
        }
        assert!(matches!(
            database
                .persist_scheduled_run_handoff(
                    &job,
                    &key,
                    lease,
                    RunId::new(),
                    None,
                    TimestampMillis::new(2_300),
                )
                .await,
            Err(RepositoryError::ExecutionStateConflict)
        ));
        let state: (Option<String>, String) =
            sqlx::query_as("SELECT run_id, state FROM scheduled_job_runs WHERE occurrence_key = ?")
                .bind(key.as_str())
                .fetch_one(database.pool())
                .await
                .expect("occurrence");
        assert_eq!(state, (None, "claimed".into()), "{change}");
        let runs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_runs")
            .fetch_one(database.pool())
            .await
            .expect("run count");
        assert_eq!(runs, 0, "{change}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_occurrence_claims_have_one_winner() {
    let (_directory, first_database, second_database) = file_databases().await;
    insert_service_and_job(&first_database).await;
    let key = OccurrenceKey::new(
        job_id(),
        JobRevision::new(1).expect("revision"),
        TimestampMillis::new(2_000),
    );
    let barrier = Arc::new(Barrier::new(3));
    let first = tokio::spawn({
        let barrier = Arc::clone(&barrier);
        let key = key.clone();
        async move {
            barrier.wait().await;
            first_database
                .claim_job_occurrence(
                    &key,
                    Uuid::new_v4(),
                    TimestampMillis::new(2_100),
                    TimestampMillis::new(3_000),
                )
                .await
        }
    });
    let second = tokio::spawn({
        let barrier = Arc::clone(&barrier);
        async move {
            barrier.wait().await;
            second_database
                .claim_job_occurrence(
                    &key,
                    Uuid::new_v4(),
                    TimestampMillis::new(2_100),
                    TimestampMillis::new(3_000),
                )
                .await
        }
    });
    barrier.wait().await;
    let results = [
        first.await.expect("first task").expect("first claim"),
        second.await.expect("second task").expect("second claim"),
    ];

    assert_eq!(results.into_iter().filter(|claimed| *claimed).count(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn occurrence_claim_waits_for_concurrent_eligibility_changes() {
    for change in ["service-disabled", "new-revision", "job-disabled"] {
        let (_directory, writer, claimant) = file_databases().await;
        insert_service_and_job(&writer).await;
        let mut transaction = writer
            .pool()
            .begin_with("BEGIN IMMEDIATE")
            .await
            .expect("writer transaction");
        match change {
            "service-disabled" => {
                sqlx::query(
                    "UPDATE service_identities SET enabled = 0
                     WHERE workspace_id = ? AND provider = ? AND subject = ?",
                )
                .bind(workspace_id().to_string())
                .bind(service().provider())
                .bind(service().subject())
                .execute(&mut *transaction)
                .await
                .expect("service disabled");
            }
            "new-revision" | "job-disabled" => {
                sqlx::query(
                    "INSERT INTO scheduled_job_revisions (
                        job_id, revision, schedule_kind, schedule_start_at, interval_millis,
                        prompt, data_class, max_model_turns, max_actions, enabled,
                        next_due_at, idempotent, created_at
                     )
                     SELECT job_id, 2, schedule_kind, schedule_start_at, interval_millis,
                            prompt, data_class, max_model_turns, max_actions, ?, ?,
                            idempotent, 1500
                     FROM scheduled_job_revisions WHERE job_id = ? AND revision = 1",
                )
                .bind(if change == "new-revision" {
                    1_i64
                } else {
                    0_i64
                })
                .bind(if change == "new-revision" {
                    Some(3_000_i64)
                } else {
                    None
                })
                .bind(job_id().to_string())
                .execute(&mut *transaction)
                .await
                .expect("job revision changed");
            }
            _ => unreachable!(),
        }

        let key = OccurrenceKey::new(
            job_id(),
            JobRevision::new(1).expect("revision"),
            TimestampMillis::new(2_000),
        );
        let barrier = Arc::new(Barrier::new(2));
        let mut claim = tokio::spawn({
            let barrier = Arc::clone(&barrier);
            async move {
                barrier.wait().await;
                claimant
                    .claim_job_occurrence(
                        &key,
                        Uuid::new_v4(),
                        TimestampMillis::new(2_100),
                        TimestampMillis::new(3_000),
                    )
                    .await
            }
        });
        barrier.wait().await;
        tokio::task::yield_now().await;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut claim)
                .await
                .is_err(),
            "claim must wait for {change} transaction"
        );
        transaction.commit().await.expect("state change committed");
        assert!(
            !claim
                .await
                .expect("claim task")
                .expect("claim after state change"),
            "claim must reject {change}"
        );
        let leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM scheduled_job_leases")
            .fetch_one(writer.pool())
            .await
            .expect("lease count");
        assert_eq!(leases, 0, "{change} must not create a lease");
    }
}

#[tokio::test]
async fn occurrence_claim_rechecks_latest_job_and_service_state() {
    let first_database = database().await;
    insert_service_and_job(&first_database).await;
    first_database
        .append_scheduled_job_revision(
            &ScheduledJobRevision::new(
                job_id(),
                JobRevision::new(2).expect("revision"),
                workspace_id(),
                service(),
                owner(),
                ScheduleSpec::once(TimestampMillis::new(2_000)),
                "disabled",
                DataClass::Workspace,
                1,
                1,
                false,
                None,
                false,
                TimestampMillis::new(1_500),
            )
            .expect("disabled revision"),
        )
        .await
        .expect("disabled revision stored");
    let stale = OccurrenceKey::new(
        job_id(),
        JobRevision::new(1).expect("revision"),
        TimestampMillis::new(2_000),
    );
    assert!(
        !first_database
            .claim_job_occurrence(
                &stale,
                Uuid::new_v4(),
                TimestampMillis::new(2_100),
                TimestampMillis::new(3_000),
            )
            .await
            .expect("stale claim checked")
    );

    let database = database().await;
    insert_service_and_job(&database).await;
    database
        .upsert_service_identity(
            &ServiceIdentity::new(
                service(),
                workspace_id(),
                owner(),
                "Daily brief",
                false,
                TimestampMillis::new(1_000),
                TimestampMillis::new(1_500),
            )
            .expect("disabled service"),
            [],
        )
        .await
        .expect("service disabled");
    assert!(
        !database
            .claim_job_occurrence(
                &stale,
                Uuid::new_v4(),
                TimestampMillis::new(2_100),
                TimestampMillis::new(3_000),
            )
            .await
            .expect("disabled service claim checked")
    );
}

#[tokio::test]
async fn skill_versions_and_capture_drafts_are_separate_immutable_records() {
    let database = database().await;
    let skill = SkillVersionRecord::new(
        skill_id(),
        SkillVersion::parse("1.0.0").expect("version"),
        workspace_id(),
        "Daily Brief",
        "Summarize yesterday's notable changes.",
        "markdown",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        true,
        owner(),
        Some(owner()),
        TimestampMillis::new(1_000),
        Some(TimestampMillis::new(1_100)),
    )
    .expect("skill version");
    database
        .insert_skill_version(&skill)
        .await
        .expect("skill stored");
    database
        .set_skill_workspace_state(
            workspace_id(),
            skill_id(),
            &SkillVersion::parse("1.0.0").expect("version"),
            true,
            TimestampMillis::new(1_200),
        )
        .await
        .expect("skill enabled");

    assert_eq!(
        database
            .enabled_skill_versions(workspace_id())
            .await
            .expect("enabled skills"),
        vec![skill.clone()]
    );
    assert!(matches!(
        database.insert_skill_version(&skill).await,
        Err(RepositoryError::Sqlx(_))
    ));

    let draft = WorkflowCaptureDraft::new(
        Uuid::parse_str("44444444-4444-4444-8444-444444444444").expect("draft"),
        workspace_id(),
        "Captured brief",
        "redacted steps",
        owner(),
        TimestampMillis::new(2_000),
    )
    .expect("capture draft");
    database
        .insert_workflow_capture_draft(&draft)
        .await
        .expect("draft stored");
    assert_eq!(
        database
            .get_workflow_capture_draft(draft.id())
            .await
            .expect("draft loaded"),
        Some(draft)
    );
    let skill_count: i64 = sqlx::query("SELECT COUNT(*) AS count FROM skill_versions")
        .fetch_one(database.pool())
        .await
        .expect("skill count")
        .try_get("count")
        .expect("count");
    assert_eq!(skill_count, 1);
}

#[tokio::test]
async fn a_new_skill_version_cannot_silently_change_the_pinned_name() {
    let database = database().await;
    let first = SkillVersionRecord::new(
        skill_id(),
        SkillVersion::parse("1.0.0").expect("version"),
        workspace_id(),
        "Daily Brief",
        "Reviewed brief",
        "markdown",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        true,
        owner(),
        Some(owner()),
        TimestampMillis::new(1_000),
        Some(TimestampMillis::new(1_000)),
    )
    .expect("first version");
    database
        .insert_skill_version(&first)
        .await
        .expect("first stored");
    let changed = SkillVersionRecord::new(
        skill_id(),
        SkillVersion::parse("2.0.0").expect("version"),
        workspace_id(),
        "Different Name",
        "Reviewed brief",
        "markdown",
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        true,
        owner(),
        Some(owner()),
        TimestampMillis::new(2_000),
        Some(TimestampMillis::new(2_000)),
    )
    .expect("changed version");

    assert!(database.insert_skill_version(&changed).await.is_err());
    assert!(
        database
            .skill_version(workspace_id(), skill_id(), changed.version())
            .await
            .expect("version lookup")
            .is_none()
    );
}
