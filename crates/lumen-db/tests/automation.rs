use std::time::Duration;

use lumen_core::{
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
    assert!(matches!(duplicate, Err(RepositoryError::Sqlx(_))));
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
