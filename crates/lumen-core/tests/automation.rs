use std::time::Duration;

use lumen_core::{
    action::RunId,
    approval::TimestampMillis,
    automation::{
        JobId, JobOrigin, JobRevision, OccurrenceKey, ScheduleSpec, SkillId, SkillVersion,
    },
    identity::{PrincipalId, WorkspaceId},
    run::RunContext,
};

#[test]
fn automation_identifiers_and_versions_are_canonical() {
    let job_id = JobId::from_uuid(
        uuid::Uuid::parse_str("7825c2e7-1d9c-40df-ad69-209aeb02fc8d").expect("job id"),
    );
    let skill_id = SkillId::from_uuid(
        uuid::Uuid::parse_str("5ed0e220-393b-42d3-9e3b-49691cf71bcf").expect("skill id"),
    );
    let revision = JobRevision::new(7).expect("revision");
    let version = SkillVersion::parse("1.2.3").expect("skill version");

    assert_eq!(job_id.to_string(), "7825c2e7-1d9c-40df-ad69-209aeb02fc8d");
    assert_eq!(skill_id.to_string(), "5ed0e220-393b-42d3-9e3b-49691cf71bcf");
    assert_eq!(revision.as_u64(), 7);
    assert_eq!(version.as_str(), "1.2.3");
    assert!(JobRevision::new(0).is_err());
    assert!(SkillVersion::parse("latest").is_err());
}

#[test]
fn service_principals_are_explicit_and_non_inheriting() {
    let service = lumen_core::automation::service_principal("daily-brief").expect("service");
    let local = PrincipalId::new("local", "daily-brief").expect("local principal");

    assert_eq!(service.provider(), "service");
    assert_eq!(service.subject(), "daily-brief");
    assert_ne!(service, local);
    assert!(lumen_core::automation::service_principal("").is_err());
    assert!(lumen_core::automation::service_principal("daily\nbrief").is_err());
}

#[test]
fn schedules_calculate_next_due_times_and_reject_ambiguous_intervals() {
    let once = ScheduleSpec::once(TimestampMillis::new(1_000));
    assert_eq!(
        once.next_after(TimestampMillis::new(999), true),
        Some(TimestampMillis::new(1_000))
    );
    assert_eq!(once.next_after(TimestampMillis::new(1_000), true), None);
    assert_eq!(once.next_after(TimestampMillis::new(999), false), None);

    let interval = ScheduleSpec::interval(TimestampMillis::new(1_000), Duration::from_millis(250))
        .expect("interval");
    assert_eq!(
        interval.next_after(TimestampMillis::new(900), true),
        Some(TimestampMillis::new(1_000))
    );
    assert_eq!(
        interval.next_after(TimestampMillis::new(1_000), true),
        Some(TimestampMillis::new(1_250))
    );
    assert_eq!(
        interval.next_after(TimestampMillis::new(1_999), true),
        Some(TimestampMillis::new(2_000))
    );
    assert_eq!(
        interval.next_after(TimestampMillis::new(1_000), false),
        None
    );
    assert!(ScheduleSpec::interval(TimestampMillis::new(1_000), Duration::ZERO).is_err());
}

#[test]
fn occurrence_keys_are_deterministic_over_job_revision_and_scheduled_time() {
    let job_id = JobId::from_uuid(
        uuid::Uuid::parse_str("7825c2e7-1d9c-40df-ad69-209aeb02fc8d").expect("job id"),
    );
    let first = OccurrenceKey::new(
        job_id,
        JobRevision::new(2).expect("revision"),
        TimestampMillis::new(1_700_000_000_000),
    );
    let same = OccurrenceKey::new(
        job_id,
        JobRevision::new(2).expect("revision"),
        TimestampMillis::new(1_700_000_000_000),
    );
    let different_revision = OccurrenceKey::new(
        job_id,
        JobRevision::new(3).expect("revision"),
        TimestampMillis::new(1_700_000_000_000),
    );

    assert_eq!(first, same);
    assert_ne!(first, different_revision);
    assert_eq!(
        first.as_str(),
        "7825c2e7-1d9c-40df-ad69-209aeb02fc8d:2:1700000000000"
    );
}

#[test]
fn run_context_can_carry_optional_job_origin_without_changing_interactive_runs() {
    let context = RunContext::new(
        RunId::new(),
        WorkspaceId::new(),
        PrincipalId::new("local", "operator").expect("principal"),
    );
    assert_eq!(context.job_origin(), None);

    let job_id = JobId::from_uuid(
        uuid::Uuid::parse_str("7825c2e7-1d9c-40df-ad69-209aeb02fc8d").expect("job id"),
    );
    let origin = JobOrigin::new(
        job_id,
        JobRevision::new(1).expect("revision"),
        TimestampMillis::new(1_700_000_000_000),
    );
    let scheduled = context.clone().with_job_origin(origin.clone());

    assert_eq!(scheduled.run_id(), context.run_id());
    assert_eq!(scheduled.workspace_id(), context.workspace_id());
    assert_eq!(scheduled.actor(), context.actor());
    assert_eq!(scheduled.job_origin(), Some(&origin));
}
