use std::time::Duration;

use lumen_core::{
    approval::TimestampMillis,
    automation::{JobId, JobRevision, OccurrenceKey, ScheduleSpec, SkillId, SkillVersion},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
};
use sqlx::Row;
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceIdentity {
    principal: PrincipalId,
    workspace_id: WorkspaceId,
    owner: PrincipalId,
    label: String,
    enabled: bool,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl ServiceIdentity {
    pub fn new(
        principal: PrincipalId,
        workspace_id: WorkspaceId,
        owner: PrincipalId,
        label: impl Into<String>,
        enabled: bool,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        let label = label.into();
        if principal.provider() != "service"
            || label.is_empty()
            || label.len() > 128
            || label.trim() != label
            || label.chars().any(char::is_control)
            || updated_at < created_at
        {
            return Err(RepositoryError::InvalidAutomationState);
        }
        Ok(Self {
            principal,
            workspace_id,
            owner,
            label,
            enabled,
            created_at,
            updated_at,
        })
    }

    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn owner(&self) -> &PrincipalId {
        &self.owner
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledJobRevision {
    job_id: JobId,
    revision: JobRevision,
    workspace_id: WorkspaceId,
    service: PrincipalId,
    owner: PrincipalId,
    schedule: ScheduleSpec,
    prompt: String,
    data_class: DataClass,
    max_model_turns: u32,
    max_actions: u32,
    enabled: bool,
    next_due_at: Option<TimestampMillis>,
    idempotent: bool,
    created_at: TimestampMillis,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScheduledOccurrenceRecord {
    run_id: Option<lumen_core::action::RunId>,
    state: String,
}

impl ScheduledOccurrenceRecord {
    pub const fn run_id(&self) -> Option<lumen_core::action::RunId> {
        self.run_id
    }

    pub fn state(&self) -> &str {
        &self.state
    }
}

impl ScheduledJobRevision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: JobId,
        revision: JobRevision,
        workspace_id: WorkspaceId,
        service: PrincipalId,
        owner: PrincipalId,
        schedule: ScheduleSpec,
        prompt: impl Into<String>,
        data_class: DataClass,
        max_model_turns: u32,
        max_actions: u32,
        enabled: bool,
        next_due_at: Option<TimestampMillis>,
        idempotent: bool,
        created_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        let prompt = prompt.into();
        if service.provider() != "service"
            || prompt.is_empty()
            || prompt.len() > 8192
            || prompt.trim() != prompt
            || prompt.chars().any(char::is_control)
            || data_class == DataClass::Secret
            || max_model_turns == 0
            || max_actions == 0
        {
            return Err(RepositoryError::InvalidAutomationState);
        }
        Ok(Self {
            job_id,
            revision,
            workspace_id,
            service,
            owner,
            schedule,
            prompt,
            data_class,
            max_model_turns,
            max_actions,
            enabled,
            next_due_at,
            idempotent,
            created_at,
        })
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub const fn revision(&self) -> JobRevision {
        self.revision
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn service(&self) -> &PrincipalId {
        &self.service
    }

    pub const fn owner(&self) -> &PrincipalId {
        &self.owner
    }

    pub const fn schedule(&self) -> ScheduleSpec {
        self.schedule
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }

    pub const fn max_model_turns(&self) -> u32 {
        self.max_model_turns
    }

    pub const fn max_actions(&self) -> u32 {
        self.max_actions
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn next_due_at(&self) -> Option<TimestampMillis> {
        self.next_due_at
    }

    pub const fn idempotent(&self) -> bool {
        self.idempotent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillVersionRecord {
    skill_id: SkillId,
    version: SkillVersion,
    workspace_id: WorkspaceId,
    name: String,
    description: String,
    source_format: String,
    source_digest: String,
    reviewed: bool,
    created_by: PrincipalId,
    reviewed_by: Option<PrincipalId>,
    created_at: TimestampMillis,
    reviewed_at: Option<TimestampMillis>,
}

impl SkillVersionRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        skill_id: SkillId,
        version: SkillVersion,
        workspace_id: WorkspaceId,
        name: impl Into<String>,
        description: impl Into<String>,
        source_format: impl Into<String>,
        source_digest: impl Into<String>,
        reviewed: bool,
        created_by: PrincipalId,
        reviewed_by: Option<PrincipalId>,
        created_at: TimestampMillis,
        reviewed_at: Option<TimestampMillis>,
    ) -> Result<Self, RepositoryError> {
        let name = name.into();
        let description = description.into();
        let source_format = source_format.into();
        let source_digest = source_digest.into();
        if invalid_text(&name, 128)
            || invalid_text(&description, 2048)
            || invalid_text(&source_format, 32)
            || !valid_sha256_digest(&source_digest)
            || (reviewed && (reviewed_by.is_none() || reviewed_at.is_none()))
            || reviewed_at.is_some_and(|timestamp| timestamp < created_at)
        {
            return Err(RepositoryError::InvalidAutomationState);
        }
        Ok(Self {
            skill_id,
            version,
            workspace_id,
            name,
            description,
            source_format,
            source_digest,
            reviewed,
            created_by,
            reviewed_by,
            created_at,
            reviewed_at,
        })
    }

    pub const fn skill_id(&self) -> SkillId {
        self.skill_id
    }

    pub const fn version(&self) -> &SkillVersion {
        &self.version
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn source_format(&self) -> &str {
        &self.source_format
    }

    pub fn source_digest(&self) -> &str {
        &self.source_digest
    }

    pub const fn reviewed(&self) -> bool {
        self.reviewed
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowCaptureDraft {
    id: Uuid,
    workspace_id: WorkspaceId,
    title: String,
    body: String,
    created_by: PrincipalId,
    created_at: TimestampMillis,
}

impl WorkflowCaptureDraft {
    pub fn new(
        id: Uuid,
        workspace_id: WorkspaceId,
        title: impl Into<String>,
        body: impl Into<String>,
        created_by: PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        let title = title.into();
        let body = body.into();
        if invalid_text(&title, 128) || invalid_body_text(&body, 65_536) {
            return Err(RepositoryError::InvalidAutomationState);
        }
        Ok(Self {
            id,
            workspace_id,
            title,
            body,
            created_by,
            created_at,
        })
    }

    pub const fn id(&self) -> Uuid {
        self.id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn title(&self) -> &str {
        &self.title
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

impl Database {
    pub async fn upsert_service_identity(
        &self,
        identity: &ServiceIdentity,
        grants: impl IntoIterator<Item = Capability>,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(identity.created_at)?;
        let updated_at = timestamp_to_i64(identity.updated_at)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
        )
        .bind(identity.principal.provider())
        .bind(identity.principal.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO service_identities (
                provider, subject, workspace_id, owner_provider, owner_subject,
                label, enabled, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(provider, subject) DO UPDATE SET
                workspace_id = excluded.workspace_id,
                owner_provider = excluded.owner_provider,
                owner_subject = excluded.owner_subject,
                label = excluded.label,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at",
        )
        .bind(identity.principal.provider())
        .bind(identity.principal.subject())
        .bind(identity.workspace_id.to_string())
        .bind(identity.owner.provider())
        .bind(identity.owner.subject())
        .bind(&identity.label)
        .bind(if identity.enabled { 1_i64 } else { 0_i64 })
        .bind(created_at)
        .bind(updated_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "DELETE FROM service_identity_grants
             WHERE provider = ? AND subject = ? AND workspace_id = ?",
        )
        .bind(identity.principal.provider())
        .bind(identity.principal.subject())
        .bind(identity.workspace_id.to_string())
        .execute(&mut *transaction)
        .await?;
        for grant in grants {
            let parts = grant_scope_parts(grant.scope())?;
            sqlx::query(
                "INSERT INTO service_identity_grants (
                    provider, subject, workspace_id, capability_name, scope_kind,
                    scope_workspace_id, scope_path, scope_resource_type, scope_resource_value
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(identity.principal.provider())
            .bind(identity.principal.subject())
            .bind(identity.workspace_id.to_string())
            .bind(grant.name().as_str())
            .bind(parts.kind)
            .bind(parts.workspace_id.unwrap_or_default())
            .bind(parts.path.unwrap_or_default())
            .bind(parts.resource_type.unwrap_or_default())
            .bind(parts.resource_value.unwrap_or_default())
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn get_service_identity(
        &self,
        workspace_id: WorkspaceId,
        principal: &PrincipalId,
    ) -> Result<Option<ServiceIdentity>, RepositoryError> {
        let row = sqlx::query(
            "SELECT owner_provider, owner_subject, label, enabled, created_at, updated_at
             FROM service_identities
             WHERE workspace_id = ? AND provider = ? AND subject = ?",
        )
        .bind(workspace_id.to_string())
        .bind(principal.provider())
        .bind(principal.subject())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            ServiceIdentity::new(
                principal.clone(),
                workspace_id,
                PrincipalId::new(
                    row.try_get::<String, _>("owner_provider")?,
                    row.try_get::<String, _>("owner_subject")?,
                )
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
                row.try_get::<String, _>("label")?,
                row.try_get::<i64, _>("enabled")? == 1,
                timestamp_from_row(&row, "created_at")?,
                timestamp_from_row(&row, "updated_at")?,
            )
        })
        .transpose()
    }

    pub async fn service_identity_grants(
        &self,
        workspace_id: WorkspaceId,
        principal: &PrincipalId,
    ) -> Result<Vec<Capability>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT capability_name, scope_kind, scope_workspace_id, scope_path,
                    scope_resource_type, scope_resource_value
             FROM service_identity_grants
             WHERE workspace_id = ? AND provider = ? AND subject = ?
             ORDER BY capability_name, scope_kind, scope_workspace_id, scope_path,
                      scope_resource_type, scope_resource_value",
        )
        .bind(workspace_id.to_string())
        .bind(principal.provider())
        .bind(principal.subject())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                let name = CapabilityName::parse(&row.try_get::<String, _>("capability_name")?)
                    .ok_or(RepositoryError::InvalidAutomationState)?;
                let scope = scope_from_row(&row)?;
                Ok(Capability::new(name, scope))
            })
            .collect()
    }

    pub async fn append_scheduled_job_revision(
        &self,
        revision: &ScheduledJobRevision,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT OR IGNORE INTO scheduled_jobs (
                job_id, workspace_id, service_provider, service_subject,
                owner_provider, owner_subject, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(revision.job_id.to_string())
        .bind(revision.workspace_id.to_string())
        .bind(revision.service.provider())
        .bind(revision.service.subject())
        .bind(revision.owner.provider())
        .bind(revision.owner.subject())
        .bind(timestamp_to_i64(revision.created_at)?)
        .execute(&mut *transaction)
        .await?;
        let identity: (String, String, String, String, String) = sqlx::query_as(
            "SELECT workspace_id, service_provider, service_subject, owner_provider, owner_subject
             FROM scheduled_jobs WHERE job_id = ?",
        )
        .bind(revision.job_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        if identity
            != (
                revision.workspace_id.to_string(),
                revision.service.provider().to_owned(),
                revision.service.subject().to_owned(),
                revision.owner.provider().to_owned(),
                revision.owner.subject().to_owned(),
            )
        {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let revision_number = i64::try_from(revision.revision.as_u64())
            .map_err(|_| RepositoryError::InvalidAutomationState)?;
        let latest: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(revision) FROM scheduled_job_revisions WHERE job_id = ?",
        )
        .bind(revision.job_id.to_string())
        .fetch_one(&mut *transaction)
        .await?;
        let expected_revision = latest
            .map_or(Some(1), |value| value.checked_add(1))
            .ok_or(RepositoryError::InvalidAutomationState)?;
        if revision_number != expected_revision {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let (schedule_kind, schedule_start_at, interval_millis) = schedule_parts(revision.schedule);
        sqlx::query(
            "INSERT INTO scheduled_job_revisions (
                job_id, revision, schedule_kind, schedule_start_at, interval_millis,
                prompt, data_class, max_model_turns, max_actions, enabled,
                next_due_at, idempotent, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(revision.job_id.to_string())
        .bind(revision_number)
        .bind(schedule_kind)
        .bind(timestamp_to_i64(schedule_start_at)?)
        .bind(
            interval_millis
                .map(|value| {
                    i64::try_from(value).map_err(|_| RepositoryError::InvalidAutomationState)
                })
                .transpose()?,
        )
        .bind(&revision.prompt)
        .bind(revision.data_class.as_str())
        .bind(i64::from(revision.max_model_turns))
        .bind(i64::from(revision.max_actions))
        .bind(if revision.enabled { 1_i64 } else { 0_i64 })
        .bind(revision.next_due_at.map(timestamp_to_i64).transpose()?)
        .bind(if revision.idempotent { 1_i64 } else { 0_i64 })
        .bind(timestamp_to_i64(revision.created_at)?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn latest_scheduled_job_revision(
        &self,
        job_id: JobId,
    ) -> Result<Option<ScheduledJobRevision>, RepositoryError> {
        let row = sqlx::query(
            "SELECT job.workspace_id, job.service_provider, job.service_subject,
                    job.owner_provider, job.owner_subject,
                    revision.revision, revision.schedule_kind, revision.schedule_start_at,
                    revision.interval_millis, revision.prompt, revision.data_class,
                    revision.max_model_turns, revision.max_actions, revision.enabled,
                    revision.next_due_at, revision.idempotent, revision.created_at
             FROM scheduled_jobs job
             JOIN scheduled_job_revisions revision ON revision.job_id = job.job_id
             WHERE job.job_id = ?
             ORDER BY revision.revision DESC LIMIT 1",
        )
        .bind(job_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| scheduled_job_revision_from_row(job_id, &row))
            .transpose()
    }

    pub async fn due_scheduled_job_revisions(
        &self,
        now: TimestampMillis,
    ) -> Result<Vec<ScheduledJobRevision>, RepositoryError> {
        let rows = sqlx::query(
            "WITH latest_revisions AS (
                SELECT job_id, MAX(revision) AS revision
                FROM scheduled_job_revisions
                GROUP BY job_id
             )
             SELECT job.workspace_id, job.service_provider, job.service_subject,
                    job.owner_provider, job.owner_subject, job.job_id,
                    revision.revision, revision.schedule_kind, revision.schedule_start_at,
                    revision.interval_millis, revision.prompt, revision.data_class,
                    revision.max_model_turns, revision.max_actions, revision.enabled,
                    revision.next_due_at, revision.idempotent, revision.created_at
             FROM latest_revisions latest
             JOIN scheduled_jobs job ON job.job_id = latest.job_id
             JOIN scheduled_job_revisions revision
               ON revision.job_id = latest.job_id AND revision.revision = latest.revision
             JOIN service_identities service
               ON service.provider = job.service_provider
              AND service.subject = job.service_subject
              AND service.workspace_id = job.workspace_id
             WHERE revision.enabled = 1
               AND service.enabled = 1
               AND revision.next_due_at IS NOT NULL
               AND revision.next_due_at <= ?
             ORDER BY revision.next_due_at, job.job_id",
        )
        .bind(timestamp_to_i64(now)?)
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                let job_id = JobId::from_uuid(
                    row.try_get::<String, _>("job_id")?
                        .parse()
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                );
                scheduled_job_revision_from_row(job_id, &row)
            })
            .collect()
    }

    pub async fn claim_job_occurrence(
        &self,
        key: &OccurrenceKey,
        lease_id: Uuid,
        now: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<bool, RepositoryError> {
        let now_i64 = timestamp_to_i64(now)?;
        let expires_i64 = timestamp_to_i64(expires_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let eligible: i64 = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1
                FROM scheduled_jobs job
                JOIN scheduled_job_revisions revision ON revision.job_id = job.job_id
                JOIN service_identities service
                  ON service.workspace_id = job.workspace_id
                 AND service.provider = job.service_provider
                 AND service.subject = job.service_subject
                WHERE job.job_id = ?
                  AND revision.revision = ?
                  AND revision.revision = (
                      SELECT MAX(latest.revision)
                      FROM scheduled_job_revisions latest
                      WHERE latest.job_id = job.job_id
                  )
                  AND revision.enabled = 1
                  AND revision.next_due_at = ?
                  AND service.enabled = 1
             )",
        )
        .bind(key.job_id().to_string())
        .bind(
            i64::try_from(key.revision().as_u64())
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        )
        .bind(timestamp_to_i64(key.scheduled_for())?)
        .fetch_one(&mut *transaction)
        .await?;
        if eligible == 0 {
            transaction.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT OR IGNORE INTO scheduled_job_runs (
                occurrence_key, job_id, revision, scheduled_for, state, created_at, updated_at
             ) VALUES (?, ?, ?, ?, 'claimed', ?, ?)",
        )
        .bind(key.as_str())
        .bind(key.job_id().to_string())
        .bind(
            i64::try_from(key.revision().as_u64())
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        )
        .bind(timestamp_to_i64(key.scheduled_for())?)
        .bind(now_i64)
        .bind(now_i64)
        .execute(&mut *transaction)
        .await?;
        let active: Option<i64> = sqlx::query_scalar(
            "SELECT expires_at FROM scheduled_job_leases
             WHERE occurrence_key = ? AND expires_at > ?",
        )
        .bind(key.as_str())
        .bind(now_i64)
        .fetch_optional(&mut *transaction)
        .await?;
        if active.is_some() {
            transaction.commit().await?;
            return Ok(false);
        }
        sqlx::query(
            "INSERT INTO scheduled_job_leases (occurrence_key, lease_id, leased_at, expires_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(occurrence_key) DO UPDATE SET
                lease_id = excluded.lease_id,
                leased_at = excluded.leased_at,
                expires_at = excluded.expires_at",
        )
        .bind(key.as_str())
        .bind(lease_id.to_string())
        .bind(now_i64)
        .bind(expires_i64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query("UPDATE scheduled_job_runs SET updated_at = ? WHERE occurrence_key = ?")
            .bind(now_i64)
            .bind(key.as_str())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(true)
    }

    pub async fn scheduled_occurrence_run_id(
        &self,
        key: &OccurrenceKey,
    ) -> Result<Option<lumen_core::action::RunId>, RepositoryError> {
        let row: Option<String> = sqlx::query_scalar(
            "SELECT run_id FROM scheduled_job_runs
                 WHERE occurrence_key = ? AND run_id IS NOT NULL",
        )
        .bind(key.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(|value| {
            Ok(lumen_core::action::RunId::from_uuid(
                value
                    .parse()
                    .map_err(|_| RepositoryError::InvalidAutomationState)?,
            ))
        })
        .transpose()
    }

    pub async fn scheduled_occurrence_record(
        &self,
        key: &OccurrenceKey,
    ) -> Result<Option<ScheduledOccurrenceRecord>, RepositoryError> {
        let row = sqlx::query(
            "SELECT run_id, state FROM scheduled_job_runs
                 WHERE occurrence_key = ?",
        )
        .bind(key.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let run_id = match row.try_get::<Option<String>, _>("run_id")? {
                Some(value) => Some(lumen_core::action::RunId::from_uuid(
                    value
                        .parse()
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                )),
                None => None,
            };
            Ok(ScheduledOccurrenceRecord {
                run_id,
                state: row.try_get("state")?,
            })
        })
        .transpose()
    }

    pub async fn ready_scheduled_run_handoffs(
        &self,
    ) -> Result<
        Vec<(
            OccurrenceKey,
            lumen_core::action::RunId,
            ScheduledJobRevision,
        )>,
        RepositoryError,
    > {
        let rows = sqlx::query(
            "SELECT job.workspace_id, job.service_provider, job.service_subject,
                    job.owner_provider, job.owner_subject, job.job_id,
                    revision.revision, revision.schedule_kind, revision.schedule_start_at,
                    revision.interval_millis, revision.prompt, revision.data_class,
                    revision.max_model_turns, revision.max_actions, revision.enabled,
                    revision.next_due_at, revision.idempotent, revision.created_at,
                    occurrence.scheduled_for, occurrence.run_id
             FROM scheduled_job_runs occurrence
             JOIN scheduled_jobs job ON job.job_id = occurrence.job_id
             JOIN scheduled_job_revisions revision
               ON revision.job_id = occurrence.job_id
              AND revision.revision = occurrence.revision
             WHERE occurrence.state = 'claimed' AND occurrence.run_id IS NOT NULL
             ORDER BY occurrence.created_at, occurrence.occurrence_key",
        )
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                let job_id = JobId::from_uuid(
                    row.try_get::<String, _>("job_id")?
                        .parse()
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                );
                let revision = JobRevision::new(
                    u64::try_from(row.try_get::<i64, _>("revision")?)
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                )
                .map_err(|_| RepositoryError::InvalidAutomationState)?;
                let scheduled_for = TimestampMillis::new(
                    u64::try_from(row.try_get::<i64, _>("scheduled_for")?)
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                );
                let run_id = lumen_core::action::RunId::from_uuid(
                    row.try_get::<String, _>("run_id")?
                        .parse()
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                );
                let job = scheduled_job_revision_from_row(job_id, &row)?;
                Ok((
                    OccurrenceKey::new(job_id, revision, scheduled_for),
                    run_id,
                    job,
                ))
            })
            .collect()
    }

    pub async fn claim_ready_scheduled_run(
        &self,
        key: &OccurrenceKey,
        lease_id: Uuid,
        now: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<bool, RepositoryError> {
        let now_i64 = timestamp_to_i64(now)?;
        let updated = sqlx::query(
            "UPDATE scheduled_job_leases
             SET lease_id = ?, leased_at = ?, expires_at = ?
             WHERE occurrence_key = ? AND expires_at <= ?
               AND EXISTS (
                   SELECT 1 FROM scheduled_job_runs occurrence
                   WHERE occurrence.occurrence_key = scheduled_job_leases.occurrence_key
                     AND occurrence.state = 'claimed' AND occurrence.run_id IS NOT NULL
               )",
        )
        .bind(lease_id.to_string())
        .bind(now_i64)
        .bind(timestamp_to_i64(expires_at)?)
        .bind(key.as_str())
        .bind(now_i64)
        .execute(self.pool())
        .await?
        .rows_affected();
        Ok(updated == 1)
    }

    pub async fn recover_expired_running_scheduled_runs(
        &self,
        now: TimestampMillis,
    ) -> Result<Vec<lumen_core::action::RunId>, RepositoryError> {
        let now_i64 = timestamp_to_i64(now)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT occurrence.run_id, run.state
             FROM scheduled_job_runs occurrence
             JOIN scheduled_job_leases lease
               ON lease.occurrence_key = occurrence.occurrence_key
             JOIN agent_runs run ON run.id = occurrence.run_id
             WHERE occurrence.state = 'running' AND lease.expires_at <= ?
               AND occurrence.run_id IS NOT NULL",
        )
        .bind(now_i64)
        .fetch_all(&mut *transaction)
        .await?;
        for (run_id, run_state) in &rows {
            let (occurrence_state, fail_run) = match run_state.as_str() {
                "completed" => ("succeeded", false),
                "failed" => ("failed", false),
                "cancelled" => ("cancelled", false),
                "created" | "running" | "awaiting_approval" => ("unknown", true),
                _ => return Err(RepositoryError::InvalidAutomationState),
            };
            let occurrence = sqlx::query(
                "UPDATE scheduled_job_runs SET state = ?, updated_at = ?
                 WHERE run_id = ? AND state = 'running'",
            )
            .bind(occurrence_state)
            .bind(now_i64)
            .bind(run_id)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
            if occurrence != 1 {
                return Err(RepositoryError::ExecutionStateConflict);
            }
            if fail_run {
                let run = sqlx::query(
                    "UPDATE agent_runs SET state = 'failed', completed_at = ?
                     WHERE id = ? AND state IN ('created', 'running', 'awaiting_approval')",
                )
                .bind(now_i64)
                .bind(run_id)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
                if run != 1 {
                    return Err(RepositoryError::ExecutionStateConflict);
                }
            }
        }
        transaction.commit().await?;
        rows.into_iter()
            .map(|(run_id, _)| {
                Ok(lumen_core::action::RunId::from_uuid(
                    run_id
                        .parse()
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                ))
            })
            .collect()
    }

    pub async fn persist_scheduled_run_handoff(
        &self,
        job: &ScheduledJobRevision,
        key: &OccurrenceKey,
        lease_id: Uuid,
        run_id: lumen_core::action::RunId,
        next_due_at: Option<TimestampMillis>,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        if key.job_id() != job.job_id()
            || key.revision() != job.revision()
            || Some(key.scheduled_for()) != job.next_due_at()
            || next_due_at
                != job
                    .schedule()
                    .next_after(key.scheduled_for(), job.enabled())
        {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let now_i64 = timestamp_to_i64(now)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let eligible: i64 = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1
                FROM scheduled_job_runs occurrence
                JOIN scheduled_job_leases lease
                  ON lease.occurrence_key = occurrence.occurrence_key
                JOIN scheduled_jobs job ON job.job_id = occurrence.job_id
                JOIN scheduled_job_revisions revision
                  ON revision.job_id = occurrence.job_id
                 AND revision.revision = occurrence.revision
                JOIN service_identities service
                  ON service.workspace_id = job.workspace_id
                 AND service.provider = job.service_provider
                 AND service.subject = job.service_subject
                WHERE occurrence.occurrence_key = ?
                  AND (
                      (occurrence.state = 'claimed' AND occurrence.run_id IS NULL)
                      OR (occurrence.state = 'unknown' AND revision.idempotent = 1)
                  )
                  AND lease.lease_id = ?
                  AND lease.expires_at > ?
                  AND revision.revision = (
                      SELECT MAX(latest.revision)
                      FROM scheduled_job_revisions latest
                      WHERE latest.job_id = occurrence.job_id
                  )
                  AND revision.enabled = 1
                  AND revision.next_due_at = occurrence.scheduled_for
                  AND job.workspace_id = ?
                  AND job.service_provider = ?
                  AND job.service_subject = ?
                  AND service.enabled = 1
             )",
        )
        .bind(key.as_str())
        .bind(lease_id.to_string())
        .bind(now_i64)
        .bind(job.workspace_id().to_string())
        .bind(job.service().provider())
        .bind(job.service().subject())
        .fetch_one(&mut *transaction)
        .await?;
        if eligible == 0 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        sqlx::query(
            "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
        )
        .bind(job.service().provider())
        .bind(job.service().subject())
        .bind(now_i64)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO agent_runs (
                id, workspace_id, actor_provider, actor_subject, state, created_at
             ) VALUES (?, ?, ?, ?, 'created', ?)",
        )
        .bind(run_id.to_string())
        .bind(job.workspace_id().to_string())
        .bind(job.service().provider())
        .bind(job.service().subject())
        .bind(now_i64)
        .execute(&mut *transaction)
        .await?;
        let linked = sqlx::query(
            "UPDATE scheduled_job_runs
             SET run_id = ?, state = 'claimed', updated_at = ?
             WHERE occurrence_key = ?
               AND ((state = 'claimed' AND run_id IS NULL) OR state = 'unknown')",
        )
        .bind(run_id.to_string())
        .bind(now_i64)
        .bind(key.as_str())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let advanced = sqlx::query(
            "UPDATE scheduled_job_revisions
             SET next_due_at = ?
             WHERE job_id = ? AND revision = ? AND next_due_at = ?",
        )
        .bind(next_due_at.map(timestamp_to_i64).transpose()?)
        .bind(job.job_id().to_string())
        .bind(
            i64::try_from(job.revision().as_u64())
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        )
        .bind(timestamp_to_i64(key.scheduled_for())?)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if linked != 1 || advanced != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn start_scheduled_run(
        &self,
        key: &OccurrenceKey,
        lease_id: Uuid,
        run_id: lumen_core::action::RunId,
        now: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let now_i64 = timestamp_to_i64(now)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let occurrence = sqlx::query(
            "UPDATE scheduled_job_runs
             SET state = 'running', updated_at = ?
             WHERE occurrence_key = ? AND run_id = ? AND state = 'claimed'
               AND EXISTS (
                   SELECT 1 FROM scheduled_job_leases lease
                   WHERE lease.occurrence_key = scheduled_job_runs.occurrence_key
                     AND lease.lease_id = ? AND lease.expires_at > ?
               )",
        )
        .bind(now_i64)
        .bind(key.as_str())
        .bind(run_id.to_string())
        .bind(lease_id.to_string())
        .bind(now_i64)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let run = sqlx::query(
            "UPDATE agent_runs SET state = 'running' WHERE id = ? AND state = 'created'",
        )
        .bind(run_id.to_string())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        let lease = sqlx::query(
            "UPDATE scheduled_job_leases SET expires_at = ?
             WHERE occurrence_key = ? AND lease_id = ? AND expires_at > ?",
        )
        .bind(timestamp_to_i64(expires_at)?)
        .bind(key.as_str())
        .bind(lease_id.to_string())
        .bind(now_i64)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if occurrence != 1 || run != 1 || lease != 1 {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn scheduled_run_lease_is_current(
        &self,
        key: &OccurrenceKey,
        lease_id: Uuid,
        run_id: lumen_core::action::RunId,
    ) -> Result<bool, RepositoryError> {
        let current: i64 = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1
                FROM scheduled_job_runs occurrence
                JOIN scheduled_job_leases lease
                  ON lease.occurrence_key = occurrence.occurrence_key
                WHERE occurrence.occurrence_key = ?
                  AND occurrence.run_id = ?
                  AND occurrence.state = 'running'
                  AND lease.lease_id = ?
             )",
        )
        .bind(key.as_str())
        .bind(run_id.to_string())
        .bind(lease_id.to_string())
        .fetch_one(self.pool())
        .await?;
        Ok(current == 1)
    }

    pub async fn complete_scheduled_occurrence_for_run(
        &self,
        run_id: lumen_core::action::RunId,
        state: &str,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        if !matches!(state, "succeeded" | "failed" | "cancelled" | "unknown") {
            return Err(RepositoryError::ExecutionStateConflict);
        }
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let updated = sqlx::query(
            "UPDATE scheduled_job_runs
             SET state = ?, updated_at = ?
             WHERE run_id = ? AND state = 'running'",
        )
        .bind(state)
        .bind(timestamp_to_i64(now)?)
        .bind(run_id.to_string())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if updated == 0 {
            let current: Option<String> =
                sqlx::query_scalar("SELECT state FROM scheduled_job_runs WHERE run_id = ?")
                    .bind(run_id.to_string())
                    .fetch_optional(&mut *transaction)
                    .await?;
            if current.as_deref() != Some(state) {
                return Err(RepositoryError::ExecutionStateConflict);
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn advance_scheduled_job_next_due(
        &self,
        job_id: JobId,
        revision: JobRevision,
        next_due_at: Option<TimestampMillis>,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "UPDATE scheduled_job_revisions
             SET next_due_at = ?
             WHERE job_id = ? AND revision = ?",
        )
        .bind(next_due_at.map(timestamp_to_i64).transpose()?)
        .bind(job_id.to_string())
        .bind(
            i64::try_from(revision.as_u64())
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        )
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn insert_skill_version(
        &self,
        skill: &SkillVersionRecord,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO agent_skills (skill_id, workspace_id, name, description, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(skill.skill_id.to_string())
        .bind(skill.workspace_id.to_string())
        .bind(&skill.name)
        .bind(&skill.description)
        .bind(timestamp_to_i64(skill.created_at)?)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO skill_versions (
                skill_id, version, source_format, source_digest, reviewed,
                created_provider, created_subject, reviewed_provider, reviewed_subject,
                created_at, reviewed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(skill.skill_id.to_string())
        .bind(skill.version.as_str())
        .bind(&skill.source_format)
        .bind(&skill.source_digest)
        .bind(if skill.reviewed { 1_i64 } else { 0_i64 })
        .bind(skill.created_by.provider())
        .bind(skill.created_by.subject())
        .bind(skill.reviewed_by.as_ref().map(PrincipalId::provider))
        .bind(skill.reviewed_by.as_ref().map(PrincipalId::subject))
        .bind(timestamp_to_i64(skill.created_at)?)
        .bind(skill.reviewed_at.map(timestamp_to_i64).transpose()?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn set_skill_workspace_state(
        &self,
        workspace_id: WorkspaceId,
        skill_id: SkillId,
        version: &SkillVersion,
        enabled: bool,
        updated_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO skill_workspace_state (workspace_id, skill_id, version, enabled, updated_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(workspace_id, skill_id) DO UPDATE SET
                version = excluded.version,
                enabled = excluded.enabled,
                updated_at = excluded.updated_at",
        )
        .bind(workspace_id.to_string())
        .bind(skill_id.to_string())
        .bind(version.as_str())
        .bind(if enabled { 1_i64 } else { 0_i64 })
        .bind(timestamp_to_i64(updated_at)?)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn enabled_skill_versions(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<SkillVersionRecord>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT skill.skill_id, skill.name, skill.description, version.version,
                    version.source_format, version.source_digest, version.reviewed,
                    version.created_provider, version.created_subject,
                    version.reviewed_provider, version.reviewed_subject,
                    version.created_at, version.reviewed_at
             FROM skill_workspace_state state
             JOIN agent_skills skill ON skill.skill_id = state.skill_id
             JOIN skill_versions version
               ON version.skill_id = state.skill_id AND version.version = state.version
             WHERE state.workspace_id = ? AND state.enabled = 1
             ORDER BY skill.name, version.version",
        )
        .bind(workspace_id.to_string())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| skill_version_from_row(workspace_id, &row))
            .collect()
    }

    pub async fn skill_version(
        &self,
        workspace_id: WorkspaceId,
        skill_id: SkillId,
        version: &SkillVersion,
    ) -> Result<Option<SkillVersionRecord>, RepositoryError> {
        let row = sqlx::query(
            "SELECT skill.skill_id, skill.name, skill.description, version.version,
                    version.source_format, version.source_digest, version.reviewed,
                    version.created_provider, version.created_subject,
                    version.reviewed_provider, version.reviewed_subject,
                    version.created_at, version.reviewed_at
             FROM agent_skills skill
             JOIN skill_versions version ON version.skill_id = skill.skill_id
             WHERE skill.workspace_id = ? AND skill.skill_id = ? AND version.version = ?",
        )
        .bind(workspace_id.to_string())
        .bind(skill_id.to_string())
        .bind(version.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.as_ref()
            .map(|row| skill_version_from_row(workspace_id, row))
            .transpose()
    }

    pub async fn insert_workflow_capture_draft(
        &self,
        draft: &WorkflowCaptureDraft,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO workflow_capture_drafts (
                draft_id, workspace_id, title, body, created_provider, created_subject, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(draft.id.to_string())
        .bind(draft.workspace_id.to_string())
        .bind(&draft.title)
        .bind(&draft.body)
        .bind(draft.created_by.provider())
        .bind(draft.created_by.subject())
        .bind(timestamp_to_i64(draft.created_at)?)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn get_workflow_capture_draft(
        &self,
        id: Uuid,
    ) -> Result<Option<WorkflowCaptureDraft>, RepositoryError> {
        let row = sqlx::query(
            "SELECT workspace_id, title, body, created_provider, created_subject, created_at
             FROM workflow_capture_drafts WHERE draft_id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            WorkflowCaptureDraft::new(
                id,
                WorkspaceId::from_uuid(
                    row.try_get::<String, _>("workspace_id")?
                        .parse()
                        .map_err(|_| RepositoryError::InvalidAutomationState)?,
                ),
                row.try_get::<String, _>("title")?,
                row.try_get::<String, _>("body")?,
                PrincipalId::new(
                    row.try_get::<String, _>("created_provider")?,
                    row.try_get::<String, _>("created_subject")?,
                )
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
                timestamp_from_row(&row, "created_at")?,
            )
        })
        .transpose()
    }
}

struct ScopeParts {
    kind: &'static str,
    workspace_id: Option<String>,
    path: Option<String>,
    resource_type: Option<String>,
    resource_value: Option<String>,
}

fn grant_scope_parts(scope: &ResourceScope) -> Result<ScopeParts, RepositoryError> {
    Ok(match scope {
        ResourceScope::Workspace { workspace_id } => ScopeParts {
            kind: "workspace",
            workspace_id: Some(workspace_id.to_string()),
            path: None,
            resource_type: None,
            resource_value: None,
        },
        ResourceScope::Path { workspace_id, path } => ScopeParts {
            kind: "path",
            workspace_id: Some(workspace_id.to_string()),
            path: Some(path.as_str().to_owned()),
            resource_type: None,
            resource_value: None,
        },
        ResourceScope::Exact {
            resource_type,
            value,
        } => ScopeParts {
            kind: "exact",
            workspace_id: None,
            path: None,
            resource_type: Some(resource_type.clone()),
            resource_value: Some(value.clone()),
        },
    })
}

fn scope_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ResourceScope, RepositoryError> {
    match row.try_get::<String, _>("scope_kind")?.as_str() {
        "workspace" => Ok(ResourceScope::workspace(WorkspaceId::from_uuid(
            row.try_get::<String, _>("scope_workspace_id")?
                .parse()
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        ))),
        "path" => Ok(ResourceScope::path(
            WorkspaceId::from_uuid(
                row.try_get::<String, _>("scope_workspace_id")?
                    .parse()
                    .map_err(|_| RepositoryError::InvalidAutomationState)?,
            ),
            WorkspacePath::parse(row.try_get::<String, _>("scope_path")?)
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        )),
        "exact" => ResourceScope::exact(
            row.try_get::<String, _>("scope_resource_type")?,
            row.try_get::<String, _>("scope_resource_value")?,
        )
        .map_err(|_| RepositoryError::InvalidAutomationState),
        _ => Err(RepositoryError::InvalidAutomationState),
    }
}

fn schedule_parts(schedule: ScheduleSpec) -> (&'static str, TimestampMillis, Option<u64>) {
    match schedule {
        ScheduleSpec::Once { run_at } => ("once", run_at, None),
        ScheduleSpec::Interval {
            start_at,
            interval_millis,
        } => ("interval", start_at, Some(interval_millis)),
    }
}

fn schedule_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<ScheduleSpec, RepositoryError> {
    let start = timestamp_from_row(row, "schedule_start_at")?;
    match row.try_get::<String, _>("schedule_kind")?.as_str() {
        "once" => Ok(ScheduleSpec::once(start)),
        "interval" => {
            let interval = u64::try_from(row.try_get::<i64, _>("interval_millis")?)
                .map_err(|_| RepositoryError::InvalidAutomationState)?;
            ScheduleSpec::interval(start, Duration::from_millis(interval))
                .map_err(|_| RepositoryError::InvalidAutomationState)
        }
        _ => Err(RepositoryError::InvalidAutomationState),
    }
}

fn scheduled_job_revision_from_row(
    job_id: JobId,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<ScheduledJobRevision, RepositoryError> {
    ScheduledJobRevision::new(
        job_id,
        JobRevision::new(
            u64::try_from(row.try_get::<i64, _>("revision")?)
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        )
        .map_err(|_| RepositoryError::InvalidAutomationState)?,
        WorkspaceId::from_uuid(
            row.try_get::<String, _>("workspace_id")?
                .parse()
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        ),
        PrincipalId::new(
            row.try_get::<String, _>("service_provider")?,
            row.try_get::<String, _>("service_subject")?,
        )
        .map_err(|_| RepositoryError::InvalidAutomationState)?,
        PrincipalId::new(
            row.try_get::<String, _>("owner_provider")?,
            row.try_get::<String, _>("owner_subject")?,
        )
        .map_err(|_| RepositoryError::InvalidAutomationState)?,
        schedule_from_row(row)?,
        row.try_get::<String, _>("prompt")?,
        parse_data_class(&row.try_get::<String, _>("data_class")?)?,
        u32::try_from(row.try_get::<i64, _>("max_model_turns")?)
            .map_err(|_| RepositoryError::InvalidAutomationState)?,
        u32::try_from(row.try_get::<i64, _>("max_actions")?)
            .map_err(|_| RepositoryError::InvalidAutomationState)?,
        row.try_get::<i64, _>("enabled")? == 1,
        row.try_get::<Option<i64>, _>("next_due_at")?
            .map(|value| {
                u64::try_from(value)
                    .map(TimestampMillis::new)
                    .map_err(|_| RepositoryError::InvalidAutomationState)
            })
            .transpose()?,
        row.try_get::<i64, _>("idempotent")? == 1,
        timestamp_from_row(row, "created_at")?,
    )
}

fn skill_version_from_row(
    workspace_id: WorkspaceId,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SkillVersionRecord, RepositoryError> {
    SkillVersionRecord::new(
        SkillId::from_uuid(
            row.try_get::<String, _>("skill_id")?
                .parse()
                .map_err(|_| RepositoryError::InvalidAutomationState)?,
        ),
        SkillVersion::parse(row.try_get::<String, _>("version")?)
            .map_err(|_| RepositoryError::InvalidAutomationState)?,
        workspace_id,
        row.try_get::<String, _>("name")?,
        row.try_get::<String, _>("description")?,
        row.try_get::<String, _>("source_format")?,
        row.try_get::<String, _>("source_digest")?,
        row.try_get::<i64, _>("reviewed")? == 1,
        PrincipalId::new(
            row.try_get::<String, _>("created_provider")?,
            row.try_get::<String, _>("created_subject")?,
        )
        .map_err(|_| RepositoryError::InvalidAutomationState)?,
        match (
            row.try_get::<Option<String>, _>("reviewed_provider")?,
            row.try_get::<Option<String>, _>("reviewed_subject")?,
        ) {
            (Some(provider), Some(subject)) => Some(
                PrincipalId::new(provider, subject)
                    .map_err(|_| RepositoryError::InvalidAutomationState)?,
            ),
            _ => None,
        },
        timestamp_from_row(row, "created_at")?,
        row.try_get::<Option<i64>, _>("reviewed_at")?
            .map(|value| {
                u64::try_from(value)
                    .map(TimestampMillis::new)
                    .map_err(|_| RepositoryError::InvalidAutomationState)
            })
            .transpose()?,
    )
}

fn timestamp_from_row(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<TimestampMillis, RepositoryError> {
    Ok(TimestampMillis::new(
        u64::try_from(row.try_get::<i64, _>(column)?)
            .map_err(|_| RepositoryError::InvalidAutomationState)?,
    ))
}

fn parse_data_class(value: &str) -> Result<DataClass, RepositoryError> {
    match value {
        "public" => Ok(DataClass::Public),
        "workspace" => Ok(DataClass::Workspace),
        "sensitive" => Ok(DataClass::Sensitive),
        _ => Err(RepositoryError::InvalidAutomationState),
    }
}

fn invalid_text(value: &str, max_len: usize) -> bool {
    value.is_empty()
        || value.len() > max_len
        || value.trim() != value
        || value.chars().any(char::is_control)
}

fn invalid_body_text(value: &str, max_len: usize) -> bool {
    value.is_empty()
        || value.len() > max_len
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\t'))
}

fn valid_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}
