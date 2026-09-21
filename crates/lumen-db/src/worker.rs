use std::collections::BTreeSet;

use lumen_core::{
    action::RunId,
    approval::TimestampMillis,
    context::{ContextDigest, ProjectionId, parse_data_class},
    egress::ProviderId,
    identity::{PrincipalId, WorkspaceId},
    orchestration::{OrchestrationId, TaskNodeId},
    provider::ModelProfileId,
    worker::{
        WorkerAssignment, WorkerAttemptId, WorkerAttemptState, WorkerCapabilityGrant,
        WorkerRunBudget,
    },
};
use sqlx::{Row, Sqlite, sqlite::SqliteRow};
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Clone, Debug)]
pub struct WorkerAttemptRecord {
    attempt_id: WorkerAttemptId,
    assignment: WorkerAssignment,
    task_attempt: u32,
    run_id: RunId,
    state: WorkerAttemptState,
    lease_owner: Uuid,
    lease_expires_at: TimestampMillis,
    created_at: TimestampMillis,
    started_at: Option<TimestampMillis>,
    completed_at: Option<TimestampMillis>,
    diagnostic: Option<String>,
}
impl WorkerAttemptRecord {
    pub const fn attempt_id(&self) -> WorkerAttemptId {
        self.attempt_id
    }
    pub fn assignment(&self) -> &WorkerAssignment {
        &self.assignment
    }
    pub const fn task_attempt(&self) -> u32 {
        self.task_attempt
    }
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
    pub const fn state(&self) -> WorkerAttemptState {
        self.state
    }
    pub const fn lease_owner(&self) -> Uuid {
        self.lease_owner
    }
    pub const fn lease_expires_at(&self) -> TimestampMillis {
        self.lease_expires_at
    }
    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
    pub const fn started_at(&self) -> Option<TimestampMillis> {
        self.started_at
    }
    pub const fn completed_at(&self) -> Option<TimestampMillis> {
        self.completed_at
    }
    pub fn diagnostic(&self) -> Option<&str> {
        self.diagnostic.as_deref()
    }
}

impl Database {
    pub async fn reserve_worker_attempt(
        &self,
        assignment: &WorkerAssignment,
        attempt_id: WorkerAttemptId,
        run_id: RunId,
        owner: Uuid,
        lease_expires_at: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<WorkerAttemptRecord, RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        if cancelled(&mut tx, assignment.orchestration_id()).await? {
            return Err(RepositoryError::InvalidWorkerState);
        }
        validate_assignment(&mut tx, assignment).await?;
        let row = sqlx::query("SELECT state_revision,state,attempt_count FROM orchestration_task_state_revisions WHERE orchestration_id=? AND graph_revision=? AND task_node_id=? ORDER BY state_revision DESC LIMIT 1")
            .bind(assignment.orchestration_id().to_string()).bind(pos(assignment.graph_revision())?).bind(assignment.task_node_id().to_string()).fetch_optional(&mut *tx).await?.ok_or(RepositoryError::InvalidWorkerState)?;
        if row.try_get::<String, _>("state")? != "ready" {
            return Err(RepositoryError::InvalidWorkerState);
        }
        let revision = pos(u64::try_from(row.try_get::<i64, _>("state_revision")?)
            .map_err(|_| RepositoryError::InvalidWorkerState)?)?;
        let prior_attempts = u32::try_from(row.try_get::<i64, _>("attempt_count")?)
            .map_err(|_| RepositoryError::InvalidWorkerState)?;
        let max_attempts: i64 = sqlx::query_scalar("SELECT max_attempts FROM orchestration_task_nodes WHERE orchestration_id=? AND graph_revision=? AND task_node_id=?").bind(assignment.orchestration_id().to_string()).bind(pos(assignment.graph_revision())?).bind(assignment.task_node_id().to_string()).fetch_one(&mut *tx).await?;
        let task_attempt = prior_attempts
            .checked_add(1)
            .filter(|v| i64::from(*v) <= max_attempts)
            .ok_or(RepositoryError::InvalidWorkerState)?;
        let stamp = timestamp_to_i64(now)?;
        sqlx::query("INSERT INTO agent_runs(id,workspace_id,actor_provider,actor_subject,state,created_at) VALUES(?,?,?,?, 'created',?)")
            .bind(run_id.to_string()).bind(assignment.workspace_id().to_string()).bind(assignment.actor().provider()).bind(assignment.actor().subject()).bind(stamp).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO orchestration_task_state_revisions(orchestration_id,graph_revision,task_node_id,state_revision,state,attempt_count,created_at) VALUES(?,?,?,?, 'running',?,?)")
            .bind(assignment.orchestration_id().to_string()).bind(pos(assignment.graph_revision())?).bind(assignment.task_node_id().to_string()).bind(revision + 1).bind(i64::from(task_attempt)).bind(stamp).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO worker_attempts(attempt_id,orchestration_id,graph_revision,task_node_id,task_attempt,workspace_id,actor_provider,actor_subject,provider_id,provider_revision,profile_id,profile_revision,policy_revision,projection_id,projection_digest,data_class,prompt,capability_grants_json,allowed_tools_json,max_model_turns,max_actions,max_wall_time_millis,max_captured_result_bytes,run_id,state,lease_owner,lease_expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, 'reserved',?,?,?)")
            .bind(attempt_id.to_string()).bind(assignment.orchestration_id().to_string()).bind(pos(assignment.graph_revision())?).bind(assignment.task_node_id().to_string()).bind(i64::from(task_attempt)).bind(assignment.workspace_id().to_string()).bind(assignment.actor().provider()).bind(assignment.actor().subject()).bind(assignment.provider_id().as_str()).bind(pos(assignment.provider_revision())?).bind(assignment.model_profile_id().as_str()).bind(pos(assignment.model_profile_revision())?).bind(pos(assignment.policy_revision())?).bind(assignment.projection_id().to_string()).bind(assignment.projection_digest().as_str()).bind(data_class(assignment.data_class())).bind(assignment.prompt()).bind(serde_json::to_string(assignment.grants())?).bind(serde_json::to_string(assignment.allowed_tools())?).bind(i64::from(assignment.budget().max_model_turns())).bind(i64::from(assignment.budget().max_actions())).bind(pos(assignment.budget().max_wall_time_millis())?).bind(i64::try_from(assignment.budget().max_captured_result_bytes()).map_err(|_| RepositoryError::InvalidWorkerState)?).bind(run_id.to_string()).bind(owner.to_string()).bind(timestamp_to_i64(lease_expires_at)?).bind(stamp).execute(&mut *tx).await?;
        tx.commit().await?;
        self.worker_attempt(attempt_id)
            .await?
            .ok_or(RepositoryError::InvalidWorkerState)
    }
    pub async fn worker_attempt(
        &self,
        id: WorkerAttemptId,
    ) -> Result<Option<WorkerAttemptRecord>, RepositoryError> {
        sqlx::query("SELECT * FROM worker_attempts WHERE attempt_id=?")
            .bind(id.to_string())
            .fetch_optional(self.pool())
            .await?
            .map(row)
            .transpose()
    }
    pub async fn start_worker_attempt(
        &self,
        id: WorkerAttemptId,
        owner: Uuid,
        expiry: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        self.move_attempt(
            id,
            owner,
            WorkerAttemptState::Reserved,
            WorkerAttemptState::Running,
            expiry,
            now,
        )
        .await
    }
    pub async fn pause_worker_attempt_for_approval(
        &self,
        id: WorkerAttemptId,
        owner: Uuid,
        expiry: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        self.move_attempt(
            id,
            owner,
            WorkerAttemptState::Running,
            WorkerAttemptState::AwaitingApproval,
            expiry,
            now,
        )
        .await
    }
    pub async fn resume_worker_attempt_from_approval(
        &self,
        id: WorkerAttemptId,
        owner: Uuid,
        expiry: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        self.move_attempt(
            id,
            owner,
            WorkerAttemptState::AwaitingApproval,
            WorkerAttemptState::Running,
            expiry,
            now,
        )
        .await
    }
    async fn move_attempt(
        &self,
        id: WorkerAttemptId,
        owner: Uuid,
        from: WorkerAttemptState,
        to: WorkerAttemptState,
        expiry: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let changed = sqlx::query("UPDATE worker_attempts SET state=?, lease_expires_at=?, started_at=COALESCE(started_at,?) WHERE attempt_id=? AND lease_owner=? AND state=?")
            .bind(to.as_str()).bind(timestamp_to_i64(expiry)?).bind(timestamp_to_i64(now)?).bind(id.to_string()).bind(owner.to_string()).bind(from.as_str()).execute(self.pool()).await?.rows_affected();
        if changed != 1 {
            return Err(RepositoryError::InvalidWorkerState);
        }
        Ok(())
    }
    pub async fn renew_worker_attempt_lease(
        &self,
        id: WorkerAttemptId,
        owner: Uuid,
        expiry: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<bool, RepositoryError> {
        Ok(sqlx::query("UPDATE worker_attempts SET lease_expires_at=? WHERE attempt_id=? AND lease_owner=? AND state IN('reserved','running','awaiting_approval') AND lease_expires_at>=?").bind(timestamp_to_i64(expiry)?).bind(id.to_string()).bind(owner.to_string()).bind(timestamp_to_i64(now)?).execute(self.pool()).await?.rows_affected()==1)
    }
    pub async fn terminalize_worker_attempt(
        &self,
        id: WorkerAttemptId,
        owner: Option<Uuid>,
        state: WorkerAttemptState,
        diagnostic: Option<&str>,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        if !state.is_terminal() || diagnostic.is_some_and(|v| v.len() > 1024) {
            return Err(RepositoryError::InvalidWorkerState);
        }
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let current = sqlx::query("SELECT orchestration_id,graph_revision,task_node_id,lease_owner,state FROM worker_attempts WHERE attempt_id=?").bind(id.to_string()).fetch_optional(&mut *tx).await?.ok_or(RepositoryError::InvalidWorkerState)?;
        if current.try_get::<String, _>("state")?.as_str() != "reserved"
            && current.try_get::<String, _>("state")?.as_str() != "running"
            && current.try_get::<String, _>("state")?.as_str() != "awaiting_approval"
        {
            return Err(RepositoryError::InvalidWorkerState);
        }
        if let Some(owner) = owner
            && current.try_get::<String, _>("lease_owner")? != owner.to_string()
        {
            return Err(RepositoryError::InvalidWorkerState);
        }
        let changed = sqlx::query(
            "UPDATE worker_attempts SET state=?,completed_at=?,diagnostic=? WHERE attempt_id=?",
        )
        .bind(state.as_str())
        .bind(timestamp_to_i64(now)?)
        .bind(diagnostic)
        .bind(id.to_string())
        .execute(&mut *tx)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(RepositoryError::InvalidWorkerState);
        }
        append_task_terminal(&mut tx, &current, state, now).await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn request_orchestration_cancellation(
        &self,
        id: OrchestrationId,
        actor: &PrincipalId,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO orchestration_cancellations(orchestration_id,requested_by_provider,requested_by_subject,requested_at) VALUES(?,?,?,?) ON CONFLICT(orchestration_id) DO NOTHING").bind(id.to_string()).bind(actor.provider()).bind(actor.subject()).bind(timestamp_to_i64(now)?).execute(self.pool()).await?;
        Ok(())
    }
    pub async fn orchestration_cancelled(
        &self,
        id: OrchestrationId,
    ) -> Result<bool, RepositoryError> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM orchestration_cancellations WHERE orchestration_id=?",
        )
        .bind(id.to_string())
        .fetch_optional(self.pool())
        .await?
        .is_some())
    }
    pub async fn recover_expired_worker_attempts(
        &self,
        now: TimestampMillis,
    ) -> Result<(Vec<WorkerAttemptId>, Vec<OrchestrationId>), RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let stamp = timestamp_to_i64(now)?;
        let reserved = sqlx::query_scalar::<_, String>(
            "SELECT attempt_id FROM worker_attempts WHERE state='reserved' AND lease_expires_at<?",
        )
        .bind(stamp)
        .fetch_all(&mut *tx)
        .await?
        .into_iter()
        .map(parse_attempt)
        .collect::<Result<Vec<_>, _>>()?;
        let rows = sqlx::query("SELECT attempt_id,orchestration_id,graph_revision,task_node_id FROM worker_attempts WHERE state IN('running','awaiting_approval') AND lease_expires_at<?").bind(stamp).fetch_all(&mut *tx).await?;
        let mut touched = BTreeSet::new();
        for item in rows {
            let id = parse_attempt(item.try_get::<String, _>("attempt_id")?)?;
            let oid = parse_orchestration(item.try_get::<String, _>("orchestration_id")?)?;
            sqlx::query("UPDATE worker_attempts SET state='unknown',completed_at=?,diagnostic='worker lease expired after dispatch' WHERE attempt_id=?").bind(stamp).bind(id.to_string()).execute(&mut *tx).await?;
            append_task_terminal(&mut tx, &item, WorkerAttemptState::Unknown, now).await?;
            touched.insert(oid);
        }
        tx.commit().await?;
        Ok((reserved, touched.into_iter().collect()))
    }
    pub async fn claim_reserved_worker_attempt(
        &self,
        id: WorkerAttemptId,
        owner: Uuid,
        expiry: TimestampMillis,
        now: TimestampMillis,
    ) -> Result<bool, RepositoryError> {
        Ok(sqlx::query("UPDATE worker_attempts SET lease_owner=?,lease_expires_at=? WHERE attempt_id=? AND state='reserved' AND lease_expires_at<?").bind(owner.to_string()).bind(timestamp_to_i64(expiry)?).bind(id.to_string()).bind(timestamp_to_i64(now)?).execute(self.pool()).await?.rows_affected()==1)
    }
}

async fn validate_assignment(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    a: &WorkerAssignment,
) -> Result<(), RepositoryError> {
    let revision: Option<i64> = sqlx::query_scalar("SELECT revision FROM orchestration_graph_revisions WHERE orchestration_id=? ORDER BY revision DESC LIMIT 1").bind(a.orchestration_id().to_string()).fetch_optional(&mut **tx).await?;
    if revision.and_then(|v| u64::try_from(v).ok()) != Some(a.graph_revision()) {
        return Err(RepositoryError::InvalidWorkerState);
    }
    let ok: Option<i64> = sqlx::query_scalar("SELECT 1 FROM task_projections WHERE projection_id=? AND workspace_id=? AND profile_id=? AND profile_revision=? AND policy_revision=? AND payload_digest=?").bind(a.projection_id().to_string()).bind(a.workspace_id().to_string()).bind(a.model_profile_id().as_str()).bind(pos(a.model_profile_revision())?).bind(pos(a.policy_revision())?).bind(a.projection_digest().as_str()).fetch_optional(&mut **tx).await?;
    if ok.is_none() {
        return Err(RepositoryError::InvalidWorkerState);
    }
    Ok(())
}
async fn cancelled(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    id: OrchestrationId,
) -> Result<bool, RepositoryError> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM orchestration_cancellations WHERE orchestration_id=?",
    )
    .bind(id.to_string())
    .fetch_optional(&mut **tx)
    .await?
    .is_some())
}
async fn append_task_terminal(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    worker: &SqliteRow,
    state: WorkerAttemptState,
    now: TimestampMillis,
) -> Result<(), RepositoryError> {
    let oid = worker.try_get::<String, _>("orchestration_id")?;
    let graph = worker.try_get::<i64, _>("graph_revision")?;
    let node = worker.try_get::<String, _>("task_node_id")?;
    let current=sqlx::query("SELECT state_revision,attempt_count FROM orchestration_task_state_revisions WHERE orchestration_id=? AND graph_revision=? AND task_node_id=? ORDER BY state_revision DESC LIMIT 1").bind(&oid).bind(graph).bind(&node).fetch_one(&mut **tx).await?;
    let next = match state {
        WorkerAttemptState::Completed => "completed",
        WorkerAttemptState::Failed => "failed",
        WorkerAttemptState::Cancelled => "cancelled",
        WorkerAttemptState::Unknown => "unknown",
        _ => return Err(RepositoryError::InvalidWorkerState),
    };
    sqlx::query("INSERT INTO orchestration_task_state_revisions(orchestration_id,graph_revision,task_node_id,state_revision,state,attempt_count,created_at) VALUES(?,?,?,?,?,?,?)").bind(oid).bind(graph).bind(node).bind(current.try_get::<i64,_>("state_revision")?+1).bind(next).bind(current.try_get::<i64,_>("attempt_count")?).bind(timestamp_to_i64(now)?).execute(&mut **tx).await?;
    Ok(())
}
fn row(value: SqliteRow) -> Result<WorkerAttemptRecord, RepositoryError> {
    let grants = serde_json::from_str::<BTreeSet<WorkerCapabilityGrant>>(
        &value.try_get::<String, _>("capability_grants_json")?,
    )?;
    let tools = serde_json::from_str::<BTreeSet<String>>(
        &value.try_get::<String, _>("allowed_tools_json")?,
    )?;
    let assignment = WorkerAssignment::from_stored_parts(
        parse_orchestration(value.try_get("orchestration_id")?)?,
        num(&value, "graph_revision")?,
        parse_node(value.try_get("task_node_id")?)?,
        parse_workspace(value.try_get("workspace_id")?)?,
        PrincipalId::new(
            value.try_get::<String, _>("actor_provider")?,
            value.try_get::<String, _>("actor_subject")?,
        )
        .map_err(|_| RepositoryError::InvalidWorkerState)?,
        ProviderId::parse(value.try_get::<String, _>("provider_id")?)
            .map_err(|_| RepositoryError::InvalidWorkerState)?,
        num(&value, "provider_revision")?,
        ModelProfileId::parse(value.try_get::<String, _>("profile_id")?)
            .map_err(|_| RepositoryError::InvalidWorkerState)?,
        num(&value, "profile_revision")?,
        num(&value, "policy_revision")?,
        ProjectionId::from_uuid(
            Uuid::parse_str(&value.try_get::<String, _>("projection_id")?)
                .map_err(|_| RepositoryError::InvalidWorkerState)?,
        ),
        ContextDigest::parse(value.try_get::<String, _>("projection_digest")?)
            .map_err(|_| RepositoryError::InvalidWorkerState)?,
        parse_data_class(&value.try_get::<String, _>("data_class")?)
            .ok_or(RepositoryError::InvalidWorkerState)?,
        value.try_get("prompt")?,
        grants,
        tools,
        WorkerRunBudget::new(
            num(&value, "max_model_turns")?,
            num(&value, "max_actions")?,
            num(&value, "max_wall_time_millis")?,
            usize::try_from(value.try_get::<i64, _>("max_captured_result_bytes")?)
                .map_err(|_| RepositoryError::InvalidWorkerState)?,
        )
        .map_err(|_| RepositoryError::InvalidWorkerState)?,
    )
    .map_err(|_| RepositoryError::InvalidWorkerState)?;
    Ok(WorkerAttemptRecord {
        attempt_id: parse_attempt(value.try_get("attempt_id")?)?,
        assignment,
        task_attempt: num(&value, "task_attempt")?,
        run_id: RunId::from_uuid(
            Uuid::parse_str(&value.try_get::<String, _>("run_id")?)
                .map_err(|_| RepositoryError::InvalidWorkerState)?,
        ),
        state: WorkerAttemptState::parse(&value.try_get::<String, _>("state")?)
            .ok_or(RepositoryError::InvalidWorkerState)?,
        lease_owner: Uuid::parse_str(&value.try_get::<String, _>("lease_owner")?)
            .map_err(|_| RepositoryError::InvalidWorkerState)?,
        lease_expires_at: TimestampMillis::new(num(&value, "lease_expires_at")?),
        created_at: TimestampMillis::new(num(&value, "created_at")?),
        started_at: optional(&value, "started_at")?,
        completed_at: optional(&value, "completed_at")?,
        diagnostic: value.try_get("diagnostic")?,
    })
}
fn num<T: TryFrom<i64>>(row: &SqliteRow, key: &str) -> Result<T, RepositoryError> {
    row.try_get::<i64, _>(key)?
        .try_into()
        .map_err(|_| RepositoryError::InvalidWorkerState)
}
fn optional(row: &SqliteRow, key: &str) -> Result<Option<TimestampMillis>, RepositoryError> {
    row.try_get::<Option<i64>, _>(key)?
        .map(|v| {
            u64::try_from(v)
                .map(TimestampMillis::new)
                .map_err(|_| RepositoryError::InvalidWorkerState)
        })
        .transpose()
}
fn pos(v: u64) -> Result<i64, RepositoryError> {
    i64::try_from(v)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(RepositoryError::InvalidWorkerState)
}
fn data_class(v: lumen_core::egress::DataClass) -> &'static str {
    match v {
        lumen_core::egress::DataClass::Public => "public",
        lumen_core::egress::DataClass::Workspace => "workspace",
        lumen_core::egress::DataClass::Sensitive => "sensitive",
        lumen_core::egress::DataClass::Secret => "secret",
    }
}
fn parse_attempt(v: String) -> Result<WorkerAttemptId, RepositoryError> {
    Uuid::parse_str(&v)
        .map(WorkerAttemptId::from_uuid)
        .map_err(|_| RepositoryError::InvalidWorkerState)
}
fn parse_orchestration(v: String) -> Result<OrchestrationId, RepositoryError> {
    Uuid::parse_str(&v)
        .map(OrchestrationId::from_uuid)
        .map_err(|_| RepositoryError::InvalidWorkerState)
}
fn parse_node(v: String) -> Result<TaskNodeId, RepositoryError> {
    Uuid::parse_str(&v)
        .map(TaskNodeId::from_uuid)
        .map_err(|_| RepositoryError::InvalidWorkerState)
}
fn parse_workspace(v: String) -> Result<WorkspaceId, RepositoryError> {
    Uuid::parse_str(&v)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| RepositoryError::InvalidWorkerState)
}
