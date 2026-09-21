use lumen_core::{
    approval::TimestampMillis,
    egress::ProviderId,
    orchestration::{OrchestrationId, TaskNodeId},
    provider::{ModelProfileId, ProviderUsageEvent},
    routing::{
        BudgetReservationId, BudgetSnapshot, HealthObservation, HealthState, ModelRoutingMetadata,
        OrchestrationBudget, RoutingPlan,
    },
};
use sqlx::{Row, Sqlite};
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Clone, Debug)]
pub struct RoutingDispatchRecord {
    pub reservation_id: BudgetReservationId,
    pub generation: lumen_core::model::ModelGenerationConfig,
}

impl Database {
    pub async fn append_model_routing_metadata(
        &self,
        metadata: &ModelRoutingMetadata,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO model_routing_metadata_revisions VALUES(?,?,?,?,?)")
            .bind(metadata.profile_id.as_str())
            .bind(pos(metadata.profile_revision)?)
            .bind(pos(metadata.revision)?)
            .bind(serde_json::to_string(metadata)?)
            .bind(timestamp_to_i64(metadata.created_at)?)
            .execute(self.pool())
            .await?;
        Ok(())
    }
    pub async fn latest_model_routing_metadata(
        &self,
        id: &ModelProfileId,
        revision: u64,
    ) -> Result<Option<ModelRoutingMetadata>, RepositoryError> {
        sqlx::query_scalar("SELECT metadata_json FROM model_routing_metadata_revisions WHERE profile_id=? AND profile_revision=? ORDER BY revision DESC LIMIT 1")
            .bind(id.as_str()).bind(pos(revision)?).fetch_optional(self.pool()).await?
            .map(|json: String| serde_json::from_str(&json).map_err(RepositoryError::from)).transpose()
    }
    pub async fn append_provider_health(
        &self,
        id: &ProviderId,
        revision: u64,
        observation: &HealthObservation,
    ) -> Result<(), RepositoryError> {
        self.append_health("provider", id.as_str(), revision, observation)
            .await
    }
    pub async fn append_model_health(
        &self,
        id: &ModelProfileId,
        revision: u64,
        observation: &HealthObservation,
    ) -> Result<(), RepositoryError> {
        self.append_health("model", id.as_str(), revision, observation)
            .await
    }
    async fn append_health(
        &self,
        kind: &str,
        id: &str,
        revision: u64,
        observation: &HealthObservation,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO routing_health_observations VALUES(?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string())
            .bind(kind)
            .bind(id)
            .bind(pos(revision)?)
            .bind(observation.state.as_str())
            .bind(i64n(observation.latency_millis)?)
            .bind(timestamp_to_i64(observation.observed_at)?)
            .bind(timestamp_to_i64(observation.expires_at)?)
            .execute(self.pool())
            .await?;
        Ok(())
    }
    pub async fn latest_provider_health(
        &self,
        id: &ProviderId,
        revision: u64,
    ) -> Result<Option<HealthObservation>, RepositoryError> {
        self.health("provider", id.as_str(), revision).await
    }
    pub async fn latest_model_health(
        &self,
        id: &ModelProfileId,
        revision: u64,
    ) -> Result<Option<HealthObservation>, RepositoryError> {
        self.health("model", id.as_str(), revision).await
    }
    async fn health(
        &self,
        kind: &str,
        id: &str,
        revision: u64,
    ) -> Result<Option<HealthObservation>, RepositoryError> {
        sqlx::query("SELECT state,latency_millis,observed_at,expires_at FROM routing_health_observations WHERE target_kind=? AND target_id=? AND target_revision=? ORDER BY observed_at DESC LIMIT 1").bind(kind).bind(id).bind(pos(revision)?).fetch_optional(self.pool()).await?.map(|row| HealthObservation::new(HealthState::parse(&row.try_get::<String, _>("state")?).ok_or(RepositoryError::InvalidRoutingState)?, u64v(&row, "latency_millis")?, TimestampMillis::new(u64v(&row, "observed_at")?), TimestampMillis::new(u64v(&row, "expires_at")?)).map_err(|_| RepositoryError::InvalidRoutingState)).transpose()
    }
    pub async fn append_orchestration_budget(
        &self,
        budget: &OrchestrationBudget,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        match load_budget(&mut tx, budget.orchestration_id).await? {
            None if budget.revision != 1 => return Err(RepositoryError::InvalidRoutingState),
            Some(old) if !budget.is_tightening_of(&old) => {
                return Err(RepositoryError::InvalidRoutingState);
            }
            _ => {}
        }
        sqlx::query("INSERT INTO orchestration_budget_revisions VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(budget.orchestration_id.to_string())
            .bind(pos(budget.revision)?)
            .bind(pos(budget.max_model_calls)?)
            .bind(pos(budget.max_input_tokens)?)
            .bind(pos(budget.max_output_tokens)?)
            .bind(i64n(budget.max_remote_cost_micros)?)
            .bind(i64::from(budget.max_concurrent_workers))
            .bind(pos(budget.max_wall_time_millis)?)
            .bind(timestamp_to_i64(budget.window_started_at)?)
            .bind(timestamp_to_i64(budget.created_at)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn budget_snapshot(
        &self,
        id: OrchestrationId,
        now: TimestampMillis,
    ) -> Result<Option<BudgetSnapshot>, RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let result = match load_budget(&mut tx, id).await? {
            Some(budget) => {
                let (calls, input, output, cost, active) = used(&mut tx, id).await?;
                Some(BudgetSnapshot::new(
                    budget, calls, input, output, cost, active, now,
                ))
            }
            None => None,
        };
        tx.commit().await?;
        Ok(result)
    }
    pub async fn persist_route_and_reserve(
        &self,
        id: OrchestrationId,
        graph_revision: u64,
        task: TaskNodeId,
        plan: &RoutingPlan,
        now: TimestampMillis,
    ) -> Result<BudgetReservationId, RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let budget = load_budget(&mut tx, id)
            .await?
            .ok_or(RepositoryError::InvalidRoutingState)?;
        if budget.revision != plan.budget_revision {
            return Err(RepositoryError::RoutingBudgetConflict);
        }
        let (calls, input, output, cost, active) = used(&mut tx, id).await?;
        let snapshot = BudgetSnapshot::new(budget, calls, input, output, cost, active, now);
        let request = plan.reservation;
        if request.concurrent_workers != 1
            || snapshot.expired
            || request.calls > snapshot.remaining_calls
            || request.input > snapshot.remaining_input
            || request.output > snapshot.remaining_output
            || request.remote_cost_micros > snapshot.remaining_cost
            || snapshot.remaining_concurrency == 0
        {
            return Err(RepositoryError::RoutingBudgetConflict);
        }
        let reservation = BudgetReservationId::new();
        sqlx::query("INSERT INTO routing_decisions VALUES(?,?,?,?,?,?,?,?,?,?,?)")
            .bind(plan.decision_id.to_string())
            .bind(id.to_string())
            .bind(pos(graph_revision)?)
            .bind(task.to_string())
            .bind(pos(plan.budget_revision)?)
            .bind(plan.provider_id.as_str())
            .bind(pos(plan.provider_revision)?)
            .bind(plan.profile_id.as_str())
            .bind(pos(plan.profile_revision)?)
            .bind(serde_json::to_string(plan)?)
            .bind(timestamp_to_i64(now)?)
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT INTO routing_budget_reservations(reservation_id,decision_id,orchestration_id,graph_revision,task_node_id,reserved_calls,reserved_input_tokens,reserved_output_tokens,reserved_remote_cost_micros,state,created_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?)").bind(reservation.to_string()).bind(plan.decision_id.to_string()).bind(id.to_string()).bind(pos(graph_revision)?).bind(task.to_string()).bind(pos(request.calls)?).bind(pos(request.input)?).bind(pos(request.output)?).bind(i64n(request.remote_cost_micros)?).bind(timestamp_to_i64(now)?).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(reservation)
    }
    pub async fn active_routing_dispatch(
        &self,
        id: OrchestrationId,
        revision: u64,
        task: TaskNodeId,
    ) -> Result<Option<RoutingDispatchRecord>, RepositoryError> {
        sqlx::query("SELECT b.reservation_id,d.plan_json FROM routing_budget_reservations b JOIN routing_decisions d ON d.decision_id=b.decision_id WHERE b.orchestration_id=? AND b.graph_revision=? AND b.task_node_id=? AND b.state='active'").bind(id.to_string()).bind(pos(revision)?).bind(task.to_string()).fetch_optional(self.pool()).await?.map(|row| { let plan: RoutingPlan = serde_json::from_str(&row.try_get::<String, _>("plan_json")?)?; Ok(RoutingDispatchRecord { reservation_id: reservation(&row.try_get::<String, _>("reservation_id")?)?, generation: plan.generation }) }).transpose()
    }
    pub async fn record_provider_usage(
        &self,
        reservation_id: BudgetReservationId,
        event: &ProviderUsageEvent,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let reservation = sqlx::query("SELECT r.reserved_calls,r.reserved_input_tokens,r.reserved_output_tokens,r.reserved_remote_cost_micros,d.plan_json,p.endpoint_class FROM routing_budget_reservations r JOIN routing_decisions d ON d.decision_id=r.decision_id JOIN model_provider_runtime_revisions p ON p.provider_id=d.provider_id AND p.revision=d.provider_revision WHERE r.reservation_id=? AND r.state='active'").bind(reservation_id.to_string()).fetch_optional(&mut *tx).await?.ok_or(RepositoryError::InvalidRoutingState)?;
        let plan: RoutingPlan =
            serde_json::from_str(&reservation.try_get::<String, _>("plan_json")?)?;
        let usage = event.usage();
        let complete = usage.input_tokens.is_some() && usage.output_tokens.is_some();
        let remote_cost = match (usage.input_tokens, usage.output_tokens) {
            (Some(input), Some(output))
                if reservation.try_get::<String, _>("endpoint_class")? == "remote" =>
            {
                Some(plan.pricing.cost_micros(input, output))
            }
            (Some(_), Some(_)) => Some(0),
            _ => None,
        };
        sqlx::query("INSERT INTO model_usage_records VALUES(?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string())
            .bind(reservation_id.to_string())
            .bind(event.resolved_model())
            .bind(usage.input_tokens.map(i64n).transpose()?)
            .bind(usage.output_tokens.map(i64n).transpose()?)
            .bind(remote_cost.map(i64n).transpose()?)
            .bind(complete)
            .bind(timestamp_to_i64(now)?)
            .execute(&mut *tx)
            .await?;
        let totals = sqlx::query("SELECT COUNT(*) calls,COALESCE(SUM(input_tokens),0) input,COALESCE(SUM(output_tokens),0) output,COALESCE(SUM(remote_cost_micros),0) cost FROM model_usage_records WHERE reservation_id=?").bind(reservation_id.to_string()).fetch_one(&mut *tx).await?;
        if u64v(&totals, "calls")? > u64v(&reservation, "reserved_calls")?
            || u64v(&totals, "input")? > u64v(&reservation, "reserved_input_tokens")?
            || u64v(&totals, "output")? > u64v(&reservation, "reserved_output_tokens")?
            || u64v(&totals, "cost")? > u64v(&reservation, "reserved_remote_cost_micros")?
        {
            return Err(RepositoryError::RoutingBudgetConflict);
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn settle_active_routing_for_task(
        &self,
        id: OrchestrationId,
        revision: u64,
        task: TaskNodeId,
        now: TimestampMillis,
    ) -> Result<bool, RepositoryError> {
        settle(self, id, revision, task, false, now).await
    }
    pub async fn release_active_routing_for_task(
        &self,
        id: OrchestrationId,
        revision: u64,
        task: TaskNodeId,
        now: TimestampMillis,
    ) -> Result<bool, RepositoryError> {
        settle(self, id, revision, task, true, now).await
    }
    pub async fn active_worker_counts(
        &self,
        provider: &ProviderId,
        profile: &ModelProfileId,
        revision: u64,
    ) -> Result<(u32, u32), RepositoryError> {
        let provider_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM worker_attempts WHERE provider_id=? AND state='running'",
        )
        .bind(provider.as_str())
        .fetch_one(self.pool())
        .await?;
        let profile_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM worker_attempts WHERE profile_id=? AND profile_revision=? AND state='running'").bind(profile.as_str()).bind(pos(revision)?).fetch_one(self.pool()).await?;
        Ok((
            u32::try_from(provider_count).map_err(|_| RepositoryError::InvalidRoutingState)?,
            u32::try_from(profile_count).map_err(|_| RepositoryError::InvalidRoutingState)?,
        ))
    }
}
async fn settle(
    db: &Database,
    id: OrchestrationId,
    revision: u64,
    task: TaskNodeId,
    release: bool,
    now: TimestampMillis,
) -> Result<bool, RepositoryError> {
    let result = sqlx::query("UPDATE routing_budget_reservations SET state=?,actual_calls=reserved_calls,actual_input_tokens=reserved_input_tokens,actual_output_tokens=reserved_output_tokens,actual_remote_cost_micros=reserved_remote_cost_micros,usage_complete=0,settled_at=? WHERE orchestration_id=? AND graph_revision=? AND task_node_id=? AND state='active'").bind(if release { "released" } else { "settled" }).bind(timestamp_to_i64(now)?).bind(id.to_string()).bind(pos(revision)?).bind(task.to_string()).execute(db.pool()).await?;
    Ok(result.rows_affected() == 1)
}
async fn load_budget(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    id: OrchestrationId,
) -> Result<Option<OrchestrationBudget>, RepositoryError> {
    sqlx::query("SELECT * FROM orchestration_budget_revisions WHERE orchestration_id=? ORDER BY revision DESC LIMIT 1").bind(id.to_string()).fetch_optional(&mut **tx).await?.map(|row| OrchestrationBudget::new(id, u64v(&row,"revision")?, u64v(&row,"max_model_calls")?, u64v(&row,"max_input_tokens")?, u64v(&row,"max_output_tokens")?, u64v(&row,"max_remote_cost_micros")?, u32::try_from(row.try_get::<i64,_>("max_concurrent_workers")?).map_err(|_| RepositoryError::InvalidRoutingState)?, u64v(&row,"max_wall_time_millis")?, TimestampMillis::new(u64v(&row,"window_started_at")?), TimestampMillis::new(u64v(&row,"created_at")?)).map_err(|_| RepositoryError::InvalidRoutingState)).transpose()
}
async fn used(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    id: OrchestrationId,
) -> Result<(u64, u64, u64, u64, u32), RepositoryError> {
    let row = sqlx::query("SELECT COALESCE(SUM(reserved_calls),0) calls,COALESCE(SUM(reserved_input_tokens),0) input,COALESCE(SUM(reserved_output_tokens),0) output,COALESCE(SUM(reserved_remote_cost_micros),0) cost,COUNT(*) active FROM routing_budget_reservations WHERE orchestration_id=? AND state='active'").bind(id.to_string()).fetch_one(&mut **tx).await?;
    Ok((
        u64v(&row, "calls")?,
        u64v(&row, "input")?,
        u64v(&row, "output")?,
        u64v(&row, "cost")?,
        u32::try_from(row.try_get::<i64, _>("active")?)
            .map_err(|_| RepositoryError::InvalidRoutingState)?,
    ))
}
fn pos(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidRoutingState)
}
fn i64n(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value).map_err(|_| RepositoryError::InvalidRoutingState)
}
fn u64v(row: &sqlx::sqlite::SqliteRow, key: &str) -> Result<u64, RepositoryError> {
    u64::try_from(row.try_get::<i64, _>(key)?).map_err(|_| RepositoryError::InvalidRoutingState)
}
fn reservation(value: &str) -> Result<BudgetReservationId, RepositoryError> {
    Uuid::parse_str(value)
        .map(BudgetReservationId::from_uuid)
        .map_err(|_| RepositoryError::InvalidRoutingState)
}
