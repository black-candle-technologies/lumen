use crate::{Database, RepositoryError, timestamp_to_i64};
use lumen_core::{
    approval::TimestampMillis,
    artifact::ArtifactId,
    context::{ContextDigest, ContextSource, ContextSourceId},
    identity::WorkspaceId,
    model::ReasoningProfile,
    operator::OrchestrationControlPolicy,
    orchestration::{OrchestrationId, TaskNodeId},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ControlEvent {
    pub sequence: u64,
    pub kind: String,
    pub payload: Value,
    pub created_at: TimestampMillis,
}
impl Database {
    pub async fn append_control_policy(
        &self,
        p: &OrchestrationControlPolicy,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let old=sqlx::query("SELECT * FROM orchestration_control_policy_revisions WHERE orchestration_id=? ORDER BY revision DESC LIMIT 1").bind(p.orchestration_id.to_string()).fetch_optional(&mut*tx).await?;
        if let Some(r) = old {
            if !p.is_tightening_of(&policy(p.orchestration_id, &r)?) {
                return Err(RepositoryError::InvalidControlState);
            }
        } else if p.revision != 1 {
            return Err(RepositoryError::InvalidControlState);
        }
        sqlx::query("INSERT INTO orchestration_control_policy_revisions VALUES(?,?,?,?,?,?)")
            .bind(p.orchestration_id.to_string())
            .bind(pos(p.revision)?)
            .bind(p.remote_allowed)
            .bind(p.prefer_local)
            .bind(reasoning(p.reasoning))
            .bind(timestamp_to_i64(p.created_at)?)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn latest_control_policy(
        &self,
        id: OrchestrationId,
    ) -> Result<Option<OrchestrationControlPolicy>, RepositoryError> {
        sqlx::query("SELECT * FROM orchestration_control_policy_revisions WHERE orchestration_id=? ORDER BY revision DESC LIMIT 1").bind(id.to_string()).fetch_optional(self.pool()).await?.map(|r|policy(id,&r)).transpose()
    }
    pub async fn link_orchestration_input_source(
        &self,
        id: OrchestrationId,
        source: ContextSourceId,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO orchestration_input_sources VALUES(?,?,?)")
            .bind(id.to_string())
            .bind(source.to_string())
            .bind(timestamp_to_i64(now)?)
            .execute(self.pool())
            .await?;
        Ok(())
    }
    pub async fn orchestration_input_sources(
        &self,
        id: OrchestrationId,
    ) -> Result<Vec<ContextSource>, RepositoryError> {
        let ids=sqlx::query_scalar::<_,String>("SELECT source_id FROM orchestration_input_sources WHERE orchestration_id=? ORDER BY created_at,source_id").bind(id.to_string()).fetch_all(self.pool()).await?;
        let mut out = Vec::new();
        for raw in ids {
            out.push(
                self.context_source(ContextSourceId::from_uuid(
                    Uuid::parse_str(&raw).map_err(|_| RepositoryError::InvalidControlState)?,
                ))
                .await?
                .ok_or(RepositoryError::InvalidControlState)?,
            )
        }
        Ok(out)
    }
    pub async fn record_planner_invocation(
        &self,
        id: Uuid,
        o: OrchestrationId,
        w: WorkspaceId,
        d: &ContextDigest,
        p: &impl Serialize,
        now: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        sqlx::query("INSERT INTO planner_invocations VALUES(?,?,?,?,?,?)")
            .bind(id.to_string())
            .bind(o.to_string())
            .bind(w.to_string())
            .bind(d.as_str())
            .bind(serde_json::to_string(p)?)
            .bind(timestamp_to_i64(now)?)
            .execute(self.pool())
            .await?;
        Ok(())
    }
    pub async fn control_events(
        &self,
        w: WorkspaceId,
        id: OrchestrationId,
        after: u64,
        limit: u16,
    ) -> Result<Vec<ControlEvent>, RepositoryError> {
        if limit == 0 || limit > 500 {
            return Err(RepositoryError::InvalidControlState);
        }
        sqlx::query("SELECT sequence,kind,payload_json,created_at FROM orchestration_control_events WHERE workspace_id=? AND orchestration_id=? AND sequence>? ORDER BY sequence LIMIT ?").bind(w.to_string()).bind(id.to_string()).bind(i64n(after)?).bind(i64::from(limit)).fetch_all(self.pool()).await?.into_iter().map(|r|Ok(ControlEvent{sequence:u64v(&r,"sequence")?,kind:r.try_get("kind")?,payload:serde_json::from_str(&r.try_get::<String,_>("payload_json")?)?,created_at:TimestampMillis::new(u64v(&r,"created_at")?)})).collect()
    }
    pub async fn orchestration_ids_for_workspace(
        &self,
        w: WorkspaceId,
    ) -> Result<Vec<OrchestrationId>, RepositoryError> {
        sqlx::query_scalar::<_,String>("SELECT orchestration_id FROM orchestrations WHERE workspace_id=? ORDER BY created_at DESC").bind(w.to_string()).fetch_all(self.pool()).await?.into_iter().map(|s|Uuid::parse_str(&s).map(OrchestrationId::from_uuid).map_err(|_|RepositoryError::InvalidControlState)).collect()
    }
    pub async fn handoff_artifact_ids(
        &self,
        id: OrchestrationId,
        rev: u64,
        task: TaskNodeId,
    ) -> Result<Vec<ArtifactId>, RepositoryError> {
        sqlx::query_scalar::<_,String>("WITH l AS(SELECT artifact_id,MAX(revision)r FROM artifact_validation_revisions GROUP BY artifact_id)SELECT a.artifact_id FROM worker_artifacts a JOIN worker_attempts w ON w.attempt_id=a.attempt_id JOIN l ON l.artifact_id=a.artifact_id JOIN artifact_validation_revisions v ON v.artifact_id=l.artifact_id AND v.revision=l.r WHERE a.orchestration_id=? AND a.graph_revision=? AND a.task_node_id=? AND w.state='completed' AND v.state='accepted' ORDER BY a.created_at").bind(id.to_string()).bind(pos(rev)?).bind(task.to_string()).fetch_all(self.pool()).await?.into_iter().map(|s|Uuid::parse_str(&s).map(ArtifactId::from_uuid).map_err(|_|RepositoryError::InvalidControlState)).collect()
    }
    pub async fn orchestration_view(
        &self,
        w: WorkspaceId,
        id: OrchestrationId,
        now: TimestampMillis,
    ) -> Result<Option<Value>, RepositoryError> {
        let Some(s) = self.latest_orchestration_snapshot(id).await? else {
            return Ok(None);
        };
        if s.graph().workspace_id() != w {
            return Ok(None);
        }
        let attempts = self.worker_attempts_for_orchestration(id).await?;
        let edges = s.graph().dependency_edges().collect::<Vec<_>>();
        let tasks=s.graph().nodes().map(|n|{let st=s.state(n.id());let a=attempts.iter().filter(|x|x.assignment().task_node_id()==n.id()).map(|x|json!({"attempt_id":x.attempt_id().to_string(),"run_id":x.run_id().to_string(),"state":x.state().as_str(),"provider_id":x.assignment().provider_id().as_str(),"profile_id":x.assignment().model_profile_id().as_str(),"created_at":x.created_at().as_u64(),"started_at":x.started_at().map(TimestampMillis::as_u64),"completed_at":x.completed_at().map(TimestampMillis::as_u64),"diagnostic":x.diagnostic()})).collect::<Vec<_>>();json!({"id":n.id().to_string(),"key":n.key().as_str(),"description":n.description(),"expected_output":n.expected_output().as_str(),"state":st.map(|x|x.state().as_str()),"attempt_count":st.map(|x|x.attempt_count()).unwrap_or(0),"dependencies":edges.iter().filter_map(|(c,d)|(*c==n.id()).then_some(d.to_string())).collect::<Vec<_>>(),"attempts":a})}).collect::<Vec<_>>();
        let routes = sqlx::query_scalar::<_, String>(
            "SELECT plan_json FROM routing_decisions WHERE orchestration_id=? ORDER BY created_at",
        )
        .bind(id.to_string())
        .fetch_all(self.pool())
        .await?
        .into_iter()
        .map(|v| serde_json::from_str::<Value>(&v))
        .collect::<Result<Vec<_>, _>>()?;
        let artifacts=sqlx::query("SELECT artifact_id,task_node_id,artifact_kind,content_hash,classification,created_at FROM worker_artifacts WHERE orchestration_id=? ORDER BY created_at").bind(id.to_string()).fetch_all(self.pool()).await?.into_iter().map(|r|Ok(json!({"artifact_id":r.try_get::<String,_>("artifact_id")?,"task_node_id":r.try_get::<String,_>("task_node_id")?,"kind":r.try_get::<String,_>("artifact_kind")?,"sha256":r.try_get::<String,_>("content_hash")?,"classification":r.try_get::<String,_>("classification")?,"created_at":u64v(&r,"created_at")?}))).collect::<Result<Vec<_>,RepositoryError>>()?;
        let u=sqlx::query("SELECT COALESCE(SUM(actual_calls),0)c,COALESCE(SUM(actual_input_tokens),0)i,COALESCE(SUM(actual_output_tokens),0)o,COALESCE(SUM(actual_remote_cost_micros),0)cost FROM routing_budget_reservations WHERE orchestration_id=? AND state<>'released'").bind(id.to_string()).fetch_one(self.pool()).await?;
        let b = self.budget_snapshot(id, now).await?;
        Ok(Some(
            json!({"orchestration_id":id.to_string(),"graph_revision":s.graph().revision(),"graph_digest":s.graph().digest().as_str(),"tasks":tasks,"routing":routes,"artifacts":artifacts,"usage":{"calls":u64v(&u,"c")?,"input_tokens":u64v(&u,"i")?,"output_tokens":u64v(&u,"o")?,"remote_cost_micros":u64v(&u,"cost")?},"budget":b.map(|x|json!({"limits":x.budget,"remaining":{"calls":x.remaining_calls,"input":x.remaining_input,"output":x.remaining_output,"cost":x.remaining_cost,"workers":x.remaining_concurrency,"wall":x.remaining_wall_millis}})),"control":self.latest_control_policy(id).await?}),
        ))
    }
}
fn policy(
    id: OrchestrationId,
    r: &sqlx::sqlite::SqliteRow,
) -> Result<OrchestrationControlPolicy, RepositoryError> {
    OrchestrationControlPolicy::new(
        id,
        u64v(r, "revision")?,
        r.try_get::<i64, _>("remote_allowed")? == 1,
        r.try_get::<i64, _>("prefer_local")? == 1,
        parse_reasoning(&r.try_get::<String, _>("reasoning_profile")?)
            .ok_or(RepositoryError::InvalidControlState)?,
        TimestampMillis::new(u64v(r, "created_at")?),
    )
    .map_err(|_| RepositoryError::InvalidControlState)
}
fn reasoning(v: ReasoningProfile) -> &'static str {
    match v {
        ReasoningProfile::Fast => "fast",
        ReasoningProfile::Balanced => "balanced",
        ReasoningProfile::Deep => "deep",
        ReasoningProfile::Maximum => "maximum",
    }
}
fn parse_reasoning(v: &str) -> Option<ReasoningProfile> {
    match v {
        "fast" => Some(ReasoningProfile::Fast),
        "balanced" => Some(ReasoningProfile::Balanced),
        "deep" => Some(ReasoningProfile::Deep),
        "maximum" => Some(ReasoningProfile::Maximum),
        _ => None,
    }
}
fn pos(v: u64) -> Result<i64, RepositoryError> {
    i64::try_from(v)
        .ok()
        .filter(|x| *x > 0)
        .ok_or(RepositoryError::InvalidControlState)
}
fn i64n(v: u64) -> Result<i64, RepositoryError> {
    i64::try_from(v).map_err(|_| RepositoryError::InvalidControlState)
}
fn u64v(r: &sqlx::sqlite::SqliteRow, k: &str) -> Result<u64, RepositoryError> {
    u64::try_from(r.try_get::<i64, _>(k)?).map_err(|_| RepositoryError::InvalidControlState)
}
