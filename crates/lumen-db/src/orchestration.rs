use crate::{Database, RepositoryError, timestamp_to_i64};
use lumen_core::{
    action::ActionKind,
    approval::TimestampMillis,
    context::{CompartmentId, ContextDigest, ModelDataPolicy, data_class_str, parse_data_class},
    identity::{PrincipalId, WorkspaceId},
    orchestration::{
        ModelProfileRef, OrchestrationId, OrchestrationSnapshot, TaskGraph, TaskNode, TaskNodeId,
        TaskNodeKey, TaskNodeLimits, TaskNodeState, TaskOutputKind, TaskRequirements,
        TaskStateRevision,
    },
    provider::{ModelCapabilities, ModelProfile},
};
use sqlx::{Row, SqliteConnection};
use std::collections::BTreeSet;
use uuid::Uuid;
impl Database {
    pub async fn append_task_graph(
        &self,
        graph: &TaskGraph,
        profiles: &[ModelProfile],
        policies: &[ModelDataPolicy],
    ) -> Result<(), RepositoryError> {
        graph
            .validate_against_catalog(profiles, policies)
            .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let root = sqlx::query(
            "SELECT workspace_id, created_by_provider, created_by_subject
             FROM orchestrations WHERE orchestration_id = ?",
        )
        .bind(graph.orchestration_id().to_string())
        .fetch_optional(&mut *transaction)
        .await?;
        match root {
            Some(row) => {
                if row.try_get::<String, _>("workspace_id")? != graph.workspace_id().to_string()
                    || row.try_get::<String, _>("created_by_provider")?
                        != graph.created_by().provider()
                    || row.try_get::<String, _>("created_by_subject")?
                        != graph.created_by().subject()
                {
                    return Err(RepositoryError::InvalidOrchestrationState);
                }
            }
            None => {
                if graph.revision() != 1 {
                    return Err(RepositoryError::InvalidOrchestrationState);
                }
                sqlx::query(
                    "INSERT INTO orchestrations (
                        orchestration_id, workspace_id, created_by_provider,
                        created_by_subject, created_at
                     ) VALUES (?, ?, ?, ?, ?)",
                )
                .bind(graph.orchestration_id().to_string())
                .bind(graph.workspace_id().to_string())
                .bind(graph.created_by().provider())
                .bind(graph.created_by().subject())
                .bind(timestamp_to_i64(graph.created_at())?)
                .execute(&mut *transaction)
                .await?;
            }
        }
        let latest: Option<i64> = sqlx::query_scalar(
            "SELECT MAX(revision) FROM orchestration_graph_revisions
             WHERE orchestration_id = ?",
        )
        .bind(graph.orchestration_id().to_string())
        .fetch_one(&mut *transaction)
        .await?;
        let latest_revision = latest.and_then(|value| u64::try_from(value).ok());
        let expected = latest_revision
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        if graph.revision() != expected {
            return Err(RepositoryError::InvalidOrchestrationState);
        }
        if let Some(previous_revision) = latest_revision {
            let started: i64 = sqlx::query_scalar(
                "WITH latest_state AS (
                    SELECT task_node_id, MAX(state_revision) AS state_revision
                    FROM orchestration_task_state_revisions
                    WHERE orchestration_id = ? AND graph_revision = ?
                    GROUP BY task_node_id
                 )
                 SELECT COUNT(*)
                 FROM latest_state latest
                 JOIN orchestration_task_state_revisions state
                   ON state.orchestration_id = ?
                  AND state.graph_revision = ?
                  AND state.task_node_id = latest.task_node_id
                  AND state.state_revision = latest.state_revision
                 WHERE state.attempt_count > 0
                    OR state.state IN ('running','completed','failed','cancelled','unknown')",
            )
            .bind(graph.orchestration_id().to_string())
            .bind(positive_i64(previous_revision)?)
            .bind(graph.orchestration_id().to_string())
            .bind(positive_i64(previous_revision)?)
            .fetch_one(&mut *transaction)
            .await?;
            if started != 0 {
                return Err(RepositoryError::InvalidOrchestrationState);
            }
        }
        sqlx::query(
            "INSERT INTO orchestration_graph_revisions (
                orchestration_id, revision, graph_digest, created_at
             ) VALUES (?, ?, ?, ?)",
        )
        .bind(graph.orchestration_id().to_string())
        .bind(positive_i64(graph.revision())?)
        .bind(graph.digest().as_str())
        .bind(timestamp_to_i64(graph.created_at())?)
        .execute(&mut *transaction)
        .await?;
        for node in graph.nodes() {
            insert_node(&mut transaction, graph, node).await?;
        }
        for (node_id, dependency_id) in graph.dependency_edges() {
            sqlx::query(
                "INSERT INTO orchestration_task_dependencies (
                    orchestration_id, graph_revision, task_node_id,
                    depends_on_task_node_id
                 ) VALUES (?, ?, ?, ?)",
            )
            .bind(graph.orchestration_id().to_string())
            .bind(positive_i64(graph.revision())?)
            .bind(node_id.to_string())
            .bind(dependency_id.to_string())
            .execute(&mut *transaction)
            .await?;
        }
        for state in graph.initial_state_revisions(graph.created_at()) {
            insert_state(&mut transaction, &state).await?;
        }
        transaction.commit().await?;
        Ok(())
    }
    pub async fn latest_orchestration_snapshot(
        &self,
        orchestration_id: OrchestrationId,
    ) -> Result<Option<OrchestrationSnapshot>, RepositoryError> {
        let mut transaction = self.pool().begin().await?;
        let Some(revision) = latest_graph_revision(&mut transaction, orchestration_id).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let graph = load_graph(&mut transaction, orchestration_id, revision)
            .await?
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        let states = load_latest_states(&mut transaction, &graph).await?;
        let snapshot = OrchestrationSnapshot::new(graph, states)
            .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
        transaction.commit().await?;
        Ok(Some(snapshot))
    }
    pub async fn transition_task_state(
        &self,
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        task_node_id: TaskNodeId,
        expected_state_revision: u64,
        next_state: TaskNodeState,
        created_at: TimestampMillis,
    ) -> Result<TaskStateRevision, RepositoryError> {
        if graph_revision == 0 || expected_state_revision == 0 {
            return Err(RepositoryError::InvalidOrchestrationState);
        }
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        if latest_graph_revision(&mut transaction, orchestration_id).await? != Some(graph_revision)
        {
            return Err(RepositoryError::InvalidOrchestrationState);
        }
        let graph = load_graph(&mut transaction, orchestration_id, graph_revision)
            .await?
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        let node = graph
            .node(task_node_id)
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        let current = load_latest_state(&mut transaction, &graph, task_node_id)
            .await?
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        if current.revision() != expected_state_revision {
            return Err(RepositoryError::InvalidOrchestrationState);
        }
        let next = current
            .transition(next_state, node.limits().max_attempts(), created_at)
            .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
        insert_state(&mut transaction, &next).await?;
        transaction.commit().await?;
        Ok(next)
    }
    pub async fn reconcile_task_readiness(
        &self,
        orchestration_id: OrchestrationId,
        created_at: TimestampMillis,
    ) -> Result<Vec<TaskStateRevision>, RepositoryError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let revision = latest_graph_revision(&mut transaction, orchestration_id)
            .await?
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        let graph = load_graph(&mut transaction, orchestration_id, revision)
            .await?
            .ok_or(RepositoryError::InvalidOrchestrationState)?;
        let states = load_latest_states(&mut transaction, &graph).await?;
        let snapshot = OrchestrationSnapshot::new(graph, states)
            .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
        let updates = snapshot
            .readiness_updates(created_at)
            .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
        for update in &updates {
            insert_state(&mut transaction, update).await?;
        }
        transaction.commit().await?;
        Ok(updates)
    }
}
async fn insert_node(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    graph: &TaskGraph,
    node: &TaskNode,
) -> Result<(), RepositoryError> {
    let requirements = node.requirements();
    sqlx::query(
        "INSERT INTO orchestration_task_nodes (
            orchestration_id, graph_revision, task_node_id, task_key, description,
            expected_output, required_model_capabilities_json,
            allowed_model_profiles_json, data_class, required_compartments_json,
            required_tools_json, max_input_tokens, max_output_tokens, max_attempts,
            deadline_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(graph.orchestration_id().to_string())
    .bind(positive_i64(graph.revision())?)
    .bind(node.id().to_string())
    .bind(node.key().as_str())
    .bind(node.description())
    .bind(node.expected_output().as_str())
    .bind(serde_json::to_string(
        requirements.required_model_capabilities(),
    )?)
    .bind(serde_json::to_string(
        requirements.allowed_model_profiles(),
    )?)
    .bind(data_class_str(requirements.data_class()))
    .bind(serde_json::to_string(requirements.required_compartments())?)
    .bind(serde_json::to_string(requirements.required_tools())?)
    .bind(positive_i64(node.limits().max_input_tokens())?)
    .bind(positive_i64(node.limits().max_output_tokens())?)
    .bind(i64::from(node.limits().max_attempts()))
    .bind(node.deadline_at().map(timestamp_to_i64).transpose()?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
async fn insert_state(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    state: &TaskStateRevision,
) -> Result<(), RepositoryError> {
    sqlx::query(
        "INSERT INTO orchestration_task_state_revisions (
            orchestration_id, graph_revision, task_node_id, state_revision,
            state, attempt_count, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(state.orchestration_id().to_string())
    .bind(positive_i64(state.graph_revision())?)
    .bind(state.task_node_id().to_string())
    .bind(positive_i64(state.revision())?)
    .bind(state.state().as_str())
    .bind(i64::from(state.attempt_count()))
    .bind(timestamp_to_i64(state.created_at())?)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
async fn latest_graph_revision(
    connection: &mut SqliteConnection,
    orchestration_id: OrchestrationId,
) -> Result<Option<u64>, RepositoryError> {
    let value: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(revision) FROM orchestration_graph_revisions
         WHERE orchestration_id = ?",
    )
    .bind(orchestration_id.to_string())
    .fetch_one(&mut *connection)
    .await?;
    value.map(positive_u64).transpose()
}
async fn load_graph(
    connection: &mut SqliteConnection,
    orchestration_id: OrchestrationId,
    revision: u64,
) -> Result<Option<TaskGraph>, RepositoryError> {
    let row = sqlx::query(
        "SELECT o.workspace_id, o.created_by_provider, o.created_by_subject,
                g.graph_digest, g.created_at
         FROM orchestration_graph_revisions g
         JOIN orchestrations o ON o.orchestration_id = g.orchestration_id
         WHERE g.orchestration_id = ? AND g.revision = ?",
    )
    .bind(orchestration_id.to_string())
    .bind(positive_i64(revision)?)
    .fetch_optional(&mut *connection)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let workspace_id = parse_workspace(row.try_get::<String, _>("workspace_id")?)?;
    let created_by = PrincipalId::new(
        row.try_get::<String, _>("created_by_provider")?,
        row.try_get::<String, _>("created_by_subject")?,
    )
    .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
    let digest = ContextDigest::parse(row.try_get::<String, _>("graph_digest")?)
        .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
    let created_at = TimestampMillis::new(nonnegative_u64(row.try_get::<i64, _>("created_at")?)?);
    let node_rows = sqlx::query(
        "SELECT task_node_id, task_key, description, expected_output,
                required_model_capabilities_json, allowed_model_profiles_json,
                data_class, required_compartments_json, required_tools_json,
                max_input_tokens, max_output_tokens, max_attempts, deadline_at
         FROM orchestration_task_nodes
         WHERE orchestration_id = ? AND graph_revision = ?
         ORDER BY task_key ASC",
    )
    .bind(orchestration_id.to_string())
    .bind(positive_i64(revision)?)
    .fetch_all(&mut *connection)
    .await?;
    if node_rows.is_empty() {
        return Err(RepositoryError::InvalidOrchestrationState);
    }
    let nodes = node_rows
        .into_iter()
        .map(node_from_row)
        .collect::<Result<Vec<_>, _>>()?;
    let dependency_rows = sqlx::query(
        "SELECT task_node_id, depends_on_task_node_id
         FROM orchestration_task_dependencies
         WHERE orchestration_id = ? AND graph_revision = ?
         ORDER BY task_node_id ASC, depends_on_task_node_id ASC",
    )
    .bind(orchestration_id.to_string())
    .bind(positive_i64(revision)?)
    .fetch_all(&mut *connection)
    .await?;
    let dependency_edges = dependency_rows
        .into_iter()
        .map(|row| {
            Ok((
                parse_task_node_id(row.try_get::<String, _>("task_node_id")?)?,
                parse_task_node_id(row.try_get::<String, _>("depends_on_task_node_id")?)?,
            ))
        })
        .collect::<Result<Vec<_>, RepositoryError>>()?;
    TaskGraph::from_stored_parts(
        orchestration_id,
        workspace_id,
        revision,
        created_by,
        created_at,
        nodes,
        dependency_edges,
        digest,
    )
    .map(Some)
    .map_err(|_| RepositoryError::InvalidOrchestrationState)
}
async fn load_latest_states(
    connection: &mut SqliteConnection,
    graph: &TaskGraph,
) -> Result<Vec<TaskStateRevision>, RepositoryError> {
    let rows = sqlx::query(
        "WITH latest AS (
            SELECT task_node_id, MAX(state_revision) AS state_revision
            FROM orchestration_task_state_revisions
            WHERE orchestration_id = ? AND graph_revision = ?
            GROUP BY task_node_id
         )
         SELECT state.task_node_id, state.state_revision, state.state,
                state.attempt_count, state.created_at
         FROM latest
         JOIN orchestration_task_state_revisions state
           ON state.orchestration_id = ?
          AND state.graph_revision = ?
          AND state.task_node_id = latest.task_node_id
          AND state.state_revision = latest.state_revision
         ORDER BY state.task_node_id ASC",
    )
    .bind(graph.orchestration_id().to_string())
    .bind(positive_i64(graph.revision())?)
    .bind(graph.orchestration_id().to_string())
    .bind(positive_i64(graph.revision())?)
    .fetch_all(&mut *connection)
    .await?;
    rows.into_iter()
        .map(|row| state_from_row(graph, row))
        .collect()
}
async fn load_latest_state(
    connection: &mut SqliteConnection,
    graph: &TaskGraph,
    task_node_id: TaskNodeId,
) -> Result<Option<TaskStateRevision>, RepositoryError> {
    let row = sqlx::query(
        "SELECT task_node_id, state_revision, state, attempt_count, created_at
         FROM orchestration_task_state_revisions
         WHERE orchestration_id = ? AND graph_revision = ? AND task_node_id = ?
         ORDER BY state_revision DESC LIMIT 1",
    )
    .bind(graph.orchestration_id().to_string())
    .bind(positive_i64(graph.revision())?)
    .bind(task_node_id.to_string())
    .fetch_optional(&mut *connection)
    .await?;
    row.map(|row| state_from_row(graph, row)).transpose()
}
fn node_from_row(row: sqlx::sqlite::SqliteRow) -> Result<TaskNode, RepositoryError> {
    let requirements = TaskRequirements::new(
        serde_json::from_str::<ModelCapabilities>(
            &row.try_get::<String, _>("required_model_capabilities_json")?,
        )?,
        serde_json::from_str::<BTreeSet<ModelProfileRef>>(
            &row.try_get::<String, _>("allowed_model_profiles_json")?,
        )?,
        parse_data_class(&row.try_get::<String, _>("data_class")?)
            .ok_or(RepositoryError::InvalidOrchestrationState)?,
        serde_json::from_str::<BTreeSet<CompartmentId>>(
            &row.try_get::<String, _>("required_compartments_json")?,
        )?,
        serde_json::from_str::<BTreeSet<ActionKind>>(
            &row.try_get::<String, _>("required_tools_json")?,
        )?,
    )
    .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
    let limits = TaskNodeLimits::new(
        positive_u64(row.try_get::<i64, _>("max_input_tokens")?)?,
        positive_u64(row.try_get::<i64, _>("max_output_tokens")?)?,
        positive_u32(row.try_get::<i64, _>("max_attempts")?)?,
    )
    .map_err(|_| RepositoryError::InvalidOrchestrationState)?;
    TaskNode::new(
        parse_task_node_id(row.try_get::<String, _>("task_node_id")?)?,
        TaskNodeKey::parse(row.try_get::<String, _>("task_key")?)
            .map_err(|_| RepositoryError::InvalidOrchestrationState)?,
        row.try_get::<String, _>("description")?,
        TaskOutputKind::parse(&row.try_get::<String, _>("expected_output")?)
            .ok_or(RepositoryError::InvalidOrchestrationState)?,
        requirements,
        limits,
        row.try_get::<Option<i64>, _>("deadline_at")?
            .map(nonnegative_u64)
            .transpose()?
            .map(TimestampMillis::new),
    )
    .map_err(|_| RepositoryError::InvalidOrchestrationState)
}
fn state_from_row(
    graph: &TaskGraph,
    row: sqlx::sqlite::SqliteRow,
) -> Result<TaskStateRevision, RepositoryError> {
    let task_node_id = parse_task_node_id(row.try_get::<String, _>("task_node_id")?)?;
    let node = graph
        .node(task_node_id)
        .ok_or(RepositoryError::InvalidOrchestrationState)?;
    let state = TaskNodeState::parse(&row.try_get::<String, _>("state")?)
        .ok_or(RepositoryError::InvalidOrchestrationState)?;
    TaskStateRevision::from_stored_parts(
        graph.orchestration_id(),
        graph.revision(),
        task_node_id,
        positive_u64(row.try_get::<i64, _>("state_revision")?)?,
        state,
        nonnegative_u32(row.try_get::<i64, _>("attempt_count")?)?,
        node.limits().max_attempts(),
        TimestampMillis::new(nonnegative_u64(row.try_get::<i64, _>("created_at")?)?),
    )
    .map_err(|_| RepositoryError::InvalidOrchestrationState)
}
fn parse_workspace(value: String) -> Result<WorkspaceId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| RepositoryError::InvalidOrchestrationState)
}
fn parse_task_node_id(value: String) -> Result<TaskNodeId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(TaskNodeId::from_uuid)
        .map_err(|_| RepositoryError::InvalidOrchestrationState)
}
fn positive_i64(value: u64) -> Result<i64, RepositoryError> {
    i64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidOrchestrationState)
}
fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidOrchestrationState)
}
fn positive_u32(value: i64) -> Result<u32, RepositoryError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidOrchestrationState)
}
fn nonnegative_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::InvalidOrchestrationState)
}
fn nonnegative_u32(value: i64) -> Result<u32, RepositoryError> {
    u32::try_from(value).map_err(|_| RepositoryError::InvalidOrchestrationState)
}
