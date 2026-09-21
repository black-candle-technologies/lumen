use crate::{Database, RepositoryError, timestamp_to_i64};
use lumen_core::{
    action::CanonicalValue,
    approval::TimestampMillis,
    context::{
        CompartmentId, ContextDigest, ContextSource, ContextSourceId, ModelDataPolicy,
        ProjectionId, ProjectionTaskKey, SourceProvenance, SourceProvenanceKind, TaskProjection,
        data_class_str, parse_data_class,
    },
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
    provider::{ModelProfileId, ModelTrustZone},
};
use sqlx::Row;
use std::collections::BTreeSet;
use uuid::Uuid;
impl Database {
    pub async fn append_context_source(
        &self,
        source: &ContextSource,
    ) -> Result<(), RepositoryError> {
        sqlx::query(
            "INSERT INTO context_sources (
source_id, workspace_id, classification, compartments_json,
provenance_kind, provenance_reference, content_json, content_digest,
created_by_provider, created_by_subject, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(source.id().to_string())
        .bind(source.workspace_id().to_string())
        .bind(data_class_str(source.classification()))
        .bind(serde_json::to_string(source.compartments())?)
        .bind(source.provenance().kind().as_str())
        .bind(source.provenance().reference())
        .bind(serde_json::to_string(source.content())?)
        .bind(source.digest().as_str())
        .bind(source.created_by().provider())
        .bind(source.created_by().subject())
        .bind(timestamp_to_i64(source.created_at())?)
        .execute(self.pool())
        .await?;
        Ok(())
    }
    pub async fn context_source(
        &self,
        source_id: ContextSourceId,
    ) -> Result<Option<ContextSource>, RepositoryError> {
        let row = sqlx::query(
            "SELECT
source_id, workspace_id, classification, compartments_json,
provenance_kind, provenance_reference, content_json, content_digest,
created_by_provider, created_by_subject, created_at
FROM context_sources
WHERE source_id = ?",
        )
        .bind(source_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        row.map(context_source_from_row).transpose()
    }
    pub async fn append_model_data_policy(
        &self,
        policy: &ModelDataPolicy,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let stored_trust = sqlx::query_scalar::<_, String>(
            "SELECT trust_zone
FROM model_profile_revisions
WHERE profile_id = ? AND revision = ? AND enabled = 1",
        )
        .bind(policy.model_profile_id().as_str())
        .bind(
            i64::try_from(policy.model_profile_revision())
                .map_err(|_| RepositoryError::InvalidContextState)?,
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RepositoryError::InvalidContextState)?;
        if ModelTrustZone::parse(&stored_trust) != Some(policy.model_trust_zone()) {
            return Err(RepositoryError::InvalidContextState);
        }
        let latest = sqlx::query_scalar::<_, i64>(
            "SELECT COALESCE(MAX(revision), 0)
FROM model_data_policy_revisions
WHERE workspace_id = ? AND profile_id = ?",
        )
        .bind(policy.workspace_id().to_string())
        .bind(policy.model_profile_id().as_str())
        .fetch_one(&mut *tx)
        .await?;
        let expected = u64::try_from(latest)
            .ok()
            .and_then(|value| value.checked_add(1));
        if expected != Some(policy.revision()) {
            return Err(RepositoryError::InvalidContextState);
        }
        sqlx::query(
            "INSERT INTO model_data_policy_revisions (
workspace_id, profile_id, revision, profile_revision, trust_zone,
allowed_data_classes_json, allowed_compartments_json,
allow_uncompartmented, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(policy.workspace_id().to_string())
        .bind(policy.model_profile_id().as_str())
        .bind(i64::try_from(policy.revision()).map_err(|_| RepositoryError::InvalidContextState)?)
        .bind(
            i64::try_from(policy.model_profile_revision())
                .map_err(|_| RepositoryError::InvalidContextState)?,
        )
        .bind(policy.model_trust_zone().as_str())
        .bind(serde_json::to_string(policy.allowed_data_classes())?)
        .bind(serde_json::to_string(policy.allowed_compartments())?)
        .bind(policy.allow_uncompartmented())
        .bind(timestamp_to_i64(policy.created_at())?)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn model_data_policy_revision(
        &self,
        workspace_id: WorkspaceId,
        profile_id: &ModelProfileId,
        revision: u64,
    ) -> Result<Option<ModelDataPolicy>, RepositoryError> {
        let row = sqlx::query(
            "SELECT
workspace_id, profile_id, revision, profile_revision, trust_zone,
allowed_data_classes_json, allowed_compartments_json,
allow_uncompartmented, created_at
FROM model_data_policy_revisions
WHERE workspace_id = ? AND profile_id = ? AND revision = ?",
        )
        .bind(workspace_id.to_string())
        .bind(profile_id.as_str())
        .bind(i64::try_from(revision).map_err(|_| RepositoryError::InvalidContextState)?)
        .fetch_optional(self.pool())
        .await?;
        row.map(model_data_policy_from_row).transpose()
    }
    pub async fn latest_model_data_policy(
        &self,
        workspace_id: WorkspaceId,
        profile_id: &ModelProfileId,
    ) -> Result<Option<ModelDataPolicy>, RepositoryError> {
        let row = sqlx::query(
            "SELECT
workspace_id, profile_id, revision, profile_revision, trust_zone,
allowed_data_classes_json, allowed_compartments_json,
allow_uncompartmented, created_at
FROM model_data_policy_revisions
WHERE workspace_id = ? AND profile_id = ?
ORDER BY revision DESC
LIMIT 1",
        )
        .bind(workspace_id.to_string())
        .bind(profile_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(model_data_policy_from_row).transpose()
    }
    pub async fn insert_task_projection(
        &self,
        projection: &TaskProjection,
    ) -> Result<(), RepositoryError> {
        projection
            .verify_digest()
            .map_err(|_| RepositoryError::InvalidContextState)?;
        let policy = self
            .model_data_policy_revision(
                projection.workspace_id(),
                projection.model_profile_id(),
                projection.policy_revision(),
            )
            .await?
            .ok_or(RepositoryError::InvalidContextState)?;
        let profile = self
            .latest_model_profile(projection.model_profile_id())
            .await?
            .ok_or(RepositoryError::InvalidContextState)?;
        if profile.revision() != projection.model_profile_revision() {
            return Err(RepositoryError::InvalidContextState);
        }
        projection
            .validate_for(&profile, &policy)
            .map_err(|_| RepositoryError::InvalidContextState)?;
        let mut tx = self.pool().begin().await?;
        for projected in projection.sources() {
            let row = sqlx::query(
                "SELECT workspace_id, content_digest
FROM context_sources
WHERE source_id = ?",
            )
            .bind(projected.source_id().to_string())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(RepositoryError::InvalidContextState)?;
            let workspace: String = row.try_get("workspace_id")?;
            let digest: String = row.try_get("content_digest")?;
            if workspace != projection.workspace_id().to_string()
                || digest != projected.source_digest().as_str()
            {
                return Err(RepositoryError::InvalidContextState);
            }
        }
        sqlx::query(
            "INSERT INTO task_projections (
projection_id, workspace_id, task_key, profile_id, profile_revision,
policy_revision, classification, compartments_json,
payload_json, payload_digest, created_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(projection.id().to_string())
        .bind(projection.workspace_id().to_string())
        .bind(projection.task_key().as_str())
        .bind(projection.model_profile_id().as_str())
        .bind(
            i64::try_from(projection.model_profile_revision())
                .map_err(|_| RepositoryError::InvalidContextState)?,
        )
        .bind(
            i64::try_from(projection.policy_revision())
                .map_err(|_| RepositoryError::InvalidContextState)?,
        )
        .bind(data_class_str(projection.classification()))
        .bind(serde_json::to_string(projection.compartments())?)
        .bind(projection.serialized_payload())
        .bind(projection.digest().as_str())
        .bind(timestamp_to_i64(projection.created_at())?)
        .execute(&mut *tx)
        .await?;
        for (ordinal, projected) in projection.sources().iter().enumerate() {
            sqlx::query(
                "INSERT INTO task_projection_sources (
projection_id, ordinal, source_id, source_digest
) VALUES (?, ?, ?, ?)",
            )
            .bind(projection.id().to_string())
            .bind(i64::try_from(ordinal).map_err(|_| RepositoryError::InvalidContextState)?)
            .bind(projected.source_id().to_string())
            .bind(projected.source_digest().as_str())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn task_projection(
        &self,
        projection_id: ProjectionId,
    ) -> Result<Option<TaskProjection>, RepositoryError> {
        let row = sqlx::query(
            "SELECT
projection_id, workspace_id, task_key, profile_id, profile_revision,
policy_revision, classification, compartments_json,
payload_json, payload_digest, created_at
FROM task_projections
WHERE projection_id = ?",
        )
        .bind(projection_id.to_string())
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let workspace_id = parse_workspace(row.try_get::<String, _>("workspace_id")?)?;
        let stored_classification = parse_data_class(&row.try_get::<String, _>("classification")?)
            .ok_or(RepositoryError::InvalidContextState)?;
        let stored_compartments = serde_json::from_str::<BTreeSet<CompartmentId>>(
            &row.try_get::<String, _>("compartments_json")?,
        )?;
        let stored_payload: String = row.try_get("payload_json")?;
        let stored_digest = ContextDigest::parse(row.try_get::<String, _>("payload_digest")?)
            .map_err(|_| RepositoryError::InvalidContextState)?;
        let source_rows = sqlx::query(
            "SELECT source_id, source_digest
FROM task_projection_sources
WHERE projection_id = ?
ORDER BY ordinal ASC",
        )
        .bind(projection_id.to_string())
        .fetch_all(self.pool())
        .await?;
        if source_rows.is_empty() {
            return Err(RepositoryError::InvalidContextState);
        }
        let mut sources = Vec::with_capacity(source_rows.len());
        for source_row in source_rows {
            let source_id = parse_context_source_id(source_row.try_get::<String, _>("source_id")?)?;
            let expected = source_row.try_get::<String, _>("source_digest")?;
            let source = self
                .context_source(source_id)
                .await?
                .ok_or(RepositoryError::InvalidContextState)?;
            if source.digest().as_str() != expected {
                return Err(RepositoryError::InvalidContextState);
            }
            sources.push(source);
        }
        let projection = TaskProjection::from_stored_parts(
            projection_id,
            workspace_id,
            ProjectionTaskKey::parse(row.try_get::<String, _>("task_key")?)
                .map_err(|_| RepositoryError::InvalidContextState)?,
            ModelProfileId::parse(row.try_get::<String, _>("profile_id")?)
                .map_err(|_| RepositoryError::InvalidContextState)?,
            positive_u64(row.try_get::<i64, _>("profile_revision")?)?,
            positive_u64(row.try_get::<i64, _>("policy_revision")?)?,
            sources,
            TimestampMillis::new(nonnegative_u64(row.try_get::<i64, _>("created_at")?)?),
            stored_digest,
        )
        .map_err(|_| RepositoryError::InvalidContextState)?;
        if projection.classification() != stored_classification
            || projection.compartments() != &stored_compartments
            || projection.serialized_payload() != stored_payload
        {
            return Err(RepositoryError::InvalidContextState);
        }
        Ok(Some(projection))
    }
}
fn context_source_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ContextSource, RepositoryError> {
    let source_id = parse_context_source_id(row.try_get::<String, _>("source_id")?)?;
    let workspace_id = parse_workspace(row.try_get::<String, _>("workspace_id")?)?;
    let classification = parse_data_class(&row.try_get::<String, _>("classification")?)
        .ok_or(RepositoryError::InvalidContextState)?;
    let compartments = serde_json::from_str::<BTreeSet<CompartmentId>>(
        &row.try_get::<String, _>("compartments_json")?,
    )?;
    let provenance_kind =
        SourceProvenanceKind::parse(&row.try_get::<String, _>("provenance_kind")?)
            .ok_or(RepositoryError::InvalidContextState)?;
    let provenance = SourceProvenance::new(
        provenance_kind,
        row.try_get::<String, _>("provenance_reference")?,
    )
    .map_err(|_| RepositoryError::InvalidContextState)?;
    let content =
        serde_json::from_str::<CanonicalValue>(&row.try_get::<String, _>("content_json")?)?;
    let digest = ContextDigest::parse(row.try_get::<String, _>("content_digest")?)
        .map_err(|_| RepositoryError::InvalidContextState)?;
    let created_by = PrincipalId::new(
        row.try_get::<String, _>("created_by_provider")?,
        row.try_get::<String, _>("created_by_subject")?,
    )
    .map_err(|_| RepositoryError::InvalidContextState)?;
    ContextSource::from_stored_parts(
        source_id,
        workspace_id,
        classification,
        compartments,
        provenance,
        content,
        created_by,
        TimestampMillis::new(nonnegative_u64(row.try_get::<i64, _>("created_at")?)?),
        digest,
    )
    .map_err(|_| RepositoryError::InvalidContextState)
}
fn model_data_policy_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<ModelDataPolicy, RepositoryError> {
    let trust_zone = ModelTrustZone::parse(&row.try_get::<String, _>("trust_zone")?)
        .ok_or(RepositoryError::InvalidContextState)?;
    ModelDataPolicy::new(
        parse_workspace(row.try_get::<String, _>("workspace_id")?)?,
        ModelProfileId::parse(row.try_get::<String, _>("profile_id")?)
            .map_err(|_| RepositoryError::InvalidContextState)?,
        positive_u64(row.try_get::<i64, _>("profile_revision")?)?,
        trust_zone,
        positive_u64(row.try_get::<i64, _>("revision")?)?,
        serde_json::from_str::<BTreeSet<DataClass>>(
            &row.try_get::<String, _>("allowed_data_classes_json")?,
        )?,
        serde_json::from_str::<BTreeSet<CompartmentId>>(
            &row.try_get::<String, _>("allowed_compartments_json")?,
        )?,
        row.try_get::<bool, _>("allow_uncompartmented")?,
        TimestampMillis::new(nonnegative_u64(row.try_get::<i64, _>("created_at")?)?),
    )
    .map_err(|_| RepositoryError::InvalidContextState)
}
fn parse_workspace(value: String) -> Result<WorkspaceId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(WorkspaceId::from_uuid)
        .map_err(|_| RepositoryError::InvalidContextState)
}
fn parse_context_source_id(value: String) -> Result<ContextSourceId, RepositoryError> {
    Uuid::parse_str(&value)
        .map(ContextSourceId::from_uuid)
        .map_err(|_| RepositoryError::InvalidContextState)
}
fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidContextState)
}
fn nonnegative_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::InvalidContextState)
}
#[cfg(test)]
mod tests {
    use super::*;
    use lumen_core::{
        context::{CompartmentId, ContextSourceId, ProjectionId, SourceProvenanceKind},
        egress::ProviderId,
        provider::{
            LocalRuntimeKind, ModelCapabilities, ModelCapability, ModelProfile, ModelTrustZone,
            ProviderConfig,
        },
    };
    #[tokio::test]
    async fn secure_context_round_trip_is_digest_and_policy_pinned() {
        let db = Database::connect_in_memory().await.unwrap();
        let workspace = WorkspaceId::new();
        let actor = PrincipalId::new("local", "operator").unwrap();
        sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,'Test',0)")
            .bind(workspace.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO identities(provider,subject,created_at) VALUES(?,?,0)")
            .bind(actor.provider())
            .bind(actor.subject())
            .execute(db.pool())
            .await
            .unwrap();
        let provider = ProviderConfig::local_openai_compatible(
            ProviderId::parse("local").unwrap(),
            1,
            "http://127.0.0.1:11434/v1/",
            LocalRuntimeKind::Ollama,
            true,
            None,
        )
        .unwrap();
        db.append_provider_config(&provider, TimestampMillis::new(1))
            .await
            .unwrap();
        let profile = ModelProfile::new(
            ModelProfileId::parse("coder").unwrap(),
            1,
            provider.id().clone(),
            1,
            "qwen-coder",
            true,
            ModelCapabilities::new([ModelCapability::Text]),
            32_768,
            ModelTrustZone::LocalRestricted,
            1,
            0,
        )
        .unwrap();
        db.append_model_profile(&profile, TimestampMillis::new(2))
            .await
            .unwrap();
        let source = ContextSource::new(
            ContextSourceId::new(),
            workspace,
            DataClass::Workspace,
            [CompartmentId::parse("workspace/source-code").unwrap()],
            SourceProvenance::new(SourceProvenanceKind::File, "src/lib.rs").unwrap(),
            CanonicalValue::from("pub fn example() {}"),
            actor,
            TimestampMillis::new(3),
        )
        .unwrap();
        db.append_context_source(&source).await.unwrap();
        let policy = ModelDataPolicy::new(
            workspace,
            profile.id().clone(),
            1,
            profile.trust_zone(),
            1,
            [DataClass::Public, DataClass::Workspace],
            [CompartmentId::parse("workspace/source-code").unwrap()],
            true,
            TimestampMillis::new(4),
        )
        .unwrap();
        db.append_model_data_policy(&policy).await.unwrap();
        let projection = TaskProjection::build(
            ProjectionId::new(),
            ProjectionTaskKey::parse("backend").unwrap(),
            &profile,
            &policy,
            vec![source],
            TimestampMillis::new(5),
        )
        .unwrap();
        db.insert_task_projection(&projection).await.unwrap();
        let loaded = db.task_projection(projection.id()).await.unwrap().unwrap();
        assert_eq!(loaded.digest(), projection.digest());
        assert_eq!(loaded.serialized_payload(), projection.serialized_payload());
        assert_eq!(
            db.latest_model_data_policy(workspace, profile.id())
                .await
                .unwrap()
                .unwrap()
                .revision(),
            1
        );
    }
    #[tokio::test]
    async fn projection_insert_rejects_unpersisted_source() {
        let db = Database::connect_in_memory().await.unwrap();
        let workspace = WorkspaceId::new();
        let actor = PrincipalId::new("local", "operator").unwrap();
        sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,'Test',0)")
            .bind(workspace.to_string())
            .execute(db.pool())
            .await
            .unwrap();
        sqlx::query("INSERT INTO identities(provider,subject,created_at) VALUES(?,?,0)")
            .bind(actor.provider())
            .bind(actor.subject())
            .execute(db.pool())
            .await
            .unwrap();
        let provider = ProviderConfig::local_openai_compatible(
            ProviderId::parse("local").unwrap(),
            1,
            "http://127.0.0.1:11434/v1/",
            LocalRuntimeKind::Ollama,
            true,
            None,
        )
        .unwrap();
        db.append_provider_config(&provider, TimestampMillis::new(1))
            .await
            .unwrap();
        let profile = ModelProfile::new(
            ModelProfileId::parse("coder").unwrap(),
            1,
            provider.id().clone(),
            1,
            "qwen-coder",
            true,
            ModelCapabilities::new([ModelCapability::Text]),
            32_768,
            ModelTrustZone::LocalRestricted,
            1,
            0,
        )
        .unwrap();
        db.append_model_profile(&profile, TimestampMillis::new(2))
            .await
            .unwrap();
        let policy = ModelDataPolicy::new(
            workspace,
            profile.id().clone(),
            1,
            profile.trust_zone(),
            1,
            [DataClass::Workspace],
            [CompartmentId::parse("workspace/source-code").unwrap()],
            true,
            TimestampMillis::new(3),
        )
        .unwrap();
        db.append_model_data_policy(&policy).await.unwrap();
        let source = ContextSource::new(
            ContextSourceId::new(),
            workspace,
            DataClass::Workspace,
            [CompartmentId::parse("workspace/source-code").unwrap()],
            SourceProvenance::new(SourceProvenanceKind::File, "missing.rs").unwrap(),
            CanonicalValue::from("missing"),
            actor,
            TimestampMillis::new(4),
        )
        .unwrap();
        let projection = TaskProjection::build(
            ProjectionId::new(),
            ProjectionTaskKey::parse("backend").unwrap(),
            &profile,
            &policy,
            vec![source],
            TimestampMillis::new(5),
        )
        .unwrap();
        assert!(matches!(
            db.insert_task_projection(&projection).await,
            Err(RepositoryError::InvalidContextState)
        ));
    }
}
