use std::collections::BTreeSet;

use lumen_core::{
    approval::TimestampMillis,
    egress::{DataClass, DestinationScope, ProviderId},
    identity::WorkspaceId,
    secret::SecretRefId,
};
use sqlx::Row;

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelEndpointClass {
    Local,
    Remote,
}

impl ModelEndpointClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }

    fn parse(value: &str) -> Result<Self, RepositoryError> {
        match value {
            "local" => Ok(Self::Local),
            "remote" => Ok(Self::Remote),
            _ => Err(RepositoryError::InvalidEgressPolicy),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelProviderRevision {
    provider_id: ProviderId,
    revision: u64,
    endpoint_class: ModelEndpointClass,
    endpoint: DestinationScope,
    model: String,
    enabled: bool,
    credential_secret_ref: Option<SecretRefId>,
    allowed_data_classes: BTreeSet<DataClass>,
    created_at: TimestampMillis,
}

impl ModelProviderRevision {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderId,
        revision: u64,
        endpoint_class: ModelEndpointClass,
        endpoint: DestinationScope,
        model: impl Into<String>,
        enabled: bool,
        credential_secret_ref: Option<SecretRefId>,
        allowed_data_classes: impl IntoIterator<Item = DataClass>,
        created_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        let model = model.into();
        let allowed_data_classes = allowed_data_classes.into_iter().collect::<BTreeSet<_>>();
        if revision == 0
            || model.is_empty()
            || model.len() > 256
            || model.trim() != model
            || model.chars().any(char::is_control)
            || allowed_data_classes.is_empty()
            || allowed_data_classes.contains(&DataClass::Secret)
        {
            return Err(RepositoryError::InvalidEgressPolicy);
        }
        Ok(Self {
            provider_id,
            revision,
            endpoint_class,
            endpoint,
            model,
            enabled,
            credential_secret_ref,
            allowed_data_classes,
            created_at,
        })
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn endpoint_class(&self) -> ModelEndpointClass {
        self.endpoint_class
    }

    pub const fn endpoint(&self) -> &DestinationScope {
        &self.endpoint
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn credential_secret_ref(&self) -> Option<SecretRefId> {
        self.credential_secret_ref
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub fn allows(&self, data_class: DataClass) -> bool {
        self.allowed_data_classes.contains(&data_class)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceModelEgressRevision {
    workspace_id: WorkspaceId,
    provider_id: ProviderId,
    revision: u64,
    allowed_data_classes: BTreeSet<DataClass>,
    created_at: TimestampMillis,
}

impl WorkspaceModelEgressRevision {
    pub fn new(
        workspace_id: WorkspaceId,
        provider_id: ProviderId,
        revision: u64,
        allowed_data_classes: impl IntoIterator<Item = DataClass>,
        created_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        let allowed_data_classes = allowed_data_classes.into_iter().collect::<BTreeSet<_>>();
        if revision == 0
            || allowed_data_classes.is_empty()
            || allowed_data_classes.contains(&DataClass::Secret)
        {
            return Err(RepositoryError::InvalidEgressPolicy);
        }
        Ok(Self {
            workspace_id,
            provider_id,
            revision,
            allowed_data_classes,
            created_at,
        })
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub fn allows(&self, data_class: DataClass) -> bool {
        self.allowed_data_classes.contains(&data_class)
    }
}

impl Database {
    pub async fn append_model_provider_revision(
        &self,
        revision: &ModelProviderRevision,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(revision.created_at)?;
        let revision_number =
            i64::try_from(revision.revision).map_err(|_| RepositoryError::InvalidEgressPolicy)?;
        let allowed = serde_json::to_string(&revision.allowed_data_classes)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO egress_model_providers (provider_id, created_at)
             VALUES (?, ?)",
        )
        .bind(revision.provider_id.as_str())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO egress_model_provider_revisions (
                provider_id, revision, endpoint_class, endpoint_url, model, enabled,
                credential_secret_ref, allowed_data_classes_json, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(revision.provider_id.as_str())
        .bind(revision_number)
        .bind(revision.endpoint_class.as_str())
        .bind(revision.endpoint.as_str())
        .bind(&revision.model)
        .bind(if revision.enabled { 1_i64 } else { 0_i64 })
        .bind(revision.credential_secret_ref.map(|id| id.to_string()))
        .bind(allowed)
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn latest_model_provider_revision(
        &self,
        provider_id: ProviderId,
    ) -> Result<Option<ModelProviderRevision>, RepositoryError> {
        let row = sqlx::query(
            "SELECT revision, endpoint_class, endpoint_url, model, enabled,
                    credential_secret_ref, allowed_data_classes_json, created_at
             FROM egress_model_provider_revisions
             WHERE provider_id = ? ORDER BY revision DESC LIMIT 1",
        )
        .bind(provider_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let revision = u64::try_from(row.try_get::<i64, _>("revision")?)
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
            let created_at = u64::try_from(row.try_get::<i64, _>("created_at")?)
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
            let endpoint = DestinationScope::parse(row.try_get::<String, _>("endpoint_url")?)
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
            let credential = row
                .try_get::<Option<String>, _>("credential_secret_ref")?
                .map(|value| SecretRefId::parse(&value))
                .transpose()
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
            Self::model_provider_revision_from_parts(
                provider_id.clone(),
                revision,
                ModelEndpointClass::parse(&row.try_get::<String, _>("endpoint_class")?)?,
                endpoint,
                row.try_get::<String, _>("model")?,
                row.try_get::<i64, _>("enabled")? == 1,
                credential,
                serde_json::from_str::<BTreeSet<DataClass>>(
                    &row.try_get::<String, _>("allowed_data_classes_json")?,
                )?,
                TimestampMillis::new(created_at),
            )
        })
        .transpose()
    }

    pub async fn append_workspace_model_egress_revision(
        &self,
        revision: &WorkspaceModelEgressRevision,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(revision.created_at)?;
        let revision_number =
            i64::try_from(revision.revision).map_err(|_| RepositoryError::InvalidEgressPolicy)?;
        sqlx::query(
            "INSERT INTO egress_workspace_model_policies (
                workspace_id, provider_id, revision, allowed_data_classes_json, created_at
             ) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(revision.workspace_id.to_string())
        .bind(revision.provider_id.as_str())
        .bind(revision_number)
        .bind(serde_json::to_string(&revision.allowed_data_classes)?)
        .bind(created_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn latest_workspace_model_egress_revision(
        &self,
        workspace_id: WorkspaceId,
        provider_id: ProviderId,
    ) -> Result<Option<WorkspaceModelEgressRevision>, RepositoryError> {
        let row = sqlx::query(
            "SELECT revision, allowed_data_classes_json, created_at
             FROM egress_workspace_model_policies
             WHERE workspace_id = ? AND provider_id = ?
             ORDER BY revision DESC LIMIT 1",
        )
        .bind(workspace_id.to_string())
        .bind(provider_id.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let revision = u64::try_from(row.try_get::<i64, _>("revision")?)
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
            let created_at = u64::try_from(row.try_get::<i64, _>("created_at")?)
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
            WorkspaceModelEgressRevision::new(
                workspace_id,
                provider_id.clone(),
                revision,
                serde_json::from_str::<BTreeSet<DataClass>>(
                    &row.try_get::<String, _>("allowed_data_classes_json")?,
                )?,
                TimestampMillis::new(created_at),
            )
        })
        .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    fn model_provider_revision_from_parts(
        provider_id: ProviderId,
        revision: u64,
        endpoint_class: ModelEndpointClass,
        endpoint: DestinationScope,
        model: String,
        enabled: bool,
        credential_secret_ref: Option<SecretRefId>,
        allowed_data_classes: BTreeSet<DataClass>,
        created_at: TimestampMillis,
    ) -> Result<ModelProviderRevision, RepositoryError> {
        ModelProviderRevision::new(
            provider_id,
            revision,
            endpoint_class,
            endpoint,
            model,
            enabled,
            credential_secret_ref,
            allowed_data_classes,
            created_at,
        )
    }
}
