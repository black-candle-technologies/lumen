use std::collections::BTreeSet;

use lumen_core::{
    approval::TimestampMillis,
    capability::{Capability, CapabilityName, ResourceScope},
    egress::{DataClass, DestinationScope, EndpointClass, ProviderId, ProviderRoute},
    identity::{ChannelDestination, ExternalChannelIdentity, PrincipalId, WorkspaceId},
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

    const fn to_core(self) -> EndpointClass {
        match self {
            Self::Local => EndpointClass::Local,
            Self::Remote => EndpointClass::Remote,
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
    priority: u32,
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
        priority: u32,
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
            priority,
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

    pub const fn priority(&self) -> u32 {
        self.priority
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationRevision {
    destination: DestinationScope,
    revision: u64,
    enabled: bool,
    allowed_data_classes: BTreeSet<DataClass>,
    created_at: TimestampMillis,
}

impl DestinationRevision {
    pub fn new(
        destination: DestinationScope,
        revision: u64,
        enabled: bool,
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
            destination,
            revision,
            enabled,
            allowed_data_classes,
            created_at,
        })
    }

    pub const fn destination(&self) -> &DestinationScope {
        &self.destination
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub fn allows(&self, data_class: DataClass) -> bool {
        self.allowed_data_classes.contains(&data_class)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelIdentityMapping {
    external: ExternalChannelIdentity,
    principal: PrincipalId,
    workspace_id: WorkspaceId,
    allowed: bool,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl ChannelIdentityMapping {
    pub fn new(
        external: ExternalChannelIdentity,
        principal: PrincipalId,
        workspace_id: WorkspaceId,
        allowed: bool,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        if updated_at.as_u64() < created_at.as_u64() {
            return Err(RepositoryError::InvalidEgressPolicy);
        }
        Ok(Self {
            external,
            principal,
            workspace_id,
            allowed,
            created_at,
            updated_at,
        })
    }

    pub const fn external(&self) -> &ExternalChannelIdentity {
        &self.external
    }

    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn allowed(&self) -> bool {
        self.allowed
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }

    pub const fn updated_at(&self) -> TimestampMillis {
        self.updated_at
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
        let priority = i64::from(revision.priority);
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
                priority, credential_secret_ref, allowed_data_classes_json, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(revision.provider_id.as_str())
        .bind(revision_number)
        .bind(revision.endpoint_class.as_str())
        .bind(revision.endpoint.as_str())
        .bind(&revision.model)
        .bind(if revision.enabled { 1_i64 } else { 0_i64 })
        .bind(priority)
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
                    priority, credential_secret_ref, allowed_data_classes_json, created_at
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
                u32::try_from(row.try_get::<i64, _>("priority")?)
                    .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                credential,
                serde_json::from_str::<BTreeSet<DataClass>>(
                    &row.try_get::<String, _>("allowed_data_classes_json")?,
                )?,
                TimestampMillis::new(created_at),
            )
        })
        .transpose()
    }

    pub async fn model_provider_routes(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<ProviderRoute>, RepositoryError> {
        let rows = sqlx::query(
            "WITH latest_provider_revisions AS (
                SELECT provider_id, MAX(revision) AS revision
                FROM egress_model_provider_revisions
                GROUP BY provider_id
             ),
             latest_workspace_policies AS (
                SELECT provider_id, MAX(revision) AS revision
                FROM egress_workspace_model_policies
                WHERE workspace_id = ?
                GROUP BY provider_id
             )
             SELECT
                provider.provider_id,
                provider.endpoint_class,
                provider.enabled,
                provider.priority,
                provider.allowed_data_classes_json AS provider_allowed_data_classes_json,
                workspace_policy.allowed_data_classes_json
                    AS workspace_allowed_data_classes_json
             FROM latest_provider_revisions latest_provider
             JOIN egress_model_provider_revisions provider
                ON provider.provider_id = latest_provider.provider_id
               AND provider.revision = latest_provider.revision
             LEFT JOIN latest_workspace_policies latest_workspace
                ON latest_workspace.provider_id = provider.provider_id
             LEFT JOIN egress_workspace_model_policies workspace_policy
                ON workspace_policy.workspace_id = ?
               AND workspace_policy.provider_id = latest_workspace.provider_id
               AND workspace_policy.revision = latest_workspace.revision
             ORDER BY provider.priority ASC, provider.provider_id ASC",
        )
        .bind(workspace_id.to_string())
        .bind(workspace_id.to_string())
        .fetch_all(self.pool())
        .await?;

        rows.into_iter()
            .map(|row| {
                let provider_id = ProviderId::parse(row.try_get::<String, _>("provider_id")?)
                    .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
                let endpoint_class =
                    ModelEndpointClass::parse(&row.try_get::<String, _>("endpoint_class")?)?
                        .to_core();
                let provider_classes = serde_json::from_str::<BTreeSet<DataClass>>(
                    &row.try_get::<String, _>("provider_allowed_data_classes_json")?,
                )?;
                let workspace_classes = row
                    .try_get::<Option<String>, _>("workspace_allowed_data_classes_json")?
                    .map(|json| serde_json::from_str::<BTreeSet<DataClass>>(&json))
                    .transpose()?;
                ProviderRoute::new(
                    provider_id,
                    endpoint_class,
                    row.try_get::<i64, _>("enabled")? == 1,
                    provider_classes,
                    workspace_classes,
                    u32::try_from(row.try_get::<i64, _>("priority")?)
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                )
                .map_err(|_| RepositoryError::InvalidEgressPolicy)
            })
            .collect()
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

    pub async fn append_destination_revision(
        &self,
        revision: &DestinationRevision,
    ) -> Result<(), RepositoryError> {
        let revision_number =
            i64::try_from(revision.revision).map_err(|_| RepositoryError::InvalidEgressPolicy)?;
        let created_at = timestamp_to_i64(revision.created_at)?;
        sqlx::query(
            "INSERT INTO egress_destinations (
                destination, revision, enabled, allowed_data_classes_json, created_at
             ) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(revision.destination.as_str())
        .bind(revision_number)
        .bind(if revision.enabled { 1_i64 } else { 0_i64 })
        .bind(serde_json::to_string(&revision.allowed_data_classes)?)
        .bind(created_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn latest_destination_revision(
        &self,
        destination: DestinationScope,
    ) -> Result<Option<DestinationRevision>, RepositoryError> {
        let row = sqlx::query(
            "SELECT revision, enabled, allowed_data_classes_json, created_at
             FROM egress_destinations
             WHERE destination = ?
             ORDER BY revision DESC LIMIT 1",
        )
        .bind(destination.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            DestinationRevision::new(
                destination.clone(),
                u64::try_from(row.try_get::<i64, _>("revision")?)
                    .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                row.try_get::<i64, _>("enabled")? == 1,
                serde_json::from_str::<BTreeSet<DataClass>>(
                    &row.try_get::<String, _>("allowed_data_classes_json")?,
                )?,
                TimestampMillis::new(
                    u64::try_from(row.try_get::<i64, _>("created_at")?)
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                ),
            )
        })
        .transpose()
    }

    pub async fn enabled_network_egress_capabilities(
        &self,
    ) -> Result<Vec<Capability>, RepositoryError> {
        let rows = sqlx::query(
            "WITH latest_destinations AS (
                SELECT destination, MAX(revision) AS revision
                FROM egress_destinations
                GROUP BY destination
             )
             SELECT destination.destination
             FROM latest_destinations latest
             JOIN egress_destinations destination
               ON destination.destination = latest.destination
              AND destination.revision = latest.revision
             WHERE destination.enabled = 1
             ORDER BY destination.destination ASC",
        )
        .fetch_all(self.pool())
        .await?;

        rows.into_iter()
            .map(|row| {
                let destination = DestinationScope::parse(row.try_get::<String, _>("destination")?)
                    .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
                Ok(Capability::new(
                    CapabilityName::NetworkEgress,
                    ResourceScope::exact("destination", destination.as_str())
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                ))
            })
            .collect()
    }

    pub async fn upsert_channel_identity_mapping(
        &self,
        mapping: &ChannelIdentityMapping,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(mapping.created_at)?;
        let updated_at = timestamp_to_i64(mapping.updated_at)?;
        sqlx::query(
            "INSERT INTO egress_channel_mappings (
                provider, external_workspace_id, channel_id, external_user_id,
                lumen_provider, lumen_subject, workspace_id, allowed, created_at, updated_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(provider, external_workspace_id, channel_id, external_user_id)
             DO UPDATE SET
                lumen_provider = excluded.lumen_provider,
                lumen_subject = excluded.lumen_subject,
                workspace_id = excluded.workspace_id,
                allowed = excluded.allowed,
                updated_at = excluded.updated_at",
        )
        .bind(mapping.external.provider())
        .bind(mapping.external.external_workspace_id())
        .bind(mapping.external.channel_id())
        .bind(mapping.external.external_user_id())
        .bind(mapping.principal.provider())
        .bind(mapping.principal.subject())
        .bind(mapping.workspace_id.to_string())
        .bind(if mapping.allowed { 1_i64 } else { 0_i64 })
        .bind(created_at)
        .bind(updated_at)
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn resolve_external_channel_identity(
        &self,
        external: &ExternalChannelIdentity,
    ) -> Result<Option<ChannelIdentityMapping>, RepositoryError> {
        let row = sqlx::query(
            "SELECT
                lumen_provider, lumen_subject, workspace_id, allowed, created_at, updated_at
             FROM egress_channel_mappings
             WHERE provider = ?
               AND external_workspace_id = ?
               AND channel_id = ?
               AND external_user_id = ?
               AND allowed = 1",
        )
        .bind(external.provider())
        .bind(external.external_workspace_id())
        .bind(external.channel_id())
        .bind(external.external_user_id())
        .fetch_optional(self.pool())
        .await?;

        row.map(|row| {
            ChannelIdentityMapping::new(
                external.clone(),
                PrincipalId::new(
                    row.try_get::<String, _>("lumen_provider")?,
                    row.try_get::<String, _>("lumen_subject")?,
                )
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                WorkspaceId::from_uuid(
                    row.try_get::<String, _>("workspace_id")?
                        .parse()
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                ),
                row.try_get::<i64, _>("allowed")? == 1,
                TimestampMillis::new(
                    u64::try_from(row.try_get::<i64, _>("created_at")?)
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                ),
                TimestampMillis::new(
                    u64::try_from(row.try_get::<i64, _>("updated_at")?)
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                ),
            )
        })
        .transpose()
    }

    pub async fn allowed_channel_send_capabilities(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<Vec<Capability>, RepositoryError> {
        let rows = sqlx::query(
            "SELECT DISTINCT provider, external_workspace_id, channel_id
             FROM egress_channel_mappings
             WHERE workspace_id = ? AND allowed = 1
             ORDER BY provider ASC, external_workspace_id ASC, channel_id ASC",
        )
        .bind(workspace_id.to_string())
        .fetch_all(self.pool())
        .await?;

        rows.into_iter()
            .map(|row| {
                let destination = ChannelDestination::new(
                    row.try_get::<String, _>("provider")?,
                    row.try_get::<String, _>("external_workspace_id")?,
                    row.try_get::<String, _>("channel_id")?,
                )
                .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
                Ok(Capability::new(
                    CapabilityName::ChannelSend,
                    ResourceScope::exact("channel", destination.as_scope_value())
                        .map_err(|_| RepositoryError::InvalidEgressPolicy)?,
                ))
            })
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    fn model_provider_revision_from_parts(
        provider_id: ProviderId,
        revision: u64,
        endpoint_class: ModelEndpointClass,
        endpoint: DestinationScope,
        model: String,
        enabled: bool,
        priority: u32,
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
            priority,
            credential_secret_ref,
            allowed_data_classes,
            created_at,
        )
    }
}
