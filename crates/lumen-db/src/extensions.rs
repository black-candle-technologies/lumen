use std::collections::BTreeMap;

use lumen_core::{
    approval::TimestampMillis,
    capability::{Capability, CapabilityName, CapabilitySet, ResourceScope, WorkspacePath},
    extension::{
        ExtensionFailureClass, ManifestPath, PluginComponentId, PluginId, PluginManifest,
        PluginVersion, Sha256Digest, canonical_grant_set_digest,
    },
    identity::{PrincipalId, WorkspaceId},
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::Row;
use uuid::Uuid;

use crate::{Database, RepositoryError, timestamp_to_i64};

#[derive(Clone, Debug)]
pub struct StagedPluginPackage {
    id: Uuid,
    manifest: PluginManifest,
    quarantine_path: String,
    file_hashes: BTreeMap<String, Sha256Digest>,
    package_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    requested_by: PrincipalId,
    created_at: TimestampMillis,
}

impl StagedPluginPackage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        manifest: PluginManifest,
        quarantine_path: impl Into<String>,
        file_hashes: BTreeMap<String, Sha256Digest>,
        package_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
        requested_by: PrincipalId,
        created_at: TimestampMillis,
    ) -> Result<Self, RepositoryError> {
        let quarantine_path = quarantine_path.into();
        ManifestPath::parse(&quarantine_path)
            .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?;
        if file_hashes.is_empty()
            || !file_hashes.contains_key("lumen-plugin.toml")
            || file_hashes
                .get(manifest.runtime().entrypoint().as_str())
                .is_none_or(|digest| digest != manifest.integrity().artifact())
        {
            return Err(RepositoryError::InvalidPluginPackage(
                "file hashes do not contain the declared manifest and artifact".into(),
            ));
        }
        for path in file_hashes.keys() {
            ManifestPath::parse(path)
                .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?;
        }
        Ok(Self {
            id,
            manifest,
            quarantine_path,
            file_hashes,
            package_digest,
            manifest_digest,
            requested_by,
            created_at,
        })
    }

    pub const fn id(&self) -> Uuid {
        self.id
    }

    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn quarantine_path(&self) -> &str {
        &self.quarantine_path
    }

    pub const fn package_digest(&self) -> &Sha256Digest {
        &self.package_digest
    }

    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    pub const fn file_hashes(&self) -> &BTreeMap<String, Sha256Digest> {
        &self.file_hashes
    }

    pub const fn requested_by(&self) -> &PrincipalId {
        &self.requested_by
    }

    pub const fn created_at(&self) -> TimestampMillis {
        self.created_at
    }
}

#[derive(Clone, Debug)]
pub struct InstalledPluginVersion {
    manifest: PluginManifest,
    artifact_path: String,
    package_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    artifact_quarantined: bool,
}

impl InstalledPluginVersion {
    pub const fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    pub fn artifact_path(&self) -> &str {
        &self.artifact_path
    }

    pub const fn package_digest(&self) -> &Sha256Digest {
        &self.package_digest
    }

    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    pub const fn is_artifact_quarantined(&self) -> bool {
        self.artifact_quarantined
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallResult {
    Installed,
    AlreadyInstalled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PluginWorkspaceState {
    Enabled,
    Disabled,
    HealthQuarantine,
}

impl PluginWorkspaceState {
    fn parse(value: &str) -> Result<Self, RepositoryError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            "health_quarantine" => Ok(Self::HealthQuarantine),
            _ => Err(RepositoryError::PluginStateConflict),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginGrantScope {
    Global,
    Workspace(WorkspaceId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginGrantRevision {
    revision: u64,
    digest: Sha256Digest,
    grants: CapabilitySet,
}

impl PluginGrantRevision {
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    pub fn allows(&self, capability: &Capability) -> bool {
        self.grants.allows(capability)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = &Capability> {
        self.grants.capabilities()
    }
}

impl PluginGrantScope {
    fn parts(&self) -> (&'static str, String) {
        match self {
            Self::Global => ("global", "*".into()),
            Self::Workspace(workspace) => ("workspace", workspace.to_string()),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PluginSettingScope {
    Global,
    Workspace(WorkspaceId),
    User(PrincipalId),
    Agent(String),
}

impl PluginSettingScope {
    fn parts(&self) -> Result<(&'static str, String), RepositoryError> {
        match self {
            Self::Global => Ok(("global", "*".into())),
            Self::Workspace(workspace) => Ok(("workspace", workspace.to_string())),
            Self::User(principal) => Ok((
                "user",
                format!("{}:{}", principal.provider(), principal.subject()),
            )),
            Self::Agent(agent) => {
                PluginComponentId::parse(agent)
                    .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?;
                Ok(("agent", agent.clone()))
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginSettingRevision {
    config_version: u64,
    config: Value,
    schema_digest: Sha256Digest,
    settings_digest: Sha256Digest,
}

impl PluginSettingRevision {
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    pub const fn config(&self) -> &Value {
        &self.config
    }

    pub const fn schema_digest(&self) -> &Sha256Digest {
        &self.schema_digest
    }

    pub const fn settings_digest(&self) -> &Sha256Digest {
        &self.settings_digest
    }
}

impl Database {
    pub async fn staged_plugin_package(
        &self,
        id: Uuid,
    ) -> Result<Option<StagedPluginPackage>, RepositoryError> {
        let row = sqlx::query(
            "SELECT manifest_json, quarantine_path, file_hashes_json, package_digest,
                    manifest_digest, requested_by_provider, requested_by_subject, created_at
             FROM plugin_staged_packages WHERE id = ?",
        )
        .bind(id.to_string())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let created_at = row.try_get::<i64, _>("created_at")?;
            let created_at = u64::try_from(created_at)
                .map_err(|_| RepositoryError::InvalidPluginPackage("invalid timestamp".into()))?;
            StagedPluginPackage::new(
                id,
                serde_json::from_str(&row.try_get::<String, _>("manifest_json")?)?,
                row.try_get::<String, _>("quarantine_path")?,
                serde_json::from_str(&row.try_get::<String, _>("file_hashes_json")?)?,
                Sha256Digest::parse(row.try_get::<String, _>("package_digest")?)
                    .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?,
                Sha256Digest::parse(row.try_get::<String, _>("manifest_digest")?)
                    .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?,
                PrincipalId::new(
                    row.try_get::<String, _>("requested_by_provider")?,
                    row.try_get::<String, _>("requested_by_subject")?,
                )
                .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?,
                TimestampMillis::new(created_at),
            )
        })
        .transpose()
    }

    pub async fn staged_plugin_package_by_digest(
        &self,
        package_digest: Sha256Digest,
    ) -> Result<Option<StagedPluginPackage>, RepositoryError> {
        let id: Option<String> =
            sqlx::query_scalar("SELECT id FROM plugin_staged_packages WHERE package_digest = ?")
                .bind(package_digest.as_str())
                .fetch_optional(self.pool())
                .await?;
        let Some(id) = id else { return Ok(None) };
        let id = Uuid::parse_str(&id)
            .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?;
        self.staged_plugin_package(id).await
    }

    pub async fn installed_plugin_version(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
    ) -> Result<Option<InstalledPluginVersion>, RepositoryError> {
        let row = sqlx::query(
            "SELECT manifest_json, artifact_path, package_digest, manifest_digest,
                    artifact_digest, artifact_state
             FROM plugin_versions WHERE plugin_id = ? AND version = ?",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            let digest = |column| -> Result<Sha256Digest, RepositoryError> {
                Sha256Digest::parse(row.try_get::<String, _>(column)?)
                    .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))
            };
            let state: String = row.try_get("artifact_state")?;
            if !matches!(state.as_str(), "installed" | "artifact_quarantine") {
                return Err(RepositoryError::PluginStateConflict);
            }
            Ok(InstalledPluginVersion {
                manifest: serde_json::from_str(&row.try_get::<String, _>("manifest_json")?)?,
                artifact_path: row.try_get("artifact_path")?,
                package_digest: digest("package_digest")?,
                manifest_digest: digest("manifest_digest")?,
                artifact_digest: digest("artifact_digest")?,
                artifact_quarantined: state == "artifact_quarantine",
            })
        })
        .transpose()
    }

    pub async fn latest_plugin_grants(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
        component: PluginComponentId,
        scope: PluginGrantScope,
    ) -> Result<Option<PluginGrantRevision>, RepositoryError> {
        let (scope_type, scope_id) = scope.parts();
        let row = sqlx::query(
            "SELECT revision, grant_set_digest FROM plugin_grant_revisions
             WHERE plugin_id = ? AND plugin_version = ? AND component_id = ?
               AND scope_type = ? AND scope_id = ? ORDER BY revision DESC LIMIT 1",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(component.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .fetch_optional(self.pool())
        .await?;
        let Some(row) = row else { return Ok(None) };
        let revision: i64 = row.try_get("revision")?;
        let rows = sqlx::query(
            "SELECT capability_name, resource_json FROM plugin_capability_grants
             WHERE plugin_id = ? AND plugin_version = ? AND component_id = ?
               AND scope_type = ? AND scope_id = ? AND revision = ?",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(component.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .bind(revision)
        .fetch_all(self.pool())
        .await?;
        let mut grants = Vec::new();
        for grant in rows {
            let name = CapabilityName::parse(&grant.try_get::<String, _>("capability_name")?)
                .ok_or(RepositoryError::PluginGrantConflict)?;
            grants.push(Capability::new(
                name,
                parse_resource_scope(&grant.try_get::<String, _>("resource_json")?)?,
            ));
        }
        Ok(Some(PluginGrantRevision {
            revision: revision as u64,
            digest: Sha256Digest::parse(row.try_get::<String, _>("grant_set_digest")?)
                .map_err(|_| RepositoryError::PluginGrantConflict)?,
            grants: CapabilitySet::new(grants),
        }))
    }

    pub async fn latest_plugin_setting(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
        scope: PluginSettingScope,
    ) -> Result<Option<PluginSettingRevision>, RepositoryError> {
        let (scope_type, scope_id) = scope.parts()?;
        let row = sqlx::query(
            "SELECT config_version, config_json, schema_digest, settings_digest
             FROM plugin_settings WHERE plugin_id = ? AND plugin_version = ?
               AND scope_type = ? AND scope_id = ? ORDER BY config_version DESC LIMIT 1",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .fetch_optional(self.pool())
        .await?;
        row.map(|row| {
            Ok(PluginSettingRevision {
                config_version: row.try_get::<i64, _>("config_version")? as u64,
                config: serde_json::from_str(&row.try_get::<String, _>("config_json")?)?,
                schema_digest: Sha256Digest::parse(row.try_get::<String, _>("schema_digest")?)
                    .map_err(|_| RepositoryError::PluginSettingConflict)?,
                settings_digest: Sha256Digest::parse(row.try_get::<String, _>("settings_digest")?)
                    .map_err(|_| RepositoryError::PluginSettingConflict)?,
            })
        })
        .transpose()
    }

    pub async fn insert_staged_plugin_package(
        &self,
        package: &StagedPluginPackage,
    ) -> Result<(), RepositoryError> {
        let created_at = timestamp_to_i64(package.created_at)?;
        let mut transaction = self.pool().begin().await?;
        sqlx::query(
            "INSERT OR IGNORE INTO identities (provider, subject, created_at) VALUES (?, ?, ?)",
        )
        .bind(package.requested_by.provider())
        .bind(package.requested_by.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO plugin_staged_packages (
                id, plugin_id, plugin_version, runtime_type, quarantine_path,
                package_digest, manifest_digest, artifact_digest, manifest_json,
                file_hashes_json, source_type, requested_by_provider,
                requested_by_subject, state, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'local', ?, ?, 'staged', ?)",
        )
        .bind(package.id.to_string())
        .bind(package.manifest.id().as_str())
        .bind(package.manifest.version().as_str())
        .bind(package.manifest.runtime().runtime().as_str())
        .bind(&package.quarantine_path)
        .bind(package.package_digest.as_str())
        .bind(package.manifest_digest.as_str())
        .bind(package.manifest.integrity().artifact().as_str())
        .bind(serde_json::to_string(&package.manifest)?)
        .bind(serde_json::to_string(&package.file_hashes)?)
        .bind(package.requested_by.provider())
        .bind(package.requested_by.subject())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn install_staged_plugin(
        &self,
        staged_id: Uuid,
        artifact_path: impl Into<String>,
        installed_at: TimestampMillis,
    ) -> Result<InstallResult, RepositoryError> {
        let artifact_path = artifact_path.into();
        ManifestPath::parse(&artifact_path)
            .map_err(|error| RepositoryError::InvalidPluginPackage(error.to_string()))?;
        let installed_at = timestamp_to_i64(installed_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let staged = sqlx::query(
            "SELECT plugin_id, plugin_version, runtime_type, package_digest,
                    manifest_digest, artifact_digest, manifest_json, state
             FROM plugin_staged_packages WHERE id = ?",
        )
        .bind(staged_id.to_string())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(RepositoryError::PluginStateConflict)?;
        let plugin_id: String = staged.try_get("plugin_id")?;
        let version: String = staged.try_get("plugin_version")?;
        let runtime: String = staged.try_get("runtime_type")?;
        let package_digest: String = staged.try_get("package_digest")?;
        let manifest_digest: String = staged.try_get("manifest_digest")?;
        let artifact_digest: String = staged.try_get("artifact_digest")?;
        let manifest_json: String = staged.try_get("manifest_json")?;
        let manifest: PluginManifest = serde_json::from_str(&manifest_json)?;

        if let Some(existing) = sqlx::query(
            "SELECT package_digest, manifest_digest, artifact_digest
             FROM plugin_versions WHERE plugin_id = ? AND version = ?",
        )
        .bind(&plugin_id)
        .bind(&version)
        .fetch_optional(&mut *transaction)
        .await?
        {
            let identical = existing.try_get::<String, _>("package_digest")? == package_digest
                && existing.try_get::<String, _>("manifest_digest")? == manifest_digest
                && existing.try_get::<String, _>("artifact_digest")? == artifact_digest;
            if !identical {
                return Err(RepositoryError::PluginVersionConflict);
            }
            sqlx::query(
                "UPDATE plugin_staged_packages
                 SET state = 'installed', installed_at = COALESCE(installed_at, ?)
                 WHERE id = ?",
            )
            .bind(installed_at)
            .bind(staged_id.to_string())
            .execute(&mut *transaction)
            .await?;
            transaction.commit().await?;
            return Ok(InstallResult::AlreadyInstalled);
        }

        sqlx::query(
            "INSERT INTO plugins (id, name, description, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO NOTHING",
        )
        .bind(&plugin_id)
        .bind(manifest.name())
        .bind(manifest.description())
        .bind(installed_at)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO plugin_versions (
                plugin_id, version, runtime_type, artifact_path, package_digest,
                manifest_digest, artifact_digest, manifest_json, artifact_state, installed_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'installed', ?)",
        )
        .bind(&plugin_id)
        .bind(&version)
        .bind(&runtime)
        .bind(&artifact_path)
        .bind(&package_digest)
        .bind(&manifest_digest)
        .bind(&artifact_digest)
        .bind(&manifest_json)
        .bind(installed_at)
        .execute(&mut *transaction)
        .await?;
        for component in manifest.components() {
            sqlx::query(
                "INSERT INTO plugin_components (
                    plugin_id, plugin_version, component_id, kind, description,
                    input_schema_path, output_schema_path, action_kinds_json
                 ) VALUES (?, ?, ?, 'tool', ?, ?, ?, ?)",
            )
            .bind(&plugin_id)
            .bind(&version)
            .bind(component.id().as_str())
            .bind(component.description())
            .bind(component.input_schema().as_str())
            .bind(component.output_schema().as_str())
            .bind(serde_json::to_string(component.action_kinds())?)
            .execute(&mut *transaction)
            .await?;
            for request in component.capabilities() {
                sqlx::query(
                    "INSERT INTO plugin_capability_requests (
                        plugin_id, plugin_version, component_id, capability_name, requested_scope
                     ) VALUES (?, ?, ?, ?, 'workspace')",
                )
                .bind(&plugin_id)
                .bind(&version)
                .bind(component.id().as_str())
                .bind(request.name().as_str())
                .execute(&mut *transaction)
                .await?;
            }
        }
        sqlx::query(
            "UPDATE plugin_staged_packages SET state = 'installed', installed_at = ? WHERE id = ?",
        )
        .bind(installed_at)
        .bind(staged_id.to_string())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(InstallResult::Installed)
    }

    pub async fn enable_plugin_version(
        &self,
        workspace_id: WorkspaceId,
        plugin_id: PluginId,
        version: PluginVersion,
        updated_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let updated_at = timestamp_to_i64(updated_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let available: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM plugin_versions
             WHERE plugin_id = ? AND version = ? AND artifact_state = 'installed'",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        if available != 1 {
            return Err(RepositoryError::PluginStateConflict);
        }
        sqlx::query(
            "UPDATE plugin_workspace_versions SET state = 'disabled', updated_at = ?
             WHERE workspace_id = ? AND plugin_id = ? AND state = 'enabled'",
        )
        .bind(updated_at)
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO plugin_workspace_versions (
                workspace_id, plugin_id, plugin_version, state, updated_at
             ) VALUES (?, ?, ?, 'enabled', ?)
             ON CONFLICT(workspace_id, plugin_id, plugin_version)
             DO UPDATE SET state = 'enabled', updated_at = excluded.updated_at",
        )
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(updated_at)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn disable_plugin_version(
        &self,
        workspace_id: WorkspaceId,
        plugin_id: PluginId,
        version: PluginVersion,
        updated_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let result = sqlx::query(
            "UPDATE plugin_workspace_versions SET state = 'disabled', updated_at = ?
             WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?
               AND state IN ('enabled', 'disabled')",
        )
        .bind(timestamp_to_i64(updated_at)?)
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .execute(self.pool())
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::PluginStateConflict);
        }
        Ok(())
    }

    pub async fn release_plugin_health_quarantine(
        &self,
        workspace_id: WorkspaceId,
        plugin_id: PluginId,
        version: PluginVersion,
        updated_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let result = sqlx::query(
            "UPDATE plugin_workspace_versions SET state = 'disabled', updated_at = ?
             WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?
               AND state = 'health_quarantine'",
        )
        .bind(timestamp_to_i64(updated_at)?)
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .execute(self.pool())
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::PluginStateConflict);
        }
        Ok(())
    }

    pub async fn release_plugin_artifact_quarantine(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
        released_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE plugin_versions SET artifact_state = 'installed', artifact_quarantined_at = NULL
             WHERE plugin_id = ? AND version = ? AND artifact_state = 'artifact_quarantine'",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::PluginStateConflict);
        }
        sqlx::query(
            "UPDATE plugin_workspace_versions SET state = 'disabled', updated_at = ?
             WHERE plugin_id = ? AND plugin_version = ?",
        )
        .bind(timestamp_to_i64(released_at)?)
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn plugin_workspace_state(
        &self,
        workspace_id: WorkspaceId,
        plugin_id: PluginId,
        version: PluginVersion,
    ) -> Result<Option<PluginWorkspaceState>, RepositoryError> {
        let state: Option<String> = sqlx::query_scalar(
            "SELECT state FROM plugin_workspace_versions
             WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?",
        )
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .fetch_optional(self.pool())
        .await?;
        state
            .as_deref()
            .map(PluginWorkspaceState::parse)
            .transpose()
    }

    pub async fn quarantine_plugin_artifact(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
        quarantined_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let quarantined_at = timestamp_to_i64(quarantined_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let result = sqlx::query(
            "UPDATE plugin_versions
             SET artifact_state = 'artifact_quarantine', artifact_quarantined_at = ?
             WHERE plugin_id = ? AND version = ? AND artifact_state = 'installed'",
        )
        .bind(quarantined_at)
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .execute(&mut *transaction)
        .await?;
        if result.rows_affected() != 1 {
            return Err(RepositoryError::PluginStateConflict);
        }
        sqlx::query(
            "UPDATE plugin_workspace_versions SET state = 'disabled', updated_at = ?
             WHERE plugin_id = ? AND plugin_version = ?",
        )
        .bind(quarantined_at)
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn append_plugin_grant_revision(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
        component: PluginComponentId,
        scope: PluginGrantScope,
        expected_revision: Option<u64>,
        grants: Vec<Capability>,
        grant_set_digest: Sha256Digest,
        created_at: TimestampMillis,
    ) -> Result<u64, RepositoryError> {
        let (scope_type, scope_id) = scope.parts();
        if canonical_grant_set_digest(&grants) != grant_set_digest {
            return Err(RepositoryError::PluginGrantConflict);
        }
        let created_at = timestamp_to_i64(created_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision), 0) FROM plugin_grant_revisions
             WHERE plugin_id = ? AND plugin_version = ? AND component_id = ?
               AND scope_type = ? AND scope_id = ?",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(component.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .fetch_one(&mut *transaction)
        .await?;
        if expected_revision.unwrap_or(0) != current as u64 {
            return Err(RepositoryError::PluginGrantConflict);
        }
        for grant in &grants {
            let requested: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM plugin_capability_requests
                 WHERE plugin_id = ? AND plugin_version = ? AND component_id = ?
                   AND capability_name = ?",
            )
            .bind(plugin_id.as_str())
            .bind(version.as_str())
            .bind(component.as_str())
            .bind(grant.name().as_str())
            .fetch_one(&mut *transaction)
            .await?;
            if requested != 1 {
                return Err(RepositoryError::PluginGrantConflict);
            }
        }
        if let PluginGrantScope::Workspace(workspace_id) = &scope {
            let latest_global: i64 = sqlx::query_scalar(
                "SELECT COALESCE(MAX(revision), 0) FROM plugin_grant_revisions
                 WHERE plugin_id = ? AND plugin_version = ? AND component_id = ?
                   AND scope_type = 'global' AND scope_id = '*'",
            )
            .bind(plugin_id.as_str())
            .bind(version.as_str())
            .bind(component.as_str())
            .fetch_one(&mut *transaction)
            .await?;
            if latest_global == 0 {
                return Err(RepositoryError::PluginGrantConflict);
            }
            let rows = sqlx::query(
                "SELECT capability_name, resource_json FROM plugin_capability_grants
                 WHERE plugin_id = ? AND plugin_version = ? AND component_id = ?
                   AND scope_type = 'global' AND scope_id = '*' AND revision = ?",
            )
            .bind(plugin_id.as_str())
            .bind(version.as_str())
            .bind(component.as_str())
            .bind(latest_global)
            .fetch_all(&mut *transaction)
            .await?;
            let mut global = Vec::new();
            for row in rows {
                let name: String = row.try_get("capability_name")?;
                let Some(candidate) = grants.iter().find(|grant| grant.name().as_str() == name)
                else {
                    continue;
                };
                let resource = parse_resource_scope(&row.try_get::<String, _>("resource_json")?)?;
                global.push(Capability::new(candidate.name(), resource));
            }
            let global = CapabilitySet::new(global);
            if grants.iter().any(|grant| {
                !global.allows(grant)
                    || match grant.scope() {
                        ResourceScope::Workspace {
                            workspace_id: grant_workspace,
                        }
                        | ResourceScope::Path {
                            workspace_id: grant_workspace,
                            ..
                        } => grant_workspace != workspace_id,
                        ResourceScope::Exact { .. } => false,
                    }
            }) {
                return Err(RepositoryError::PluginGrantConflict);
            }
        }
        let revision = current + 1;
        sqlx::query(
            "INSERT INTO plugin_grant_revisions (
                plugin_id, plugin_version, component_id, scope_type, scope_id,
                revision, grant_set_digest, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(component.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .bind(revision)
        .bind(grant_set_digest.as_str())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        for grant in grants {
            sqlx::query(
                "INSERT INTO plugin_capability_grants (
                    plugin_id, plugin_version, component_id, scope_type, scope_id,
                    revision, capability_name, resource_json
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(plugin_id.as_str())
            .bind(version.as_str())
            .bind(component.as_str())
            .bind(scope_type)
            .bind(&scope_id)
            .bind(revision)
            .bind(grant.name().as_str())
            .bind(serde_json::to_string(grant.scope())?)
            .execute(&mut *transaction)
            .await?;
        }
        invalidate_plugin_approvals(
            &mut transaction,
            plugin_id.as_str(),
            version.as_str(),
            "grant_set_digest",
            grant_set_digest.as_str(),
        )
        .await?;
        transaction.commit().await?;
        Ok(revision as u64)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn put_plugin_setting(
        &self,
        plugin_id: PluginId,
        version: PluginVersion,
        scope: PluginSettingScope,
        expected_version: Option<u64>,
        config: Value,
        schema_digest: Sha256Digest,
        created_at: TimestampMillis,
    ) -> Result<PluginSettingRevision, RepositoryError> {
        let (scope_type, scope_id) = scope.parts()?;
        let created_at = timestamp_to_i64(created_at)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let current: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(config_version), 0) FROM plugin_settings
             WHERE plugin_id = ? AND plugin_version = ? AND scope_type = ? AND scope_id = ?",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .fetch_one(&mut *transaction)
        .await?;
        if expected_version.unwrap_or(0) != current as u64 {
            return Err(RepositoryError::PluginSettingConflict);
        }
        let config_version = current + 1;
        let settings_digest = Sha256Digest::parse(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&serde_json::json!({
                "config": &config,
                "config_version": config_version,
                "scope_type": scope_type,
                "scope_id": &scope_id,
            }))?)
        ))
        .expect("SHA-256 output is canonical");
        sqlx::query(
            "INSERT INTO plugin_settings (
                plugin_id, plugin_version, scope_type, scope_id, config_version,
                config_json, schema_digest, settings_digest, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(scope_type)
        .bind(&scope_id)
        .bind(config_version)
        .bind(serde_json::to_string(&config)?)
        .bind(schema_digest.as_str())
        .bind(settings_digest.as_str())
        .bind(created_at)
        .execute(&mut *transaction)
        .await?;
        invalidate_plugin_approvals(
            &mut transaction,
            plugin_id.as_str(),
            version.as_str(),
            "settings_digest",
            settings_digest.as_str(),
        )
        .await?;
        transaction.commit().await?;
        Ok(PluginSettingRevision {
            config_version: config_version as u64,
            config,
            schema_digest,
            settings_digest,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record_plugin_failure(
        &self,
        workspace_id: WorkspaceId,
        plugin_id: PluginId,
        version: PluginVersion,
        component: PluginComponentId,
        invocation_id: Uuid,
        class: ExtensionFailureClass,
        occurred_at: TimestampMillis,
    ) -> Result<PluginWorkspaceState, RepositoryError> {
        let occurred_at = timestamp_to_i64(occurred_at)?;
        let window_start = occurred_at.saturating_sub(10 * 60 * 1_000);
        let counted = i64::from(class.counts_toward_health());
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "INSERT INTO plugin_failures (
                workspace_id, plugin_id, plugin_version, component_id,
                invocation_id, failure_class, counted, occurred_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(component.as_str())
        .bind(invocation_id.to_string())
        .bind(class.as_str())
        .bind(counted)
        .bind(occurred_at)
        .execute(&mut *transaction)
        .await?;
        let failures: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM plugin_failures
             WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?
               AND counted = 1 AND occurred_at >= ? AND occurred_at <= ?",
        )
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .bind(window_start)
        .bind(occurred_at)
        .fetch_one(&mut *transaction)
        .await?;
        if failures >= 3 {
            sqlx::query(
                "UPDATE plugin_workspace_versions
                 SET state = 'health_quarantine', updated_at = ?
                 WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?",
            )
            .bind(occurred_at)
            .bind(workspace_id.to_string())
            .bind(plugin_id.as_str())
            .bind(version.as_str())
            .execute(&mut *transaction)
            .await?;
        }
        let state: String = sqlx::query_scalar(
            "SELECT state FROM plugin_workspace_versions
             WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?",
        )
        .bind(workspace_id.to_string())
        .bind(plugin_id.as_str())
        .bind(version.as_str())
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        PluginWorkspaceState::parse(&state)
    }
}

fn parse_resource_scope(encoded: &str) -> Result<ResourceScope, RepositoryError> {
    let value: Value = serde_json::from_str(encoded)?;
    let object = value
        .as_object()
        .ok_or(RepositoryError::PluginGrantConflict)?;
    let kind = object
        .get("type")
        .and_then(Value::as_str)
        .ok_or(RepositoryError::PluginGrantConflict)?;
    let workspace = || -> Result<WorkspaceId, RepositoryError> {
        let value = object
            .get("workspace_id")
            .and_then(Value::as_str)
            .ok_or(RepositoryError::PluginGrantConflict)?;
        let uuid = Uuid::parse_str(value).map_err(|_| RepositoryError::PluginGrantConflict)?;
        Ok(WorkspaceId::from_uuid(uuid))
    };
    match kind {
        "workspace" => Ok(ResourceScope::workspace(workspace()?)),
        "path" => {
            let path = object
                .get("path")
                .and_then(Value::as_str)
                .ok_or(RepositoryError::PluginGrantConflict)?;
            let path =
                WorkspacePath::parse(path).map_err(|_| RepositoryError::PluginGrantConflict)?;
            Ok(ResourceScope::path(workspace()?, path))
        }
        "exact" => ResourceScope::exact(
            object
                .get("resource_type")
                .and_then(Value::as_str)
                .ok_or(RepositoryError::PluginGrantConflict)?,
            object
                .get("value")
                .and_then(Value::as_str)
                .ok_or(RepositoryError::PluginGrantConflict)?,
        )
        .map_err(|_| RepositoryError::PluginGrantConflict),
        _ => Err(RepositoryError::PluginGrantConflict),
    }
}

async fn invalidate_plugin_approvals(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    plugin_id: &str,
    version: &str,
    digest_field: &str,
    current_digest: &str,
) -> Result<(), RepositoryError> {
    let digest_path = match digest_field {
        "grant_set_digest" => "$.grant_set_digest",
        "settings_digest" => "$.settings_digest",
        _ => return Err(RepositoryError::PluginStateConflict),
    };
    sqlx::query(
        "UPDATE approval_requests SET state = 'invalidated'
         WHERE state IN ('pending', 'granted') AND EXISTS (
             SELECT 1 FROM actions
             WHERE actions.id = approval_requests.action_id
               AND json_extract(actions.extension_provenance_json, '$.plugin_id') = ?
               AND json_extract(actions.extension_provenance_json, '$.plugin_version') = ?
               AND json_extract(actions.extension_provenance_json, ?) != ?
         )",
    )
    .bind(plugin_id)
    .bind(version)
    .bind(digest_path)
    .bind(current_digest)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
