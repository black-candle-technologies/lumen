use lumen_core::{
    approval::TimestampMillis,
    egress::{EndpointClass, ProviderId},
    provider::{
        LocalRuntimeKind, ModelCapabilities, ModelProfile, ModelProfileId, ModelTrustZone,
        ProviderConfig, ProviderKind,
    },
    secret::SecretRefId,
};
use sqlx::Row;

use crate::{Database, RepositoryError, timestamp_to_i64};

impl Database {
    pub async fn append_provider_config(
        &self,
        config: &ProviderConfig,
        created_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin().await?;
        let created_at = timestamp_to_i64(created_at)?;
        sqlx::query("INSERT INTO egress_model_providers(provider_id,created_at) VALUES(?,?) ON CONFLICT(provider_id) DO NOTHING").bind(config.id().as_str()).bind(created_at).execute(&mut *transaction).await?;
        let latest: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(revision),0) FROM model_provider_runtime_revisions WHERE provider_id=?").bind(config.id().as_str()).fetch_one(&mut *transaction).await?;
        if u64::try_from(latest)
            .ok()
            .and_then(|value| value.checked_add(1))
            != Some(config.revision())
        {
            return Err(RepositoryError::InvalidModelRegistry);
        }
        sqlx::query("INSERT INTO model_provider_runtime_revisions(provider_id,revision,provider_kind,endpoint_class,endpoint_url,local_runtime,enabled,credential_secret_ref,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(config.id().as_str()).bind(i64::try_from(config.revision()).map_err(|_| RepositoryError::InvalidModelRegistry)?).bind(config.kind().as_str()).bind(endpoint_class(config.endpoint_class())).bind(config.endpoint().as_str()).bind(config.local_runtime().map(LocalRuntimeKind::as_str)).bind(config.enabled()).bind(config.credential_secret_ref().map(|value| value.to_string())).bind(created_at).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn latest_provider_config(
        &self,
        id: &ProviderId,
    ) -> Result<Option<ProviderConfig>, RepositoryError> {
        sqlx::query("SELECT provider_id,revision,provider_kind,endpoint_class,endpoint_url,local_runtime,enabled,credential_secret_ref FROM model_provider_runtime_revisions WHERE provider_id=? ORDER BY revision DESC LIMIT 1").bind(id.as_str()).fetch_optional(self.pool()).await?.map(provider_from_row).transpose()
    }

    pub async fn append_model_profile(
        &self,
        profile: &ModelProfile,
        created_at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let mut transaction = self.pool().begin().await?;
        let created_at = timestamp_to_i64(created_at)?;
        let provider_exists: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM model_provider_runtime_revisions WHERE provider_id=? AND revision=?",
        )
        .bind(profile.provider_id().as_str())
        .bind(
            i64::try_from(profile.provider_revision())
                .map_err(|_| RepositoryError::InvalidModelRegistry)?,
        )
        .fetch_optional(&mut *transaction)
        .await?;
        if provider_exists.is_none() {
            return Err(RepositoryError::InvalidModelRegistry);
        }
        sqlx::query("INSERT INTO model_profiles(profile_id,provider_id,created_at) VALUES(?,?,?) ON CONFLICT(profile_id) DO NOTHING").bind(profile.id().as_str()).bind(profile.provider_id().as_str()).bind(created_at).execute(&mut *transaction).await?;
        let provider_id: String =
            sqlx::query_scalar("SELECT provider_id FROM model_profiles WHERE profile_id=?")
                .bind(profile.id().as_str())
                .fetch_one(&mut *transaction)
                .await?;
        if provider_id != profile.provider_id().as_str() {
            return Err(RepositoryError::InvalidModelRegistry);
        }
        let latest: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0) FROM model_profile_revisions WHERE profile_id=?",
        )
        .bind(profile.id().as_str())
        .fetch_one(&mut *transaction)
        .await?;
        if u64::try_from(latest)
            .ok()
            .and_then(|value| value.checked_add(1))
            != Some(profile.revision())
        {
            return Err(RepositoryError::InvalidModelRegistry);
        }
        sqlx::query("INSERT INTO model_profile_revisions(profile_id,provider_id,revision,provider_revision,model_name,enabled,capabilities_json,context_window_tokens,trust_zone,concurrency_limit,priority,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(profile.id().as_str()).bind(profile.provider_id().as_str()).bind(i64::try_from(profile.revision()).map_err(|_| RepositoryError::InvalidModelRegistry)?).bind(i64::try_from(profile.provider_revision()).map_err(|_| RepositoryError::InvalidModelRegistry)?).bind(profile.model_name()).bind(profile.enabled()).bind(serde_json::to_string(profile.capabilities())?).bind(i64::from(profile.context_window_tokens())).bind(profile.trust_zone().as_str()).bind(i64::from(profile.concurrency_limit())).bind(i64::from(profile.priority())).bind(created_at).execute(&mut *transaction).await?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn latest_model_profile(
        &self,
        id: &ModelProfileId,
    ) -> Result<Option<ModelProfile>, RepositoryError> {
        sqlx::query("SELECT profile_id,provider_id,revision,provider_revision,model_name,enabled,capabilities_json,context_window_tokens,trust_zone,concurrency_limit,priority FROM model_profile_revisions WHERE profile_id=? ORDER BY revision DESC LIMIT 1").bind(id.as_str()).fetch_optional(self.pool()).await?.map(profile_from_row).transpose()
    }

    pub async fn list_latest_model_profiles(&self) -> Result<Vec<ModelProfile>, RepositoryError> {
        sqlx::query("SELECT p.profile_id,p.provider_id,p.revision,p.provider_revision,p.model_name,p.enabled,p.capabilities_json,p.context_window_tokens,p.trust_zone,p.concurrency_limit,p.priority FROM model_profile_revisions p JOIN (SELECT profile_id,MAX(revision) revision FROM model_profile_revisions GROUP BY profile_id) latest ON latest.profile_id=p.profile_id AND latest.revision=p.revision ORDER BY p.priority,p.profile_id").fetch_all(self.pool()).await?.into_iter().map(profile_from_row).collect()
    }
}

fn provider_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ProviderConfig, RepositoryError> {
    let id = ProviderId::parse(row.try_get::<String, _>("provider_id")?)
        .map_err(|_| RepositoryError::InvalidModelRegistry)?;
    let kind = ProviderKind::parse(&row.try_get::<String, _>("provider_kind")?)
        .ok_or(RepositoryError::InvalidModelRegistry)?;
    let class = match row.try_get::<String, _>("endpoint_class")?.as_str() {
        "local" => EndpointClass::Local,
        "remote" => EndpointClass::Remote,
        _ => return Err(RepositoryError::InvalidModelRegistry),
    };
    let runtime = row
        .try_get::<Option<String>, _>("local_runtime")?
        .map(|value| LocalRuntimeKind::parse(&value).ok_or(RepositoryError::InvalidModelRegistry))
        .transpose()?;
    let secret = row
        .try_get::<Option<String>, _>("credential_secret_ref")?
        .map(|value| SecretRefId::parse(&value).map_err(|_| RepositoryError::InvalidModelRegistry))
        .transpose()?;
    ProviderConfig::from_stored_parts(
        id,
        positive_u64(row.try_get("revision")?)?,
        kind,
        class,
        row.try_get::<String, _>("endpoint_url")?,
        row.try_get::<bool, _>("enabled")?,
        runtime,
        secret,
    )
    .map_err(|_| RepositoryError::InvalidModelRegistry)
}
fn profile_from_row(row: sqlx::sqlite::SqliteRow) -> Result<ModelProfile, RepositoryError> {
    let id = ModelProfileId::parse(row.try_get::<String, _>("profile_id")?)
        .map_err(|_| RepositoryError::InvalidModelRegistry)?;
    let provider = ProviderId::parse(row.try_get::<String, _>("provider_id")?)
        .map_err(|_| RepositoryError::InvalidModelRegistry)?;
    let capabilities: ModelCapabilities =
        serde_json::from_str(&row.try_get::<String, _>("capabilities_json")?)?;
    let trust = ModelTrustZone::parse(&row.try_get::<String, _>("trust_zone")?)
        .ok_or(RepositoryError::InvalidModelRegistry)?;
    ModelProfile::new(
        id,
        positive_u64(row.try_get("revision")?)?,
        provider,
        positive_u64(row.try_get("provider_revision")?)?,
        row.try_get::<String, _>("model_name")?,
        row.try_get::<bool, _>("enabled")?,
        capabilities,
        positive_u32(row.try_get("context_window_tokens")?)?,
        trust,
        positive_u32(row.try_get("concurrency_limit")?)?,
        i32::try_from(row.try_get::<i64, _>("priority")?)
            .map_err(|_| RepositoryError::InvalidModelRegistry)?,
    )
    .map_err(|_| RepositoryError::InvalidModelRegistry)
}
fn endpoint_class(value: EndpointClass) -> &'static str {
    match value {
        EndpointClass::Local => "local",
        EndpointClass::Remote => "remote",
    }
}
fn positive_u64(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidModelRegistry)
}
fn positive_u32(value: i64) -> Result<u32, RepositoryError> {
    u32::try_from(value)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(RepositoryError::InvalidModelRegistry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lumen_core::provider::ModelCapability;
    #[tokio::test]
    async fn stores_two_profiles_on_one_provider() {
        let database = Database::connect_in_memory().await.unwrap();
        let provider = ProviderConfig::local_openai_compatible(
            ProviderId::parse("local").unwrap(),
            1,
            "http://127.0.0.1:11434/v1/",
            LocalRuntimeKind::Ollama,
            true,
            None,
        )
        .unwrap();
        database
            .append_provider_config(&provider, TimestampMillis::new(1))
            .await
            .unwrap();
        for (id, model, priority) in [("coder", "qwen-coder", 1), ("reasoner", "deepseek", 2)] {
            let profile = ModelProfile::new(
                ModelProfileId::parse(id).unwrap(),
                1,
                provider.id().clone(),
                1,
                model,
                true,
                ModelCapabilities::new([ModelCapability::Text]),
                32768,
                ModelTrustZone::LocalRestricted,
                1,
                priority,
            )
            .unwrap();
            database
                .append_model_profile(&profile, TimestampMillis::new(2))
                .await
                .unwrap();
        }
        assert_eq!(
            database.list_latest_model_profiles().await.unwrap().len(),
            2
        );
    }
}
