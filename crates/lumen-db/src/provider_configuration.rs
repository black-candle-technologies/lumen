//! Provider-purpose metadata and atomic operator registration. No key bytes enter this repository.
use crate::{
    Database, ModelEndpointClass, ModelProviderRevision, RepositoryError,
    WorkspaceModelEgressRevision, timestamp_to_i64,
};
use crate::{
    audit::append_audit_event_in,
    egress::{insert_model_egress_in, insert_workspace_egress_in},
    model_registry::{insert_model_profile_in, insert_provider_config_in},
};
use lumen_core::{
    approval::TimestampMillis,
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    egress::{DataClass, ProviderId},
    identity::{PrincipalId, WorkspaceId},
    provider::{ModelProfile, ModelProfileId, ProviderConfig, validate_binding},
    secret::SecretRefId,
};
use serde::Serialize;
use serde_json::json;
use sqlx::Row;
use std::collections::BTreeSet;
pub struct ProviderRegistration {
    pub workspace: WorkspaceId,
    pub provider: ProviderConfig,
    pub profile: ModelProfile,
    pub egress: ModelProviderRevision,
    pub workspace_policy: WorkspaceModelEgressRevision,
    pub expected_provider: u64,
    pub expected_profile: u64,
    pub expected_egress: u64,
    pub expected_workspace_policy: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RegistrationReceipt {
    pub provider_revision: u64,
    pub profile_revision: u64,
    pub egress_revision: u64,
    pub workspace_policy_revision: u64,
}

pub fn next_provider_revision(value: u64) -> Result<u64, RepositoryError> {
    value
        .checked_add(1)
        .filter(|v| *v <= i64::MAX as u64)
        .ok_or(RepositoryError::InvalidModelRegistry)
}
fn require_head(found: i64, expected: u64) -> Result<(), RepositoryError> {
    if u64::try_from(found).ok() != Some(expected) {
        return Err(RepositoryError::ProviderRevisionConflict);
    }
    Ok(())
}
impl Database {
    pub async fn register_provider_bundle(
        &self,
        r: &ProviderRegistration,
        actor: &PrincipalId,
        at: TimestampMillis,
    ) -> Result<RegistrationReceipt, RepositoryError> {
        validate_registration_shape(r)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;

        let owner: Option<String> = sqlx::query_scalar(
            "SELECT workspace_id FROM model_provider_owners WHERE provider_id=?",
        )
        .bind(r.provider.id().as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if owner.as_deref() != Some(r.workspace.to_string().as_str()) {
            return Err(RepositoryError::ProviderScopeDenied);
        }

        let p: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0) FROM model_provider_runtime_revisions WHERE provider_id=?"
        ).bind(r.provider.id().as_str()).fetch_one(&mut *tx).await?;
        let m: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0) FROM model_profile_revisions WHERE profile_id=?",
        )
        .bind(r.profile.id().as_str())
        .fetch_one(&mut *tx)
        .await?;
        let e: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0) FROM egress_model_provider_revisions WHERE provider_id=?"
        ).bind(r.provider.id().as_str()).fetch_one(&mut *tx).await?;
        let w: i64 = sqlx::query_scalar(
            "SELECT COALESCE(MAX(revision),0) FROM egress_workspace_model_policies WHERE workspace_id=? AND provider_id=?"
        ).bind(r.workspace.to_string()).bind(r.provider.id().as_str())
         .fetch_one(&mut *tx).await?;
        require_head(p, r.expected_provider)?;
        require_head(m, r.expected_profile)?;
        require_head(e, r.expected_egress)?;
        require_head(w, r.expected_workspace_policy)?;
        let profile_provider: Option<String> =
            sqlx::query_scalar("SELECT provider_id FROM model_profiles WHERE profile_id=?")
                .bind(r.profile.id().as_str())
                .fetch_optional(&mut *tx)
                .await?;
        if profile_provider
            .as_deref()
            .is_some_and(|id| id != r.provider.id().as_str())
        {
            return Err(RepositoryError::ProviderRevisionConflict);
        }

        let id = r
            .provider
            .credential_secret_ref()
            .ok_or(RepositoryError::ProviderCredentialUnavailable)?;
        let reference: Option<(String, String, String, String, String)> = sqlx::query_as(
            "SELECT workspace_id,provider_id,provider_kind,endpoint_url,state
             FROM model_provider_secret_references WHERE secret_ref_id=?",
        )
        .bind(id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        let Some((workspace, provider, kind, endpoint, state)) = reference else {
            return Err(RepositoryError::ProviderCredentialUnavailable);
        };
        if workspace != r.workspace.to_string()
            || provider != r.provider.id().as_str()
            || kind != r.provider.kind().as_str()
            || endpoint != r.provider.endpoint().as_str()
            || state != "ready"
        {
            return Err(RepositoryError::ProviderCredentialUnavailable);
        }

        insert_provider_config_in(&mut tx, &r.provider, at).await?;
        insert_model_profile_in(&mut tx, &r.profile, at).await?;
        insert_model_egress_in(&mut tx, &r.egress).await?;
        insert_workspace_egress_in(&mut tx, &r.workspace_policy).await?;
        append_audit_event_in(&mut tx, registration_audit_event(r, actor, at)).await?;
        tx.commit().await?;
        Ok(RegistrationReceipt {
            provider_revision: r.provider.revision(),
            profile_revision: r.profile.revision(),
            egress_revision: next_provider_revision(r.expected_egress)?,
            workspace_policy_revision: next_provider_revision(r.expected_workspace_policy)?,
        })
    }
}
pub struct RegisteredModelSnapshot {
    pub provider: ProviderConfig,
    pub profile: ModelProfile,
    pub route: lumen_core::egress::ProviderRoute,
    pub egress_revision: u64,
    pub workspace_policy_revision: Option<u64>,
}

impl Database {
    pub async fn registered_model_snapshot(
        &self,
        workspace: WorkspaceId,
        profile_id: &ModelProfileId,
        profile_revision: u64,
    ) -> Result<RegisteredModelSnapshot, RepositoryError> {
        use lumen_core::egress::{EndpointClass, ProviderRoute};
        use sqlx::Row;
        let mut tx = self.pool().begin().await?; // consistent read snapshot
        let row =
            sqlx::query("SELECT * FROM model_profile_revisions WHERE profile_id=? AND revision=?")
                .bind(profile_id.as_str())
                .bind(
                    i64::try_from(profile_revision)
                        .map_err(|_| RepositoryError::InvalidModelRegistry)?,
                )
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(RepositoryError::ProviderSelectionUnavailable)?;
        let profile = crate::model_registry::profile_from_row(row)?;
        let row = sqlx::query(
            "SELECT * FROM model_provider_runtime_revisions WHERE provider_id=? AND revision=?",
        )
        .bind(profile.provider_id().as_str())
        .bind(
            i64::try_from(profile.provider_revision())
                .map_err(|_| RepositoryError::InvalidModelRegistry)?,
        )
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(RepositoryError::ProviderSelectionUnavailable)?;
        let provider = crate::model_registry::provider_from_row(row)?;
        lumen_core::provider::validate_binding(&provider, &profile)
            .map_err(|_| RepositoryError::ProviderSelectionUnavailable)?;

        // Conservative pin semantics: changed heads require explicit re-selection.
        // Historical rows remain readable, but are not permission to keep sending.
        let latest_p: i64 = sqlx::query_scalar(
            "SELECT MAX(revision) FROM model_provider_runtime_revisions WHERE provider_id=?",
        )
        .bind(provider.id().as_str())
        .fetch_one(&mut *tx)
        .await?;
        let latest_m: i64 = sqlx::query_scalar(
            "SELECT MAX(revision) FROM model_profile_revisions WHERE profile_id=?",
        )
        .bind(profile.id().as_str())
        .fetch_one(&mut *tx)
        .await?;
        require_head(latest_p, provider.revision())?;
        require_head(latest_m, profile.revision())?;

        let owner: Option<String> = sqlx::query_scalar(
            "SELECT workspace_id FROM model_provider_owners WHERE provider_id=?",
        )
        .bind(provider.id().as_str())
        .fetch_optional(&mut *tx)
        .await?;
        if owner.as_deref() != Some(workspace.to_string().as_str()) {
            return Err(RepositoryError::ProviderScopeDenied);
        }
        let e = sqlx::query(
            "SELECT revision,endpoint_class,endpoint_url,enabled,credential_secret_ref,
                    allowed_data_classes_json,priority
             FROM egress_model_provider_revisions WHERE provider_id=? ORDER BY revision DESC LIMIT 1"
        ).bind(provider.id().as_str()).fetch_optional(&mut *tx).await?
         .ok_or(RepositoryError::ProviderSelectionUnavailable)?;
        let class = match e.try_get::<String, _>("endpoint_class")?.as_str() {
            "local" => EndpointClass::Local,
            "remote" => EndpointClass::Remote,
            _ => return Err(RepositoryError::InvalidModelRegistry),
        };
        let reference = e.try_get::<Option<String>, _>("credential_secret_ref")?;
        if class != provider.endpoint_class()
            || e.try_get::<String, _>("endpoint_url")? != provider.endpoint().as_str()
            || reference != provider.credential_secret_ref().map(|v| v.to_string())
            || !e.try_get::<bool, _>("enabled")?
        {
            return Err(RepositoryError::ProviderSelectionUnavailable);
        }
        let provider_classes: BTreeSet<DataClass> =
            serde_json::from_str(&e.try_get::<String, _>("allowed_data_classes_json")?)?;
        let policy: Option<(i64, String)> = sqlx::query_as(
            "SELECT revision,allowed_data_classes_json FROM egress_workspace_model_policies
             WHERE workspace_id=? AND provider_id=? ORDER BY revision DESC LIMIT 1",
        )
        .bind(workspace.to_string())
        .bind(provider.id().as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let (policy_revision, workspace_classes) = match policy {
            Some((revision, json)) => (
                Some(positive_revision(revision)?),
                Some(serde_json::from_str::<BTreeSet<DataClass>>(&json)?),
            ),
            None => (None, None), // remote selector will deny; never default allow
        };
        let route = ProviderRoute::new(
            provider.id().clone(),
            class,
            provider.enabled(),
            provider_classes,
            workspace_classes,
            u32::try_from(e.try_get::<i64, _>("priority")?)
                .map_err(|_| RepositoryError::InvalidModelRegistry)?,
        )
        .map_err(|_| RepositoryError::InvalidEgressPolicy)?;
        let egress_revision = positive_revision(e.try_get("revision")?)?;
        if let Some(id) = provider.credential_secret_ref() {
            let valid: i64=sqlx::query_scalar("SELECT COUNT(*) FROM model_provider_secret_references WHERE secret_ref_id=? AND workspace_id=? AND provider_id=? AND provider_kind=? AND endpoint_url=? AND state='ready'")
                .bind(id.to_string()).bind(workspace.to_string()).bind(provider.id().as_str()).bind(provider.kind().as_str()).bind(provider.endpoint().as_str()).fetch_one(&mut *tx).await?;
            if valid != 1 {
                return Err(RepositoryError::ProviderCredentialUnavailable);
            }
        }
        tx.commit().await?;
        Ok(RegisteredModelSnapshot {
            provider,
            profile,
            route,
            egress_revision,
            workspace_policy_revision: policy_revision,
        })
    }
}
fn positive_revision(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|v| *v > 0)
        .ok_or(RepositoryError::InvalidModelRegistry)
}

fn validate_registration_shape(r: &ProviderRegistration) -> Result<(), RepositoryError> {
    let p = &r.provider;
    let m = &r.profile;
    let e = &r.egress;
    let w = &r.workspace_policy;
    if p.endpoint_class() != lumen_core::egress::EndpointClass::Remote
        || p.revision() != next_provider_revision(r.expected_provider)?
        || m.revision() != next_provider_revision(r.expected_profile)?
        || e.revision() != next_provider_revision(r.expected_egress)?
        || w.revision() != next_provider_revision(r.expected_workspace_policy)?
        || m.provider_id() != p.id()
        || m.provider_revision() != p.revision()
        || m.trust_zone() != lumen_core::provider::ModelTrustZone::RemoteUntrusted
        || e.provider_id() != p.id()
        || e.endpoint_class() != ModelEndpointClass::Remote
        || e.endpoint().as_str() != p.endpoint().as_str()
        || e.credential_secret_ref() != p.credential_secret_ref()
        || e.enabled() != p.enabled()
        || e.model() != m.model_name()
        || w.workspace_id() != r.workspace
        || w.provider_id() != p.id()
        || e.allowed_data_classes().is_empty()
        || w.allowed_data_classes().is_empty()
        || e.allowed_data_classes().contains(&DataClass::Secret)
        || w.allowed_data_classes().contains(&DataClass::Secret)
    {
        return Err(RepositoryError::InvalidModelRegistry);
    }
    if p.enabled() && m.enabled() {
        validate_binding(p, m).map_err(|_| RepositoryError::InvalidModelRegistry)?;
    }
    Ok(())
}
fn registration_audit_event(
    r: &ProviderRegistration,
    actor: &PrincipalId,
    at: TimestampMillis,
) -> AuditEvent {
    event(
        r.workspace,
        actor,
        at,
        AuditEventKind::ProviderConfigured,
        AuditOutcome::Success,
        json!({
       "provider_id":r.provider.id().as_str(),"profile_id":r.profile.id().as_str(),"provider_revision":r.provider.revision(),
       "profile_revision":r.profile.revision(),"egress_revision":r.egress.revision(),"workspace_policy_revision":r.workspace_policy.revision(),
       "protocol":r.provider.kind().as_str(),"endpoint":r.provider.endpoint().as_str(),"enabled":r.provider.enabled(),"profile_enabled":r.profile.enabled(),
       "allowed_data_classes":r.egress.allowed_data_classes(),"workspace_allowed_data_classes":r.workspace_policy.allowed_data_classes()}),
    )
}
fn event(
    workspace: WorkspaceId,
    actor: &PrincipalId,
    at: TimestampMillis,
    kind: AuditEventKind,
    outcome: AuditOutcome,
    mut payload: serde_json::Value,
) -> AuditEvent {
    payload["actor"] = json!(actor);
    AuditEvent::new(
        AuditEventId::new(),
        at,
        kind,
        outcome,
        Some(workspace),
        serde_json::from_value(payload).expect("safe metadata"),
    )
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderCredentialReference {
    pub id: SecretRefId,
    pub workspace: WorkspaceId,
    pub provider_id: String,
    pub protocol: String,
    pub endpoint: String,
    pub label: String,
    pub credential_status: String,
}
impl Database {
    /// Reserve a fresh provider identity; historical IDs cannot be implicitly adopted.
    pub async fn reserve_provider_credential(
        &self,
        workspace: WorkspaceId,
        p: &ProviderConfig,
        label: &str,
        actor: &PrincipalId,
        at: TimestampMillis,
    ) -> Result<SecretRefId, RepositoryError> {
        if label.is_empty()
            || label.len() > 128
            || label.trim() != label
            || label.chars().any(char::is_control)
            || p.endpoint_class() != lumen_core::egress::EndpointClass::Remote
        {
            return Err(RepositoryError::InvalidModelRegistry);
        }
        let id = p
            .credential_secret_ref()
            .ok_or(RepositoryError::ProviderCredentialUnavailable)?;
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT workspace_id FROM model_provider_owners WHERE provider_id=?",
        )
        .bind(p.id().as_str())
        .fetch_optional(&mut *tx)
        .await?;
        match owner {
            Some(value) if value == workspace.to_string() => {}
            Some(_) => return Err(RepositoryError::ProviderScopeDenied),
            None => {
                let exists: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM egress_model_providers WHERE provider_id=?",
                )
                .bind(p.id().as_str())
                .fetch_one(&mut *tx)
                .await?;
                if exists != 0 {
                    return Err(RepositoryError::ProviderScopeDenied);
                }
                sqlx::query(
                    "INSERT INTO egress_model_providers(provider_id,created_at) VALUES(?,?)",
                )
                .bind(p.id().as_str())
                .bind(timestamp_to_i64(at)?)
                .execute(&mut *tx)
                .await?;
                sqlx::query("INSERT INTO model_provider_owners(provider_id,workspace_id,created_at) VALUES(?,?,?)").bind(p.id().as_str()).bind(workspace.to_string()).bind(timestamp_to_i64(at)?).execute(&mut *tx).await?;
            }
        }
        sqlx::query("INSERT INTO model_provider_secret_references(secret_ref_id,workspace_id,provider_id,provider_kind,endpoint_url,label,state,created_at,updated_at) VALUES(?,?,?,?,?,?,'pending',?,?)")
            .bind(id.to_string()).bind(workspace.to_string()).bind(p.id().as_str()).bind(p.kind().as_str()).bind(p.endpoint().as_str()).bind(label).bind(timestamp_to_i64(at)?).bind(timestamp_to_i64(at)?).execute(&mut *tx).await?;
        append_audit_event_in(
            &mut tx,
            event(
                workspace,
                actor,
                at,
                AuditEventKind::ProviderCredentialCreated,
                AuditOutcome::Pending,
                json!({"reference_id":id,"provider_id":p.id().as_str(),"state":"pending"}),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(id)
    }
    pub async fn set_provider_credential_state(
        &self,
        workspace: WorkspaceId,
        id: SecretRefId,
        ready: bool,
        actor: &PrincipalId,
        at: TimestampMillis,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let state = if ready { "ready" } else { "revoked" };
        let changed=sqlx::query("UPDATE model_provider_secret_references SET state=?,updated_at=MAX(updated_at,?) WHERE secret_ref_id=? AND workspace_id=? AND (state='pending' OR (?='revoked'))")
            .bind(state).bind(timestamp_to_i64(at)?).bind(id.to_string()).bind(workspace.to_string()).bind(state).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(RepositoryError::ProviderCredentialUnavailable);
        }
        append_audit_event_in(
            &mut tx,
            event(
                workspace,
                actor,
                at,
                if ready {
                    AuditEventKind::ProviderCredentialCreated
                } else {
                    AuditEventKind::ProviderCredentialRevoked
                },
                AuditOutcome::Success,
                json!({"reference_id":id,"state":state}),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
    pub async fn list_provider_credentials(
        &self,
        workspace: WorkspaceId,
    ) -> Result<Vec<ProviderCredentialReference>, RepositoryError> {
        sqlx::query("SELECT * FROM model_provider_secret_references WHERE workspace_id=? ORDER BY created_at,secret_ref_id").bind(workspace.to_string()).fetch_all(self.pool()).await?.into_iter().map(|row| Ok(ProviderCredentialReference {
            id:SecretRefId::parse(&row.try_get::<String,_>("secret_ref_id")?).map_err(|_|RepositoryError::InvalidModelRegistry)?,workspace,
            provider_id:row.try_get("provider_id")?,protocol:row.try_get("provider_kind")?,endpoint:row.try_get("endpoint_url")?,label:row.try_get("label")?,credential_status:row.try_get("state")?
        })).collect()
    }
    pub async fn require_ready_provider_reference(
        &self,
        workspace: WorkspaceId,
        p: &ProviderConfig,
        id: SecretRefId,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let valid: i64=sqlx::query_scalar("SELECT COUNT(*) FROM model_provider_secret_references r JOIN model_provider_owners o ON o.provider_id=r.provider_id AND o.workspace_id=r.workspace_id WHERE r.secret_ref_id=? AND r.workspace_id=? AND o.workspace_id=? AND r.provider_id=? AND r.provider_kind=? AND r.endpoint_url=? AND r.state='ready'")
            .bind(id.to_string()).bind(workspace.to_string()).bind(workspace.to_string()).bind(p.id().as_str()).bind(p.kind().as_str()).bind(p.endpoint().as_str()).fetch_one(&mut *tx).await?;
        if valid != 1 || p.credential_secret_ref() != Some(id) {
            return Err(RepositoryError::ProviderCredentialUnavailable);
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn require_current_provider(
        &self,
        workspace: WorkspaceId,
        p: &ProviderConfig,
    ) -> Result<(), RepositoryError> {
        let mut tx = self.pool().begin().await?;
        let current=sqlx::query("SELECT * FROM model_provider_runtime_revisions WHERE provider_id=? ORDER BY revision DESC LIMIT 1").bind(p.id().as_str()).fetch_optional(&mut *tx).await?.map(crate::model_registry::provider_from_row).transpose()?;
        if current.as_ref() != Some(p) || !p.enabled() {
            return Err(RepositoryError::ProviderSelectionUnavailable);
        }
        if p.endpoint_class() != lumen_core::egress::EndpointClass::Local
            || p.credential_secret_ref().is_some()
        {
            let owner: Option<String> = sqlx::query_scalar(
                "SELECT workspace_id FROM model_provider_owners WHERE provider_id=?",
            )
            .bind(p.id().as_str())
            .fetch_optional(&mut *tx)
            .await?;
            if owner.as_deref() != Some(workspace.to_string().as_str()) {
                return Err(RepositoryError::ProviderScopeDenied);
            }
        }
        tx.commit().await?;
        Ok(())
    }
    pub async fn provider_owned_by(
        &self,
        workspace: WorkspaceId,
        id: &ProviderId,
    ) -> Result<bool, RepositoryError> {
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT workspace_id FROM model_provider_owners WHERE provider_id=?",
        )
        .bind(id.as_str())
        .fetch_optional(self.pool())
        .await?;
        Ok(owner.as_deref() == Some(workspace.to_string().as_str()))
    }
}
