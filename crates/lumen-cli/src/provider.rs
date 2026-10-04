use clap::Subcommand;
use lumen_core::secret::SecretRefId;
use std::path::PathBuf;

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ProviderCommand {
    /// Register a remote provider, one default profile, and explicit policies.
    Register {
        #[arg(long)]
        file: PathBuf,
    },
    List,
    Show {
        id: String,
    },
    Credential {
        #[command(subcommand)]
        command: ProviderCredentialCommand,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Subcommand)]
pub enum ProviderCredentialCommand {
    /// Metadata comes from JSON; the value comes only from standard input.
    Create {
        #[arg(long)]
        metadata: PathBuf,
        #[arg(long, required = true)]
        stdin: bool,
    },
    List,
    /// Keep historical metadata; disable future resolution and remove keyring value.
    Revoke {
        #[arg(long)]
        id: SecretRefId,
    },
}
use lumen_core::{
    egress::DataClass,
    provider::{ModelCapabilities, ProviderKind},
};
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum WireProviderKind {
    #[serde(rename = "openai")]
    OpenAi,
    #[serde(rename = "anthropic")]
    Anthropic,
    #[serde(rename = "openai_compatible")]
    OpenAiCompatible,
}
impl From<WireProviderKind> for ProviderKind {
    fn from(value: WireProviderKind) -> Self {
        match value {
            WireProviderKind::OpenAi => Self::OpenAi,
            WireProviderKind::Anthropic => Self::Anthropic,
            WireProviderKind::OpenAiCompatible => Self::OpenAiCompatible,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialDescriptor {
    pub provider_id: String,
    pub kind: WireProviderKind,
    pub endpoint: String,
    pub label: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistrationDescriptor {
    pub provider_id: String,
    pub kind: WireProviderKind,
    pub endpoint: String,
    pub credential_secret_ref: SecretRefId,
    pub enabled: bool,
    pub expected: ExpectedHeads,
    pub allowed_data_classes: BTreeSet<DataClass>,
    pub workspace_allowed_data_classes: BTreeSet<DataClass>,
    pub model_data_policy: lumen_db::ModelDataPolicyDescriptor,
    pub profile: ProfileDescriptor,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedHeads {
    pub provider: u64,
    pub profile: u64,
    pub egress: u64,
    pub workspace_policy: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileDescriptor {
    pub id: String,
    pub model: String,
    pub enabled: bool,
    pub capabilities: ModelCapabilities,
    pub context_window_tokens: u32,
    pub concurrency_limit: u32,
    pub priority: i32,
}

use crate::{CliError, CommandOutput, config::Config, runtime};
use lumen_core::{
    egress::{DestinationScope, ProviderId},
    provider::{ModelProfile, ModelProfileId, ModelTrustZone, ProviderConfig},
};
use lumen_db::{
    Database, ModelEndpointClass, ModelProviderRevision, ProviderRegistration,
    WorkspaceModelEgressRevision, next_provider_revision,
};
use lumen_integrations::{providers::ProviderCredential, secrets::SecretStore};
use serde::{Serialize, de::DeserializeOwned};
use std::{io::Read, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderSummary {
    pub id: String,
    pub protocol: String,
    pub endpoint: String,
    pub enabled: bool,
    pub provider_revision: u64,
    pub egress_revision: Option<u64>,
    pub workspace_policy_revision: Option<u64>,
    pub credential_status: String,
    pub profiles: Vec<ProfileSummary>,
    pub network_status: String,
    pub configuration_status: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProfileSummary {
    pub id: String,
    pub revision: u64,
    pub provider_revision: u64,
    pub model: String,
    pub enabled: bool,
}
fn invalid(message: &str) -> CliError {
    CliError::Runtime(message.into())
}
fn descriptor<T: DeserializeOwned>(path: &std::path::Path) -> Result<T, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 65536 {
        return Err(invalid("provider descriptor exceeds 64 KiB"));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| invalid("invalid provider descriptor; check field names and values"))
}
pub(crate) fn read_input() -> Result<Zeroizing<Vec<u8>>, CliError> {
    let mut bytes = Zeroizing::new(Vec::new());
    std::io::stdin().take(16387).read_to_end(&mut bytes)?;
    if bytes.len() > 16386 {
        return Err(invalid("invalid provider credential"));
    }
    Ok(bytes)
}
pub(crate) fn needs_store(command: &ProviderCommand) -> bool {
    matches!(
        command,
        ProviderCommand::Credential {
            command: ProviderCredentialCommand::Create { .. }
                | ProviderCredentialCommand::Revoke { .. }
        }
    )
}
pub(crate) async fn execute(
    config: &Config,
    command: ProviderCommand,
    store: Option<Arc<dyn SecretStore>>,
    input: Option<Zeroizing<Vec<u8>>>,
) -> Result<CommandOutput, CliError> {
    let credential = if matches!(
        command,
        ProviderCommand::Credential {
            command: ProviderCredentialCommand::Create { .. }
        }
    ) {
        Some(
            ProviderCredential::from_stdin(input.ok_or(CliError::MissingSecretInput)?)
                .map_err(|_| invalid("invalid provider credential"))?,
        )
    } else {
        None
    };
    let database = Database::connect(&config.database.path).await?;
    let workspace = config.workspace_id();
    let actor = config.bootstrap_principal();
    database
        .bootstrap_workspace(workspace, &config.workspace.name, &actor, runtime::now())
        .await?;
    let result = match command {
        ProviderCommand::Register { file } => {
            let d: RegistrationDescriptor = descriptor(&file)?;
            let p = ProviderConfig::remote(
                ProviderId::parse(d.provider_id).map_err(|_| invalid("invalid provider ID"))?,
                next_provider_revision(d.expected.provider)?,
                d.kind.into(),
                d.endpoint,
                d.enabled,
                d.credential_secret_ref,
            )
            .map_err(|_| invalid("invalid provider shape or endpoint"))?;
            let profile = ModelProfile::new(
                ModelProfileId::parse(d.profile.id).map_err(|_| invalid("invalid profile ID"))?,
                next_provider_revision(d.expected.profile)?,
                p.id().clone(),
                p.revision(),
                d.profile.model,
                d.profile.enabled,
                d.profile.capabilities,
                d.profile.context_window_tokens,
                ModelTrustZone::RemoteUntrusted,
                d.profile.concurrency_limit,
                d.profile.priority,
            )
            .map_err(|_| invalid("invalid model profile"))?;
            let at = runtime::now();
            let egress = ModelProviderRevision::new(
                p.id().clone(),
                next_provider_revision(d.expected.egress)?,
                ModelEndpointClass::Remote,
                DestinationScope::parse(p.endpoint().as_str())
                    .map_err(|_| invalid("invalid provider endpoint"))?,
                profile.model_name(),
                p.enabled(),
                0,
                p.credential_secret_ref(),
                d.allowed_data_classes,
                at,
            )?;
            let workspace_policy = WorkspaceModelEgressRevision::new(
                workspace,
                p.id().clone(),
                next_provider_revision(d.expected.workspace_policy)?,
                d.workspace_allowed_data_classes,
                at,
            )?;
            let r = ProviderRegistration {
                workspace,
                provider: p,
                profile,
                egress,
                workspace_policy,
                model_data_policy: d.model_data_policy,
                expected_provider: d.expected.provider,
                expected_profile: d.expected.profile,
                expected_egress: d.expected.egress,
                expected_workspace_policy: d.expected.workspace_policy,
            };
            database.register_provider_bundle(&r, &actor, at).await?;
            CommandOutput::ProviderRegistered(
                provider_summaries(&database, workspace, Some(r.provider.id()))
                    .await?
                    .pop()
                    .expect("committed provider metadata"),
            )
        }
        ProviderCommand::List => {
            CommandOutput::Providers(provider_summaries(&database, workspace, None).await?)
        }
        ProviderCommand::Show { id } => {
            let id = ProviderId::parse(id).map_err(|_| invalid("invalid provider ID"))?;
            let mut summaries = provider_summaries(&database, workspace, Some(&id)).await?;
            CommandOutput::ProviderShown(
                summaries
                    .pop()
                    .ok_or_else(|| invalid("provider unavailable in this workspace"))?,
            )
        }
        ProviderCommand::Credential {
            command: ProviderCredentialCommand::List,
        } => {
            CommandOutput::ProviderCredentials(database.list_provider_credentials(workspace).await?)
        }
        ProviderCommand::Credential {
            command: ProviderCredentialCommand::Create { metadata, .. },
        } => {
            let d: CredentialDescriptor = descriptor(&metadata)?;
            if credential
                .as_ref()
                .expect("validated input")
                .with_exposed_str(|value| {
                    [&d.provider_id, &d.endpoint, &d.label]
                        .into_iter()
                        .any(|field| field.contains(value))
                })
            {
                return Err(invalid(
                    "credential material is not permitted in provider metadata",
                ));
            }
            let id = SecretRefId::new();
            let p = ProviderConfig::remote(
                ProviderId::parse(d.provider_id).map_err(|_| invalid("invalid provider ID"))?,
                1,
                d.kind.into(),
                d.endpoint,
                true,
                id,
            )
            .map_err(|_| invalid("invalid provider shape or endpoint"))?;
            let store = store.ok_or_else(|| invalid("provider secret store unavailable"))?;
            // Interrupted creations never became usable. Deterministic recovery under the owner lock.
            for pending in database
                .list_provider_credentials(workspace)
                .await?
                .into_iter()
                .filter(|r| r.credential_status == "pending")
            {
                delete_account(
                    store.as_ref(),
                    &format!("provider:{workspace}:{}", pending.id),
                )
                .await
                .map_err(|_| {
                    invalid("pending provider credential cleanup failed; revoke it explicitly")
                })?;
                database
                    .set_provider_credential_state(
                        workspace,
                        pending.id,
                        false,
                        &actor,
                        runtime::now(),
                    )
                    .await?;
            }
            database
                .reserve_provider_credential(workspace, &p, &d.label, &actor, runtime::now())
                .await?;
            let account = format!("provider:{workspace}:{id}");
            let value = credential.expect("create credential validated");
            // SecretStore::put owns Vec: this is the one copy at the existing store boundary.
            let stored = store
                .put(&account, value.with_exposed_str(|s| s.as_bytes().to_vec()))
                .await;
            if stored.is_err() {
                let _ = store.delete(&account).await;
                return Err(invalid(
                    "provider credential storage failed; pending reference requires cleanup",
                ));
            }
            if database
                .set_provider_credential_state(workspace, id, true, &actor, runtime::now())
                .await
                .is_err()
            {
                let _ = store.delete(&account).await;
                return Err(invalid(
                    "provider credential finalization failed; pending reference requires cleanup",
                ));
            }
            CommandOutput::ProviderCredentialCreated(
                database
                    .list_provider_credentials(workspace)
                    .await?
                    .into_iter()
                    .find(|r| r.id == id)
                    .expect("finalized reference"),
            )
        }
        ProviderCommand::Credential {
            command: ProviderCredentialCommand::Revoke { id },
        } => {
            database
                .set_provider_credential_state(workspace, id, false, &actor, runtime::now())
                .await?;
            let store =
                store.ok_or_else(|| invalid("credential revoked; keyring cleanup unavailable"))?;
            delete_account(store.as_ref(), &format!("provider:{workspace}:{id}"))
                .await
                .map_err(|_| invalid("credential revoked; keyring cleanup failed, retry revoke"))?;
            CommandOutput::ProviderCredentialRevoked(id)
        }
    };
    database.close().await;
    Ok(result)
}

async fn delete_account(
    store: &dyn SecretStore,
    account: &str,
) -> Result<(), lumen_integrations::secrets::SecretStoreError> {
    match store.delete(account).await {
        Ok(()) | Err(lumen_integrations::secrets::SecretStoreError::NotFound) => Ok(()),
        Err(error) => Err(error),
    }
}
async fn provider_summaries(
    database: &Database,
    workspace: lumen_core::identity::WorkspaceId,
    filter: Option<&ProviderId>,
) -> Result<Vec<ProviderSummary>, CliError> {
    let mut result = Vec::new();
    let refs = database.list_provider_credentials(workspace).await?;
    let profiles = database.list_latest_model_profiles().await?;
    for p in database.list_latest_provider_configs().await? {
        if filter.is_some_and(|id| id != p.id())
            || !database.provider_owned_by(workspace, p.id()).await?
        {
            continue;
        }
        result.push(ProviderSummary {
            id: p.id().as_str().into(),
            protocol: p.kind().as_str().into(),
            endpoint: p.endpoint().as_str().into(),
            enabled: p.enabled(),
            provider_revision: p.revision(),
            egress_revision: database
                .latest_model_provider_revision(p.id().clone())
                .await?
                .map(|e| e.revision()),
            workspace_policy_revision: database
                .latest_workspace_model_egress_revision(workspace, p.id().clone())
                .await?
                .map(|e| e.revision()),
            credential_status: refs
                .iter()
                .find(|r| Some(r.id) == p.credential_secret_ref())
                .map(|r| r.credential_status.clone())
                .unwrap_or_else(|| "unavailable".into()),
            profiles: profiles
                .iter()
                .filter(|m| m.provider_id() == p.id())
                .map(|m| ProfileSummary {
                    id: m.id().as_str().into(),
                    revision: m.revision(),
                    provider_revision: m.provider_revision(),
                    model: m.model_name().into(),
                    enabled: m.enabled(),
                })
                .collect(),
            network_status: "not_tested".into(),
            configuration_status: "configured".into(),
        });
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    #[test]
    fn cli_parses_provider_commands_and_requires_stdin() {
        for args in [
            vec!["lumen", "provider", "register", "--file", "provider.json"],
            vec!["lumen", "provider", "list"],
            vec!["lumen", "provider", "show", "primary"],
            vec!["lumen", "provider", "credential", "list"],
            vec![
                "lumen",
                "provider",
                "credential",
                "create",
                "--metadata",
                "credential.json",
                "--stdin",
            ],
            vec![
                "lumen",
                "provider",
                "credential",
                "revoke",
                "--id",
                "11111111-1111-4111-8111-111111111111",
            ],
        ] {
            assert!(matches!(
                crate::Cli::try_parse_from(args).unwrap().command,
                crate::Command::Provider { .. }
            ));
        }
        assert!(
            crate::Cli::try_parse_from([
                "lumen",
                "provider",
                "credential",
                "create",
                "--metadata",
                "credential.json"
            ])
            .is_err()
        );
        assert!(
            crate::Cli::try_parse_from([
                "lumen",
                "provider",
                "credential",
                "create",
                "--metadata",
                "credential.json",
                "--stdin",
                "--key",
                "value"
            ])
            .is_err()
        );
    }
    #[test]
    fn descriptors_are_bounded_strict_and_errors_do_not_echo_values() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("descriptor.json");
        for value in [r#"{"provider_id":"primary","kind":"openai","endpoint":"https://provider.test/","label":"provider","api_key":"sentinel-key"}"#.to_string(),"x".repeat(65537)] {
            std::fs::write(&path,value).unwrap();let error=descriptor::<CredentialDescriptor>(&path).err().unwrap();assert!(!error.to_string().contains("sentinel-key"));
        }
    }
}
