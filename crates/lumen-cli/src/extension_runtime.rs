use std::path::PathBuf;

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorFuture, ExecutorPort},
    extension::{
        PluginComponentId, PluginId, PluginVersion, Sha256Digest, canonical_grant_set_digest,
    },
    identity::ComponentId,
    model::ActionProposal,
    run::{ActionNormalizer, NormalizationError, RunContext},
};
use lumen_db::{Database, PluginGrantScope, PluginSettingScope};
use lumen_integrations::{
    extension_package::{PackageIdentity, PackageStager},
    extension_schema::{BoundedSchema, SchemaLimits},
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::runtime::now;

const ADMIN_COMPONENT: &str = "runtime.extensions";

pub(crate) struct ExtensionActionNormalizer;

impl ActionNormalizer for ExtensionActionNormalizer {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError> {
        let kind = proposal.kind().to_owned();
        let arguments = proposal.into_arguments();
        let (arguments, capability) = match kind.as_str() {
            "plugin.install" => {
                let parsed: InstallArguments = parse(&arguments)?;
                parsed.validate()?;
                let scope = plugin_scope(&parsed.plugin_id, &parsed.plugin_version)?;
                (
                    canonical(&parsed)?,
                    Capability::new(CapabilityName::PluginInstall, scope),
                )
            }
            "plugin.enable" | "plugin.disable" => {
                let parsed: VersionArguments = parse(&arguments)?;
                parsed.validate()?;
                let scope = plugin_scope(&parsed.plugin_id, &parsed.plugin_version)?;
                (
                    canonical(&parsed)?,
                    Capability::new(CapabilityName::PluginEnable, scope),
                )
            }
            "plugin.capabilities.set" => {
                let parsed: GrantArguments = parse(&arguments)?;
                let normalized = parsed.normalize(context)?;
                let scope = plugin_scope(&normalized.plugin_id, &normalized.plugin_version)?;
                (
                    canonical(&normalized)?,
                    Capability::new(CapabilityName::PluginCapabilitiesSet, scope),
                )
            }
            "plugin.settings.set" => {
                let parsed: SettingArguments = parse(&arguments)?;
                parsed.validate(context)?;
                let scope = plugin_scope(&parsed.plugin_id, &parsed.plugin_version)?;
                (
                    canonical(&parsed)?,
                    Capability::new(CapabilityName::PluginSettingsSet, scope),
                )
            }
            "plugin.quarantine.release" => {
                let parsed: QuarantineReleaseArguments = parse(&arguments)?;
                parsed.validate()?;
                let scope = plugin_scope(&parsed.plugin_id, &parsed.plugin_version)?;
                (
                    canonical(&parsed)?,
                    Capability::new(CapabilityName::PluginQuarantineRelease, scope),
                )
            }
            _ => {
                return Err(NormalizationError::new(format!(
                    "unsupported extension action: {kind}"
                )));
            }
        };
        Ok(ActionEnvelope::new(
            ActionId::new(),
            context.run_id(),
            context.workspace_id(),
            context.actor().clone(),
            ComponentId::new(ADMIN_COMPONENT).expect("static component ID"),
            ActionKind::new(kind).map_err(normalization)?,
            arguments,
            vec![capability],
        ))
    }
}

#[derive(Clone)]
pub(crate) struct ExtensionAdminExecutor {
    database: Database,
    data_root: PathBuf,
    packages: PackageStager,
}

impl ExtensionAdminExecutor {
    pub(crate) fn new(database: Database, data_root: PathBuf) -> Self {
        Self {
            database,
            data_root,
            packages: PackageStager::default(),
        }
    }

    async fn dispatch(
        &self,
        action: &ActionEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ExecutionOutcome, ExecutorError> {
        if cancellation.is_cancelled() {
            return Ok(ExecutionOutcome::Cancelled);
        }
        let result = match action.kind().as_str() {
            "plugin.install" => self.install(action).await,
            "plugin.enable" => self.enable(action).await,
            "plugin.disable" => self.disable(action).await,
            "plugin.capabilities.set" => self.set_grants(action).await,
            "plugin.settings.set" => self.set_settings(action).await,
            "plugin.quarantine.release" => self.release_quarantine(action).await,
            kind => {
                return Err(ExecutorError::new(format!(
                    "unsupported extension action: {kind}"
                )));
            }
        };
        Ok(match result {
            Ok(value) => ExecutionOutcome::Succeeded(value),
            Err(message) => ExecutionOutcome::Failed(message),
        })
    }

    async fn install(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: InstallArguments = parse_executor(action.arguments())?;
        arguments.validate().map_err(|error| error.to_string())?;
        let staged = self
            .database
            .staged_plugin_package(arguments.stage_id)
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "staged plugin package was not found".to_owned())?;
        if staged.manifest().id().as_str() != arguments.plugin_id
            || staged.manifest().version().as_str() != arguments.plugin_version
            || staged.package_digest().as_str() != arguments.package_digest
            || staged.manifest_digest().as_str() != arguments.manifest_digest
            || staged.manifest().integrity().artifact().as_str() != arguments.artifact_digest
        {
            return Err("staged plugin identity changed after approval".into());
        }
        let identity = PackageIdentity::new(
            staged.manifest().clone(),
            staged.file_hashes().clone(),
            staged.package_digest().clone(),
            staged.manifest_digest().clone(),
            staged.manifest().integrity().artifact().clone(),
        );
        let installed_root = self.data_root.join("plugins/installed");
        let installed = self
            .packages
            .install_staged(
                self.data_root.join(staged.quarantine_path()),
                &installed_root,
                &identity,
            )
            .map_err(|error| error.to_string())?;
        let artifact = installed
            .path()
            .join(staged.manifest().runtime().entrypoint().as_str());
        let relative = artifact
            .strip_prefix(&self.data_root)
            .map_err(|_| "installed artifact escaped the runtime data directory".to_owned())?
            .to_str()
            .ok_or_else(|| "installed artifact path is not UTF-8".to_owned())?;
        self.database
            .install_staged_plugin(arguments.stage_id, relative, now())
            .await
            .map_err(|error| error.to_string())?;
        Ok(CanonicalValue::object([
            ("plugin_id", CanonicalValue::from(arguments.plugin_id)),
            (
                "plugin_version",
                CanonicalValue::from(arguments.plugin_version),
            ),
            (
                "package_digest",
                CanonicalValue::from(arguments.package_digest),
            ),
        ]))
    }

    async fn enable(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: VersionArguments = parse_executor(action.arguments())?;
        let (plugin, version) = arguments.parsed()?;
        self.database
            .enable_plugin_version(action.workspace_id(), plugin, version, now())
            .await
            .map_err(|error| error.to_string())?;
        Ok(version_result(arguments, "enabled"))
    }

    async fn disable(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: VersionArguments = parse_executor(action.arguments())?;
        let (plugin, version) = arguments.parsed()?;
        self.database
            .disable_plugin_version(action.workspace_id(), plugin, version, now())
            .await
            .map_err(|error| error.to_string())?;
        Ok(version_result(arguments, "disabled"))
    }

    async fn set_grants(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: NormalizedGrantArguments = parse_executor(action.arguments())?;
        let plugin = PluginId::parse(&arguments.plugin_id).map_err(|error| error.to_string())?;
        let version =
            PluginVersion::parse(&arguments.plugin_version).map_err(|error| error.to_string())?;
        let component =
            PluginComponentId::parse(&arguments.component_id).map_err(|error| error.to_string())?;
        let scope = match arguments.scope_type.as_str() {
            "global" if arguments.scope_id == "*" => PluginGrantScope::Global,
            "workspace" if arguments.scope_id == action.workspace_id().to_string() => {
                PluginGrantScope::Workspace(action.workspace_id())
            }
            _ => return Err("grant scope does not match the authorized workspace".into()),
        };
        let grants = arguments
            .grants
            .iter()
            .map(|grant| grant.parse(action.workspace_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let digest = canonical_grant_set_digest(&grants);
        if digest.as_str() != arguments.grant_set_digest {
            return Err("grant-set digest changed after approval".into());
        }
        let revision = self
            .database
            .append_plugin_grant_revision(
                plugin,
                version,
                component,
                scope,
                arguments.expected_revision,
                grants,
                digest,
                now(),
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(CanonicalValue::object([
            (
                "revision",
                CanonicalValue::from(i64::try_from(revision).unwrap_or(i64::MAX)),
            ),
            (
                "grant_set_digest",
                CanonicalValue::from(arguments.grant_set_digest),
            ),
        ]))
    }

    async fn set_settings(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: SettingArguments = parse_executor(action.arguments())?;
        arguments.validate_workspace(action.workspace_id())?;
        let plugin = PluginId::parse(&arguments.plugin_id).map_err(|error| error.to_string())?;
        let version =
            PluginVersion::parse(&arguments.plugin_version).map_err(|error| error.to_string())?;
        let installed = self
            .database
            .installed_plugin_version(plugin.clone(), version.clone())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "installed plugin version was not found".to_owned())?;
        if installed.is_artifact_quarantined() {
            return Err("plugin artifact is quarantined".into());
        }
        let schema_path = installed
            .manifest()
            .settings()
            .ok_or_else(|| "plugin does not declare settings".to_owned())?
            .schema();
        let artifact_path = self.data_root.join(installed.artifact_path());
        let package_root = artifact_path
            .parent()
            .ok_or_else(|| "installed artifact path has no package root".to_owned())?;
        let schema_bytes = std::fs::read(package_root.join(schema_path.as_str()))
            .map_err(|error| error.to_string())?;
        let schema_digest = format!("{:x}", Sha256::digest(&schema_bytes));
        if schema_digest != arguments.schema_digest {
            return Err("settings schema digest changed after approval".into());
        }
        let schema = BoundedSchema::compile(
            serde_json::from_slice(&schema_bytes).map_err(|error| error.to_string())?,
            SchemaLimits::default(),
        )
        .map_err(|error| error.to_string())?;
        let config = serde_json::to_value(&arguments.config).map_err(|error| error.to_string())?;
        schema
            .validate(&config)
            .map_err(|error| error.to_string())?;
        let scope = arguments.setting_scope(action.workspace_id(), action.actor())?;
        let revision = self
            .database
            .put_plugin_setting(
                plugin,
                version,
                scope,
                arguments.expected_version,
                config,
                Sha256Digest::parse(schema_digest).map_err(|error| error.to_string())?,
                now(),
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(CanonicalValue::object([
            (
                "config_version",
                CanonicalValue::from(i64::try_from(revision.config_version()).unwrap_or(i64::MAX)),
            ),
            (
                "settings_digest",
                CanonicalValue::from(revision.settings_digest().to_string()),
            ),
        ]))
    }

    async fn release_quarantine(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: QuarantineReleaseArguments = parse_executor(action.arguments())?;
        let plugin = PluginId::parse(&arguments.plugin_id).map_err(|error| error.to_string())?;
        let version =
            PluginVersion::parse(&arguments.plugin_version).map_err(|error| error.to_string())?;
        match arguments.quarantine_type.as_str() {
            "health" => {
                self.database
                    .release_plugin_health_quarantine(action.workspace_id(), plugin, version, now())
                    .await
                    .map_err(|error| error.to_string())?;
            }
            "artifact" => {
                let installed = self
                    .database
                    .installed_plugin_version(plugin.clone(), version.clone())
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "installed plugin version was not found".to_owned())?;
                if !installed.is_artifact_quarantined() {
                    return Err("plugin artifact is not quarantined".into());
                }
                let staged = self
                    .database
                    .staged_plugin_package_by_digest(installed.package_digest().clone())
                    .await
                    .map_err(|error| error.to_string())?
                    .ok_or_else(|| "reviewed staged identity was not found".to_owned())?;
                let identity = PackageIdentity::new(
                    staged.manifest().clone(),
                    staged.file_hashes().clone(),
                    staged.package_digest().clone(),
                    staged.manifest_digest().clone(),
                    staged.manifest().integrity().artifact().clone(),
                );
                let artifact_path = self.data_root.join(installed.artifact_path());
                let package_root = artifact_path
                    .parent()
                    .ok_or_else(|| "installed artifact path has no package root".to_owned())?;
                self.packages
                    .verify_installed(package_root, &identity)
                    .map_err(|error| error.to_string())?;
                self.database
                    .release_plugin_artifact_quarantine(plugin, version, now())
                    .await
                    .map_err(|error| error.to_string())?;
            }
            _ => return Err("unsupported quarantine type".into()),
        }
        Ok(version_result(
            VersionArguments {
                plugin_id: arguments.plugin_id,
                plugin_version: arguments.plugin_version,
            },
            "disabled",
        ))
    }
}

impl ExecutorPort for ExtensionAdminExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move { self.dispatch(action.action(), cancellation).await })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstallArguments {
    pub(crate) stage_id: Uuid,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) package_digest: String,
    pub(crate) manifest_digest: String,
    pub(crate) artifact_digest: String,
}

impl InstallArguments {
    fn validate(&self) -> Result<(), NormalizationError> {
        PluginId::parse(&self.plugin_id).map_err(normalization)?;
        PluginVersion::parse(&self.plugin_version).map_err(normalization)?;
        for value in [
            &self.package_digest,
            &self.manifest_digest,
            &self.artifact_digest,
        ] {
            Sha256Digest::parse(value).map_err(normalization)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VersionArguments {
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
}

impl VersionArguments {
    fn validate(&self) -> Result<(), NormalizationError> {
        self.parsed().map(|_| ()).map_err(NormalizationError::new)
    }

    fn parsed(&self) -> Result<(PluginId, PluginVersion), String> {
        Ok((
            PluginId::parse(&self.plugin_id).map_err(|error| error.to_string())?,
            PluginVersion::parse(&self.plugin_version).map_err(|error| error.to_string())?,
        ))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantArguments {
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) component_id: String,
    pub(crate) scope_type: String,
    pub(crate) scope_id: String,
    pub(crate) expected_revision: Option<u64>,
    pub(crate) grants: Vec<GrantInput>,
}

impl GrantArguments {
    fn normalize(
        self,
        context: &RunContext,
    ) -> Result<NormalizedGrantArguments, NormalizationError> {
        PluginId::parse(&self.plugin_id).map_err(normalization)?;
        PluginVersion::parse(&self.plugin_version).map_err(normalization)?;
        PluginComponentId::parse(&self.component_id).map_err(normalization)?;
        match self.scope_type.as_str() {
            "global" if self.scope_id == "*" => {}
            "workspace" if self.scope_id == context.workspace_id().to_string() => {}
            _ => {
                return Err(NormalizationError::new(
                    "grant scope does not match the request workspace",
                ));
            }
        }
        let grants = self
            .grants
            .into_iter()
            .map(|grant| grant.normalize(context.workspace_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let parsed = grants
            .iter()
            .map(|grant| grant.parse(context.workspace_id()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(NormalizationError::new)?;
        let digest = canonical_grant_set_digest(&parsed).to_string();
        Ok(NormalizedGrantArguments {
            plugin_id: self.plugin_id,
            plugin_version: self.plugin_version,
            component_id: self.component_id,
            scope_type: self.scope_type,
            scope_id: self.scope_id,
            expected_revision: self.expected_revision,
            grants,
            grant_set_digest: digest,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NormalizedGrantArguments {
    plugin_id: String,
    plugin_version: String,
    component_id: String,
    scope_type: String,
    scope_id: String,
    expected_revision: Option<u64>,
    grants: Vec<GrantInput>,
    grant_set_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantInput {
    pub(crate) name: String,
    pub(crate) scope: CanonicalValue,
}

impl GrantInput {
    fn normalize(
        self,
        workspace: lumen_core::identity::WorkspaceId,
    ) -> Result<Self, NormalizationError> {
        let capability = self.parse(workspace).map_err(NormalizationError::new)?;
        Ok(Self {
            name: capability.name().as_str().to_owned(),
            scope: serde_json::from_value(
                serde_json::to_value(capability.scope()).map_err(normalization)?,
            )
            .map_err(normalization)?,
        })
    }

    fn parse(&self, workspace: lumen_core::identity::WorkspaceId) -> Result<Capability, String> {
        let name = CapabilityName::parse(&self.name)
            .ok_or_else(|| "unknown capability name".to_owned())?;
        let object = match &self.scope {
            CanonicalValue::Object(object) => object,
            _ => return Err("capability scope must be an object".into()),
        };
        let text = |key: &str| match object.get(key) {
            Some(CanonicalValue::String(value)) => Ok(value.as_str()),
            _ => Err(format!("capability scope is missing {key}")),
        };
        let scope = match text("type")? {
            "workspace" => {
                if text("workspace_id")? != workspace.to_string() {
                    return Err("capability workspace does not match the request".into());
                }
                ResourceScope::workspace(workspace)
            }
            "path" => {
                if text("workspace_id")? != workspace.to_string() {
                    return Err("capability workspace does not match the request".into());
                }
                ResourceScope::path(
                    workspace,
                    WorkspacePath::parse(text("path")?).map_err(|error| error.to_string())?,
                )
            }
            "exact" => ResourceScope::exact(text("resource_type")?, text("value")?)
                .map_err(|error| error.to_string())?,
            _ => return Err("unsupported capability scope".into()),
        };
        Ok(Capability::new(name, scope))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SettingArguments {
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) scope_type: String,
    pub(crate) scope_id: String,
    pub(crate) expected_version: Option<u64>,
    pub(crate) config: CanonicalValue,
    pub(crate) schema_digest: String,
}

impl SettingArguments {
    fn validate(&self, context: &RunContext) -> Result<(), NormalizationError> {
        PluginId::parse(&self.plugin_id).map_err(normalization)?;
        PluginVersion::parse(&self.plugin_version).map_err(normalization)?;
        Sha256Digest::parse(&self.schema_digest).map_err(normalization)?;
        self.setting_scope(context.workspace_id(), context.actor())
            .map(|_| ())
            .map_err(NormalizationError::new)
    }

    fn validate_workspace(
        &self,
        workspace: lumen_core::identity::WorkspaceId,
    ) -> Result<(), String> {
        match self.scope_type.as_str() {
            "global" if self.scope_id == "*" => Ok(()),
            "workspace" if self.scope_id == workspace.to_string() => Ok(()),
            "user" | "agent" if !self.scope_id.is_empty() => Ok(()),
            _ => Err("settings scope does not match the request workspace".into()),
        }
    }

    fn setting_scope(
        &self,
        workspace: lumen_core::identity::WorkspaceId,
        actor: &lumen_core::identity::PrincipalId,
    ) -> Result<PluginSettingScope, String> {
        match self.scope_type.as_str() {
            "global" if self.scope_id == "*" => Ok(PluginSettingScope::Global),
            "workspace" if self.scope_id == workspace.to_string() => {
                Ok(PluginSettingScope::Workspace(workspace))
            }
            "user" if self.scope_id == format!("{}:{}", actor.provider(), actor.subject()) => {
                Ok(PluginSettingScope::User(actor.clone()))
            }
            "agent" => {
                PluginComponentId::parse(&self.scope_id).map_err(|error| error.to_string())?;
                Ok(PluginSettingScope::Agent(self.scope_id.clone()))
            }
            _ => Err("settings scope is not authorized for the request actor".into()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QuarantineReleaseArguments {
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) quarantine_type: String,
}

impl QuarantineReleaseArguments {
    fn validate(&self) -> Result<(), NormalizationError> {
        PluginId::parse(&self.plugin_id).map_err(normalization)?;
        PluginVersion::parse(&self.plugin_version).map_err(normalization)?;
        if !matches!(self.quarantine_type.as_str(), "health" | "artifact") {
            return Err(NormalizationError::new("unsupported quarantine type"));
        }
        Ok(())
    }
}

fn plugin_scope(plugin_id: &str, version: &str) -> Result<ResourceScope, NormalizationError> {
    ResourceScope::exact("plugin", format!("{plugin_id}@{version}")).map_err(normalization)
}

fn canonical(value: &impl Serialize) -> Result<CanonicalValue, NormalizationError> {
    serde_json::from_value(serde_json::to_value(value).map_err(normalization)?)
        .map_err(normalization)
}

fn parse<T: DeserializeOwned>(value: &CanonicalValue) -> Result<T, NormalizationError> {
    serde_json::from_value(serde_json::to_value(value).map_err(normalization)?)
        .map_err(normalization)
}

fn parse_executor<T: DeserializeOwned>(value: &CanonicalValue) -> Result<T, String> {
    serde_json::from_value(serde_json::to_value(value).map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())
}

fn normalization(error: impl std::fmt::Display) -> NormalizationError {
    NormalizationError::new(error.to_string())
}

fn version_result(arguments: VersionArguments, state: &str) -> CanonicalValue {
    CanonicalValue::object([
        ("plugin_id", CanonicalValue::from(arguments.plugin_id)),
        (
            "plugin_version",
            CanonicalValue::from(arguments.plugin_version),
        ),
        ("state", CanonicalValue::from(state)),
    ])
}

pub(crate) fn admin_capabilities(
    plugin_id: &str,
    version: &str,
) -> Result<Vec<Capability>, NormalizationError> {
    let scope = plugin_scope(plugin_id, version)?;
    Ok([
        CapabilityName::PluginInstall,
        CapabilityName::PluginEnable,
        CapabilityName::PluginCapabilitiesSet,
        CapabilityName::PluginSettingsSet,
        CapabilityName::PluginQuarantineRelease,
    ]
    .into_iter()
    .map(|name| Capability::new(name, scope.clone()))
    .collect())
}

pub(crate) fn action_proposal(
    kind: &str,
    arguments: &impl Serialize,
) -> Result<ActionProposal, NormalizationError> {
    Ok(ActionProposal::new(kind, canonical(arguments)?))
}

pub(crate) fn is_extension_action(kind: &str) -> bool {
    matches!(
        kind,
        "plugin.install"
            | "plugin.enable"
            | "plugin.disable"
            | "plugin.capabilities.set"
            | "plugin.settings.set"
            | "plugin.quarantine.release"
            | "plugin.invoke"
    )
}
