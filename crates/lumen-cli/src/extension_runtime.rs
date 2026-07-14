use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorFuture, ExecutorPort},
    extension::{
        AttributedActionProposal, ExtensionFailureClass, ExtensionInvocationLimits,
        ExtensionProvenance, ExtensionResponse, PluginComponentId, PluginId, PluginRuntime,
        PluginVersion, ProtocolVersion, Sha256Digest, canonical_grant_set_digest,
    },
    identity::ComponentId,
    model::ActionProposal,
    run::{ActionNormalizer, NormalizationError, RunContext},
};
use lumen_db::{
    Database, InstalledPluginVersion, PluginGrantScope, PluginSettingScope, PluginWorkspaceState,
};
use lumen_extension_sdk::{CURRENT_PROTOCOL_VERSION, InvocationRequest};
use lumen_integrations::{
    extension_package::{PackageIdentity, PackageStager},
    extension_process::{SubprocessHost, SubprocessHostError},
    extension_schema::{BoundedSchema, SchemaLimits, merge_scoped_settings},
    extension_wasm::{WasmComponentHost, WasmHostError},
    sandbox::{ResourceLimits, SandboxBackend},
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
            "plugin.invoke" => {
                let parsed: InvokeArguments = parse(&arguments)?;
                let normalized = parsed.normalize(context)?;
                let capability = Capability::new(
                    CapabilityName::PluginInvoke,
                    plugin_component_scope(
                        &normalized.plugin_id,
                        &normalized.plugin_version,
                        &normalized.component_id,
                    )?,
                );
                let provenance = normalized.provenance()?;
                return Ok(ActionEnvelope::new(
                    ActionId::new(),
                    context.run_id(),
                    context.workspace_id(),
                    context.actor().clone(),
                    ComponentId::new(ADMIN_COMPONENT).expect("static component ID"),
                    ActionKind::new(kind).map_err(normalization)?,
                    canonical(&normalized)?,
                    vec![capability],
                )
                .with_extension_provenance(provenance));
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvokeArguments {
    pub(crate) request_id: Uuid,
    pub(crate) plugin_id: String,
    pub(crate) plugin_version: String,
    pub(crate) component_id: String,
    pub(crate) runtime: PluginRuntime,
    pub(crate) protocol_version: u16,
    pub(crate) package_digest: String,
    pub(crate) manifest_digest: String,
    pub(crate) artifact_digest: String,
    pub(crate) settings_digest: String,
    pub(crate) grant_set_digest: String,
    pub(crate) input_hash: String,
    pub(crate) input: CanonicalValue,
    pub(crate) settings: CanonicalValue,
    pub(crate) effective_grants: Vec<GrantInput>,
    pub(crate) declared_action_kinds: Vec<String>,
    pub(crate) limits: InvokeLimits,
}

impl InvokeArguments {
    fn normalize(mut self, context: &RunContext) -> Result<Self, NormalizationError> {
        PluginId::parse(&self.plugin_id).map_err(normalization)?;
        PluginVersion::parse(&self.plugin_version).map_err(normalization)?;
        PluginComponentId::parse(&self.component_id).map_err(normalization)?;
        ProtocolVersion::new(self.protocol_version).map_err(normalization)?;
        if self.protocol_version != CURRENT_PROTOCOL_VERSION {
            return Err(NormalizationError::new(
                "plugin invocation protocol version is unsupported",
            ));
        }
        self.limits.parse().map_err(normalization)?;
        for value in [
            &self.package_digest,
            &self.manifest_digest,
            &self.artifact_digest,
            &self.settings_digest,
            &self.grant_set_digest,
            &self.input_hash,
        ] {
            Sha256Digest::parse(value).map_err(normalization)?;
        }
        let input_hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&self.input).map_err(normalization)?)
        );
        if input_hash != self.input_hash {
            return Err(NormalizationError::new(
                "plugin invocation input hash changed",
            ));
        }
        let mut parsed_grants = self
            .effective_grants
            .into_iter()
            .map(|grant| grant.normalize(context.workspace_id()))
            .collect::<Result<Vec<_>, _>>()?;
        parsed_grants.sort_by_key(|grant| {
            serde_json::to_string(grant).expect("normalized capability serialization")
        });
        parsed_grants.dedup_by(|left, right| left.name == right.name && left.scope == right.scope);
        let grants = parsed_grants
            .iter()
            .map(|grant| grant.parse(context.workspace_id()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(NormalizationError::new)?;
        if canonical_grant_set_digest(&grants).as_str() != self.grant_set_digest {
            return Err(NormalizationError::new(
                "plugin invocation grant-set digest changed",
            ));
        }
        self.declared_action_kinds
            .iter()
            .map(ActionKind::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(normalization)?;
        self.declared_action_kinds.sort_unstable();
        self.declared_action_kinds.dedup();
        self.effective_grants = parsed_grants;
        Ok(self)
    }

    fn provenance(&self) -> Result<ExtensionProvenance, NormalizationError> {
        Ok(ExtensionProvenance::new(
            PluginId::parse(&self.plugin_id).map_err(normalization)?,
            PluginVersion::parse(&self.plugin_version).map_err(normalization)?,
            PluginComponentId::parse(&self.component_id).map_err(normalization)?,
            self.runtime,
            Sha256Digest::parse(&self.package_digest).map_err(normalization)?,
            Sha256Digest::parse(&self.manifest_digest).map_err(normalization)?,
            Sha256Digest::parse(&self.artifact_digest).map_err(normalization)?,
            Sha256Digest::parse(&self.settings_digest).map_err(normalization)?,
            Sha256Digest::parse(&self.grant_set_digest).map_err(normalization)?,
            ProtocolVersion::new(self.protocol_version).map_err(normalization)?,
            None,
        ))
    }

    fn limits(&self) -> Result<ExtensionInvocationLimits, String> {
        self.limits.parse()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvokeLimits {
    pub(crate) deadline_millis: u64,
    pub(crate) max_result_bytes: u64,
    pub(crate) fuel: u64,
    pub(crate) max_memory_bytes: u64,
}

impl InvokeLimits {
    fn parse(self) -> Result<ExtensionInvocationLimits, String> {
        ExtensionInvocationLimits::new(
            self.deadline_millis,
            self.max_result_bytes,
            self.fuel,
            self.max_memory_bytes,
        )
        .map_err(|error| error.to_string())
    }
}

impl Default for InvokeLimits {
    fn default() -> Self {
        Self {
            deadline_millis: 30_000,
            max_result_bytes: 1024 * 1024,
            fuel: 10_000_000,
            max_memory_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone)]
struct InvocationContext {
    installed: InstalledPluginVersion,
    component: lumen_core::extension::PluginComponentManifest,
    settings: CanonicalValue,
    settings_digest: Sha256Digest,
    grants: Vec<Capability>,
    grant_set_digest: Sha256Digest,
}

impl InvocationContext {
    fn arguments(
        &self,
        request_id: Uuid,
        input: CanonicalValue,
    ) -> Result<InvokeArguments, String> {
        let input_hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&input).map_err(|error| error.to_string())?)
        );
        let effective_grants = self
            .grants
            .iter()
            .map(GrantInput::from_capability)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(InvokeArguments {
            request_id,
            plugin_id: self.installed.manifest().id().to_string(),
            plugin_version: self.installed.manifest().version().to_string(),
            component_id: self.component.id().to_string(),
            runtime: self.installed.manifest().runtime().runtime(),
            protocol_version: self.installed.manifest().runtime().protocol_version().get(),
            package_digest: self.installed.package_digest().to_string(),
            manifest_digest: self.installed.manifest_digest().to_string(),
            artifact_digest: self.installed.artifact_digest().to_string(),
            settings_digest: self.settings_digest.to_string(),
            grant_set_digest: self.grant_set_digest.to_string(),
            input_hash,
            input,
            settings: self.settings.clone(),
            effective_grants,
            declared_action_kinds: self
                .component
                .action_kinds()
                .iter()
                .map(|kind| kind.as_str().to_owned())
                .collect(),
            limits: InvokeLimits::default(),
        })
    }
}

pub(crate) async fn prepare_invocation(
    database: &Database,
    data_root: &std::path::Path,
    target: InvocationTarget,
    input: CanonicalValue,
) -> Result<InvokeArguments, String> {
    let context = load_invocation_context(database, data_root, &target, &input).await?;
    context.arguments(target.request_id, input)
}

async fn load_invocation_context(
    database: &Database,
    data_root: &std::path::Path,
    target: &InvocationTarget,
    input: &CanonicalValue,
) -> Result<InvocationContext, String> {
    let workspace = target.workspace;
    let plugin = target.plugin.clone();
    let version = target.version.clone();
    let component_id = target.component.clone();
    let installed = database
        .installed_plugin_version(plugin.clone(), version.clone())
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "installed plugin version was not found".to_owned())?;
    if installed.is_artifact_quarantined() {
        return Err("plugin artifact is quarantined".into());
    }
    if database
        .plugin_workspace_state(workspace, plugin.clone(), version.clone())
        .await
        .map_err(|error| error.to_string())?
        != Some(PluginWorkspaceState::Enabled)
    {
        return Err("plugin version is not enabled in this workspace".into());
    }
    let component = installed
        .manifest()
        .components()
        .iter()
        .find(|candidate| candidate.id() == &component_id)
        .cloned()
        .ok_or_else(|| "plugin component was not found".to_owned())?;
    let artifact_path = data_root.join(installed.artifact_path());
    let package_root = artifact_path
        .parent()
        .ok_or_else(|| "installed artifact path has no package root".to_owned())?;
    let schema_limits = SchemaLimits::default();
    let input_schema = read_schema(package_root, component.input_schema(), schema_limits)?;
    let input_json = serde_json::to_value(input).map_err(|error| error.to_string())?;
    input_schema
        .validate(&input_json)
        .map_err(|error| error.to_string())?;

    let (settings, settings_digest) = if let Some(settings_manifest) =
        installed.manifest().settings()
    {
        let schema_path = package_root.join(settings_manifest.schema().as_str());
        let schema_bytes = std::fs::read(&schema_path).map_err(|error| error.to_string())?;
        let schema_digest = Sha256Digest::parse(format!("{:x}", Sha256::digest(&schema_bytes)))
            .expect("SHA-256 output is canonical");
        let schema = BoundedSchema::compile(
            serde_json::from_slice(&schema_bytes).map_err(|error| error.to_string())?,
            schema_limits,
        )
        .map_err(|error| error.to_string())?;
        let scopes = [
            PluginSettingScope::Global,
            PluginSettingScope::Workspace(workspace),
            PluginSettingScope::User(target.actor.clone()),
            PluginSettingScope::Agent(component_id.to_string()),
        ];
        let mut layers = Vec::new();
        for scope in scopes {
            if let Some(revision) = database
                .latest_plugin_setting(plugin.clone(), version.clone(), scope)
                .await
                .map_err(|error| error.to_string())?
            {
                if revision.schema_digest() != &schema_digest {
                    return Err("plugin settings schema changed after configuration".into());
                }
                layers.push((revision.config_version(), revision.config().clone()));
            }
        }
        let effective =
            merge_scoped_settings(&schema, layers).map_err(|error| error.to_string())?;
        (
            serde_json::from_value(effective.value().clone()).map_err(|error| error.to_string())?,
            effective.digest().clone(),
        )
    } else {
        let settings = CanonicalValue::object([] as [(&str, CanonicalValue); 0]);
        let digest = Sha256Digest::parse(format!(
            "{:x}",
            Sha256::digest(br#"{"settings":{},"revisions":[]}"#)
        ))
        .expect("SHA-256 output is canonical");
        (settings, digest)
    };

    let (grants, grant_set_digest) = if component.capabilities().is_empty() {
        let grants = Vec::new();
        let digest = canonical_grant_set_digest(&grants);
        (grants, digest)
    } else {
        let global = database
            .latest_plugin_grants(
                plugin.clone(),
                version.clone(),
                component_id.clone(),
                PluginGrantScope::Global,
            )
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "plugin component has no global grant revision".to_owned())?;
        let workspace_grants = database
            .latest_plugin_grants(
                plugin,
                version,
                component_id,
                PluginGrantScope::Workspace(workspace),
            )
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "plugin component has no workspace grant revision".to_owned())?;
        let grants = workspace_grants.capabilities().cloned().collect::<Vec<_>>();
        if grants.iter().any(|grant| !global.allows(grant)) {
            return Err("workspace plugin grants exceed the global revision".into());
        }
        let digest = canonical_grant_set_digest(&grants);
        if &digest != workspace_grants.digest() {
            return Err("stored plugin grant digest is inconsistent".into());
        }
        (grants, digest)
    };

    Ok(InvocationContext {
        installed,
        component,
        settings,
        settings_digest,
        grants,
        grant_set_digest,
    })
}

pub(crate) struct InvocationTarget {
    pub(crate) workspace: lumen_core::identity::WorkspaceId,
    pub(crate) actor: lumen_core::identity::PrincipalId,
    pub(crate) plugin: PluginId,
    pub(crate) version: PluginVersion,
    pub(crate) component: PluginComponentId,
    pub(crate) request_id: Uuid,
}

fn read_schema(
    package_root: &std::path::Path,
    path: &lumen_core::extension::ManifestPath,
    limits: SchemaLimits,
) -> Result<BoundedSchema, String> {
    let bytes =
        std::fs::read(package_root.join(path.as_str())).map_err(|error| error.to_string())?;
    BoundedSchema::compile(
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?,
        limits,
    )
    .map_err(|error| error.to_string())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ActiveInvocationKey {
    workspace: lumen_core::identity::WorkspaceId,
    plugin: PluginId,
    version: PluginVersion,
    component: PluginComponentId,
}

#[derive(Clone, Default)]
struct ActiveInvocations {
    entries: Arc<Mutex<BTreeMap<ActiveInvocationKey, BTreeMap<Uuid, CancellationToken>>>>,
}

impl ActiveInvocations {
    fn register(
        &self,
        key: ActiveInvocationKey,
        invocation_id: Uuid,
        token: CancellationToken,
    ) -> ActiveInvocationRegistration {
        self.entries
            .lock()
            .expect("active invocation lock")
            .entry(key.clone())
            .or_default()
            .insert(invocation_id, token);
        ActiveInvocationRegistration {
            active: self.clone(),
            key,
            invocation_id,
        }
    }

    fn cancel_workspace_plugin(
        &self,
        workspace: lumen_core::identity::WorkspaceId,
        plugin: &PluginId,
    ) {
        self.cancel_where(|key| key.workspace == workspace && &key.plugin == plugin);
    }

    fn cancel_workspace_version(
        &self,
        workspace: lumen_core::identity::WorkspaceId,
        plugin: &PluginId,
        version: &PluginVersion,
    ) {
        self.cancel_where(|key| {
            key.workspace == workspace && &key.plugin == plugin && &key.version == version
        });
    }

    fn cancel_component(
        &self,
        workspace: Option<lumen_core::identity::WorkspaceId>,
        plugin: &PluginId,
        version: &PluginVersion,
        component: &PluginComponentId,
    ) {
        self.cancel_where(|key| {
            workspace.is_none_or(|workspace| key.workspace == workspace)
                && &key.plugin == plugin
                && &key.version == version
                && &key.component == component
        });
    }

    fn cancel_global_version(&self, plugin: &PluginId, version: &PluginVersion) {
        self.cancel_where(|key| &key.plugin == plugin && &key.version == version);
    }

    fn cancel_where(&self, predicate: impl Fn(&ActiveInvocationKey) -> bool) {
        let entries = self.entries.lock().expect("active invocation lock");
        for (key, invocations) in entries.iter() {
            if predicate(key) {
                for token in invocations.values() {
                    token.cancel();
                }
            }
        }
    }

    fn remove(&self, key: &ActiveInvocationKey, invocation_id: Uuid) {
        let mut entries = self.entries.lock().expect("active invocation lock");
        if let Some(invocations) = entries.get_mut(key) {
            invocations.remove(&invocation_id);
            if invocations.is_empty() {
                entries.remove(key);
            }
        }
    }
}

struct ActiveInvocationRegistration {
    active: ActiveInvocations,
    key: ActiveInvocationKey,
    invocation_id: Uuid,
}

impl Drop for ActiveInvocationRegistration {
    fn drop(&mut self) {
        self.active.remove(&self.key, self.invocation_id);
    }
}

#[derive(Clone)]
pub(crate) struct ExtensionExecutor {
    admin: ExtensionAdminExecutor,
    invocation: ExtensionInvocationExecutor,
}

impl ExtensionExecutor {
    pub(crate) fn new(
        database: Database,
        data_root: PathBuf,
        sandbox: Arc<dyn SandboxBackend>,
        resource_limits: ResourceLimits,
        max_stderr_bytes: usize,
    ) -> Result<Self, String> {
        let active = ActiveInvocations::default();
        Ok(Self {
            admin: ExtensionAdminExecutor::new(database.clone(), data_root.clone(), active.clone()),
            invocation: ExtensionInvocationExecutor::new(
                database,
                data_root,
                active,
                sandbox,
                resource_limits,
                max_stderr_bytes,
            )?,
        })
    }
}

impl ExecutorPort for ExtensionExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        if action.action().kind().as_str() == "plugin.invoke" {
            self.invocation.execute(action, cancellation)
        } else {
            self.admin.execute(action, cancellation)
        }
    }
}

#[derive(Clone)]
struct ExtensionAdminExecutor {
    database: Database,
    data_root: PathBuf,
    packages: PackageStager,
    active: ActiveInvocations,
}

impl ExtensionAdminExecutor {
    fn new(database: Database, data_root: PathBuf, active: ActiveInvocations) -> Self {
        Self {
            database,
            data_root,
            packages: PackageStager::default(),
            active,
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
        if staged.manifest().runtime().runtime() == PluginRuntime::Subprocess {
            make_runtime_executable(&artifact).map_err(|error| error.to_string())?;
        }
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
            .enable_plugin_version(action.workspace_id(), plugin.clone(), version, now())
            .await
            .map_err(|error| error.to_string())?;
        self.active
            .cancel_workspace_plugin(action.workspace_id(), &plugin);
        Ok(version_result(arguments, "enabled"))
    }

    async fn disable(&self, action: &ActionEnvelope) -> Result<CanonicalValue, String> {
        let arguments: VersionArguments = parse_executor(action.arguments())?;
        let (plugin, version) = arguments.parsed()?;
        self.database
            .disable_plugin_version(
                action.workspace_id(),
                plugin.clone(),
                version.clone(),
                now(),
            )
            .await
            .map_err(|error| error.to_string())?;
        self.active
            .cancel_workspace_version(action.workspace_id(), &plugin, &version);
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
                plugin.clone(),
                version.clone(),
                component.clone(),
                scope.clone(),
                arguments.expected_revision,
                grants,
                digest,
                now(),
            )
            .await
            .map_err(|error| error.to_string())?;
        let workspace = match scope {
            PluginGrantScope::Global => None,
            PluginGrantScope::Workspace(workspace) => Some(workspace),
        };
        self.active
            .cancel_component(workspace, &plugin, &version, &component);
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
                plugin.clone(),
                version.clone(),
                scope.clone(),
                arguments.expected_version,
                config,
                Sha256Digest::parse(schema_digest).map_err(|error| error.to_string())?,
                now(),
            )
            .await
            .map_err(|error| error.to_string())?;
        match scope {
            PluginSettingScope::Global => self.active.cancel_global_version(&plugin, &version),
            PluginSettingScope::Workspace(workspace) => self
                .active
                .cancel_workspace_version(workspace, &plugin, &version),
            PluginSettingScope::User(_) | PluginSettingScope::Agent(_) => self
                .active
                .cancel_workspace_version(action.workspace_id(), &plugin, &version),
        }
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

#[derive(Clone)]
struct ExtensionInvocationExecutor {
    database: Database,
    data_root: PathBuf,
    packages: PackageStager,
    active: ActiveInvocations,
    wasm: WasmComponentHost,
    subprocess: SubprocessHost,
}

impl ExtensionInvocationExecutor {
    fn new(
        database: Database,
        data_root: PathBuf,
        active: ActiveInvocations,
        sandbox: Arc<dyn SandboxBackend>,
        resource_limits: ResourceLimits,
        max_stderr_bytes: usize,
    ) -> Result<Self, String> {
        Ok(Self {
            database,
            data_root,
            packages: PackageStager::default(),
            active,
            wasm: WasmComponentHost::default(),
            subprocess: SubprocessHost::new(sandbox, resource_limits, max_stderr_bytes)
                .map_err(|error| error.to_string())?,
        })
    }

    async fn dispatch(
        &self,
        action: &ActionEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ExecutionOutcome, ExecutorError> {
        if cancellation.is_cancelled() {
            return Ok(ExecutionOutcome::Cancelled);
        }
        let arguments: InvokeArguments =
            parse_executor(action.arguments()).map_err(ExecutorError::new)?;
        let arguments = arguments
            .normalize(&RunContext::new(
                action.run_id(),
                action.workspace_id(),
                action.actor().clone(),
            ))
            .map_err(|error| ExecutorError::new(error.to_string()))?;
        let provenance = arguments
            .provenance()
            .map_err(|error| ExecutorError::new(error.to_string()))?;
        if action.extension_provenance() != Some(&provenance) {
            return Ok(ExecutionOutcome::Failed(
                "plugin invocation provenance changed after authorization".into(),
            ));
        }
        let plugin = PluginId::parse(&arguments.plugin_id)
            .map_err(|error| ExecutorError::new(error.to_string()))?;
        let version = PluginVersion::parse(&arguments.plugin_version)
            .map_err(|error| ExecutorError::new(error.to_string()))?;
        let component = PluginComponentId::parse(&arguments.component_id)
            .map_err(|error| ExecutorError::new(error.to_string()))?;
        let target = InvocationTarget {
            workspace: action.workspace_id(),
            actor: action.actor().clone(),
            plugin: plugin.clone(),
            version: version.clone(),
            component: component.clone(),
            request_id: arguments.request_id,
        };
        let context = match load_invocation_context(
            &self.database,
            &self.data_root,
            &target,
            &arguments.input,
        )
        .await
        {
            Ok(context) => context,
            Err(error) => return Ok(ExecutionOutcome::Failed(error)),
        };
        let mut expected = context
            .arguments(arguments.request_id, arguments.input.clone())
            .map_err(ExecutorError::new)?;
        expected.limits = arguments.limits;
        if expected != arguments {
            return Ok(ExecutionOutcome::Failed(
                "plugin invocation context changed after authorization".into(),
            ));
        }

        let artifact_path = self.data_root.join(context.installed.artifact_path());
        let package_root = artifact_path
            .parent()
            .ok_or_else(|| ExecutorError::new("installed artifact path has no package root"))?;
        if let Err(error) = self
            .verify_installed(&context.installed, package_root)
            .await
        {
            let _ = self
                .database
                .quarantine_plugin_artifact(plugin.clone(), version.clone(), now())
                .await;
            self.active.cancel_global_version(&plugin, &version);
            return Ok(ExecutionOutcome::Failed(format!(
                "installed plugin package failed verification: {error}"
            )));
        }
        let output_schema = match read_schema(
            package_root,
            context.component.output_schema(),
            SchemaLimits::default(),
        ) {
            Ok(schema) => schema,
            Err(error) => {
                let _ = self
                    .database
                    .quarantine_plugin_artifact(plugin.clone(), version.clone(), now())
                    .await;
                self.active.cancel_global_version(&plugin, &version);
                return Ok(ExecutionOutcome::Failed(format!(
                    "installed plugin output schema failed verification: {error}"
                )));
            }
        };

        let invocation_token = cancellation.child_token();
        let key = ActiveInvocationKey {
            workspace: action.workspace_id(),
            plugin: plugin.clone(),
            version: version.clone(),
            component: component.clone(),
        };
        let _registration =
            self.active
                .register(key, arguments.request_id, invocation_token.clone());
        let context = match load_invocation_context(
            &self.database,
            &self.data_root,
            &target,
            &arguments.input,
        )
        .await
        {
            Ok(context) => context,
            Err(error) => return Ok(ExecutionOutcome::Failed(error)),
        };
        let mut expected = context
            .arguments(arguments.request_id, arguments.input.clone())
            .map_err(ExecutorError::new)?;
        expected.limits = arguments.limits;
        if expected != arguments {
            return Ok(ExecutionOutcome::Failed(
                "plugin invocation context changed before host dispatch".into(),
            ));
        }
        if invocation_token.is_cancelled() {
            return Ok(ExecutionOutcome::Cancelled);
        }
        let request = InvocationRequest::new(
            arguments.request_id.to_string(),
            &arguments.component_id,
            serde_json::to_value(&arguments.input)
                .map_err(|error| ExecutorError::new(error.to_string()))?,
            serde_json::to_value(&arguments.settings)
                .map_err(|error| ExecutorError::new(error.to_string()))?,
            arguments.limits.deadline_millis,
        )
        .map_err(|error| ExecutorError::new(error.to_string()))?;
        let limits = arguments.limits().map_err(ExecutorError::new)?;
        let response = match arguments.runtime {
            PluginRuntime::WasmComponent => {
                let bytes = match std::fs::read(&artifact_path) {
                    Ok(bytes) => Arc::<[u8]>::from(bytes),
                    Err(error) => {
                        return Ok(self
                            .artifact_failure(&plugin, &version, error.to_string())
                            .await);
                    }
                };
                self.wasm
                    .invoke(
                        context.installed.artifact_digest().clone(),
                        bytes,
                        request,
                        limits,
                        invocation_token.clone(),
                    )
                    .await
                    .map_err(HostInvocationError::from)
            }
            PluginRuntime::Subprocess => self
                .subprocess
                .invoke(
                    context.installed.artifact_digest().clone(),
                    &artifact_path,
                    request,
                    limits,
                    invocation_token.clone(),
                )
                .await
                .map_err(HostInvocationError::from),
        };
        if invocation_token.is_cancelled() {
            self.record_failure(
                action.workspace_id(),
                plugin,
                version,
                component,
                arguments.request_id,
                ExtensionFailureClass::Cancelled,
            )
            .await;
            return Ok(ExecutionOutcome::Cancelled);
        }
        match response {
            Ok(ExtensionResponse::Result { value }) => {
                let json = serde_json::to_value(&value)
                    .map_err(|error| ExecutorError::new(error.to_string()))?;
                if let Err(error) = output_schema.validate(&json) {
                    self.record_failure(
                        action.workspace_id(),
                        plugin,
                        version,
                        component,
                        arguments.request_id,
                        ExtensionFailureClass::PluginFault,
                    )
                    .await;
                    return Ok(ExecutionOutcome::Failed(format!(
                        "plugin result failed schema validation: {error}"
                    )));
                }
                Ok(ExecutionOutcome::Succeeded(value))
            }
            Ok(ExtensionResponse::Proposal {
                kind,
                arguments: proposal_arguments,
            }) => match AttributedActionProposal::new(
                ActionProposal::new(kind.as_str(), proposal_arguments),
                provenance.with_parent_action_id(action.id()),
                context.component.action_kinds().to_vec(),
                context.grants,
            ) {
                Ok(proposal) => Ok(ExecutionOutcome::Proposed(Box::new(proposal))),
                Err(error) => {
                    self.record_failure(
                        action.workspace_id(),
                        plugin,
                        version,
                        component,
                        arguments.request_id,
                        ExtensionFailureClass::PluginFault,
                    )
                    .await;
                    Ok(ExecutionOutcome::Failed(error.to_string()))
                }
            },
            Ok(ExtensionResponse::Failure { failure }) => {
                self.record_failure(
                    action.workspace_id(),
                    plugin,
                    version,
                    component,
                    arguments.request_id,
                    ExtensionFailureClass::PluginFault,
                )
                .await;
                Ok(ExecutionOutcome::Failed(failure.message().to_owned()))
            }
            Err(error) => {
                let class = error.failure_class();
                if error.is_artifact_mismatch() {
                    return Ok(self
                        .artifact_failure(&plugin, &version, error.to_string())
                        .await);
                }
                self.record_failure(
                    action.workspace_id(),
                    plugin,
                    version,
                    component,
                    arguments.request_id,
                    class,
                )
                .await;
                Ok(error.into_outcome())
            }
        }
    }

    async fn verify_installed(
        &self,
        installed: &InstalledPluginVersion,
        package_root: &Path,
    ) -> Result<(), String> {
        let staged = self
            .database
            .staged_plugin_package_by_digest(installed.package_digest().clone())
            .await
            .map_err(|error| error.to_string())?
            .ok_or_else(|| "reviewed staged identity was not found".to_owned())?;
        if staged.manifest_digest() != installed.manifest_digest()
            || staged.manifest().integrity().artifact() != installed.artifact_digest()
        {
            return Err("reviewed package identity differs from the installed record".into());
        }
        self.packages
            .verify_installed(
                package_root,
                &PackageIdentity::new(
                    staged.manifest().clone(),
                    staged.file_hashes().clone(),
                    staged.package_digest().clone(),
                    staged.manifest_digest().clone(),
                    staged.manifest().integrity().artifact().clone(),
                ),
            )
            .map_err(|error| error.to_string())
    }

    async fn artifact_failure(
        &self,
        plugin: &PluginId,
        version: &PluginVersion,
        message: String,
    ) -> ExecutionOutcome {
        let _ = self
            .database
            .quarantine_plugin_artifact(plugin.clone(), version.clone(), now())
            .await;
        self.active.cancel_global_version(plugin, version);
        ExecutionOutcome::Failed(format!("plugin artifact verification failed: {message}"))
    }

    async fn record_failure(
        &self,
        workspace: lumen_core::identity::WorkspaceId,
        plugin: PluginId,
        version: PluginVersion,
        component: PluginComponentId,
        invocation_id: Uuid,
        class: ExtensionFailureClass,
    ) {
        if self
            .database
            .record_plugin_failure(
                workspace,
                plugin.clone(),
                version.clone(),
                component,
                invocation_id,
                class,
                now(),
            )
            .await
            .is_ok_and(|state| state == PluginWorkspaceState::HealthQuarantine)
        {
            self.active
                .cancel_workspace_version(workspace, &plugin, &version);
        }
    }
}

impl ExecutorPort for ExtensionInvocationExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move { self.dispatch(action.action(), cancellation).await })
    }
}

enum HostInvocationError {
    ArtifactMismatch,
    Cancelled,
    TimedOut,
    ResourceExhaustion,
    PluginFault(String),
    HostFault(String),
}

impl HostInvocationError {
    const fn failure_class(&self) -> ExtensionFailureClass {
        match self {
            Self::Cancelled => ExtensionFailureClass::Cancelled,
            Self::ResourceExhaustion | Self::TimedOut => ExtensionFailureClass::ResourceExhaustion,
            Self::PluginFault(_) | Self::ArtifactMismatch => ExtensionFailureClass::PluginFault,
            Self::HostFault(_) => ExtensionFailureClass::HostFault,
        }
    }

    const fn is_artifact_mismatch(&self) -> bool {
        matches!(self, Self::ArtifactMismatch)
    }

    fn into_outcome(self) -> ExecutionOutcome {
        match self {
            Self::Cancelled => ExecutionOutcome::Cancelled,
            Self::TimedOut => ExecutionOutcome::TimedOut,
            Self::ResourceExhaustion => {
                ExecutionOutcome::Failed("plugin exhausted a resource limit".into())
            }
            Self::PluginFault(message) => ExecutionOutcome::Failed(message),
            Self::HostFault(message) => ExecutionOutcome::Unknown(message),
            Self::ArtifactMismatch => {
                ExecutionOutcome::Failed("plugin artifact digest changed".into())
            }
        }
    }
}

impl std::fmt::Display for HostInvocationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArtifactMismatch => formatter.write_str("plugin artifact digest changed"),
            Self::Cancelled => formatter.write_str("plugin invocation was cancelled"),
            Self::TimedOut => formatter.write_str("plugin invocation timed out"),
            Self::ResourceExhaustion => formatter.write_str("plugin exhausted a resource limit"),
            Self::PluginFault(message) | Self::HostFault(message) => formatter.write_str(message),
        }
    }
}

impl From<WasmHostError> for HostInvocationError {
    fn from(error: WasmHostError) -> Self {
        match error {
            WasmHostError::ArtifactDigestMismatch => Self::ArtifactMismatch,
            WasmHostError::Cancelled => Self::Cancelled,
            WasmHostError::DeadlineExceeded => Self::TimedOut,
            WasmHostError::ResourceExhaustion => Self::ResourceExhaustion,
            WasmHostError::Host(message) => Self::HostFault(message),
            error => Self::PluginFault(error.to_string()),
        }
    }
}

impl From<SubprocessHostError> for HostInvocationError {
    fn from(error: SubprocessHostError) -> Self {
        match error {
            SubprocessHostError::ArtifactDigestMismatch => Self::ArtifactMismatch,
            SubprocessHostError::Cancelled => Self::Cancelled,
            SubprocessHostError::DeadlineExceeded => Self::TimedOut,
            SubprocessHostError::ResourceExhaustion => Self::ResourceExhaustion,
            SubprocessHostError::SandboxUnavailable | SubprocessHostError::Host(_) => {
                Self::HostFault(error.to_string())
            }
            error => Self::PluginFault(error.to_string()),
        }
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GrantInput {
    pub(crate) name: String,
    pub(crate) scope: CanonicalValue,
}

impl GrantInput {
    fn from_capability(capability: &Capability) -> Result<Self, String> {
        Ok(Self {
            name: capability.name().as_str().to_owned(),
            scope: serde_json::from_value(
                serde_json::to_value(capability.scope()).map_err(|error| error.to_string())?,
            )
            .map_err(|error| error.to_string())?,
        })
    }

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

fn plugin_component_scope(
    plugin_id: &str,
    version: &str,
    component_id: &str,
) -> Result<ResourceScope, NormalizationError> {
    ResourceScope::exact(
        "plugin_component",
        format!("{plugin_id}@{version}#{component_id}"),
    )
    .map_err(normalization)
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

#[cfg(unix)]
fn make_runtime_executable(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))
}

#[cfg(not(unix))]
fn make_runtime_executable(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
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

pub(crate) fn invocation_capability(
    plugin_id: &str,
    version: &str,
    component_id: &str,
) -> Result<Capability, NormalizationError> {
    Ok(Capability::new(
        CapabilityName::PluginInvoke,
        plugin_component_scope(plugin_id, version, component_id)?,
    ))
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

#[cfg(test)]
mod tests {
    use lumen_core::{
        action::{CanonicalValue, RunId},
        capability::{Capability, CapabilityName, ResourceScope},
        identity::{PrincipalId, WorkspaceId},
        model::ActionProposal,
        run::{ActionNormalizer as _, RunContext},
    };
    use sha2::{Digest as _, Sha256};
    use uuid::Uuid;

    use super::ExtensionActionNormalizer;

    #[test]
    fn invocation_normalization_pins_identity_and_exact_authority() {
        let workspace = WorkspaceId::from_uuid(Uuid::new_v4());
        let context = RunContext::new(
            RunId::new(),
            workspace,
            PrincipalId::new("local", "operator").expect("principal"),
        );
        let input = serde_json::json!({"path": "notes.txt"});
        let input_hash = format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&input).expect("input JSON"))
        );
        let grant_set_digest = lumen_core::extension::canonical_grant_set_digest(&[]).to_string();
        let digest = "a".repeat(64);
        let arguments: CanonicalValue = serde_json::from_value(serde_json::json!({
            "request_id": Uuid::new_v4(),
            "plugin_id": "dev.example.fixture",
            "plugin_version": "1.0.0",
            "component_id": "reader",
            "runtime": "wasm-component",
            "protocol_version": 1,
            "package_digest": digest,
            "manifest_digest": "b".repeat(64),
            "artifact_digest": "c".repeat(64),
            "settings_digest": "d".repeat(64),
            "grant_set_digest": grant_set_digest,
            "input_hash": input_hash,
            "input": input,
            "settings": {},
            "effective_grants": [],
            "declared_action_kinds": ["filesystem.read"],
            "limits": {
                "deadline_millis": 30_000,
                "max_result_bytes": 1_048_576,
                "fuel": 10_000_000,
                "max_memory_bytes": 268_435_456
            }
        }))
        .expect("canonical arguments");

        let action = ExtensionActionNormalizer
            .normalize(&context, ActionProposal::new("plugin.invoke", arguments))
            .expect("normalized invocation");

        let scope = ResourceScope::exact("plugin_component", "dev.example.fixture@1.0.0#reader")
            .expect("scope");
        assert_eq!(
            action.required_capabilities(),
            &[Capability::new(CapabilityName::PluginInvoke, scope)]
        );
        let provenance = action.extension_provenance().expect("provenance");
        assert_eq!(
            provenance.resource_key(),
            "dev.example.fixture@1.0.0#reader"
        );
        assert_eq!(provenance.package_digest().as_str(), "a".repeat(64));
        assert!(provenance.parent_action_id().is_none());
    }
}
