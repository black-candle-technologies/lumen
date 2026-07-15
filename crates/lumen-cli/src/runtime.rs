use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lumen_core::{
    action::{ActionEnvelope, CanonicalValue, RunId},
    approval::{
        ApprovalId, ApprovalRequest, ApprovalState, DispatchAuthorization, ExecutionAttemptId,
        TimestampMillis,
    },
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    capability::{Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope},
    egress::{DataClass, DestinationScope, ProviderId, select_model_provider},
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorFuture, ExecutorPort},
    extension::{PluginComponentId, PluginId, PluginVersion},
    model::{ActionProposal, ModelError, ModelFuture, ModelInput, ModelPort},
    policy::{Policy, PolicyVersion},
    run::{
        ActionFuture, ActionNormalizer, ActionPort, ActionPortError, ApprovalFuture, ApprovalPort,
        ApprovalPortError, ApprovalResolution, AuditFuture, AuditPort, AuditPortError,
        NormalizationError, RunBudget, RunContext, RunOrchestrator, RunOutcome, RunState,
    },
    secret::SecretRefId,
};
use lumen_db::{
    Database, DispatchReservation, ModelEndpointClass, ModelProviderRevision, PluginGrantScope,
    PluginSettingScope, WorkspaceModelEgressRevision,
};
use lumen_integrations::{
    filesystem::WorkspaceReader,
    openai_compatible::{EndpointPolicy, OpenAiCompatibleClient, OpenAiCompatibleConfig},
    process::{
        BuiltinActionNormalizer, BuiltinExecutor, ProcessExecutor, ProcessSecretError,
        ProcessSecretFuture, ProcessSecretResolver,
    },
    sandbox::{ResourceLimits, SandboxBackend},
    secrets::SecretStore,
};
use lumen_server::{
    ApprovalDecision, ApprovalDecisionCommand, ApprovalPreview, ApprovalQuery, ApprovalResult,
    ApprovalSecretReference, AuditEntry, AuditQuery, CancelRunCommand, CreateRunCommand,
    EventBroker, PluginActionCommand, PluginActionRequested, PluginComponentReview,
    PluginDetailsQuery, PluginFailureReview, PluginReviewQuery, PluginSettingReview,
    PluginVersionDetails, PrincipalSummary, RunCancellation, RunCreated, RuntimeService,
    ServiceError, ServiceFuture, StagedPluginReview,
};
use sqlx::Row;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::extension_runtime::{
    ExtensionActionNormalizer, ExtensionExecutor, InvocationTarget, VersionArguments,
    action_proposal, admin_capabilities, invocation_capability, is_extension_action,
    prepare_invocation,
};
use crate::{
    CliError,
    config::{Config, RemoteDataClass},
};

#[derive(Clone)]
pub(crate) struct LocalRuntimeService {
    model: Arc<dyn ModelPort>,
    enforce_model_egress_policy: bool,
    normalizer: Arc<dyn ActionNormalizer>,
    executor: Arc<dyn ExecutorPort>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<DatabaseAudit>,
    actions: Arc<DatabaseActions>,
    database: Database,
    data_root: Arc<Path>,
    events: EventBroker,
    policy: Policy,
    policy_version: PolicyVersion,
    ambient_capabilities: CapabilitySet,
    capabilities: EffectiveCapabilities,
    budget: RunBudget,
    runs: Arc<Mutex<BTreeMap<RunId, StoredRun>>>,
    cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    run_workspaces: Arc<Mutex<BTreeMap<RunId, lumen_core::identity::WorkspaceId>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    redactor: Arc<SecretRedactor>,
}

struct PluginInvocationCommand {
    workspace_id: lumen_core::identity::WorkspaceId,
    actor: lumen_core::identity::PrincipalId,
    plugin_id: String,
    plugin_version: String,
    component_id: String,
    request_id: uuid::Uuid,
    input: CanonicalValue,
}

impl LocalRuntimeService {
    pub(crate) async fn build_with_secret_store(
        config: &Config,
        database: Database,
        events: EventBroker,
        sandbox: Arc<dyn SandboxBackend>,
        secrets: Vec<String>,
        secret_store: Arc<dyn SecretStore>,
    ) -> Result<Self, CliError> {
        let workspace = std::fs::canonicalize(&config.workspace.path)?;
        std::fs::create_dir_all(&config.runtime.data_directory)?;
        let data_root = std::fs::canonicalize(&config.runtime.data_directory)?;
        bootstrap_configured_remote_model_provider(config, &database).await?;
        let endpoint_policy = if config.model.allow_remote {
            EndpointPolicy::AllowRemote
        } else {
            EndpointPolicy::LoopbackOnly
        };
        let model_config = OpenAiCompatibleConfig::new(
            &config.model.endpoint,
            &config.model.model,
            endpoint_policy,
        )
        .map_err(|error| CliError::Runtime(error.to_string()))?
        .with_streaming(config.model.streaming)
        .with_timeout(Duration::from_secs(config.model.timeout_seconds))
        .with_max_response_bytes(config.model.max_response_bytes);
        let model = OpenAiCompatibleClient::new(model_config)
            .map_err(|error| CliError::Runtime(error.to_string()))?;
        let allowed_programs: Vec<_> = config.process.allowed_programs.iter().cloned().collect();
        let secret_references = database
            .list_secret_references(config.workspace_id())
            .await?;
        let network_egress_capabilities = database.enabled_network_egress_capabilities().await?;
        let channel_send_capabilities = database
            .allowed_channel_send_capabilities(config.workspace_id())
            .await?;
        let resource_limits = ResourceLimits::new(
            config.process.max_cpu_seconds,
            config.process.max_address_space_bytes,
            config.process.max_file_size_bytes,
            config.process.max_open_files,
            config.process.max_processes,
        )
        .map_err(|error| CliError::Runtime(error.to_string()))?;
        let process = ProcessExecutor::new(
            &workspace,
            allowed_programs.clone(),
            config.process.allowed_environment.clone(),
            Duration::from_secs(config.process.timeout_seconds),
            config.process.max_output_bytes,
            resource_limits,
            Arc::clone(&sandbox),
        )
        .map_err(|error| CliError::Runtime(error.to_string()))?;
        let filesystem = WorkspaceReader::with_limits(
            &workspace,
            config.runtime.file_read_limit_bytes,
            config.runtime.file_write_limit_bytes,
        )
        .map_err(|error| CliError::Runtime(error.to_string()))?;
        let approvals = Arc::new(ApprovalRegistry::new(
            database.clone(),
            Duration::from_secs(config.runtime.approval_ttl_seconds),
        ));
        let redactor = Arc::new(SecretRedactor::new(secrets));
        let secret_resolver = Arc::new(RuntimeSecretResolver {
            database: database.clone(),
            store: secret_store,
            redactor: Arc::clone(&redactor),
        });
        let builtin_executor: Arc<dyn ExecutorPort> = Arc::new(
            BuiltinExecutor::new(filesystem.clone(), process).with_secret_resolver(secret_resolver),
        );
        let extension_executor: Arc<dyn ExecutorPort> = Arc::new(
            ExtensionExecutor::new(
                database.clone(),
                data_root.clone(),
                sandbox,
                resource_limits,
                config.process.max_output_bytes,
            )
            .map_err(CliError::Runtime)?,
        );
        let executor = RedactingExecutor {
            inner: Arc::new(RoutingExecutor {
                builtin: builtin_executor,
                extension: extension_executor,
            }),
            redactor: Arc::clone(&redactor),
            approvals: Arc::clone(&approvals),
        };
        let builtin_normalizer: Arc<dyn ActionNormalizer> =
            Arc::new(BuiltinActionNormalizer::with_filesystem(
                lumen_core::identity::ComponentId::new("builtin.tools")
                    .expect("static component ID"),
                filesystem,
            ));
        let normalizer = SecretRejectingNormalizer {
            inner: Arc::new(RoutingNormalizer {
                builtin: builtin_normalizer,
                extension: Arc::new(ExtensionActionNormalizer),
            }),
            redactor: Arc::clone(&redactor),
        };
        let mut grants = vec![
            Capability::new(
                CapabilityName::FsRead,
                ResourceScope::workspace(config.workspace_id()),
            ),
            Capability::new(
                CapabilityName::FsWrite,
                ResourceScope::workspace(config.workspace_id()),
            ),
        ];
        for program in allowed_programs {
            let canonical = std::fs::canonicalize(program)?;
            grants.push(Capability::new(
                CapabilityName::ProcessSpawn,
                ResourceScope::exact("executable", canonical.to_string_lossy())
                    .map_err(|error| CliError::Runtime(error.to_string()))?,
            ));
        }
        for reference in secret_references {
            grants.push(Capability::new(
                CapabilityName::SecretUse,
                ResourceScope::exact("secret_reference", reference.id().to_string())
                    .map_err(|error| CliError::Runtime(error.to_string()))?,
            ));
        }
        grants.extend(network_egress_capabilities);
        grants.extend(channel_send_capabilities);
        let ambient_capabilities = CapabilitySet::new(grants);
        Ok(Self {
            model: Arc::new(model),
            enforce_model_egress_policy: config.model.allow_remote,
            normalizer: Arc::new(normalizer),
            executor: Arc::new(executor),
            approvals,
            audit: Arc::new(DatabaseAudit(database.clone())),
            actions: Arc::new(DatabaseActions(database.clone())),
            database,
            data_root: Arc::from(data_root),
            events,
            policy: Policy::default(),
            policy_version: PolicyVersion::new("local-policy-v1").expect("static policy version"),
            capabilities: EffectiveCapabilities::new([ambient_capabilities.clone()]),
            ambient_capabilities,
            budget: RunBudget::new(config.runtime.max_model_turns, config.runtime.max_actions)
                .with_quotas(
                    Duration::from_secs(config.runtime.max_wall_time_seconds),
                    config.runtime.max_captured_result_bytes,
                ),
            runs: Arc::new(Mutex::new(BTreeMap::new())),
            cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            run_workspaces: Arc::new(Mutex::new(BTreeMap::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            redactor,
        })
    }

    async fn spawn_advance(&self, run_id: RunId) {
        let handle = tokio::spawn(self.clone().advance(run_id));
        self.tasks.lock().await.push(handle);
    }

    pub(crate) async fn shutdown(&self) {
        let mut tasks = std::mem::take(&mut *self.tasks.lock().await);
        let completed = tokio::time::timeout(Duration::from_secs(5), async {
            for task in &mut tasks {
                let _ = task.await;
            }
        })
        .await
        .is_ok();
        if !completed {
            for task in tasks {
                task.abort();
                let _ = task.await;
            }
        }
    }

    async fn advance(self, run_id: RunId) {
        let Some(mut stored) = self.runs.lock().await.remove(&run_id) else {
            return;
        };
        let _ = self
            .database
            .update_run_state(run_id, "running", None)
            .await;
        let cancellation = self
            .cancellations
            .lock()
            .await
            .get(&run_id)
            .cloned()
            .unwrap_or_else(CancellationToken::new);
        let selected_model = stored
            .model_override
            .clone()
            .unwrap_or_else(|| Arc::clone(&self.model));
        let checked_model = if stored.model_override.is_none() && self.enforce_model_egress_policy {
            Some(EgressCheckedModel {
                inner: Arc::clone(&selected_model),
                database: self.database.clone(),
                audit: DatabaseAudit(self.database.clone()),
                workspace_id: stored.workspace_id,
            })
        } else {
            None
        };
        let model_inner = checked_model
            .as_ref()
            .map_or(selected_model.as_ref(), |model| model as &dyn ModelPort);
        let model = CancellableModel {
            inner: model_inner,
            cancellation: cancellation.clone(),
        };
        let orchestrator = RunOrchestrator::new(
            &model,
            self.normalizer.as_ref(),
            self.executor.as_ref(),
            self.approvals.as_ref(),
            self.audit.as_ref(),
            self.actions.as_ref(),
            self.policy.clone(),
            self.policy_version.clone(),
        )
        .with_cancellation(cancellation.clone());
        match orchestrator
            .run_until_blocked(
                &mut stored.state,
                stored
                    .capabilities_override
                    .as_ref()
                    .unwrap_or(&self.capabilities),
                now(),
            )
            .await
        {
            Ok(RunOutcome::AwaitingApproval { approval_id }) => {
                let _ = self
                    .database
                    .update_run_state(run_id, "awaiting_approval", None)
                    .await;
                let _ = self.events.publish(
                    stored.workspace_id,
                    run_id,
                    "approval.required",
                    CanonicalValue::object([(
                        "approval_id",
                        CanonicalValue::from(approval_id.to_string()),
                    )]),
                );
                self.runs.lock().await.insert(run_id, stored);
            }
            Ok(outcome) => {
                let (state, kind, mut payload) = terminal_event(&outcome);
                self.redactor.redact_value(&mut payload);
                let timestamp = now();
                let _ = self
                    .database
                    .update_run_state(run_id, state, Some(timestamp))
                    .await;
                let _ = self
                    .events
                    .publish(stored.workspace_id, run_id, kind, payload);
                self.finish_run(run_id).await;
            }
            Err(error) => {
                let timestamp = now();
                if cancellation.is_cancelled() {
                    let _ = self
                        .audit
                        .record(AuditEvent::new(
                            AuditEventId::new(),
                            timestamp,
                            AuditEventKind::RunCancelled,
                            AuditOutcome::Failure,
                            Some(stored.workspace_id),
                            CanonicalValue::object([(
                                "run_id",
                                CanonicalValue::from(run_id.to_string()),
                            )]),
                        ))
                        .await;
                }
                let _ = self
                    .database
                    .update_run_state(
                        run_id,
                        if cancellation.is_cancelled() {
                            "cancelled"
                        } else {
                            "failed"
                        },
                        Some(timestamp),
                    )
                    .await;
                let mut message = error.to_string();
                self.redactor.redact_string(&mut message);
                let _ = self.events.publish(
                    stored.workspace_id,
                    run_id,
                    if cancellation.is_cancelled() {
                        "run.cancelled"
                    } else {
                        "run.failed"
                    },
                    CanonicalValue::from(message),
                );
                self.finish_run(run_id).await;
            }
        }
    }

    async fn finish_run(&self, run_id: RunId) {
        self.cancellations.lock().await.remove(&run_id);
        self.run_workspaces.lock().await.remove(&run_id);
    }

    pub(crate) async fn request_extension_action(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        actor: lumen_core::identity::PrincipalId,
        proposal: ActionProposal,
        capabilities: CapabilitySet,
    ) -> Result<RunId, ServiceError> {
        let run_id = RunId::new();
        self.database
            .create_run(run_id, workspace_id, &actor, now())
            .await
            .map_err(repository_service_error)?;
        let model: Arc<dyn ModelPort> = Arc::new(ActionRequestModel { proposal });
        self.runs.lock().await.insert(
            run_id,
            StoredRun {
                workspace_id,
                state: RunState::new(
                    RunContext::new(run_id, workspace_id, actor),
                    "authenticated extension administration request",
                    self.budget,
                ),
                model_override: Some(model),
                capabilities_override: Some(EffectiveCapabilities::new([capabilities])),
            },
        );
        self.cancellations
            .lock()
            .await
            .insert(run_id, CancellationToken::new());
        self.run_workspaces
            .lock()
            .await
            .insert(run_id, workspace_id);
        self.events
            .publish(
                workspace_id,
                run_id,
                "run.created",
                CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
            )
            .map_err(|error| ServiceError::Internal(error.to_string()))?;
        self.spawn_advance(run_id).await;
        Ok(run_id)
    }

    pub(crate) async fn request_plugin_invocation(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        actor: lumen_core::identity::PrincipalId,
        plugin_id: &str,
        plugin_version: &str,
        component_id: &str,
        input: CanonicalValue,
    ) -> Result<RunId, ServiceError> {
        self.request_plugin_invocation_request(PluginInvocationCommand {
            workspace_id,
            actor,
            plugin_id: plugin_id.to_owned(),
            plugin_version: plugin_version.to_owned(),
            component_id: component_id.to_owned(),
            request_id: uuid::Uuid::new_v4(),
            input,
        })
        .await
    }

    async fn request_plugin_invocation_request(
        &self,
        command: PluginInvocationCommand,
    ) -> Result<RunId, ServiceError> {
        let plugin = PluginId::parse(&command.plugin_id)
            .map_err(|error| ServiceError::Conflict(error.to_string()))?;
        let version = PluginVersion::parse(&command.plugin_version)
            .map_err(|error| ServiceError::Conflict(error.to_string()))?;
        let component = PluginComponentId::parse(&command.component_id)
            .map_err(|error| ServiceError::Conflict(error.to_string()))?;
        let arguments = prepare_invocation(
            &self.database,
            self.data_root.as_ref(),
            InvocationTarget {
                workspace: command.workspace_id,
                actor: command.actor.clone(),
                plugin,
                version,
                component,
                request_id: command.request_id,
            },
            command.input,
        )
        .await
        .map_err(ServiceError::Conflict)?;
        let capability = invocation_capability(
            &command.plugin_id,
            &command.plugin_version,
            &command.component_id,
        )
        .map_err(|error| ServiceError::Conflict(error.to_string()))?;
        let mut run_capabilities = self
            .ambient_capabilities
            .capabilities()
            .cloned()
            .collect::<Vec<_>>();
        run_capabilities.push(capability);
        self.request_extension_action(
            command.workspace_id,
            command.actor,
            action_proposal("plugin.invoke", &arguments)
                .map_err(|error| ServiceError::Conflict(error.to_string()))?,
            CapabilitySet::new(run_capabilities),
        )
        .await
    }
}

async fn bootstrap_configured_remote_model_provider(
    config: &Config,
    database: &Database,
) -> Result<(), CliError> {
    let Some(provider) = &config.model.remote_provider else {
        return Ok(());
    };
    let provider_id =
        ProviderId::parse(&provider.id).map_err(|error| CliError::Runtime(error.to_string()))?;
    let provider_exists = database
        .latest_model_provider_revision(provider_id.clone())
        .await?
        .is_some();
    let workspace_policy_exists = database
        .latest_workspace_model_egress_revision(config.workspace_id(), provider_id.clone())
        .await?
        .is_some();
    let allowed_data_classes = provider
        .allowed_data_classes
        .iter()
        .copied()
        .map(remote_data_class)
        .collect::<Vec<_>>();
    let created_at = now();
    if !provider_exists {
        let provider_revision = ModelProviderRevision::new(
            provider_id.clone(),
            1,
            ModelEndpointClass::Remote,
            DestinationScope::parse(&config.model.endpoint)
                .map_err(|error| CliError::Runtime(error.to_string()))?,
            config.model.model.clone(),
            true,
            0,
            None,
            allowed_data_classes.clone(),
            created_at,
        )
        .map_err(CliError::Repository)?;
        database
            .append_model_provider_revision(&provider_revision)
            .await?;
    }
    if !workspace_policy_exists {
        let workspace_revision = WorkspaceModelEgressRevision::new(
            config.workspace_id(),
            provider_id,
            1,
            allowed_data_classes,
            created_at,
        )
        .map_err(CliError::Repository)?;
        database
            .append_workspace_model_egress_revision(&workspace_revision)
            .await?;
    }
    Ok(())
}

const fn remote_data_class(value: RemoteDataClass) -> DataClass {
    match value {
        RemoteDataClass::Public => DataClass::Public,
        RemoteDataClass::Workspace => DataClass::Workspace,
        RemoteDataClass::Sensitive => DataClass::Sensitive,
        RemoteDataClass::Secret => DataClass::Secret,
    }
}

impl RuntimeService for LocalRuntimeService {
    fn create_run(&self, command: CreateRunCommand) -> ServiceFuture<'_, RunCreated> {
        let service = self.clone();
        Box::pin(async move {
            let run_id = RunId::new();
            service
                .database
                .create_run(run_id, command.workspace_id(), command.actor(), now())
                .await
                .map_err(repository_service_error)?;
            let state = RunState::new(
                RunContext::new(run_id, command.workspace_id(), command.actor().clone()),
                command.prompt(),
                service.budget,
            )
            .with_data_class(command.data_class());
            service.runs.lock().await.insert(
                run_id,
                StoredRun {
                    workspace_id: command.workspace_id(),
                    state,
                    model_override: None,
                    capabilities_override: None,
                },
            );
            service
                .cancellations
                .lock()
                .await
                .insert(run_id, CancellationToken::new());
            service
                .run_workspaces
                .lock()
                .await
                .insert(run_id, command.workspace_id());
            service
                .events
                .publish(
                    command.workspace_id(),
                    run_id,
                    "run.created",
                    CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
                )
                .map_err(|error| ServiceError::Internal(error.to_string()))?;
            service.spawn_advance(run_id).await;
            Ok(RunCreated::new(run_id))
        })
    }

    fn decide_approval(
        &self,
        command: ApprovalDecisionCommand,
    ) -> ServiceFuture<'_, ApprovalResult> {
        let service = self.clone();
        Box::pin(async move {
            let (run_id, result) = service.approvals.decide(&command, now()).await?;
            service
                .events
                .publish(
                    command.workspace_id(),
                    run_id,
                    match command.decision() {
                        ApprovalDecision::Grant => "approval.granted",
                        ApprovalDecision::Reject => "approval.rejected",
                    },
                    CanonicalValue::object([(
                        "approval_id",
                        CanonicalValue::from(command.approval_id().to_string()),
                    )]),
                )
                .map_err(|error| ServiceError::Internal(error.to_string()))?;
            service.spawn_advance(run_id).await;
            Ok(result)
        })
    }

    fn list_audit(&self, query: AuditQuery) -> ServiceFuture<'_, Vec<AuditEntry>> {
        Box::pin(async move {
            let records = self
                .database
                .list_audit_records(query.workspace_id(), query.after(), query.limit())
                .await
                .map_err(repository_service_error)?;
            records
                .into_iter()
                .map(|record| {
                    let event = record.event();
                    let workspace_id = event.workspace_id().ok_or_else(|| {
                        ServiceError::Internal("workspace audit query returned global event".into())
                    })?;
                    Ok(AuditEntry::new(
                        record.sequence(),
                        event.id(),
                        event.timestamp(),
                        event.kind(),
                        event.outcome(),
                        workspace_id,
                        event.payload().clone(),
                    ))
                })
                .collect()
        })
    }

    fn list_approvals(&self, query: ApprovalQuery) -> ServiceFuture<'_, Vec<ApprovalPreview>> {
        Box::pin(async move {
            let approvals = self
                .database
                .list_pending_approvals(query.workspace_id())
                .await
                .map_err(repository_service_error)?;
            let references = self
                .database
                .list_secret_references(query.workspace_id())
                .await
                .map_err(repository_service_error)?;
            approvals
                .into_iter()
                .map(|approval| {
                    let arguments =
                        serde_json::to_value(approval.arguments()).map_err(|error| {
                            ServiceError::Internal(format!(
                                "approval arguments are invalid: {error}"
                            ))
                        })?;
                    let used_references = arguments
                        .get("secret_environment")
                        .and_then(serde_json::Value::as_object)
                        .into_iter()
                        .flat_map(|bindings| bindings.values())
                        .filter_map(serde_json::Value::as_str)
                        .filter_map(|value| SecretRefId::parse(value).ok())
                        .collect::<std::collections::BTreeSet<_>>();
                    let metadata = references
                        .iter()
                        .filter(|reference| used_references.contains(&reference.id()))
                        .map(|reference| {
                            ApprovalSecretReference::new(
                                reference.id(),
                                reference.label(),
                                reference.environment_name(),
                            )
                        });
                    Ok(ApprovalPreview::new(
                        approval.approval_id(),
                        approval.run_id(),
                        approval.kind(),
                        approval.arguments().clone(),
                        approval.capabilities().to_vec(),
                        approval.fingerprint(),
                        approval.created_at(),
                        approval.expires_at(),
                    )
                    .with_secret_references(metadata))
                })
                .collect()
        })
    }

    fn cancel_run(&self, command: CancelRunCommand) -> ServiceFuture<'_, RunCancellation> {
        let service = self.clone();
        Box::pin(async move {
            let workspace = service
                .run_workspaces
                .lock()
                .await
                .get(&command.run_id())
                .copied()
                .ok_or(ServiceError::NotFound)?;
            if workspace != command.workspace_id() {
                return Err(ServiceError::NotFound);
            }
            let cancellation = service
                .cancellations
                .lock()
                .await
                .get(&command.run_id())
                .cloned()
                .ok_or(ServiceError::NotFound)?;
            cancellation.cancel();
            let should_advance = {
                let mut runs = service.runs.lock().await;
                runs.get_mut(&command.run_id()).is_some_and(|stored| {
                    stored.state.cancel();
                    true
                })
            };
            if should_advance {
                service.spawn_advance(command.run_id()).await;
            }
            Ok(RunCancellation::new(command.run_id()))
        })
    }

    fn list_staged_plugins(
        &self,
        query: PluginReviewQuery,
    ) -> ServiceFuture<'_, Vec<StagedPluginReview>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT id, manifest_json, runtime_type, file_hashes_json, package_digest,
                        manifest_digest, artifact_digest, requested_by_provider,
                        requested_by_subject, created_at
                 FROM plugin_staged_packages
                 WHERE state = 'staged' AND created_at >= ?
                 ORDER BY created_at, id
                 LIMIT ?",
            )
            .bind(i64::try_from(query.after()).map_err(|_| {
                ServiceError::Conflict("plugin review cursor is out of range".into())
            })?)
            .bind(i64::from(query.limit()))
            .fetch_all(self.database.pool())
            .await
            .map_err(sql_service_error)?;

            rows.into_iter()
                .map(|row| {
                    let manifest: lumen_core::extension::PluginManifest = serde_json::from_str(
                        &row.try_get::<String, _>("manifest_json")
                            .map_err(sql_service_error)?,
                    )
                    .map_err(|error| ServiceError::Internal(error.to_string()))?;
                    let requested_by = lumen_core::identity::PrincipalId::new(
                        row.try_get::<String, _>("requested_by_provider")
                            .map_err(sql_service_error)?,
                        row.try_get::<String, _>("requested_by_subject")
                            .map_err(sql_service_error)?,
                    )
                    .map_err(|error| ServiceError::Internal(error.to_string()))?;
                    let file_hashes: BTreeMap<String, String> = serde_json::from_str(
                        &row.try_get::<String, _>("file_hashes_json")
                            .map_err(sql_service_error)?,
                    )
                    .map_err(|error| ServiceError::Internal(error.to_string()))?;
                    let created_at: i64 = row.try_get("created_at").map_err(sql_service_error)?;
                    let created_at = u64::try_from(created_at)
                        .map_err(|_| ServiceError::Internal("invalid plugin timestamp".into()))?;
                    Ok(StagedPluginReview::new(
                        row.try_get::<String, _>("id").map_err(sql_service_error)?,
                        manifest.id().as_str(),
                        manifest.version().as_str(),
                        row.try_get::<String, _>("runtime_type")
                            .map_err(sql_service_error)?,
                        row.try_get::<String, _>("package_digest")
                            .map_err(sql_service_error)?,
                        row.try_get::<String, _>("manifest_digest")
                            .map_err(sql_service_error)?,
                        row.try_get::<String, _>("artifact_digest")
                            .map_err(sql_service_error)?,
                        file_hashes,
                        PrincipalSummary::new(&requested_by),
                        TimestampMillis::new(created_at),
                    ))
                })
                .collect()
        })
    }

    fn plugin_details(&self, query: PluginDetailsQuery) -> ServiceFuture<'_, PluginVersionDetails> {
        Box::pin(async move {
            let plugin_id = PluginId::parse(query.plugin_id())
                .map_err(|error| ServiceError::Conflict(error.to_string()))?;
            let version = PluginVersion::parse(query.plugin_version())
                .map_err(|error| ServiceError::Conflict(error.to_string()))?;
            let installed = self
                .database
                .installed_plugin_version(plugin_id.clone(), version.clone())
                .await
                .map_err(repository_service_error)?
                .ok_or(ServiceError::NotFound)?;
            let state = self
                .database
                .plugin_workspace_state(query.workspace_id(), plugin_id.clone(), version.clone())
                .await
                .map_err(repository_service_error)?;
            let state = if installed.is_artifact_quarantined() {
                "artifact_quarantine".to_owned()
            } else {
                match state {
                    Some(lumen_db::PluginWorkspaceState::Enabled) => "enabled".to_owned(),
                    Some(lumen_db::PluginWorkspaceState::Disabled) => "disabled".to_owned(),
                    Some(lumen_db::PluginWorkspaceState::HealthQuarantine) => {
                        "health_quarantine".to_owned()
                    }
                    None => "not_enabled".to_owned(),
                }
            };

            let mut components = Vec::new();
            for component in installed.manifest().components() {
                let requested = component
                    .capabilities()
                    .iter()
                    .map(|request| {
                        CanonicalValue::object([
                            ("name", CanonicalValue::from(request.name().as_str())),
                            ("scope", CanonicalValue::from("workspace")),
                        ])
                    })
                    .collect::<Vec<_>>();
                let component_id = component.id().clone();
                let grants = self
                    .database
                    .latest_plugin_grants(
                        plugin_id.clone(),
                        version.clone(),
                        component_id,
                        PluginGrantScope::Workspace(query.workspace_id()),
                    )
                    .await
                    .map_err(repository_service_error)?;
                let (grant_revision, grant_set_digest, effective_grants) =
                    if let Some(grants) = grants {
                        let effective_grants = grants
                            .capabilities()
                            .map(capability_review)
                            .collect::<Result<Vec<_>, _>>()?;
                        (
                            grants.revision(),
                            grants.digest().to_string(),
                            effective_grants,
                        )
                    } else {
                        (
                            0,
                            lumen_core::extension::canonical_grant_set_digest(&[]).to_string(),
                            Vec::new(),
                        )
                    };
                components.push(PluginComponentReview::new(
                    component.id().as_str(),
                    "tool",
                    requested,
                    effective_grants,
                    grant_revision,
                    grant_set_digest,
                ));
            }

            let settings = plugin_settings_review(
                &self.database,
                &self.redactor,
                &plugin_id,
                &version,
                query.workspace_id(),
                query.actor(),
            )
            .await?;
            let failures =
                plugin_failures_review(&self.database, query.workspace_id(), &plugin_id, &version)
                    .await?;

            Ok(PluginVersionDetails::new(
                installed.manifest().id().as_str(),
                installed.manifest().version().as_str(),
                state,
                installed.package_digest().to_string(),
                installed.manifest_digest().to_string(),
                installed.artifact_digest().to_string(),
                components,
                settings,
                failures,
            ))
        })
    }

    fn request_plugin_action(
        &self,
        command: PluginActionCommand,
    ) -> ServiceFuture<'_, PluginActionRequested> {
        let service = self.clone();
        Box::pin(async move {
            let proposal = if let Some(arguments) = command.arguments().cloned() {
                ActionProposal::new(command.kind(), arguments)
            } else {
                match command.kind() {
                    "plugin.enable" | "plugin.disable" => action_proposal(
                        command.kind(),
                        &VersionArguments {
                            plugin_id: command.plugin_id().to_owned(),
                            plugin_version: command.plugin_version().to_owned(),
                        },
                    )
                    .map_err(|error| ServiceError::Conflict(error.to_string()))?,
                    _ => {
                        return Err(ServiceError::Conflict(
                            "plugin action requires canonical arguments".into(),
                        ));
                    }
                }
            };
            let capabilities = admin_capabilities(command.plugin_id(), command.plugin_version())
                .map_err(|error| ServiceError::Conflict(error.to_string()))?;
            let run_id = service
                .request_extension_action(
                    command.workspace_id(),
                    command.actor().clone(),
                    proposal,
                    CapabilitySet::new(capabilities),
                )
                .await?;
            Ok(PluginActionRequested::new(run_id))
        })
    }
}

fn capability_review(capability: &Capability) -> Result<CanonicalValue, ServiceError> {
    let scope: CanonicalValue = serde_json::from_value(
        serde_json::to_value(capability.scope())
            .map_err(|error| ServiceError::Internal(error.to_string()))?,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    Ok(CanonicalValue::object([
        ("name", CanonicalValue::from(capability.name().as_str())),
        ("scope", scope),
    ]))
}

async fn plugin_settings_review(
    database: &Database,
    redactor: &SecretRedactor,
    plugin_id: &PluginId,
    version: &PluginVersion,
    workspace_id: lumen_core::identity::WorkspaceId,
    actor: &lumen_core::identity::PrincipalId,
) -> Result<Vec<PluginSettingReview>, ServiceError> {
    let scopes = [
        (
            "global".to_owned(),
            "*".to_owned(),
            PluginSettingScope::Global,
        ),
        (
            "workspace".to_owned(),
            workspace_id.to_string(),
            PluginSettingScope::Workspace(workspace_id),
        ),
        (
            "user".to_owned(),
            format!("{}:{}", actor.provider(), actor.subject()),
            PluginSettingScope::User(actor.clone()),
        ),
    ];
    let mut settings = Vec::new();
    for (scope_type, scope_id, scope) in scopes {
        let Some(revision) = database
            .latest_plugin_setting(plugin_id.clone(), version.clone(), scope)
            .await
            .map_err(repository_service_error)?
        else {
            continue;
        };
        let mut config = revision.config().clone();
        redact_json(redactor, &mut config);
        settings.push(PluginSettingReview::new(
            scope_type,
            scope_id,
            revision.config_version(),
            config,
            revision.schema_digest().to_string(),
            revision.settings_digest().to_string(),
        ));
    }
    Ok(settings)
}

fn redact_json(redactor: &SecretRedactor, value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => redactor.redact_string(value),
        serde_json::Value::Array(values) => {
            for value in values {
                redact_json(redactor, value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                redact_json(redactor, value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

async fn plugin_failures_review(
    database: &Database,
    workspace_id: lumen_core::identity::WorkspaceId,
    plugin_id: &PluginId,
    version: &PluginVersion,
) -> Result<Vec<PluginFailureReview>, ServiceError> {
    let rows = sqlx::query(
        "SELECT failure_class, COUNT(*) AS count, MAX(occurred_at) AS last_seen_at
         FROM plugin_failures
         WHERE workspace_id = ? AND plugin_id = ? AND plugin_version = ?
         GROUP BY failure_class
         ORDER BY last_seen_at DESC, failure_class",
    )
    .bind(workspace_id.to_string())
    .bind(plugin_id.as_str())
    .bind(version.as_str())
    .fetch_all(database.pool())
    .await
    .map_err(sql_service_error)?;
    rows.into_iter()
        .map(|row| {
            let count: i64 = row.try_get("count").map_err(sql_service_error)?;
            let last_seen_at: i64 = row.try_get("last_seen_at").map_err(sql_service_error)?;
            let last_seen_at = u64::try_from(last_seen_at)
                .map_err(|_| ServiceError::Internal("invalid plugin failure timestamp".into()))?;
            Ok(PluginFailureReview::new(
                row.try_get::<String, _>("failure_class")
                    .map_err(sql_service_error)?,
                u64::try_from(count)
                    .map_err(|_| ServiceError::Internal("invalid plugin failure count".into()))?,
                "[redacted]",
                "0".repeat(64),
                TimestampMillis::new(last_seen_at),
            ))
        })
        .collect()
}

fn sql_service_error(error: sqlx::Error) -> ServiceError {
    ServiceError::Internal(error.to_string())
}

struct CancellableModel<'a> {
    inner: &'a dyn ModelPort,
    cancellation: CancellationToken,
}

struct RedactingExecutor {
    inner: Arc<dyn ExecutorPort>,
    redactor: Arc<SecretRedactor>,
    approvals: Arc<ApprovalRegistry>,
}

struct SecretRejectingNormalizer {
    inner: Arc<dyn ActionNormalizer>,
    redactor: Arc<SecretRedactor>,
}

struct RuntimeSecretResolver {
    database: Database,
    store: Arc<dyn SecretStore>,
    redactor: Arc<SecretRedactor>,
}

impl ProcessSecretResolver for RuntimeSecretResolver {
    fn resolve<'a>(
        &'a self,
        workspace_id: lumen_core::identity::WorkspaceId,
        program: &'a Path,
        bindings: &'a BTreeMap<String, SecretRefId>,
    ) -> ProcessSecretFuture<'a> {
        Box::pin(async move {
            let program = program.to_string_lossy();
            let mut resolved = BTreeMap::new();
            for (environment, reference_id) in bindings {
                let reference = self
                    .database
                    .get_secret_reference(workspace_id, *reference_id)
                    .await
                    .map_err(|error| ProcessSecretError::new(error.to_string()))?
                    .ok_or_else(|| ProcessSecretError::new("secret reference was not found"))?;
                if !reference.allows(workspace_id, &program, environment) {
                    return Err(ProcessSecretError::new(
                        "secret reference does not allow this process environment",
                    ));
                }
                let value = self
                    .store
                    .resolve(reference.keychain_account())
                    .await
                    .map_err(|error| ProcessSecretError::new(error.to_string()))?;
                let value = String::from_utf8(value)
                    .map_err(|_| ProcessSecretError::new("secret value is not valid UTF-8"))?;
                self.redactor.register(&value);
                resolved.insert(environment.clone(), value);
            }
            Ok(resolved)
        })
    }
}

impl ActionNormalizer for SecretRejectingNormalizer {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError> {
        let action = self.inner.normalize(context, proposal)?;
        let encoded = serde_json::to_string(&action)
            .map_err(|error| NormalizationError::new(error.to_string()))?;
        if self.redactor.contains_secret(&encoded) {
            return Err(NormalizationError::new(
                "action contains known secret material",
            ));
        }
        Ok(action)
    }
}

impl ExecutorPort for RedactingExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move {
            let attempt_id = self.approvals.reserve(action, now()).await?;
            let outcome = match self.inner.execute(action, cancellation).await {
                Ok(outcome) => outcome,
                Err(error) => {
                    let _ = self
                        .approvals
                        .database
                        .complete_execution(attempt_id, action.action().id(), "unknown", now())
                        .await;
                    return Ok(ExecutionOutcome::Unknown(error.to_string()));
                }
            };
            let outcome = match outcome {
                ExecutionOutcome::Succeeded(mut value) => {
                    self.redactor.redact_value(&mut value);
                    ExecutionOutcome::Succeeded(value)
                }
                ExecutionOutcome::Proposed(proposal) => ExecutionOutcome::Proposed(proposal),
                ExecutionOutcome::Failed(mut message) => {
                    self.redactor.redact_string(&mut message);
                    ExecutionOutcome::Failed(message)
                }
                ExecutionOutcome::Cancelled => ExecutionOutcome::Cancelled,
                ExecutionOutcome::TimedOut => ExecutionOutcome::TimedOut,
                ExecutionOutcome::Unknown(mut message) => {
                    self.redactor.redact_string(&mut message);
                    ExecutionOutcome::Unknown(message)
                }
            };
            let state = match &outcome {
                ExecutionOutcome::Succeeded(_) => "succeeded",
                ExecutionOutcome::Proposed(_) => "succeeded",
                ExecutionOutcome::Failed(_) => "failed",
                ExecutionOutcome::Cancelled => "cancelled",
                ExecutionOutcome::TimedOut => "timed_out",
                ExecutionOutcome::Unknown(_) => "unknown",
            };
            if let Err(error) = self
                .approvals
                .database
                .complete_execution(attempt_id, action.action().id(), state, now())
                .await
            {
                return Ok(ExecutionOutcome::Unknown(format!(
                    "execution outcome could not be persisted: {error}"
                )));
            }
            Ok(outcome)
        })
    }
}

struct SecretRedactor {
    secrets: RwLock<Vec<String>>,
}

impl SecretRedactor {
    fn new(secrets: Vec<String>) -> Self {
        let redactor = Self {
            secrets: RwLock::new(Vec::new()),
        };
        for secret in secrets {
            redactor.register(&secret);
        }
        redactor
    }

    fn register(&self, secret: &str) {
        if secret.is_empty() {
            return;
        }
        let mut secrets = self.secrets.write().expect("secret redactor lock");
        secrets.push(secret.to_owned());
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
    }

    fn redact_value(&self, value: &mut CanonicalValue) {
        match value {
            CanonicalValue::String(value) => self.redact_string(value),
            CanonicalValue::Array(values) => {
                for value in values {
                    self.redact_value(value);
                }
            }
            CanonicalValue::Object(values) => {
                for value in values.values_mut() {
                    self.redact_value(value);
                }
            }
            CanonicalValue::Null | CanonicalValue::Bool(_) | CanonicalValue::Integer(_) => {}
        }
    }

    fn redact_string(&self, value: &mut String) {
        for secret in self.secrets.read().expect("secret redactor lock").iter() {
            if value.contains(secret) {
                *value = value.replace(secret, "[REDACTED]");
            }
        }
    }

    fn contains_secret(&self, value: &str) -> bool {
        self.secrets
            .read()
            .expect("secret redactor lock")
            .iter()
            .any(|secret| value.contains(secret))
    }
}

impl ModelPort for CancellableModel<'_> {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        Box::pin(async move {
            tokio::select! {
                biased;
                () = self.cancellation.cancelled() => Err(ModelError::new("model request cancelled")),
                result = self.inner.generate(input) => result,
            }
        })
    }
}

struct StoredRun {
    workspace_id: lumen_core::identity::WorkspaceId,
    state: RunState,
    model_override: Option<Arc<dyn ModelPort>>,
    capabilities_override: Option<EffectiveCapabilities>,
}

struct EgressCheckedModel {
    inner: Arc<dyn ModelPort>,
    database: Database,
    audit: DatabaseAudit,
    workspace_id: lumen_core::identity::WorkspaceId,
}

impl ModelPort for EgressCheckedModel {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        Box::pin(async move {
            let data_class = input.data_class();
            let routes = self
                .database
                .model_provider_routes(self.workspace_id)
                .await
                .map_err(|error| ModelError::new(format!("model egress policy failed: {error}")))?;
            let decision = match select_model_provider(data_class, routes) {
                Ok(decision) => decision,
                Err(error) => {
                    self.audit_model_egress_denied(data_class, error.to_string())
                        .await?;
                    return Err(ModelError::new(error.to_string()));
                }
            };
            self.audit_model_egress_success(data_class, &decision)
                .await?;
            self.inner.generate(input).await
        })
    }
}

impl EgressCheckedModel {
    async fn audit_model_egress_success(
        &self,
        data_class: DataClass,
        decision: &lumen_core::egress::RoutingDecision,
    ) -> Result<(), ModelError> {
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                now(),
                AuditEventKind::ModelEgress,
                AuditOutcome::Success,
                Some(self.workspace_id),
                CanonicalValue::object([
                    ("data_class", CanonicalValue::from(data_class.as_str())),
                    (
                        "egress_occurred",
                        CanonicalValue::from(decision.egress_occurred()),
                    ),
                    (
                        "endpoint_class",
                        CanonicalValue::from(endpoint_class_name(decision.endpoint_class())),
                    ),
                    (
                        "provider_id",
                        CanonicalValue::from(decision.provider().as_str().to_owned()),
                    ),
                ]),
            ))
            .await
            .map_err(|error| ModelError::new(format!("model egress audit failed: {error}")))
    }

    async fn audit_model_egress_denied(
        &self,
        data_class: DataClass,
        failure: String,
    ) -> Result<(), ModelError> {
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                now(),
                AuditEventKind::ModelEgress,
                AuditOutcome::Denied,
                Some(self.workspace_id),
                CanonicalValue::object([
                    ("data_class", CanonicalValue::from(data_class.as_str())),
                    ("egress_occurred", CanonicalValue::from(false)),
                    ("failure", CanonicalValue::from(failure)),
                ]),
            ))
            .await
            .map_err(|error| ModelError::new(format!("model egress audit failed: {error}")))
    }
}

const fn endpoint_class_name(endpoint_class: lumen_core::egress::EndpointClass) -> &'static str {
    match endpoint_class {
        lumen_core::egress::EndpointClass::Local => "local",
        lumen_core::egress::EndpointClass::Remote => "remote",
    }
}

struct RoutingNormalizer {
    builtin: Arc<dyn ActionNormalizer>,
    extension: Arc<dyn ActionNormalizer>,
}

impl ActionNormalizer for RoutingNormalizer {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError> {
        if is_extension_action(proposal.kind()) {
            self.extension.normalize(context, proposal)
        } else {
            self.builtin.normalize(context, proposal)
        }
    }
}

struct RoutingExecutor {
    builtin: Arc<dyn ExecutorPort>,
    extension: Arc<dyn ExecutorPort>,
}

impl ExecutorPort for RoutingExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        if is_extension_action(action.action().kind().as_str()) {
            self.extension.execute(action, cancellation)
        } else {
            self.builtin.execute(action, cancellation)
        }
    }
}

struct ActionRequestModel {
    proposal: ActionProposal,
}

impl ModelPort for ActionRequestModel {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        let has_tool_result = input
            .messages()
            .iter()
            .any(|message| message.role() == lumen_core::model::ModelRole::Tool);
        let output = if has_tool_result {
            lumen_core::model::ModelOutput::FinalText("extension action completed".into())
        } else {
            lumen_core::model::ModelOutput::Action(self.proposal.clone())
        };
        Box::pin(async move { Ok(output) })
    }
}

fn terminal_event(outcome: &RunOutcome) -> (&'static str, &'static str, CanonicalValue) {
    match outcome {
        RunOutcome::Completed { text } => (
            "completed",
            "run.completed",
            CanonicalValue::object([("text", CanonicalValue::from(text.clone()))]),
        ),
        RunOutcome::Cancelled => (
            "cancelled",
            "run.cancelled",
            CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        ),
        RunOutcome::ExecutionTimedOut => (
            "failed",
            "run.timed_out",
            CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        ),
        other => (
            "failed",
            "run.failed",
            CanonicalValue::from(format!("{other:?}")),
        ),
    }
}

struct ApprovalRecord {
    workspace_id: lumen_core::identity::WorkspaceId,
    run_id: RunId,
    action: lumen_core::action::ActionEnvelope,
    request: ApprovalRequest,
    attempt_id: Option<ExecutionAttemptId>,
}

struct ApprovalRegistry {
    database: Database,
    ttl: Duration,
    records: Mutex<BTreeMap<ApprovalId, ApprovalRecord>>,
}

impl ApprovalRegistry {
    fn new(database: Database, ttl: Duration) -> Self {
        Self {
            database,
            ttl,
            records: Mutex::new(BTreeMap::new()),
        }
    }

    async fn decide(
        &self,
        command: &ApprovalDecisionCommand,
        now: TimestampMillis,
    ) -> Result<(RunId, ApprovalResult), ServiceError> {
        let mut records = self.records.lock().await;
        let record = records
            .get_mut(&command.approval_id())
            .ok_or(ServiceError::NotFound)?;
        if record.workspace_id != command.workspace_id() {
            return Err(ServiceError::NotFound);
        }
        let mut request = record.request.clone();
        match command.decision() {
            ApprovalDecision::Grant => request.grant(command.actor().clone(), now),
            ApprovalDecision::Reject => request.reject(command.actor().clone(), now),
        }
        .map_err(|error| ServiceError::Conflict(error.to_string()))?;
        self.database
            .update_approval_decision(command.workspace_id(), &request)
            .await
            .map_err(repository_service_error)?;
        record.request = request;
        Ok((
            record.run_id,
            ApprovalResult::new(command.approval_id(), command.decision()),
        ))
    }

    async fn reserve(
        &self,
        action: &AuthorizedAction,
        now: TimestampMillis,
    ) -> Result<ExecutionAttemptId, lumen_core::executor::ExecutorError> {
        let attempt_id = ExecutionAttemptId::new();
        match action.authorization() {
            DispatchAuthorization::PolicyAllowed => {
                self.database
                    .reserve_allowed_execution(attempt_id, action.action().id(), now)
                    .await
                    .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
            }
            DispatchAuthorization::Approved { approval_id } => {
                let mut records = self.records.lock().await;
                let record = records.get_mut(&approval_id).ok_or_else(|| {
                    lumen_core::executor::ExecutorError::new("approved action is not registered")
                })?;
                if record.action.fingerprint() != action.action().fingerprint()
                    || record.attempt_id.is_some()
                {
                    return Err(lumen_core::executor::ExecutorError::new(
                        "approved action cannot be reserved",
                    ));
                }
                self.database
                    .reserve_execution(DispatchReservation::new(
                        attempt_id,
                        action.action().id(),
                        approval_id,
                        action.action().fingerprint(),
                        record.request.policy_version().clone(),
                        now,
                    ))
                    .await
                    .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
                record.attempt_id = Some(attempt_id);
            }
        }
        Ok(attempt_id)
    }
}

impl ApprovalPort for ApprovalRegistry {
    fn resolve<'a>(
        &'a self,
        action: &'a lumen_core::action::ActionEnvelope,
        policy_version: &'a PolicyVersion,
        now: TimestampMillis,
    ) -> ApprovalFuture<'a> {
        Box::pin(async move {
            let mut records = self.records.lock().await;
            if let Some((approval_id, record)) = records
                .iter_mut()
                .find(|(_, record)| record.action.fingerprint() == action.fingerprint())
            {
                return match record.request.state() {
                    ApprovalState::Pending => Ok(ApprovalResolution::Pending(*approval_id)),
                    ApprovalState::Rejected => Ok(ApprovalResolution::Rejected(*approval_id)),
                    ApprovalState::Granted => {
                        Ok(ApprovalResolution::Granted(record.request.clone()))
                    }
                    state => Err(ApprovalPortError::new(format!(
                        "approval cannot be resolved from state {state:?}"
                    ))),
                };
            }

            let approval_id = ApprovalId::new();
            let ttl_millis = u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX);
            let expires_at = TimestampMillis::new(now.as_u64().saturating_add(ttl_millis));
            let request = ApprovalRequest::new(
                approval_id,
                action.fingerprint(),
                policy_version.clone(),
                now,
                expires_at,
            )
            .map_err(|error| ApprovalPortError::new(error.to_string()))?;
            self.database
                .insert_approval(&request)
                .await
                .map_err(|error| ApprovalPortError::new(error.to_string()))?;
            records.insert(
                approval_id,
                ApprovalRecord {
                    workspace_id: action.workspace_id(),
                    run_id: action.run_id(),
                    action: action.clone(),
                    request,
                    attempt_id: None,
                },
            );
            Ok(ApprovalResolution::Pending(approval_id))
        })
    }
}

struct DatabaseAudit(Database);

struct DatabaseActions(Database);

impl ActionPort for DatabaseActions {
    fn persist<'a>(&'a self, action: &'a ActionEnvelope, now: TimestampMillis) -> ActionFuture<'a> {
        Box::pin(async move {
            self.0
                .insert_action(action, now)
                .await
                .map_err(|error| ActionPortError::new(error.to_string()))
        })
    }
}

impl AuditPort for DatabaseAudit {
    fn record(&self, event: AuditEvent) -> AuditFuture<'_> {
        Box::pin(async move {
            self.0
                .append_audit_event(event)
                .await
                .map(|_| ())
                .map_err(|error| AuditPortError::new(error.to_string()))
        })
    }
}

fn repository_service_error(error: lumen_db::RepositoryError) -> ServiceError {
    ServiceError::Internal(error.to_string())
}

pub(crate) fn now() -> TimestampMillis {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    TimestampMillis::new(u64::try_from(millis).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod security_tests;

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use lumen_core::{audit::AuditEventKind, identity::PrincipalId};
    use lumen_db::Database;
    use lumen_integrations::{
        sandbox::{
            SandboxBackend, SandboxError, SandboxFuture, SandboxReport, SandboxRequest,
            SandboxStrength,
        },
        secrets::InMemorySecretStore,
    };
    use lumen_server::{CreateRunCommand, EventBroker, RuntimeService};
    use tempfile::tempdir;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{LocalRuntimeService, now};
    use crate::config::Config;

    struct EnforcedSandbox;

    impl SandboxBackend for EnforcedSandbox {
        fn report(&self) -> SandboxReport {
            SandboxReport::new("test", SandboxStrength::KernelEnforced, None)
        }

        fn execute(&self, _request: SandboxRequest) -> SandboxFuture<'_> {
            Box::pin(async {
                Err(SandboxError::Unavailable(
                    "process execution is not used by this test".into(),
                ))
            })
        }
    }

    #[tokio::test]
    async fn composed_runtime_persists_a_loopback_model_run() {
        let model = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "local result", "tool_calls": []}}]
            })))
            .mount(&model)
            .await;
        let directory = tempdir().expect("temporary runtime");
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace directory");
        let config = Config::parse(&format!(
            r#"
[database]
path = "ignored.sqlite3"

[model]
endpoint = "{}/v1/"
model = "local-model"
streaming = false

[workspace]
id = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name = "Default"
path = "{}"

[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
            model.uri(),
            workspace.display()
        ))
        .expect("runtime config");
        let database = Database::connect_in_memory().await.expect("database");
        database
            .bootstrap_workspace(
                config.workspace_id(),
                &config.workspace.name,
                &config.bootstrap_principal(),
                now(),
            )
            .await
            .expect("workspace bootstrap");
        let service = LocalRuntimeService::build_with_secret_store(
            &config,
            database.clone(),
            EventBroker::new(64),
            Arc::new(EnforcedSandbox),
            Vec::new(),
            Arc::new(InMemorySecretStore::new()),
        )
        .await
        .expect("runtime builds");

        service
            .create_run(CreateRunCommand::new(
                config.workspace_id(),
                PrincipalId::new("local", "operator").expect("principal"),
                "hello".into(),
            ))
            .await
            .expect("run created");

        let mut completed = false;
        for _ in 0..50 {
            let records = database
                .list_audit_records(config.workspace_id(), 0, 100)
                .await
                .expect("audit records");
            if records
                .iter()
                .any(|record| record.event().kind() == AuditEventKind::RunCompleted)
            {
                completed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        service.shutdown().await;

        assert!(completed, "composed runtime did not persist completion");
        database
            .verify_audit_chain()
            .await
            .expect("audit chain verifies");
    }
}
