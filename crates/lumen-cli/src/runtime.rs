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
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorFuture, ExecutorPort},
    model::{ActionProposal, ModelError, ModelFuture, ModelInput, ModelPort},
    policy::{Policy, PolicyVersion},
    run::{
        ActionFuture, ActionNormalizer, ActionPort, ActionPortError, ApprovalFuture, ApprovalPort,
        ApprovalPortError, ApprovalResolution, AuditFuture, AuditPort, AuditPortError,
        NormalizationError, RunBudget, RunContext, RunOrchestrator, RunOutcome, RunState,
    },
    secret::SecretRefId,
};
use lumen_db::{Database, DispatchReservation};
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
    EventBroker, RunCancellation, RunCreated, RuntimeService, ServiceError, ServiceFuture,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::{CliError, config::Config};

#[derive(Clone)]
pub(crate) struct LocalRuntimeService {
    model: Arc<dyn ModelPort>,
    normalizer: Arc<dyn ActionNormalizer>,
    executor: Arc<dyn ExecutorPort>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<DatabaseAudit>,
    actions: Arc<DatabaseActions>,
    database: Database,
    events: EventBroker,
    policy: Policy,
    policy_version: PolicyVersion,
    capabilities: EffectiveCapabilities,
    budget: RunBudget,
    runs: Arc<Mutex<BTreeMap<RunId, StoredRun>>>,
    cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    run_workspaces: Arc<Mutex<BTreeMap<RunId, lumen_core::identity::WorkspaceId>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    redactor: Arc<SecretRedactor>,
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
        let model_config = OpenAiCompatibleConfig::new(
            &config.model.endpoint,
            &config.model.model,
            EndpointPolicy::LoopbackOnly,
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
        let process = ProcessExecutor::new(
            &workspace,
            allowed_programs.clone(),
            config.process.allowed_environment.clone(),
            Duration::from_secs(config.process.timeout_seconds),
            config.process.max_output_bytes,
            ResourceLimits::new(
                config.process.max_cpu_seconds,
                config.process.max_address_space_bytes,
                config.process.max_file_size_bytes,
                config.process.max_open_files,
                config.process.max_processes,
            )
            .map_err(|error| CliError::Runtime(error.to_string()))?,
            sandbox,
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
        let executor = RedactingExecutor {
            inner: BuiltinExecutor::new(filesystem.clone(), process)
                .with_secret_resolver(secret_resolver),
            redactor: Arc::clone(&redactor),
            approvals: Arc::clone(&approvals),
        };
        let normalizer = SecretRejectingNormalizer {
            inner: BuiltinActionNormalizer::with_filesystem(
                lumen_core::identity::ComponentId::new("builtin.tools")
                    .expect("static component ID"),
                filesystem,
            ),
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
        Ok(Self {
            model: Arc::new(model),
            normalizer: Arc::new(normalizer),
            executor: Arc::new(executor),
            approvals,
            audit: Arc::new(DatabaseAudit(database.clone())),
            actions: Arc::new(DatabaseActions(database.clone())),
            database,
            events,
            policy: Policy::default(),
            policy_version: PolicyVersion::new("local-policy-v1").expect("static policy version"),
            capabilities: EffectiveCapabilities::new([CapabilitySet::new(grants)]),
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
        let model = CancellableModel {
            inner: self.model.as_ref(),
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
            .run_until_blocked(&mut stored.state, &self.capabilities, now())
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
            );
            service.runs.lock().await.insert(
                run_id,
                StoredRun {
                    workspace_id: command.workspace_id(),
                    state,
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
}

struct CancellableModel<'a> {
    inner: &'a dyn ModelPort,
    cancellation: CancellationToken,
}

struct RedactingExecutor {
    inner: BuiltinExecutor,
    redactor: Arc<SecretRedactor>,
    approvals: Arc<ApprovalRegistry>,
}

struct SecretRejectingNormalizer {
    inner: BuiltinActionNormalizer,
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
