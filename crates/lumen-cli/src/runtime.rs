use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use lumen_core::{
    action::{ActionEnvelope, CanonicalValue, RunId},
    approval::{
        ApprovalError, ApprovalId, ApprovalRequest, ApprovalState, DispatchAuthorization,
        ExecutionAttemptId, TimestampMillis, authorize_dispatch,
    },
    audit::{AuditEvent, AuditEventId, AuditEventKind, AuditOutcome},
    automation::{
        JobId, JobOrigin, JobRevision, OccurrenceKey, ScheduleSpec, SkillId, SkillVersion,
    },
    capability::{Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope},
    egress::{DataClass, DestinationScope, ProviderId, select_model_provider},
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorFuture, ExecutorPort},
    extension::{PluginComponentId, PluginId, PluginVersion},
    model::{ActionProposal, ModelError, ModelFuture, ModelInput, ModelPort, ModelTool},
    policy::{Policy, PolicyDecision, PolicyVersion},
    run::{
        ActionFuture, ActionNormalizer, ActionPort, ActionPortError, ApprovalFuture, ApprovalPort,
        ApprovalPortError, ApprovalResolution, AuditFuture, AuditPort, AuditPortError, Clock,
        LoadedSkillMetadata, NormalizationError, RunBudget, RunContext, RunOrchestrator,
        RunOutcome, RunState, SkillLoadMetadata, SystemClock,
    },
    secret::SecretRefId,
};
use lumen_db::{
    ChannelIdentityMapping, Database, DestinationRevision, DispatchReservation, EffectCertainty,
    ModelEndpointClass, ModelProviderRevision, PluginGrantScope, PluginSettingScope,
    ScheduledJobRevision, ServiceIdentity, SkillVersionRecord, TerminalSpec, TerminalState,
    WorkflowCaptureDraft, WorkspaceModelEgressRevision,
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
    ApprovalConflict, ApprovalDecision, ApprovalDecisionCommand, ApprovalPreview, ApprovalQuery,
    ApprovalRenewal, ApprovalRenewalCommand, ApprovalResult, ApprovalSecretReference, AuditEntry,
    AuditQuery, AutomationActionRequested, CancelRunCommand, CaptureWorkflowCommand,
    ChannelMappingCommand, ChannelMappingQuery, ChannelMappingReview, CreateRunCommand,
    DestinationPolicyCommand, DestinationPolicyQuery, DestinationPolicyReview, EventBroker,
    JobActionCommand, JobReview, JobReviewQuery, PluginActionCommand, PluginActionRequested,
    PluginComponentReview, PluginDetailsQuery, PluginFailureReview, PluginReviewQuery,
    PluginSettingReview, PluginVersionDetails, PrincipalSummary, ProviderPolicyCommand,
    ProviderPolicyQuery, ProviderPolicyReview, RunCancellation, RunCreated, RuntimeService,
    ServiceError, ServiceFuture, ServiceIdentityCommand, ServiceIdentityQuery,
    ServiceIdentityReview, SkillActionCommand, SkillReview, SkillReviewQuery, StagedPluginReview,
    WorkflowCaptureDraftReview, WorkspaceModelPolicyReview,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, Notify};
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

const REVIEWED_SKILL_SOURCE_MAX_BYTES: usize = 65_536;

async fn read_bounded_skill_source(
    reader: impl AsyncRead + Unpin,
) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut source = Vec::with_capacity(REVIEWED_SKILL_SOURCE_MAX_BYTES + 1);
    reader
        .take((REVIEWED_SKILL_SOURCE_MAX_BYTES + 1) as u64)
        .read_to_end(&mut source)
        .await?;
    Ok((source.len() <= REVIEWED_SKILL_SOURCE_MAX_BYTES).then_some(source))
}

#[derive(Clone)]
pub(crate) struct LocalRuntimeService {
    model: Arc<dyn ModelPort>,
    model_probe: Arc<OpenAiCompatibleClient>,
    enforce_model_egress_policy: bool,
    normalizer: Arc<dyn ActionNormalizer>,
    executor: Arc<dyn ExecutorPort>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<DatabaseAudit>,
    actions: Arc<DatabaseActions>,
    database: Database,
    owner_instance_id: uuid::Uuid,
    data_root: Arc<Path>,
    events: EventBroker,
    policy: Policy,
    policy_version: PolicyVersion,
    ambient_capabilities: CapabilitySet,
    capabilities: EffectiveCapabilities,
    budget: RunBudget,
    required_skills: BTreeSet<(SkillId, SkillVersion)>,
    scheduled_execution_lease_millis: u64,
    runs: Arc<Mutex<BTreeMap<RunId, StoredRun>>>,
    // ponytail: one shared wakeup; use per-run signals only if contention becomes measurable.
    run_available: Arc<Notify>,
    #[cfg(test)]
    missing_run_observed: Arc<Notify>,
    cancellations: Arc<Mutex<BTreeMap<RunId, CancellationToken>>>,
    run_workspaces: Arc<Mutex<BTreeMap<RunId, lumen_core::identity::WorkspaceId>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    scheduler_cancellation: CancellationToken,
    shutting_down: Arc<AtomicBool>,
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
        .with_max_response_bytes(config.model.max_response_bytes)
        .with_ollama_gpu_policy(config.model.gpu_policy)
        .map_err(|error| CliError::Runtime(error.to_string()))?;
        let model = Arc::new(
            OpenAiCompatibleClient::new(model_config)
                .map_err(|error| CliError::Runtime(error.to_string()))?,
        );
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
                database: database.clone(),
                data_root: Arc::from(data_root.as_path()),
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
        let service = Self {
            model: model.clone(),
            model_probe: model,
            enforce_model_egress_policy: config.model.allow_remote,
            normalizer: Arc::new(normalizer),
            executor: Arc::new(executor),
            approvals,
            audit: Arc::new(DatabaseAudit(database.clone())),
            actions: Arc::new(DatabaseActions(database.clone())),
            database,
            owner_instance_id: uuid::Uuid::new_v4(),
            data_root: Arc::from(data_root),
            events,
            policy: Policy::default(),
            policy_version: PolicyVersion::new("local-policy-v1").expect("static policy version"),
            capabilities: EffectiveCapabilities::new([ambient_capabilities.clone()]),
            ambient_capabilities,
            budget: RunBudget::limited(
                config.runtime.max_model_turns,
                config.runtime.max_actions,
                Duration::from_secs(config.runtime.max_wall_time_seconds),
                config.runtime.max_captured_result_bytes,
            ),
            required_skills: config.required_skills(),
            scheduled_execution_lease_millis: config
                .runtime
                .max_wall_time_seconds
                .saturating_mul(1_000)
                .saturating_add(30_000),
            runs: Arc::new(Mutex::new(BTreeMap::new())),
            run_available: Arc::new(Notify::new()),
            #[cfg(test)]
            missing_run_observed: Arc::new(Notify::new()),
            cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            run_workspaces: Arc::new(Mutex::new(BTreeMap::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
            scheduler_cancellation: CancellationToken::new(),
            shutting_down: Arc::new(AtomicBool::new(false)),
            redactor,
        };
        service
            .recover_scheduled_run_handoffs(now())
            .await
            .map_err(|error| CliError::Runtime(error.to_string()))?;
        service.spawn_scheduler_loop().await;
        Ok(service)
    }

    async fn spawn_advance(&self, run_id: RunId) {
        let mut tasks = self.tasks.lock().await;
        if self.shutting_down.load(Ordering::SeqCst) {
            return;
        }
        let handle = tokio::spawn(self.clone().advance(run_id));
        tasks.push(handle);
    }

    async fn spawn_scheduler_loop(&self) {
        let handle = tokio::spawn(self.clone().scheduled_job_loop());
        self.tasks.lock().await.push(handle);
    }

    fn ensure_accepting_work(&self) -> Result<(), ServiceError> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(ServiceError::Unavailable("runtime is shutting down".into()));
        }
        Ok(())
    }

    async fn scheduled_job_loop(self) {
        loop {
            tokio::select! {
                biased;
                () = self.scheduler_cancellation.cancelled() => break,
                () = tokio::time::sleep(Duration::from_secs(60)) => {
                    if self.scheduler_cancellation.is_cancelled() {
                        break;
                    }
                    let timestamp = now();
                    if let Err(error) = self.run_due_scheduled_jobs_once(timestamp).await {
                        self.record_scheduler_poll_failure(&error, timestamp).await;
                    }
                }
            }
        }
    }

    pub(crate) async fn run_due_scheduled_jobs_once(
        &self,
        timestamp: TimestampMillis,
    ) -> Result<Vec<RunId>, ServiceError> {
        self.ensure_accepting_work()?;
        let mut created = self.recover_scheduled_run_handoffs(timestamp).await?;
        let due = self
            .database
            .due_scheduled_job_revisions(timestamp)
            .await
            .map_err(|error| ServiceError::Internal(format!("load due scheduled jobs: {error}")))?;
        for job in due {
            match self.run_due_scheduled_job(job.clone(), timestamp).await {
                Ok(Some(run_id)) => created.push(run_id),
                Ok(None) => {}
                Err(error) => {
                    self.record_scheduler_job_failure(
                        &job,
                        job.next_due_at().unwrap_or(timestamp),
                        &error,
                        timestamp,
                    )
                    .await?;
                }
            }
        }
        Ok(created)
    }

    async fn record_scheduler_job_failure(
        &self,
        job: &ScheduledJobRevision,
        scheduled_for: TimestampMillis,
        error: &ServiceError,
        timestamp: TimestampMillis,
    ) -> Result<(), ServiceError> {
        let diagnostic = self.bounded_diagnostic(error);
        self.audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                timestamp,
                AuditEventKind::SchedulerJobFailed,
                AuditOutcome::Failure,
                Some(job.workspace_id()),
                CanonicalValue::object([
                    ("job_id", CanonicalValue::from(job.job_id().to_string())),
                    (
                        "revision",
                        CanonicalValue::from(
                            i64::try_from(job.revision().as_u64()).unwrap_or(i64::MAX),
                        ),
                    ),
                    (
                        "scheduled_for",
                        CanonicalValue::from(
                            i64::try_from(scheduled_for.as_u64()).unwrap_or(i64::MAX),
                        ),
                    ),
                    ("diagnostic", CanonicalValue::from(diagnostic)),
                ]),
            ))
            .await
            .map_err(|error| ServiceError::Internal(error.to_string()))
    }

    async fn record_scheduler_poll_failure(
        &self,
        error: &ServiceError,
        timestamp: TimestampMillis,
    ) {
        let diagnostic = self.bounded_diagnostic(error);
        eprintln!("event=scheduler_poll_failed diagnostic={diagnostic:?}");
        if self
            .audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                timestamp,
                AuditEventKind::SchedulerPollFailed,
                AuditOutcome::Failure,
                None,
                CanonicalValue::object([("diagnostic", CanonicalValue::from(diagnostic))]),
            ))
            .await
            .is_err()
        {
            eprintln!("event=scheduler_poll_failed diagnostic_persistence=failed");
        }
    }

    fn bounded_diagnostic(&self, error: &impl std::fmt::Display) -> String {
        let mut diagnostic = error.to_string();
        self.redactor.redact_string(&mut diagnostic);
        diagnostic.chars().take(256).collect()
    }

    async fn recover_scheduled_run_handoffs(
        &self,
        timestamp: TimestampMillis,
    ) -> Result<Vec<RunId>, ServiceError> {
        self.database
            .recover_expired_running_scheduled_runs(timestamp)
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("recover running scheduled runs: {error}"))
            })?;
        let ready = self
            .database
            .ready_scheduled_run_handoffs()
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("load ready scheduled runs: {error}"))
            })?;
        let mut recovered = Vec::new();
        for (occurrence, run_id, job) in ready {
            match self
                .recover_ready_scheduled_run(&occurrence, run_id, &job, timestamp)
                .await
            {
                Ok(true) => recovered.push(run_id),
                Ok(false) => {}
                Err(error) => {
                    self.record_scheduler_job_failure(
                        &job,
                        occurrence.scheduled_for(),
                        &error,
                        timestamp,
                    )
                    .await?;
                }
            }
        }
        Ok(recovered)
    }

    async fn recover_ready_scheduled_run(
        &self,
        occurrence: &OccurrenceKey,
        run_id: RunId,
        job: &ScheduledJobRevision,
        timestamp: TimestampMillis,
    ) -> Result<bool, ServiceError> {
        let lease_id = uuid::Uuid::new_v4();
        let claimed = self
            .database
            .claim_ready_scheduled_run(
                occurrence,
                lease_id,
                timestamp,
                scheduled_lease_expiry(timestamp),
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("claim ready scheduled run: {error}"))
            })?;
        if !claimed {
            return Ok(false);
        }
        let mut stored = self
            .prepare_stored_run(
                run_id,
                self.scheduled_run_request(job, occurrence, lease_id)
                    .await?,
            )
            .await?;
        self.publish_run_created(run_id, stored.workspace_id)?;
        self.database
            .start_owned_scheduled_run(
                occurrence,
                lease_id,
                run_id,
                self.owner_instance_id,
                timestamp,
                self.scheduled_execution_lease_expiry(timestamp),
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("start recovered scheduled run: {error}"))
            })?;
        stored.start_disposition = StartDisposition::ScheduledStartCommitted;
        self.install_and_spawn_run(run_id, stored).await;
        Ok(true)
    }

    async fn run_due_scheduled_job(
        &self,
        job: ScheduledJobRevision,
        timestamp: TimestampMillis,
    ) -> Result<Option<RunId>, ServiceError> {
        let Some(scheduled_for) = job.next_due_at() else {
            return Ok(None);
        };
        let occurrence = OccurrenceKey::new(job.job_id(), job.revision(), scheduled_for);
        if let Some(existing) = self
            .database
            .scheduled_occurrence_record(&occurrence)
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("load scheduled occurrence: {error}"))
            })?
            && existing.run_id().is_some()
            && (existing.state() != "unknown" || !job.idempotent())
        {
            return Ok(None);
        }
        let lease_id = uuid::Uuid::new_v4();
        let claimed = self
            .database
            .claim_job_occurrence(
                &occurrence,
                lease_id,
                timestamp,
                scheduled_lease_expiry(timestamp),
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("claim scheduled occurrence: {error}"))
            })?;
        if !claimed {
            return Ok(None);
        }
        if let Some(existing) = self
            .database
            .scheduled_occurrence_record(&occurrence)
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("reload scheduled occurrence: {error}"))
            })?
            && let Some(run_id) = existing.run_id()
            && (existing.state() != "unknown" || !job.idempotent())
        {
            return Ok(Some(run_id));
        }
        let request = self
            .scheduled_run_request(&job, &occurrence, lease_id)
            .await?;
        let run_id = RunId::new();
        let mut stored = self.prepare_stored_run(run_id, request).await?;
        self.database
            .persist_owned_scheduled_run_handoff(
                &job,
                &occurrence,
                lease_id,
                run_id,
                self.owner_instance_id,
                job.schedule().next_after(scheduled_for, job.enabled()),
                timestamp,
            )
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("persist scheduled run handoff: {error}"))
            })?;
        self.publish_run_created(run_id, stored.workspace_id)?;
        self.database
            .start_owned_scheduled_run(
                &occurrence,
                lease_id,
                run_id,
                self.owner_instance_id,
                timestamp,
                self.scheduled_execution_lease_expiry(timestamp),
            )
            .await
            .map_err(|error| ServiceError::Internal(format!("start scheduled run: {error}")))?;
        stored.start_disposition = StartDisposition::ScheduledStartCommitted;
        self.install_and_spawn_run(run_id, stored).await;
        Ok(Some(run_id))
    }

    async fn scheduled_run_request(
        &self,
        job: &ScheduledJobRevision,
        occurrence: &OccurrenceKey,
        lease_id: uuid::Uuid,
    ) -> Result<StoredRunRequest, ServiceError> {
        let grants = self
            .database
            .service_identity_grants(job.workspace_id(), job.service())
            .await
            .map_err(|error| {
                ServiceError::Internal(format!("load scheduled service grants: {error}"))
            })?;
        Ok(StoredRunRequest {
            workspace_id: job.workspace_id(),
            actor: job.service().clone(),
            prompt: job.prompt().to_owned(),
            budget: self
                .budget
                .with_step_limits(job.max_model_turns(), job.max_actions()),
            data_class: job.data_class(),
            model_override: None,
            capabilities_override: Some(EffectiveCapabilities::new([
                self.ambient_capabilities.clone(),
                CapabilitySet::new(grants),
            ])),
            job_origin: Some(JobOrigin::new(
                occurrence.job_id(),
                occurrence.revision(),
                occurrence.scheduled_for(),
            )),
            scheduled_handoff: Some((occurrence.clone(), lease_id)),
        })
    }

    fn scheduled_execution_lease_expiry(&self, timestamp: TimestampMillis) -> TimestampMillis {
        TimestampMillis::new(
            timestamp
                .as_u64()
                .saturating_add(self.scheduled_execution_lease_millis),
        )
    }

    async fn prepare_stored_run(
        &self,
        run_id: RunId,
        request: StoredRunRequest,
    ) -> Result<StoredRun, ServiceError> {
        let mut context = RunContext::new(run_id, request.workspace_id, request.actor);
        if let Some(origin) = request.job_origin {
            context = context.with_job_origin(origin);
        }
        let reviewed_skills = self
            .prompt_with_reviewed_skills(request.workspace_id, &request.prompt)
            .await?;
        context = context
            .with_loaded_skills(reviewed_skills.loaded_skills)
            .with_skill_loads(reviewed_skills.skill_loads);
        let state = RunState::new(context, reviewed_skills.prompt, request.budget)
            .with_data_class(request.data_class);
        Ok(StoredRun {
            workspace_id: request.workspace_id,
            state,
            model_override: request.model_override,
            capabilities_override: request.capabilities_override,
            scheduled_handoff: request.scheduled_handoff,
            start_disposition: StartDisposition::Created,
        })
    }

    fn publish_run_created(
        &self,
        run_id: RunId,
        workspace_id: lumen_core::identity::WorkspaceId,
    ) -> Result<(), ServiceError> {
        self.events
            .publish(
                workspace_id,
                run_id,
                "run.created",
                CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
            )
            .map(|_| ())
            .map_err(|error| ServiceError::Internal(error.to_string()))
    }

    async fn install_and_spawn_run(&self, run_id: RunId, stored: StoredRun) {
        let workspace_id = stored.workspace_id;
        for skill in stored
            .state
            .context()
            .skill_loads()
            .iter()
            .filter(|skill| skill.status() == "excluded")
        {
            let _ = self.events.publish(
                workspace_id,
                run_id,
                "skill.excluded",
                skill_load_value(skill),
            );
        }
        self.runs.lock().await.insert(run_id, stored);
        let cancellation = CancellationToken::new();
        if self.shutting_down.load(Ordering::SeqCst) {
            cancellation.cancel();
        }
        self.cancellations.lock().await.insert(run_id, cancellation);
        self.run_workspaces
            .lock()
            .await
            .insert(run_id, workspace_id);
        self.spawn_advance(run_id).await;
    }

    async fn prompt_with_reviewed_skills(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        prompt: &str,
    ) -> Result<ReviewedSkillPrompt, ServiceError> {
        let skills = self
            .database
            .enabled_skill_versions(workspace_id)
            .await
            .map_err(repository_service_error)?;
        let mut rendered = Vec::new();
        let mut loaded_skills = Vec::new();
        let mut skill_loads = Vec::new();
        let mut selected = BTreeSet::new();
        for skill in skills {
            selected.insert((skill.skill_id(), skill.version().clone()));
            let result = self.load_reviewed_skill_context(workspace_id, &skill).await;
            skill_loads.push(result.metadata);
            if let Some(context) = result.loaded {
                loaded_skills.push(context.metadata);
                rendered.push(context.rendered);
            }
        }
        for (skill_id, version) in self.required_skills.difference(&selected) {
            let record = self
                .database
                .skill_version(workspace_id, *skill_id, version)
                .await
                .map_err(repository_service_error)?;
            skill_loads.push(SkillLoadMetadata::excluded(
                skill_id.to_string(),
                version.as_str(),
                record
                    .as_ref()
                    .map_or("", SkillVersionRecord::source_digest),
                if record.is_some() {
                    "disabled"
                } else {
                    "not_eligible"
                },
                true,
            ));
        }
        if rendered.is_empty() {
            return Ok(ReviewedSkillPrompt {
                prompt: prompt.to_owned(),
                loaded_skills,
                skill_loads,
            });
        }
        Ok(ReviewedSkillPrompt {
            prompt: format!("{}\n\nUser request:\n{}", rendered.join("\n\n"), prompt),
            loaded_skills,
            skill_loads,
        })
    }

    async fn load_reviewed_skill_context(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        skill: &SkillVersionRecord,
    ) -> SkillLoadResult {
        let required = self
            .required_skills
            .contains(&(skill.skill_id(), skill.version().clone()));
        let excluded = |reason| SkillLoadResult {
            metadata: SkillLoadMetadata::excluded(
                skill.skill_id().to_string(),
                skill.version().as_str(),
                skill.source_digest(),
                reason,
                required,
            ),
            loaded: None,
        };
        if skill.workspace_id() != workspace_id {
            return excluded("not_eligible");
        }
        if !skill.reviewed() {
            return excluded("unreviewed");
        }
        if skill.source_format() != "markdown" {
            return excluded("unsupported_format");
        }
        let path = self
            .data_root
            .join("skills")
            .join(skill.skill_id().to_string())
            .join(format!("{}.md", skill.version().as_str()));
        let file = match tokio::fs::File::open(&path).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return excluded("missing_source");
            }
            Err(_) => return excluded("read_failed"),
        };
        let source = match read_bounded_skill_source(file).await {
            Ok(Some(source)) => source,
            Ok(None) => return excluded("oversized"),
            Err(_) => return excluded("read_failed"),
        };
        let source = match String::from_utf8(source) {
            Ok(source) => source,
            Err(_) => return excluded("unsupported_encoding"),
        };
        if sha256_hex(source.as_bytes()) != skill.source_digest() {
            return excluded("digest_mismatch");
        }
        SkillLoadResult {
            metadata: SkillLoadMetadata::loaded(
                skill.skill_id().to_string(),
                skill.version().as_str(),
                skill.source_digest(),
                required,
            ),
            loaded: Some(LoadedReviewedSkill {
                metadata: LoadedSkillMetadata::new(
                    skill.skill_id().to_string(),
                    skill.version().as_str(),
                    skill.source_digest(),
                ),
                rendered: format!(
                    "Reviewed Lumen skill\nid: {}\nversion: {}\ndigest: {}\nformat: {}\nname: {}\ndescription: {}\n\n{}",
                    skill.skill_id(),
                    skill.version().as_str(),
                    skill.source_digest(),
                    skill.source_format(),
                    skill.name(),
                    skill.description(),
                    source
                ),
            }),
        }
    }

    #[allow(dead_code)]
    pub(crate) async fn capture_workflow_draft(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        run_id: RunId,
        actor: lumen_core::identity::PrincipalId,
    ) -> Result<uuid::Uuid, ServiceError> {
        self.ensure_accepting_work()?;
        self.database.verify_audit_chain().await.map_err(|error| {
            ServiceError::Conflict(format!("audit chain does not verify: {error}"))
        })?;
        let run = sqlx::query("SELECT state FROM agent_runs WHERE id = ? AND workspace_id = ?")
            .bind(run_id.to_string())
            .bind(workspace_id.to_string())
            .fetch_optional(self.database.pool())
            .await
            .map_err(sql_service_error)?
            .ok_or(ServiceError::NotFound)?;
        let state: String = run.try_get("state").map_err(sql_service_error)?;
        if state != "completed" {
            return Err(ServiceError::Conflict(
                "workflow capture requires a completed source run".into(),
            ));
        }
        let actions = sqlx::query(
            "SELECT kind, arguments_json, state FROM actions
             WHERE run_id = ? ORDER BY created_at, id",
        )
        .bind(run_id.to_string())
        .fetch_all(self.database.pool())
        .await
        .map_err(sql_service_error)?;
        let mut action_lines = Vec::new();
        let mut procedure_lines = Vec::new();
        for (index, action) in actions.into_iter().enumerate() {
            let arguments: String = action
                .try_get("arguments_json")
                .map_err(sql_service_error)?;
            let kind = action
                .try_get::<String, _>("kind")
                .map_err(sql_service_error)?;
            let state = action
                .try_get::<String, _>("state")
                .map_err(sql_service_error)?;
            action_lines.push(format!(
                "- kind: {}; state: {}; arguments_sha256: {}",
                kind,
                state,
                sha256_hex(arguments.as_bytes())
            ));
            procedure_lines.push(format!(
                "{}. Review whether `{kind}` is still appropriate, supply fresh operator-approved inputs, and verify its live result.",
                index + 1
            ));
        }
        let capture_kind = if action_lines.is_empty() {
            procedure_lines.push(
                "- No tool procedure was observed; this is provenance only and is not evidence of learned reusable behavior."
                    .to_owned(),
            );
            "provenance-only zero-action draft"
        } else {
            "review-required tool procedure draft"
        };
        if action_lines.is_empty() {
            action_lines.push("- none".to_owned());
        }
        let audit_records = self
            .database
            .list_audit_records_for_run(workspace_id, run_id)
            .await
            .map_err(repository_service_error)?;
        let event_kinds = audit_records
            .iter()
            .map(|record| record.event().kind().as_str())
            .collect::<Vec<_>>();
        let mut body = format!(
            "# Reviewable Workflow Capture Draft\n\nartifact_type: {capture_kind}\nsource_run_id: {run_id}\nsource_workspace_id: {workspace_id}\n\nThis draft preserves verified provenance, not replayable historical inputs or trusted automation.\n\n## Observed Actions\n{}\n\n## Candidate Procedure\n{}\n\n## Audit Events\n{}\n\n## Required Variables\n- Historical raw action inputs are deliberately unavailable; only their digests are retained.\n- Before publishing, the operator must define every fresh non-secret input required by each candidate step.\n\n## Expected Outputs\n- Verify each fresh action result during the new run; historical raw outputs are not reconstructed.\n- The source run completed successfully, which does not guarantee a changed-input run will succeed.\n\n## Operator Review Before Publishing\n1. Verify the source run, workspace, ordered actions, argument digests, and audit events.\n2. Confirm each action kind is still appropriate and document the current safe inputs outside this artifact.\n3. Reject the draft if a required variable, expected result, or failure condition is unclear.\n4. Publish only through the approval-bound skill publication path.\n\n## Capture Limitations\n- No historical raw inputs, tool outputs, or secret values are reconstructed.\n- Publication records review and integrity; it does not grant capabilities or bypass approval.\n\n## Failure Notes\n- No source-run failure was captured because only completed runs are eligible.",
            action_lines.join("\n"),
            procedure_lines.join("\n"),
            event_kinds.join(", ")
        );
        self.redactor.redact_string(&mut body);
        let draft = WorkflowCaptureDraft::new(
            uuid::Uuid::new_v4(),
            workspace_id,
            format!("Reviewable workflow draft {run_id}"),
            body,
            actor,
            now(),
        )
        .map_err(|error| ServiceError::Conflict(error.to_string()))?;
        let draft_id = draft.id();
        self.database
            .insert_workflow_capture_draft(&draft)
            .await
            .map_err(repository_service_error)?;
        Ok(draft_id)
    }

    pub(crate) async fn shutdown(&self) {
        self.shutdown_with_timeout(Duration::from_secs(5)).await;
    }

    pub(crate) async fn drain_submitted_work(&self) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        self.scheduler_cancellation.cancel();
        let mut tasks = std::mem::take(&mut *self.tasks.lock().await);
        if tokio::time::timeout(Duration::from_secs(5), async {
            for task in &mut tasks {
                let _ = task.await;
            }
        })
        .await
        .is_err()
        {
            for task in tasks {
                if !task.is_finished() {
                    task.abort();
                    let _ = task.await;
                }
            }
        }
    }

    async fn shutdown_with_timeout(&self, drain_timeout: Duration) {
        if self.shutting_down.swap(true, Ordering::SeqCst) {
            return;
        }
        self.scheduler_cancellation.cancel();
        for cancellation in self.cancellations.lock().await.values() {
            cancellation.cancel();
        }
        let waiting = {
            let mut runs = self.runs.lock().await;
            runs.iter_mut()
                .map(|(run_id, stored)| {
                    stored.state.cancel();
                    *run_id
                })
                .collect::<Vec<_>>()
        };
        let mut tasks = std::mem::take(&mut *self.tasks.lock().await);
        tasks.extend(
            waiting
                .into_iter()
                .map(|run_id| tokio::spawn(self.clone().advance(run_id))),
        );
        let completed = tokio::time::timeout(drain_timeout, async {
            for task in &mut tasks {
                let _ = task.await;
            }
        })
        .await
        .is_ok();
        if !completed {
            for task in tasks {
                if task.is_finished() {
                    continue;
                }
                task.abort();
                let _ = task.await;
            }
        }
        let remaining = self.run_workspaces.lock().await.clone();
        if !remaining.is_empty() {
            eprintln!(
                "event=runtime_shutdown_forced remaining_runs={}",
                remaining.len()
            );
        }
        for (run_id, workspace_id) in remaining {
            let timestamp = now();
            let terminal = TerminalSpec::new(
                TerminalState::Failed,
                EffectCertainty::Unknown,
                "shutdown_forced",
                Some("graceful drain deadline exceeded".into()),
            )
            .expect("static shutdown terminal specification");
            match self
                .database
                .terminalize_owned_run(
                    run_id,
                    workspace_id,
                    self.owner_instance_id,
                    &terminal,
                    AuditEventId::new(),
                    timestamp,
                )
                .await
            {
                Ok(()) => {
                    if let Err(error) = self
                        .database
                        .flush_terminal_audit(workspace_id, run_id)
                        .await
                    {
                        eprintln!(
                            "event=runtime_shutdown_audit_pending run_id={run_id} diagnostic={:?}",
                            self.bounded_diagnostic(&error)
                        );
                    }
                }
                Err(error) => {
                    eprintln!(
                        "event=runtime_shutdown_forced run_id={run_id} diagnostic={:?}",
                        self.bounded_diagnostic(&error)
                    );
                }
            }
            self.runs.lock().await.remove(&run_id);
            self.finish_run(run_id).await;
        }
    }

    async fn advance(self, run_id: RunId) {
        let mut stored = loop {
            let available = self.run_available.notified();
            tokio::pin!(available);
            available.as_mut().enable();
            if let Some(stored) = self.runs.lock().await.remove(&run_id) {
                break stored;
            }
            #[cfg(test)]
            self.missing_run_observed.notify_one();
            if !self.cancellations.lock().await.contains_key(&run_id) {
                return;
            }
            available.await;
        };
        if let Some((occurrence, lease_id)) = &stored.scheduled_handoff {
            let current = match self
                .database
                .scheduled_run_lease_is_current(occurrence, *lease_id, run_id)
                .await
            {
                Ok(current) => current,
                Err(error) => {
                    self.record_run_reconciliation_required(
                        stored.workspace_id,
                        run_id,
                        "dispatch_fence",
                        &error,
                        now(),
                    )
                    .await;
                    self.finish_run(run_id).await;
                    return;
                }
            };
            if !current {
                self.finish_run(run_id).await;
                return;
            }
        }
        let start = match stored.start_disposition {
            StartDisposition::Created => {
                self.database
                    .start_owned_run(
                        run_id,
                        stored.workspace_id,
                        self.owner_instance_id,
                        false,
                        now(),
                    )
                    .await
            }
            StartDisposition::ResumeApproval => {
                self.database
                    .start_owned_run(
                        run_id,
                        stored.workspace_id,
                        self.owner_instance_id,
                        true,
                        now(),
                    )
                    .await
            }
            StartDisposition::ScheduledStartCommitted => Ok(()),
        };
        if let Err(error) = start {
            self.record_run_reconciliation_required(
                stored.workspace_id,
                run_id,
                "run_start",
                &error,
                now(),
            )
            .await;
            self.finish_run(run_id).await;
            return;
        }
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
                run_id,
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
        let clock = SystemClock;
        let orchestrator = RunOrchestrator::new(
            &model,
            self.normalizer.as_ref(),
            self.executor.as_ref(),
            self.approvals.as_ref(),
            self.audit.as_ref(),
            self.actions.as_ref(),
            &clock,
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
            )
            .await
        {
            Ok(RunOutcome::AwaitingApproval { approval_id }) => {
                if let Err(error) = self
                    .database
                    .pause_owned_run_for_approval(
                        run_id,
                        stored.workspace_id,
                        self.owner_instance_id,
                        now(),
                    )
                    .await
                {
                    self.record_run_reconciliation_required(
                        stored.workspace_id,
                        run_id,
                        "approval_pause",
                        &error,
                        now(),
                    )
                    .await;
                    self.finish_run(run_id).await;
                    return;
                }
                stored.start_disposition = StartDisposition::ResumeApproval;
                if let Err(error) = self.events.publish(
                    stored.workspace_id,
                    run_id,
                    "approval.required",
                    CanonicalValue::object([(
                        "approval_id",
                        CanonicalValue::from(approval_id.to_string()),
                    )]),
                ) {
                    self.record_run_reconciliation_required(
                        stored.workspace_id,
                        run_id,
                        "approval_event",
                        &error,
                        now(),
                    )
                    .await;
                }
                self.runs.lock().await.insert(run_id, stored);
                self.run_available.notify_waiters();
            }
            Ok(outcome) => {
                let (state, kind, mut payload) = terminal_event(&outcome);
                self.redactor.redact_value(&mut payload);
                self.terminalize_stored_run(
                    run_id,
                    &stored,
                    state,
                    scheduled_occurrence_terminal_state(&outcome),
                    kind,
                    payload,
                    None,
                    now(),
                )
                .await;
            }
            Err(error) => {
                let timestamp = now();
                let audit_failure = if cancellation.is_cancelled() {
                    self.audit
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
                        .await
                        .err()
                        .map(|error| ("cancellation_audit", error.to_string()))
                } else {
                    None
                };
                let cancelled = cancellation.is_cancelled();
                self.terminalize_stored_run(
                    run_id,
                    &stored,
                    if cancelled { "cancelled" } else { "failed" },
                    if cancelled { "cancelled" } else { "failed" },
                    if cancelled {
                        "run.cancelled"
                    } else {
                        "run.failed"
                    },
                    CanonicalValue::from(self.bounded_diagnostic(&error)),
                    audit_failure,
                    timestamp,
                )
                .await;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn terminalize_stored_run(
        &self,
        run_id: RunId,
        stored: &StoredRun,
        state: &str,
        scheduled_state: &str,
        event_kind: &str,
        payload: CanonicalValue,
        prerequisite_failure: Option<(&'static str, String)>,
        timestamp: TimestampMillis,
    ) {
        let terminal_state = match state {
            "completed" if prerequisite_failure.is_none() => TerminalState::Completed,
            "cancelled" => TerminalState::Cancelled,
            _ => TerminalState::Failed,
        };
        let certainty = if scheduled_state == "unknown" || prerequisite_failure.is_some() {
            EffectCertainty::Unknown
        } else {
            EffectCertainty::NoEffect
        };
        let code = prerequisite_failure.as_ref().map_or_else(
            || match event_kind {
                "run.completed" => "run_completed",
                "run.cancelled" => "run_cancelled",
                "run.timed_out" => "run_timed_out",
                _ => "run_failed",
            },
            |(stage, _)| stage,
        );
        let diagnostic = prerequisite_failure
            .as_ref()
            .map(|(_, error)| self.bounded_diagnostic(error));
        let terminal = TerminalSpec::new(terminal_state, certainty, code, diagnostic)
            .expect("bounded terminal specification");
        match self
            .database
            .terminalize_owned_run(
                run_id,
                stored.workspace_id,
                self.owner_instance_id,
                &terminal,
                AuditEventId::new(),
                timestamp,
            )
            .await
        {
            Ok(()) => {
                if let Err(error) = self
                    .database
                    .flush_terminal_audit(stored.workspace_id, run_id)
                    .await
                {
                    eprintln!(
                        "event=run_terminal_audit_pending run_id={run_id} diagnostic={:?}",
                        self.bounded_diagnostic(&error)
                    );
                } else if let Err(error) =
                    self.events
                        .publish(stored.workspace_id, run_id, event_kind, payload)
                {
                    self.record_run_reconciliation_required(
                        stored.workspace_id,
                        run_id,
                        "terminal_event",
                        &error,
                        timestamp,
                    )
                    .await;
                }
            }
            Err(error) => {
                self.record_run_reconciliation_required(
                    stored.workspace_id,
                    run_id,
                    "terminal_persistence",
                    &error,
                    timestamp,
                )
                .await;
            }
        }
        self.finish_run(run_id).await;
    }

    async fn record_run_reconciliation_required(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        run_id: RunId,
        stage: &'static str,
        error: &impl std::fmt::Display,
        timestamp: TimestampMillis,
    ) {
        let diagnostic = self.bounded_diagnostic(error);
        let payload = CanonicalValue::object([
            ("run_id", CanonicalValue::from(run_id.to_string())),
            ("stage", CanonicalValue::from(stage)),
            ("diagnostic", CanonicalValue::from(diagnostic.clone())),
        ]);
        if self
            .audit
            .record(AuditEvent::new(
                AuditEventId::new(),
                timestamp,
                AuditEventKind::RunReconciliationRequired,
                AuditOutcome::Unknown,
                Some(workspace_id),
                payload.clone(),
            ))
            .await
            .is_err()
        {
            eprintln!(
                "event=run_reconciliation_required run_id={run_id} stage={stage} diagnostic={diagnostic:?} audit_persistence=failed"
            );
        }
        if self
            .events
            .publish(workspace_id, run_id, "run.reconciliation_required", payload)
            .is_err()
        {
            eprintln!(
                "event=run_reconciliation_required run_id={run_id} stage={stage} diagnostic={diagnostic:?} event_publication=failed"
            );
        }
    }

    async fn finish_run(&self, run_id: RunId) {
        self.cancellations.lock().await.remove(&run_id);
        self.run_workspaces.lock().await.remove(&run_id);
        self.run_available.notify_waiters();
    }

    pub(crate) async fn request_extension_action(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        actor: lumen_core::identity::PrincipalId,
        proposal: ActionProposal,
        capabilities: CapabilitySet,
    ) -> Result<RunId, ServiceError> {
        self.ensure_accepting_work()?;
        let run_id = RunId::new();
        self.database
            .create_owned_run(run_id, workspace_id, &actor, self.owner_instance_id, now())
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
                scheduled_handoff: None,
                start_disposition: StartDisposition::Created,
            },
        );
        let cancellation = CancellationToken::new();
        if self.shutting_down.load(Ordering::SeqCst) {
            cancellation.cancel();
        }
        self.cancellations.lock().await.insert(run_id, cancellation);
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
    fn model_readiness(
        &self,
        _workspace_id: lumen_core::identity::WorkspaceId,
    ) -> ServiceFuture<'_, String> {
        Box::pin(async move {
            if self.model_probe.identity().endpoint_class()
                == lumen_integrations::openai_compatible::EndpointClass::Remote
            {
                return Ok("remote_not_probed".into());
            }
            Ok(match self.model_probe.probe_local_model().await {
                Ok(true) => "listed",
                Ok(false) => "not_listed",
                Err(_) => "unavailable",
            }
            .into())
        })
    }

    fn create_run(&self, command: CreateRunCommand) -> ServiceFuture<'_, RunCreated> {
        let service = self.clone();
        Box::pin(async move {
            service.ensure_accepting_work()?;
            let run_id = RunId::new();
            service
                .database
                .create_owned_run(
                    run_id,
                    command.workspace_id(),
                    command.actor(),
                    service.owner_instance_id,
                    now(),
                )
                .await
                .map_err(repository_service_error)?;
            let reviewed_skills = service
                .prompt_with_reviewed_skills(command.workspace_id(), command.prompt())
                .await?;
            let state = RunState::new(
                RunContext::new(run_id, command.workspace_id(), command.actor().clone())
                    .with_loaded_skills(reviewed_skills.loaded_skills)
                    .with_skill_loads(reviewed_skills.skill_loads),
                reviewed_skills.prompt,
                service.budget,
            )
            .with_data_class(command.data_class());
            let stored = StoredRun {
                workspace_id: command.workspace_id(),
                state,
                model_override: None,
                capabilities_override: None,
                scheduled_handoff: None,
                start_disposition: StartDisposition::Created,
            };
            service.publish_run_created(run_id, command.workspace_id())?;
            service.install_and_spawn_run(run_id, stored).await;
            Ok(RunCreated::new(run_id))
        })
    }

    fn decide_approval(
        &self,
        command: ApprovalDecisionCommand,
    ) -> ServiceFuture<'_, ApprovalResult> {
        let service = self.clone();
        Box::pin(async move {
            service.ensure_accepting_work()?;
            let (run_id, result) = service.approvals.decide(&command).await?;
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

    fn renew_approval(
        &self,
        command: ApprovalRenewalCommand,
    ) -> ServiceFuture<'_, ApprovalRenewal> {
        let service = self.clone();
        Box::pin(async move {
            service.ensure_accepting_work()?;
            let previous = command.approval_id();
            let mut runs = service.runs.lock().await;
            let run_id = runs
                .iter()
                .find_map(|(run_id, stored)| {
                    stored
                        .state
                        .is_awaiting_approval(previous)
                        .then_some(*run_id)
                })
                .ok_or(ServiceError::ApprovalConflict(ApprovalConflict::Stale))?;
            let (_, approval_id) = service
                .approvals
                .renew(command.workspace_id(), previous, run_id)
                .await?;
            let updated = runs
                .get_mut(&run_id)
                .is_some_and(|stored| stored.state.renew_pending_approval(previous, approval_id));
            if !updated {
                return Err(ServiceError::ApprovalConflict(ApprovalConflict::Stale));
            }
            drop(runs);
            service
                .audit
                .record(AuditEvent::new(
                    AuditEventId::new(),
                    now(),
                    AuditEventKind::ApprovalCreated,
                    AuditOutcome::Pending,
                    Some(command.workspace_id()),
                    CanonicalValue::object([
                        ("run_id", CanonicalValue::from(run_id.to_string())),
                        (
                            "previous_approval_id",
                            CanonicalValue::from(previous.to_string()),
                        ),
                        ("approval_id", CanonicalValue::from(approval_id.to_string())),
                        (
                            "renewed_by",
                            CanonicalValue::from(command.actor().subject()),
                        ),
                    ]),
                ))
                .await
                .map_err(|error| ServiceError::Internal(error.to_string()))?;
            service
                .events
                .publish(
                    command.workspace_id(),
                    run_id,
                    "approval.renewed",
                    CanonicalValue::object([
                        (
                            "previous_approval_id",
                            CanonicalValue::from(previous.to_string()),
                        ),
                        ("approval_id", CanonicalValue::from(approval_id.to_string())),
                    ]),
                )
                .map_err(|error| ServiceError::Internal(error.to_string()))?;
            Ok(ApprovalRenewal::new(previous, approval_id, run_id))
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
                .list_pending_approvals(query.workspace_id(), now())
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

    fn run_status(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        run_id: RunId,
    ) -> ServiceFuture<'_, String> {
        let service = self.clone();
        Box::pin(async move {
            sqlx::query_scalar("SELECT state FROM agent_runs WHERE id = ? AND workspace_id = ?")
                .bind(run_id.to_string())
                .bind(workspace_id.to_string())
                .fetch_optional(service.database.pool())
                .await
                .map_err(sql_service_error)?
                .ok_or(ServiceError::NotFound)
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

    fn list_channel_mappings(
        &self,
        query: ChannelMappingQuery,
    ) -> ServiceFuture<'_, Vec<ChannelMappingReview>> {
        Box::pin(async move {
            self.database
                .list_channel_identity_mappings(query.workspace_id())
                .await
                .map_err(repository_service_error)?
                .into_iter()
                .map(channel_mapping_review)
                .collect()
        })
    }

    fn update_channel_mapping(
        &self,
        command: ChannelMappingCommand,
    ) -> ServiceFuture<'_, ChannelMappingReview> {
        Box::pin(async move {
            let timestamp = now();
            let mapping = ChannelIdentityMapping::new(
                command.external().clone(),
                command.principal().clone(),
                command.workspace_id(),
                command.allowed(),
                timestamp,
                timestamp,
            )
            .map_err(|error| ServiceError::Conflict(error.to_string()))?;
            self.database
                .upsert_channel_identity_mapping(&mapping)
                .await
                .map_err(repository_service_error)?;
            channel_mapping_review(mapping)
        })
    }

    fn list_destination_policies(
        &self,
        _query: DestinationPolicyQuery,
    ) -> ServiceFuture<'_, Vec<DestinationPolicyReview>> {
        Box::pin(async move {
            self.database
                .list_latest_destination_revisions()
                .await
                .map_err(repository_service_error)?
                .into_iter()
                .map(destination_policy_review)
                .collect()
        })
    }

    fn update_destination_policy(
        &self,
        command: DestinationPolicyCommand,
    ) -> ServiceFuture<'_, DestinationPolicyReview> {
        Box::pin(async move {
            let latest = self
                .database
                .latest_destination_revision(command.destination().clone())
                .await
                .map_err(repository_service_error)?;
            let revision = latest.as_ref().map_or(1, |current| current.revision() + 1);
            let policy = DestinationRevision::new(
                command.destination().clone(),
                revision,
                command.enabled(),
                command.allowed_data_classes().iter().copied(),
                now(),
            )
            .map_err(|error| ServiceError::Conflict(error.to_string()))?;
            self.database
                .append_destination_revision(&policy)
                .await
                .map_err(repository_service_error)?;
            destination_policy_review(policy)
        })
    }

    fn list_provider_policies(
        &self,
        query: ProviderPolicyQuery,
    ) -> ServiceFuture<'_, Vec<ProviderPolicyReview>> {
        Box::pin(async move {
            let workspace_policies = self
                .database
                .list_latest_workspace_model_egress_revisions(query.workspace_id())
                .await
                .map_err(repository_service_error)?
                .into_iter()
                .map(|policy| (policy.provider_id().clone(), policy))
                .collect::<BTreeMap<_, _>>();
            self.database
                .list_latest_model_provider_revisions()
                .await
                .map_err(repository_service_error)?
                .into_iter()
                .map(|provider| {
                    let workspace_policy = workspace_policies.get(provider.provider_id());
                    provider_policy_review(provider, workspace_policy)
                })
                .collect()
        })
    }

    fn update_provider_policy(
        &self,
        command: ProviderPolicyCommand,
    ) -> ServiceFuture<'_, ProviderPolicyReview> {
        let service = self.clone();
        Box::pin(async move {
            let requested_sensitive = command
                .workspace_allowed_data_classes()
                .contains(&DataClass::Sensitive);
            let current_workspace_policy = service
                .database
                .latest_workspace_model_egress_revision(
                    command.workspace_id(),
                    command.provider_id().clone(),
                )
                .await
                .map_err(repository_service_error)?;
            let expands_to_sensitive = requested_sensitive
                && !current_workspace_policy
                    .as_ref()
                    .is_some_and(|policy| policy.allows(DataClass::Sensitive));
            let provider = service
                .database
                .latest_model_provider_revision(command.provider_id().clone())
                .await
                .map_err(repository_service_error)?
                .ok_or(ServiceError::NotFound)?;
            if expands_to_sensitive {
                let capability = Capability::new(
                    CapabilityName::PolicyModify,
                    ResourceScope::exact("egress_provider", command.provider_id().as_str())
                        .map_err(|error| ServiceError::Conflict(error.to_string()))?,
                );
                let run_id = service
                    .request_extension_action(
                        command.workspace_id(),
                        command.actor().clone(),
                        provider_policy_update_proposal(
                            command.provider_id(),
                            command.enabled(),
                            command.workspace_allowed_data_classes(),
                        ),
                        CapabilitySet::new([capability]),
                    )
                    .await?;
                return provider_policy_review(provider, current_workspace_policy.as_ref())
                    .map(|review| review.with_approval_requested(run_id));
            }

            let (provider_revision, workspace_policy) = apply_provider_policy_update(
                &service.database,
                command.workspace_id(),
                command.provider_id().clone(),
                command.enabled(),
                command.workspace_allowed_data_classes(),
            )
            .await?;
            provider_policy_review(provider_revision, Some(&workspace_policy))
        })
    }

    fn list_service_identities(
        &self,
        query: ServiceIdentityQuery,
    ) -> ServiceFuture<'_, Vec<ServiceIdentityReview>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT provider, subject, workspace_id, owner_provider, owner_subject,
                        label, enabled, created_at, updated_at
                 FROM service_identities
                 WHERE workspace_id = ?
                 ORDER BY label, subject",
            )
            .bind(query.workspace_id().to_string())
            .fetch_all(self.database.pool())
            .await
            .map_err(sql_service_error)?;
            let mut reviews = Vec::with_capacity(rows.len());
            for row in rows {
                let principal = principal_from_columns(&row, "provider", "subject")?;
                let grants = self
                    .database
                    .service_identity_grants(query.workspace_id(), &principal)
                    .await
                    .map_err(repository_service_error)?
                    .into_iter()
                    .map(|capability| capability_review(&capability))
                    .collect::<Result<Vec<_>, _>>()?;
                reviews.push(ServiceIdentityReview::new(
                    PrincipalSummary::new(&principal),
                    query.workspace_id(),
                    PrincipalSummary::new(&principal_from_columns(
                        &row,
                        "owner_provider",
                        "owner_subject",
                    )?),
                    row.try_get::<String, _>("label")
                        .map_err(sql_service_error)?,
                    row.try_get::<i64, _>("enabled")
                        .map_err(sql_service_error)?
                        == 1,
                    grants,
                    timestamp_from_sql_row(&row, "created_at")?,
                    timestamp_from_sql_row(&row, "updated_at")?,
                ));
            }
            Ok(reviews)
        })
    }

    fn update_service_identity(
        &self,
        command: ServiceIdentityCommand,
    ) -> ServiceFuture<'_, ServiceIdentityReview> {
        Box::pin(async move {
            let timestamp = now();
            let grants = command
                .grants()
                .iter()
                .map(|grant| parse_capability_review(grant, command.workspace_id()))
                .collect::<Result<Vec<_>, _>>()?;
            let identity = ServiceIdentity::new(
                command.principal().clone(),
                command.workspace_id(),
                command.actor().clone(),
                command.label(),
                command.enabled(),
                timestamp,
                timestamp,
            )
            .map_err(|error| ServiceError::Conflict(error.to_string()))?;
            self.database
                .upsert_service_identity(&identity, grants.iter().cloned())
                .await
                .map_err(repository_service_error)?;
            Ok(ServiceIdentityReview::new(
                PrincipalSummary::new(identity.principal()),
                identity.workspace_id(),
                PrincipalSummary::new(identity.owner()),
                identity.label(),
                identity.enabled(),
                grants
                    .into_iter()
                    .map(|capability| capability_review(&capability))
                    .collect::<Result<Vec<_>, _>>()?,
                identity.created_at(),
                identity.updated_at(),
            ))
        })
    }

    fn list_jobs(&self, query: JobReviewQuery) -> ServiceFuture<'_, Vec<JobReview>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT job.job_id, job.workspace_id, job.service_provider, job.service_subject,
                        job.owner_provider, job.owner_subject, revision.revision,
                        revision.schedule_kind, revision.schedule_start_at,
                        revision.interval_millis, revision.prompt, revision.data_class,
                        revision.max_model_turns, revision.max_actions, revision.enabled,
                        revision.next_due_at, revision.idempotent, revision.created_at,
                        (SELECT run.state FROM scheduled_job_runs run
                         WHERE run.job_id = job.job_id
                           AND run.revision = revision.revision
                         ORDER BY run.scheduled_for DESC, run.updated_at DESC
                         LIMIT 1) AS last_run_state
                 FROM scheduled_jobs job
                 JOIN (
                    SELECT job_id, MAX(revision) AS revision
                    FROM scheduled_job_revisions
                    GROUP BY job_id
                 ) latest ON latest.job_id = job.job_id
                 JOIN scheduled_job_revisions revision
                   ON revision.job_id = latest.job_id AND revision.revision = latest.revision
                 WHERE job.workspace_id = ?
                 ORDER BY revision.created_at DESC, job.job_id",
            )
            .bind(query.workspace_id().to_string())
            .fetch_all(self.database.pool())
            .await
            .map_err(sql_service_error)?;
            rows.into_iter().map(job_review_from_row).collect()
        })
    }

    fn request_job_action(
        &self,
        command: JobActionCommand,
    ) -> ServiceFuture<'_, AutomationActionRequested> {
        let service = self.clone();
        Box::pin(async move {
            let current = service
                .database
                .latest_scheduled_job_revision(command.job_id())
                .await
                .map_err(repository_service_error)?;
            let kind = if current.is_some() {
                "schedule.job.update"
            } else {
                "schedule.job.create"
            };
            let capability = Capability::new(
                if kind == "schedule.job.create" {
                    CapabilityName::ScheduleCreate
                } else {
                    CapabilityName::ScheduleModify
                },
                ResourceScope::exact("scheduled_job", command.job_id().to_string())
                    .map_err(|error| ServiceError::Conflict(error.to_string()))?,
            );
            let run_id = service
                .request_extension_action(
                    command.workspace_id(),
                    command.actor().clone(),
                    scheduled_job_action_proposal(&command, kind, current.as_ref()),
                    CapabilitySet::new([capability]),
                )
                .await?;
            Ok(AutomationActionRequested::new(run_id))
        })
    }

    fn list_skills(&self, query: SkillReviewQuery) -> ServiceFuture<'_, Vec<SkillReview>> {
        let service = self.clone();
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT skill.skill_id, skill.workspace_id, skill.name, skill.description,
                        version.version, version.source_format, version.source_digest,
                        version.reviewed, version.created_provider, version.created_subject,
                        version.reviewed_provider, version.reviewed_subject,
                        version.created_at, version.reviewed_at,
                        COALESCE(state.enabled, 0) AS enabled
                 FROM agent_skills skill
                 JOIN skill_versions version ON version.skill_id = skill.skill_id
                 LEFT JOIN skill_workspace_state state
                   ON state.workspace_id = skill.workspace_id
                  AND state.skill_id = version.skill_id
                  AND state.version = version.version
                 WHERE skill.workspace_id = ?
                 ORDER BY skill.name, version.version",
            )
            .bind(query.workspace_id().to_string())
            .fetch_all(self.database.pool())
            .await
            .map_err(sql_service_error)?;
            let mut reviews = rows
                .into_iter()
                .map(skill_review_from_row)
                .collect::<Result<Vec<_>, _>>()?;
            let enabled = service
                .database
                .enabled_skill_versions(query.workspace_id())
                .await
                .map_err(repository_service_error)?;
            for review in &mut reviews {
                let required = service
                    .required_skills
                    .contains(&(review.skill_id(), review.version().clone()));
                if !review.enabled() {
                    review.set_load_status(required, "disabled", None);
                    continue;
                }
                let Some(skill) = enabled.iter().find(|skill| {
                    skill.skill_id() == review.skill_id() && skill.version() == review.version()
                }) else {
                    review.set_load_status(required, "excluded", Some("not_eligible"));
                    continue;
                };
                let load = service
                    .load_reviewed_skill_context(query.workspace_id(), skill)
                    .await;
                review.set_load_status(required, load.metadata.status(), load.metadata.reason());
            }
            Ok(reviews)
        })
    }

    fn request_skill_action(
        &self,
        command: SkillActionCommand,
    ) -> ServiceFuture<'_, AutomationActionRequested> {
        let service = self.clone();
        Box::pin(async move {
            if command.kind() != "skill.publish" {
                return Err(ServiceError::Conflict("unsupported skill action".into()));
            }
            let capability = Capability::new(
                CapabilityName::SkillPublish,
                ResourceScope::exact("skill", command.skill_id().to_string())
                    .map_err(|error| ServiceError::Conflict(error.to_string()))?,
            );
            let draft_id = command
                .draft_id()
                .ok_or_else(|| ServiceError::Conflict("skill publish requires a draft".into()))?;
            let draft = service
                .database
                .get_workflow_capture_draft(draft_id)
                .await
                .map_err(repository_service_error)?
                .ok_or(ServiceError::NotFound)?;
            if draft.workspace_id() != command.workspace_id() {
                return Err(ServiceError::NotFound);
            }
            let source_digest = sha256_hex(draft.body().as_bytes());
            let source_run_id = draft
                .body()
                .lines()
                .find_map(|line| line.strip_prefix("source_run_id: "));
            let run_id = service
                .request_extension_action(
                    command.workspace_id(),
                    command.actor().clone(),
                    ActionProposal::new(
                        command.kind(),
                        CanonicalValue::object([
                            ("draft_id", CanonicalValue::from(draft_id.to_string())),
                            (
                                "skill_id",
                                CanonicalValue::from(command.skill_id().to_string()),
                            ),
                            ("version", CanonicalValue::from(command.version().as_str())),
                            ("name", CanonicalValue::from(command.name())),
                            ("description", CanonicalValue::from(command.description())),
                            ("source_format", CanonicalValue::from("markdown")),
                            ("source_digest", CanonicalValue::from(source_digest)),
                            (
                                "source_run_id",
                                source_run_id.map_or(CanonicalValue::Null, CanonicalValue::from),
                            ),
                        ]),
                    ),
                    CapabilitySet::new([capability]),
                )
                .await?;
            Ok(AutomationActionRequested::new(run_id))
        })
    }

    fn list_capture_drafts(
        &self,
        query: SkillReviewQuery,
    ) -> ServiceFuture<'_, Vec<WorkflowCaptureDraftReview>> {
        Box::pin(async move {
            let rows = sqlx::query(
                "SELECT draft_id, workspace_id, title, body, created_provider,
                        created_subject, created_at
                 FROM workflow_capture_drafts
                 WHERE workspace_id = ?
                 ORDER BY created_at DESC, draft_id",
            )
            .bind(query.workspace_id().to_string())
            .fetch_all(self.database.pool())
            .await
            .map_err(sql_service_error)?;
            rows.into_iter()
                .map(capture_draft_review_from_row)
                .collect()
        })
    }

    fn capture_workflow(
        &self,
        command: CaptureWorkflowCommand,
    ) -> ServiceFuture<'_, WorkflowCaptureDraftReview> {
        let service = self.clone();
        Box::pin(async move {
            let draft_id = service
                .capture_workflow_draft(
                    command.workspace_id(),
                    command.run_id(),
                    command.actor().clone(),
                )
                .await?;
            let draft = service
                .database
                .get_workflow_capture_draft(draft_id)
                .await
                .map_err(repository_service_error)?
                .ok_or(ServiceError::NotFound)?;
            Ok(WorkflowCaptureDraftReview::new(
                draft.id(),
                draft.workspace_id(),
                draft.title(),
                draft.body(),
                PrincipalSummary::new(command.actor()),
                now(),
            ))
        })
    }
}

async fn apply_provider_policy_update(
    database: &Database,
    workspace_id: lumen_core::identity::WorkspaceId,
    provider_id: ProviderId,
    enabled: bool,
    workspace_allowed_data_classes: &[DataClass],
) -> Result<(ModelProviderRevision, WorkspaceModelEgressRevision), ServiceError> {
    let provider = database
        .latest_model_provider_revision(provider_id.clone())
        .await
        .map_err(repository_service_error)?
        .ok_or(ServiceError::NotFound)?;
    let provider_revision = ModelProviderRevision::new(
        provider_id.clone(),
        provider.revision() + 1,
        provider.endpoint_class(),
        provider.endpoint().clone(),
        provider.model(),
        enabled,
        provider.priority(),
        provider.credential_secret_ref(),
        provider.allowed_data_classes().iter().copied(),
        now(),
    )
    .map_err(|error| ServiceError::Conflict(error.to_string()))?;
    database
        .append_model_provider_revision(&provider_revision)
        .await
        .map_err(repository_service_error)?;

    let workspace_revision = database
        .latest_workspace_model_egress_revision(workspace_id, provider_id.clone())
        .await
        .map_err(repository_service_error)?
        .as_ref()
        .map_or(1, |current| current.revision() + 1);
    let workspace_policy = WorkspaceModelEgressRevision::new(
        workspace_id,
        provider_id,
        workspace_revision,
        workspace_allowed_data_classes.iter().copied(),
        now(),
    )
    .map_err(|error| ServiceError::Conflict(error.to_string()))?;
    database
        .append_workspace_model_egress_revision(&workspace_policy)
        .await
        .map_err(repository_service_error)?;

    Ok((provider_revision, workspace_policy))
}

fn provider_policy_update_proposal(
    provider_id: &ProviderId,
    enabled: bool,
    workspace_allowed_data_classes: &[DataClass],
) -> ActionProposal {
    ActionProposal::new(
        "egress.provider.policy.update",
        CanonicalValue::object([
            ("provider_id", CanonicalValue::from(provider_id.as_str())),
            ("enabled", CanonicalValue::from(enabled)),
            (
                "workspace_allowed_data_classes",
                CanonicalValue::Array(
                    workspace_allowed_data_classes
                        .iter()
                        .map(|data_class| CanonicalValue::from(data_class.as_str()))
                        .collect(),
                ),
            ),
        ]),
    )
}

fn scheduled_job_action_proposal(
    command: &JobActionCommand,
    kind: &str,
    current: Option<&ScheduledJobRevision>,
) -> ActionProposal {
    let (schedule_kind, run_at, start_at, interval_millis) = match command.schedule() {
        ScheduleSpec::Once { run_at } => (
            CanonicalValue::from("once"),
            Some(canonical_u64(run_at.as_u64())),
            None,
            None,
        ),
        ScheduleSpec::Interval {
            start_at,
            interval_millis,
        } => (
            CanonicalValue::from("interval"),
            None,
            Some(canonical_u64(start_at.as_u64())),
            Some(canonical_u64(interval_millis)),
        ),
    };
    let mut schedule = BTreeMap::from([("kind".to_owned(), schedule_kind)]);
    if let Some(run_at) = run_at {
        schedule.insert("run_at".to_owned(), run_at);
    }
    if let Some(start_at) = start_at {
        schedule.insert("start_at".to_owned(), start_at);
    }
    if let Some(interval_millis) = interval_millis {
        schedule.insert("interval_millis".to_owned(), interval_millis);
    }
    let next_due_at = command.schedule().next_after(
        TimestampMillis::new(now().as_u64().saturating_sub(1)),
        command.enabled(),
    );
    ActionProposal::new(
        kind,
        CanonicalValue::object([
            ("job_id", CanonicalValue::from(command.job_id().to_string())),
            (
                "service_provider",
                CanonicalValue::from(command.service().provider()),
            ),
            (
                "service_subject",
                CanonicalValue::from(command.service().subject()),
            ),
            (
                "owner_provider",
                CanonicalValue::from(command.actor().provider()),
            ),
            (
                "owner_subject",
                CanonicalValue::from(command.actor().subject()),
            ),
            ("schedule", CanonicalValue::Object(schedule)),
            ("prompt", CanonicalValue::from(command.prompt())),
            (
                "data_class",
                CanonicalValue::from(command.data_class().as_str()),
            ),
            (
                "max_model_turns",
                CanonicalValue::from(i64::from(command.max_model_turns())),
            ),
            (
                "max_actions",
                CanonicalValue::from(i64::from(command.max_actions())),
            ),
            ("enabled", CanonicalValue::from(command.enabled())),
            (
                "next_due_at",
                next_due_at.map_or(CanonicalValue::Null, |timestamp| {
                    canonical_u64(timestamp.as_u64())
                }),
            ),
            ("idempotent", CanonicalValue::from(command.idempotent())),
            (
                "previous_revision",
                current.map_or(CanonicalValue::Null, |job| {
                    canonical_u64(job.revision().as_u64())
                }),
            ),
            (
                "previous_enabled",
                current.map_or(CanonicalValue::Null, |job| {
                    CanonicalValue::from(job.enabled())
                }),
            ),
            (
                "target_revision",
                canonical_u64(
                    current
                        .map(|job| job.revision().as_u64().saturating_add(1))
                        .unwrap_or(1),
                ),
            ),
        ]),
    )
}

fn canonical_u64(value: u64) -> CanonicalValue {
    CanonicalValue::from(i64::try_from(value).unwrap_or(i64::MAX))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderPolicyUpdateAction {
    provider_id: ProviderId,
    enabled: bool,
    workspace_allowed_data_classes: Vec<DataClass>,
}

fn parse_provider_policy_update_action(
    arguments: &CanonicalValue,
) -> Result<ProviderPolicyUpdateAction, lumen_core::executor::ExecutorError> {
    let value = serde_json::to_value(arguments)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    let parsed: ProviderPolicyUpdateAction = serde_json::from_value(value)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    if parsed.workspace_allowed_data_classes.is_empty()
        || parsed
            .workspace_allowed_data_classes
            .contains(&DataClass::Secret)
    {
        return Err(lumen_core::executor::ExecutorError::new(
            "provider policy data classes are invalid",
        ));
    }
    Ok(parsed)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledJobAdminAction {
    job_id: String,
    service_provider: String,
    service_subject: String,
    owner_provider: String,
    owner_subject: String,
    schedule: ScheduledJobScheduleAction,
    prompt: String,
    data_class: DataClass,
    max_model_turns: i64,
    max_actions: i64,
    enabled: bool,
    next_due_at: Option<i64>,
    idempotent: bool,
    previous_revision: Option<i64>,
    previous_enabled: Option<bool>,
    target_revision: Option<i64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScheduledJobScheduleAction {
    kind: String,
    run_at: Option<i64>,
    start_at: Option<i64>,
    interval_millis: Option<i64>,
}

struct ParsedScheduledJobAdminAction {
    job_id: JobId,
    service: lumen_core::identity::PrincipalId,
    owner: lumen_core::identity::PrincipalId,
    schedule: ScheduleSpec,
    prompt: String,
    data_class: DataClass,
    max_model_turns: u32,
    max_actions: u32,
    enabled: bool,
    next_due_at: Option<TimestampMillis>,
    idempotent: bool,
    previous_revision: Option<JobRevision>,
    previous_enabled: Option<bool>,
    target_revision: Option<JobRevision>,
}

async fn apply_scheduled_job_action(
    database: &Database,
    kind: &str,
    workspace_id: lumen_core::identity::WorkspaceId,
    parsed: ParsedScheduledJobAdminAction,
) -> Result<(), ServiceError> {
    let latest = database
        .latest_scheduled_job_revision(parsed.job_id)
        .await
        .map_err(repository_service_error)?;
    if let Some(expected_revision) = parsed.previous_revision {
        let Some(current) = latest.as_ref() else {
            return Err(ServiceError::Conflict(
                "scheduled job changed since approval".into(),
            ));
        };
        if current.revision() != expected_revision
            || parsed.previous_enabled != Some(current.enabled())
        {
            return Err(ServiceError::Conflict(
                "scheduled job changed since approval".into(),
            ));
        }
    } else if parsed.previous_enabled.is_some() {
        return Err(ServiceError::Conflict(
            "scheduled job approval state is invalid".into(),
        ));
    }
    let revision = match (kind, latest.as_ref()) {
        ("schedule.job.create", None) => JobRevision::new(1),
        ("schedule.job.create", Some(_)) => {
            return Err(ServiceError::Conflict(
                "scheduled job already exists".into(),
            ));
        }
        ("schedule.job.update" | "schedule.job.enable", Some(current)) => {
            JobRevision::new(current.revision().as_u64().saturating_add(1))
        }
        ("schedule.job.update" | "schedule.job.enable", None) => {
            return Err(ServiceError::NotFound);
        }
        _ => {
            return Err(ServiceError::Conflict(
                "unsupported scheduled job action".into(),
            ));
        }
    }
    .map_err(|error| ServiceError::Conflict(error.to_string()))?;
    if parsed
        .target_revision
        .is_some_and(|expected| expected != revision)
    {
        return Err(ServiceError::Conflict(
            "scheduled job changed since approval".into(),
        ));
    }
    let created_at = now();
    let revision = ScheduledJobRevision::new(
        parsed.job_id,
        revision,
        workspace_id,
        parsed.service,
        parsed.owner,
        parsed.schedule,
        parsed.prompt,
        parsed.data_class,
        parsed.max_model_turns,
        parsed.max_actions,
        parsed.enabled,
        parsed.next_due_at,
        parsed.idempotent,
        created_at,
    )
    .map_err(|error| ServiceError::Conflict(error.to_string()))?;
    database
        .append_scheduled_job_revision(&revision)
        .await
        .map_err(repository_service_error)
}

fn parse_scheduled_job_action(
    arguments: &CanonicalValue,
) -> Result<ParsedScheduledJobAdminAction, lumen_core::executor::ExecutorError> {
    let value = serde_json::to_value(arguments)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    let parsed: ScheduledJobAdminAction = serde_json::from_value(value)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    let job_id = JobId::from_uuid(
        parsed
            .job_id
            .parse()
            .map_err(|_| lumen_core::executor::ExecutorError::new("invalid job ID"))?,
    );
    let service =
        lumen_core::identity::PrincipalId::new(parsed.service_provider, parsed.service_subject)
            .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    let owner = lumen_core::identity::PrincipalId::new(parsed.owner_provider, parsed.owner_subject)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    if parsed.prompt.is_empty() || parsed.prompt.len() > 8192 {
        return Err(lumen_core::executor::ExecutorError::new(
            "scheduled job prompt length is invalid",
        ));
    }
    if parsed.max_model_turns <= 0 || parsed.max_actions <= 0 {
        return Err(lumen_core::executor::ExecutorError::new(
            "scheduled job budgets must be positive",
        ));
    }
    let max_model_turns = u32::try_from(parsed.max_model_turns).map_err(|_| {
        lumen_core::executor::ExecutorError::new("scheduled job model budget is invalid")
    })?;
    let max_actions = u32::try_from(parsed.max_actions).map_err(|_| {
        lumen_core::executor::ExecutorError::new("scheduled job action budget is invalid")
    })?;
    let next_due_at = parsed.next_due_at.map(timestamp_from_i64).transpose()?;
    let previous_revision = parsed
        .previous_revision
        .map(job_revision_from_i64)
        .transpose()?;
    let target_revision = parsed
        .target_revision
        .map(job_revision_from_i64)
        .transpose()?;
    Ok(ParsedScheduledJobAdminAction {
        job_id,
        service,
        owner,
        schedule: parse_scheduled_job_schedule(parsed.schedule)?,
        prompt: parsed.prompt,
        data_class: parsed.data_class,
        max_model_turns,
        max_actions,
        enabled: parsed.enabled,
        next_due_at,
        idempotent: parsed.idempotent,
        previous_revision,
        previous_enabled: parsed.previous_enabled,
        target_revision,
    })
}

fn job_revision_from_i64(value: i64) -> Result<JobRevision, lumen_core::executor::ExecutorError> {
    JobRevision::new(u64::try_from(value).map_err(|_| {
        lumen_core::executor::ExecutorError::new("scheduled job revision is invalid")
    })?)
    .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))
}

fn parse_scheduled_job_schedule(
    schedule: ScheduledJobScheduleAction,
) -> Result<ScheduleSpec, lumen_core::executor::ExecutorError> {
    match schedule.kind.as_str() {
        "once" => {
            let run_at = timestamp_from_i64(schedule.run_at.ok_or_else(|| {
                lumen_core::executor::ExecutorError::new("once schedule requires run_at")
            })?)?;
            if schedule.start_at.is_some() || schedule.interval_millis.is_some() {
                return Err(lumen_core::executor::ExecutorError::new(
                    "once schedule cannot include interval fields",
                ));
            }
            Ok(ScheduleSpec::once(run_at))
        }
        "interval" => {
            let start_at = timestamp_from_i64(schedule.start_at.ok_or_else(|| {
                lumen_core::executor::ExecutorError::new("interval schedule requires start_at")
            })?)?;
            let interval_millis = schedule.interval_millis.ok_or_else(|| {
                lumen_core::executor::ExecutorError::new(
                    "interval schedule requires interval_millis",
                )
            })?;
            if interval_millis <= 0 || schedule.run_at.is_some() {
                return Err(lumen_core::executor::ExecutorError::new(
                    "interval schedule fields are invalid",
                ));
            }
            let interval_millis = u64::try_from(interval_millis).map_err(|_| {
                lumen_core::executor::ExecutorError::new("interval duration is invalid")
            })?;
            ScheduleSpec::interval(start_at, Duration::from_millis(interval_millis))
                .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))
        }
        _ => Err(lumen_core::executor::ExecutorError::new(
            "scheduled job schedule kind is invalid",
        )),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillPublishAction {
    draft_id: String,
    skill_id: String,
    version: String,
    name: String,
    description: String,
    source_format: String,
    source_digest: Option<String>,
    source_run_id: Option<String>,
}

struct ParsedSkillPublishAction {
    draft_id: uuid::Uuid,
    skill_id: SkillId,
    version: SkillVersion,
    name: String,
    description: String,
    source_format: String,
    source_digest: Option<String>,
}

async fn apply_skill_publish_action(
    database: &Database,
    data_root: &Path,
    workspace_id: lumen_core::identity::WorkspaceId,
    actor: lumen_core::identity::PrincipalId,
    parsed: ParsedSkillPublishAction,
) -> Result<SkillId, ServiceError> {
    let draft = database
        .get_workflow_capture_draft(parsed.draft_id)
        .await
        .map_err(repository_service_error)?
        .ok_or(ServiceError::NotFound)?;
    if draft.workspace_id() != workspace_id {
        return Err(ServiceError::NotFound);
    }
    if parsed
        .source_digest
        .as_ref()
        .is_some_and(|expected| expected != &sha256_hex(draft.body().as_bytes()))
    {
        return Err(ServiceError::Conflict(
            "capture draft changed since approval".into(),
        ));
    }
    if database
        .skill_version(workspace_id, parsed.skill_id, &parsed.version)
        .await
        .map_err(repository_service_error)?
        .is_some()
    {
        return Err(ServiceError::Conflict(
            "skill version already published".into(),
        ));
    }
    let digest = sha256_hex(draft.body().as_bytes());
    let created_at = now();
    let record = SkillVersionRecord::new(
        parsed.skill_id,
        parsed.version.clone(),
        workspace_id,
        parsed.name,
        parsed.description,
        parsed.source_format,
        digest,
        true,
        actor.clone(),
        Some(actor),
        created_at,
        Some(created_at),
    )
    .map_err(|error| ServiceError::Conflict(error.to_string()))?;
    let source_path = data_root
        .join("skills")
        .join(parsed.skill_id.to_string())
        .join(format!("{}.md", parsed.version.as_str()));
    tokio::fs::create_dir_all(
        source_path
            .parent()
            .ok_or_else(|| ServiceError::Internal("invalid skill source path".into()))?,
    )
    .await
    .map_err(|error| ServiceError::Internal(error.to_string()))?;
    let mut source_file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&source_path)
        .await
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                ServiceError::Conflict("skill version source already exists".into())
            } else {
                ServiceError::Internal(error.to_string())
            }
        })?;
    let source_write = source_file.write_all(draft.body().as_bytes()).await;
    drop(source_file);
    if let Err(error) = source_write {
        let cleanup = tokio::fs::remove_file(&source_path).await;
        return Err(ServiceError::Internal(match cleanup {
            Ok(()) => error.to_string(),
            Err(cleanup) => format!("{error}; source cleanup failed: {cleanup}"),
        }));
    }
    if let Err(error) = database.publish_skill_version(&record, created_at).await {
        let cleanup = tokio::fs::remove_file(&source_path).await;
        return Err(match cleanup {
            Ok(()) if matches!(error, lumen_db::RepositoryError::SkillMetadataConflict) => {
                ServiceError::Conflict(error.to_string())
            }
            Ok(()) => repository_service_error(error),
            Err(cleanup) => {
                ServiceError::Internal(format!("{error}; source cleanup failed: {cleanup}"))
            }
        });
    }
    Ok(parsed.skill_id)
}

fn parse_skill_publish_action(
    arguments: &CanonicalValue,
) -> Result<ParsedSkillPublishAction, lumen_core::executor::ExecutorError> {
    let value = serde_json::to_value(arguments)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    let parsed: SkillPublishAction = serde_json::from_value(value)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    let draft_id = parsed
        .draft_id
        .parse()
        .map_err(|_| lumen_core::executor::ExecutorError::new("invalid capture draft ID"))?;
    let skill_id = SkillId::from_uuid(
        parsed
            .skill_id
            .parse()
            .map_err(|_| lumen_core::executor::ExecutorError::new("invalid skill ID"))?,
    );
    let version = SkillVersion::parse(parsed.version)
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
    if parsed.name.is_empty()
        || parsed.name.len() > 128
        || parsed.description.is_empty()
        || parsed.description.len() > 2048
        || parsed.source_format != "markdown"
    {
        return Err(lumen_core::executor::ExecutorError::new(
            "skill publish metadata is invalid",
        ));
    }
    if parsed.source_digest.as_ref().is_some_and(|digest| {
        digest.len() != 71
            || !digest.starts_with("sha256:")
            || !digest[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) || parsed
        .source_run_id
        .as_ref()
        .is_some_and(|run_id| uuid::Uuid::parse_str(run_id).is_err())
    {
        return Err(lumen_core::executor::ExecutorError::new(
            "skill publish provenance is invalid",
        ));
    }
    Ok(ParsedSkillPublishAction {
        draft_id,
        skill_id,
        version,
        name: parsed.name,
        description: parsed.description,
        source_format: parsed.source_format,
        source_digest: parsed.source_digest,
    })
}

fn timestamp_from_i64(value: i64) -> Result<TimestampMillis, lumen_core::executor::ExecutorError> {
    Ok(TimestampMillis::new(u64::try_from(value).map_err(
        |_| lumen_core::executor::ExecutorError::new("timestamp cannot be negative"),
    )?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{digest:x}")
}

fn is_scheduled_job_admin_action(kind: &str) -> bool {
    matches!(
        kind,
        "schedule.job.create" | "schedule.job.update" | "schedule.job.enable"
    )
}

fn principal_from_columns(
    row: &sqlx::sqlite::SqliteRow,
    provider_column: &str,
    subject_column: &str,
) -> Result<lumen_core::identity::PrincipalId, ServiceError> {
    lumen_core::identity::PrincipalId::new(
        row.try_get::<String, _>(provider_column)
            .map_err(sql_service_error)?,
        row.try_get::<String, _>(subject_column)
            .map_err(sql_service_error)?,
    )
    .map_err(|error| ServiceError::Internal(error.to_string()))
}

fn timestamp_from_sql_row(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<TimestampMillis, ServiceError> {
    Ok(TimestampMillis::new(
        u64::try_from(row.try_get::<i64, _>(column).map_err(sql_service_error)?)
            .map_err(|_| ServiceError::Internal("invalid timestamp".into()))?,
    ))
}

fn optional_timestamp_from_sql_row(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<Option<TimestampMillis>, ServiceError> {
    row.try_get::<Option<i64>, _>(column)
        .map_err(sql_service_error)?
        .map(|value| {
            u64::try_from(value)
                .map(TimestampMillis::new)
                .map_err(|_| ServiceError::Internal("invalid timestamp".into()))
        })
        .transpose()
}

fn data_class_from_sql(
    row: &sqlx::sqlite::SqliteRow,
    column: &str,
) -> Result<DataClass, ServiceError> {
    match row
        .try_get::<String, _>(column)
        .map_err(sql_service_error)?
        .as_str()
    {
        "public" => Ok(DataClass::Public),
        "workspace" => Ok(DataClass::Workspace),
        "sensitive" => Ok(DataClass::Sensitive),
        _ => Err(ServiceError::Internal("invalid data class".into())),
    }
}

fn schedule_from_sql(row: &sqlx::sqlite::SqliteRow) -> Result<ScheduleSpec, ServiceError> {
    let start_at = timestamp_from_sql_row(row, "schedule_start_at")?;
    match row
        .try_get::<String, _>("schedule_kind")
        .map_err(sql_service_error)?
        .as_str()
    {
        "once" => Ok(ScheduleSpec::once(start_at)),
        "interval" => {
            let interval_millis = u64::try_from(
                row.try_get::<i64, _>("interval_millis")
                    .map_err(sql_service_error)?,
            )
            .map_err(|_| ServiceError::Internal("invalid interval".into()))?;
            ScheduleSpec::interval(start_at, Duration::from_millis(interval_millis))
                .map_err(|error| ServiceError::Internal(error.to_string()))
        }
        _ => Err(ServiceError::Internal("invalid schedule".into())),
    }
}

fn job_review_from_row(row: sqlx::sqlite::SqliteRow) -> Result<JobReview, ServiceError> {
    Ok(JobReview::new(
        JobId::from_uuid(
            row.try_get::<String, _>("job_id")
                .map_err(sql_service_error)?
                .parse()
                .map_err(|_| ServiceError::Internal("invalid job ID".into()))?,
        ),
        JobRevision::new(
            u64::try_from(
                row.try_get::<i64, _>("revision")
                    .map_err(sql_service_error)?,
            )
            .map_err(|_| ServiceError::Internal("invalid job revision".into()))?,
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?,
        lumen_core::identity::WorkspaceId::from_uuid(
            row.try_get::<String, _>("workspace_id")
                .map_err(sql_service_error)?
                .parse()
                .map_err(|_| ServiceError::Internal("invalid workspace ID".into()))?,
        ),
        PrincipalSummary::new(&principal_from_columns(
            &row,
            "service_provider",
            "service_subject",
        )?),
        PrincipalSummary::new(&principal_from_columns(
            &row,
            "owner_provider",
            "owner_subject",
        )?),
        schedule_from_sql(&row)?,
        row.try_get::<String, _>("prompt")
            .map_err(sql_service_error)?,
        data_class_from_sql(&row, "data_class")?,
        u32::try_from(
            row.try_get::<i64, _>("max_model_turns")
                .map_err(sql_service_error)?,
        )
        .map_err(|_| ServiceError::Internal("invalid model turn budget".into()))?,
        u32::try_from(
            row.try_get::<i64, _>("max_actions")
                .map_err(sql_service_error)?,
        )
        .map_err(|_| ServiceError::Internal("invalid action budget".into()))?,
        row.try_get::<i64, _>("enabled")
            .map_err(sql_service_error)?
            == 1,
        optional_timestamp_from_sql_row(&row, "next_due_at")?,
        row.try_get::<i64, _>("idempotent")
            .map_err(sql_service_error)?
            == 1,
        row.try_get::<Option<String>, _>("last_run_state")
            .map_err(sql_service_error)?,
        timestamp_from_sql_row(&row, "created_at")?,
    ))
}

fn skill_review_from_row(row: sqlx::sqlite::SqliteRow) -> Result<SkillReview, ServiceError> {
    let workspace_id = lumen_core::identity::WorkspaceId::from_uuid(
        row.try_get::<String, _>("workspace_id")
            .map_err(sql_service_error)?
            .parse()
            .map_err(|_| ServiceError::Internal("invalid workspace ID".into()))?,
    );
    let reviewed_by = match (
        row.try_get::<Option<String>, _>("reviewed_provider")
            .map_err(sql_service_error)?,
        row.try_get::<Option<String>, _>("reviewed_subject")
            .map_err(sql_service_error)?,
    ) {
        (Some(provider), Some(subject)) => Some(PrincipalSummary::new(
            &lumen_core::identity::PrincipalId::new(provider, subject)
                .map_err(|error| ServiceError::Internal(error.to_string()))?,
        )),
        _ => None,
    };
    Ok(SkillReview::new(
        SkillId::from_uuid(
            row.try_get::<String, _>("skill_id")
                .map_err(sql_service_error)?
                .parse()
                .map_err(|_| ServiceError::Internal("invalid skill ID".into()))?,
        ),
        SkillVersion::parse(
            row.try_get::<String, _>("version")
                .map_err(sql_service_error)?,
        )
        .map_err(|error| ServiceError::Internal(error.to_string()))?,
        workspace_id,
        row.try_get::<String, _>("name")
            .map_err(sql_service_error)?,
        row.try_get::<String, _>("description")
            .map_err(sql_service_error)?,
        row.try_get::<String, _>("source_format")
            .map_err(sql_service_error)?,
        row.try_get::<String, _>("source_digest")
            .map_err(sql_service_error)?,
        row.try_get::<i64, _>("reviewed")
            .map_err(sql_service_error)?
            == 1,
        row.try_get::<i64, _>("enabled")
            .map_err(sql_service_error)?
            == 1,
        PrincipalSummary::new(&principal_from_columns(
            &row,
            "created_provider",
            "created_subject",
        )?),
        reviewed_by,
        timestamp_from_sql_row(&row, "created_at")?,
        optional_timestamp_from_sql_row(&row, "reviewed_at")?,
    ))
}

fn capture_draft_review_from_row(
    row: sqlx::sqlite::SqliteRow,
) -> Result<WorkflowCaptureDraftReview, ServiceError> {
    Ok(WorkflowCaptureDraftReview::new(
        row.try_get::<String, _>("draft_id")
            .map_err(sql_service_error)?
            .parse()
            .map_err(|_| ServiceError::Internal("invalid capture draft ID".into()))?,
        lumen_core::identity::WorkspaceId::from_uuid(
            row.try_get::<String, _>("workspace_id")
                .map_err(sql_service_error)?
                .parse()
                .map_err(|_| ServiceError::Internal("invalid workspace ID".into()))?,
        ),
        row.try_get::<String, _>("title")
            .map_err(sql_service_error)?,
        row.try_get::<String, _>("body")
            .map_err(sql_service_error)?,
        PrincipalSummary::new(&principal_from_columns(
            &row,
            "created_provider",
            "created_subject",
        )?),
        timestamp_from_sql_row(&row, "created_at")?,
    ))
}

fn parse_capability_review(
    value: &CanonicalValue,
    workspace_id: lumen_core::identity::WorkspaceId,
) -> Result<Capability, ServiceError> {
    let CanonicalValue::Object(object) = value else {
        return Err(ServiceError::Conflict(
            "capability grant must be an object".into(),
        ));
    };
    let name = match object.get("name") {
        Some(CanonicalValue::String(value)) => CapabilityName::parse(value)
            .ok_or_else(|| ServiceError::Conflict("invalid capability name".into()))?,
        _ => {
            return Err(ServiceError::Conflict(
                "capability grant requires a name".into(),
            ));
        }
    };
    let scope = match object.get("scope") {
        Some(CanonicalValue::String(scope)) if scope == "workspace" => {
            ResourceScope::workspace(workspace_id)
        }
        Some(CanonicalValue::Object(scope)) => match (
            scope.get("type"),
            scope.get("resource_type"),
            scope.get("value"),
        ) {
            (
                Some(CanonicalValue::String(kind)),
                Some(CanonicalValue::String(resource_type)),
                Some(CanonicalValue::String(resource_value)),
            ) if kind == "exact" => ResourceScope::exact(resource_type, resource_value)
                .map_err(|error| ServiceError::Conflict(error.to_string()))?,
            _ => {
                return Err(ServiceError::Conflict(
                    "unsupported capability grant scope".into(),
                ));
            }
        },
        _ => {
            return Err(ServiceError::Conflict(
                "capability grant requires a scope".into(),
            ));
        }
    };
    Ok(Capability::new(name, scope))
}

fn channel_mapping_review(
    mapping: ChannelIdentityMapping,
) -> Result<ChannelMappingReview, ServiceError> {
    Ok(ChannelMappingReview::new(
        mapping.external().clone(),
        PrincipalSummary::new(mapping.principal()),
        mapping.workspace_id(),
        mapping.allowed(),
        mapping.created_at(),
        mapping.updated_at(),
    ))
}

fn destination_policy_review(
    revision: DestinationRevision,
) -> Result<DestinationPolicyReview, ServiceError> {
    let allowed_data_classes = [
        DataClass::Public,
        DataClass::Workspace,
        DataClass::Sensitive,
    ]
    .into_iter()
    .filter(|data_class| revision.allows(*data_class))
    .collect();
    Ok(DestinationPolicyReview::new(
        revision.destination().clone(),
        revision.revision(),
        revision.enabled(),
        allowed_data_classes,
        revision.created_at(),
    ))
}

fn provider_policy_review(
    provider: ModelProviderRevision,
    workspace_policy: Option<&WorkspaceModelEgressRevision>,
) -> Result<ProviderPolicyReview, ServiceError> {
    let allowed_data_classes = ordered_data_classes()
        .into_iter()
        .filter(|data_class| provider.allows(*data_class))
        .collect();
    let workspace_policy = workspace_policy.map(|policy| {
        WorkspaceModelPolicyReview::new(
            policy.revision(),
            ordered_data_classes()
                .into_iter()
                .filter(|data_class| policy.allows(*data_class))
                .collect(),
            policy.created_at(),
        )
    });
    Ok(ProviderPolicyReview::new(
        provider.provider_id().clone(),
        provider.revision(),
        match provider.endpoint_class() {
            ModelEndpointClass::Local => lumen_core::egress::EndpointClass::Local,
            ModelEndpointClass::Remote => lumen_core::egress::EndpointClass::Remote,
        },
        provider.endpoint().clone(),
        provider.model(),
        provider.enabled(),
        provider.priority(),
        provider.credential_secret_ref().is_some(),
        allowed_data_classes,
        workspace_policy,
        provider.created_at(),
    ))
}

fn ordered_data_classes() -> [DataClass; 3] {
    [
        DataClass::Public,
        DataClass::Workspace,
        DataClass::Sensitive,
    ]
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

    fn model_tools(&self, context: &RunContext) -> Vec<ModelTool> {
        self.inner.model_tools(context)
    }
}

impl ExecutorPort for RedactingExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move {
            let attempt_id = self.approvals.reserve(action).await?;
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
    scheduled_handoff: Option<(OccurrenceKey, uuid::Uuid)>,
    start_disposition: StartDisposition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartDisposition {
    Created,
    ScheduledStartCommitted,
    ResumeApproval,
}

struct ReviewedSkillPrompt {
    prompt: String,
    loaded_skills: Vec<LoadedSkillMetadata>,
    skill_loads: Vec<SkillLoadMetadata>,
}

struct LoadedReviewedSkill {
    rendered: String,
    metadata: LoadedSkillMetadata,
}

struct SkillLoadResult {
    metadata: SkillLoadMetadata,
    loaded: Option<LoadedReviewedSkill>,
}

fn skill_load_value(skill: &SkillLoadMetadata) -> CanonicalValue {
    CanonicalValue::object([
        ("skill_id", CanonicalValue::from(skill.skill_id())),
        ("version", CanonicalValue::from(skill.version())),
        (
            "expected_digest",
            CanonicalValue::from(skill.expected_digest()),
        ),
        ("status", CanonicalValue::from(skill.status())),
        (
            "reason",
            skill
                .reason()
                .map_or(CanonicalValue::Null, CanonicalValue::from),
        ),
        ("required", CanonicalValue::from(skill.required())),
    ])
}

struct StoredRunRequest {
    workspace_id: lumen_core::identity::WorkspaceId,
    actor: lumen_core::identity::PrincipalId,
    prompt: String,
    budget: RunBudget,
    data_class: DataClass,
    model_override: Option<Arc<dyn ModelPort>>,
    capabilities_override: Option<EffectiveCapabilities>,
    job_origin: Option<JobOrigin>,
    scheduled_handoff: Option<(OccurrenceKey, uuid::Uuid)>,
}

struct EgressCheckedModel {
    inner: Arc<dyn ModelPort>,
    database: Database,
    audit: DatabaseAudit,
    workspace_id: lumen_core::identity::WorkspaceId,
    run_id: RunId,
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
                    ("run_id", CanonicalValue::from(self.run_id.to_string())),
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
                    ("run_id", CanonicalValue::from(self.run_id.to_string())),
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

    fn model_tools(&self, context: &RunContext) -> Vec<ModelTool> {
        let mut tools = self.builtin.model_tools(context);
        tools.extend(self.extension.model_tools(context));
        tools
    }
}

struct RoutingExecutor {
    database: Database,
    data_root: Arc<Path>,
    builtin: Arc<dyn ExecutorPort>,
    extension: Arc<dyn ExecutorPort>,
}

impl ExecutorPort for RoutingExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        if action.action().kind().as_str() == "egress.provider.policy.update" {
            return Box::pin(async move {
                let parsed = parse_provider_policy_update_action(action.action().arguments())?;
                let provider_id = parsed.provider_id.clone();
                apply_provider_policy_update(
                    &self.database,
                    action.action().workspace_id(),
                    parsed.provider_id,
                    parsed.enabled,
                    &parsed.workspace_allowed_data_classes,
                )
                .await
                .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
                Ok(ExecutionOutcome::Succeeded(CanonicalValue::object([(
                    "provider_id",
                    CanonicalValue::from(provider_id.as_str()),
                )])))
            });
        }
        if is_scheduled_job_admin_action(action.action().kind().as_str()) {
            return Box::pin(async move {
                let parsed = parse_scheduled_job_action(action.action().arguments())?;
                let job_id = parsed.job_id;
                apply_scheduled_job_action(
                    &self.database,
                    action.action().kind().as_str(),
                    action.action().workspace_id(),
                    parsed,
                )
                .await
                .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
                Ok(ExecutionOutcome::Succeeded(CanonicalValue::object([(
                    "job_id",
                    CanonicalValue::from(job_id.to_string()),
                )])))
            });
        }
        if action.action().kind().as_str() == "skill.publish" {
            return Box::pin(async move {
                let parsed = parse_skill_publish_action(action.action().arguments())?;
                let skill_id = apply_skill_publish_action(
                    &self.database,
                    self.data_root.as_ref(),
                    action.action().workspace_id(),
                    action.action().actor().clone(),
                    parsed,
                )
                .await
                .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
                Ok(ExecutionOutcome::Succeeded(CanonicalValue::object([(
                    "skill_id",
                    CanonicalValue::from(skill_id.to_string()),
                )])))
            });
        }
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
        RunOutcome::RequiredSkillUnavailable {
            skill_id,
            version,
            reason,
        } => (
            "failed",
            "run.failed",
            CanonicalValue::object([
                ("code", CanonicalValue::from("required_skill_unavailable")),
                ("skill_id", CanonicalValue::from(skill_id.clone())),
                ("version", CanonicalValue::from(version.clone())),
                ("reason", CanonicalValue::from(*reason)),
            ]),
        ),
        other => (
            "failed",
            "run.failed",
            CanonicalValue::from(format!("{other:?}")),
        ),
    }
}

const fn scheduled_occurrence_terminal_state(outcome: &RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Completed { .. } => "succeeded",
        RunOutcome::Cancelled => "cancelled",
        RunOutcome::ExecutionUnknown { .. } => "unknown",
        _ => "failed",
    }
}

struct ApprovalRecord {
    workspace_id: lumen_core::identity::WorkspaceId,
    run_id: RunId,
    action: lumen_core::action::ActionEnvelope,
    request: ApprovalRequest,
    attempt_id: Option<ExecutionAttemptId>,
    renewed: bool,
}

struct ApprovalRegistry {
    database: Database,
    ttl: Duration,
    clock: Arc<dyn Clock>,
    records: Mutex<BTreeMap<ApprovalId, ApprovalRecord>>,
    #[cfg(test)]
    reservation_waiting: Arc<Notify>,
}

impl ApprovalRegistry {
    fn new(database: Database, ttl: Duration) -> Self {
        Self::with_clock(database, ttl, Arc::new(SystemClock))
    }

    fn with_clock(database: Database, ttl: Duration, clock: Arc<dyn Clock>) -> Self {
        Self {
            database,
            ttl,
            clock,
            records: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            reservation_waiting: Arc::new(Notify::new()),
        }
    }

    async fn decide(
        &self,
        command: &ApprovalDecisionCommand,
    ) -> Result<(RunId, ApprovalResult), ServiceError> {
        let mut records = self.records.lock().await;
        let record = records
            .get_mut(&command.approval_id())
            .ok_or(ServiceError::NotFound)?;
        if record.workspace_id != command.workspace_id() {
            return Err(ServiceError::NotFound);
        }
        if record.renewed {
            return Err(ServiceError::ApprovalConflict(ApprovalConflict::Stale));
        }
        let now = self.clock.now();
        let mut request = record.request.clone();
        let decision = match command.decision() {
            ApprovalDecision::Grant => request.grant(command.actor().clone(), now),
            ApprovalDecision::Reject => request.reject(command.actor().clone(), now),
        };
        if let Err(error) = decision {
            if request.state() == ApprovalState::Expired {
                self.database
                    .expire_pending_approvals(command.workspace_id(), now)
                    .await
                    .map_err(repository_service_error)?;
                record.request = request;
            }
            return Err(ServiceError::ApprovalConflict(approval_conflict(error)));
        }
        let persisted = match command.decision() {
            ApprovalDecision::Grant => self
                .database
                .update_approval_decision(command.workspace_id(), &request)
                .await
                .map(|_| ()),
            ApprovalDecision::Reject => self
                .database
                .reject_approval_and_action(command.workspace_id(), &request)
                .await
                .and_then(|persisted_run_id| {
                    if persisted_run_id == record.run_id {
                        Ok(())
                    } else {
                        Err(lumen_db::RepositoryError::ApprovalDecisionConflict)
                    }
                }),
        };
        persisted.map_err(|error| match error {
            lumen_db::RepositoryError::ApprovalStale => {
                ServiceError::ApprovalConflict(ApprovalConflict::Stale)
            }
            lumen_db::RepositoryError::ApprovalActionChanged => {
                ServiceError::ApprovalConflict(ApprovalConflict::ActionChanged)
            }
            lumen_db::RepositoryError::ApprovalExpired => {
                ServiceError::ApprovalConflict(ApprovalConflict::Expired)
            }
            lumen_db::RepositoryError::ApprovalConsumed => {
                ServiceError::ApprovalConflict(ApprovalConflict::Consumed)
            }
            lumen_db::RepositoryError::ApprovalDecisionConflict => {
                ServiceError::ApprovalConflict(ApprovalConflict::AlreadyDecided)
            }
            error => repository_service_error(error),
        })?;
        record.request = request;
        Ok((
            record.run_id,
            ApprovalResult::new(command.approval_id(), command.decision()),
        ))
    }

    async fn renew(
        &self,
        workspace_id: lumen_core::identity::WorkspaceId,
        approval_id: ApprovalId,
        expected_run_id: RunId,
    ) -> Result<(RunId, ApprovalId), ServiceError> {
        let mut records = self.records.lock().await;
        let now = self.clock.now();
        let (run_id, action, policy_version) = {
            let record = records
                .get_mut(&approval_id)
                .ok_or(ServiceError::NotFound)?;
            if record.workspace_id != workspace_id {
                return Err(ServiceError::NotFound);
            }
            if record.run_id != expected_run_id {
                return Err(ServiceError::ApprovalConflict(ApprovalConflict::Stale));
            }
            if record.renewed {
                return Err(ServiceError::ApprovalConflict(ApprovalConflict::Stale));
            }
            if record.request.expire(now) {
                self.database
                    .expire_pending_approvals(workspace_id, now)
                    .await
                    .map_err(repository_service_error)?;
            }
            match record.request.state() {
                ApprovalState::Expired => {}
                ApprovalState::Pending => {
                    return Err(ServiceError::ApprovalConflict(
                        ApprovalConflict::NotRenewable,
                    ));
                }
                ApprovalState::Granted | ApprovalState::Rejected => {
                    return Err(ServiceError::ApprovalConflict(
                        ApprovalConflict::AlreadyDecided,
                    ));
                }
                ApprovalState::Consumed => {
                    return Err(ServiceError::ApprovalConflict(ApprovalConflict::Consumed));
                }
                ApprovalState::Invalidated => {
                    return Err(ServiceError::ApprovalConflict(ApprovalConflict::Stale));
                }
            }
            (
                record.run_id,
                record.action.clone(),
                record.request.policy_version().clone(),
            )
        };
        let replacement = ApprovalId::new();
        let ttl_millis = u64::try_from(self.ttl.as_millis()).unwrap_or(u64::MAX);
        let request = ApprovalRequest::new(
            replacement,
            action.fingerprint(),
            policy_version,
            now,
            TimestampMillis::new(now.as_u64().saturating_add(ttl_millis)),
        )
        .map_err(|error| ServiceError::ApprovalConflict(approval_conflict(error)))?;
        self.database
            .insert_approval(&request)
            .await
            .map_err(repository_service_error)?;
        records
            .get_mut(&approval_id)
            .expect("renewed approval remains registered")
            .renewed = true;
        records.insert(
            replacement,
            ApprovalRecord {
                workspace_id,
                run_id,
                action,
                request,
                attempt_id: None,
                renewed: false,
            },
        );
        Ok((run_id, replacement))
    }

    async fn reserve(
        &self,
        action: &AuthorizedAction,
    ) -> Result<ExecutionAttemptId, lumen_core::executor::ExecutorError> {
        match action.authorization() {
            DispatchAuthorization::PolicyAllowed => {
                let attempt_id = ExecutionAttemptId::new();
                self.database
                    .reserve_allowed_execution(attempt_id, action.action().id(), self.clock.now())
                    .await
                    .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
                Ok(attempt_id)
            }
            DispatchAuthorization::Approved { approval_id } => {
                self.reserve_approved(action.action(), approval_id).await
            }
        }
    }

    async fn reserve_approved(
        &self,
        action: &ActionEnvelope,
        approval_id: ApprovalId,
    ) -> Result<ExecutionAttemptId, lumen_core::executor::ExecutorError> {
        let attempt_id = ExecutionAttemptId::new();
        #[cfg(test)]
        self.reservation_waiting.notify_waiters();
        let mut records = self.records.lock().await;
        let record = records.get_mut(&approval_id).ok_or_else(|| {
            lumen_core::executor::ExecutorError::new("approved action is not registered")
        })?;
        if record.action.fingerprint() != action.fingerprint() || record.attempt_id.is_some() {
            return Err(lumen_core::executor::ExecutorError::new(
                "approved action cannot be reserved",
            ));
        }
        let mut validated_request = record.request.clone();
        let policy_version = validated_request.policy_version().clone();
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            action,
            &policy_version,
            Some(&mut validated_request),
            self.clock.now(),
        )
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
        let clock = Arc::clone(&self.clock);
        let reserved_at = self
            .database
            .reserve_execution_with_clock(
                DispatchReservation::new(
                    attempt_id,
                    action.id(),
                    approval_id,
                    action.fingerprint(),
                    record.request.policy_version().clone(),
                    self.clock.now(),
                ),
                move || clock.now(),
            )
            .await
            .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
        let mut consumed_request = record.request.clone();
        authorize_dispatch(
            &PolicyDecision::RequireApproval,
            action,
            &policy_version,
            Some(&mut consumed_request),
            reserved_at,
        )
        .map_err(|error| lumen_core::executor::ExecutorError::new(error.to_string()))?;
        record.request = consumed_request;
        record.attempt_id = Some(attempt_id);
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
            if let Some((approval_id, record)) = records.iter_mut().find(|(_, record)| {
                !record.renewed && record.action.fingerprint() == action.fingerprint()
            }) {
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
                    renewed: false,
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

    fn deny<'a>(
        &'a self,
        action: &'a ActionEnvelope,
        _reason: &'a lumen_core::policy::DenialReason,
        now: TimestampMillis,
    ) -> ActionFuture<'a> {
        Box::pin(async move {
            self.0
                .mark_action_denied(action.id(), now)
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

fn approval_conflict(error: ApprovalError) -> ApprovalConflict {
    match error {
        ApprovalError::Expired => ApprovalConflict::Expired,
        ApprovalError::AlreadyGranted | ApprovalError::Rejected => ApprovalConflict::AlreadyDecided,
        ApprovalError::AlreadyConsumed => ApprovalConflict::Consumed,
        ApprovalError::ActionFingerprintMismatch => ApprovalConflict::ActionChanged,
        ApprovalError::PolicyVersionMismatch
        | ApprovalError::Invalidated
        | ApprovalError::InvalidDecisionTime
        | ApprovalError::InvalidTimeRange
        | ApprovalError::NotGranted => ApprovalConflict::Stale,
    }
}

pub(crate) fn now() -> TimestampMillis {
    SystemClock.now()
}

fn scheduled_lease_expiry(timestamp: TimestampMillis) -> TimestampMillis {
    TimestampMillis::new(timestamp.as_u64().saturating_add(30_000))
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
    use crate::config::{Config, toml_string};

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
path = {}

[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
            model.uri(),
            toml_string(workspace.to_string_lossy().into_owned())
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
