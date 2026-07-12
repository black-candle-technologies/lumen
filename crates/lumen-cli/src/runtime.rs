use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::{ApprovalId, ApprovalRequest, ApprovalState, ExecutionAttemptId, TimestampMillis},
    audit::AuditEvent,
    capability::{Capability, CapabilityName, CapabilitySet, EffectiveCapabilities, ResourceScope},
    executor::ExecutorPort,
    model::ModelPort,
    policy::{Policy, PolicyVersion},
    run::{
        ActionNormalizer, ApprovalFuture, ApprovalPort, ApprovalPortError, ApprovalResolution,
        AuditFuture, AuditPort, AuditPortError, RunBudget, RunContext, RunOrchestrator, RunOutcome,
        RunState,
    },
};
use lumen_db::{Database, DispatchReservation};
use lumen_integrations::{
    filesystem::WorkspaceReader,
    openai_compatible::{EndpointPolicy, OpenAiCompatibleClient, OpenAiCompatibleConfig},
    process::{BuiltinActionNormalizer, BuiltinExecutor, ProcessExecutor},
    sandbox::SandboxBackend,
};
use lumen_server::{
    ApprovalDecision, ApprovalDecisionCommand, ApprovalResult, AuditEntry, AuditQuery,
    CreateRunCommand, EventBroker, RunCreated, RuntimeService, ServiceError, ServiceFuture,
};
use tokio::sync::Mutex;

use crate::{CliError, config::Config};

#[derive(Clone)]
pub(crate) struct LocalRuntimeService {
    model: Arc<dyn ModelPort>,
    normalizer: Arc<dyn ActionNormalizer>,
    executor: Arc<dyn ExecutorPort>,
    approvals: Arc<ApprovalRegistry>,
    audit: Arc<DatabaseAudit>,
    database: Database,
    events: EventBroker,
    policy: Policy,
    policy_version: PolicyVersion,
    capabilities: EffectiveCapabilities,
    budget: RunBudget,
    runs: Arc<Mutex<BTreeMap<RunId, StoredRun>>>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl LocalRuntimeService {
    pub(crate) fn build(
        config: &Config,
        database: Database,
        events: EventBroker,
        sandbox: Arc<dyn SandboxBackend>,
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
        let process = ProcessExecutor::new(
            &workspace,
            allowed_programs.clone(),
            config.process.allowed_environment.clone(),
            Duration::from_secs(config.process.timeout_seconds),
            config.process.max_output_bytes,
            sandbox,
        )
        .map_err(|error| CliError::Runtime(error.to_string()))?;
        let filesystem = WorkspaceReader::new(&workspace, config.runtime.file_read_limit_bytes)
            .map_err(|error| CliError::Runtime(error.to_string()))?;
        let executor = BuiltinExecutor::new(filesystem, process);
        let normalizer = BuiltinActionNormalizer::new(
            lumen_core::identity::ComponentId::new("builtin.tools").expect("static component ID"),
        );
        let mut grants = vec![Capability::new(
            CapabilityName::FsRead,
            ResourceScope::workspace(config.workspace_id()),
        )];
        for program in allowed_programs {
            let canonical = std::fs::canonicalize(program)?;
            grants.push(Capability::new(
                CapabilityName::ProcessSpawn,
                ResourceScope::exact("executable", canonical.to_string_lossy())
                    .map_err(|error| CliError::Runtime(error.to_string()))?,
            ));
        }
        let approvals = Arc::new(ApprovalRegistry::new(
            database.clone(),
            Duration::from_secs(config.runtime.approval_ttl_seconds),
        ));
        Ok(Self {
            model: Arc::new(model),
            normalizer: Arc::new(normalizer),
            executor: Arc::new(executor),
            approvals,
            audit: Arc::new(DatabaseAudit(database.clone())),
            database,
            events,
            policy: Policy::default(),
            policy_version: PolicyVersion::new("local-policy-v1").expect("static policy version"),
            capabilities: EffectiveCapabilities::new([CapabilitySet::new(grants)]),
            budget: RunBudget::new(config.runtime.max_model_turns, config.runtime.max_actions),
            runs: Arc::new(Mutex::new(BTreeMap::new())),
            tasks: Arc::new(Mutex::new(Vec::new())),
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
        let orchestrator = RunOrchestrator::new(
            self.model.as_ref(),
            self.normalizer.as_ref(),
            self.executor.as_ref(),
            self.approvals.as_ref(),
            self.audit.as_ref(),
            self.policy.clone(),
            self.policy_version.clone(),
        );
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
                let (state, kind, payload) = terminal_event(&outcome);
                let timestamp = now();
                let _ = self
                    .database
                    .update_run_state(run_id, state, Some(timestamp))
                    .await;
                let _ = self
                    .events
                    .publish(stored.workspace_id, run_id, kind, payload);
            }
            Err(error) => {
                let timestamp = now();
                let _ = self
                    .database
                    .update_run_state(run_id, "failed", Some(timestamp))
                    .await;
                let _ = self.events.publish(
                    stored.workspace_id,
                    run_id,
                    "run.failed",
                    CanonicalValue::from(error.to_string()),
                );
            }
        }
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
    reserved: bool,
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
                    ApprovalState::Granted if !record.reserved => {
                        self.database
                            .reserve_execution(DispatchReservation::new(
                                ExecutionAttemptId::new(),
                                action.id(),
                                *approval_id,
                                action.fingerprint(),
                                policy_version.clone(),
                                now,
                            ))
                            .await
                            .map_err(|error| ApprovalPortError::new(error.to_string()))?;
                        record.reserved = true;
                        Ok(ApprovalResolution::Granted(record.request.clone()))
                    }
                    ApprovalState::Granted => Err(ApprovalPortError::new(
                        "approval already has an execution reservation",
                    )),
                    state => Err(ApprovalPortError::new(format!(
                        "approval cannot be resolved from state {state:?}"
                    ))),
                };
            }

            self.database
                .insert_action(action, now)
                .await
                .map_err(|error| ApprovalPortError::new(error.to_string()))?;
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
                    reserved: false,
                },
            );
            Ok(ApprovalResolution::Pending(approval_id))
        })
    }
}

struct DatabaseAudit(Database);

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
mod tests {
    use std::{sync::Arc, time::Duration};

    use lumen_core::{audit::AuditEventKind, identity::PrincipalId};
    use lumen_db::Database;
    use lumen_integrations::sandbox::{
        SandboxBackend, SandboxError, SandboxFuture, SandboxReport, SandboxRequest, SandboxStrength,
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
        let service = LocalRuntimeService::build(
            &config,
            database.clone(),
            EventBroker::new(64),
            Arc::new(EnforcedSandbox),
        )
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
