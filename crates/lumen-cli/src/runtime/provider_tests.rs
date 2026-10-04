use super::*;
use crate::{
    Cli, Command, CommandOutput, execute_with_secret_store,
    provider::{ProviderCommand, ProviderCredentialCommand},
};
use lumen_core::{
    identity::WorkspaceId,
    model::{ModelMessage, ModelRole},
    provider::ModelProfileId,
    secret::SecretRefId,
};
use lumen_integrations::secrets::{InMemorySecretStore, SecretStoreError, SecretStoreFuture};
use lumen_server::{CreateRunCommand, RuntimeService};
use serde_json::json;
use std::sync::atomic::AtomicUsize;
#[path = "../../../lumen-integrations/tests/common/mod.rs"]
mod tls;

const KEY: &str = "sentinel-provider-key";
#[path = "dispatch_tests.rs"]
mod dispatch_regressions;
#[tokio::test]
async fn real_registration_persists_explicit_policy_and_catalog_visibility() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public"]))
        .await
        .unwrap();
    let db = f.db().await;
    let catalog = lumen_control_plane::DatabaseCandidateCatalog::new(
        db.clone(),
        Vec::new(),
        lumen_core::worker::WorkerRunBudget::new(1, 1, 1000, 1024).unwrap(),
    );
    let (profiles, policies) = catalog.catalog(f.config.workspace_id()).await.unwrap();
    assert_eq!(profiles.len(), 1);
    assert_eq!(policies.len(), 1);
    let p = &policies[0];
    assert_eq!(p.workspace_id(), f.config.workspace_id());
    assert_eq!(p.model_profile_id(), profiles[0].id());
    assert_eq!(p.model_profile_revision(), profiles[0].revision());
    assert_eq!(p.model_trust_zone(), profiles[0].trust_zone());
    assert_eq!(p.allowed_data_classes(), &[DataClass::Public].into());
    assert_eq!(
        p.allowed_compartments(),
        &[lumen_core::context::CompartmentId::parse("engineering").unwrap()].into()
    );
    assert!(p.allow_uncompartmented());
    db.close().await;
}

#[tokio::test]
async fn real_registration_policy_failure_leaves_no_bundle() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    let db = f.db().await;
    sqlx::query("CREATE TRIGGER fail_policy BEFORE INSERT ON model_data_policy_revisions BEGIN SELECT RAISE(ABORT,'injected'); END").execute(db.pool()).await.unwrap();
    db.close().await;
    assert!(
        f.register("openai_compatible", json!(["public"]))
            .await
            .is_err()
    );
    let db = f.db().await;
    assert!(db.list_latest_model_profiles().await.unwrap().is_empty());
    assert!(db.list_latest_provider_configs().await.unwrap().is_empty());
    assert!(
        db.latest_model_data_policy(
            f.config.workspace_id(),
            &ModelProfileId::parse("default-remote").unwrap()
        )
        .await
        .unwrap()
        .is_none()
    );
    db.verify_audit_chain().await.unwrap();
    db.close().await;
}
struct CountingStore {
    inner: InMemorySecretStore,
    reads: AtomicUsize,
    fail_put: AtomicBool,
    fail_delete: AtomicBool,
}
impl CountingStore {
    fn new() -> Self {
        Self {
            inner: InMemorySecretStore::new(),
            reads: AtomicUsize::new(0),
            fail_put: AtomicBool::new(false),
            fail_delete: AtomicBool::new(false),
        }
    }
}
impl SecretStore for CountingStore {
    fn put<'a>(&'a self, account: &'a str, value: Vec<u8>) -> SecretStoreFuture<'a, ()> {
        Box::pin(async move {
            if self.fail_put.load(Ordering::SeqCst) {
                return Err(SecretStoreError::Backend(KEY.into()));
            }
            self.inner.put(account, value).await
        })
    }
    fn resolve<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, Vec<u8>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.inner.resolve(account)
    }
    fn delete<'a>(&'a self, account: &'a str) -> SecretStoreFuture<'a, ()> {
        Box::pin(async move {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(SecretStoreError::Backend(KEY.into()));
            }
            self.inner.delete(account).await
        })
    }
}
struct Fixture {
    dir: tempfile::TempDir,
    config: Config,
    config_path: std::path::PathBuf,
    server: tls::TlsServer,
    store: Arc<CountingStore>,
    outputs: Vec<String>,
    credential: Option<SecretRefId>,
}
impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let server = tls::TlsServer::new().await;
        std::fs::create_dir(dir.path().join("workspace")).unwrap();
        let config_path = dir.path().join("lumen.toml");
        let text = format!(
            r#"[database]
path={}
[model]
allow_remote=true
streaming=false
timeout_seconds=2
[model.registry_profile]
id="default-remote"
revision=1
[runtime]
data_directory={}
[workspace]
id="26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name="Default"
path={}
[bootstrap_admin]
provider="local"
subject="operator"
"#,
            crate::config::toml_string(
                dir.path().join("db.sqlite3").to_string_lossy().into_owned()
            ),
            crate::config::toml_string(dir.path().join("runtime").to_string_lossy().into_owned()),
            crate::config::toml_string(dir.path().join("workspace").to_string_lossy().into_owned())
        );
        std::fs::write(&config_path, &text).unwrap();
        let config = Config::parse(&text).unwrap();
        Self {
            dir,
            config,
            config_path,
            server,
            store: Arc::new(CountingStore::new()),
            outputs: Vec::new(),
            credential: None,
        }
    }
    async fn command(
        &mut self,
        command: ProviderCommand,
        input: Option<Vec<u8>>,
    ) -> Result<CommandOutput, CliError> {
        let output = execute_with_secret_store(
            Cli {
                config: self.config_path.clone(),
                command: Command::Provider { command },
            },
            self.store.clone(),
            input,
        )
        .await?;
        let rendered = output.render();
        assert!(!rendered.contains(KEY));
        assert!(!format!("{output:?}").contains(KEY));
        self.outputs.push(rendered);
        Ok(output)
    }
    async fn create(&mut self, kind: &str) -> Result<SecretRefId, CliError> {
        let metadata = self.dir.path().join("credential.json");
        std::fs::write(&metadata,json!({"provider_id":"primary","kind":kind,"endpoint":self.server.endpoint,"label":"primary"}).to_string()).unwrap();
        match self
            .command(
                ProviderCommand::Credential {
                    command: ProviderCredentialCommand::Create {
                        metadata,
                        stdin: true,
                    },
                },
                Some(format!("{KEY}\r\n").into_bytes()),
            )
            .await?
        {
            CommandOutput::ProviderCredentialCreated(reference) => {
                self.credential = Some(reference.id);
                Ok(reference.id)
            }
            _ => panic!("expected reference"),
        }
    }
    async fn register(
        &mut self,
        kind: &str,
        classes: serde_json::Value,
    ) -> Result<CommandOutput, CliError> {
        let file = self.dir.path().join("provider.json");
        std::fs::write(&file,json!({"provider_id":"primary","kind":kind,"endpoint":self.server.endpoint,"credential_secret_ref":self.credential.unwrap(),"enabled":true,"expected":{"provider":0,"profile":0,"egress":0,"workspace_policy":0},"allowed_data_classes":["public","workspace"],"workspace_allowed_data_classes":classes,"model_data_policy":{"allowed_data_classes":["public"],"allowed_compartments":["engineering"],"allow_uncompartmented":true},"profile":{"id":"default-remote","model":"registered-model","enabled":true,"capabilities":["text","tool_calling"],"context_window_tokens":32768,"concurrency_limit":1,"priority":0}}).to_string()).unwrap();
        self.command(ProviderCommand::Register { file }, None).await
    }
    async fn db(&self) -> Database {
        Database::connect(&self.config.database.path).await.unwrap()
    }
    async fn start(&self) -> LocalRuntimeService {
        let db = self.db().await;
        let mut service = LocalRuntimeService::build_with_secret_store(
            &self.config,
            db.clone(),
            EventBroker::new(128),
            Arc::new(super::security_tests::RecordingSandbox::new()),
            Vec::new(),
            self.store.clone(),
        )
        .await
        .unwrap();
        let factory = Arc::new(
            DatabaseProviderFactory::new(db, self.store.clone(), service.redactor.clone())
                .with_http_client(self.server.client.clone()),
        );
        if let ConfiguredModel::Registry {
            factory: current, ..
        } = &mut service.model
        {
            *current = factory.clone();
        } else {
            panic!("registered model required")
        }
        service.provider_factory = factory;
        service
    }
    async fn no_leaks(&self) {
        let db = self.db().await;
        db.verify_audit_chain().await.unwrap();
        let audits = db
            .list_audit_records(self.config.workspace_id(), 0, 500)
            .await
            .unwrap();
        assert!(!format!("{audits:?}").contains(KEY));
        for file in [
            self.config.database.path.clone(),
            self.config.database.path.with_extension("sqlite3-wal"),
        ] {
            if let Ok(bytes) = std::fs::read(file) {
                assert!(!bytes.windows(KEY.len()).any(|b| b == KEY.as_bytes()));
            }
        }
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM secret_references")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            0
        );
    }
}
fn input(class: DataClass) -> ModelInput {
    ModelInput::new(vec![ModelMessage::new(ModelRole::User, "hello".into())]).with_data_class(class)
}
async fn wait_phase(service: &LocalRuntimeService, run_id: RunId, phase: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let current = service
                .database
                .get_run_lifecycle(
                    WorkspaceId::from_uuid(
                        uuid::Uuid::parse_str("26db5a31-94f0-4e92-a9c9-4cdf19d71c31").unwrap(),
                    ),
                    run_id,
                )
                .await
                .unwrap()
                .unwrap();
            let state: String = sqlx::query_scalar("SELECT state FROM agent_runs WHERE id=?")
                .bind(run_id.to_string())
                .fetch_one(service.database.pool())
                .await
                .unwrap();
            if state == phase {
                break;
            }
            assert!(state != "failed", "run failed: {current:?}");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn registered_cli_restart_normal_runtime_all_three_protocols() {
    for kind in ["openai", "anthropic", "openai_compatible"] {
        let mut f = Fixture::new().await;
        f.create(kind).await.unwrap();
        f.register(kind, json!(["public", "workspace"]))
            .await
            .unwrap();
        f.command(ProviderCommand::List, None).await.unwrap();
        f.command(
            ProviderCommand::Show {
                id: "primary".into(),
            },
            None,
        )
        .await
        .unwrap();
        f.command(
            ProviderCommand::Credential {
                command: ProviderCredentialCommand::List,
            },
            None,
        )
        .await
        .unwrap();
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
        for _ in 0..2 {
            let body = match kind {
                "openai" => {
                    json!({"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":"hello"}]}]})
                }
                "anthropic" => {
                    json!({"stop_reason":"end_turn","content":[{"type":"text","text":"hello"}]})
                }
                _ => json!({"choices":[{"finish_reason":"stop","message":{"content":"hello"}}]}),
            };
            f.server
                .replies
                .lock()
                .await
                .push_back(tls::Reply::json(body));
            let service = f.start().await;
            assert_eq!(
                service
                    .model_readiness(f.config.workspace_id())
                    .await
                    .unwrap(),
                "remote_not_probed"
            );
            let run = service
                .create_run(CreateRunCommand::new(
                    f.config.workspace_id(),
                    f.config.bootstrap_principal(),
                    "say hello".into(),
                ))
                .await
                .unwrap();
            wait_phase(&service, run.run_id(), "completed").await;
            service.shutdown().await;
        }
        let requests = f.server.requests.lock().await;
        assert_eq!(requests.len(), 2);
        let path = match kind {
            "openai" => "responses",
            "anthropic" => "messages",
            _ => "chat/completions",
        };
        for request in requests.iter() {
            assert!(request.starts_with(&format!("POST /gateway/v1/{path} ")));
            assert!(request.contains("registered-model"));
            let lowered = request.to_lowercase();
            if kind == "anthropic" {
                assert!(lowered.contains(&format!("x-api-key: {KEY}")));
                assert!(lowered.contains("anthropic-version: 2023-06-01"));
            } else {
                assert!(lowered.contains(&format!("authorization: bearer {KEY}")));
            }
            assert!(!request.split("\r\n\r\n").nth(1).unwrap().contains(KEY));
        }
        drop(requests);
        f.no_leaks().await;
    }
}
#[tokio::test]
async fn policy_binding_planner_workspace_secret_and_staleness_before_key_use() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public"]))
        .await
        .unwrap();
    let service = f.start().await;
    for (workspace, class) in [
        (f.config.workspace_id(), DataClass::Workspace),
        (f.config.workspace_id(), DataClass::Secret),
        (WorkspaceId::new(), DataClass::Public),
    ] {
        assert!(
            service
                .planner_model(workspace)
                .generate(input(class))
                .await
                .is_err()
        );
    }
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
    assert!(f.server.requests.lock().await.is_empty());
    assert_eq!(
        service
            .planner_model(f.config.workspace_id())
            .generate(input(DataClass::Public))
            .await
            .unwrap(),
        lumen_core::model::ModelOutput::FinalText("hello".into())
    );
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
    service
        .database
        .set_provider_credential_state(
            f.config.workspace_id(),
            f.credential.unwrap(),
            false,
            &f.config.bootstrap_principal(),
            now(),
        )
        .await
        .unwrap();
    assert!(
        service
            .planner_model(f.config.workspace_id())
            .generate(input(DataClass::Public))
            .await
            .is_err()
    );
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
    assert_eq!(
        service
            .model_readiness(f.config.workspace_id())
            .await
            .unwrap(),
        "unavailable"
    );
    service.shutdown().await;
}
#[tokio::test]
async fn provider_b_permission_cannot_authorize_selected_a() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public"]))
        .await
        .unwrap();
    let db = f.db().await;
    let other = ProviderId::parse("b").unwrap();
    db.append_model_provider_revision(
        &ModelProviderRevision::new(
            other.clone(),
            1,
            ModelEndpointClass::Remote,
            lumen_core::egress::DestinationScope::parse("https://b.test/").unwrap(),
            "other",
            true,
            0,
            None,
            [DataClass::Workspace],
            now(),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    db.append_workspace_model_egress_revision(
        &WorkspaceModelEgressRevision::new(
            f.config.workspace_id(),
            other,
            1,
            [DataClass::Workspace],
            now(),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let service = f.start().await;
    assert!(
        service
            .planner_model(f.config.workspace_id())
            .generate(input(DataClass::Workspace))
            .await
            .is_err()
    );
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
    assert!(f.server.requests.lock().await.is_empty());
    service.shutdown().await;
}
#[tokio::test]
async fn reflected_key_missing_material_cancel_and_metadata_checks() {
    let mut f = Fixture::new().await;
    let id = f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public", "workspace"]))
        .await
        .unwrap();
    let service = f.start().await;
    f.server.replies.lock().await.push_back(tls::Reply::json(json!({"choices":[{"finish_reason":"stop","message":{"content":format!("reflection {KEY}")}}]})));
    let error = service
        .planner_model(f.config.workspace_id())
        .generate(input(DataClass::Public))
        .await
        .unwrap_err();
    assert!(!error.to_string().contains(KEY));
    f.store
        .inner
        .delete(&format!("provider:{}:{id}", f.config.workspace_id()))
        .await
        .unwrap();
    assert!(
        service
            .planner_model(f.config.workspace_id())
            .generate(input(DataClass::Public))
            .await
            .is_err()
    );
    assert_eq!(f.server.requests.lock().await.len(), 1);
    let cancel = CancellationToken::new();
    cancel.cancel();
    let model = service
        .model
        .for_context(f.config.workspace_id(), None, cancel);
    let before = f.store.reads.load(Ordering::SeqCst);
    assert!(model.generate(input(DataClass::Public)).await.is_err());
    assert_eq!(f.store.reads.load(Ordering::SeqCst), before);
    assert_eq!(
        service
            .model_readiness(f.config.workspace_id())
            .await
            .unwrap(),
        "remote_not_probed"
    );
    let health = crate::health::collect(&f.config, &service.database)
        .await
        .unwrap();
    assert!(
        health
            .checks
            .iter()
            .any(|c| c.detail.contains("network not tested"))
    );
    assert_eq!(f.store.reads.load(Ordering::SeqCst), before);
    service.shutdown().await;
    f.no_leaks().await;
}
#[tokio::test]
async fn interrupted_credential_creation_and_revocation_cleanup_fail_closed() {
    let mut f = Fixture::new().await;
    f.store.fail_put.store(true, Ordering::SeqCst);
    let error = f.create("openai_compatible").await.unwrap_err();
    assert!(!error.to_string().contains(KEY));
    let db = f.db().await;
    let pending = db
        .list_provider_credentials(f.config.workspace_id())
        .await
        .unwrap();
    assert_eq!(pending[0].credential_status, "pending");
    f.store.fail_put.store(false, Ordering::SeqCst);
    let id = f.create("openai_compatible").await.unwrap();
    assert_eq!(
        db.list_provider_credentials(f.config.workspace_id())
            .await
            .unwrap()
            .iter()
            .filter(|r| r.credential_status == "revoked")
            .count(),
        1
    );
    f.register("openai_compatible", json!(["public"]))
        .await
        .unwrap();
    f.store.fail_delete.store(true, Ordering::SeqCst);
    let error = f
        .command(
            ProviderCommand::Credential {
                command: ProviderCredentialCommand::Revoke { id },
            },
            None,
        )
        .await
        .unwrap_err();
    assert!(!error.to_string().contains(KEY));
    assert_eq!(
        db.list_provider_credentials(f.config.workspace_id())
            .await
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .unwrap()
            .credential_status,
        "revoked"
    );
    assert!(
        db.registered_model_snapshot(
            f.config.workspace_id(),
            &ModelProfileId::parse("default-remote").unwrap(),
            1
        )
        .await
        .is_err()
    );
    f.store.fail_delete.store(false, Ordering::SeqCst);
    for _ in 0..2 {
        f.command(
            ProviderCommand::Credential {
                command: ProviderCredentialCommand::Revoke { id },
            },
            None,
        )
        .await
        .unwrap();
    }
    f.no_leaks().await;
}
#[tokio::test]
async fn scheduled_runs_use_registered_workspace_provider() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public", "workspace"]))
        .await
        .unwrap();
    let service = f.start().await;
    let principal = lumen_core::identity::PrincipalId::new("service", "scheduled").unwrap();
    let t = TimestampMillis::new(1000);
    service
        .database
        .upsert_service_identity(
            &ServiceIdentity::new(
                principal.clone(),
                f.config.workspace_id(),
                f.config.bootstrap_principal(),
                "scheduled",
                true,
                t,
                t,
            )
            .unwrap(),
            Vec::<Capability>::new(),
        )
        .await
        .unwrap();
    service
        .database
        .append_scheduled_job_revision(
            &ScheduledJobRevision::new(
                JobId::from_uuid(uuid::Uuid::new_v4()),
                JobRevision::new(1).unwrap(),
                f.config.workspace_id(),
                principal,
                f.config.bootstrap_principal(),
                ScheduleSpec::once(t),
                "hello",
                DataClass::Workspace,
                2,
                1,
                true,
                Some(t),
                false,
                t,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let runs = service
        .run_due_scheduled_jobs_once(TimestampMillis::new(2000))
        .await
        .unwrap();
    assert_eq!(runs.len(), 1);
    wait_phase(&service, runs[0], "completed").await;
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
    assert_eq!(f.server.requests.lock().await.len(), 1);
    service.shutdown().await;
}
#[tokio::test]
async fn registered_tool_call_approval_tool_result_and_final_text() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public", "workspace"]))
        .await
        .unwrap();
    f.server.replies.lock().await.push_back(tls::Reply::json(json!({"choices":[{"finish_reason":"tool_calls","message":{"content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"filesystem_write","arguments":"{\"path\":\"result.txt\",\"content\":\"hello\"}"}}]}}]})));
    let service = f.start().await;
    let run = service
        .create_run(CreateRunCommand::new(
            f.config.workspace_id(),
            f.config.bootstrap_principal(),
            "write result".into(),
        ))
        .await
        .unwrap();
    wait_phase(&service, run.run_id(), "awaiting_approval").await;
    let approvals = service
        .database
        .list_pending_approvals(f.config.workspace_id(), now())
        .await
        .unwrap();
    assert_eq!(approvals.len(), 1);
    service
        .decide_approval(ApprovalDecisionCommand::new(
            f.config.workspace_id(),
            approvals[0].approval_id(),
            f.config.bootstrap_principal(),
            ApprovalDecision::Grant,
        ))
        .await
        .unwrap();
    wait_phase(&service, run.run_id(), "completed").await;
    assert_eq!(
        std::fs::read_to_string(f.config.workspace.path.join("result.txt")).unwrap(),
        "hello"
    );
    let requests = f.server.requests.lock().await;
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("tool_call_id"));
    drop(requests);
    service.shutdown().await;
    f.no_leaks().await;
}
#[tokio::test]
async fn worker_projection_gate_precedes_shared_credential_resolution() {
    use lumen_core::{
        context::{
            ContextSource, ContextSourceId, ProjectionId, ProjectionTaskKey, SourceProvenance,
            SourceProvenanceKind, TaskProjection,
        },
        worker::{WorkerAssignment, WorkerRunBudget},
    };
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public", "workspace"]))
        .await
        .unwrap();
    let service = f.start().await;
    let snapshot = service
        .database
        .registered_model_snapshot(
            f.config.workspace_id(),
            &ModelProfileId::parse("default-remote").unwrap(),
            1,
        )
        .await
        .unwrap();
    let policy = service
        .database
        .latest_model_data_policy(f.config.workspace_id(), snapshot.profile.id())
        .await
        .unwrap()
        .unwrap();
    let source = ContextSource::new(
        ContextSourceId::new(),
        f.config.workspace_id(),
        DataClass::Public,
        [],
        SourceProvenance::new(SourceProvenanceKind::UserMessage, "test").unwrap(),
        "projected".into(),
        f.config.bootstrap_principal(),
        now(),
    )
    .unwrap();
    let projection = TaskProjection::build(
        ProjectionId::new(),
        ProjectionTaskKey::parse("task").unwrap(),
        &snapshot.profile,
        &policy,
        vec![source.clone()],
        now(),
    )
    .unwrap();
    service
        .database
        .append_context_source(&source)
        .await
        .unwrap();
    service
        .database
        .insert_task_projection(&projection)
        .await
        .unwrap();
    let assignment = WorkerAssignment::from_stored_parts(
        lumen_core::orchestration::OrchestrationId::new(),
        1,
        lumen_core::orchestration::TaskNodeId::new(),
        f.config.workspace_id(),
        f.config.bootstrap_principal(),
        snapshot.provider.id().clone(),
        snapshot.provider.revision(),
        snapshot.profile.id().clone(),
        snapshot.profile.revision(),
        1,
        projection.id(),
        projection.digest().clone(),
        DataClass::Public,
        "hello".into(),
        BTreeSet::new(),
        BTreeSet::new(),
        WorkerRunBudget::new(2, 1, 1000, 4096).unwrap(),
    )
    .unwrap();
    let materializer = lumen_control_plane::DatabaseWorkerMaterializer::new(
        service.database.clone(),
        service.provider_factory(),
    );
    let sink = Arc::new(CountingUsageSink(AtomicUsize::new(0)));
    let generation = lumen_core::model::ModelGenerationConfig::new(
        lumen_core::model::ReasoningProfile::Fast,
        lumen_core::model::ReasoningWireFormat::None,
        None,
        32,
    )
    .unwrap();
    let worker = lumen_worker_runtime::WorkerMaterializer::materialize(
        &materializer,
        &assignment,
        Some(generation),
        Some(sink.clone()),
        CancellationToken::new(),
    )
    .await
    .unwrap()
    .model;
    assert!(worker.generate(input(DataClass::Workspace)).await.is_err());
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
    assert!(f.server.requests.lock().await.is_empty());
    assert!(worker.generate(input(DataClass::Public)).await.is_ok());
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 1);
    assert_eq!(sink.0.load(Ordering::SeqCst), 1);
    assert!(f.server.requests.lock().await[0].contains("\"max_tokens\":32"));
    service
        .database
        .append_model_provider_revision(
            &ModelProviderRevision::new(
                snapshot.provider.id().clone(),
                2,
                ModelEndpointClass::Remote,
                lumen_core::egress::DestinationScope::parse("https://changed.test/").unwrap(),
                "registered-model",
                true,
                0,
                snapshot.provider.credential_secret_ref(),
                [DataClass::Public],
                now(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    assert!(worker.generate(input(DataClass::Public)).await.is_err());
    assert_eq!(
        f.store.reads.load(Ordering::SeqCst),
        1,
        "changed egress must fail before resolving worker key"
    );
    assert_eq!(f.server.requests.lock().await.len(), 1);
    service.shutdown().await;
}

#[tokio::test]
async fn credential_material_in_metadata_and_busy_owner_fail_before_mutation() {
    let mut f = Fixture::new().await;
    let metadata = f.dir.path().join("credential.json");
    std::fs::write(&metadata,json!({"provider_id":"primary","kind":"openai_compatible","endpoint":f.server.endpoint,"label":KEY}).to_string()).unwrap();
    let command = ProviderCommand::Credential {
        command: ProviderCredentialCommand::Create {
            metadata,
            stdin: true,
        },
    };
    let error = f
        .command(command, Some(KEY.as_bytes().to_vec()))
        .await
        .unwrap_err();
    assert!(!error.to_string().contains(KEY));
    assert!(
        f.db()
            .await
            .list_provider_credentials(f.config.workspace_id())
            .await
            .unwrap()
            .is_empty()
    );
    let _guard = crate::acquire_runtime_ownership(&f.config.database.path).unwrap();
    assert!(f.command(ProviderCommand::List, None).await.is_err());
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
    assert!(f.server.requests.lock().await.is_empty());
    f.no_leaks().await;
}

struct CountingUsageSink(AtomicUsize);
impl lumen_core::provider::ProviderUsageSink for CountingUsageSink {
    fn record<'a>(
        &'a self,
        _: lumen_core::provider::ProviderUsageEvent,
    ) -> lumen_core::provider::ProviderUsageSinkFuture<'a> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

#[tokio::test]
async fn changed_provider_profile_or_egress_mirror_blocks_next_request() {
    use lumen_core::provider::{ModelProfile, ProviderConfig};
    for change in ["provider", "profile", "endpoint", "reference"] {
        let mut f = Fixture::new().await;
        f.create("openai_compatible").await.unwrap();
        f.register("openai_compatible", json!(["public", "workspace"]))
            .await
            .unwrap();
        let service = f.start().await;
        let snapshot = service
            .database
            .registered_model_snapshot(
                f.config.workspace_id(),
                &ModelProfileId::parse("default-remote").unwrap(),
                1,
            )
            .await
            .unwrap();
        match change {
            "provider" => service
                .database
                .append_provider_config(
                    &ProviderConfig::remote(
                        snapshot.provider.id().clone(),
                        2,
                        snapshot.provider.kind(),
                        snapshot.provider.endpoint(),
                        false,
                        f.credential.unwrap(),
                    )
                    .unwrap(),
                    now(),
                )
                .await
                .unwrap(),
            "profile" => service
                .database
                .append_model_profile(
                    &ModelProfile::new(
                        snapshot.profile.id().clone(),
                        2,
                        snapshot.provider.id().clone(),
                        1,
                        snapshot.profile.model_name(),
                        false,
                        snapshot.profile.capabilities().clone(),
                        4096,
                        snapshot.profile.trust_zone(),
                        1,
                        0,
                    )
                    .unwrap(),
                    now(),
                )
                .await
                .unwrap(),
            _ => service
                .database
                .append_model_provider_revision(
                    &ModelProviderRevision::new(
                        snapshot.provider.id().clone(),
                        2,
                        ModelEndpointClass::Remote,
                        lumen_core::egress::DestinationScope::parse(if change == "endpoint" {
                            "https://other.test/"
                        } else {
                            snapshot.provider.endpoint().as_str()
                        })
                        .unwrap(),
                        "registered-model",
                        true,
                        0,
                        if change == "reference" {
                            Some(SecretRefId::new())
                        } else {
                            f.credential
                        },
                        [DataClass::Public, DataClass::Workspace],
                        now(),
                    )
                    .unwrap(),
                )
                .await
                .unwrap(),
        }
        assert!(
            service
                .planner_model(f.config.workspace_id())
                .generate(input(DataClass::Public))
                .await
                .is_err()
        );
        assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
        assert!(f.server.requests.lock().await.is_empty());
        service.shutdown().await;
    }
}

#[tokio::test]
async fn ready_audit_failure_leaves_pending_reference_and_cleans_store() {
    let mut f = Fixture::new().await;
    let db = f.db().await;
    sqlx::raw_sql("CREATE TRIGGER fail_ready BEFORE INSERT ON audit_events WHEN NEW.event_type='provider_credential_created' AND json_extract(NEW.payload_json,'$.state')='ready' BEGIN SELECT RAISE(ABORT,'injected'); END").execute(db.pool()).await.unwrap();
    assert!(f.create("openai_compatible").await.is_err());
    let refs = db
        .list_provider_credentials(f.config.workspace_id())
        .await
        .unwrap();
    assert_eq!(refs.len(), 1);
    assert_eq!(refs[0].credential_status, "pending");
    assert!(matches!(
        f.store
            .inner
            .resolve(&format!(
                "provider:{}:{}",
                f.config.workspace_id(),
                refs[0].id
            ))
            .await,
        Err(SecretStoreError::NotFound)
    ));
    db.verify_audit_chain().await.unwrap();
}

#[tokio::test]
async fn support_bundle_reuses_runtime_observer_without_reading_keyring() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public", "workspace"]))
        .await
        .unwrap();
    let service = f.start().await;
    service
        .planner_model(f.config.workspace_id())
        .generate(input(DataClass::Public))
        .await
        .unwrap();
    let reads = f.store.reads.load(Ordering::SeqCst);
    let out = f.dir.path().join("support");
    crate::support_bundle::export_bundle_with_redactor(
        &f.config,
        &service.database,
        &f.config_path,
        &out,
        false,
        service.redactor.as_ref(),
    )
    .await
    .unwrap();
    for file in std::fs::read_dir(&out).unwrap() {
        let file = file.unwrap();
        if file.file_type().unwrap().is_file() {
            assert!(!std::fs::read_to_string(file.path()).unwrap().contains(KEY));
        }
    }
    assert_eq!(f.store.reads.load(Ordering::SeqCst), reads);
    service.shutdown().await;
}

#[tokio::test]
async fn legacy_remote_startup_requires_explicit_registration() {
    let f = Fixture::new().await;
    let mut config = f.config.clone();
    config.model.registry_profile = None;
    config.model.endpoint = f.server.endpoint.clone();
    config.model.model = "legacy".into();
    let result = LocalRuntimeService::build_with_secret_store(
        &config,
        f.db().await,
        EventBroker::new(128),
        Arc::new(super::security_tests::RecordingSandbox::new()),
        Vec::new(),
        f.store.clone(),
    )
    .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => panic!("legacy remote must not build"),
    };
    assert!(error.to_string().contains("provider register"));
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn local_unkeyed_worker_uses_same_materializer_without_os_reads() {
    use lumen_core::{
        context::{
            ContextSource, ContextSourceId, ModelDataPolicy, ProjectionId, ProjectionTaskKey,
            SourceProvenance, SourceProvenanceKind, TaskProjection,
        },
        provider::{
            LocalRuntimeKind, ModelCapabilities, ModelCapability, ModelProfile, ModelTrustZone,
            ProviderConfig,
        },
        worker::{WorkerAssignment, WorkerRunBudget},
    };
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
    let f = Fixture::new().await;
    let server = MockServer::start().await;
    Mock::given(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"choices":[{"message":{"content":"local result"},"finish_reason":"stop"}]}),
        ))
        .mount(&server)
        .await;
    let db = f.db().await;
    let w = f.config.workspace_id();
    db.bootstrap_workspace(w, "Local", &f.config.bootstrap_principal(), now())
        .await
        .unwrap();
    let p = ProviderConfig::local_openai_compatible(
        ProviderId::parse("local-worker").unwrap(),
        1,
        format!("{}/v1/", server.uri()),
        LocalRuntimeKind::Ollama,
        true,
        None,
    )
    .unwrap();
    let m = ModelProfile::new(
        ModelProfileId::parse("local-worker-text").unwrap(),
        1,
        p.id().clone(),
        1,
        "local-model",
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        4096,
        ModelTrustZone::LocalRestricted,
        1,
        0,
    )
    .unwrap();
    db.append_provider_config(&p, now()).await.unwrap();
    db.append_model_profile(&m, now()).await.unwrap();
    let policy = ModelDataPolicy::new(
        w,
        m.id().clone(),
        1,
        m.trust_zone(),
        1,
        [DataClass::Public],
        [],
        true,
        now(),
    )
    .unwrap();
    db.append_model_data_policy(&policy).await.unwrap();
    let source = ContextSource::new(
        ContextSourceId::new(),
        w,
        DataClass::Public,
        [],
        SourceProvenance::new(SourceProvenanceKind::UserMessage, "local").unwrap(),
        "public local input".into(),
        f.config.bootstrap_principal(),
        now(),
    )
    .unwrap();
    db.append_context_source(&source).await.unwrap();
    let projection = TaskProjection::build(
        ProjectionId::new(),
        ProjectionTaskKey::parse("local-task").unwrap(),
        &m,
        &policy,
        vec![source],
        now(),
    )
    .unwrap();
    db.insert_task_projection(&projection).await.unwrap();
    let assignment = WorkerAssignment::from_stored_parts(
        lumen_core::orchestration::OrchestrationId::new(),
        1,
        lumen_core::orchestration::TaskNodeId::new(),
        w,
        f.config.bootstrap_principal(),
        p.id().clone(),
        1,
        m.id().clone(),
        1,
        1,
        projection.id(),
        projection.digest().clone(),
        DataClass::Public,
        "local prompt".into(),
        BTreeSet::new(),
        BTreeSet::new(),
        WorkerRunBudget::new(2, 1, 1000, 4096).unwrap(),
    )
    .unwrap();
    let factory = Arc::new(DatabaseProviderFactory::new(
        db.clone(),
        f.store.clone(),
        Arc::new(SecretRedactor::new(Vec::new())),
    ));
    let materializer = lumen_control_plane::DatabaseWorkerMaterializer::new(db, factory);
    let worker = lumen_worker_runtime::WorkerMaterializer::materialize(
        &materializer,
        &assignment,
        None,
        None,
        CancellationToken::new(),
    )
    .await
    .unwrap();
    assert_eq!(
        worker
            .model
            .generate(input(DataClass::Public))
            .await
            .unwrap(),
        lumen_core::model::ModelOutput::FinalText("local result".into())
    );
    assert_eq!(f.store.reads.load(Ordering::SeqCst), 0);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(!requests[0].headers.contains_key("authorization"));
}

#[tokio::test]
async fn reflected_tool_fields_model_names_and_normal_final_text_are_blocked() {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public", "workspace"]))
        .await
        .unwrap();
    let service = f.start().await;
    let tool = lumen_core::model::ModelTool::new(
        "write",
        "write",
        "fs.write",
        CanonicalValue::object([("type", CanonicalValue::from("object"))]),
    );
    for body in [
        json!({"model":KEY,"choices":[{"finish_reason":"stop","message":{"content":"hello"}}]}),
        json!({"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":KEY,"type":"function","function":{"name":"write","arguments":"{}"}}]}}]}),
        json!({"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":"call","type":"function","function":{"name":"write","arguments":json!({"content":KEY}).to_string()}}]}}]}),
        json!({"choices":[{"finish_reason":"tool_calls","message":{"tool_calls":[{"id":"call","type":"function","function":{"name":KEY,"arguments":"{}"}}]}}]}),
    ] {
        f.server
            .replies
            .lock()
            .await
            .push_back(tls::Reply::json(body));
        let error = service
            .planner_model(f.config.workspace_id())
            .generate(input(DataClass::Public).with_tools(vec![tool.clone()]))
            .await
            .unwrap_err();
        assert!(!error.to_string().contains(KEY));
    }
    f.server.replies.lock().await.push_back(tls::Reply::json(
        json!({"choices":[{"finish_reason":"stop","message":{"content":KEY}}]}),
    ));
    let run = service
        .create_run(CreateRunCommand::new(
            f.config.workspace_id(),
            f.config.bootstrap_principal(),
            "benign".into(),
        ))
        .await
        .unwrap();
    wait_phase(&service, run.run_id(), "failed").await;
    service.shutdown().await;
    f.no_leaks().await;
}
