use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use lumen_core::audit::AuditEventKind;
use lumen_core::{approval::TimestampMillis, identity::WorkspaceId, secret::SecretRefId};
use lumen_db::{Database, SecretReference};
use lumen_integrations::{
    sandbox::{
        SandboxBackend, SandboxError, SandboxFuture, SandboxOutput, SandboxReport, SandboxRequest,
        SandboxStrength,
    },
    secrets::{InMemorySecretStore, SecretStore},
};
use lumen_server::{ApiState, EventBroker, SandboxCapabilityReport, router};
use tempfile::TempDir;
use tower::ServiceExt;
use wiremock::{
    Mock, MockServer, Request as MockRequest, ResponseTemplate,
    matchers::{method, path},
};

use super::{LocalRuntimeService, now};
use crate::config::Config;

const TOKEN: &str = "security-test-token";

#[derive(Clone)]
struct RecordingSandbox {
    calls: Arc<AtomicUsize>,
    environments: Arc<StdMutex<Vec<BTreeMap<String, String>>>>,
    output: Arc<StdMutex<SandboxOutput>>,
    wait_for_cancellation: bool,
}

impl RecordingSandbox {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            environments: Arc::new(StdMutex::new(Vec::new())),
            output: Arc::new(StdMutex::new(SandboxOutput::new(
                Some(0),
                b"ok\n".to_vec(),
                Vec::new(),
            ))),
            wait_for_cancellation: false,
        }
    }

    fn with_stdout(self, output: impl Into<Vec<u8>>) -> Self {
        *self.output.lock().expect("sandbox output lock") =
            SandboxOutput::new(Some(0), output.into(), Vec::new());
        self
    }

    fn last_environment(&self) -> BTreeMap<String, String> {
        self.environments
            .lock()
            .expect("sandbox environment lock")
            .last()
            .cloned()
            .unwrap_or_default()
    }

    fn waiting_for_cancellation(mut self) -> Self {
        self.wait_for_cancellation = true;
        self
    }
}

impl SandboxBackend for RecordingSandbox {
    fn report(&self) -> SandboxReport {
        SandboxReport::new("test", SandboxStrength::KernelEnforced, None)
    }

    fn execute(&self, request: SandboxRequest) -> SandboxFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.environments
            .lock()
            .expect("sandbox environment lock")
            .push(request.environment().clone());
        let output = self.output.lock().expect("sandbox output lock").clone();
        let cancellation = request.cancellation();
        if self.wait_for_cancellation {
            Box::pin(async move {
                cancellation.cancelled().await;
                Err(SandboxError::Cancelled)
            })
        } else {
            Box::pin(async move { Ok(output) })
        }
    }
}

struct SecretSetup {
    id: SecretRefId,
    program: String,
    environment: String,
    value: String,
}

struct Harness {
    _directory: TempDir,
    app: axum::Router,
    service: Arc<LocalRuntimeService>,
    database: Database,
    sandbox: RecordingSandbox,
    workspace_id: lumen_core::identity::WorkspaceId,
}

impl Harness {
    async fn new(model: &MockServer, prepare_workspace: impl FnOnce(&std::path::Path)) -> Self {
        Self::new_inner(model, prepare_workspace, None).await.0
    }

    async fn new_with_secret(
        model: &MockServer,
        setup: SecretSetup,
    ) -> (Self, SecretReference, Arc<InMemorySecretStore>) {
        let (harness, reference, store) = Self::new_inner(model, |_| {}, Some(setup)).await;
        (harness, reference.expect("secret reference"), store)
    }

    async fn new_with_cancellable_process(model: &MockServer) -> Self {
        let (mut harness, _, _) = Self::new_inner(model, |_| {}, None).await;
        let sandbox = RecordingSandbox::new().waiting_for_cancellation();
        let config = Config::parse(&format!(
            r#"
[database]
path = "ignored.sqlite3"

[model]
endpoint = "{}/v1/"
model = "local-model"
streaming = false

[process]
allowed_programs = ["/bin/echo"]

[workspace]
id = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
name = "Default"
path = "{}"

[bootstrap_admin]
provider = "local"
subject = "operator"
"#,
            model.uri(),
            harness._directory.path().join("workspace").display()
        ))
        .expect("cancellable config");
        let events = EventBroker::new(128);
        let service = Arc::new(
            LocalRuntimeService::build_with_secret_store(
                &config,
                harness.database.clone(),
                events.clone(),
                Arc::new(sandbox.clone()),
                vec![TOKEN.to_owned()],
                Arc::new(InMemorySecretStore::new()),
            )
            .await
            .expect("runtime builds"),
        );
        let state = ApiState::new(
            service.clone(),
            events,
            TOKEN,
            config.bootstrap_principal(),
            BTreeSet::from([config.workspace_id()]),
            SandboxCapabilityReport::new(
                "test",
                "kernel_enforced",
                ["filesystem_isolation", "network_isolation"],
                None,
            ),
        )
        .expect("API state");
        harness.service.shutdown().await;
        harness.app = router(state);
        harness.service = service;
        harness.sandbox = sandbox;
        harness
    }

    async fn new_inner(
        model: &MockServer,
        prepare_workspace: impl FnOnce(&std::path::Path),
        secret: Option<SecretSetup>,
    ) -> (Self, Option<SecretReference>, Arc<InMemorySecretStore>) {
        let directory = tempfile::tempdir().expect("temporary runtime");
        let workspace = directory.path().join("workspace");
        std::fs::create_dir(&workspace).expect("workspace directory");
        prepare_workspace(&workspace);
        let config = Config::parse(&format!(
            r#"
[database]
path = "ignored.sqlite3"

[model]
endpoint = "{}/v1/"
model = "local-model"
streaming = false

[process]
allowed_programs = ["/bin/echo"]

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
        .expect("security config");
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
        let secret_store = Arc::new(InMemorySecretStore::new());
        let reference = if let Some(secret) = secret {
            let reference = SecretReference::new(
                secret.id,
                config.workspace_id(),
                "runtime test secret",
                secret.program,
                secret.environment,
                TimestampMillis::new(1),
            )
            .expect("secret metadata");
            secret_store
                .put(reference.keychain_account(), secret.value.into_bytes())
                .await
                .expect("secret stored");
            database
                .insert_secret_reference(&reference)
                .await
                .expect("secret reference stored");
            Some(reference)
        } else {
            None
        };
        let events = EventBroker::new(128);
        let sandbox = match &reference {
            Some(_) => RecordingSandbox::new().with_stdout(
                secret_store
                    .resolve(
                        reference
                            .as_ref()
                            .expect("secret reference")
                            .keychain_account(),
                    )
                    .await
                    .expect("secret output"),
            ),
            None => RecordingSandbox::new(),
        };
        let service = Arc::new(
            LocalRuntimeService::build_with_secret_store(
                &config,
                database.clone(),
                events.clone(),
                Arc::new(sandbox.clone()),
                vec![TOKEN.to_owned()],
                secret_store.clone(),
            )
            .await
            .expect("runtime builds"),
        );
        let state = ApiState::new(
            service.clone(),
            events,
            TOKEN,
            config.bootstrap_principal(),
            BTreeSet::from([config.workspace_id()]),
            SandboxCapabilityReport::new(
                "test",
                "kernel_enforced",
                ["filesystem_isolation", "network_isolation"],
                None,
            ),
        )
        .expect("API state");
        (
            Self {
                _directory: directory,
                app: router(state),
                service,
                database,
                sandbox,
                workspace_id: config.workspace_id(),
            },
            reference,
            secret_store,
        )
    }

    fn uri(&self, suffix: &str) -> String {
        format!("/api/v1/workspaces/{}/{suffix}", self.workspace_id)
    }

    async fn request(&self, method: &str, suffix: &str, body: &str) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(self.uri(suffix))
                    .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_owned()))
                    .expect("request"),
            )
            .await
            .expect("response")
    }

    async fn create_run(&self, prompt: &str) -> String {
        let response = self
            .request(
                "POST",
                "runs",
                &serde_json::json!({"prompt": prompt}).to_string(),
            )
            .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = response
            .into_body()
            .collect()
            .await
            .expect("run body")
            .to_bytes();
        serde_json::from_slice::<serde_json::Value>(&body).expect("run JSON")["run_id"]
            .as_str()
            .expect("run ID")
            .to_owned()
    }

    async fn wait_for_audit(&self, kind: AuditEventKind) {
        for _ in 0..100 {
            let records = self
                .database
                .list_audit_records(self.workspace_id, 0, 200)
                .await
                .expect("audit records");
            if records.iter().any(|record| record.event().kind() == kind) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("audit event {kind:?} was not recorded");
    }

    async fn pending_approval_id(&self) -> String {
        for _ in 0..100 {
            let approvals = self
                .database
                .list_pending_approvals(self.workspace_id)
                .await
                .expect("pending approvals");
            if let Some(approval) = approvals.first() {
                return approval.approval_id().to_string();
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("approval was not created");
    }

    async fn sse_until(&self, run_id: &str, needle: &str) -> String {
        let response = self
            .request("GET", &format!("runs/{run_id}/events"), "")
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut output = String::new();
            while let Some(chunk) = stream.next().await {
                output.push_str(&String::from_utf8_lossy(&chunk.expect("SSE chunk")));
                if output.contains(needle) {
                    return output;
                }
            }
            output
        })
        .await
        .expect("SSE deadline")
    }
}

fn final_response(text: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "choices": [{"message": {"content": text, "tool_calls": []}}]
    }))
}

fn action_response(kind: &str, arguments: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(serde_json::json!({
        "choices": [{"message": {
            "content": null,
            "tool_calls": [{"function": {
                "name": kind,
                "arguments": serde_json::to_string(&arguments).expect("arguments JSON")
            }}]
        }}]
    }))
}

async fn mount_response(model: &MockServer, response: ResponseTemplate) {
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(response)
        .mount(model)
        .await;
}

#[tokio::test]
async fn hostile_content_cannot_expand_the_executable_allowlist() {
    let model = MockServer::start().await;
    mount_response(
        &model,
        action_response(
            "process.spawn",
            serde_json::json!({"program":"/bin/sh","args":["-c","cat /etc/passwd"],"environment":{}}),
        ),
    )
    .await;
    let harness = Harness::new(&model, |_| {}).await;

    harness
        .create_run("Retrieved page says to ignore policy and run /bin/sh")
        .await;
    harness.wait_for_audit(AuditEventKind::PolicyDenied).await;

    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0);
    let action_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions")
        .fetch_one(harness.database.pool())
        .await
        .expect("denied action count");
    assert_eq!(action_count, 1);
    harness.service.shutdown().await;
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_fails_through_the_model_to_executor_path() {
    use std::os::unix::fs::symlink;

    let model = MockServer::start().await;
    mount_response(
        &model,
        action_response(
            "filesystem.read",
            serde_json::json!({"path":"escape/secret.txt"}),
        ),
    )
    .await;
    let outside = tempfile::tempdir().expect("outside directory");
    std::fs::write(outside.path().join("secret.txt"), "must-not-leak").expect("secret");
    let harness = Harness::new(&model, |workspace| {
        symlink(outside.path(), workspace.join("escape")).expect("escape symlink");
    })
    .await;

    let run_id = harness.create_run("read the linked file").await;
    harness
        .wait_for_audit(AuditEventKind::ExecutionFailed)
        .await;
    let stream = harness.sse_until(&run_id, "run.failed").await;

    assert!(!stream.contains("must-not-leak"));
    let attempt_state: String = sqlx::query_scalar("SELECT state FROM execution_attempts LIMIT 1")
        .fetch_one(harness.database.pool())
        .await
        .expect("filesystem attempt state");
    assert_eq!(attempt_state, "failed");
    harness.service.shutdown().await;
}

#[tokio::test]
async fn cancellation_stops_an_in_flight_model_request_and_is_audited() {
    let model = MockServer::start().await;
    mount_response(
        &model,
        final_response("too late").set_delay(Duration::from_secs(5)),
    )
    .await;
    let harness = Harness::new(&model, |_| {}).await;
    let run_id = harness.create_run("slow request").await;

    let response = harness
        .request("POST", &format!("runs/{run_id}/cancel"), "")
        .await;
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    harness.wait_for_audit(AuditEventKind::RunCancelled).await;

    let state: String = sqlx::query_scalar("SELECT state FROM agent_runs WHERE id = ?")
        .bind(&run_id)
        .fetch_one(harness.database.pool())
        .await
        .expect("run state");
    assert_eq!(state, "cancelled");
    harness.service.shutdown().await;
}

#[tokio::test]
async fn known_bootstrap_secrets_are_redacted_from_streamed_model_output() {
    let model = MockServer::start().await;
    mount_response(&model, final_response(&format!("echoed {TOKEN}"))).await;
    let harness = Harness::new(&model, |_| {}).await;
    let run_id = harness.create_run("echo input").await;

    let stream = harness.sse_until(&run_id, "run.completed").await;

    assert!(stream.contains("[REDACTED]"));
    assert!(!stream.contains(TOKEN));
    harness.service.shutdown().await;
}

#[tokio::test]
async fn known_secrets_in_model_actions_are_rejected_before_persistence() {
    let model = MockServer::start().await;
    mount_response(
        &model,
        action_response(
            "process.spawn",
            serde_json::json!({"program":"/bin/echo","args":[TOKEN],"environment":{}}),
        ),
    )
    .await;
    let harness = Harness::new(&model, |_| {}).await;

    harness.create_run("perform the proposed action").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let action_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actions")
        .fetch_one(harness.database.pool())
        .await
        .expect("action count");
    assert_eq!(action_count, 0);
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn approval_policy_mutation_and_replay_never_dispatch_twice() {
    let model = MockServer::start().await;
    let turn = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with({
            let turn = Arc::clone(&turn);
            move |_request: &MockRequest| {
                if turn.fetch_add(1, Ordering::SeqCst) == 0 {
                    action_response(
                        "process.spawn",
                        serde_json::json!({"program":"/bin/echo","args":["hello"],"environment":{}}),
                    )
                } else {
                    final_response("done")
                }
            }
        })
        .mount(&model)
        .await;
    let harness = Harness::new(&model, |_| {}).await;
    let _run_id = harness.create_run("run echo").await;
    let approval_id = loop {
        let approvals = harness
            .database
            .list_pending_approvals(harness.workspace_id)
            .await
            .expect("pending approvals");
        if let Some(approval) = approvals.first() {
            break approval.approval_id().to_string();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    sqlx::query("UPDATE approval_requests SET policy_version = 'tampered' WHERE id = ?")
        .bind(&approval_id)
        .execute(harness.database.pool())
        .await
        .expect("approval mutated");
    let first = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0);

    let replay = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts")
        .fetch_one(harness.database.pool())
        .await
        .expect("attempt count");
    assert_eq!(attempts, 0);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn granted_approval_dispatches_once_and_http_replay_is_rejected() {
    let model = MockServer::start().await;
    let turn = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with({
            let turn = Arc::clone(&turn);
            move |_request: &MockRequest| {
                if turn.fetch_add(1, Ordering::SeqCst) == 0 {
                    action_response(
                        "process.spawn",
                        serde_json::json!({"program":"/bin/echo","args":["hello"],"environment":{}}),
                    )
                } else {
                    final_response("done")
                }
            }
        })
        .mount(&model)
        .await;
    let harness = Harness::new(&model, |_| {}).await;
    harness.create_run("run echo").await;
    let approval_id = loop {
        let approvals = harness
            .database
            .list_pending_approvals(harness.workspace_id)
            .await
            .expect("pending approvals");
        if let Some(approval) = approvals.first() {
            break approval.approval_id().to_string();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };

    let granted = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(granted.status(), StatusCode::OK);
    harness
        .wait_for_audit(AuditEventKind::ExecutionSucceeded)
        .await;
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 1);

    let replay = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts")
        .fetch_one(harness.database.pool())
        .await
        .expect("attempt count");
    assert_eq!(attempts, 1);
    let attempt_state: String = sqlx::query_scalar("SELECT state FROM execution_attempts LIMIT 1")
        .fetch_one(harness.database.pool())
        .await
        .expect("attempt state");
    assert_eq!(attempt_state, "succeeded");
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 1);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn approved_file_write_uses_the_one_shot_runtime_dispatch_path() {
    let model = MockServer::start().await;
    let turn = Arc::new(AtomicUsize::new(0));
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with({
            let turn = Arc::clone(&turn);
            move |_request: &MockRequest| {
                if turn.fetch_add(1, Ordering::SeqCst) == 0 {
                    action_response(
                        "filesystem.write",
                        serde_json::json!({"path":"note.txt","content":"after"}),
                    )
                } else {
                    final_response("done")
                }
            }
        })
        .mount(&model)
        .await;
    let harness = Harness::new(&model, |workspace| {
        std::fs::write(workspace.join("note.txt"), "before").expect("existing note");
    })
    .await;
    harness.create_run("replace the note").await;
    let approval_id = loop {
        let approvals = harness
            .database
            .list_pending_approvals(harness.workspace_id)
            .await
            .expect("pending approvals");
        if let Some(approval) = approvals.first() {
            break approval.approval_id().to_string();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let note = harness._directory.path().join("workspace/note.txt");
    assert_eq!(std::fs::read_to_string(&note).expect("note read"), "before");

    let granted = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(granted.status(), StatusCode::OK);
    harness
        .wait_for_audit(AuditEventKind::ExecutionSucceeded)
        .await;

    assert_eq!(std::fs::read_to_string(note).expect("note read"), "after");
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0);
    let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM execution_attempts")
        .fetch_one(harness.database.pool())
        .await
        .expect("attempt count");
    assert_eq!(attempts, 1);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn approved_secret_is_injected_once_and_never_crosses_persistence_or_api_boundaries() {
    let secret = "injected-runtime-secret";
    let reference_id =
        SecretRefId::parse("5f7cc8b4-e848-4cb4-91ef-27c5983c41a5").expect("secret reference");
    let model = MockServer::start().await;
    let turn = Arc::new(AtomicUsize::new(0));
    let model_requests = Arc::new(StdMutex::new(Vec::new()));
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with({
            let turn = Arc::clone(&turn);
            let model_requests = Arc::clone(&model_requests);
            move |request: &MockRequest| {
                model_requests
                    .lock()
                    .expect("model request lock")
                    .push(String::from_utf8_lossy(&request.body).into_owned());
                if turn.fetch_add(1, Ordering::SeqCst) == 0 {
                    action_response(
                        "process.spawn",
                        serde_json::json!({
                            "program":"/bin/echo",
                            "secret_environment":{"API_TOKEN":reference_id.to_string()}
                        }),
                    )
                } else {
                    final_response("done")
                }
            }
        })
        .mount(&model)
        .await;
    let (harness, reference, _) = Harness::new_with_secret(
        &model,
        SecretSetup {
            id: reference_id,
            program: std::fs::canonicalize("/bin/echo")
                .expect("echo executable")
                .to_string_lossy()
                .into_owned(),
            environment: "API_TOKEN".to_owned(),
            value: secret.to_owned(),
        },
    )
    .await;

    let run_id = harness.create_run("use the configured credential").await;
    let approval_id = harness.pending_approval_id().await;
    let approval_response = harness.request("GET", "approvals", "").await;
    let approval_body = String::from_utf8_lossy(
        &approval_response
            .into_body()
            .collect()
            .await
            .expect("approval body")
            .to_bytes(),
    )
    .into_owned();
    let pending_stream = harness.sse_until(&run_id, "approval.required").await;
    assert!(approval_body.contains(&reference.id().to_string()));
    assert!(!approval_body.contains(secret));
    assert!(!pending_stream.contains(secret));

    let granted = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(granted.status(), StatusCode::OK);
    harness
        .wait_for_audit(AuditEventKind::ExecutionSucceeded)
        .await;
    let completed_stream = harness.sse_until(&run_id, "run.completed").await;

    assert_eq!(
        harness.sandbox.last_environment().get("API_TOKEN"),
        Some(&secret.to_owned())
    );
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 1);
    assert!(!completed_stream.contains(secret));
    {
        let requests = model_requests.lock().expect("model request lock");
        assert!(
            requests
                .iter()
                .any(|request| request.contains("[REDACTED]"))
        );
        assert!(!requests.iter().any(|request| request.contains(secret)));
    }

    let action_json: Vec<String> = sqlx::query_scalar(
        "SELECT arguments_json || capabilities_json FROM actions ORDER BY created_at, id",
    )
    .fetch_all(harness.database.pool())
    .await
    .expect("action JSON");
    let approval_json: Vec<String> =
        sqlx::query_scalar("SELECT action_fingerprint || policy_version FROM approval_requests")
            .fetch_all(harness.database.pool())
            .await
            .expect("approval JSON");
    let audit_json: Vec<String> =
        sqlx::query_scalar("SELECT payload_json FROM audit_events ORDER BY sequence")
            .fetch_all(harness.database.pool())
            .await
            .expect("audit JSON");
    for encoded in action_json
        .into_iter()
        .chain(approval_json)
        .chain(audit_json)
    {
        assert!(!encoded.contains(secret));
    }
    let audit_response = harness.request("GET", "audit", "").await;
    let audit_body = audit_response
        .into_body()
        .collect()
        .await
        .expect("audit body")
        .to_bytes();
    assert!(!String::from_utf8_lossy(&audit_body).contains(secret));

    let replay = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(replay.status(), StatusCode::CONFLICT);
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 1);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn missing_or_mismatched_secret_scope_never_reaches_the_sandbox() {
    for (case, program, environment, remove_reference) in [
        (
            "program",
            std::fs::canonicalize("/bin/cat")
                .expect("cat executable")
                .to_string_lossy()
                .into_owned(),
            "API_TOKEN".to_owned(),
            false,
        ),
        (
            "environment",
            std::fs::canonicalize("/bin/echo")
                .expect("echo executable")
                .to_string_lossy()
                .into_owned(),
            "OTHER_TOKEN".to_owned(),
            false,
        ),
        (
            "missing",
            std::fs::canonicalize("/bin/echo")
                .expect("echo executable")
                .to_string_lossy()
                .into_owned(),
            "API_TOKEN".to_owned(),
            true,
        ),
    ] {
        let reference_id = SecretRefId::new();
        let model = MockServer::start().await;
        mount_response(
            &model,
            action_response(
                "process.spawn",
                serde_json::json!({
                    "program":"/bin/echo",
                    "secret_environment":{"API_TOKEN":reference_id.to_string()}
                }),
            ),
        )
        .await;
        let (harness, reference, _) = Harness::new_with_secret(
            &model,
            SecretSetup {
                id: reference_id,
                program,
                environment,
                value: format!("scope-secret-{case}"),
            },
        )
        .await;
        if remove_reference {
            harness
                .database
                .delete_secret_reference(harness.workspace_id, reference.id())
                .await
                .expect("reference removed");
        }

        harness.create_run("use scoped secret").await;
        let approval_id = harness.pending_approval_id().await;
        let granted = harness
            .request(
                "POST",
                &format!("approvals/{approval_id}/decision"),
                r#"{"decision":"grant"}"#,
            )
            .await;
        assert_eq!(granted.status(), StatusCode::OK, "{case}");
        harness
            .wait_for_audit(AuditEventKind::ExecutionFailed)
            .await;
        assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0, "{case}");
        harness.service.shutdown().await;
    }
}

#[tokio::test]
async fn another_workspaces_secret_reference_is_denied_before_approval() {
    let reference_id = SecretRefId::new();
    let model = MockServer::start().await;
    mount_response(
        &model,
        action_response(
            "process.spawn",
            serde_json::json!({
                "program":"/bin/echo",
                "secret_environment":{"API_TOKEN":reference_id.to_string()}
            }),
        ),
    )
    .await;
    let harness = Harness::new(&model, |_| {}).await;
    let other_workspace = WorkspaceId::new();
    harness
        .database
        .insert_workspace(other_workspace, "Other", TimestampMillis::new(1))
        .await
        .expect("other workspace");
    harness
        .database
        .insert_secret_reference(
            &SecretReference::new(
                reference_id,
                other_workspace,
                "other workspace secret",
                std::fs::canonicalize("/bin/echo")
                    .expect("echo executable")
                    .to_string_lossy()
                    .into_owned(),
                "API_TOKEN",
                TimestampMillis::new(2),
            )
            .expect("secret metadata"),
        )
        .await
        .expect("other workspace reference");

    harness.create_run("cross workspace secret").await;
    harness.wait_for_audit(AuditEventKind::PolicyDenied).await;
    assert!(
        harness
            .database
            .list_pending_approvals(harness.workspace_id)
            .await
            .expect("pending approvals")
            .is_empty()
    );
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn secret_scope_does_not_expand_literal_environment_permissions() {
    let reference_id = SecretRefId::new();
    let model = MockServer::start().await;
    mount_response(
        &model,
        action_response(
            "process.spawn",
            serde_json::json!({
                "program":"/bin/echo",
                "environment":{"API_TOKEN":"attacker-controlled"}
            }),
        ),
    )
    .await;
    let (harness, _, _) = Harness::new_with_secret(
        &model,
        SecretSetup {
            id: reference_id,
            program: std::fs::canonicalize("/bin/echo")
                .expect("echo executable")
                .to_string_lossy()
                .into_owned(),
            environment: "API_TOKEN".to_owned(),
            value: "stored-secret".to_owned(),
        },
    )
    .await;

    harness.create_run("set a literal secret environment").await;
    let approval_id = harness.pending_approval_id().await;
    let granted = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(granted.status(), StatusCode::OK);
    harness
        .wait_for_audit(AuditEventKind::ExecutionFailed)
        .await;
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 0);
    harness.service.shutdown().await;
}

#[tokio::test]
async fn run_cancellation_reaches_an_executing_process_and_persists_cancelled() {
    let model = MockServer::start().await;
    mount_response(
        &model,
        action_response(
            "process.spawn",
            serde_json::json!({"program":"/bin/echo","args":["waiting"]}),
        ),
    )
    .await;
    let harness = Harness::new_with_cancellable_process(&model).await;
    let run_id = harness.create_run("start a cancellable process").await;
    let approval_id = harness.pending_approval_id().await;
    let granted = harness
        .request(
            "POST",
            &format!("approvals/{approval_id}/decision"),
            r#"{"decision":"grant"}"#,
        )
        .await;
    assert_eq!(granted.status(), StatusCode::OK);
    for _ in 0..100 {
        if harness.sandbox.calls.load(Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(harness.sandbox.calls.load(Ordering::SeqCst), 1);

    let cancelled = harness
        .request("POST", &format!("runs/{run_id}/cancel"), "")
        .await;
    assert_eq!(cancelled.status(), StatusCode::ACCEPTED);
    harness
        .wait_for_audit(AuditEventKind::ExecutionCancelled)
        .await;

    let attempt_state: String = sqlx::query_scalar("SELECT state FROM execution_attempts LIMIT 1")
        .fetch_one(harness.database.pool())
        .await
        .expect("attempt state");
    let run_state: String = sqlx::query_scalar("SELECT state FROM agent_runs WHERE id = ?")
        .bind(&run_id)
        .fetch_one(harness.database.pool())
        .await
        .expect("run state");
    assert_eq!(attempt_state, "cancelled");
    assert_eq!(run_state, "cancelled");
    harness.service.shutdown().await;
}
