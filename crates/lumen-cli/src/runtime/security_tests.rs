use std::{
    collections::BTreeSet,
    sync::{
        Arc,
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
use lumen_db::Database;
use lumen_integrations::sandbox::{
    SandboxBackend, SandboxFuture, SandboxOutput, SandboxReport, SandboxRequest, SandboxStrength,
};
use lumen_server::{ApiState, EventBroker, router};
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
}

impl RecordingSandbox {
    fn new() -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SandboxBackend for RecordingSandbox {
    fn report(&self) -> SandboxReport {
        SandboxReport::new("test", SandboxStrength::KernelEnforced, None)
    }

    fn execute(&self, _request: SandboxRequest) -> SandboxFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Ok(SandboxOutput::new(Some(0), b"ok\n".to_vec(), Vec::new())) })
    }
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
        let events = EventBroker::new(128);
        let sandbox = RecordingSandbox::new();
        let service = Arc::new(
            LocalRuntimeService::build_with_secrets(
                &config,
                database.clone(),
                events.clone(),
                Arc::new(sandbox.clone()),
                vec![TOKEN.to_owned()],
            )
            .expect("runtime builds"),
        );
        let state = ApiState::new(
            service.clone(),
            events,
            TOKEN,
            config.bootstrap_principal(),
            BTreeSet::from([config.workspace_id()]),
        )
        .expect("API state");
        Self {
            _directory: directory,
            app: router(state),
            service,
            database,
            sandbox,
            workspace_id: config.workspace_id(),
        }
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
