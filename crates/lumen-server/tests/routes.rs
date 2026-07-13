use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::{ApprovalId, TimestampMillis},
    audit::{AuditEventId, AuditEventKind, AuditOutcome},
    identity::{PrincipalId, WorkspaceId},
    secret::SecretRefId,
};
use lumen_server::{
    ApiState, ApprovalDecision, ApprovalDecisionCommand, ApprovalPreview, ApprovalQuery,
    ApprovalResult, ApprovalSecretReference, AuditEntry, AuditQuery, CancelRunCommand,
    CreateRunCommand, EventBroker, RunCancellation, RunCreated, RuntimeService,
    SandboxCapabilityReport, ServiceFuture, router,
};
use tower::ServiceExt;

const TOKEN: &str = "local-test-token";

#[derive(Default)]
struct FakeService {
    run_commands: Mutex<Vec<CreateRunCommand>>,
    approval_commands: Mutex<Vec<ApprovalDecisionCommand>>,
    audit_queries: Mutex<Vec<AuditQuery>>,
    audit_entries: Mutex<Vec<AuditEntry>>,
    approval_queries: Mutex<Vec<ApprovalQuery>>,
    approval_previews: Mutex<Vec<ApprovalPreview>>,
    cancellation_commands: Mutex<Vec<CancelRunCommand>>,
}

impl RuntimeService for FakeService {
    fn create_run(&self, command: CreateRunCommand) -> ServiceFuture<'_, RunCreated> {
        self.run_commands
            .lock()
            .expect("run commands")
            .push(command);
        Box::pin(async { Ok(RunCreated::new(RunId::new())) })
    }

    fn decide_approval(
        &self,
        command: ApprovalDecisionCommand,
    ) -> ServiceFuture<'_, ApprovalResult> {
        let decision = command.decision();
        let approval_id = command.approval_id();
        self.approval_commands
            .lock()
            .expect("approval commands")
            .push(command);
        Box::pin(async move { Ok(ApprovalResult::new(approval_id, decision)) })
    }

    fn list_audit(&self, query: AuditQuery) -> ServiceFuture<'_, Vec<AuditEntry>> {
        self.audit_queries
            .lock()
            .expect("audit queries")
            .push(query);
        let entries = self.audit_entries.lock().expect("audit entries").clone();
        Box::pin(async move { Ok(entries) })
    }

    fn list_approvals(&self, query: ApprovalQuery) -> ServiceFuture<'_, Vec<ApprovalPreview>> {
        self.approval_queries
            .lock()
            .expect("approval queries")
            .push(query);
        let approvals = self
            .approval_previews
            .lock()
            .expect("approval previews")
            .clone();
        Box::pin(async move { Ok(approvals) })
    }

    fn cancel_run(&self, command: CancelRunCommand) -> ServiceFuture<'_, RunCancellation> {
        let run_id = command.run_id();
        self.cancellation_commands
            .lock()
            .expect("cancellation commands")
            .push(command);
        Box::pin(async move { Ok(RunCancellation::new(run_id)) })
    }
}

fn test_app(workspace_id: WorkspaceId) -> (axum::Router, Arc<FakeService>, EventBroker) {
    let service = Arc::new(FakeService::default());
    let events = EventBroker::new(64);
    let state = ApiState::new(
        service.clone(),
        events.clone(),
        TOKEN,
        PrincipalId::new("local", "operator").expect("principal"),
        BTreeSet::from([workspace_id]),
        SandboxCapabilityReport::new(
            "test-sandbox",
            "kernel_enforced",
            ["filesystem_isolation", "network_isolation"],
            None,
        ),
    )
    .expect("API state");
    (router(state), service, events)
}

#[tokio::test]
async fn runtime_capability_report_is_authenticated_and_workspace_scoped() {
    let workspace_id = WorkspaceId::new();
    let (app, _, _) = test_app(workspace_id);

    let response = app
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/runtime/capabilities"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["sandbox"]["backend"], "test-sandbox");
    assert_eq!(body["sandbox"]["strength"], "kernel_enforced");
    assert_eq!(
        body["sandbox"]["guarantees"],
        serde_json::json!(["filesystem_isolation", "network_isolation"])
    );
}

fn request(method: &str, uri: String, body: Body) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(body)
        .expect("request")
}

async fn json_body(response: axum::response::Response) -> serde_json::Value {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("JSON response")
}

#[tokio::test]
async fn local_bearer_authentication_is_required() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/workspaces/{workspace_id}/runs"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"hello"}"#))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
        "Bearer"
    );
    assert!(
        service
            .run_commands
            .lock()
            .expect("run commands")
            .is_empty()
    );
}

#[tokio::test]
async fn incorrect_local_bearer_token_is_rejected() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);
    let request = Request::builder()
        .method("POST")
        .uri(format!("/api/v1/workspaces/{workspace_id}/runs"))
        .header(header::AUTHORIZATION, "Bearer incorrect-local-token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"prompt":"hello"}"#))
        .expect("request");

    let response = app.oneshot(request).await.expect("response");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(
        service
            .run_commands
            .lock()
            .expect("run commands")
            .is_empty()
    );
}

#[tokio::test]
async fn unknown_workspace_is_rejected_before_service_dispatch() {
    let allowed_workspace = WorkspaceId::new();
    let requested_workspace = WorkspaceId::new();
    let (app, service, _) = test_app(allowed_workspace);

    let response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{requested_workspace}/runs"),
            Body::from(r#"{"prompt":"hello"}"#),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        service
            .run_commands
            .lock()
            .expect("run commands")
            .is_empty()
    );
}

#[tokio::test]
async fn run_creation_uses_authenticated_actor_and_workspace() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);

    let response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/runs"),
            Body::from(r#"{"prompt":"summarize notes"}"#),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json_body(response).await;
    assert!(body["run_id"].as_str().is_some());
    let commands = service.run_commands.lock().expect("run commands");
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].workspace_id(), workspace_id);
    assert_eq!(commands[0].actor().subject(), "operator");
    assert_eq!(commands[0].prompt(), "summarize notes");
}

#[tokio::test]
async fn approval_grant_and_reject_are_forwarded_as_decisions_not_dispatches() {
    let workspace_id = WorkspaceId::new();
    let approval_id = ApprovalId::new();
    let (app, service, _) = test_app(workspace_id);

    for decision in ["grant", "reject"] {
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                format!("/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/decision"),
                Body::from(format!(r#"{{"decision":"{decision}"}}"#)),
            ))
            .await
            .expect("response");
        assert_eq!(response.status(), StatusCode::OK);
    }

    let commands = service.approval_commands.lock().expect("approval commands");
    assert_eq!(commands.len(), 2);
    assert_eq!(commands[0].decision(), ApprovalDecision::Grant);
    assert_eq!(commands[1].decision(), ApprovalDecision::Reject);
    assert!(
        commands
            .iter()
            .all(|command| command.actor().subject() == "operator")
    );
}

#[tokio::test]
async fn sse_replays_events_after_last_event_id() {
    let workspace_id = WorkspaceId::new();
    let run_id = RunId::new();
    let (app, _, events) = test_app(workspace_id);
    events
        .publish(
            workspace_id,
            run_id,
            "run.created",
            CanonicalValue::from("first"),
        )
        .expect("first event");
    events
        .publish(
            WorkspaceId::new(),
            run_id,
            "run.completed",
            CanonicalValue::from("cross-workspace-secret"),
        )
        .expect("other workspace event");
    events
        .publish(
            workspace_id,
            run_id,
            "run.completed",
            CanonicalValue::from("second"),
        )
        .expect("second event");

    let mut response = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/api/v1/workspaces/{workspace_id}/runs/{run_id}/events"
                ))
                .header(header::AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header("last-event-id", "1")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "text/event-stream"
    );
    let chunk = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        response.body_mut().into_data_stream().next(),
    )
    .await
    .expect("SSE chunk deadline")
    .expect("SSE chunk")
    .expect("SSE bytes");
    let text = String::from_utf8(chunk.to_vec()).expect("UTF-8 SSE");
    assert!(text.contains("id: 3"));
    assert!(text.contains("event: run.completed"));
    assert!(text.contains("second"));
    assert!(!text.contains("first"));
    assert!(!text.contains("cross-workspace-secret"));
}

#[tokio::test]
async fn audit_listing_is_workspace_scoped_and_bounded() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);
    service
        .audit_entries
        .lock()
        .expect("audit entries")
        .push(AuditEntry::new(
            7,
            AuditEventId::new(),
            TimestampMillis::new(42),
            AuditEventKind::RunCreated,
            AuditOutcome::Success,
            workspace_id,
            CanonicalValue::object([] as [(&str, CanonicalValue); 0]),
        ));

    let response = app
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/audit?after=5&limit=10"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["events"][0]["sequence"], 7);
    let queries = service.audit_queries.lock().expect("audit queries");
    assert_eq!(queries[0].workspace_id(), workspace_id);
    assert_eq!(queries[0].after(), 5);
    assert_eq!(queries[0].limit(), 10);
}

#[tokio::test]
async fn approval_listing_returns_exact_action_previews() {
    let workspace_id = WorkspaceId::new();
    let approval_id = ApprovalId::new();
    let run_id = RunId::new();
    let secret_id =
        SecretRefId::parse("5f7cc8b4-e848-4cb4-91ef-27c5983c41a5").expect("secret reference");
    let (app, service, _) = test_app(workspace_id);
    service
        .approval_previews
        .lock()
        .expect("approval previews")
        .push(
            ApprovalPreview::new(
                approval_id,
                run_id,
                "process.spawn",
                CanonicalValue::object([("program", CanonicalValue::from("/bin/echo"))]),
                vec![CanonicalValue::object([(
                    "name",
                    CanonicalValue::from("process.spawn"),
                )])],
                "a".repeat(64),
                TimestampMillis::new(10),
                TimestampMillis::new(20),
            )
            .with_secret_references([ApprovalSecretReference::new(
                secret_id,
                "Example API token",
                "API_TOKEN",
            )]),
        );

    let response = app
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/approvals"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["approvals"][0]["kind"], "process.spawn");
    assert_eq!(body["approvals"][0]["arguments"]["program"], "/bin/echo");
    assert_eq!(body["approvals"][0]["fingerprint"], "a".repeat(64));
    assert_eq!(
        body["approvals"][0]["secret_references"][0]["id"],
        secret_id.to_string()
    );
    assert_eq!(
        body["approvals"][0]["secret_references"][0]["label"],
        "Example API token"
    );
    assert_eq!(
        body["approvals"][0]["secret_references"][0]["environment"],
        "API_TOKEN"
    );
    assert!(
        body["approvals"][0]["secret_references"][0]
            .get("value")
            .is_none()
    );
    let queries = service.approval_queries.lock().expect("approval queries");
    assert_eq!(queries[0].workspace_id(), workspace_id);
    assert_eq!(queries[0].actor().subject(), "operator");
}

#[tokio::test]
async fn run_cancellation_is_forwarded_to_the_runtime_service() {
    let workspace_id = WorkspaceId::new();
    let run_id = RunId::new();
    let (app, service, _) = test_app(workspace_id);

    let response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/runs/{run_id}/cancel"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let commands = service
        .cancellation_commands
        .lock()
        .expect("cancellation commands");
    assert_eq!(commands[0].workspace_id(), workspace_id);
    assert_eq!(commands[0].run_id(), run_id);
    assert_eq!(commands[0].actor().subject(), "operator");
}

#[tokio::test]
async fn no_direct_dispatch_route_exists() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);

    let response = app
        .oneshot(request("POST", "/api/v1/dispatch".into(), Body::from("{}")))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert!(
        service
            .run_commands
            .lock()
            .expect("run commands")
            .is_empty()
    );
    assert!(
        service
            .approval_commands
            .lock()
            .expect("approval commands")
            .is_empty()
    );
}
