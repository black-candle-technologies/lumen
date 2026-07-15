use std::{
    collections::{BTreeMap, BTreeSet},
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
    egress::DataClass,
    identity::{ExternalChannelIdentity, PrincipalId, WorkspaceId},
    secret::SecretRefId,
};
use lumen_server::{
    ApiState, ApprovalDecision, ApprovalDecisionCommand, ApprovalPreview, ApprovalQuery,
    ApprovalResult, ApprovalSecretReference, AuditEntry, AuditQuery, CancelRunCommand,
    ChannelMappingCommand, ChannelMappingQuery, ChannelMappingReview, CreateRunCommand,
    EventBroker, PluginActionCommand, PluginActionRequested, PluginComponentReview,
    PluginDetailsQuery, PluginFailureReview, PluginReviewQuery, PluginSettingReview,
    PluginVersionDetails, PrincipalSummary, RunCancellation, RunCreated, RuntimeService,
    SandboxCapabilityReport, ServiceError, ServiceFuture, StagedPluginReview, router,
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
    plugin_review_queries: Mutex<Vec<PluginReviewQuery>>,
    plugin_details_queries: Mutex<Vec<PluginDetailsQuery>>,
    plugin_action_commands: Mutex<Vec<PluginActionCommand>>,
    channel_mapping_queries: Mutex<Vec<ChannelMappingQuery>>,
    channel_mapping_commands: Mutex<Vec<ChannelMappingCommand>>,
    channel_mapping_reviews: Mutex<Vec<ChannelMappingReview>>,
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

    fn list_staged_plugins(
        &self,
        query: PluginReviewQuery,
    ) -> ServiceFuture<'_, Vec<StagedPluginReview>> {
        let requested_by = PrincipalSummary::new(query.actor());
        self.plugin_review_queries
            .lock()
            .expect("plugin review queries")
            .push(query);
        let package = StagedPluginReview::new(
            "11111111-1111-4111-8111-111111111111",
            "com.example.review",
            "1.0.0",
            "subprocess",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            BTreeMap::from([
                ("lumen-plugin.toml".to_owned(), "b".repeat(64)),
                ("bin/plugin".to_owned(), "c".repeat(64)),
            ]),
            requested_by,
            TimestampMillis::new(100),
        );
        Box::pin(async move { Ok(vec![package]) })
    }

    fn plugin_details(&self, query: PluginDetailsQuery) -> ServiceFuture<'_, PluginVersionDetails> {
        match query.plugin_id() {
            "com.example.conflict" => {
                return Box::pin(async {
                    Err(ServiceError::Conflict(
                        "review digest conflicts with current runtime state".into(),
                    ))
                });
            }
            "com.example.unavailable" => {
                return Box::pin(async {
                    Err(ServiceError::Unavailable(
                        "plugin runtime is unavailable".into(),
                    ))
                });
            }
            _ => {}
        }
        self.plugin_details_queries
            .lock()
            .expect("plugin details queries")
            .push(query);
        let capability = CanonicalValue::object([
            ("name", CanonicalValue::from("filesystem.read")),
            (
                "resource",
                CanonicalValue::object([("workspace_path", CanonicalValue::from("docs"))]),
            ),
        ]);
        let details = PluginVersionDetails::new(
            "com.example.review",
            "1.0.0",
            "enabled",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            vec![PluginComponentReview::new(
                "summarize",
                "tool",
                vec![capability.clone()],
                vec![capability],
                3,
                "9".repeat(64),
            )],
            vec![PluginSettingReview::new(
                "workspace",
                "workspace",
                4,
                serde_json::json!({
                    "api_key": "[redacted]",
                    "mode": "local"
                }),
                "d".repeat(64),
                "e".repeat(64),
            )],
            vec![PluginFailureReview::new(
                "host_protocol",
                2,
                "[redacted]",
                "f".repeat(64),
                TimestampMillis::new(200),
            )],
        );
        Box::pin(async move { Ok(details) })
    }

    fn request_plugin_action(
        &self,
        command: PluginActionCommand,
    ) -> ServiceFuture<'_, PluginActionRequested> {
        self.plugin_action_commands
            .lock()
            .expect("plugin action commands")
            .push(command);
        Box::pin(async { Ok(PluginActionRequested::new(RunId::new())) })
    }

    fn list_channel_mappings(
        &self,
        query: ChannelMappingQuery,
    ) -> ServiceFuture<'_, Vec<ChannelMappingReview>> {
        self.channel_mapping_queries
            .lock()
            .expect("channel mapping queries")
            .push(query);
        let reviews = self
            .channel_mapping_reviews
            .lock()
            .expect("channel mapping reviews")
            .clone();
        Box::pin(async move { Ok(reviews) })
    }

    fn update_channel_mapping(
        &self,
        command: ChannelMappingCommand,
    ) -> ServiceFuture<'_, ChannelMappingReview> {
        self.channel_mapping_commands
            .lock()
            .expect("channel mapping commands")
            .push(command.clone());
        Box::pin(async move {
            Ok(ChannelMappingReview::new(
                command.external().clone(),
                PrincipalSummary::new(command.principal()),
                command.workspace_id(),
                command.allowed(),
                TimestampMillis::new(1_000),
                TimestampMillis::new(2_000),
            ))
        })
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
        .clone()
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

#[tokio::test]
async fn channel_mapping_review_is_authenticated_and_workspace_scoped() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);
    service
        .channel_mapping_reviews
        .lock()
        .expect("channel mapping reviews")
        .push(ChannelMappingReview::new(
            ExternalChannelIdentity::new("slack", "T123", "C456", "U789")
                .expect("external identity"),
            PrincipalSummary::new(&PrincipalId::new("local", "alice").expect("principal")),
            workspace_id,
            true,
            TimestampMillis::new(1_000),
            TimestampMillis::new(2_000),
        ));

    let response = app
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/egress/channels"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["mappings"][0]["provider"], "slack");
    assert_eq!(body["mappings"][0]["external_workspace_id"], "T123");
    assert_eq!(body["mappings"][0]["channel_id"], "C456");
    assert_eq!(body["mappings"][0]["external_user_id"], "U789");
    assert_eq!(body["mappings"][0]["lumen_identity"]["subject"], "alice");
    assert_eq!(
        body["mappings"][0]["workspace_id"],
        workspace_id.to_string()
    );
    assert_eq!(body["mappings"][0]["allowed"], true);
    let queries = service
        .channel_mapping_queries
        .lock()
        .expect("channel mapping queries");
    assert_eq!(queries[0].workspace_id(), workspace_id);
    assert_eq!(queries[0].actor().subject(), "operator");
}

#[tokio::test]
async fn channel_mapping_updates_are_validated_and_forwarded() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/egress/channels"),
            Body::from(
                r#"{
                    "provider":"slack",
                    "external_workspace_id":"T123",
                    "channel_id":"C456",
                    "external_user_id":"U789",
                    "lumen_provider":"local",
                    "lumen_subject":"alice",
                    "allowed":true
                }"#,
            ),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["provider"], "slack");
    assert_eq!(body["lumen_identity"]["subject"], "alice");
    assert_eq!(body["allowed"], true);
    {
        let commands = service
            .channel_mapping_commands
            .lock()
            .expect("channel mapping commands");
        assert_eq!(commands[0].workspace_id(), workspace_id);
        assert_eq!(commands[0].actor().subject(), "operator");
        assert_eq!(commands[0].external().channel_id(), "C456");
        assert_eq!(commands[0].principal().subject(), "alice");
        assert!(commands[0].allowed());
    }

    let bad_response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/egress/channels"),
            Body::from(
                r#"{
                    "provider":"slack",
                    "external_workspace_id":"T123",
                    "channel_id":"bad/channel",
                    "external_user_id":"U789",
                    "lumen_provider":"local",
                    "lumen_subject":"alice",
                    "allowed":true
                }"#,
            ),
        ))
        .await
        .expect("bad response");
    assert_eq!(bad_response.status(), StatusCode::BAD_REQUEST);
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
        .clone()
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
async fn run_creation_accepts_explicit_data_class() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);

    let response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/runs"),
            Body::from(r#"{"prompt":"publish release notes","data_class":"public"}"#),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let commands = service.run_commands.lock().expect("run commands");
    assert_eq!(commands.len(), 1);
    assert_eq!(commands[0].data_class(), DataClass::Public);
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

#[tokio::test]
async fn plugin_review_lists_staged_packages_with_review_hashes() {
    let workspace_id = WorkspaceId::new();
    let (app, _, _) = test_app(workspace_id);

    let response = app
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/plugins/staged?limit=20"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["packages"][0]["plugin_id"], "com.example.review");
    assert_eq!(body["packages"][0]["package_digest"], "a".repeat(64));
    assert_eq!(body["packages"][0]["manifest_digest"], "b".repeat(64));
    assert_eq!(body["packages"][0]["artifact_digest"], "c".repeat(64));
    assert_eq!(
        body["packages"][0]["file_hashes"]["lumen-plugin.toml"],
        "b".repeat(64)
    );
    assert_eq!(body["packages"][0]["requested_by"]["subject"], "operator");
}

#[tokio::test]
async fn plugin_details_expose_authority_settings_and_failures_without_secrets() {
    let workspace_id = WorkspaceId::new();
    let (app, _, _) = test_app(workspace_id);

    let response = app
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/plugins/com.example.review/versions/1.0.0"),
            Body::empty(),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
    let body = json_body(response).await;
    assert_eq!(body["plugin_id"], "com.example.review");
    assert_eq!(body["version"], "1.0.0");
    assert_eq!(body["state"], "enabled");
    assert_eq!(body["components"][0]["id"], "summarize");
    assert_eq!(
        body["components"][0]["requested_capabilities"][0]["name"],
        "filesystem.read"
    );
    assert_eq!(
        body["components"][0]["effective_grants"][0]["name"],
        "filesystem.read"
    );
    assert_eq!(body["settings"][0]["scope_type"], "workspace");
    assert_eq!(body["settings"][0]["config"]["api_key"], "[redacted]");
    assert!(body["settings"][0]["config"].get("api_key_value").is_none());
    assert_eq!(body["settings"][0]["schema_digest"], "d".repeat(64));
    assert_eq!(body["settings"][0]["settings_digest"], "e".repeat(64));
    assert_eq!(body["failures"][0]["class"], "host_protocol");
    assert_eq!(body["failures"][0]["diagnostic"], "[redacted]");
    assert_eq!(body["failures"][0]["diagnostic_digest"], "f".repeat(64));
}

#[tokio::test]
async fn plugin_lifecycle_action_requests_are_authenticated_and_bounded() {
    let workspace_id = WorkspaceId::new();
    let (app, service, _) = test_app(workspace_id);

    let response = app
        .clone()
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/plugins/actions"),
            Body::from(
                r#"{
                    "kind":"plugin.enable",
                    "plugin_id":"com.example.review",
                    "plugin_version":"1.0.0",
                    "expected_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }"#,
            ),
        ))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = json_body(response).await;
    assert!(body["run_id"].as_str().is_some());
    assert_eq!(body["state"], "approval_requested");
    {
        let commands = service
            .plugin_action_commands
            .lock()
            .expect("plugin action commands");
        assert_eq!(commands[0].workspace_id(), workspace_id);
        assert_eq!(commands[0].actor().subject(), "operator");
        assert_eq!(commands[0].kind(), "plugin.enable");
        assert_eq!(commands[0].plugin_id(), "com.example.review");
        assert_eq!(commands[0].plugin_version(), "1.0.0");
        assert_eq!(commands[0].expected_digest(), "a".repeat(64));
    }

    let response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/plugins/actions"),
            Body::from(
                r#"{
                    "kind":"plugin.settings.set",
                    "plugin_id":"com.example.review",
                    "plugin_version":"1.0.0",
                    "expected_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "arguments":{
                        "plugin_id":"com.example.review",
                        "plugin_version":"1.0.0",
                        "scope_type":"workspace",
                        "scope_id":"workspace",
                        "expected_version":4,
                        "config":{"mode":"local"},
                        "schema_digest":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
                    }
                }"#,
            ),
        ))
        .await
        .expect("settings response");

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let commands = service
        .plugin_action_commands
        .lock()
        .expect("plugin action commands");
    assert_eq!(commands[1].kind(), "plugin.settings.set");
    let Some(CanonicalValue::Object(arguments)) = commands[1].arguments() else {
        panic!("settings arguments");
    };
    let Some(CanonicalValue::Object(config)) = arguments.get("config") else {
        panic!("settings config");
    };
    assert_eq!(config.get("mode"), Some(&CanonicalValue::from("local")));
}

#[tokio::test]
async fn plugin_routes_reject_unknown_fields_and_oversized_pages() {
    let workspace_id = WorkspaceId::new();
    let (app, _, _) = test_app(workspace_id);

    let page_response = app
        .clone()
        .oneshot(request(
            "GET",
            format!("/api/v1/workspaces/{workspace_id}/plugins/staged?limit=500"),
            Body::empty(),
        ))
        .await
        .expect("page response");
    assert_eq!(page_response.status(), StatusCode::BAD_REQUEST);

    let body_response = app
        .oneshot(request(
            "POST",
            format!("/api/v1/workspaces/{workspace_id}/plugins/actions"),
            Body::from(
                r#"{
                    "kind":"plugin.enable",
                    "plugin_id":"com.example.review",
                    "plugin_version":"1.0.0",
                    "expected_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "surprise":true
                }"#,
            ),
        ))
        .await
        .expect("body response");
    assert_eq!(body_response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn plugin_detail_routes_preserve_service_conflict_and_unavailable_statuses() {
    let workspace_id = WorkspaceId::new();
    let (app, _, _) = test_app(workspace_id);

    let conflict = app
        .clone()
        .oneshot(request(
            "GET",
            format!(
                "/api/v1/workspaces/{workspace_id}/plugins/com.example.conflict/versions/1.0.0"
            ),
            Body::empty(),
        ))
        .await
        .expect("conflict response");
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    let conflict_body = json_body(conflict).await;
    assert_eq!(conflict_body["error"]["code"], "conflict");

    let unavailable = app
        .oneshot(request(
            "GET",
            format!(
                "/api/v1/workspaces/{workspace_id}/plugins/com.example.unavailable/versions/1.0.0"
            ),
            Body::empty(),
        ))
        .await
        .expect("unavailable response");
    assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let unavailable_body = json_body(unavailable).await;
    assert_eq!(unavailable_body["error"]["code"], "unavailable");
}
