//! Exercises the worker assembly used by serve with real registration and TLS.
use super::*;
use lumen_control_plane::DatabaseCandidateCatalog;
use lumen_core::{
    context::{ContextSource, ContextSourceId, SourceProvenance, SourceProvenanceKind},
    model::{ReasoningProfile, ReasoningWireFormat},
    operator::OrchestrationControlPolicy,
    orchestration::{
        OrchestrationId, TaskGraph, TaskGraphProposal, TaskNodeKey, TaskNodeLimits,
        TaskNodeProposal, TaskNodeState, TaskOutputKind, TaskRequirements,
    },
    provider::{ModelCapabilities, ModelCapability},
    routing::{
        HealthObservation, HealthState, ModelPricing, ModelRoutingMetadata, OrchestrationBudget,
        RoutingPolicy,
    },
    worker::{WorkerAttemptState, WorkerRunBudget},
};
use lumen_server::ApiState;

async fn fixture() -> (Fixture, Arc<LocalRuntimeService>) {
    let mut f = Fixture::new().await;
    f.create("openai_compatible").await.unwrap();
    f.register("openai_compatible", json!(["public"]))
        .await
        .unwrap();
    f.config.runtime.max_model_turns = 1;
    f.config.runtime.max_wall_time_seconds = 10;
    let service = Arc::new(f.start().await);
    let db = &service.database;
    let profile = db
        .latest_model_profile(&ModelProfileId::parse("default-remote").unwrap())
        .await
        .unwrap()
        .unwrap();
    let t = now();
    db.append_model_routing_metadata(
        &ModelRoutingMetadata::new(
            profile.id().clone(),
            1,
            1,
            ReasoningWireFormat::None,
            BTreeMap::from([(ReasoningProfile::Balanced, None)]),
            ModelPricing::new(0, 0),
            BTreeMap::new(),
            t,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let health = HealthObservation::new(
        HealthState::Healthy,
        1,
        t,
        TimestampMillis::new(t.as_u64() + 60_000),
    )
    .unwrap();
    db.append_provider_health(profile.provider_id(), 1, &health)
        .await
        .unwrap();
    db.append_model_health(profile.id(), 1, &health)
        .await
        .unwrap();
    (f, service)
}
fn proposal(count: usize, tools: bool) -> TaskGraphProposal {
    TaskGraphProposal::new(
        (0..count)
            .map(|i| {
                TaskNodeProposal::new(
                    TaskNodeKey::parse(format!("task-{i}")).unwrap(),
                    "produce a public answer",
                    TaskOutputKind::Text,
                    [],
                    TaskRequirements::new(
                        ModelCapabilities::new([ModelCapability::Text]),
                        [],
                        DataClass::Public,
                        [],
                        if tools {
                            vec![lumen_core::action::ActionKind::new("filesystem.write").unwrap()]
                        } else {
                            Vec::new()
                        },
                    )
                    .unwrap(),
                    TaskNodeLimits::new(2000, 2000, 2).unwrap(),
                    None,
                )
                .unwrap()
            })
            .collect(),
    )
}
async fn durable_graph(f: &Fixture, db: &Database, count: usize, tools: bool) -> TaskGraph {
    let t = now();
    let (profiles, policies) = DatabaseCandidateCatalog::new(
        db.clone(),
        Vec::new(),
        WorkerRunBudget::new(1, 1, 10_000, 4096).unwrap(),
    )
    .catalog(f.config.workspace_id())
    .await
    .unwrap();
    let g = TaskGraph::from_proposal(
        OrchestrationId::new(),
        f.config.workspace_id(),
        1,
        f.config.bootstrap_principal(),
        proposal(count, tools),
        t,
    )
    .unwrap();
    db.append_task_graph(&g, &profiles, &policies)
        .await
        .unwrap();
    let source = ContextSource::new(
        ContextSourceId::new(),
        f.config.workspace_id(),
        DataClass::Public,
        [],
        SourceProvenance::new(SourceProvenanceKind::UserMessage, "dispatch-regression").unwrap(),
        "public input".into(),
        f.config.bootstrap_principal(),
        t,
    )
    .unwrap();
    db.append_context_source(&source).await.unwrap();
    db.link_orchestration_input_source(g.orchestration_id(), source.id(), t)
        .await
        .unwrap();
    db.append_orchestration_budget(
        &OrchestrationBudget::new(
            g.orchestration_id(),
            1,
            100,
            100_000,
            100_000,
            0,
            1,
            60_000,
            t,
            t,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    db.append_control_policy(
        &OrchestrationControlPolicy::new(
            g.orchestration_id(),
            1,
            true,
            false,
            ReasoningProfile::Balanced,
            t,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    db.reconcile_task_readiness(g.orchestration_id(), t)
        .await
        .unwrap();
    g
}
async fn wait_attempts(db: &Database, g: &TaskGraph, count: usize, state: WorkerAttemptState) {
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let attempts = db
                .worker_attempts_for_orchestration(g.orchestration_id())
                .await
                .unwrap();
            if attempts.len() == count && attempts.iter().all(|a| a.state() == state) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    let attempts = db
        .worker_attempts_for_orchestration(g.orchestration_id())
        .await
        .unwrap();
    assert!(
        result.is_ok(),
        "expected {count} {state:?} attempts, got {:?}",
        attempts
            .iter()
            .map(|a| (a.state(), a.diagnostic()))
            .collect::<Vec<_>>()
    );
}
fn delayed_reply() -> tls::Reply {
    let mut reply = tls::Reply::json(
        json!({"choices":[{"finish_reason":"stop","message":{"content":"worker result"}}]}),
    );
    reply.delay = Duration::from_millis(700);
    reply
}

#[tokio::test]
async fn admission_failure_releases_route_and_restart_recovers_unadmitted_route() {
    let (f, service) = fixture().await;
    let (_, poller) = crate::start_orchestration_workers(&f.config, &service.database, &service)
        .await
        .unwrap()
        .unwrap();
    poller.request_stop();
    poller.join().await;
    let g = durable_graph(&f, &service.database, 1, false).await;
    let scheduler = service.worker_scheduler.lock().await.clone().unwrap();
    let catalog = DatabaseCandidateCatalog::new(
        service.database.clone(),
        service.worker_grants().unwrap(),
        WorkerRunBudget::new(1, 1, 10_000, 4096).unwrap(),
    );
    let n = g.nodes().next().unwrap();
    let candidates = catalog
        .candidates(&g, n, g.created_by(), now())
        .await
        .unwrap();
    let assignment = scheduler
        .prepare_routed_assignment(
            &g,
            n,
            g.created_by().clone(),
            candidates,
            ReasoningProfile::Balanced,
            RoutingPolicy::new(true, false),
            now(),
        )
        .await
        .unwrap();
    assert!(
        service
            .database
            .active_routing_dispatch(g.orchestration_id(), 1, n.id())
            .await
            .unwrap()
            .is_some()
    );
    assert!(scheduler.shutdown(Duration::from_secs(1)).await);
    assert!(
        scheduler
            .dispatch_prepared(assignment, now())
            .await
            .is_err()
    );
    assert!(
        service
            .database
            .active_routing_dispatch(g.orchestration_id(), 1, n.id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        service
            .database
            .worker_attempts_for_orchestration(g.orchestration_id())
            .await
            .unwrap()
            .is_empty()
    );
    // Simulate a crash in the committed-reservation/pre-admission window.
    let candidates = catalog
        .candidates(&g, n, g.created_by(), now())
        .await
        .unwrap();
    scheduler
        .prepare_routed_assignment(
            &g,
            n,
            g.created_by().clone(),
            candidates,
            ReasoningProfile::Balanced,
            RoutingPolicy::new(true, false),
            now(),
        )
        .await
        .unwrap();
    service.shutdown().await;
    service.database.clone().close().await;
    let service = Arc::new(f.start().await);
    let (_, poller) = crate::start_orchestration_workers(&f.config, &service.database, &service)
        .await
        .unwrap()
        .unwrap();
    wait_attempts(&service.database, &g, 1, WorkerAttemptState::Completed).await;
    poller.request_stop();
    poller.join().await;
    assert!(service.shutdown().await.is_clean());
}

#[tokio::test]
async fn serve_assembly_recovers_ready_work_and_serializes_two_tasks() {
    let (f, service) = fixture().await;
    let g = durable_graph(&f, &service.database, 2, false).await;
    // Close and reopen the database before recovery, with no API kick.
    service.shutdown().await;
    service.database.clone().close().await;
    let service = Arc::new(f.start().await);
    f.server
        .replies
        .lock()
        .await
        .extend([delayed_reply(), delayed_reply()]);
    let (_, poller) = crate::start_orchestration_workers(&f.config, &service.database, &service)
        .await
        .unwrap()
        .unwrap();
    wait_attempts(&service.database, &g, 1, WorkerAttemptState::Running).await;
    tokio::time::sleep(Duration::from_millis(350)).await;
    let snap = service
        .database
        .latest_orchestration_snapshot(g.orchestration_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        snap.states()
            .filter(|s| s.state() == TaskNodeState::Running)
            .count(),
        1
    );
    assert_eq!(
        snap.states()
            .filter(|s| s.state() == TaskNodeState::Ready)
            .count(),
        1
    );
    assert_eq!(
        service
            .database
            .budget_snapshot(g.orchestration_id(), now())
            .await
            .unwrap()
            .unwrap()
            .remaining_concurrency,
        0
    );
    wait_attempts(&service.database, &g, 2, WorkerAttemptState::Completed).await;
    poller.request_stop();
    poller.join().await;
    assert!(service.shutdown().await.is_clean());
    f.no_leaks().await;
}

#[tokio::test]
async fn serve_assembly_dispatches_after_one_create_api_request() {
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let (f, service) = fixture().await;
    f.server.replies.lock().await.push_back(tls::Reply::json(json!({"choices":[{"finish_reason":"stop","message":{"content":serde_json::to_string(&proposal(1, false)).unwrap()}}]})));
    let (control, poller) =
        crate::start_orchestration_workers(&f.config, &service.database, &service)
            .await
            .unwrap()
            .unwrap();
    let state = ApiState::new(
        service.clone(),
        EventBroker::new(128),
        "dispatch-test-token",
        f.config.bootstrap_principal(),
        [f.config.workspace_id()].into(),
        crate::api_sandbox_report(&super::super::security_tests::RecordingSandbox::new().report()),
    )
    .unwrap()
    .with_orchestration_service(control);
    let response = lumen_server::router(state).oneshot(axum::http::Request::builder()
        .method("POST").uri(format!("/api/v1/workspaces/{}/orchestrations", f.config.workspace_id()))
        .header("authorization", "Bearer dispatch-test-token").header("content-type", "application/json")
        .body(axum::body::Body::from(json!({"prompt":"public plan","data_class":"public","reasoning":"balanced","remote_allowed":true,"prefer_local":false,"max_model_calls":100,"max_input_tokens":100000,"max_output_tokens":100000,"max_remote_cost_micros":0,"max_concurrent_workers":1,"max_wall_time_millis":60000}).to_string())).unwrap()).await.unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let _: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let ids = service
        .database
        .orchestration_ids_for_workspace(f.config.workspace_id())
        .await
        .unwrap();
    let g = service
        .database
        .latest_orchestration_snapshot(ids[0])
        .await
        .unwrap()
        .unwrap()
        .graph()
        .clone();
    wait_attempts(&service.database, &g, 1, WorkerAttemptState::Completed).await;
    assert_eq!(f.server.requests.lock().await.len(), 2);
    poller.request_stop();
    poller.join().await;
    assert!(service.shutdown().await.is_clean());
}

#[tokio::test]
async fn overlapping_ticks_and_shutdown_do_not_admit_duplicate_workers() {
    let (f, service) = fixture().await;
    let g = durable_graph(&f, &service.database, 2, false).await;
    f.server.replies.lock().await.push_back(delayed_reply());
    let (control, poller) =
        crate::start_orchestration_workers(&f.config, &service.database, &service)
            .await
            .unwrap()
            .unwrap();
    let stop = CancellationToken::new();
    let (a, b) = tokio::join!(
        control.dispatch_workspace_once(now(), &stop),
        control.dispatch_workspace_once(now(), &stop)
    );
    a.unwrap();
    b.unwrap();
    wait_attempts(&service.database, &g, 1, WorkerAttemptState::Running).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (shutdown, stopped) = tokio::sync::oneshot::channel();
    let running_service = service.clone();
    let server = tokio::spawn(async move {
        let report = super::super::security_tests::RecordingSandbox::new().report();
        crate::serve_listener_until_shutdown(
            listener,
            axum::Router::new(),
            EventBroker::new(128),
            running_service,
            Some(poller),
            (
                std::path::Path::new("test-lumen.toml"),
                "dispatch-test",
                &report,
            ),
            async {
                let _ = stopped.await;
            },
        )
        .await
    });
    shutdown.send(()).unwrap();
    server.await.unwrap().unwrap();
    let attempts = service
        .database
        .worker_attempts_for_orchestration(g.orchestration_id())
        .await
        .unwrap();
    assert_eq!(attempts.len(), 1);
    assert!(attempts[0].state().is_terminal());
    // Even an independent driver cannot admit into the sealed scheduler.
    control.dispatch_workspace_once(now(), &stop).await.unwrap();
    assert_eq!(
        service
            .database
            .worker_attempts_for_orchestration(g.orchestration_id())
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        service
            .database
            .active_routing_dispatch(
                g.orchestration_id(),
                1,
                g.nodes()
                    .find(|n| n.id() != attempts[0].assignment().task_node_id())
                    .unwrap()
                    .id()
            )
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn awaiting_approval_is_not_redispatched_and_rejection_stays_terminal() {
    use lumen_core::{
        context::ModelDataPolicy,
        provider::{LocalRuntimeKind, ModelProfile, ModelTrustZone, ProviderConfig},
    };
    use lumen_db::{ModelEndpointClass, ModelProviderRevision};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::path};
    let (f, service) = fixture().await;
    // Tool-bearing work requires LocalTrusted under the existing trust gate.
    let local = MockServer::start().await;
    let p = ProviderConfig::local_openai_compatible(
        ProviderId::parse("trusted-local").unwrap(),
        1,
        format!("{}/v1/", local.uri()),
        LocalRuntimeKind::Ollama,
        true,
        None,
    )
    .unwrap();
    let m = ModelProfile::new(
        ModelProfileId::parse("trusted-text").unwrap(),
        1,
        p.id().clone(),
        1,
        "local",
        true,
        ModelCapabilities::new([ModelCapability::Text, ModelCapability::ToolCalling]),
        8192,
        ModelTrustZone::LocalTrusted,
        1,
        0,
    )
    .unwrap();
    let db = &service.database;
    let t = now();
    db.append_provider_config(&p, t).await.unwrap();
    db.append_model_profile(&m, t).await.unwrap();
    db.append_model_data_policy(
        &ModelDataPolicy::new(
            f.config.workspace_id(),
            m.id().clone(),
            1,
            m.trust_zone(),
            1,
            [DataClass::Public],
            [],
            true,
            t,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    db.append_model_provider_revision(
        &ModelProviderRevision::new(
            p.id().clone(),
            1,
            ModelEndpointClass::Local,
            lumen_core::egress::DestinationScope::parse("https://localhost.localdomain/v1/")
                .unwrap(),
            "local",
            true,
            0,
            None,
            [DataClass::Public],
            t,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    db.append_model_routing_metadata(
        &ModelRoutingMetadata::new(
            m.id().clone(),
            1,
            1,
            ReasoningWireFormat::None,
            BTreeMap::from([(ReasoningProfile::Balanced, None)]),
            ModelPricing::new(0, 0),
            BTreeMap::new(),
            t,
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let health = HealthObservation::new(
        HealthState::Healthy,
        0,
        t,
        TimestampMillis::new(t.as_u64() + 60_000),
    )
    .unwrap();
    db.append_provider_health(p.id(), 1, &health).await.unwrap();
    db.append_model_health(m.id(), 1, &health).await.unwrap();
    let g = durable_graph(&f, &service.database, 1, true).await;
    Mock::given(path("/v1/chat/completions")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"choices":[{"finish_reason":"tool_calls","message":{"content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"filesystem_write","arguments":"{\"path\":\"result.txt\",\"content\":\"hello\"}"}}]}}]}))).mount(&local).await;
    let (_, poller) = crate::start_orchestration_workers(&f.config, &service.database, &service)
        .await
        .unwrap()
        .unwrap();
    wait_attempts(
        &service.database,
        &g,
        1,
        WorkerAttemptState::AwaitingApproval,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(550)).await;
    assert_eq!(
        service
            .database
            .worker_attempts_for_orchestration(g.orchestration_id())
            .await
            .unwrap()
            .len(),
        1
    );
    let approvals = service
        .database
        .list_pending_approvals(f.config.workspace_id(), now())
        .await
        .unwrap();
    service
        .decide_approval(ApprovalDecisionCommand::new(
            f.config.workspace_id(),
            approvals[0].approval_id(),
            f.config.bootstrap_principal(),
            ApprovalDecision::Reject,
        ))
        .await
        .unwrap();
    wait_attempts(&service.database, &g, 1, WorkerAttemptState::Failed).await;
    assert!(!f.config.workspace.path.join("result.txt").exists());
    poller.request_stop();
    poller.join().await;
    assert!(service.shutdown().await.is_clean());
}

#[tokio::test]
async fn cancelled_quarantined_and_expired_graphs_are_not_dispatched() {
    let (f, service) = fixture().await;
    let cancelled = durable_graph(&f, &service.database, 1, false).await;
    service
        .database
        .request_orchestration_cancellation(
            cancelled.orchestration_id(),
            &f.config.bootstrap_principal(),
            now(),
        )
        .await
        .unwrap();
    let quarantined = durable_graph(&f, &service.database, 1, false).await;
    let report = lumen_core::trust_gate::OrchestrationIntegrityReport::new(
        quarantined.orchestration_id(),
        f.config.workspace_id(),
        [lumen_core::trust_gate::IntegrityIssue::GraphDigest].into(),
        now(),
    )
    .unwrap();
    service
        .database
        .record_recovery_integrity(&report)
        .await
        .unwrap();
    let expired = durable_graph(&f, &service.database, 1, false).await;
    let budget = service
        .database
        .budget_snapshot(expired.orchestration_id(), now())
        .await
        .unwrap()
        .unwrap()
        .budget;
    service
        .database
        .append_orchestration_budget(
            &OrchestrationBudget::new(
                expired.orchestration_id(),
                2,
                budget.max_model_calls,
                budget.max_input_tokens,
                budget.max_output_tokens,
                budget.max_remote_cost_micros,
                1,
                1,
                budget.window_started_at,
                now(),
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2)).await;
    let (control, poller) =
        crate::start_orchestration_workers(&f.config, &service.database, &service)
            .await
            .unwrap()
            .unwrap();
    poller.request_stop();
    poller.join().await;
    let stop = CancellationToken::new();
    control
        .dispatch_workspace_once(TimestampMillis::new(now().as_u64() + 60_001), &stop)
        .await
        .unwrap();
    for g in [&cancelled, &quarantined, &expired] {
        assert!(
            service
                .database
                .worker_attempts_for_orchestration(g.orchestration_id())
                .await
                .unwrap()
                .is_empty()
        );
    }
    assert!(
        service
            .database
            .latest_orchestration_snapshot(expired.orchestration_id())
            .await
            .unwrap()
            .unwrap()
            .states()
            .all(|s| s.state() == TaskNodeState::Blocked)
    );
    assert!(service.shutdown().await.is_clean());
}
