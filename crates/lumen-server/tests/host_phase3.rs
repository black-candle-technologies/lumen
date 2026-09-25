//! Phase 3 host integration: the vertical slice across real seams.
//!
//! Wires the session supervisor, mediated tool catalog, model gateway,
//! Jev router, and authd client together with mock kernel/provider/sandbox
//! doubles and proves the host-side flow end to end:
//!
//!   authd login -> spawn Pi session -> Jev recommends model -> host
//!   rechecks -> set_model -> Pi tool request -> catalog decode ->
//!   envelope -> kernel decide -> sandbox run -> audit -> result +
//!   usage + audit ref -> terminate revokes leases + destroys identity.

use std::{path::PathBuf, sync::Arc, time::Duration};

use lumen_server::{
    AuthdClient, ChatMessage, CredentialVault, GatewayConfig, JevRouter, MemorySessionStore,
    MemorySpendPool, MockAuthdClient, MockJevRouter, MockKernelClient, MockProviderAdapter,
    MockSandboxRunner, MockVerdict, ModelGateway, ModelPolicy, ModelRequest, ModelSwitchDecision,
    PiToolRequest, SecretString, SessionStatus, SessionSupervisor, SizeBucket, SpendPool,
    SupervisorConfig, TaskProfile, ToolOutcome, ToolPipeline, apply_recommendation,
    default_catalog, now_ms, sha256_hex,
};
use tokio_util::sync::CancellationToken;

fn fixture_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fake-pi.sh")
}

fn test_config() -> SupervisorConfig {
    let script = fixture_script();
    let digest = sha256_hex(&std::fs::read(&script).unwrap());
    SupervisorConfig {
        pi_binary: script.clone(),
        pi_args: Vec::new(),
        pi_version: "fake-0.0.0".to_string(),
        pi_digest: digest.clone(),
        extension_path: script,
        extension_digest: digest,
        outbound_queue_depth: 8,
        max_line_bytes: 4096,
        malformed_threshold: 3,
        idle_timeout: Duration::from_secs(3600),
        max_lifetime: Duration::from_secs(3600),
        shutdown_grace: Duration::from_secs(2),
        watchdog_interval: Duration::from_millis(50),
        event_buffer: 64,
        stderr_line_cap: 16,
        ..SupervisorConfig::default()
    }
}

#[tokio::test]
async fn phase3_vertical_slice() {
    // 1. authd: token -> stable account ID.
    let authd = MockAuthdClient::new().with_token("user-token", "acct-7");
    let owner = authd.authenticate("user-token").await.unwrap();
    assert_eq!(owner.account_id.as_str(), "acct-7");

    // 2. Spawn a supervised Pi session for that account.
    let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
    let supervisor = SessionSupervisor::new(
        test_config(),
        kernel.clone(),
        Arc::new(default_catalog()),
        Arc::new(MemorySessionStore::new()),
    );
    let handle = supervisor.spawn_session(&owner).await.unwrap();
    assert_eq!(handle.status().await.unwrap(), SessionStatus::Running);
    assert!(handle.binding().await.unwrap().owner_is(&owner.account_id));

    // 3. Jev recommends a model; the host rechecks against lease policy.
    let jev = MockJevRouter::new(vec![Ok(MockJevRouter::recommend_model(
        "acme-large",
        "acme",
        60_000,
        1,
    ))]);
    let profile = TaskProfile {
        task_class: "codegen".to_string(),
        size_bucket: SizeBucket::Medium,
        latency_sensitive: false,
        sequence: 1,
    };
    let recommendation = jev.recommend(&profile).await.unwrap();
    let policy = ModelPolicy {
        allowed_models: vec!["acme-large".to_string()],
        allowed_providers: vec!["acme".to_string()],
        max_cost_micros_per_request: 1000,
        max_output_tokens: 1000,
    };
    let pool = MemorySpendPool::new(1_000_000);
    let decision = apply_recommendation(
        &recommendation,
        "acme-small",
        &policy,
        &pool,
        profile.sequence,
        now_ms(),
    );
    let ModelSwitchDecision::Switch { model, .. } = decision else {
        panic!("expected the host to approve the model switch");
    };
    handle.set_model(model).await.unwrap();

    // 4. Model gateway: credentials stay host-side; usage is normalized.
    let vault = Arc::new(CredentialVault::new());
    vault.insert("acme", SecretString::new("sk-test"));
    let mut gateway = ModelGateway::new(GatewayConfig::default(), vault);
    let adapter = Arc::new(MockProviderAdapter::new("acme", vec![]));
    gateway.register_adapter(adapter.clone());
    let response = gateway
        .complete(
            &ModelRequest {
                provider: "acme".to_string(),
                model: "acme-large".to_string(),
                messages: vec![ChatMessage {
                    role: "user".to_string(),
                    content: "write a test".to_string(),
                }],
                max_output_tokens: 100,
                cancel: CancellationToken::new(),
            },
            &policy,
            &pool,
        )
        .await
        .unwrap();
    assert!(response.usage.usage_known);
    assert!(adapter.saw_credential());
    let audit_record = response.redacted_audit_record();
    assert!(
        !serde_json::to_string(&audit_record)
            .unwrap()
            .contains("sk-test")
    );

    // 5. Tool pipeline: Pi typed request -> kernel -> sandbox -> audit.
    let pipeline = ToolPipeline::new(
        Arc::new(default_catalog()),
        kernel.clone(),
        Arc::new(MockSandboxRunner::new()),
    );
    let outcome = pipeline
        .handle(
            &PiToolRequest {
                id: "call-1".to_string(),
                tool: "bct.fs.read".to_string(),
                arguments: serde_json::json!({"path": "/tmp/x"}),
            },
            handle.binding().await.unwrap().session_subject.as_str(),
            &["lease-1".to_string()],
        )
        .await;
    let ToolOutcome::Completed {
        usage, audit_ref, ..
    } = outcome
    else {
        panic!("expected Completed, got {outcome:?}");
    };
    assert!(!audit_ref.event_id.is_empty());
    assert_eq!(usage.cpu_ms, 12);
    assert_eq!(kernel.decisions_made(), 1);
    assert_eq!(kernel.audit_log().len(), 2);

    // 6. Termination: leases revoked, identity destroyed, spend pool sane.
    let report = handle.terminate().await.unwrap();
    assert!(report.leases_revoked);
    assert!(report.identity_destroyed);
    assert!(report.revoke_error.is_none());
    assert_eq!(handle.status().await.unwrap(), SessionStatus::Terminated);
    assert!(!pool.quarantined());
}
