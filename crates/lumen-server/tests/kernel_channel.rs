//! Kernel channel integration tests: the typed Pi-to-host mediation
//! path over the Unix socket.
//!
//! Each test serves a real [`KernelChannel`] on a private socket and
//! speaks the JSONL protocol as the BCT extension would. The fake
//! resolver stands in for the session supervisor's credential registry.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use lumen_server::{
    ACTION_ENVELOPE_VERSION, ACTION_START_DEADLINE_SECS, ActionEnvelope, ChannelDecision,
    ChannelDeps, ChannelFuture, ChannelRequest, ChannelResponse, ChannelSession,
    ChannelSessionResolver, EffectClass, FailCommitSandbox, KERNEL_CHANNEL_PROTOCOL, KernelChannel,
    KernelChannelConfig, MockKernelClient, MockSandboxRunner, MockVerdict, SandboxRunner,
    SessionId, deadline_rfc3339, default_catalog,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct FakeResolver {
    sessions: Mutex<HashMap<String, ChannelSession>>,
}

impl ChannelSessionResolver for FakeResolver {
    fn resolve_session<'a>(
        &'a self,
        credential: &'a str,
    ) -> ChannelFuture<'a, Option<ChannelSession>> {
        Box::pin(async move { self.sessions.lock().unwrap().get(credential).cloned() })
    }
}

struct Harness {
    _channel: KernelChannel,
    kernel: Arc<MockKernelClient>,
    sandbox: Arc<MockSandboxRunner>,
    socket: PathBuf,
    subject: String,
    credential: String,
}

async fn serve(
    name: &str,
    kernel: MockKernelClient,
    sandbox: Arc<MockSandboxRunner>,
    child_pid: Option<u32>,
    verify_peer_pid: bool,
    max_request_bytes: usize,
) -> Harness {
    let dir = std::env::temp_dir().join(format!(
        "lumen-ch-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("kernel.sock");
    let subject = format!("lumen-session:{name}");
    let credential = format!("cred-{name}");

    let mut sessions = HashMap::new();
    sessions.insert(
        credential.clone(),
        ChannelSession {
            session_id: SessionId::new(),
            subject: subject.clone(),
            child_pid,
        },
    );

    let kernel = Arc::new(kernel);
    let config = KernelChannelConfig {
        socket_path: socket.clone(),
        max_request_bytes,
        request_timeout: Duration::from_secs(10),
        max_connections: 8,
        verify_peer_pid,
    };
    let deps = ChannelDeps {
        catalog: Arc::new(default_catalog()),
        kernel: kernel.clone(),
        sandbox: sandbox.clone(),
        sessions: Arc::new(FakeResolver {
            sessions: Mutex::new(sessions),
        }),
    };
    let channel = KernelChannel::serve(config, deps).await.unwrap();
    // The listener is up once serve returns; the accept loop is spawned.
    Harness {
        _channel: channel,
        kernel,
        sandbox,
        socket,
        subject,
        credential,
    }
}

/// A valid envelope for `bct.fs.read`, bound to `subject`.
fn valid_envelope(subject: &str) -> ActionEnvelope {
    let catalog = default_catalog();
    let args = catalog
        .decode("bct.fs.read", &serde_json::json!({"path": "/tmp/x"}))
        .unwrap();
    let (resources, effects) = catalog.project("bct.fs.read", &args).unwrap();
    let tool = catalog.tool_ref("bct.fs.read").unwrap();
    ActionEnvelope {
        protocol_version: ACTION_ENVELOPE_VERSION,
        action_id: uuid::Uuid::new_v4().to_string(),
        session_id: subject.to_string(),
        tool,
        arguments: serde_json::to_value(args.fields()).unwrap(),
        input_hashes: Vec::new(),
        resources,
        lease_chain: vec!["lease-1".to_string()],
        nonce: uuid::Uuid::new_v4().to_string(),
        expires_at: deadline_rfc3339(ACTION_START_DEADLINE_SECS),
        expected_effects: effects,
    }
}

fn request_line(credential: &str, envelope: &ActionEnvelope) -> Vec<u8> {
    let mut line = serde_json::to_vec(&ChannelRequest {
        protocol: KERNEL_CHANNEL_PROTOCOL.to_string(),
        credential: credential.to_string(),
        envelope: envelope.clone(),
    })
    .unwrap();
    line.push(b'\n');
    line
}

async fn roundtrip(socket: &Path, line: &[u8]) -> ChannelResponse {
    let stream = UnixStream::connect(socket).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(line).await.unwrap();
    write_half.shutdown().await.unwrap();
    let mut reader = BufReader::new(read_half);
    let mut out = Vec::new();
    reader.read_until(b'\n', &mut out).await.unwrap();
    assert!(!out.is_empty(), "channel closed without a response line");
    serde_json::from_slice(&out).unwrap()
}

fn allow_harness_args() -> (
    MockKernelClient,
    Arc<MockSandboxRunner>,
    Option<u32>,
    bool,
    usize,
) {
    (
        MockKernelClient::new().with_verdict(MockVerdict::Allow),
        Arc::new(MockSandboxRunner::new()),
        // The test process itself plays the extension: peer validation
        // against our own pid exercises the real check positively.
        Some(std::process::id()),
        true,
        1024 * 1024,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn allow_roundtrip_returns_result_usage_and_audit_ref() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("allow", kernel, sandbox, child_pid, verify, max_bytes).await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    assert_eq!(response.protocol, KERNEL_CHANNEL_PROTOCOL);
    assert!(
        matches!(
            response.decision,
            Some(ChannelDecision::Allow { version: 1 })
        ),
        "got: {response:?}"
    );
    assert!(response.error.is_none());
    let result = response.result.unwrap();
    assert_eq!(result["exit_code"], 0);
    let usage = response.usage.unwrap();
    assert_eq!(usage.cpu_ms, 12);
    assert!(!response.audit_ref.unwrap().event_id.is_empty());
    assert_eq!(h.kernel.decisions_made(), 1);
    assert_eq!(h.sandbox.committed_count(), 1);
}

#[tokio::test]
async fn wrong_credential_is_rejected() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("badcred", kernel, sandbox, child_pid, verify, max_bytes).await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line("wrong-credential", &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "auth");
    assert!(response.decision.is_none());
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn peer_pid_mismatch_is_rejected() {
    let (kernel, sandbox, _, _, max_bytes) = allow_harness_args();
    // A child pid no real process has: the test process (the actual
    // peer) cannot match it.
    let h = serve("peerpid", kernel, sandbox, Some(u32::MAX), true, max_bytes).await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "auth");
    assert!(error.detail.contains("peer process"));
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn oversized_request_is_rejected_before_parsing() {
    let (kernel, sandbox, child_pid, verify, _) = allow_harness_args();
    let h = serve("big", kernel, sandbox, child_pid, verify, 64).await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "too_large");
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn malformed_json_is_rejected() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("malformed", kernel, sandbox, child_pid, verify, max_bytes).await;

    let response = roundtrip(&h.socket, b"this is not json\n").await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "malformed");
    assert_eq!(h.kernel.decisions_made(), 0);
}

#[tokio::test]
async fn wrong_protocol_is_rejected() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("protocol", kernel, sandbox, child_pid, verify, max_bytes).await;

    let envelope = valid_envelope(&h.subject);
    let mut line = serde_json::to_vec(&serde_json::json!({
        "protocol": "lumen-kernel/999",
        "credential": h.credential,
        "envelope": envelope,
    }))
    .unwrap();
    line.push(b'\n');
    let response = roundtrip(&h.socket, &line).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "protocol");
    assert_eq!(h.kernel.decisions_made(), 0);
}

#[tokio::test]
async fn session_subject_mismatch_is_rejected() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("mismatch", kernel, sandbox, child_pid, verify, max_bytes).await;

    let mut envelope = valid_envelope(&h.subject);
    envelope.session_id = "lumen-session:someone-else".to_string();
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "invalid_request");
    assert!(error.detail.contains("session"), "got: {}", error.detail);
    // The envelope never reaches the kernel: no decision, no sandbox.
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn lying_resource_projection_is_rejected() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("lying", kernel, sandbox, child_pid, verify, max_bytes).await;

    // The extension declares an effect the host projection does not
    // produce: the request is rejected before the kernel is consulted.
    let mut envelope = valid_envelope(&h.subject);
    envelope.expected_effects.push(EffectClass::Network);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "invalid_request");
    assert!(error.detail.contains("projection"), "got: {}", error.detail);
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn expired_envelope_is_rejected() {
    let (kernel, sandbox, child_pid, verify, max_bytes) = allow_harness_args();
    let h = serve("expired", kernel, sandbox, child_pid, verify, max_bytes).await;

    let mut envelope = valid_envelope(&h.subject);
    envelope.expires_at = "2000-01-01T00:00:00Z".to_string();
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "invalid_request");
    assert!(error.detail.contains("expir"), "got: {}", error.detail);
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn deny_is_rendered_exactly_once() {
    let sandbox = Arc::new(MockSandboxRunner::new());
    let kernel = MockKernelClient::new()
        .with_verdict(MockVerdict::Deny)
        .with_deny_reason("no lease for this tool");
    let h = serve(
        "deny",
        kernel,
        sandbox,
        Some(std::process::id()),
        true,
        1024 * 1024,
    )
    .await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    match response.decision {
        Some(ChannelDecision::Deny { version: 1, reason }) => {
            assert!(reason.contains("no lease"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
    assert!(response.error.is_none());
    // Terminal render: exactly one decision, no sandbox contact, no
    // hidden retry.
    assert_eq!(h.kernel.decisions_made(), 1);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn pending_approval_is_rendered() {
    let sandbox = Arc::new(MockSandboxRunner::new());
    let kernel = MockKernelClient::new().with_verdict(MockVerdict::PendingApproval);
    let h = serve(
        "pending",
        kernel,
        sandbox,
        Some(std::process::id()),
        true,
        1024 * 1024,
    )
    .await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    assert!(
        matches!(
            response.decision,
            Some(ChannelDecision::PendingApproval { version: 1, .. })
        ),
        "got: {response:?}"
    );
    assert_eq!(h.kernel.decisions_made(), 1);
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn audit_failure_aborts_staged_effects() {
    let sandbox = Arc::new(MockSandboxRunner::new());
    let kernel = MockKernelClient::new().with_verdict(MockVerdict::Allow);
    kernel.fail_audit(true);
    let h = serve(
        "auditfail",
        kernel,
        sandbox,
        Some(std::process::id()),
        true,
        1024 * 1024,
    )
    .await;

    let envelope = valid_envelope(&h.subject);
    let response = roundtrip(&h.socket, &request_line(&h.credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "fault");
    assert!(
        error.detail.contains("not committed"),
        "got: {}",
        error.detail
    );
    assert!(response.audit_ref.is_none());
    // Staged exactly once, aborted on drop, never committed.
    assert_eq!(h.sandbox.staged_count(), 1);
    assert_eq!(h.sandbox.committed_count(), 0);
    assert_eq!(h.sandbox.aborted_count(), 1);
}

#[tokio::test]
async fn commit_failure_records_no_completion_claim() {
    let dir = std::env::temp_dir().join(format!(
        "lumen-ch-commitfail-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("kernel.sock");
    let subject = "lumen-session:commitfail".to_string();
    let credential = "cred-commitfail".to_string();

    let mut sessions = HashMap::new();
    sessions.insert(
        credential.clone(),
        ChannelSession {
            session_id: SessionId::new(),
            subject: subject.clone(),
            child_pid: Some(std::process::id()),
        },
    );
    let kernel = Arc::new(MockKernelClient::new().with_verdict(MockVerdict::Allow));
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(FailCommitSandbox::new());
    let config = KernelChannelConfig {
        socket_path: socket.clone(),
        max_request_bytes: 1024 * 1024,
        request_timeout: Duration::from_secs(10),
        max_connections: 8,
        verify_peer_pid: true,
    };
    let deps = ChannelDeps {
        catalog: Arc::new(default_catalog()),
        kernel: kernel.clone(),
        sandbox,
        sessions: Arc::new(FakeResolver {
            sessions: Mutex::new(sessions),
        }),
    };
    let _channel = KernelChannel::serve(config, deps).await.unwrap();

    let envelope = valid_envelope(&subject);
    let response = roundtrip(&socket, &request_line(&credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(error.code, "fault");
    assert!(
        error.detail.contains("commit failed"),
        "got: {}",
        error.detail
    );
    assert!(response.audit_ref.is_none());
    // The honest intention event is durable; no completion event may
    // exist because nothing completed.
    let log = kernel.audit_log();
    let kinds: Vec<&str> = log.iter().map(|(event, _)| event.kind.as_str()).collect();
    assert_eq!(kinds, vec!["tool_staged"]);
}
