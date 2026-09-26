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
    KernelChannelConfig, MockKernelClient, MockSandboxRunner, MockVerdict, Obligation,
    SandboxError, SandboxFuture, SandboxRunner, SessionId, StagedExecution, deadline_rfc3339,
    default_catalog,
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
    serve_with_timeout(
        name,
        kernel,
        sandbox,
        child_pid,
        verify_peer_pid,
        max_request_bytes,
        Duration::from_secs(10),
    )
    .await
}

async fn serve_with_timeout(
    name: &str,
    kernel: MockKernelClient,
    sandbox: Arc<MockSandboxRunner>,
    child_pid: Option<u32>,
    verify_peer_pid: bool,
    max_request_bytes: usize,
    request_timeout: Duration,
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
        sandbox_gid: 65534,
        max_request_bytes,
        request_timeout,
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
async fn socket_is_parent_owned_group_mediated() {
    use std::os::unix::fs::MetadataExt;
    let (kernel, sandbox, child_pid, verify_peer_pid, max_request_bytes) = allow_harness_args();
    let h = serve(
        "sockown",
        kernel,
        sandbox,
        child_pid,
        verify_peer_pid,
        max_request_bytes,
    )
    .await;
    let meta = std::fs::metadata(&h.socket).unwrap();
    let is_root = unsafe { libc::getuid() } == 0;
    if is_root {
        // Parent-owned, group `sandbox_gid`, connect-only for the
        // group: a dedicated-map child dials via group write, a 1:1
        // fallback child as the owner.
        assert_eq!(meta.uid(), 0);
        assert_eq!(meta.gid(), 65534);
        assert_eq!(meta.mode() & 0o777, 0o620);
    } else {
        // A non-root supervisor cannot chown to the sandbox gid -- but
        // it also cannot map the dedicated uid, so the owner-only
        // fallback mode is exactly right.
        assert_eq!(meta.mode() & 0o777, 0o600);
    }
}

#[tokio::test]
async fn malformed_authority_is_audited_without_secrets_or_sandbox_dispatch() {
    let (kernel, sandbox, child_pid, verify, max) = allow_harness_args();
    let h = serve("strictwire", kernel, sandbox, child_pid, verify, max).await;
    let mut request: serde_json::Value =
        serde_json::from_slice(&request_line(&h.credential, &valid_envelope(&h.subject))).unwrap();
    let marker = "SECRET_SENTINEL_NOT_A_REAL_SECRET";
    request["envelope"]["tool"][marker] = serde_json::json!(marker);
    let line = format!("{request}\n");
    let response = roundtrip(&h.socket, line.as_bytes()).await;
    assert!(!serde_json::to_string(&response).unwrap().contains(marker));
    assert_eq!(response.error.unwrap().code, "malformed");
    assert!(response.decision.is_none());
    assert_eq!(h.sandbox.call_count(), 0);
    let events = h.kernel.audit_log();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0.kind, "transport_rejected");
    assert_eq!(events[0].0.session_id, "unidentified");
    assert!(
        !serde_json::to_string(&events[0].0)
            .unwrap()
            .contains(marker)
    );
    h.kernel.fail_audit(true);
    let response = roundtrip(&h.socket, line.as_bytes()).await;
    assert_eq!(response.error.unwrap().code, "audit");
    assert!(response.decision.is_none());
    assert_eq!(h.sandbox.call_count(), 0);
}

#[tokio::test]
async fn malformed_authority_audit_timeout_never_dispatches_or_retries() {
    let (kernel, sandbox, child_pid, verify, max) = allow_harness_args();
    kernel.delay_audit(Duration::from_secs(30));
    let h = serve_with_timeout(
        "auditwait",
        kernel,
        sandbox,
        child_pid,
        verify,
        max,
        Duration::from_millis(100),
    )
    .await;
    let response =
        tokio::time::timeout(Duration::from_secs(2), roundtrip(&h.socket, b"{invalid\n"))
            .await
            .unwrap();
    assert_eq!(response.error.unwrap().code, "audit");
    assert!(response.decision.is_none());
    assert_eq!(h.sandbox.call_count(), 0);
    assert_eq!(h.kernel.decisions_made(), 0);
    assert!(h.kernel.audit_log().is_empty());
}

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
    assert_eq!(error.code, "malformed");
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
        sandbox_gid: 65534,
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

/// Sandbox whose `stage` never resolves: mediation always exceeds the
/// channel deadline.
struct HangingSandbox;

impl SandboxRunner for HangingSandbox {
    fn stage<'a>(
        &'a self,
        _envelope: &'a ActionEnvelope,
        _lease_id: &'a str,
        _obligations: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>> {
        Box::pin(async move {
            std::future::pending::<Result<Box<dyn StagedExecution>, SandboxError>>().await
        })
    }
}

fn test_socket_dir(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "lumen-ch-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("kernel.sock");
    (dir, socket)
}

/// A mediation that exceeds the channel deadline must surface as
/// `effect_uncertain` (reconcile by action digest), never as a plain
/// `timeout` error: the effect may have committed while the deadline
/// fired, and a plain timeout invites the extension to blindly retry
/// and double-execute.
#[tokio::test]
async fn mediation_timeout_is_uncertain_not_a_plain_timeout() {
    let (_dir, socket) = test_socket_dir("medtimeout");
    let subject = "lumen-session:medtimeout".to_string();
    let credential = "cred-medtimeout".to_string();

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
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(HangingSandbox);
    let config = KernelChannelConfig {
        socket_path: socket.clone(),
        sandbox_gid: 65534,
        max_request_bytes: 1024 * 1024,
        request_timeout: Duration::from_millis(300),
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
    let expected_digest = envelope.digest().unwrap();
    let response = roundtrip(&socket, &request_line(&credential, &envelope)).await;

    let error = response.error.unwrap();
    assert_eq!(
        error.code, "effect_uncertain",
        "mediation timeout must not be a plain timeout error: {error:?}"
    );
    assert!(response.decision.is_none());
    assert!(response.result.is_none());
    assert_eq!(
        response.action_digest.as_deref(),
        Some(expected_digest.as_str()),
        "the digest keys reconciliation"
    );
    assert!(
        error.detail.contains("may have committed"),
        "got: {}",
        error.detail
    );
    assert!(error.detail.contains(&expected_digest));
    // The pipeline ran exactly once: the detached task is left
    // running, never retried, and the client is told to reconcile by
    // digest rather than resubmit the action.
    assert_eq!(kernel.decisions_made(), 1);
}

/// A peer that floods the channel without ever sending a newline must
/// be rejected at the bound without the server waiting for the rest
/// of the stream, a newline, or EOF. (The unbounded `read_until`
/// this replaces would have blocked here until the peer finished or
/// closed, after buffering everything.)
#[tokio::test]
async fn newline_less_flood_is_rejected_at_the_bound() {
    let (kernel, sandbox, child_pid, verify, _) = allow_harness_args();
    let h = serve("flood", kernel, sandbox, child_pid, verify, 64).await;

    let stream = UnixStream::connect(&h.socket).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    // 16 KiB, no trailing newline, write side left open: the server
    // must answer from the first max+1 bytes alone.
    write_half.write_all(&vec![b'x'; 16 * 1024]).await.unwrap();
    let mut reader = BufReader::new(read_half);
    let mut out = Vec::new();
    reader.read_until(b'\n', &mut out).await.unwrap();
    assert!(!out.is_empty(), "channel closed without a response line");
    let response: ChannelResponse = serde_json::from_slice(&out).unwrap();

    let error = response.error.unwrap();
    assert_eq!(error.code, "too_large");
    assert_eq!(h.kernel.decisions_made(), 0);
    assert_eq!(h.sandbox.call_count(), 0);
}

/// Sandbox wrapper that stalls `stage` past the channel's request
/// timeout, then delegates to the mock. The detached mediation task
/// must still run to completion after the channel replies: its
/// audit/completion records must land even though the client already
/// received `effect_uncertain`.
struct SlowSandbox {
    inner: MockSandboxRunner,
    delay: Duration,
}

impl SandboxRunner for SlowSandbox {
    fn stage<'a>(
        &'a self,
        envelope: &'a ActionEnvelope,
        lease_id: &'a str,
        obligations: &'a [Obligation],
    ) -> SandboxFuture<'a, Box<dyn StagedExecution>> {
        let runner = self.inner.clone();
        let delay = self.delay;
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            runner.stage(envelope, lease_id, obligations).await
        })
    }
}

/// A mediation that exceeds the channel deadline must keep running in
/// its detached task: the client gets `effect_uncertain` at the
/// deadline, but the sandbox commit (and its audit/completion
/// records) still land afterwards. Cancelling the future would drop
/// those records.
#[tokio::test]
async fn mediation_timeout_does_not_cancel_mediation() {
    let (_dir, socket) = test_socket_dir("medslow");
    let subject = "lumen-session:medslow".to_string();
    let credential = "cred-medslow".to_string();

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
    let inner = MockSandboxRunner::new();
    let sandbox: Arc<dyn SandboxRunner> = Arc::new(SlowSandbox {
        inner: inner.clone(),
        delay: Duration::from_secs(2),
    });
    let config = KernelChannelConfig {
        socket_path: socket.clone(),
        sandbox_gid: 65534,
        max_request_bytes: 1024 * 1024,
        request_timeout: Duration::from_millis(300),
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

    // The channel replies `effect_uncertain` at the deadline...
    let error = response.error.expect("timeout must produce an error");
    assert_eq!(
        error.code, "effect_uncertain",
        "mediation timeout must not be a plain timeout error: {error:?}"
    );

    // ...but the detached mediation task keeps running to completion:
    // the sandbox commit (and its audit/completion records) still land
    // after the reply was sent.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if inner.committed_count() == 1 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "detached mediation task never completed after the timeout"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Exactly one mediation ran: the timeout neither retried nor
    // cancelled it.
    assert_eq!(kernel.decisions_made(), 1);
    assert_eq!(inner.call_count(), 1);
}
