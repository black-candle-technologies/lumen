//! Phase-0 bypass inventory: every Pi effect path and its closure.
//!
//! The boundary is proven when one real mediated tool can be allowed/denied
//! **and** every bypass attempt fails observably. Each entry below names the
//! attack, the mechanism that closes it, and the test that proves it. All
//! kernel-side tests go through the real Unix-socket wire
//! (`lumen-kernel/1` JSONL), not the in-process shortcut.
//!
//! | #   | Bypass attempt                                              | Closure                                                        | Test                              |
//! |-----|-------------------------------------------------------------|----------------------------------------------------------------|---------------- --------------------------------- |
//! | B1  | Forged envelope claims a path outside the lease             | kernel canonicalizes + scope-checks against the leaf lease    | `b1_forged_scope_denied`          |
//! | B2  | Fabricated lease id                                         | chain resolved from the kernel's own registry                | `b2_fake_lease_denied`            |
//! | B3  | Replay a captured envelope                                  | per-kernel single-use nonce registry                         | `b3_replay_rejected`              |
//! | B4  | Wrong credential on the kernel socket                       | constant-time nonce compare; no decision; audited             | `b4_bad_credential_rejected`      |
//! | B5  | Malformed JSONL on the kernel socket                        | `malformed_request` wire error; connection stays usable      | `b5_malformed_record_rejected`    |
//! | B6  | Unknown tool (`bash`) in the envelope                         | phase-0 policy covers only `bct.read_file`                   | `b6_unknown_tool_denied`          |
//! | B7  | Effect escalation (`file_write`, `process_spawn`)            | envelope effects must match the tool's registered class      | `b7_effect_escalation_denied`     |
//! | B8  | Expired envelope                                              | `expires_at_ms` enforced                                     | `b8_expired_denied`               |
//! | B9  | Child lease wider than its parent                           | mechanical narrowing enforced at issuance                   | `b9_child_narrowing_enforced`     |
//! | B10 | Use a revoked lease                                         | revocation flag checked on every evaluation                  | `b10_revoked_lease_denied`        |
//! | B11 | Envelope session != lease subject                           | subject binding                                              | `b11_subject_mismatch_denied`     |
//! | B12 | Supervisor sends raw RPC `bash`                             | no public path: allowlist enum + private sender (compile-time)| lumen-server unit test            |
//! | B13 | Built-in Pi tools available to the model                    | `--no-builtin-tools` enforced by spawn validation            | lumen-server unit test            |
//! | B14 | Hostile/replaced extension calls node:fs directly            | cannot mint kernel authority (no lease, no socket nonce); OS-level reads unconfined until phase 2 | documented residual risk |
//! | B15 | Model acts on a `pending` verdict without approval          | pending grants nothing: no obligations, no execution          | `b15_pending_grants_nothing`      |
//! | B16 | Deny without a trace                                        | every evaluation audits proposal + verdict                   | `b16_denials_are_audited`         |
//!
//! B12/B13 are proven in `crates/lumen-server` (`pi_supervisor` unit tests +
//! `pi_supervisor_boundary` integration tests). B14 is the known residual
//! risk of the spike: the extension runs in the Pi process with the Pi
//! process's OS permissions, so a *replaced* extension could use Node APIs
//! directly. It still cannot mint kernel authority (it has no lease, and the
//! socket credential lives in the host's environment, not the extension's),
//! but OS-level reads are not stopped until phase-2 process confinement
//! lands. The spike is honest about this: see ADR-0002.

use lumen_core::pi_boundary::*;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

const SESSION: &str = "ed25519:test-session";
const LEASED_DIR: &str = "/tmp/lumen-leased";
const APPROVABLE_DIR: &str = "/tmp/lumen-approvable";

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

struct Harness {
    kernel: Arc<LocalKernel>,
    listener: KernelListener,
    credential: String,
    socket_path: std::path::PathBuf,
    lease: LeaseId,
    _dir: tempfile::TempDir,
}

impl Harness {
    async fn spawn() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_path = dir.path().join("kernel.sock");
        let kernel = Arc::new(LocalKernel::new(LocalKernelConfig {
            approvable_roots: vec![APPROVABLE_DIR.to_string()],
            default_max_output_bytes: 64 * 1024,
        }));
        let lease = kernel
            .issue_root_lease(
                SESSION,
                vec![LEASED_DIR.to_string()],
                vec!["read".to_string()],
                now_ms() + 3_600_000,
            )
            .expect("issue lease");
        let listener = KernelListener::bind(
            kernel.clone(),
            socket_path.clone(),
            PeerPolicy::current_user(),
        )
        .await
        .expect("bind");
        let credential = listener.endpoint().nonce.clone();
        Self {
            kernel,
            listener,
            credential,
            socket_path,
            lease,
            _dir: dir,
        }
    }

    /// One JSONL request → one parsed JSONL response, on a fresh connection.
    async fn round_trip(&self, request: &Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .expect("connect");
        let mut bytes = serde_json::to_vec(request).expect("serialize");
        bytes.push(b'\n');
        stream.write_all(&bytes).await.expect("write");
        stream.flush().await.expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read");
        serde_json::from_str(&line).expect("response must be JSON")
    }

    async fn shutdown(self) {
        self.listener.shutdown().await.expect("shutdown");
    }
}

#[derive(Clone)]
struct EnvelopeOpts {
    tool_name: String,
    path: String,
    rights: PathRights,
    file_write: bool,
    process_spawn: bool,
    lease_chain: Vec<LeaseId>,
    session: String,
    expires_at_ms: i64,
}

impl EnvelopeOpts {
    fn valid(lease: LeaseId) -> Self {
        Self {
            tool_name: "bct.read_file".to_string(),
            path: format!("{LEASED_DIR}/report.txt"),
            rights: PathRights::Read,
            file_write: false,
            process_spawn: false,
            lease_chain: vec![lease],
            session: SESSION.to_string(),
            expires_at_ms: now_ms() + 60_000,
        }
    }
}

fn envelope(opts: &EnvelopeOpts) -> ActionEnvelope {
    let mut arguments = BTreeMap::new();
    arguments.insert("path".to_string(), Value::String(opts.path.clone()));
    ActionEnvelope {
        version: ACTION_ENVELOPE_VERSION,
        action_id: uuid::Uuid::new_v4(),
        session_id: opts.session.clone(),
        tool: ToolRef {
            name: opts.tool_name.clone(),
            version: "1".to_string(),
        },
        arguments,
        inputs: vec![],
        resources: ResourceSet {
            paths: vec![PathResource {
                path: opts.path.clone(),
                rights: opts.rights,
            }],
            network: vec![],
            secrets: vec![],
        },
        expected_effects: EffectClasses {
            file_read: true,
            file_write: opts.file_write,
            network_egress: false,
            network_ingress: false,
            process_spawn: opts.process_spawn,
        },
        lease_chain: opts.lease_chain.clone(),
        nonce: uuid::Uuid::new_v4().to_string(),
        expires_at_ms: opts.expires_at_ms,
    }
}

fn wire_request(credential: &str, envelope: &ActionEnvelope) -> Value {
    json!({
        "protocol": KERNEL_WIRE_PROTOCOL,
        "credential": credential,
        "envelope": envelope,
    })
}

fn decision_of(response: &Value) -> &Value {
    response
        .get("decision")
        .expect("wire response carries a decision")
}

fn deny_code(decision: &Value) -> &str {
    assert_eq!(
        decision.get("decision").and_then(Value::as_str),
        Some("deny"),
        "expected a deny decision, got {decision}"
    );
    decision
        .pointer("/reason/code")
        .and_then(Value::as_str)
        .expect("deny reason code")
}

/// B0 (control): the real mediated tool allows inside the lease and denies
/// outside it — the boundary the bypasses are tested against.
#[tokio::test]
async fn b0_allow_inside_lease_deny_outside() {
    let h = Harness::spawn().await;

    let allow_env = envelope(&EnvelopeOpts::valid(h.lease));
    let allow_res = h.round_trip(&wire_request(&h.credential, &allow_env)).await;
    assert!(allow_res.get("error").is_none(), "unexpected wire error");
    let decision = decision_of(&allow_res);
    assert_eq!(
        decision.get("decision").and_then(Value::as_str),
        Some("allow"),
        "in-lease read must be allowed"
    );
    assert!(
        allow_res
            .get("audit_sequence")
            .and_then(Value::as_u64)
            .is_some(),
        "allow must carry an audit sequence"
    );

    let mut outside = EnvelopeOpts::valid(h.lease);
    outside.path = "/etc/passwd".to_string();
    let deny_res = h
        .round_trip(&wire_request(&h.credential, &envelope(&outside)))
        .await;
    let decision = decision_of(&deny_res);
    assert_eq!(
        decision.get("decision").and_then(Value::as_str),
        Some("deny"),
        "out-of-lease read must be denied"
    );

    h.shutdown().await;
}

/// B1: forged scope — envelope claims /etc/passwd while the lease covers
/// /tmp/lumen-leased. Also try a `..` traversal spelling.
#[tokio::test]
async fn b1_forged_scope_denied() {
    let h = Harness::spawn().await;
    for path in ["/etc/passwd", "/tmp/lumen-leased/../etc/passwd"] {
        let mut opts = EnvelopeOpts::valid(h.lease);
        opts.path = path.to_string();
        let res = h
            .round_trip(&wire_request(&h.credential, &envelope(&opts)))
            .await;
        assert_eq!(
            deny_code(decision_of(&res)),
            "scope_exceeded",
            "path {path}"
        );
    }
    h.shutdown().await;
}

/// B2: fabricated lease id — the kernel resolves the chain from its own
/// registry, so an unknown id denies.
#[tokio::test]
async fn b2_fake_lease_denied() {
    let h = Harness::spawn().await;
    let mut opts = EnvelopeOpts::valid(h.lease);
    opts.lease_chain = vec![LeaseId::new()];
    let res = h
        .round_trip(&wire_request(&h.credential, &envelope(&opts)))
        .await;
    assert_eq!(deny_code(decision_of(&res)), "unknown_lease");
    h.shutdown().await;
}

/// B3: replay — the identical wire bytes sent twice. The second evaluation
/// must reject the reused nonce.
#[tokio::test]
async fn b3_replay_rejected() {
    let h = Harness::spawn().await;
    let request = wire_request(&h.credential, &envelope(&EnvelopeOpts::valid(h.lease)));
    let first = h.round_trip(&request).await;
    assert_eq!(
        decision_of(&first).get("decision").and_then(Value::as_str),
        Some("allow")
    );
    let second = h.round_trip(&request).await;
    assert_eq!(deny_code(decision_of(&second)), "replay_detected");
    h.shutdown().await;
}

/// B4: bad credential — no decision, wire error, and a transport audit event.
#[tokio::test]
async fn b4_bad_credential_rejected() {
    let h = Harness::spawn().await;
    let before = h.kernel.audit_log().len();
    let mut request = wire_request("wrong-credential", &envelope(&EnvelopeOpts::valid(h.lease)));
    // Pad to the same length so the failure is not a length oracle.
    request["credential"] = Value::String("x".repeat(h.credential.len()));
    let res = h.round_trip(&request).await;
    assert!(
        res.get("decision").is_none(),
        "no decision may be issued on bad credential, got {res}"
    );
    assert_eq!(
        res.pointer("/error/code").and_then(Value::as_str),
        Some("authentication_failed")
    );
    assert!(
        h.kernel.audit_log().len() > before,
        "transport rejection must be audited"
    );
    h.shutdown().await;
}

/// B5: malformed JSONL — wire error, and the connection stays usable.
#[tokio::test]
async fn b5_malformed_record_rejected() {
    let h = Harness::spawn().await;
    let mut stream = UnixStream::connect(&h.socket_path).await.expect("connect");
    stream
        .write_all(b"this is not json\n")
        .await
        .expect("write");
    stream.flush().await.expect("flush");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.expect("read");
    let res: Value = serde_json::from_str(&line).expect("JSON error response");
    assert_eq!(
        res.pointer("/error/code").and_then(Value::as_str),
        Some("malformed_request")
    );
    // Same connection still serves a valid request afterwards.
    let request = wire_request(&h.credential, &envelope(&EnvelopeOpts::valid(h.lease)));
    let mut bytes = serde_json::to_vec(&request).expect("serialize");
    bytes.push(b'\n');
    let mut stream = reader.into_inner();
    stream.write_all(&bytes).await.expect("write");
    stream.flush().await.expect("flush");
    let mut reader = BufReader::new(stream);
    line.clear();
    reader.read_line(&mut line).await.expect("read");
    let res: Value = serde_json::from_str(&line).expect("JSON response");
    assert_eq!(
        decision_of(&res).get("decision").and_then(Value::as_str),
        Some("allow"),
        "connection must stay usable after a malformed record"
    );
    h.shutdown().await;
}

/// B6: unknown tool — only `bct.read_file` is covered by the phase-0 policy.
#[tokio::test]
async fn b6_unknown_tool_denied() {
    let h = Harness::spawn().await;
    for tool in ["bash", "read", "bct.write_file"] {
        let mut opts = EnvelopeOpts::valid(h.lease);
        opts.tool_name = tool.to_string();
        let res = h
            .round_trip(&wire_request(&h.credential, &envelope(&opts)))
            .await;
        assert_eq!(
            deny_code(decision_of(&res)),
            "scope_exceeded",
            "tool {tool}"
        );
    }
    h.shutdown().await;
}

/// B7: effect escalation — the envelope's declared effects must match the
/// tool's registered class.
#[tokio::test]
async fn b7_effect_escalation_denied() {
    let h = Harness::spawn().await;
    let mut write = EnvelopeOpts::valid(h.lease);
    write.file_write = true;
    let res = h
        .round_trip(&wire_request(&h.credential, &envelope(&write)))
        .await;
    assert_eq!(deny_code(decision_of(&res)), "scope_exceeded");

    let mut spawn = EnvelopeOpts::valid(h.lease);
    spawn.process_spawn = true;
    let res = h
        .round_trip(&wire_request(&h.credential, &envelope(&spawn)))
        .await;
    assert_eq!(deny_code(decision_of(&res)), "scope_exceeded");
    h.shutdown().await;
}

/// B8: expired envelope.
#[tokio::test]
async fn b8_expired_denied() {
    let h = Harness::spawn().await;
    let mut opts = EnvelopeOpts::valid(h.lease);
    opts.expires_at_ms = now_ms() - 1;
    let res = h
        .round_trip(&wire_request(&h.credential, &envelope(&opts)))
        .await;
    assert_eq!(deny_code(decision_of(&res)), "expired_action");
    h.shutdown().await;
}

/// B9: child lease wider than parent — refused at issuance (mechanical
/// narrowing), so it can never reach evaluation.
#[tokio::test]
async fn b9_child_narrowing_enforced() {
    let kernel = LocalKernel::new(LocalKernelConfig::default());
    let parent = kernel
        .issue_root_lease(
            SESSION,
            vec![LEASED_DIR.to_string()],
            vec!["read".to_string()],
            now_ms() + 3_600_000,
        )
        .expect("parent");
    // Wider path prefix.
    assert!(
        kernel
            .issue_child_lease(
                parent,
                SESSION,
                vec!["/tmp".to_string()],
                vec!["read".to_string()],
                now_ms() + 3_600_000,
            )
            .is_err()
    );
    // Wider verb.
    assert!(
        kernel
            .issue_child_lease(
                parent,
                SESSION,
                vec![LEASED_DIR.to_string()],
                vec!["read".to_string(), "write".to_string()],
                now_ms() + 3_600_000,
            )
            .is_err()
    );
    // Longer expiry.
    assert!(
        kernel
            .issue_child_lease(
                parent,
                SESSION,
                vec![LEASED_DIR.to_string()],
                vec!["read".to_string()],
                now_ms() + 7_200_000,
            )
            .is_err()
    );
    // A properly narrowed child works.
    let child = kernel
        .issue_child_lease(
            parent,
            SESSION,
            vec![format!("{LEASED_DIR}/sub")],
            vec!["read".to_string()],
            now_ms() + 1_800_000,
        )
        .expect("narrowed child");
    assert_ne!(child, parent);
}

/// B10: revoked lease — denied on next use.
#[tokio::test]
async fn b10_revoked_lease_denied() {
    let h = Harness::spawn().await;
    let first = h
        .round_trip(&wire_request(
            &h.credential,
            &envelope(&EnvelopeOpts::valid(h.lease)),
        ))
        .await;
    assert_eq!(
        decision_of(&first).get("decision").and_then(Value::as_str),
        Some("allow")
    );
    h.kernel.revoke_lease(h.lease).expect("revoke");
    let second = h
        .round_trip(&wire_request(
            &h.credential,
            &envelope(&EnvelopeOpts::valid(h.lease)),
        ))
        .await;
    assert_eq!(deny_code(decision_of(&second)), "lease_revoked");
    h.shutdown().await;
}

/// B11: subject mismatch — envelope session differs from lease subject.
#[tokio::test]
async fn b11_subject_mismatch_denied() {
    let h = Harness::spawn().await;
    let mut opts = EnvelopeOpts::valid(h.lease);
    opts.session = "ed25519:attacker-session".to_string();
    let res = h
        .round_trip(&wire_request(&h.credential, &envelope(&opts)))
        .await;
    assert_eq!(deny_code(decision_of(&res)), "subject_mismatch");
    h.shutdown().await;
}

/// B15: pending-approval grants nothing — no obligations, no execution
/// authority. The approval_id names a human step that phase 4 implements.
#[tokio::test]
async fn b15_pending_grants_nothing() {
    let h = Harness::spawn().await;
    let mut opts = EnvelopeOpts::valid(h.lease);
    opts.path = format!("{APPROVABLE_DIR}/notes.txt");
    let res = h
        .round_trip(&wire_request(&h.credential, &envelope(&opts)))
        .await;
    let decision = decision_of(&res);
    assert_eq!(
        decision.get("decision").and_then(Value::as_str),
        Some("pending_approval"),
        "approvable root must yield pending, not allow"
    );
    assert!(
        decision
            .get("approval_id")
            .and_then(Value::as_str)
            .is_some(),
        "pending must name the approval"
    );
    assert!(
        decision.get("obligations").is_none(),
        "pending must grant no obligations"
    );
    h.shutdown().await;
}

/// B16: every denial is audited — proposal plus verdict, chained.
#[tokio::test]
async fn b16_denials_are_audited() {
    let h = Harness::spawn().await;
    let env = envelope(&{
        let mut opts = EnvelopeOpts::valid(h.lease);
        opts.path = "/etc/passwd".to_string();
        opts
    });
    let digest = env.digest().expect("digest");
    let before = h.kernel.audit_log().len();
    let res = h.round_trip(&wire_request(&h.credential, &env)).await;
    assert_eq!(deny_code(decision_of(&res)), "scope_exceeded");
    let events = h.kernel.audit_log().events();
    let fresh: Vec<_> = events.into_iter().skip(before).collect();
    assert!(
        fresh.len() >= 2,
        "denial must audit proposal and verdict, got {}",
        fresh.len()
    );
    assert!(
        fresh.iter().all(|e| e.action_digest == digest),
        "audit events must reference the denied action digest"
    );
    h.kernel.audit_log().verify().expect("audit chain verifies");
    h.shutdown().await;
}
