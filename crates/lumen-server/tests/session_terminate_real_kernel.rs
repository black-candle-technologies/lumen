//! Seam C proof: session termination destroys the identity AND revokes the
//! session's leases in the REAL kernel.
//!
//! Wires [`SessionSupervisor`] with a real [`LocalKernelClient`] (not the
//! mock), issues a real kernel lease for the spawned session's subject,
//! terminates the session, and proves:
//!
//! - the termination report claims leases revoked + identity destroyed;
//! - the kernel really revoked the lease: a subsequent `decide` with the
//!   same lease chain is denied as revoked;
//! - a descendant lease chained to the revoked parent is denied as
//!   revoked too (kernel-layer descendant protection — the kernel's
//!   chain check rejects any chain containing a revoked lease);
//! - the kernel audit chain still verifies.
//!
//! What this does NOT prove (coordinator design decision, not wired):
//! phase-3's supervisor owns its own `SessionIdentity`, not phase-4's
//! `SessionIdentityVault` / `SessionRegistry`, so supervisor-side
//! descendant *identity* destruction on parent termination is unwired.
//! The authority layer (lease revocation) is covered above; the identity
//! layer needs the supervisor/vault ownership design.

use std::{path::PathBuf, sync::Arc, time::Duration};

use lumen_core::pi_boundary::{LocalKernel, LocalKernelConfig};
use lumen_server::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, AuthdClient, Decision, EffectClass, KernelClient,
    LocalKernelClient, MemorySessionStore, MockAuthdClient, ResourceSet, SessionStatus,
    SessionSupervisor, SupervisorConfig, ToolRef, deadline_rfc3339, default_catalog, now_ms,
    sha256_hex,
};
use uuid::Uuid;

fn fixture_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("fake-pi.sh")
}

fn test_config() -> SupervisorConfig {
    let script = fixture_script();
    let digest = sha256_hex(&std::fs::read(&script).unwrap());
    let fixture_dir = script.parent().unwrap().to_path_buf();
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
        // The fixture script lives outside the sandbox's built-in read-only
        // set; allowlist its directory so Landlock-enforcing hosts can spawn.
        pi_sandbox: lumen_server::PiSandboxConfig {
            extra_read_only_paths: vec![fixture_dir],
            ..Default::default()
        },
        ..SupervisorConfig::default()
    }
}

fn read_envelope(subject: &str, lease: &str) -> ActionEnvelope {
    ActionEnvelope {
        protocol_version: ACTION_ENVELOPE_VERSION,
        action_id: Uuid::new_v4().to_string(),
        session_id: subject.to_string(),
        tool: ToolRef {
            name: "bct.read_file".to_string(),
            version: "1.0.0".to_string(),
        },
        arguments: serde_json::json!({"path": "/tmp/x"}),
        input_hashes: vec![],
        resources: ResourceSet {
            paths: vec!["/tmp/x".to_string()],
            hosts: vec![],
            secret_refs: vec![],
        },
        expected_effects: vec![EffectClass::Read],
        lease_chain: vec![lease.to_string()],
        nonce: format!("seam-c-{}", Uuid::new_v4()),
        expires_at: deadline_rfc3339(600),
    }
}

#[tokio::test]
async fn terminate_revokes_real_kernel_leases_and_destroys_identity() {
    let kernel = Arc::new(LocalKernelClient::new(Arc::new(LocalKernel::new(
        LocalKernelConfig::default(),
    ))));
    let supervisor = SessionSupervisor::new(
        test_config(),
        kernel.clone(),
        Arc::new(default_catalog()),
        Arc::new(MemorySessionStore::new()),
    );

    let authd = MockAuthdClient::new().with_token("user-token", "acct-7");
    let owner = authd.authenticate("user-token").await.unwrap();
    let handle = supervisor.spawn_session(&owner).await.unwrap();
    let subject = handle.binding().await.unwrap().session_subject.clone();

    // A real kernel lease for this session's subject. One expiry for both
    // leases: separate now_ms() calls can straddle a millisecond boundary,
    // and the kernel rejects a child whose expiry exceeds its parent's.
    let lease_expiry_ms = now_ms() + 3_600_000;
    let lease = kernel
        .issue_session_lease(
            &subject,
            vec!["/tmp".into()],
            vec!["read".into()],
            lease_expiry_ms,
        )
        .expect("issue real lease");

    // A descendant lease chained to the parent (leaf first, then parent).
    // The supervisor does not model descendants — this exercises the
    // kernel layer directly, which is the part that is wired.
    let child_subject = format!("{subject}::child");
    let child_lease = kernel
        .issue_session_child_lease(
            lease,
            &child_subject,
            vec!["/tmp".into()],
            vec!["read".into()],
            lease_expiry_ms,
        )
        .expect("issue real child lease");
    let mut child_env = read_envelope(&child_subject, &child_lease.to_string());
    child_env.lease_chain = vec![child_lease.to_string(), lease.to_string()];

    // Sanity: the lease authorizes before termination.
    let decision = kernel
        .decide(&read_envelope(&subject, &lease.to_string()))
        .await
        .expect("decide");
    assert!(
        matches!(decision.decision, Decision::Allow { .. }),
        "lease must authorize before termination"
    );
    let child_decision = kernel.decide(&child_env).await.expect("decide");
    assert!(
        matches!(child_decision.decision, Decision::Allow { .. }),
        "child lease must authorize before parent termination"
    );

    // The session holds a live identity before termination...
    assert!(
        handle.has_identity().await.unwrap(),
        "session must hold an identity before termination"
    );

    // Terminate: the supervisor must revoke kernel-side and destroy the identity.
    let report = handle.terminate().await.unwrap();
    assert!(report.leases_revoked, "report: {report:?}");
    assert!(report.identity_destroyed, "report: {report:?}");
    assert!(report.revoke_error.is_none(), "report: {report:?}");
    assert_eq!(handle.status().await.unwrap(), SessionStatus::Terminated);

    // ...and it is gone afterward. This checks destruction directly: the
    // report's identity_destroyed flag is also true when no identity
    // existed, so it cannot prove destruction on its own.
    assert!(
        !handle.has_identity().await.unwrap(),
        "identity must be destroyed by termination"
    );

    // The SAME lease is now dead kernel-side: decide denies as revoked.
    let decision = kernel
        .decide(&read_envelope(&subject, &lease.to_string()))
        .await
        .expect("decide");
    let reason = match &decision.decision {
        Decision::Deny { reason } => reason.clone(),
        other => panic!("expected Deny after termination, got {other:?}"),
    };
    assert!(
        reason.contains("revoked"),
        "deny reason must name revocation: {reason}"
    );

    // The descendant lease is dead too: the kernel's chain check denies
    // any lease chained to a revoked parent, even though the supervisor
    // never saw the descendant. (Supervisor-side descendant identity
    // destruction — phase-4 vault wiring — remains a coordinator design
    // decision; the authority layer is covered here.)
    child_env.nonce = format!("seam-c-child-{}", Uuid::new_v4());
    let child_decision = kernel.decide(&child_env).await.expect("decide");
    let reason = match &child_decision.decision {
        Decision::Deny { reason } => reason.clone(),
        other => panic!("expected Deny for child of revoked parent, got {other:?}"),
    };
    assert!(
        reason.contains("revoked"),
        "child deny reason must name revocation: {reason}"
    );

    kernel.audit_log().verify().expect("audit chain verifies");
}
