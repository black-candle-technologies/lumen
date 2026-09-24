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
//! - the kernel audit chain still verifies.
//!
//! Descendant sessions: the phase-4 `SessionIdentityVault::end_session`
//! destroys descendant keys, but phase-3's supervisor does not hold a vault
//! or session registry — connecting them is a coordinator design decision
//! (documented in the integration report). At the authority layer the
//! kernel's lease-chain check already denies any child lease chained to a
//! revoked parent lease.

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

    // A real kernel lease for this session's subject.
    let lease = kernel
        .issue_session_lease(
            &subject,
            vec!["/tmp".into()],
            vec!["read".into()],
            now_ms() + 3_600_000,
        )
        .expect("issue real lease");

    // Sanity: the lease authorizes before termination.
    let decision = kernel
        .decide(&read_envelope(&subject, &lease.to_string()))
        .await
        .expect("decide");
    assert!(
        matches!(decision.decision, Decision::Allow { .. }),
        "lease must authorize before termination"
    );

    // Terminate: the supervisor must revoke kernel-side and destroy the identity.
    let report = handle.terminate().await.unwrap();
    assert!(report.leases_revoked, "report: {report:?}");
    assert!(report.identity_destroyed, "report: {report:?}");
    assert!(report.revoke_error.is_none(), "report: {report:?}");
    assert_eq!(handle.status().await.unwrap(), SessionStatus::Terminated);

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

    kernel.audit_log().verify().expect("audit chain verifies");
}
