//! Seam C proof: session termination destroys the vault identity AND
//! revokes the session's leases in the REAL authority kernel.
//!
//! Wires [`SessionSupervisor`] with a real [`AuthorityKernelClient`] (not
//! the mock), spawns a session (vault-minted `ed25519:` subject), issues
//! real kernel leases for the session and a vault-child identity,
//! terminates the session, and proves:
//!
//! - the session subject is a real vault `ed25519:` identity;
//! - the termination report claims leases revoked + identity destroyed;
//! - the parent and child vault identities are no longer live (minting a
//!   child of the destroyed parent fails);
//! - the kernel really revoked the leases: a subsequent `decide` with the
//!   parent lease is denied as revoked, and the child lease is denied too;
//! - the kernel audit chain still verifies.

use std::{path::PathBuf, sync::Arc, time::Duration};

use lumen_core::budget::{Budget, BudgetDimension};
use lumen_core::canonical::{CanonicalPath, PathGrant, PathRights, RealFsResolver, ResourceScope};
use lumen_core::lease::{LeaseLimits, RootLeaseParams};
use lumen_server::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, AuthdClient, AuthorityKernelClient,
    AuthorityKernelConfig, Decision, EffectClass, KernelClient, LeaseDocument, MemorySessionStore,
    MockAuthdClient, ResourceSet, SessionIdentityAuthority, SessionStatus, SessionSupervisor,
    SupervisorConfig, ToolRef, deadline_rfc3339, default_catalog, now_ms, sha256_hex,
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

fn read_envelope(subject: &str, lease_id: &str, path: &str) -> ActionEnvelope {
    ActionEnvelope {
        protocol_version: ACTION_ENVELOPE_VERSION,
        action_id: Uuid::new_v4().to_string(),
        session_id: subject.to_string(),
        tool: ToolRef {
            name: "bct.read_file".to_string(),
            version: "1.0.0".to_string(),
        },
        arguments: serde_json::json!({"path": path}),
        input_hashes: vec![],
        resources: ResourceSet {
            paths: vec![path.to_string()],
            hosts: vec![],
            secret_refs: vec![],
        },
        expected_effects: vec![EffectClass::Read],
        lease_chain: vec![lease_id.to_string()],
        nonce: format!("seam-c-{}", Uuid::new_v4()),
        expires_at: deadline_rfc3339(600),
    }
}

/// Issue a real root lease covering `dir` reads for `subject`.
async fn issue_read_lease(
    kernel: &AuthorityKernelClient,
    subject: &str,
    dir: &str,
) -> LeaseDocument {
    let fs = RealFsResolver;
    let mut scope = ResourceScope::default();
    scope
        .tools
        .insert("bct.read_file".to_string(), "^1.0".parse().unwrap());
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse(dir, &fs, false).unwrap(),
        rights: PathRights::READ,
    });
    scope.effects.push(lumen_core::canonical::EffectClass::Read);
    let now = now_ms();
    kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: Uuid::new_v4().to_string(),
            subject: subject.to_string(),
            scope,
            limits: LeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("test-nonce-{}", Uuid::new_v4()),
            issued_at_ms: now,
        })
        .await
        .expect("issue root lease")
}

#[tokio::test]
async fn terminate_destroys_vault_identities_and_revokes_descendant_leases() {
    let kernel = Arc::new(
        AuthorityKernelClient::open(AuthorityKernelConfig::test_config())
            .await
            .expect("open authority kernel"),
    );
    let supervisor = SessionSupervisor::new(
        test_config(),
        kernel.clone(),
        Arc::new(default_catalog()),
        Arc::new(MemorySessionStore::new()),
    );

    // A real file for the read envelopes.
    let dir = tempfile::tempdir().expect("tempdir");
    let file_path = dir.path().join("x.txt");
    std::fs::write(&file_path, b"hello").unwrap();
    let file_str = file_path.to_str().unwrap().to_string();
    let dir_str = dir.path().to_str().unwrap().to_string();

    let authd = MockAuthdClient::new().with_token("user-token", "acct-7");
    let owner = authd.authenticate("user-token").await.unwrap();
    let handle = supervisor.spawn_session(&owner).await.unwrap();
    let subject = handle.binding().await.unwrap().session_subject.clone();

    // The supervisor mints a REAL vault identity: `ed25519:` subject.
    assert!(
        subject.starts_with("ed25519:"),
        "supervisor must mint vault identities, got {subject}"
    );

    // A real kernel lease for this session's subject.
    let lease = issue_read_lease(&kernel, &subject, &dir_str).await;

    // A real vault CHILD identity, and a lease for it. The supervisor
    // never sees this child; termination must destroy it via the vault's
    // descendant tracking.
    let child_info = kernel
        .start_session_identity(Some(&subject))
        .await
        .expect("mint child identity");
    let child_subject = child_info.subject.clone();
    assert_ne!(child_subject, subject);
    let child_lease = issue_read_lease(&kernel, &child_subject, &dir_str).await;

    // Sanity: both leases authorize before termination.
    let decision = kernel
        .decide(&read_envelope(&subject, &lease.lease_id, &file_str))
        .await
        .expect("decide");
    assert!(
        matches!(decision.decision, Decision::Allow { .. }),
        "parent lease must authorize before termination, got {:?}",
        decision.decision
    );
    let decision = kernel
        .decide(&read_envelope(
            &child_subject,
            &child_lease.lease_id,
            &file_str,
        ))
        .await
        .expect("decide");
    assert!(
        matches!(decision.decision, Decision::Allow { .. }),
        "child lease must authorize before parent termination"
    );

    // Terminate: vault destroy (parent + descendants), then revoke, then
    // Pi shutdown.
    let report = handle.terminate().await.expect("terminate");
    assert!(report.leases_revoked, "report: {report:?}");
    assert!(report.identity_destroyed, "report: {report:?}");
    assert!(report.revoke_error.is_none(), "report: {report:?}");
    assert_eq!(handle.status().await.unwrap(), SessionStatus::Terminated);

    // The parent vault identity is dead: minting a child of it fails.
    let child_of_dead = kernel.start_session_identity(Some(&subject)).await;
    assert!(
        child_of_dead.is_err(),
        "minting a child of a destroyed identity must fail"
    );

    // The parent lease is revoked kernel-side.
    let decision = kernel
        .decide(&read_envelope(&subject, &lease.lease_id, &file_str))
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

    // The descendant lease is dead too: the vault destroyed the child
    // identity at parent termination, and its leases were revoked.
    let decision = kernel
        .decide(&read_envelope(
            &child_subject,
            &child_lease.lease_id,
            &file_str,
        ))
        .await
        .expect("decide");
    assert!(
        matches!(decision.decision, Decision::Deny { .. }),
        "child lease must be denied after parent termination, got {:?}",
        decision.decision
    );

    // The kernel audit chain still verifies.
    kernel
        .verify_kernel_audit()
        .await
        .expect("audit chain verifies");
}
