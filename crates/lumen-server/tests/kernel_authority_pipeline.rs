//! Seam A proof: [`ToolPipeline`] drives the REAL Phase-1 authority kernel.
//!
//! This test wires `ToolPipeline` with [`AuthorityKernelClient`] — the real
//! phase-1 authority engine (canonicalization, replay gate, signature and
//! revocation checks, exact scope, one-shot consumption, budget admission,
//! durable VHL fallback) — and a mock sandbox. It proves:
//!
//! - allow iff a real kernel lease covers the action, with sandbox
//!   execution (staged + committed) and a durable audit trail whose
//!   hash chain and host-key checkpoints verify;
//! - deny for an out-of-scope path with ZERO sandbox execution;
//! - pending approval when no lease covers the action, with the approval
//!   request persisted durably (it survives a full client restart and is
//!   visible to the host/VHL poller) and ZERO sandbox execution.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use lumen_core::budget::{Budget, BudgetDimension};
use lumen_core::canonical::{
    CanonicalPath, EffectClass as KernelEffectClass, PathGrant, PathRights, RealFsResolver,
    ResourceScope,
};
use lumen_core::identity::WorkspaceId;
use lumen_core::lease::{LeaseLimits, OneShotGrant as CoreOneShotGrant, RootLeaseParams};
use lumen_db::Database;
use lumen_server::{
    AuthorityDb, AuthorityKernelClient, AuthorityKernelConfig, Catalog, CatalogError, EffectClass,
    KernelClient, KernelError, MockSandboxRunner, OneShotGrant, PendingApprovalView, PiToolRequest,
    ProjectionKind, SessionIdentityAuthority, ToolDef, ToolOutcome, ToolPipeline, now_ms,
};

fn read_file_catalog() -> Result<Catalog, CatalogError> {
    let mut catalog = Catalog::new();
    catalog.register(ToolDef {
        name: "bct.read_file".to_string(),
        version: "1.0.0".to_string(),
        description: "Phase-1 canonical read (test double for the real kernel policy).".to_string(),
        parameters_schema: serde_json::json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["path"],
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 4096}
            }
        }),
        effects: vec![EffectClass::Read],
        projection: ProjectionKind::FsRead,
    })?;
    Ok(catalog)
}

fn read_request(path: &str) -> PiToolRequest {
    PiToolRequest {
        id: "call-1".to_string(),
        tool: "bct.read_file".to_string(),
        arguments: serde_json::json!({ "path": path }),
    }
}

struct Fixture {
    pipeline: ToolPipeline<AuthorityKernelClient, MockSandboxRunner>,
    kernel: Arc<AuthorityKernelClient>,
    sandbox: Arc<MockSandboxRunner>,
    leased_file: String,
    outside_file: String,
    #[allow(dead_code)]
    dir: tempfile::TempDir,
}

async fn fixture() -> Fixture {
    fixture_with_vhl(HashMap::new()).await
}

async fn fixture_with_vhl(vhl_keys: HashMap<String, VerifyingKey>) -> Fixture {
    fixture_with_db(vhl_keys, None).await
}

/// `db_path`: if `Some`, use a file-backed database (for tests that break
/// the store from outside); otherwise in-memory.
/// `workspace`: if `Some`, use the given workspace (for restart tests that
/// must reopen the same workspace); otherwise a fresh random one.
async fn fixture_with_db(
    vhl_keys: HashMap<String, VerifyingKey>,
    db_path: Option<std::path::PathBuf>,
) -> Fixture {
    fixture_with_db_and_workspace(vhl_keys, db_path, None).await
}

async fn fixture_with_db_and_workspace(
    vhl_keys: HashMap<String, VerifyingKey>,
    db_path: Option<std::path::PathBuf>,
    workspace: Option<WorkspaceId>,
) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let leased_dir = dir.path().join("leased");
    std::fs::create_dir_all(&leased_dir).unwrap();
    let leased_file = leased_dir.join("a.txt");
    std::fs::write(&leased_file, b"hello").unwrap();
    let outside_file = dir.path().join("outside.txt");
    std::fs::write(&outside_file, b"nope").unwrap();

    let mut config = AuthorityKernelConfig::test_config();
    config.vhl_keys = vhl_keys;
    if let Some(ws) = workspace {
        config.workspace = ws;
    }
    config.db = match db_path {
        Some(path) => AuthorityDb::Path(path),
        None => AuthorityDb::Memory,
    };
    let kernel = Arc::new(
        AuthorityKernelClient::open(config)
            .await
            .expect("open authority kernel"),
    );
    let sandbox = Arc::new(MockSandboxRunner::new());
    let pipeline = ToolPipeline::new(
        Arc::new(read_file_catalog().unwrap()),
        kernel.clone(),
        sandbox.clone(),
    );
    Fixture {
        pipeline,
        kernel,
        sandbox,
        leased_file: leased_file.to_str().unwrap().to_string(),
        outside_file: outside_file.to_str().unwrap().to_string(),
        dir,
    }
}

/// Start a real vault identity and issue a real root lease covering the
/// fixture's leased directory. Returns the issued lease document.
async fn issue_test_lease(f: &Fixture) -> lumen_server::LeaseDocument {
    let info = f
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    assert!(
        info.subject.starts_with("ed25519:"),
        "the authority kernel mints real vault identities, got {}",
        info.subject
    );
    let seq = uuid::Uuid::new_v4().to_string();
    let leased_root = Path::new(&f.leased_file).parent().unwrap();
    let fs = RealFsResolver;
    let mut scope = ResourceScope::default();
    scope
        .tools
        .insert("bct.read_file".to_string(), "^1.0".parse().unwrap());
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse(leased_root.to_str().unwrap(), &fs, false).unwrap(),
        rights: PathRights::READ,
    });
    scope.effects.push(KernelEffectClass::Read);
    let now = now_ms();
    f.kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: seq.clone(),
            subject: info.subject.clone(),
            scope,
            limits: LeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("test-nonce-{seq}"),
            issued_at_ms: now,
        })
        .await
        .expect("issue root lease")
}

/// Start a real vault identity and issue a real root lease covering the
/// fixture's leased directory. Returns `(subject, lease_id)`.
async fn leased_subject(f: &Fixture) -> (String, String) {
    let lease = issue_test_lease(f).await;
    (lease.subject.clone(), lease.lease_id.clone())
}

#[tokio::test]
async fn verify_lease_accepts_pristine_presented_document() {
    let f = fixture().await;
    let lease = issue_test_lease(&f).await;
    let verification = KernelClient::verify_lease(f.kernel.as_ref(), &lease)
        .await
        .expect("pristine lease must verify");
    assert_eq!(verification.lease_id, lease.lease_id);
    assert!(!verification.revoked);
}

#[tokio::test]
async fn verify_lease_rejects_altered_presented_fields() {
    let f = fixture().await;
    let lease = issue_test_lease(&f).await;

    // Case 1: altered timestamp (limits) with the stored lease id,
    // subject, issuer id, and signature retained.
    let mut tampered = lease.clone();
    tampered.limits.expires_at_ms += 60_000;
    let error = KernelClient::verify_lease(f.kernel.as_ref(), &tampered)
        .await
        .expect_err("altered limits must fail verification");
    assert!(
        matches!(error, KernelError::VerificationFailed(_)),
        "unexpected error: {error:?}"
    );

    // Case 2: widened scope (grants an effect the stored lease never
    // granted) with id/subject/issuer/signature retained.
    let mut tampered = lease.clone();
    let mut scope: ResourceScope =
        serde_json::from_value(tampered.scope.clone()).expect("issued scope parses");
    scope.effects.push(KernelEffectClass::Write);
    tampered.scope = serde_json::to_value(&scope).expect("scope serializes");
    let error = KernelClient::verify_lease(f.kernel.as_ref(), &tampered)
        .await
        .expect_err("widened scope must fail verification");
    assert!(
        matches!(error, KernelError::VerificationFailed(_)),
        "unexpected error: {error:?}"
    );

    // Case 3: swapped nonce.
    let mut tampered = lease;
    tampered.lease_nonce = "forged-nonce".to_string();
    let error = KernelClient::verify_lease(f.kernel.as_ref(), &tampered)
        .await
        .expect_err("swapped nonce must fail verification");
    assert!(
        matches!(error, KernelError::VerificationFailed(_)),
        "unexpected error: {error:?}"
    );
}

#[tokio::test]
async fn pipeline_allows_with_real_lease_and_audits() {
    let f = fixture().await;
    let (subject, lease_id) = leased_subject(&f).await;

    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[lease_id])
        .await;
    match outcome {
        ToolOutcome::Completed { .. } => {}
        other => panic!("expected Completed from real kernel allow, got {other:?}"),
    }

    // The full pipeline ran against the real kernel: staged, audit-before-
    // commit, committed.
    assert_eq!(f.sandbox.staged_count(), 1);
    assert_eq!(f.sandbox.committed_count(), 1);

    // The kernel's durable audit chain verifies: every decision event is
    // present and anchored by a host-key checkpoint.
    f.kernel
        .verify_kernel_audit()
        .await
        .expect("kernel audit chain must verify");
}

#[tokio::test]
async fn pipeline_denies_out_of_scope_path_with_zero_execution() {
    let f = fixture().await;
    let (subject, lease_id) = leased_subject(&f).await;

    let outcome = f
        .pipeline
        .handle(&read_request(&f.outside_file), &subject, &[lease_id])
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Denied { .. }),
        "expected Denied for out-of-scope path, got {outcome:?}"
    );
    assert_eq!(
        f.sandbox.staged_count(),
        0,
        "denied actions must never reach the sandbox"
    );
    assert_eq!(f.sandbox.committed_count(), 0);
}

#[tokio::test]
async fn pipeline_pending_approval_is_durable_with_zero_execution() {
    let f = fixture().await;
    // A real vault identity, but NO lease: the kernel must not allow.
    let info = f
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let subject = info.subject;

    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[])
        .await;
    let approval_request_id = match outcome {
        ToolOutcome::PendingApproval {
            approval_request_id,
            ..
        } => approval_request_id,
        other => panic!("expected PendingApproval, got {other:?}"),
    };
    assert_eq!(
        f.sandbox.staged_count(),
        0,
        "pending actions must never reach the sandbox"
    );
    assert_eq!(f.sandbox.committed_count(), 0);

    // The approval request is durable: visible to the host/VHL poller
    // from the database, and the in-memory mirror agrees on the id.
    let pending: Vec<PendingApprovalView> = f
        .kernel
        .pending_approvals()
        .await
        .expect("pending approvals");
    assert!(
        pending
            .iter()
            .any(|p| p.request_id == approval_request_id && p.session_subject == subject),
        "durable approval request must be pollable, got {pending:?}"
    );
    let drained = f.kernel.drain_approval_requests().await;
    assert!(
        drained.iter().any(|r| r.request_id == approval_request_id),
        "outbox mirror must carry the same request id"
    );
}

/// The approval request survives a full kernel restart: close the client
/// (dropping its runtime and in-memory state), reopen on the same file
/// database, and the request is still pollable.
#[tokio::test]
async fn restart_preserves_budget_consumption() {
    use lumen_db::Database;

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("kernel.sqlite");
    let workspace = WorkspaceId::new();

    let lease_id = {
        let mut config = AuthorityKernelConfig::test_config();
        config.db = AuthorityDb::Path(db_path.clone());
        config.workspace = workspace;
        let kernel = AuthorityKernelClient::open(config)
            .await
            .expect("open authority kernel");
        let info = SessionIdentityAuthority::start_session_identity(&kernel, None)
            .await
            .expect("start session identity");
        let lease = kernel
            .issue_root_lease(RootLeaseParams {
                lease_id: uuid::Uuid::new_v4().to_string(),
                subject: info.subject.clone(),
                scope: ResourceScope::default(),
                limits: LeaseLimits {
                    not_before_ms: 0,
                    expires_at_ms: i64::MAX,
                    budget: Budget::new().set(BudgetDimension::Executions, 2),
                    max_executions: None,
                    single_use: false,
                },
                depth_limit: 4,
                lease_nonce: format!("budget-test-{}", uuid::Uuid::new_v4()),
                issued_at_ms: now_ms(),
            })
            .await
            .expect("issue root lease");
        let remaining = kernel
            .budget_remaining(&lease.lease_id)
            .await
            .expect("budget remaining");
        assert_eq!(
            remaining.get(BudgetDimension::Executions),
            2,
            "fresh lease has its full budget"
        );
        // Settle two executions out-of-band through a second connection,
        // simulating the future settle writer (write-through contract:
        // settle updates the durable accounts; the ledger rehydrates).
        let db = Database::connect(&db_path).await.expect("db connect");
        db.debit_kernel_lease(
            &workspace,
            &lease.lease_id,
            &Budget::new().set(BudgetDimension::Executions, 2),
            "settle-budget-test",
            now_ms(),
        )
        .await
        .expect("debit settled spend");
        lease.lease_id
    };

    // Restart: the ledger must rehydrate consumed spend, not reset it.
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(db_path);
    config.workspace = workspace;
    let kernel = AuthorityKernelClient::open(config)
        .await
        .expect("reopen authority kernel");
    let remaining = kernel
        .budget_remaining(&lease_id)
        .await
        .expect("budget remaining after restart");
    assert_eq!(
        remaining.get(BudgetDimension::Executions),
        0,
        "settled spend must survive a kernel restart (no over-authorization)"
    );
}

#[tokio::test]
async fn one_shot_mint_is_atomic_and_single_use() {
    // Enroll a human VHL key with the kernel (fixed test seed; the key
    // never leaves this test).
    let vhl_signing = SigningKey::from_bytes(&[7u8; 32]);
    let vhl_key_id = "test-human-1";
    let mut vhl_keys = HashMap::new();
    vhl_keys.insert(vhl_key_id.to_string(), vhl_signing.verifying_key());

    let f = fixture_with_vhl(vhl_keys).await;
    let info = f
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let subject = info.subject.clone();

    // No lease: authorize → pending approval, zero execution.
    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[])
        .await;
    let approval_id = match outcome {
        ToolOutcome::PendingApproval {
            approval_request_id,
            ..
        } => approval_request_id,
        other => panic!("expected PendingApproval, got {other:?}"),
    };
    assert_eq!(f.sandbox.staged_count(), 0);

    // The human approves. Read the view first: deciding moves the
    // request out of the `requested` listing.
    let view = f
        .kernel
        .pending_approvals()
        .await
        .expect("pending approvals")
        .into_iter()
        .find(|v| v.request_id == approval_id)
        .expect("approval visible");
    f.kernel
        .decide_approval(&approval_id, true, vhl_key_id)
        .await
        .expect("decide approval");

    // Build and sign the grant as the human.
    let mut core_grant = CoreOneShotGrant {
        approval_id: approval_id.clone(),
        action_digest: view.action_digest.clone(),
        session_subject: subject.clone(),
        signer_key_id: vhl_key_id.to_string(),
        nonce: format!("grant-{}", uuid::Uuid::new_v4()),
        created_at_ms: now_ms(),
        expires_at_ms: now_ms() + 600_000,
        signature: String::new(),
    };
    core_grant.sign(&vhl_signing);
    let grant = OneShotGrant {
        approval_id: core_grant.approval_id.clone(),
        action_digest: core_grant.action_digest.clone(),
        session_subject: core_grant.session_subject.clone(),
        signer_key_id: core_grant.signer_key_id.clone(),
        nonce: core_grant.nonce.clone(),
        created_at_ms: core_grant.created_at_ms,
        expires_at_ms: core_grant.expires_at_ms,
        signature: core_grant.signature.clone(),
    };

    // Mint: succeeds exactly once.
    let lease = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
        .await
        .expect("mint one-shot lease");
    assert!(lease.limits.single_use, "one-shot lease is single-use");
    assert_eq!(lease.subject, subject);

    // Replay the same grant: rejected (durable nonce + claimed approval).
    let err = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
        .await
        .expect_err("grant replay must be rejected");
    assert!(
        matches!(err, KernelError::OneShotRejected(_)),
        "replay rejected as OneShotRejected, got {err:?}"
    );

    // The approval is minted and no longer pending.
    let views = f.kernel.pending_approvals().await.expect("pending");
    assert!(
        !views.iter().any(|v| v.request_id == approval_id),
        "minted approval leaves the pending set"
    );

    // The minted lease authorizes its exact action once.
    let outcome = f
        .pipeline
        .handle(
            &read_request(&f.leased_file),
            &subject,
            std::slice::from_ref(&lease.lease_id),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "one-shot lease authorizes its action, got {outcome:?}"
    );
    // Second use of the single-use lease: consumed.
    let outcome = f
        .pipeline
        .handle(
            &read_request(&f.leased_file),
            &subject,
            std::slice::from_ref(&lease.lease_id),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Denied { .. }),
        "single-use lease is consumed after one use, got {outcome:?}"
    );
}

/// A durable transaction failure during one-shot mint rolls back ALL
/// in-memory side effects: the approval stays `approved`, the grant nonce
/// is unburned (retry with the same grant succeeds), the pending action
/// cache is intact, and no budget-ledger account leaks.
#[tokio::test]
async fn one_shot_durable_failure_rolls_back_cleanly() {
    let vhl_signing = SigningKey::from_bytes(&[7u8; 32]);
    let vhl_key_id = "test-human-1";
    let mut vhl_keys = HashMap::new();
    vhl_keys.insert(vhl_key_id.to_string(), vhl_signing.verifying_key());

    // File-backed DB so we can break the store from outside.
    let db_dir = tempfile::tempdir().expect("tempdir");
    let db_path = db_dir.path().join("kernel.sqlite");
    let f = fixture_with_db(vhl_keys, Some(db_path.clone())).await;

    let info = f
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let subject = info.subject.clone();

    // Authorize → pending approval.
    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[])
        .await;
    let approval_id = match outcome {
        ToolOutcome::PendingApproval {
            approval_request_id,
            ..
        } => approval_request_id,
        other => panic!("expected PendingApproval, got {other:?}"),
    };
    let view = f
        .kernel
        .pending_approvals()
        .await
        .expect("pending approvals")
        .into_iter()
        .find(|v| v.request_id == approval_id)
        .expect("approval visible");
    f.kernel
        .decide_approval(&approval_id, true, vhl_key_id)
        .await
        .expect("decide approval");

    // Build and sign the grant.
    let mut core_grant = CoreOneShotGrant {
        approval_id: approval_id.clone(),
        action_digest: view.action_digest.clone(),
        session_subject: subject.clone(),
        signer_key_id: vhl_key_id.to_string(),
        nonce: format!("grant-{}", uuid::Uuid::new_v4()),
        created_at_ms: now_ms(),
        expires_at_ms: now_ms() + 600_000,
        signature: String::new(),
    };
    core_grant.sign(&vhl_signing);
    let grant = OneShotGrant {
        approval_id: core_grant.approval_id.clone(),
        action_digest: core_grant.action_digest.clone(),
        session_subject: core_grant.session_subject.clone(),
        signer_key_id: core_grant.signer_key_id.clone(),
        nonce: core_grant.nonce.clone(),
        created_at_ms: core_grant.created_at_ms,
        expires_at_ms: core_grant.expires_at_ms,
        signature: core_grant.signature.clone(),
    };

    // Break the store: hold an exclusive lock from a second connection.
    // The kernel's durable transaction will fail with "database is locked".
    // (File permissions don't work: tests run as root, which bypasses them.)
    let lock_db = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite:{}?mode=rwc", db_path.display()))
        .await
        .expect("lock connection");
    sqlx::query("BEGIN EXCLUSIVE")
        .execute(&lock_db)
        .await
        .expect("exclusive lock");

    let err = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
        .await
        .expect_err("mint must fail when the store is locked");
    assert!(
        matches!(err, KernelError::Unavailable(_)),
        "store failure is Unavailable, got {err:?}"
    );

    // Release the lock.
    sqlx::query("ROLLBACK").execute(&lock_db).await.ok();
    lock_db.close().await;

    // Retry with the SAME grant: succeeds. This proves:
    // - the approval is still `approved` (not claimed);
    // - the grant nonce was forgotten, not burned (no replay rejection);
    // - the pending action cache was restored (not lost);
    // - no ledger account leaked (the retry's fresh mint registers cleanly).
    let lease = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
        .await
        .expect("retry after rollback must succeed");
    assert!(lease.limits.single_use);
    assert_eq!(lease.subject, subject);

    // The retried lease works.
    let outcome = f
        .pipeline
        .handle(
            &read_request(&f.leased_file),
            &subject,
            std::slice::from_ref(&lease.lease_id),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "retried lease authorizes, got {outcome:?}"
    );
}

/// One-shot mint survives a kernel restart: the lease is durable, the
/// grant nonce stays burned (replay rejected), and the approval stays
/// claimed. Note: the lease itself is NOT usable after restart — the
/// kernel generates fresh issuer keys on boot, and old-issuer leases are
/// invalid by design (see historical-key custody notes). The durability
/// guarantee is that the store reflects the mint (no lost state), not
/// that the lease remains valid across an issuer rotation.
#[tokio::test]
async fn one_shot_mint_survives_kernel_restart() {
    let vhl_signing = SigningKey::from_bytes(&[7u8; 32]);
    let vhl_key_id = "test-human-1";
    let mut vhl_keys = HashMap::new();
    vhl_keys.insert(vhl_key_id.to_string(), vhl_signing.verifying_key());

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("kernel.db");
    let db_path2 = db_path.clone();
    let workspace = WorkspaceId::new();

    // Phase 1: mint a one-shot lease.
    let (subject, lease_id, approval_id, grant_nonce) = {
        let f =
            fixture_with_db_and_workspace(vhl_keys.clone(), Some(db_path.clone()), Some(workspace))
                .await;
        let info = f
            .kernel
            .start_session_identity(None)
            .await
            .expect("start session identity");
        let subject = info.subject.clone();

        let outcome = f
            .pipeline
            .handle(&read_request(&f.leased_file), &subject, &[])
            .await;
        let approval_id = match outcome {
            ToolOutcome::PendingApproval {
                approval_request_id,
                ..
            } => approval_request_id,
            other => panic!("expected PendingApproval, got {other:?}"),
        };
        let view = f
            .kernel
            .pending_approvals()
            .await
            .expect("pending approvals")
            .into_iter()
            .find(|v| v.request_id == approval_id)
            .expect("approval visible");
        f.kernel
            .decide_approval(&approval_id, true, vhl_key_id)
            .await
            .expect("decide approval");

        let mut core_grant = CoreOneShotGrant {
            approval_id: approval_id.clone(),
            action_digest: view.action_digest.clone(),
            session_subject: subject.clone(),
            signer_key_id: vhl_key_id.to_string(),
            nonce: format!("grant-{}", uuid::Uuid::new_v4()),
            created_at_ms: now_ms(),
            expires_at_ms: now_ms() + 600_000,
            signature: String::new(),
        };
        core_grant.sign(&vhl_signing);
        let grant = OneShotGrant {
            approval_id: core_grant.approval_id.clone(),
            action_digest: core_grant.action_digest.clone(),
            session_subject: core_grant.session_subject.clone(),
            signer_key_id: core_grant.signer_key_id.clone(),
            nonce: core_grant.nonce.clone(),
            created_at_ms: core_grant.created_at_ms,
            expires_at_ms: core_grant.expires_at_ms,
            signature: core_grant.signature.clone(),
        };
        let lease = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
            .await
            .expect("mint one-shot lease");
        // `f` (and its kernel) drops here: simulated crash.
        (
            subject,
            lease.lease_id.clone(),
            approval_id,
            grant.nonce.clone(),
        )
    };

    // Phase 2: reopen the kernel on the same DB and workspace (restart).
    let f2 = fixture_with_db_and_workspace(vhl_keys, Some(db_path2), Some(workspace)).await;

    // The lease IS durable: it's in the store.
    let db = Database::connect(&db_path).await.expect("reconnect");
    let mut conn = db.pool().acquire().await.expect("acquire");
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM kernel_leases WHERE lease_id = ?")
        .bind(&lease_id)
        .fetch_one(&mut *conn)
        .await
        .expect("count lease");
    assert_eq!(row.0, 1, "minted lease must be durable across restart");
    drop(conn);
    drop(db);

    // But it's not usable: the restarted kernel has fresh issuer keys,
    // and old-issuer leases are invalid by design.
    let outcome = f2
        .pipeline
        .handle(
            &read_request(&f2.leased_file),
            &subject,
            std::slice::from_ref(&lease_id),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Denied { .. }),
        "old-issuer lease rejected after restart, got {outcome:?}"
    );

    // The grant nonce is still burned: replay is rejected even though the
    // in-memory nonce set was lost in the crash (the durable nonce gate
    // holds).
    let replay_grant = OneShotGrant {
        approval_id: approval_id.clone(),
        action_digest: "bogus".to_string(),
        session_subject: subject.clone(),
        signer_key_id: vhl_key_id.to_string(),
        nonce: grant_nonce,
        created_at_ms: now_ms(),
        expires_at_ms: now_ms() + 600_000,
        signature: "bogus".to_string(),
    };
    let err = KernelClient::request_one_shot_lease(f2.kernel.as_ref(), &replay_grant)
        .await
        .expect_err("replay after restart must be rejected");
    assert!(
        matches!(err, KernelError::OneShotRejected(_)),
        "replay rejected as OneShotRejected, got {err:?}"
    );
}

#[tokio::test]
async fn approval_request_survives_kernel_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("kernel.sqlite");
    let leased_file = dir.path().join("a.txt");
    std::fs::write(&leased_file, b"hello").unwrap();
    let leased_path = leased_file.to_str().unwrap().to_string();

    let approval_request_id = {
        // One explicit workspace: the reopen must address the same
        // authority rows (test_config() would mint a fresh one).
        let mut config = AuthorityKernelConfig::test_config();
        config.db = AuthorityDb::Path(db_path.clone());
        config.workspace = WorkspaceId::new();
        let workspace = config.workspace;
        let kernel = Arc::new(
            AuthorityKernelClient::open(config)
                .await
                .expect("open authority kernel"),
        );
        let sandbox = Arc::new(MockSandboxRunner::new());
        let pipeline = ToolPipeline::new(
            Arc::new(read_file_catalog().unwrap()),
            kernel.clone(),
            sandbox,
        );
        let info = kernel
            .start_session_identity(None)
            .await
            .expect("start session identity");
        let outcome = pipeline
            .handle(&read_request(&leased_path), &info.subject, &[])
            .await;
        let id = match outcome {
            ToolOutcome::PendingApproval {
                approval_request_id,
                ..
            } => approval_request_id,
            other => panic!("expected PendingApproval, got {other:?}"),
        };
        // `kernel`, `pipeline`, and the private runtime drop here.
        drop(pipeline);
        drop(kernel);
        (id, workspace)
    };
    let (approval_request_id, workspace) = approval_request_id;

    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(db_path);
    config.workspace = workspace;
    let kernel = AuthorityKernelClient::open(config)
        .await
        .expect("reopen authority kernel");
    let pending: Vec<PendingApprovalView> =
        kernel.pending_approvals().await.expect("pending approvals");
    assert!(
        pending.iter().any(|p| p.request_id == approval_request_id),
        "approval request must survive restart, got {pending:?}"
    );
    // The audit chain written before the restart still verifies.
    kernel
        .verify_kernel_audit()
        .await
        .expect("audit chain must verify after restart");
}

#[tokio::test]
async fn audit_failure_is_fail_closed() {
    // File-backed DB so the test can break the audit store from outside
    // the kernel's pool.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("kernel.db");
    let f = fixture_with_db(HashMap::new(), Some(db_path.clone())).await;
    let (subject, lease_id) = leased_subject(&f).await;

    // Sanity: the action authorizes before we break the store.
    let outcome = f
        .pipeline
        .handle(
            &read_request(&f.leased_file),
            &subject,
            std::slice::from_ref(&lease_id),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "expected Completed before breaking the store, got {outcome:?}"
    );

    // Break the audit store from a separate connection. FKs are off on
    // this connection only; the kernel's pool still enforces them.
    let db = Database::connect(&db_path).await.expect("connect db");
    let mut conn = db.pool().acquire().await.expect("acquire");
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *conn)
        .await
        .expect("pragma");
    sqlx::query("DROP TABLE kernel_audit_events")
        .execute(&mut *conn)
        .await
        .expect("drop audit table");
    drop(conn);
    drop(db);

    // The same action now fails closed: the kernel returns an error
    // (never an allow), and the sandbox sees zero new executions.
    let staged_before = f.sandbox.staged_count();
    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[lease_id])
        .await;
    assert!(
        !matches!(outcome, ToolOutcome::Completed { .. }),
        "audit failure must not allow execution, got {outcome:?}"
    );
    assert_eq!(
        f.sandbox.staged_count(),
        staged_before,
        "failed audit must not stage new executions"
    );
}

/// One-shot mint with a post-commit audit failure: the lease IS durable
/// (committed before the audit), but the caller never learns the lease ID
/// (fail-closed). The grant nonce is burned and the approval is claimed,
/// so the human must re-propose the action; the minted-but-not-returned
/// lease remains in the store and is visible on restart.
#[tokio::test]
async fn one_shot_audit_failure_is_minted_but_not_returned() {
    let vhl_signing = SigningKey::from_bytes(&[7u8; 32]);
    let vhl_key_id = "test-human-1";
    let mut vhl_keys = HashMap::new();
    vhl_keys.insert(vhl_key_id.to_string(), vhl_signing.verifying_key());

    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("kernel.db");
    let f = fixture_with_db(vhl_keys, Some(db_path.clone())).await;

    let info = f
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let subject = info.subject.clone();

    // Authorize → pending → approve.
    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[])
        .await;
    let approval_id = match outcome {
        ToolOutcome::PendingApproval {
            approval_request_id,
            ..
        } => approval_request_id,
        other => panic!("expected PendingApproval, got {other:?}"),
    };
    let view = f
        .kernel
        .pending_approvals()
        .await
        .expect("pending approvals")
        .into_iter()
        .find(|v| v.request_id == approval_id)
        .expect("approval visible");
    f.kernel
        .decide_approval(&approval_id, true, vhl_key_id)
        .await
        .expect("decide approval");

    let mut core_grant = CoreOneShotGrant {
        approval_id: approval_id.clone(),
        action_digest: view.action_digest.clone(),
        session_subject: subject.clone(),
        signer_key_id: vhl_key_id.to_string(),
        nonce: format!("grant-{}", uuid::Uuid::new_v4()),
        created_at_ms: now_ms(),
        expires_at_ms: now_ms() + 600_000,
        signature: String::new(),
    };
    core_grant.sign(&vhl_signing);
    let grant = OneShotGrant {
        approval_id: core_grant.approval_id.clone(),
        action_digest: core_grant.action_digest.clone(),
        session_subject: core_grant.session_subject.clone(),
        signer_key_id: core_grant.signer_key_id.clone(),
        nonce: core_grant.nonce.clone(),
        created_at_ms: core_grant.created_at_ms,
        expires_at_ms: core_grant.expires_at_ms,
        signature: core_grant.signature.clone(),
    };

    // Break the audit store.
    let db = Database::connect(&db_path).await.expect("connect db");
    let mut conn = db.pool().acquire().await.expect("acquire");
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *conn)
        .await
        .expect("pragma");
    sqlx::query("DROP TABLE kernel_audit_events")
        .execute(&mut *conn)
        .await
        .expect("drop audit table");
    drop(conn);
    drop(db);

    // Mint: the durable commit succeeds, then the audit fails. The caller
    // gets an error and never learns the lease ID.
    let err = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
        .await
        .expect_err("mint must fail when audit is broken");
    assert!(
        matches!(err, KernelError::AuditFailed(_)),
        "audit failure surfaces as AuditFailed, got {err:?}"
    );

    // But the lease IS in the durable store (committed before the audit).
    // Query the leases table directly.
    let db = Database::connect(&db_path).await.expect("reconnect");
    let mut conn = db.pool().acquire().await.expect("acquire");
    let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM kernel_leases WHERE subject = ?")
        .bind(&subject)
        .fetch_one(&mut *conn)
        .await
        .expect("count leases");
    assert_eq!(row.0, 1, "the lease must be durable despite audit failure");
    drop(conn);
    drop(db);

    // The grant cannot be retried: nonce burned, approval claimed.
    let err = KernelClient::request_one_shot_lease(f.kernel.as_ref(), &grant)
        .await
        .expect_err("replay after audit failure must be rejected");
    assert!(
        matches!(err, KernelError::OneShotRejected(_)),
        "replay rejected as OneShotRejected, got {err:?}"
    );
}

#[tokio::test]
async fn lease_store_failure_is_unavailable_not_silent_deny() {
    // File-backed DB so the test can break the lease store from outside.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("kernel.db");
    let f = fixture_with_db(HashMap::new(), Some(db_path.clone())).await;
    let (subject, lease_id) = leased_subject(&f).await;

    // Break the lease store from a separate connection. The resolver now
    // sees a repository error instead of the lease row. FKs are off on
    // this connection only; the kernel's pool still enforces them.
    let db = Database::connect(&db_path).await.expect("connect db");
    let mut conn = db.pool().acquire().await.expect("acquire");
    sqlx::query("PRAGMA foreign_keys=OFF")
        .execute(&mut *conn)
        .await
        .expect("pragma");
    sqlx::query("DROP TABLE kernel_leases")
        .execute(&mut *conn)
        .await
        .expect("drop lease table");
    drop(conn);
    drop(db);

    // The kernel must surface the outage as unavailability — never as a
    // silent policy deny (which would misreport the outage) or an allow.
    let outcome = f
        .pipeline
        .handle(&read_request(&f.leased_file), &subject, &[lease_id])
        .await;
    assert!(
        !matches!(outcome, ToolOutcome::Completed { .. }),
        "store outage must not allow execution, got {outcome:?}"
    );
    assert!(
        !matches!(outcome, ToolOutcome::Denied { .. }),
        "store outage must not masquerade as a policy deny, got {outcome:?}"
    );
    assert_eq!(
        f.sandbox.staged_count(),
        0,
        "store outage must not reach the sandbox"
    );
}
