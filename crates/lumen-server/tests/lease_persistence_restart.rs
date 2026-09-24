//! Acceptance matrix for lease persistence across kernel restarts
//! (spec §8, "Lumen Lease Persistence Across Kernel Restarts").
//!
//! Every test uses a file-backed database and drives a real close +
//! [`AuthorityKernelClient::open`] cycle ("restart") against the same db
//! path and [`WorkspaceId`]. Only the public client API and the
//! [`lumen_db`] store are touched: no non-test source is modified.
//!
//! Map to the spec's acceptance criteria:
//! - §8.1  `restart_lease_stays_valid`
//! - §8.2  `restart_expired_lease_stays_dead`
//! - §8.3  `restart_revoked_lease_stays_dead`
//! - §8.4  `restart_one_shot_replay_rejected`
//! - §8.5  `unknown_issuer_generation_fails_closed`
//! - §8.6  `purge_after_last_lease_dies`
//! - §8.7  `purge_blocked_while_referenced`
//! - §8.8  `pending_vhl_restart`
//! - §8.9  `child_lease_survives_restart`
//! - §8.10 (no-new-delegation) is covered structurally by
//!   `restored_session_cannot_mint`: the vault is empty after a restart,
//!   so no signing key exists to mint with.
//! - §8.11 `destroyed_session_stays_destroyed` (+
//!   `destroy_session_revokes_orphaned_delegation_restart_succeeds`: the
//!   kernel destroy path revokes chain-orphaned delegations so the next
//!   boot succeeds)
//! - §8.12 `killed_generation_fails_closed`
//! - §8.13 `startup_tamper_detection`
//! - §8.14 `audit_and_budget_continuity` (audit half; the budget half is
//!   `restart_preserves_budget_consumption` in `kernel_authority_pipeline`)
//! - §8.15 guarded delete/update: covered by `lumen-db`'s
//!   `lease_persistence.rs` (worker A) — not duplicated here.
//! - §8.16 (guarded delete at the db layer) — same, see above.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use lumen_core::budget::{Budget, BudgetDimension, BudgetLedger};
use lumen_core::canonical::ResourceScope;
use lumen_core::identity::{PrincipalId, WorkspaceId};
use lumen_core::lease::{
    ChildLeaseParams, LEASE_PROTOCOL_VERSION, LeaseDocument as CoreLeaseDocument,
    LeaseLimits as CoreLeaseLimits, OneShotGrant as CoreOneShotGrant, RevocationIndex,
    RootLeaseParams, SessionRegistry, mint_child_lease,
};
use lumen_core::nonce::NonceStore;
use lumen_core::operator::{AuthorityFuture, AuthorityRequest, OperatorAuthorityPort};
use lumen_core::session_identity::session_address;
use lumen_db::Database;
use lumen_db::lease::KernelAuditQuery;
use lumen_server::{
    AuthorityDb, AuthorityKernelClient, AuthorityKernelConfig, Catalog, CatalogError, EffectClass,
    KernelClient, KernelError, LeaseDocument, LeaseLimits as HostLeaseLimits, MockSandboxRunner,
    OneShotGrant, PiToolRequest, ProjectionKind, SessionIdentityAuthority, ToolDef, ToolOutcome,
    ToolPipeline, now_ms,
};

/// Stub operator authority: allows or denies every `KeyManagement`
/// request. `None` in the config means no authority is configured at all.
struct StubAuthority {
    allow: bool,
}

impl OperatorAuthorityPort for StubAuthority {
    fn authorize<'a>(&'a self, _r: &'a AuthorityRequest) -> AuthorityFuture<'a> {
        let allow = self.allow;
        Box::pin(async move { Ok(allow) })
    }
}

fn actor() -> PrincipalId {
    PrincipalId::new("test", "operator").expect("principal")
}

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

/// One restart-test environment: a file-backed db plus a stable leased
/// file (the one-shot action digest binds the absolute path, so the file
/// must not move between restarts).
struct RestartEnv {
    _db_dir: tempfile::TempDir,
    _file_dir: tempfile::TempDir,
    db_path: PathBuf,
    leased_file: String,
    workspace: WorkspaceId,
}

fn restart_env() -> RestartEnv {
    let db_dir = tempfile::tempdir().expect("tempdir");
    let file_dir = tempfile::tempdir().expect("tempdir");
    let leased = file_dir.path().join("a.txt");
    std::fs::write(&leased, b"hello").unwrap();
    RestartEnv {
        db_path: db_dir.path().join("kernel.sqlite"),
        leased_file: leased.to_str().unwrap().to_string(),
        workspace: WorkspaceId::new(),
        _db_dir: db_dir,
        _file_dir: file_dir,
    }
}

struct KernelHandles {
    kernel: Arc<AuthorityKernelClient>,
    pipeline: ToolPipeline<AuthorityKernelClient, MockSandboxRunner>,
    #[allow(dead_code)]
    sandbox: Arc<MockSandboxRunner>,
}

/// Open the kernel on the env's db path + workspace (a "boot"). Dropping
/// the returned handles and calling this again is a restart.
async fn open_kernel(
    env: &RestartEnv,
    vhl_keys: HashMap<String, VerifyingKey>,
    operator_allow: Option<bool>,
) -> KernelHandles {
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(env.db_path.clone());
    config.workspace = env.workspace;
    config.vhl_keys = vhl_keys;
    config.operator_authority = operator_allow
        .map(|a| Arc::new(StubAuthority { allow: a }) as Arc<dyn OperatorAuthorityPort>);
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
    KernelHandles {
        kernel,
        pipeline,
        sandbox,
    }
}

/// Mint a root lease for a fresh vault session, valid for `lifetime_ms`.
async fn mint_root(
    kernel: &AuthorityKernelClient,
    tag: &str,
    lifetime_ms: i64,
) -> (String, LeaseDocument) {
    let info = kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let now = now_ms();
    let lease = kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: format!("lease-{tag}-{}", uuid::Uuid::new_v4()),
            subject: info.subject.clone(),
            scope: ResourceScope::default(),
            limits: CoreLeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + lifetime_ms,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("nonce-{tag}-{}", uuid::Uuid::new_v4()),
            issued_at_ms: now,
        })
        .await
        .expect("issue root lease");
    (info.subject, lease)
}

/// Drive `decide` (via the pipeline) with no covering lease; expect the
/// kernel to emit a pending VHL approval request. Returns its id.
async fn decide_pending(h: &KernelHandles, leased_file: &str, subject: &str) -> String {
    let outcome = h
        .pipeline
        .handle(&read_request(leased_file), subject, &[])
        .await;
    match outcome {
        ToolOutcome::PendingApproval {
            approval_request_id,
            ..
        } => approval_request_id,
        other => panic!("expected PendingApproval, got {other:?}"),
    }
}

/// Build and human-sign a one-shot grant for an approval request.
fn sign_grant(
    vhl_signing: &SigningKey,
    vhl_key_id: &str,
    approval_id: &str,
    action_digest: &str,
    subject: &str,
) -> OneShotGrant {
    let mut core = CoreOneShotGrant {
        approval_id: approval_id.to_string(),
        action_digest: action_digest.to_string(),
        session_subject: subject.to_string(),
        signer_key_id: vhl_key_id.to_string(),
        nonce: format!("grant-{}", uuid::Uuid::new_v4()),
        created_at_ms: now_ms(),
        expires_at_ms: now_ms() + 600_000,
        signature: String::new(),
    };
    core.sign(vhl_signing);
    OneShotGrant {
        approval_id: core.approval_id.clone(),
        action_digest: core.action_digest.clone(),
        session_subject: core.session_subject.clone(),
        signer_key_id: core.signer_key_id.clone(),
        nonce: core.nonce.clone(),
        created_at_ms: core.created_at_ms,
        expires_at_ms: core.expires_at_ms,
        signature: core.signature.clone(),
    }
}

/// Full VHL flow: pending approval → human decision → signed grant →
/// minted one-shot lease. Returns `(session subject, lease)`.
async fn mint_one_shot(
    h: &KernelHandles,
    leased_file: &str,
    vhl_signing: &SigningKey,
    vhl_key_id: &str,
) -> (String, LeaseDocument) {
    let info = h
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let subject = info.subject.clone();
    let approval_id = decide_pending(h, leased_file, &subject).await;
    let view = h
        .kernel
        .pending_approvals()
        .await
        .expect("pending approvals")
        .into_iter()
        .find(|v| v.request_id == approval_id)
        .expect("approval visible");
    h.kernel
        .decide_approval(&approval_id, true, vhl_key_id)
        .await
        .expect("decide approval");
    let grant = sign_grant(
        vhl_signing,
        vhl_key_id,
        &approval_id,
        &view.action_digest,
        &subject,
    );
    let lease = KernelClient::request_one_shot_lease(h.kernel.as_ref(), &grant)
        .await
        .expect("mint one-shot lease");
    assert!(lease.limits.single_use, "one-shot lease is single-use");
    (subject, lease)
}

/// Core → host lease conversion (mirrors the kernel's private
/// `to_host_lease`): the store holds core docs, `verify_lease` takes host
/// docs, and hand-built test docs must cross that boundary.
fn to_host_doc(core: &CoreLeaseDocument) -> LeaseDocument {
    LeaseDocument {
        protocol_version: core.protocol_version,
        lease_id: core.lease_id.clone(),
        parent_id: core.parent_id.clone(),
        subject: core.subject.clone(),
        issuer_key_id: core.issuer_key_id.clone(),
        issued_at_ms: core.issued_at_ms,
        scope: serde_json::to_value(&core.scope).unwrap_or(serde_json::Value::Null),
        limits: HostLeaseLimits {
            not_before_ms: core.limits.not_before_ms,
            expires_at_ms: core.limits.expires_at_ms,
            budget: serde_json::to_value(&core.limits.budget).unwrap_or(serde_json::Value::Null),
            max_executions: core.limits.max_executions,
            single_use: core.limits.single_use,
        },
        depth: core.depth,
        depth_limit: core.depth_limit,
        lease_nonce: core.lease_nonce.clone(),
        signature: core.signature.clone(),
    }
}

fn assert_unknown_generation(err: &KernelError, key_id: &str) {
    match err {
        KernelError::VerificationFailed(msg) => assert!(
            msg.contains("unknown issuer generation") && msg.contains(key_id),
            "expected unknown-generation error for {key_id}, got {msg}"
        ),
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

fn assert_killed_generation(err: &KernelError, key_id: &str) {
    match err {
        KernelError::VerificationFailed(msg) => assert!(
            msg.contains("was killed") && msg.contains(key_id),
            "expected killed-generation error for {key_id}, got {msg}"
        ),
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
}

/// §8.1 — a root lease minted under generation N still verifies after a
/// restart (generation N+1), resolved through the retired generation's
/// recorded verifying key.
#[tokio::test]
async fn restart_lease_stays_valid() {
    let env = restart_env();
    let lease = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (_, lease) = mint_root(&h.kernel, "t1", 3_600_000).await;
        lease
        // `h` drops: simulated crash / upgrade.
    };

    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let verified = h2
        .kernel
        .verify_lease(&lease)
        .await
        .expect("lease must verify after restart");
    assert_eq!(verified.lease_id, lease.lease_id);
    assert!(!verified.revoked, "fresh lease must not be revoked");

    // The doc's issuer is the retired (pre-restart) generation: two
    // issuer generations are recorded, and the lease names the older one.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    let issuer_gens: Vec<_> = gens.iter().filter(|g| g.role == "issuer").collect();
    assert_eq!(
        issuer_gens.len(),
        2,
        "one generation per boot, got {issuer_gens:?}"
    );
    let current = issuer_gens
        .iter()
        .max_by_key(|g| g.created_at_ms)
        .expect("current generation");
    assert_ne!(
        lease.issuer_key_id, current.key_id,
        "the lease must name the retired generation, not the current one"
    );
    assert!(
        issuer_gens.iter().any(|g| g.key_id == lease.issuer_key_id),
        "the lease's generation must be among the recorded ones"
    );
}

/// §8.2 — an expired lease stays dead across a restart, and the failure
/// is the expiry reason (D4 ordering), not a signature error.
///
/// A second, long-lived lease keeps the issuing generation referenced so
/// the boot purge pass cannot delete it: the point here is expiry, not
/// key retention.
#[tokio::test]
async fn restart_expired_lease_stays_dead() {
    let env = restart_env();
    let (short_lease, long_lease) = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (_, short) = mint_root(&h.kernel, "t2-short", 1_200).await;
        let (_, long) = mint_root(&h.kernel, "t2-long", 3_600_000).await;
        (short, long)
    };
    tokio::time::sleep(Duration::from_secs(2)).await;

    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let err = h2
        .kernel
        .verify_lease(&short_lease)
        .await
        .expect_err("expired lease must fail verification");
    match &err {
        KernelError::VerificationFailed(msg) => assert!(
            msg.contains("not live"),
            "expected the expiry reason, got: {msg}"
        ),
        other => panic!("expected VerificationFailed, got {other:?}"),
    }
    // Sanity: the surviving lease from the same generation still verifies.
    h2.kernel
        .verify_lease(&long_lease)
        .await
        .expect("long-lived lease from the same generation must still verify");
}

/// §8.3 — a lease revoked before the restart stays revoked after it.
///
/// The anchor lease keeps the issuing generation referenced so the boot
/// purge cannot delete it: with the generation retained, the denial must
/// surface as `Revoked`, proving revocation is enforced independently of
/// key retention.
#[tokio::test]
async fn restart_revoked_lease_stays_dead() {
    let env = restart_env();
    let (lease, anchor) = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (_, lease) = mint_root(&h.kernel, "t3", 3_600_000).await;
        let (_, anchor) = mint_root(&h.kernel, "t3-anchor", 3_600_000).await;
        (lease, anchor)
    };

    // Revoke durably through the store, outside the (dropped) kernel.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.record_kernel_revocation(&env.workspace, &lease.lease_id, now_ms(), "test revocation")
        .await
        .expect("record revocation");
    drop(db);

    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let err = h2
        .kernel
        .verify_lease(&lease)
        .await
        .expect_err("revoked lease must fail verification");
    assert!(
        matches!(err, KernelError::Revoked(ref id) if *id == lease.lease_id),
        "expected Revoked, got {err:?}"
    );
    // The anchor lease (same generation, not revoked) still verifies.
    h2.kernel
        .verify_lease(&anchor)
        .await
        .expect("unrevoked lease must still verify");
}

/// §8.3, second half — revocation also denies after the issuing
/// generation is purged. D4 ordering holds on the `verify_lease` path:
/// revocation is checked before key resolution, so the denial surfaces
/// as `Revoked` even though the generation row is gone. (`validate_chain`,
/// used by `decide` and the boot self-check, follows the same order.)
#[tokio::test]
async fn restart_revoked_lease_denied_after_generation_purged() {
    let env = restart_env();
    let lease = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (_, lease) = mint_root(&h.kernel, "t3b", 3_600_000).await;
        lease
    };

    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.record_kernel_revocation(&env.workspace, &lease.lease_id, now_ms(), "test revocation")
        .await
        .expect("record revocation");
    drop(db);

    // Restart: the revoked lease is not live, so the boot purge pass
    // deletes its (now unreferenced) generation.
    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    assert!(
        !gens.iter().any(|g| g.key_id == lease.issuer_key_id),
        "the revoked lease's generation should have been purged"
    );
    drop(db);

    let err = h2
        .kernel
        .verify_lease(&lease)
        .await
        .expect_err("revoked lease must still be denied after its generation is purged");
    assert!(
        matches!(err, KernelError::Revoked(ref id) if *id == lease.lease_id),
        "expected Revoked (D4: revocation before key resolution), got {err:?}"
    );
}

/// §8.4 — a one-shot lease consumed before the restart cannot be replayed
/// after it: the durable `kernel_one_shot_uses` record (not the lost
/// in-memory cache) enforces single-use.
#[tokio::test]
async fn restart_one_shot_replay_rejected() {
    let env = restart_env();
    let vhl_signing = SigningKey::from_bytes(&[7u8; 32]);
    let vhl_key_id = "test-human-1";
    let mut vhl_keys = HashMap::new();
    vhl_keys.insert(vhl_key_id.to_string(), vhl_signing.verifying_key());

    let (subject, lease) = {
        let h = open_kernel(&env, vhl_keys.clone(), None).await;
        let (subject, lease) = mint_one_shot(&h, &env.leased_file, &vhl_signing, vhl_key_id).await;
        // Consume it once, pre-restart.
        let outcome = h
            .pipeline
            .handle(
                &read_request(&env.leased_file),
                &subject,
                std::slice::from_ref(&lease.lease_id),
            )
            .await;
        assert!(
            matches!(outcome, ToolOutcome::Completed { .. }),
            "one-shot must authorize its exact action once, got {outcome:?}"
        );
        (subject, lease)
    };

    let h2 = open_kernel(&env, vhl_keys, None).await;
    // The consumption record survived the restart.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    assert!(
        db.is_kernel_one_shot_consumed(&env.workspace, &lease.lease_id)
            .await
            .expect("consumption check"),
        "durable one-shot consumption must survive the restart"
    );
    drop(db);

    // Replay post-restart: denied via the durable record.
    let outcome = h2
        .pipeline
        .handle(
            &read_request(&env.leased_file),
            &subject,
            std::slice::from_ref(&lease.lease_id),
        )
        .await;
    match outcome {
        ToolOutcome::Denied { reason } => assert!(
            reason.contains("consumed"),
            "expected the consumed-one-shot denial, got: {reason}"
        ),
        other => panic!("replayed one-shot must be denied, got {other:?}"),
    }
}

/// §8.5 — a lease naming an unrecorded issuer generation fails closed
/// with `UnknownIssuerGeneration` (distinct from `IssuerMismatch`), both
/// before and after a restart. The boot re-validation self-check must
/// tolerate it (pre-migration leases, spec §7): unknown is counted, not
/// treated as tamper, so the open succeeds.
///
/// Note: the forged document must be *stored* (`verify_lease` only
/// resolves generations for documents that match the kernel's record —
/// an unstored forgery fails earlier as "unknown lease").
#[tokio::test]
async fn unknown_issuer_generation_fails_closed() {
    let env = restart_env();
    let now = now_ms();
    let mut core_doc = CoreLeaseDocument {
        protocol_version: LEASE_PROTOCOL_VERSION,
        lease_id: format!("forged-{}", uuid::Uuid::new_v4()),
        parent_id: None,
        subject: "ed25519:forged-subject".to_string(),
        issuer_key_id: "does-not-exist".to_string(),
        issued_at_ms: now,
        scope: ResourceScope::default(),
        limits: CoreLeaseLimits {
            not_before_ms: now,
            expires_at_ms: now + 3_600_000,
            budget: Budget::new(),
            max_executions: None,
            single_use: false,
        },
        depth: 0,
        depth_limit: 4,
        lease_nonce: format!("forged-nonce-{}", uuid::Uuid::new_v4()),
        signature: String::new(),
    };
    // Well-formed signature, but from a throwaway key no generation
    // records: the failure must be key *resolution*, not signature math.
    core_doc.sign(&SigningKey::from_bytes(&[0x5au8; 32]));
    let host_doc = to_host_doc(&core_doc);

    let h = open_kernel(&env, HashMap::new(), None).await;
    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.insert_kernel_lease(&env.workspace, &core_doc)
        .await
        .expect("insert forged lease");
    drop(db);

    // Pre-restart: fails closed with the unknown-generation message.
    let err = h
        .kernel
        .verify_lease(&host_doc)
        .await
        .expect_err("unknown generation must fail closed");
    assert_unknown_generation(&err, "does-not-exist");
    drop(h);

    // Post-restart: the open succeeds (unknown generations are counted,
    // not tamper) and verification still fails closed the same way.
    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let err = h2
        .kernel
        .verify_lease(&host_doc)
        .await
        .expect_err("unknown generation must fail closed after restart");
    assert_unknown_generation(&err, "does-not-exist");
}

/// §8.12 — killing an issuer generation fails closed for its outstanding
/// leases immediately, durably (the kill survives the restart), without
/// disturbing other generations. Pre-kill, the lease verifies — which
/// also re-proves §8.5's complement (D5: retired generations verify).
#[tokio::test]
async fn killed_generation_fails_closed() {
    let env = restart_env();
    let (lease, gen_a) = {
        let h = open_kernel(&env, HashMap::new(), Some(true)).await;
        let (_, lease) = mint_root(&h.kernel, "t6", 3_600_000).await;
        let gen_a = lease.issuer_key_id.clone();
        (lease, gen_a)
    };

    let h2 = open_kernel(&env, HashMap::new(), Some(true)).await;
    // Pre-kill it verifies: the retired generation resolves (D5).
    h2.kernel
        .verify_lease(&lease)
        .await
        .expect("pre-kill lease must verify (D5 re-proof)");

    let actor = actor();
    let report = h2
        .kernel
        .rotate_issuer_keys("test rotation", &actor)
        .await
        .expect("rotate");
    assert_ne!(report.old_issuer_key_id, report.new_issuer_key_id);
    let killed = h2
        .kernel
        .kill_key_generation(&gen_a, "issuer", "test compromise", &actor)
        .await
        .expect("kill generation");
    assert!(killed, "kill must be recorded");

    let err = h2
        .kernel
        .verify_lease(&lease)
        .await
        .expect_err("lease from a killed generation must fail");
    assert_killed_generation(&err, &gen_a);
    drop(h2);

    // The kill is durable: still fails closed after another restart.
    let h3 = open_kernel(&env, HashMap::new(), Some(true)).await;
    let err = h3
        .kernel
        .verify_lease(&lease)
        .await
        .expect_err("kill must survive the restart");
    assert_killed_generation(&err, &gen_a);
}

/// §8.7 — purge is blocked while a live lease references the retired
/// generation: the report lists it in `skipped_live`, the row survives,
/// and the lease still verifies afterwards (across a restart).
#[tokio::test]
async fn purge_blocked_while_referenced() {
    let env = restart_env();
    let (lease, gen_a) = {
        let h = open_kernel(&env, HashMap::new(), Some(true)).await;
        let (_, lease) = mint_root(&h.kernel, "t7", 3_600_000).await;
        let gen_a = lease.issuer_key_id.clone();
        (lease, gen_a)
    };

    let h2 = open_kernel(&env, HashMap::new(), Some(true)).await;
    let report = h2
        .kernel
        .purge_key_generations(&actor())
        .await
        .expect("purge");
    assert!(
        report.skipped_live.contains(&gen_a),
        "expected {gen_a} in skipped_live, got {report:?}"
    );
    assert!(
        !report.purged.contains(&gen_a),
        "a referenced generation must never be purged, got {report:?}"
    );

    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    assert!(
        gens.iter().any(|g| g.key_id == gen_a),
        "gen A row must survive the purge while referenced"
    );
    drop(db);

    h2.kernel
        .verify_lease(&lease)
        .await
        .expect("live lease must still verify after the purge attempt");
}

/// §8.6 — once the last lease referencing a retired generation dies, the
/// boot purge pass deletes the generation row.
#[tokio::test]
async fn purge_after_last_lease_dies() {
    let env = restart_env();
    let gen_a = {
        let h = open_kernel(&env, HashMap::new(), Some(true)).await;
        let (_, lease) = mint_root(&h.kernel, "t8", 1_200).await;
        let report = h
            .kernel
            .rotate_issuer_keys("test rotation", &actor())
            .await
            .expect("rotate");
        assert_eq!(
            report.old_issuer_key_id, lease.issuer_key_id,
            "the lease must have been minted under the retired generation"
        );
        lease.issuer_key_id.clone()
    };
    // Let the only lease referencing gen A expire.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Restart: the boot purge pass runs after the re-validation self-check.
    let _h2 = open_kernel(&env, HashMap::new(), Some(true)).await;
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    assert!(
        !gens.iter().any(|g| g.key_id == gen_a),
        "gen A row must be purged once its last lease died, got {:?}",
        gens.iter().map(|g| &g.key_id).collect::<Vec<_>>()
    );
    drop(db);
}

/// §8.8 — a VHL approval request interrupted by a restart.
///
/// Honest flow (verified against the implementation): the approval
/// *request* is durable (`vhl_approval_requests`), so post-restart the
/// human can still approve the old request id — but minting then fails
/// closed, because the exact cached action behind the request lives in
/// the memory-only pending map ("re-propose"). Re-deciding the same
/// action post-restart yields a fresh request; approving and granting
/// that one mints a one-shot under the *current* generation, which
/// verifies and authorizes. A second approval of the minted request is
/// rejected by the durable `approved → minted` claim guard.
#[tokio::test]
async fn pending_vhl_restart() {
    let env = restart_env();
    let vhl_signing = SigningKey::from_bytes(&[7u8; 32]);
    let vhl_key_id = "test-human-1";
    let mut vhl_keys = HashMap::new();
    vhl_keys.insert(vhl_key_id.to_string(), vhl_signing.verifying_key());

    // Phase 1: no covering lease → PendingApproval (durable request).
    let (subject, old_approval_id, old_digest) = {
        let h = open_kernel(&env, vhl_keys.clone(), None).await;
        let info = h
            .kernel
            .start_session_identity(None)
            .await
            .expect("start session identity");
        let subject = info.subject.clone();
        let approval_id = decide_pending(&h, &env.leased_file, &subject).await;
        let view = h
            .kernel
            .pending_approvals()
            .await
            .expect("pending approvals")
            .into_iter()
            .find(|v| v.request_id == approval_id)
            .expect("approval visible");
        (subject, approval_id, view.action_digest)
        // `h` drops: the in-memory pending-action cache is gone, the db
        // row is not.
    };

    // Phase 2: restart.
    let h2 = open_kernel(&env, vhl_keys.clone(), None).await;

    // The durable request survived: still pollable by the host/VHL poller.
    let pending = h2.kernel.pending_approvals().await.expect("pending");
    assert!(
        pending.iter().any(|p| p.request_id == old_approval_id),
        "approval request must survive restart, got {pending:?}"
    );

    // The human can still approve the pre-restart request id: the
    // request state machine is durable.
    h2.kernel
        .decide_approval(&old_approval_id, true, vhl_key_id)
        .await
        .expect("approving the durable pre-restart request must succeed");

    // But minting from it fails closed: the exact cached action is
    // memory-only and was lost in the restart.
    let stale_grant = sign_grant(
        &vhl_signing,
        vhl_key_id,
        &old_approval_id,
        &old_digest,
        &subject,
    );
    let err = KernelClient::request_one_shot_lease(h2.kernel.as_ref(), &stale_grant)
        .await
        .expect_err("mint from a pre-restart approval must fail");
    match &err {
        KernelError::OneShotRejected(msg) => assert!(
            msg.contains("no cached action"),
            "expected the re-propose gate, got: {msg}"
        ),
        other => panic!("expected OneShotRejected, got {other:?}"),
    }

    // Re-propose the same action post-restart: fresh request, fresh cache
    // entry.
    let new_approval_id = decide_pending(&h2, &env.leased_file, &subject).await;
    assert_ne!(
        new_approval_id, old_approval_id,
        "re-proposal must mint a fresh request id"
    );
    let view = h2
        .kernel
        .pending_approvals()
        .await
        .expect("pending approvals")
        .into_iter()
        .find(|v| v.request_id == new_approval_id)
        .expect("re-proposed approval visible");
    h2.kernel
        .decide_approval(&new_approval_id, true, vhl_key_id)
        .await
        .expect("decide approval");
    let grant = sign_grant(
        &vhl_signing,
        vhl_key_id,
        &new_approval_id,
        &view.action_digest,
        &subject,
    );
    let lease = KernelClient::request_one_shot_lease(h2.kernel.as_ref(), &grant)
        .await
        .expect("mint one-shot lease post-restart");
    assert!(lease.limits.single_use);

    // Minted under the post-restart (current) generation.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    let current_issuer = gens
        .iter()
        .filter(|g| g.role == "issuer")
        .max_by_key(|g| g.created_at_ms)
        .expect("current issuer generation");
    assert_eq!(
        lease.issuer_key_id, current_issuer.key_id,
        "the one-shot must be minted under the current generation"
    );
    drop(db);

    // It verifies and authorizes its exact action.
    h2.kernel
        .verify_lease(&lease)
        .await
        .expect("minted one-shot must verify");
    let outcome = h2
        .pipeline
        .handle(
            &read_request(&env.leased_file),
            &subject,
            std::slice::from_ref(&lease.lease_id),
        )
        .await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "minted one-shot must authorize, got {outcome:?}"
    );

    // Double-approval of the minted request: rejected by the durable
    // claim (the row is `minted`, not `requested`).
    let err = h2
        .kernel
        .decide_approval(&new_approval_id, true, vhl_key_id)
        .await
        .expect_err("double approval must be rejected");
    assert!(
        matches!(err, KernelError::Unavailable(_)),
        "expected Unavailable (state guard), got {err:?}"
    );
}

/// Durable records for one child-lease scenario: a parent and a child
/// *session* (vault keys live only in the ephemeral kernel) plus a child
/// lease minted under the parent session's signing key. Session keys are
/// deliberately NOT passed back: after a restart there is nothing to
/// pass — that is the point of §8.10.
///
/// The session rows are written *before* the kernel boots, because the
/// boot hydrates the in-memory session registry from them
/// (`issue_root_lease` requires an active subject session).
struct ChildLeaseFixture {
    parent_subject: String,
    child_subject: String,
    parent_lease_id: String,
    child_lease: LeaseDocument,
}

async fn setup_child_lease(
    parent_signing: &SigningKey,
    child_signing: &SigningKey,
    tag: &str,
    child_lifetime_ms: i64,
) -> (RestartEnv, ChildLeaseFixture) {
    let env = restart_env();
    let now = now_ms();
    let parent_subject = session_address(&parent_signing.verifying_key());
    let child_subject = session_address(&child_signing.verifying_key());

    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.ensure_workspace(&env.workspace, "test", now)
        .await
        .expect("ensure workspace");
    db.insert_kernel_session(
        &env.workspace,
        &parent_subject,
        None,
        &hex::encode(parent_signing.verifying_key().to_bytes()),
        now,
    )
    .await
    .expect("parent session");
    db.insert_kernel_session(
        &env.workspace,
        &child_subject,
        Some(&parent_subject),
        &hex::encode(child_signing.verifying_key().to_bytes()),
        now,
    )
    .await
    .expect("child session");
    drop(db);

    let h = open_kernel(&env, HashMap::new(), None).await;
    // The root lease is minted by the kernel itself: issuer-signed and
    // persisted (like any production root lease).
    let root_host = h
        .kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: format!("root-{tag}-{}", uuid::Uuid::new_v4()),
            subject: parent_subject.clone(),
            scope: ResourceScope::default(),
            limits: CoreLeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("root-nonce-{tag}-{}", uuid::Uuid::new_v4()),
            issued_at_ms: now,
        })
        .await
        .expect("issue root lease");

    let db = Database::connect(&env.db_path).await.expect("db connect");
    let parent_doc = db
        .kernel_lease(&env.workspace, &root_host.lease_id)
        .await
        .expect("fetch parent")
        .expect("parent lease stored");

    // The child is minted under the parent *session* key (not the kernel
    // issuer key): exactly what a live agent session would do.
    let mut sessions = SessionRegistry::new();
    sessions.register(
        parent_subject.clone(),
        None,
        parent_signing.verifying_key(),
        now,
    );
    sessions.register(
        child_subject.clone(),
        Some(parent_subject.clone()),
        child_signing.verifying_key(),
        now,
    );
    let nonces = NonceStore::new();
    let revocations = RevocationIndex::default();
    let ledger = BudgetLedger::new();
    // The fixture owns its budget bookkeeping: register the parent's
    // caps so the child's reservation has an account to draw on.
    ledger
        .register_lease(&parent_doc.lease_id, &parent_doc.limits.budget)
        .expect("register parent budget");
    let child_lease = mint_child_lease(
        &parent_doc,
        ChildLeaseParams {
            lease_id: format!("child-{tag}-{}", uuid::Uuid::new_v4()),
            subject: child_subject.clone(),
            scope: ResourceScope::default(),
            limits: CoreLeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + child_lifetime_ms,
                budget: Budget::new().set(BudgetDimension::Executions, 10),
                max_executions: Some(1),
                single_use: false,
            },
            depth_limit: 3,
            lease_nonce: format!("child-nonce-{tag}-{}", uuid::Uuid::new_v4()),
            issued_at_ms: now,
        },
        parent_signing,
        &sessions,
        &revocations,
        &ledger,
        &nonces,
        now,
    )
    .expect("mint child lease");
    db.insert_kernel_lease(&env.workspace, &child_lease)
        .await
        .expect("insert child lease");
    drop(db);
    drop(h);

    (
        env,
        ChildLeaseFixture {
            parent_subject,
            child_subject,
            parent_lease_id: parent_doc.lease_id,
            child_lease: to_host_doc(&child_lease),
        },
    )
}

/// §8.9 — a child lease survives a restart: its `parent_id` chain is
/// still recorded, the session registry is rehydrated from the db
/// (verifying key only), and verification succeeds under the parent
/// session's key.
#[tokio::test]
async fn child_lease_survives_restart() {
    let (env, fixture) = setup_child_lease(
        &SigningKey::from_bytes(&[0x11u8; 32]),
        &SigningKey::from_bytes(&[0x22u8; 32]),
        "t9",
        3_600_000,
    )
    .await;

    let h2 = open_kernel(&env, HashMap::new(), None).await;
    // The session rows survived (verifying keys rehydrated).
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let active = db
        .active_kernel_sessions(&env.workspace)
        .await
        .expect("active sessions");
    assert!(
        active.iter().any(|s| s.subject == fixture.child_subject),
        "child session row must survive restart"
    );
    drop(db);

    // The child → parent link is intact...
    assert_eq!(
        fixture.child_lease.parent_id.as_deref(),
        Some(fixture.parent_lease_id.as_str()),
        "the child lease must still name its parent lease"
    );
    // ...and the child lease verifies through the rehydrated registry.
    let verified = h2
        .kernel
        .verify_lease(&fixture.child_lease)
        .await
        .expect("child lease must verify after restart");
    assert_eq!(verified.lease_id, fixture.child_lease.lease_id);
    assert!(!verified.revoked);
}

/// §8.10 — a restored session cannot mint new child leases: the vault
/// holds no private keys after a restart, and the store structurally
/// cannot yield them. Proven three ways:
/// 1. the `kernel_sessions` schema has no private-key column at all;
/// 2. the active rows expose only verifying keys;
/// 3. the db file (and journals) contain no copy of the private key
///    bytes.
///
/// The child lease still verifies (the registry rehydrated), but the
/// kernel has no signing capability to mint with: no public API takes a
/// restored session to a new signature, and the construction above shows
/// the db cannot supply the private key.
#[tokio::test]
async fn restored_session_cannot_mint() {
    let parent_bytes: [u8; 32] = [0x33u8; 32];
    let (env, fixture) = setup_child_lease(
        &SigningKey::from_bytes(&parent_bytes),
        &SigningKey::from_bytes(&[0x44u8; 32]),
        "t10",
        3_600_000,
    )
    .await;

    let h2 = open_kernel(&env, HashMap::new(), None).await;
    // The vault is empty after the restart: no live session identity.
    assert!(
        !h2.kernel.identity_is_live(&fixture.parent_subject).await,
        "no session identity may be live in the vault after a restart"
    );
    assert!(
        !h2.kernel.identity_is_live(&fixture.child_subject).await,
        "no session identity may be live in the vault after a restart"
    );

    let db = Database::connect(&env.db_path).await.expect("db connect");
    // 1. Schema: no private-key column exists on the session tables.
    let columns: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM pragma_table_info('kernel_sessions')")
            .fetch_all(db.pool())
            .await
            .expect("pragma table_info");
    let names: Vec<&str> = columns.iter().map(|(n,)| n.as_str()).collect();
    for forbidden in ["private_key", "signing_key", "secret", "seed"] {
        assert!(
            !names.iter().any(|n| n.contains(forbidden)),
            "kernel_sessions must not hold private key material (columns: {names:?})"
        );
    }
    // 2. Active rows expose verifying keys only.
    let active = db
        .active_kernel_sessions(&env.workspace)
        .await
        .expect("active sessions");
    assert!(
        !active.is_empty(),
        "the restarted kernel must rehydrate sessions to have anything to check"
    );
    for row in &active {
        let key = hex::decode(&row.verifying_key_hex).expect("verifying key hex");
        assert_eq!(
            key.len(),
            32,
            "verifying key must be a 32-byte Ed25519 public key"
        );
        assert_ne!(
            key.as_slice(),
            &parent_bytes,
            "a verifying key must never equal the private key bytes"
        );
    }
    drop(db);

    // 3. No private key bytes anywhere in the db file (or its journals).
    let dir = env.db_path.parent().expect("db parent");
    for entry in std::fs::read_dir(dir).expect("read db dir") {
        let path = entry.expect("entry").path();
        let bytes = std::fs::read(&path).expect("read db file");
        assert!(
            !bytes.windows(parent_bytes.len()).any(|w| w == parent_bytes),
            "private key bytes must not be persisted in {}",
            path.display()
        );
    }

    // The child lease still verifies through the rehydrated registry.
    h2.kernel
        .verify_lease(&fixture.child_lease)
        .await
        .expect("child lease must verify after restart");
}

/// §8.11 — destroying a session pre-restart stays destroyed.
///
/// The kernel fails closed at boot: a destroyed session with live
/// leases makes the startup re-validation refuse the open (the live
/// lease's chain can no longer resolve), rather than booting with an
/// unverifiable lease. A destroyed session with *no* live leases boots
/// cleanly and stays destroyed.
#[tokio::test]
async fn destroyed_session_stays_destroyed() {
    // Part A: destroyed parent with a live child lease → the restart
    // refuses to open. The destroy persisted (otherwise the boot would
    // have succeeded) and the kernel fails closed instead of silently
    // dropping the lease.
    {
        let (env, fixture) = setup_child_lease(
            &SigningKey::from_bytes(&[0x55u8; 32]),
            &SigningKey::from_bytes(&[0x66u8; 32]),
            "t11a",
            3_600_000,
        )
        .await;
        let db = Database::connect(&env.db_path).await.expect("db connect");
        db.destroy_kernel_session(&env.workspace, &fixture.parent_subject, now_ms())
            .await
            .expect("destroy session");
        drop(db);

        let mut config = AuthorityKernelConfig::test_config();
        config.db = AuthorityDb::Path(env.db_path.clone());
        config.workspace = env.workspace;
        let err = AuthorityKernelClient::open(config)
            .await
            .map(|_| ())
            .expect_err("open must fail closed on a destroyed session with live leases");
        match &err {
            KernelError::Unavailable(msg) => assert!(
                msg.contains("startup re-validation failed") && msg.contains("unknown session key"),
                "expected the boot fail-closed refusal, got: {msg}"
            ),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }

    // Part B: destroying a session with no live leases → clean boot,
    // and the session stays destroyed.
    {
        let (env, fixture) = setup_child_lease(
            &SigningKey::from_bytes(&[0x77u8; 32]),
            &SigningKey::from_bytes(&[0x88u8; 32]),
            "t11b",
            3_600_000,
        )
        .await;
        // An extra session nobody's leases reference.
        let spare_signing = SigningKey::from_bytes(&[0x99u8; 32]);
        let spare_subject = session_address(&spare_signing.verifying_key());
        let db = Database::connect(&env.db_path).await.expect("db connect");
        db.insert_kernel_session(
            &env.workspace,
            &spare_subject,
            None,
            &hex::encode(spare_signing.verifying_key().to_bytes()),
            now_ms(),
        )
        .await
        .expect("spare session");
        db.destroy_kernel_session(&env.workspace, &spare_subject, now_ms())
            .await
            .expect("destroy spare session");
        drop(db);

        let h2 = open_kernel(&env, HashMap::new(), None).await;
        // The destroyed session stayed destroyed...
        let db = Database::connect(&env.db_path).await.expect("db connect");
        let active = db
            .active_kernel_sessions(&env.workspace)
            .await
            .expect("active");
        assert!(
            !active.iter().any(|s| s.subject == spare_subject),
            "destroyed session must not come back after a restart"
        );
        drop(db);
        // ...while the unrelated child lease still verifies.
        h2.kernel
            .verify_lease(&fixture.child_lease)
            .await
            .expect("unrelated child lease must still verify");
    }
}

/// §8.11, destroy path — a session destroyed *through the kernel* revokes
/// not only its own leases but delegations orphaned by chain: a child
/// lease whose subject is not a session descendant, but whose
/// verification needs the destroyed session's key, can never verify
/// again. The destroy revokes it, so the next boot's re-validation
/// succeeds and the session stays destroyed. (Contrast Part A of
/// `destroyed_session_stays_destroyed`, which destroys via raw db writes,
/// bypassing the kernel — that inconsistency must still fail the open.)
#[tokio::test]
async fn destroy_session_revokes_orphaned_delegation_restart_succeeds() {
    let env = restart_env();
    let now = now_ms();
    let sess_signing = SigningKey::from_bytes(&[0xC1u8; 32]);
    let sess_subject = session_address(&sess_signing.verifying_key());
    let delegatee_signing = SigningKey::from_bytes(&[0xC2u8; 32]);

    // Session row first: the boot hydrates the registry from it
    // (`issue_root_lease` requires an active subject session).
    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.ensure_workspace(&env.workspace, "test", now)
        .await
        .expect("ensure workspace");
    db.insert_kernel_session(
        &env.workspace,
        &sess_subject,
        None,
        &hex::encode(sess_signing.verifying_key().to_bytes()),
        now,
    )
    .await
    .expect("session row");
    drop(db);

    let h = open_kernel(&env, HashMap::new(), None).await;
    let root = h
        .kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: format!("root-orphan-{}", uuid::Uuid::new_v4()),
            subject: sess_subject.clone(),
            scope: ResourceScope::default(),
            limits: CoreLeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("root-nonce-orphan-{}", uuid::Uuid::new_v4()),
            issued_at_ms: now,
        })
        .await
        .expect("issue root lease");

    let db = Database::connect(&env.db_path).await.expect("db connect");
    let parent_doc = db
        .kernel_lease(&env.workspace, &root.lease_id)
        .await
        .expect("fetch parent")
        .expect("parent lease stored");

    // A delegation to an *external* subject: its subject is not a session
    // descendant, so subject-scoped revocation would miss it — but its
    // signature was made by the session key, so destroying the session
    // orphans it.
    let mut sessions = SessionRegistry::new();
    sessions.register(
        sess_subject.clone(),
        None,
        sess_signing.verifying_key(),
        now,
    );
    sessions.register(
        "external-delegatee".to_string(),
        Some(sess_subject.clone()),
        delegatee_signing.verifying_key(),
        now,
    );
    let revocations = RevocationIndex::default();
    let ledger = BudgetLedger::new();
    ledger
        .register_lease(&parent_doc.lease_id, &parent_doc.limits.budget)
        .expect("register parent budget");
    let delegation = mint_child_lease(
        &parent_doc,
        ChildLeaseParams {
            lease_id: format!("delegation-orphan-{}", uuid::Uuid::new_v4()),
            subject: "external-delegatee".to_string(),
            scope: ResourceScope::default(),
            limits: CoreLeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 10),
                max_executions: Some(1),
                single_use: false,
            },
            depth_limit: 3,
            lease_nonce: format!("delegation-nonce-{}", uuid::Uuid::new_v4()),
            issued_at_ms: now,
        },
        &sess_signing,
        &sessions,
        &revocations,
        &ledger,
        &NonceStore::new(),
        now,
    )
    .expect("mint delegation");
    db.insert_kernel_lease(&env.workspace, &delegation)
        .await
        .expect("insert delegation");
    drop(db);
    let host_delegation = to_host_doc(&delegation);

    // Sanity: the delegation verifies while the session lives.
    h.kernel
        .verify_lease(&host_delegation)
        .await
        .expect("delegation verifies pre-destroy");

    // Destroy through the kernel. The vault holds no private key for this
    // session (it came from the durable row, not `start_session_identity`),
    // so this exercises the durable-only path, including the
    // orphan-delegation revocation.
    let report = h
        .kernel
        .destroy_session_identity(&sess_subject)
        .await
        .expect("destroy session");
    assert_eq!(report.affected_subjects, vec![sess_subject.clone()]);
    drop(h);

    // The restart must now SUCCEED: the orphaned delegation was revoked
    // at destroy time instead of failing the boot re-validation.
    let h2 = open_kernel(&env, HashMap::new(), None).await;

    // The session stayed destroyed...
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let active = db
        .active_kernel_sessions(&env.workspace)
        .await
        .expect("active sessions");
    assert!(
        !active.iter().any(|s| s.subject == sess_subject),
        "destroyed session must not resurrect after a restart"
    );
    drop(db);

    // ...and the orphaned delegation is dead (revoked, not merely
    // unverifiable).
    let err = h2
        .kernel
        .verify_lease(&host_delegation)
        .await
        .expect_err("orphaned delegation must be revoked");
    assert!(
        matches!(err, KernelError::Revoked(_)),
        "expected Revoked, got {err:?}"
    );
}

/// §8.13 — startup tamper detection: if the stored issuer generation
/// record is modified on disk, the boot-time revalidation (which
/// re-signs with the sealed key and compares) aborts the open.
///
/// The tampered value is a *valid* 64-hex Ed25519 public key that does
/// not match the original: schema checks reject malformed text, so
/// tamper is simulated the way an attacker would do it. The drop of the
/// `kernel_key_generations_no_update` trigger is the test double for
/// the attacker getting at the raw file: it is the only schema piece
/// the test alters (worker A's db tests cover the guarded update/delete
/// behavior itself).
#[tokio::test]
async fn startup_tamper_detection() {
    let env = restart_env();
    {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let _ = mint_root(&h.kernel, "t13", 3_600_000).await;
    }

    // Read the recorded verifying key, then rewrite it to a different
    // valid Ed25519 public key.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    let victim = gens
        .iter()
        .find(|g| g.role == "issuer")
        .expect("issuer gen");
    let tampered_key = hex::encode(
        SigningKey::from_bytes(&[0x99u8; 32])
            .verifying_key()
            .to_bytes(),
    );
    assert_ne!(tampered_key, victim.verifying_key_hex);
    sqlx::query("DROP TRIGGER IF EXISTS kernel_key_generations_no_update")
        .execute(db.pool())
        .await
        .expect("drop guard trigger");
    sqlx::query("UPDATE kernel_key_generations SET verifying_key_hex = ? WHERE key_id = ?")
        .bind(&tampered_key)
        .bind(&victim.key_id)
        .execute(db.pool())
        .await
        .expect("tamper generation row");
    drop(db);

    // Reopening must fail: the boot self-check re-derives the sealed
    // key, re-signs, and finds the stored record does not match.
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(env.db_path.clone());
    config.workspace = env.workspace;
    let err = AuthorityKernelClient::open(config)
        .await
        .map(|_| ())
        .expect_err("tampered open must fail");
    match &err {
        KernelError::Unavailable(msg) => assert!(
            msg.contains("startup re-validation failed"),
            "expected the boot re-validation refusal, got: {msg}"
        ),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// §8.14 — audit continuity: the chain hash links across the restart
/// (the first post-restart event's `prev_hash` is the last pre-restart
/// event's `hash`), the kernel's own verifier accepts the full chain,
/// and sequence numbers are gapless (0-based). (Budget continuity is
/// covered by the fixed `restart_preserves_budget_consumption` in
/// `kernel_authority_pipeline`; this test covers the audit half.)
#[tokio::test]
async fn audit_and_budget_continuity() {
    let env = restart_env();
    {
        let h = open_kernel(&env, HashMap::new(), Some(true)).await;
        let _ = mint_root(&h.kernel, "t14a", 3_600_000).await;
        let _ = mint_root(&h.kernel, "t14b", 3_600_000).await;
    }

    let h2 = open_kernel(&env, HashMap::new(), Some(true)).await;
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let events = db
        .kernel_audit_events(&env.workspace, &KernelAuditQuery::default())
        .await
        .expect("audit events");
    drop(db);
    assert!(
        events.len() >= 2,
        "expected events on both sides of the restart, got {}",
        events.len()
    );
    // The boot revalidation event emitted by the post-restart open must
    // be in the chain.
    assert!(
        events
            .iter()
            .any(|e| e.detail.contains("kernel.restart.revalidation")),
        "expected a kernel.restart.revalidation event after the restart"
    );
    // Gapless sequence, 0-based.
    let mut seqs: Vec<u64> = events.iter().map(|e| e.sequence).collect();
    seqs.sort_unstable();
    for (i, seq) in seqs.iter().enumerate() {
        assert_eq!(
            *seq, i as u64,
            "sequence must be dense from 0, got {seqs:?}"
        );
    }
    // The chain is contiguous across the restart boundary.
    let by_seq: HashMap<u64, &lumen_core::pi_boundary::AuditEvent> =
        events.iter().map(|e| (e.sequence, e)).collect();
    for seq in 1..events.len() as u64 {
        assert_eq!(
            by_seq[&seq].prev_hash,
            by_seq[&(seq - 1)].hash,
            "event {seq} must link to event {}",
            seq - 1
        );
    }
    // The kernel's own verifier accepts the full chain.
    h2.kernel
        .verify_kernel_audit()
        .await
        .expect("kernel audit chain must verify across the restart");
}
