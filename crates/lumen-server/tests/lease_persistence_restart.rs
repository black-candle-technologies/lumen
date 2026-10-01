//! Restart security: durable historical records never restore live session authority.
//! Includes admission/execution denial, replay and budget preservation, crash
//! convergence, store ownership, and separate historical signature verification.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use lumen_core::budget::{Budget, BudgetDimension, BudgetLedger};
use lumen_core::canonical::{CanonicalPath, PathGrant, PathRights, RealFsResolver, ResourceScope};
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
    ActionEnvelope, AuthorityDb, AuthorityKernelClient, AuthorityKernelConfig, Catalog,
    CatalogError, EffectClass, KernelClient, KernelError, LeaseDocument,
    LeaseLimits as HostLeaseLimits, MockSandboxRunner, OneShotGrant, PiToolRequest, ProjectionKind,
    SessionIdentityAuthority, ToolDef, ToolOutcome, ToolPipeline, now_ms,
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
    mint_root_with_scope(kernel, tag, lifetime_ms, ResourceScope::default()).await
}

fn read_scope(env: &RestartEnv) -> ResourceScope {
    let mut scope = ResourceScope::default();
    scope
        .tools
        .insert("bct.read_file".into(), "=1.0.0".parse().unwrap());
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse(&env.leased_file, &RealFsResolver, false).unwrap(),
        rights: PathRights::READ,
    });
    scope.effects.push(lumen_core::canonical::EffectClass::Read);
    scope
}

async fn mint_root_with_scope(
    kernel: &AuthorityKernelClient,
    tag: &str,
    lifetime_ms: i64,
    scope: ResourceScope,
) -> (String, LeaseDocument) {
    let info = kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let now = now_ms();
    let lease = kernel
        .issue_root_lease(RootLeaseParams {
            lease_id: uuid::Uuid::new_v4().to_string(),
            subject: info.subject.clone(),
            scope,
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
/// kernel to emit a pending VHL approval request. Returns its id and the
/// exact envelope that was approved, so the caller can re-present it
/// verbatim after the one-shot lease is minted (the lease is bound to the
/// envelope's exact digest).
async fn decide_pending(
    h: &KernelHandles,
    leased_file: &str,
    subject: &str,
) -> (String, ActionEnvelope) {
    let envelope = h
        .pipeline
        .build_envelope(&read_request(leased_file), subject, &[])
        .expect("build envelope");
    let outcome = h.pipeline.execute_envelope(&envelope, subject).await;
    match outcome {
        ToolOutcome::PendingApproval {
            approval_request_id,
            ..
        } => (approval_request_id, envelope),
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
        action_digest: lumen_server::CoreActionDigest::from_kernel_hex(core.action_digest.clone()),
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
) -> (String, LeaseDocument, ActionEnvelope) {
    let info = h
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let subject = info.subject.clone();
    let (approval_id, envelope) = decide_pending(h, leased_file, &subject).await;
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
        view.action_digest.as_str(),
        &subject,
    );
    let lease = KernelClient::request_one_shot_lease(h.kernel.as_ref(), &grant)
        .await
        .expect("mint one-shot lease");
    assert!(lease.limits.single_use, "one-shot lease is single-use");
    (subject, lease, envelope)
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
        approved_action_digest: core
            .approved_action_digest
            .clone()
            .map(lumen_server::CoreActionDigest::from_kernel_hex),
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

/// Retained root leases and lease-less requests cannot restore old authority.
#[tokio::test]
async fn restart_root_session_cannot_authorize_or_execute() {
    let env = restart_env();
    let (subject, lease) = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (subject, lease) =
            mint_root_with_scope(&h.kernel, "old-root", 3_600_000, read_scope(&env)).await;
        let envelope = h
            .pipeline
            .build_envelope(
                &read_request(&env.leased_file),
                &subject,
                &[lease.lease_id.clone()],
            )
            .unwrap();
        // Completed requires a bound Allow and a sandbox commit in this live boot.
        let outcome = h.pipeline.execute_envelope(&envelope, &subject).await;
        assert!(
            matches!(outcome, ToolOutcome::Completed { .. }),
            "{outcome:?}"
        );
        assert_eq!(h.sandbox.staged_count(), 1);
        assert_eq!(h.sandbox.committed_count(), 1);
        (subject, lease)
    };
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert!(matches!(
        h.kernel.verify_lease(&lease).await,
        Err(KernelError::Revoked(_))
    ));
    for chain in [vec![lease.lease_id.clone()], vec![]] {
        let envelope = h
            .pipeline
            .build_envelope(&read_request(&env.leased_file), &subject, &chain)
            .unwrap();
        assert!(!h.kernel.decide(&envelope).await.unwrap().is_allow());
        assert!(matches!(
            h.pipeline.execute_envelope(&envelope, &subject).await,
            ToolOutcome::Denied { .. }
        ));
    }
    assert_eq!(h.sandbox.staged_count(), 0);
    assert_eq!(h.sandbox.committed_count(), 0);
    assert!(
        h.kernel
            .start_session_identity(Some(&subject))
            .await
            .is_err()
    );
    let fresh = h.kernel.start_session_identity(None).await.unwrap();
    assert_ne!(fresh.subject, subject);
    let (approval, _) = decide_pending(&h, &env.leased_file, &fresh.subject).await;
    assert!(!approval.is_empty());
    let db = Database::connect(&env.db_path).await.unwrap();
    let row = db
        .kernel_session(&env.workspace, &subject)
        .await
        .unwrap()
        .unwrap();
    assert!(!row.active);
    assert!(row.destroyed_at_ms.is_some());
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
        .expect_err("long-lived lease must also lose authority");
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
        .expect_err("anchor lease must also lose authority");
}

/// Historical verifying keys remain retrievable without restoring authority:
/// a revoked lease still denies before key resolution.
#[tokio::test]
async fn restart_revoked_lease_denied_with_retained_verification_key() {
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

    // Restart retains the generation for historical signature verification.
    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let gens = db
        .kernel_key_generations(&env.workspace)
        .await
        .expect("generations");
    assert!(
        gens.iter().any(|g| g.key_id == lease.issuer_key_id),
        "historical verification must retain the revoked lease's generation"
    );
    drop(db);

    let err =
        h2.kernel.verify_lease(&lease).await.expect_err(
            "revoked lease must still be denied with its historical generation retained",
        );
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

    let (subject, lease, envelope) = {
        let h = open_kernel(&env, vhl_keys.clone(), None).await;
        let (subject, lease, envelope) =
            mint_one_shot(&h, &env.leased_file, &vhl_signing, vhl_key_id).await;
        // Consume it once, pre-restart: re-present the verbatim approved
        // envelope with the lease attached.
        let mut presented = envelope.clone();
        presented.lease_chain = vec![lease.lease_id.clone()];
        let outcome = h.pipeline.execute_envelope(&presented, &subject).await;
        assert!(
            matches!(outcome, ToolOutcome::Completed { .. }),
            "one-shot must authorize its exact action once, got {outcome:?}"
        );
        (subject, lease, envelope)
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

    // Replay post-restart: denied. The durable nonce record survived the
    // restart, so the verbatim re-presentation is a durable replay denial.
    // (The durable one-shot consumption record is the backstop verified
    // directly against the store above; it would deny with "consumed" once
    // the nonce TTL lapses.)
    let mut presented = envelope.clone();
    presented.lease_chain = vec![lease.lease_id.clone()];
    let outcome = h2.pipeline.execute_envelope(&presented, &subject).await;
    match outcome {
        ToolOutcome::Denied { reason } => assert!(
            reason.contains("inactive"),
            "expected inactive session denial, got: {reason}"
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
/// The forged lease uses a live session subject: the boot self-check
/// treats a live lease naming an unknown/inactive session as corruption
/// (fail the open), so the unknown-*generation* path is only reachable
/// with a registered subject.
///
/// Note: the forged document must be *stored* (`verify_lease` only
/// resolves generations for documents that match the kernel's record —
/// an unstored forgery fails earlier as "unknown lease").
#[tokio::test]
async fn unknown_issuer_generation_fails_closed() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    // Live session subject for the forgery (see doc comment).
    let info = h
        .kernel
        .start_session_identity(None)
        .await
        .expect("start session identity");
    let now = now_ms();
    let mut core_doc = CoreLeaseDocument {
        protocol_version: LEASE_PROTOCOL_VERSION,
        lease_id: format!("forged-{}", uuid::Uuid::new_v4()),
        parent_id: None,
        subject: info.subject.clone(),
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
        approved_action_digest: None,
    };
    // Well-formed signature, but from a throwaway key no generation
    // records: the failure must be key *resolution*, not signature math.
    core_doc
        .sign(&SigningKey::from_bytes(&[0x5au8; 32]))
        .unwrap();
    let host_doc = to_host_doc(&core_doc);

    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.insert_kernel_lease_with_budget(&env.workspace, &core_doc, now)
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
    assert!(matches!(err, KernelError::Revoked(_)));
}

/// Pre-migration legacy lease: a live root lease whose subject has no
/// `kernel_sessions` row (sessions were not durably recorded before
/// migration 0025). The boot re-validation self-check must count it as
/// legacy and let the open succeed — NOT fail the open on
/// `SubjectInactive`. The lease itself must still fail closed at decision
/// time: it never authorizes.
#[tokio::test]
async fn pre_migration_lease_without_session_row_is_legacy_not_tamper() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    // A recorded (not killed) issuer generation, so the lease is not
    // UnknownIssuerGeneration: the only thing "legacy" about it is the
    // missing session row.
    let legacy_signing = SigningKey::from_bytes(&[0x5bu8; 32]);
    let legacy_issuer_id = "legacy-issuer-gen";
    let now = now_ms();
    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.record_kernel_key_generation(
        &env.workspace,
        legacy_issuer_id,
        "issuer",
        &hex::encode(legacy_signing.verifying_key().to_bytes()),
        now,
    )
    .await
    .expect("record legacy generation");
    // The subject never had a session row: this is the pre-0025 data
    // state (kernel_leases existed since 0022; kernel_sessions is 0027).
    let legacy_subject = "ed25519:legacy-no-session-row";
    let mut core_doc = CoreLeaseDocument {
        protocol_version: LEASE_PROTOCOL_VERSION,
        lease_id: uuid::Uuid::new_v4().to_string(),
        parent_id: None,
        subject: legacy_subject.to_string(),
        issuer_key_id: legacy_issuer_id.to_string(),
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
        lease_nonce: format!("legacy-nonce-{}", uuid::Uuid::new_v4()),
        signature: String::new(),
        approved_action_digest: None,
    };
    core_doc.sign(&legacy_signing).unwrap();
    db.insert_kernel_lease_with_budget(&env.workspace, &core_doc, now)
        .await
        .expect("insert legacy lease");
    drop(db);
    drop(h);

    // The open succeeds: the legacy lease is counted, not treated as
    // tamper evidence.
    let h2 = open_kernel(&env, HashMap::new(), None).await;
    // ...but the lease itself never authorizes: the decision-time
    // `validate_chain` fails closed on the unknown/inactive subject.
    // Live verification also rejects it; historical signature checks are a
    // separate core capability.
    assert!(
        h2.kernel
            .verify_lease(&to_host_doc(&core_doc))
            .await
            .is_err()
    );
    let outcome = h2
        .pipeline
        .handle(
            &read_request(&env.leased_file),
            legacy_subject,
            &[core_doc.lease_id.clone()],
        )
        .await;
    match outcome {
        ToolOutcome::Denied { reason } => assert!(
            reason.contains("not active") || reason.contains("inactive"),
            "expected the inactive-subject denial, got: {reason}"
        ),
        other => panic!("legacy lease must be denied at authorization, got {other:?}"),
    }
}

/// Crash-residue repair: a session destroyed without its leases revoked
/// (the pre-atomicity crash window) must not wedge the next boot. The
/// boot repair pass durably revokes the residue leases, the open
/// succeeds, and the residue lease stays denied.
#[tokio::test]
async fn crash_residue_repair_unblocks_boot() {
    let env = restart_env();
    let (subject, lease) = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (subject, lease) = mint_root(&h.kernel, "t-residue", 3_600_000).await;
        // Sanity: the lease verifies before the simulated crash.
        h.kernel
            .verify_lease(&lease)
            .await
            .expect("lease verifies pre-crash");
        (subject, lease)
    };
    // Simulate the crash: destroy transition committed, revocation lost.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    assert!(
        db.destroy_kernel_session(&env.workspace, &subject, now_ms())
            .await
            .expect("destroy session")
    );
    drop(db);

    // Without the repair this open failed on SubjectInactive; with it the
    // residue lease is revoked and the boot succeeds.
    let h2 = open_kernel(&env, HashMap::new(), None).await;
    let db = Database::connect(&env.db_path).await.expect("db connect");
    assert!(
        db.is_kernel_revoked(&env.workspace, &lease.lease_id)
            .await
            .expect("revocation check"),
        "boot repair must durably revoke the residue lease"
    );
    drop(db);
    // The residue lease stays denied: its session is destroyed.
    h2.kernel
        .verify_lease(&lease)
        .await
        .expect_err("residue lease must stay denied");
}

/// Killing a generation denies immediately; its kill record survives restart.
#[tokio::test]
async fn killed_generation_fails_closed() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), Some(true)).await;
    let (_, lease) = mint_root(&h.kernel, "kill", 3_600_000).await;
    h.kernel.verify_lease(&lease).await.unwrap();
    h.kernel
        .rotate_issuer_keys("rotate", &actor())
        .await
        .unwrap();
    assert!(
        h.kernel
            .kill_key_generation(&lease.issuer_key_id, "issuer", "compromise", &actor())
            .await
            .unwrap()
    );
    let err = h.kernel.verify_lease(&lease).await.unwrap_err();
    assert_killed_generation(&err, &lease.issuer_key_id);
    drop(h);
    let h = open_kernel(&env, HashMap::new(), Some(true)).await;
    assert!(matches!(
        h.kernel.verify_lease(&lease).await,
        Err(KernelError::Revoked(_))
    ));
    let db = Database::connect(&env.db_path).await.unwrap();
    assert!(
        db.killed_key_generation_ids(&env.workspace)
            .await
            .unwrap()
            .contains(&lease.issuer_key_id)
    );
}

/// Mid-boot rotation retains keys for live leases. Restart still retires authority.
#[tokio::test]
async fn purge_blocked_while_referenced() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), Some(true)).await;
    let (_, lease) = mint_root(&h.kernel, "purge", 3_600_000).await;
    h.kernel
        .rotate_issuer_keys("rotate", &actor())
        .await
        .unwrap();
    let report = h.kernel.purge_key_generations(&actor()).await.unwrap();
    assert!(report.skipped_live.contains(&lease.issuer_key_id));
    h.kernel.verify_lease(&lease).await.unwrap();
    drop(h);
    let h = open_kernel(&env, HashMap::new(), Some(true)).await;
    assert!(matches!(
        h.kernel.verify_lease(&lease).await,
        Err(KernelError::Revoked(_))
    ));
}

/// An expired lease still needs independently retrievable verification material.
#[tokio::test]
async fn purge_retains_keys_after_last_lease_dies() {
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
        gens.iter().any(|g| g.key_id == gen_a),
        "gen A must remain retrievable for historical verification, got {:?}",
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
        let (approval_id, _envelope) = decide_pending(&h, &env.leased_file, &subject).await;
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
        old_digest.as_str(),
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
    // entry. Retain the envelope: the minted one-shot is bound to its
    // exact digest.
    let old_envelope = h2
        .pipeline
        .build_envelope(&read_request(&env.leased_file), &subject, &[])
        .unwrap();
    assert!(matches!(
        h2.pipeline.execute_envelope(&old_envelope, &subject).await,
        ToolOutcome::Denied { .. }
    ));
    let subject = h2
        .kernel
        .start_session_identity(None)
        .await
        .unwrap()
        .subject;
    let (new_approval_id, envelope) = decide_pending(&h2, &env.leased_file, &subject).await;
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
        view.action_digest.as_str(),
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

    // It verifies and authorizes its exact action: re-present the verbatim
    // approved envelope with the lease attached.
    h2.kernel
        .verify_lease(&lease)
        .await
        .expect("minted one-shot must verify");
    let mut presented = envelope.clone();
    presented.lease_chain = vec![lease.lease_id.clone()];
    let outcome = h2.pipeline.execute_envelope(&presented, &subject).await;
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
/// Core fixtures persist a previous authority generation before the client
/// boots. Startup must invalidate these public rows, never hydrate them.
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
    // Construct a previous-generation fixture in the core. Public rows are
    // never admitted into a newly booted authority client.
    let keys = lumen_core::lease::KernelKeys::generate();
    db.record_kernel_key_generation(
        &env.workspace,
        &keys.issuer_key_id,
        "issuer",
        &hex::encode(keys.issuer_verifying().to_bytes()),
        now,
    )
    .await
    .unwrap();
    let mut root_sessions = SessionRegistry::new();
    root_sessions.register(
        parent_subject.clone(),
        None,
        parent_signing.verifying_key(),
        now,
    );
    let parent_doc = lumen_core::lease::mint_root_lease(
        RootLeaseParams {
            lease_id: uuid::Uuid::new_v4().to_string(),
            subject: parent_subject.clone(),
            scope: read_scope(&env),
            limits: CoreLeaseLimits {
                not_before_ms: now,
                expires_at_ms: now + 3_600_000,
                budget: Budget::new().set(BudgetDimension::Executions, 100),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: format!("root-{tag}"),
            issued_at_ms: now,
        },
        &keys,
        &root_sessions,
        &BudgetLedger::new(),
        &NonceStore::new(),
        now,
    )
    .unwrap();
    db.insert_kernel_lease_with_budget(&env.workspace, &parent_doc, now)
        .await
        .unwrap();

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
            lease_id: uuid::Uuid::new_v4().to_string(),
            subject: child_subject.clone(),
            scope: read_scope(&env),
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
    db.mint_kernel_child_lease(&env.workspace, &child_lease, now)
        .await
        .expect("insert child lease");
    drop(db);

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

async fn mint_live_child(h: &KernelHandles, env: &RestartEnv) -> ChildLeaseFixture {
    let (parent_subject, parent) =
        mint_root_with_scope(&h.kernel, "child", 3_600_000, read_scope(env)).await;
    let child_subject = h
        .kernel
        .start_session_identity(Some(&parent_subject))
        .await
        .unwrap()
        .subject;
    let now = now_ms();
    let child = h
        .kernel
        .issue_child_lease(
            &parent.lease_id,
            ChildLeaseParams {
                lease_id: uuid::Uuid::new_v4().to_string(),
                subject: child_subject.clone(),
                scope: read_scope(env),
                limits: CoreLeaseLimits {
                    not_before_ms: now,
                    expires_at_ms: parent.limits.expires_at_ms,
                    budget: Budget::new().set(BudgetDimension::Executions, 10),
                    max_executions: None,
                    single_use: false,
                },
                depth_limit: 3,
                lease_nonce: "live-child".into(),
                issued_at_ms: now,
            },
        )
        .await
        .unwrap();
    ChildLeaseFixture {
        parent_subject,
        child_subject,
        parent_lease_id: parent.lease_id,
        child_lease: child,
    }
}

/// Restart invalidates the full session subtree and retained child leases.
#[tokio::test]
async fn restart_child_session_cannot_authorize_or_execute() {
    let env = restart_env();
    let fixture = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        let fixture = mint_live_child(&h, &env).await;
        for (subject, chain) in [
            (
                &fixture.parent_subject,
                vec![fixture.parent_lease_id.clone()],
            ),
            (
                &fixture.child_subject,
                vec![
                    fixture.child_lease.lease_id.clone(),
                    fixture.parent_lease_id.clone(),
                ],
            ),
        ] {
            let envelope = h
                .pipeline
                .build_envelope(&read_request(&env.leased_file), subject, &chain)
                .unwrap();
            let outcome = h.pipeline.execute_envelope(&envelope, subject).await;
            assert!(
                matches!(outcome, ToolOutcome::Completed { .. }),
                "{outcome:?}"
            );
        }
        assert_eq!(h.sandbox.staged_count(), 2);
        assert_eq!(h.sandbox.committed_count(), 2);
        fixture
    };
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert!(matches!(
        h.kernel.verify_lease(&fixture.child_lease).await,
        Err(KernelError::Revoked(_))
    ));
    for (subject, chain) in [
        (
            &fixture.parent_subject,
            vec![fixture.parent_lease_id.clone()],
        ),
        (
            &fixture.child_subject,
            vec![
                fixture.child_lease.lease_id.clone(),
                fixture.parent_lease_id.clone(),
            ],
        ),
    ] {
        let envelope = h
            .pipeline
            .build_envelope(&read_request(&env.leased_file), subject, &chain)
            .unwrap();
        assert!(!h.kernel.decide(&envelope).await.unwrap().is_allow());
        assert!(matches!(
            h.pipeline.execute_envelope(&envelope, subject).await,
            ToolOutcome::Denied { .. }
        ));
        assert!(
            h.kernel
                .start_session_identity(Some(subject))
                .await
                .is_err()
        );
    }
    assert_eq!(
        h.kernel
            .budget_remaining(&fixture.child_lease.lease_id)
            .await
            .unwrap()
            .get(BudgetDimension::Executions),
        9
    );
    assert_eq!(
        h.kernel
            .budget_remaining(&fixture.parent_lease_id)
            .await
            .unwrap()
            .get(BudgetDimension::Executions),
        89
    );
    assert_eq!(h.sandbox.staged_count(), 0);
    assert_eq!(h.sandbox.committed_count(), 0);
    let db = Database::connect(&env.db_path).await.unwrap();
    assert!(
        db.active_kernel_sessions(&env.workspace)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Old sessions cannot mint and no private keys are ever persisted.
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
    // 2. Public records survive destruction, but never restore active authority.
    let active = db
        .active_kernel_sessions(&env.workspace)
        .await
        .expect("active sessions");
    assert!(
        active.is_empty(),
        "public records cannot restore session authority"
    );
    for subject in [&fixture.parent_subject, &fixture.child_subject] {
        let row = db
            .kernel_session(&env.workspace, subject)
            .await
            .unwrap()
            .unwrap();
        assert!(!row.active);
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

    // Retention of public records does not restore admission authority.
    h2.kernel
        .verify_lease(&fixture.child_lease)
        .await
        .expect_err("retained child lease must not verify for admission");
}

/// A partially destroyed subtree is repaired atomically without resurrection.
#[tokio::test]
async fn destroyed_parent_and_live_descendants_converge_to_inactive() {
    let (env, fixture) = setup_child_lease(
        &SigningKey::from_bytes(&[0x55; 32]),
        &SigningKey::from_bytes(&[0x66; 32]),
        "destroyed",
        3_600_000,
    )
    .await;
    let db = Database::connect(&env.db_path).await.unwrap();
    db.destroy_kernel_session(&env.workspace, &fixture.parent_subject, now_ms())
        .await
        .unwrap();
    let destroyed_at = db
        .kernel_session(&env.workspace, &fixture.parent_subject)
        .await
        .unwrap()
        .unwrap()
        .destroyed_at_ms;
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert!(
        db.active_kernel_sessions(&env.workspace)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        h.kernel.verify_lease(&fixture.child_lease).await,
        Err(KernelError::Revoked(_))
    ));
    assert_eq!(
        db.kernel_session(&env.workspace, &fixture.parent_subject)
            .await
            .unwrap()
            .unwrap()
            .destroyed_at_ms,
        destroyed_at
    );
    drop(h);
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert!(matches!(
        h.kernel.verify_lease(&fixture.child_lease).await,
        Err(KernelError::Revoked(_))
    ));
}

/// Lease ancestry is revoked even for an external subject without a session row.
#[tokio::test]
async fn restart_revokes_external_lease_descendants() {
    let child_signing = SigningKey::from_bytes(&[0xc2; 32]);
    let (env, fixture) = setup_child_lease(
        &SigningKey::from_bytes(&[0xc1; 32]),
        &child_signing,
        "external",
        3_600_000,
    )
    .await;
    let db = Database::connect(&env.db_path).await.unwrap();
    let mut external = db
        .kernel_lease(&env.workspace, &fixture.child_lease.lease_id)
        .await
        .unwrap()
        .unwrap();
    external.parent_id = Some(external.lease_id.clone());
    external.lease_id = "external-descendant".into();
    external.subject = "external-subject".into();
    external.lease_nonce = "external-descendant-nonce".into();
    external.issuer_key_id = fixture.child_subject.clone();
    external.depth += 1;
    external.sign(&child_signing).unwrap();
    db.insert_kernel_lease_with_budget(&env.workspace, &external, now_ms())
        .await
        .unwrap();
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert!(
        db.is_kernel_revoked(&env.workspace, &external.lease_id)
            .await
            .unwrap()
    );
    assert!(matches!(
        h.kernel.verify_lease(&to_host_doc(&external)).await,
        Err(KernelError::Revoked(_))
    ));
}

/// §8.13 — startup tamper detection: if the stored issuer generation
/// record is modified on disk, verifying historical signatures aborts every
/// open, including retries after the lease has been revoked.
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

    for _ in 0..2 {
        let err = AuthorityKernelClient::open(file_config(&env))
            .await
            .map(|_| ())
            .expect_err("every tampered open must fail");
        assert!(
            err.to_string().contains("startup re-validation failed"),
            "{err}"
        );
        let db = Database::connect(&env.db_path).await.unwrap();
        assert!(
            db.kernel_key_generations(&env.workspace)
                .await
                .unwrap()
                .iter()
                .any(|g| g.key_id == victim.key_id && g.verifying_key_hex == tampered_key)
        );
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

/// Wall-clock rollback fails the open: when the durable time anchor is
/// ahead of the wall clock by more than the tolerance, the kernel
/// refuses to boot rather than resurrect expired authority. A small
/// skew inside the tolerance still opens (and runs at the anchor).
#[tokio::test]
async fn rollback_clock_refuses_open() {
    let env = restart_env();
    let h1 = open_kernel(&env, HashMap::new(), None).await;
    drop(h1);

    // Simulate a backward clock jump: the anchor is now an hour ahead of
    // the wall clock.
    let db = Database::connect(&env.db_path).await.expect("db connect");
    let ahead = now_ms() + 3_600_000;
    db.record_time_high_water(&env.workspace, ahead)
        .await
        .expect("record high water");
    drop(db);

    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(env.db_path.clone());
    config.workspace = env.workspace;
    let err = AuthorityKernelClient::open(config)
        .await
        .map(|_| ())
        .expect_err("open must fail closed on a backward clock");
    match &err {
        KernelError::Unavailable(msg) => assert!(
            msg.contains("backward clock"),
            "expected the rollback refusal, got: {msg}"
        ),
        other => panic!("expected Unavailable, got {other:?}"),
    }

    // Inside the tolerance (60s skew) the kernel still opens — on a
    // fresh env, since the anchor only ever advances.
    let env2 = restart_env();
    let h1 = open_kernel(&env2, HashMap::new(), None).await;
    drop(h1);
    let db = Database::connect(&env2.db_path).await.expect("db connect");
    let slight = now_ms() + 60_000;
    db.record_time_high_water(&env2.workspace, slight)
        .await
        .expect("record high water");
    drop(db);
    let _h2 = open_kernel(&env2, HashMap::new(), None).await;

    // The anchor advanced to at least the boot time and never regressed.
    let db = Database::connect(&env2.db_path).await.expect("db connect");
    let mark = db
        .time_high_water(&env2.workspace)
        .await
        .expect("read high water");
    assert!(
        mark >= slight,
        "time anchor must not regress across boots: {mark} < {slight}"
    );
}

/// Historical public identities still undergo subject/key integrity checks.
/// Such records must never be restored into the live registry.
#[tokio::test]
async fn session_subject_key_mismatch_refuses_open() {
    let env = restart_env();
    let h1 = open_kernel(&env, HashMap::new(), None).await;
    drop(h1);

    // A row whose subject is not the address of its verifying key.
    let other_key = SigningKey::from_bytes(&[0x42u8; 32]);
    let db = Database::connect(&env.db_path).await.expect("db connect");
    db.insert_kernel_session(
        &env.workspace,
        "ed25519:not-the-address-of-this-key",
        None,
        &hex::encode(other_key.verifying_key().as_bytes()),
        now_ms(),
    )
    .await
    .expect("insert mismatched session");
    drop(db);

    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(env.db_path.clone());
    config.workspace = env.workspace;
    let err = AuthorityKernelClient::open(config)
        .await
        .map(|_| ())
        .expect_err("open must fail closed on a subject/key mismatch");
    match &err {
        KernelError::Unavailable(msg) => assert!(
            msg.contains("historical identity mismatch"),
            "expected the mismatch refusal, got: {msg}"
        ),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// Strict decoding applies at the real host/kernel seam, including after
/// rebuilding caches from SQLite; malformed scope is never a signature lookup.
#[tokio::test]
async fn strict_scope_and_lease_versions_are_enforced_across_restart() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let (_, lease) = mint_root(&h.kernel, "strict-scope", 3_600_000).await;
    h.kernel.verify_lease(&lease).await.unwrap();
    let mut unknown = lease.clone();
    unknown
        .scope
        .as_object_mut()
        .unwrap()
        .insert("future_authority".into(), serde_json::json!(true));
    let mut legacy = lease.clone();
    legacy.protocol_version = 2;
    assert!(
        h.kernel
            .verify_lease(&unknown)
            .await
            .unwrap_err()
            .to_string()
            .contains("malformed")
    );
    assert!(
        h.kernel
            .verify_lease(&legacy)
            .await
            .unwrap_err()
            .to_string()
            .contains("unsupported lease version")
    );
    drop(h);
    let reopened = open_kernel(&env, HashMap::new(), None).await;
    assert!(
        reopened
            .kernel
            .verify_lease(&unknown)
            .await
            .unwrap_err()
            .to_string()
            .contains("malformed")
    );
    assert!(
        reopened
            .kernel
            .verify_lease(&legacy)
            .await
            .unwrap_err()
            .to_string()
            .contains("unsupported lease version")
    );
}

/// Core signature verification is a historical integrity capability. It says
/// nothing about session liveness, revocation, scope, or execution admission.
#[tokio::test]
async fn historical_signatures_verify_without_restoring_authority() {
    let (env, fixture) = setup_child_lease(
        &SigningKey::from_bytes(&[0x31; 32]),
        &SigningKey::from_bytes(&[0x32; 32]),
        "history",
        3_600_000,
    )
    .await;
    let db = Database::connect(&env.db_path).await.unwrap();
    let root = db
        .kernel_lease(&env.workspace, &fixture.parent_lease_id)
        .await
        .unwrap()
        .unwrap();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let issuer = db
        .kernel_key_generations(&env.workspace)
        .await
        .unwrap()
        .into_iter()
        .find(|g| g.key_id == root.issuer_key_id)
        .unwrap();
    let issuer_key = VerifyingKey::from_bytes(
        &hex::decode(issuer.verifying_key_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    let child = db
        .kernel_lease(&env.workspace, &fixture.child_lease.lease_id)
        .await
        .unwrap()
        .unwrap();
    let parent = db
        .kernel_session(&env.workspace, &fixture.parent_subject)
        .await
        .unwrap()
        .unwrap();
    assert!(!parent.active);
    let parent_key = VerifyingKey::from_bytes(
        &hex::decode(parent.verifying_key_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    )
    .unwrap();
    root.verify_signature(&issuer_key).unwrap();
    child.verify_signature(&parent_key).unwrap();
    let mut tampered = child.clone();
    tampered.subject = "another-subject".into();
    assert!(tampered.verify_signature(&parent_key).is_err());
    assert!(matches!(
        h.kernel.verify_lease(&fixture.child_lease).await,
        Err(KernelError::Revoked(_))
    ));
    h.kernel.verify_kernel_audit().await.unwrap();
}

fn file_config(env: &RestartEnv) -> AuthorityKernelConfig {
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(env.db_path.clone());
    config.workspace = env.workspace;
    config
}

/// The transition commits before a failing audit tail; a second boot converges
/// without ever hydrating previous keys into live authority.
#[tokio::test]
async fn failed_boot_tail_converges_on_retry() {
    let env = restart_env();
    let (subject, lease) = {
        let h = open_kernel(&env, HashMap::new(), None).await;
        mint_root(&h.kernel, "boot-tail", 3_600_000).await
    };
    let db = Database::connect(&env.db_path).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_boot_audit BEFORE INSERT ON kernel_audit_events BEGIN SELECT RAISE(ABORT,'injected boot tail failure'); END")
        .execute(db.pool()).await.unwrap();
    assert!(
        AuthorityKernelClient::open(file_config(&env))
            .await
            .is_err()
    );
    let row = db
        .kernel_session(&env.workspace, &subject)
        .await
        .unwrap()
        .unwrap();
    assert!(!row.active);
    assert!(
        db.is_kernel_revoked(&env.workspace, &lease.lease_id)
            .await
            .unwrap()
    );
    let timestamp = row.destroyed_at_ms;
    sqlx::query("DROP TRIGGER fail_boot_audit")
        .execute(db.pool())
        .await
        .unwrap();
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert_eq!(
        db.kernel_session(&env.workspace, &subject)
            .await
            .unwrap()
            .unwrap()
            .destroyed_at_ms,
        timestamp
    );
    let envelope = h
        .pipeline
        .build_envelope(&read_request(&env.leased_file), &subject, &[lease.lease_id])
        .unwrap();
    assert!(matches!(
        h.pipeline.execute_envelope(&envelope, &subject).await,
        ToolOutcome::Denied { .. }
    ));
    assert_eq!(h.sandbox.committed_count(), 0);
}

/// Unknown usage blocks every recovery attempt without refunding spend or held
/// reservations. Old sessions are still durably invalidated on the first try.
#[tokio::test]
async fn unknown_execution_usage_blocks_recovery_and_preserves_reservations() {
    use lumen_core::budget::ExecutionState;
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let fixture = mint_live_child(&h, &env).await;
    let subject = fixture.child_subject.clone();
    let lease = fixture.child_lease.clone();
    let envelope = h
        .pipeline
        .build_envelope(
            &read_request(&env.leased_file),
            &subject,
            &[lease.lease_id.clone(), fixture.parent_lease_id.clone()],
        )
        .unwrap();
    assert!(h.kernel.decide(&envelope).await.unwrap().is_allow());
    assert_eq!(
        h.kernel
            .budget_remaining(&lease.lease_id)
            .await
            .unwrap()
            .get(BudgetDimension::Executions),
        9
    );
    let db = Database::connect(&env.db_path).await.unwrap();
    let executions = db.all_kernel_executions(&env.workspace).await.unwrap();
    assert_eq!(
        executions.len(),
        1,
        "real Allow must durably hold execution capacity"
    );
    let mut execution = executions[0].clone();
    assert_eq!(execution.state, ExecutionState::Held);
    db.record_kernel_nonce(
        &env.workspace,
        "preserved-nonce",
        now_ms(),
        now_ms() + 3_600_000,
    )
    .await
    .unwrap();
    drop(h);
    let accounts = db
        .kernel_budget_account_states(&env.workspace)
        .await
        .unwrap();
    let reservations = db.active_kernel_reservations(&env.workspace).await.unwrap();
    assert_eq!(reservations.len(), 1);
    for _ in 0..2 {
        let error = AuthorityKernelClient::open(file_config(&env))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unknown execution usage"));
        assert!(
            db.active_kernel_sessions(&env.workspace)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.kernel_budget_account_states(&env.workspace)
                .await
                .unwrap(),
            accounts
        );
        assert_eq!(
            db.active_kernel_reservations(&env.workspace).await.unwrap(),
            reservations
        );
        assert_eq!(
            db.get_kernel_execution(&env.workspace, &execution.id)
                .await
                .unwrap(),
            Some(execution.clone())
        );
        assert!(
            !db.record_kernel_nonce(
                &env.workspace,
                "preserved-nonce",
                now_ms(),
                now_ms() + 3_600_000
            )
            .await
            .unwrap()
        );
    }
    // An explicit reconciliation proves dispatch did not occur. Boot itself
    // must never manufacture this transition or release child reservations.
    execution.state = ExecutionState::Released;
    execution.completed_at_ms = Some(now_ms());
    db.update_kernel_execution(&env.workspace, &execution)
        .await
        .unwrap();
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert!(h.kernel.start_session_identity(None).await.is_ok());
    assert_eq!(
        db.active_kernel_reservations(&env.workspace).await.unwrap(),
        reservations
    );
}

#[tokio::test]
async fn staged_effect_with_unknown_completion_blocks_recovery() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let (subject, _) = mint_root(&h.kernel, "staged", 3_600_000).await;
    let envelope = h
        .pipeline
        .build_envelope(&read_request(&env.leased_file), &subject, &[])
        .unwrap();
    let event = lumen_server::AuditEvent {
        kind: "tool_staged".into(),
        session_id: subject,
        action_digest: Some(h.kernel.authoritative_action_digest(&envelope).unwrap()),
        payload: serde_json::json!({}),
    };
    h.kernel.append_audit(&event).await.unwrap();
    drop(h);
    for _ in 0..2 {
        let error = AuthorityKernelClient::open(file_config(&env))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unknown execution usage"));
    }
    let db = Database::connect(&env.db_path).await.unwrap();
    assert!(
        db.active_kernel_sessions(&env.workspace)
            .await
            .unwrap()
            .is_empty()
    );
}

/// Exactly one concurrent opener can own a store; clones share that owner.
#[tokio::test]
async fn concurrent_owners_are_excluded_before_boot() {
    let env = restart_env();
    let (a, b) = tokio::join!(
        AuthorityKernelClient::open(file_config(&env)),
        AuthorityKernelClient::open(file_config(&env))
    );
    let owner = match (a, b) {
        (Ok(owner), Err(error)) | (Err(error), Ok(owner)) => {
            assert!(error.to_string().contains("already owned"));
            owner
        }
        _ => panic!("exactly one store owner must boot"),
    };
    let subject = owner.start_session_identity(None).await.unwrap().subject;
    let clone = owner.clone();
    drop(owner);
    assert!(
        AuthorityKernelClient::open(file_config(&env))
            .await
            .is_err()
    );
    assert!(clone.identity_is_live(&subject).await);
    // A hard-link alias cannot evade an inode lock.
    let alias = env.db_path.with_extension("alias");
    std::fs::hard_link(&env.db_path, &alias).unwrap();
    let mut config = file_config(&env);
    config.db = AuthorityDb::Path(alias);
    assert!(AuthorityKernelClient::open(config).await.is_err());
    drop(clone);
    let next = AuthorityKernelClient::open(file_config(&env))
        .await
        .unwrap();
    assert!(!next.identity_is_live(&subject).await);
}

/// Runs in a distinct process when invoked by the ownership test below.
#[tokio::test]
async fn authority_owner_subprocess() {
    let Ok(path) = std::env::var("LUMEN_TEST_AUTHORITY_STORE") else {
        return;
    };
    let mut config = AuthorityKernelConfig::test_config();
    config.db = AuthorityDb::Path(path.into());
    config.workspace = serde_json::from_value(serde_json::Value::String(
        std::env::var("LUMEN_TEST_WORKSPACE").unwrap(),
    ))
    .unwrap();
    if let Ok(ready_path) = std::env::var("LUMEN_TEST_OWNER_READY") {
        let owner = AuthorityKernelClient::open(config).await.unwrap();
        let subject = owner.start_session_identity(None).await.unwrap().subject;
        std::fs::write(ready_path, subject).unwrap();
        std::future::pending::<()>().await;
        drop(owner);
        return;
    }
    let error = AuthorityKernelClient::open(config)
        .await
        .err()
        .expect("competing process must be refused");
    assert!(error.to_string().contains("already owned"));
}

#[tokio::test]
async fn competing_process_cannot_invalidate_live_owner() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let (subject, lease) = mint_root(&h.kernel, "process-owner", 3_600_000).await;
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "authority_owner_subprocess", "--nocapture"])
        .env("LUMEN_TEST_AUTHORITY_STORE", &env.db_path)
        .env("LUMEN_TEST_WORKSPACE", env.workspace.to_string())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "subprocess failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(h.kernel.identity_is_live(&subject).await);
    h.kernel.verify_lease(&lease).await.unwrap();
}

/// Missing accounting cannot be interpreted as an untouched declared balance.
#[tokio::test]
async fn missing_budget_account_blocks_recovery_without_restoring_caps() {
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let (subject, lease) = mint_root(&h.kernel, "missing-account", 3_600_000).await;
    let db = Database::connect(&env.db_path).await.unwrap();
    let mut unbacked = db
        .kernel_lease(&env.workspace, &lease.lease_id)
        .await
        .unwrap()
        .unwrap();
    unbacked.lease_id = uuid::Uuid::new_v4().to_string();
    unbacked.lease_nonce = "unbacked-nonce".into();
    // Unknown generation avoids making this an unrelated signature-corruption
    // fixture: the missing account itself must stop recovery.
    unbacked.issuer_key_id = "legacy-unknown-generation".into();
    unbacked.sign(&SigningKey::from_bytes(&[0x61; 32])).unwrap();
    db.insert_kernel_lease(&env.workspace, &unbacked)
        .await
        .unwrap();
    let accounts = db
        .kernel_budget_account_states(&env.workspace)
        .await
        .unwrap();
    drop(h);
    for _ in 0..2 {
        let error = AuthorityKernelClient::open(file_config(&env))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("budget account missing"));
        assert_eq!(
            db.kernel_budget_account_states(&env.workspace)
                .await
                .unwrap(),
            accounts
        );
        assert!(
            !db.kernel_session(&env.workspace, &subject)
                .await
                .unwrap()
                .unwrap()
                .active
        );
        assert!(
            db.is_kernel_revoked(&env.workspace, &unbacked.lease_id)
                .await
                .unwrap()
        );
    }
}

/// OS ownership must be released by process death, with old sessions retired by
/// the next boot instead of trusting the dead process's public records.
#[tokio::test]
async fn crashed_owner_releases_lock_and_next_boot_invalidates_sessions() {
    let env = restart_env();
    let ready_path = env.db_path.with_extension("ready");
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "authority_owner_subprocess", "--nocapture"])
        .env("LUMEN_TEST_AUTHORITY_STORE", &env.db_path)
        .env("LUMEN_TEST_WORKSPACE", env.workspace.to_string())
        .env("LUMEN_TEST_OWNER_READY", &ready_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let ready = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(subject) = std::fs::read_to_string(&ready_path) {
                break subject;
            }
            if let Some(status) = child.try_wait().unwrap() {
                panic!("owner subprocess exited early: {status}");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    // Always reap the child, including when readiness times out.
    child.kill().unwrap();
    child.wait().unwrap();
    let subject = ready.expect("owner subprocess did not become ready");
    let owner = AuthorityKernelClient::open(file_config(&env))
        .await
        .unwrap();
    assert!(!owner.identity_is_live(&subject).await);
    let db = Database::connect(&env.db_path).await.unwrap();
    assert!(
        !db.kernel_session(&env.workspace, &subject)
            .await
            .unwrap()
            .unwrap()
            .active
    );
    assert!(owner.start_session_identity(Some(&subject)).await.is_err());
    assert!(owner.start_session_identity(None).await.is_ok());
}

/// Real pipeline execution is durably charged, including after repeated boots.
#[tokio::test]
async fn completed_pipeline_usage_is_not_refunded_on_restart() {
    use lumen_core::budget::ExecutionState;
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let (subject, lease) =
        mint_root_with_scope(&h.kernel, "completed", 3_600_000, read_scope(&env)).await;
    let envelope = h
        .pipeline
        .build_envelope(
            &read_request(&env.leased_file),
            &subject,
            &[lease.lease_id.clone()],
        )
        .unwrap();
    let outcome = h.pipeline.execute_envelope(&envelope, &subject).await;
    assert!(
        matches!(outcome, ToolOutcome::Completed { .. }),
        "{outcome:?}"
    );
    assert_eq!(h.sandbox.committed_count(), 1);
    let db = Database::connect(&env.db_path).await.unwrap();
    let execs = db.all_kernel_executions(&env.workspace).await.unwrap();
    assert_eq!(execs.len(), 1);
    assert_eq!(execs[0].state, ExecutionState::Settled);
    assert_eq!(
        execs[0]
            .actual
            .as_ref()
            .unwrap()
            .get(BudgetDimension::Executions),
        1
    );
    assert!(
        !db.kernel_recovery_usage_unknown(&env.workspace)
            .await
            .unwrap()
    );
    assert_eq!(
        db.kernel_budget_remaining(&env.workspace, &lease.lease_id)
            .await
            .unwrap()
            .get(BudgetDimension::Executions),
        99
    );
    drop(h);
    for _ in 0..2 {
        let h = open_kernel(&env, HashMap::new(), None).await;
        assert_eq!(
            h.kernel
                .budget_remaining(&lease.lease_id)
                .await
                .unwrap()
                .get(BudgetDimension::Executions),
            99
        );
        h.kernel.verify_kernel_audit().await.unwrap();
    }
}

/// A failed hold write cannot expose Allow or reach the sandbox. An audit
/// failure AFTER the hold commits must preserve it and block recovery.
#[tokio::test]
async fn durable_hold_precedes_allow_and_survives_failed_admission_tail() {
    use lumen_core::budget::ExecutionState;
    for fail_hold in [true, false] {
        let env = restart_env();
        let h = open_kernel(&env, HashMap::new(), None).await;
        let (subject, lease) =
            mint_root_with_scope(&h.kernel, "hold-failure", 3_600_000, read_scope(&env)).await;
        let db = Database::connect(&env.db_path).await.unwrap();
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(
            synchronous, 2,
            "file-backed authority commits must use FULL durability"
        );
        let trigger = if fail_hold {
            "CREATE TRIGGER fail_admission BEFORE INSERT ON kernel_executions BEGIN SELECT RAISE(ABORT,'hold failure'); END"
        } else {
            "CREATE TRIGGER fail_admission BEFORE INSERT ON kernel_audit_events WHEN NEW.decision='allow' BEGIN SELECT RAISE(ABORT,'allow audit failure'); END"
        };
        sqlx::query(trigger).execute(db.pool()).await.unwrap();
        let envelope = h
            .pipeline
            .build_envelope(&read_request(&env.leased_file), &subject, &[lease.lease_id])
            .unwrap();
        let outcome = h.pipeline.execute_envelope(&envelope, &subject).await;
        assert!(matches!(outcome, ToolOutcome::Fault { .. }), "{outcome:?}");
        assert_eq!(h.sandbox.staged_count(), 0);
        assert_eq!(h.sandbox.committed_count(), 0);
        let executions = db.all_kernel_executions(&env.workspace).await.unwrap();
        if fail_hold {
            assert!(executions.is_empty());
        } else {
            assert_eq!(executions.len(), 1);
            assert_eq!(executions[0].state, ExecutionState::Held);
        }
        sqlx::query("DROP TRIGGER fail_admission")
            .execute(db.pool())
            .await
            .unwrap();
        drop(h);
        if fail_hold {
            let _h = open_kernel(&env, HashMap::new(), None).await;
        } else {
            for _ in 0..2 {
                let error = AuthorityKernelClient::open(file_config(&env))
                    .await
                    .err()
                    .unwrap();
                assert!(error.to_string().contains("unknown execution usage"));
            }
        }
    }
}

/// A landed completion audit cannot substitute for durable accounting. The
/// terminal-state write and debit roll back together, preserving the hold.
#[tokio::test]
async fn completion_accounting_failure_blocks_recovery_without_partial_debit() {
    use lumen_core::budget::ExecutionState;
    let env = restart_env();
    let h = open_kernel(&env, HashMap::new(), None).await;
    let (subject, lease) =
        mint_root_with_scope(&h.kernel, "settle-failure", 3_600_000, read_scope(&env)).await;
    let db = Database::connect(&env.db_path).await.unwrap();
    sqlx::query("CREATE TRIGGER fail_settlement BEFORE UPDATE ON kernel_executions WHEN NEW.state='settled' BEGIN SELECT RAISE(ABORT,'settlement failure'); END").execute(db.pool()).await.unwrap();
    let envelope = h
        .pipeline
        .build_envelope(
            &read_request(&env.leased_file),
            &subject,
            &[lease.lease_id.clone()],
        )
        .unwrap();
    let outcome = h.pipeline.execute_envelope(&envelope, &subject).await;
    assert!(
        matches!(outcome, ToolOutcome::Uncertain { .. }),
        "{outcome:?}"
    );
    assert_eq!(h.sandbox.committed_count(), 1);
    let execution = db
        .all_kernel_executions(&env.workspace)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(execution.state, ExecutionState::Held);
    assert!(
        db.kernel_audit_events(&env.workspace, &KernelAuditQuery::default())
            .await
            .unwrap()
            .iter()
            .any(|e| e.detail.contains("tool_committed"))
    );
    let account = db
        .kernel_budget_account_states(&env.workspace)
        .await
        .unwrap()
        .pop()
        .unwrap();
    assert!(
        account.3.is_zero(),
        "failed settlement must roll back consumption too"
    );
    assert_eq!(
        db.kernel_budget_remaining(&env.workspace, &lease.lease_id)
            .await
            .unwrap()
            .get(BudgetDimension::Executions),
        99
    );
    let digest = h.kernel.authoritative_action_digest(&envelope).unwrap();
    drop(h);
    for _ in 0..2 {
        let error = AuthorityKernelClient::open(file_config(&env))
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains("unknown execution usage"));
    }
    sqlx::query("DROP TRIGGER fail_settlement")
        .execute(db.pool())
        .await
        .unwrap();
    assert!(
        db.settle_kernel_execution(
            &env.workspace,
            &execution.id,
            "wrong-action",
            &subject,
            digest.as_str(),
            now_ms()
        )
        .await
        .is_err()
    );
    let settled = db
        .settle_kernel_execution(
            &env.workspace,
            &execution.id,
            &envelope.action_id,
            &subject,
            digest.as_str(),
            now_ms(),
        )
        .await
        .unwrap();
    let retried = db
        .settle_kernel_execution(
            &env.workspace,
            &execution.id,
            &envelope.action_id,
            &subject,
            digest.as_str(),
            now_ms(),
        )
        .await
        .unwrap();
    assert_eq!(settled, retried);
    let h = open_kernel(&env, HashMap::new(), None).await;
    assert_eq!(
        h.kernel
            .budget_remaining(&lease.lease_id)
            .await
            .unwrap()
            .get(BudgetDimension::Executions),
        99
    );
}
