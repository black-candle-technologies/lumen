//! Durable authority-kernel tests: migration 0022, leases, revocations,
//! nonces, one-shots, the transactional budget ledger, and the hash-chained
//! audit log with checkpoints.

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use lumen_core::{
    budget::{Budget, BudgetDimension, BudgetLedger, ExecutionReservation, ExecutionState},
    canonical::{CanonicalPath, EffectClass, PathGrant, PathResolver, PathRights, ResourceScope},
    identity::WorkspaceId,
    kernel_audit::AuditLink,
    lease::{
        ChildLeaseParams, KernelKeys, LeaseDocument, LeaseLimits, RevocationIndex, RootLeaseParams,
        SessionRegistry, mint_child_lease, mint_root_lease,
    },
    nonce::NonceStore,
    pi_boundary::AuditEventKind,
};
use lumen_db::{
    Database,
    lease::{KernelAuditAppend, KernelAuditQuery},
};
use rand::rngs::OsRng;
use serde_json::json;

/// Lexical test resolver: normalizes `.`/`..` without touching the
/// filesystem (no symlinks in test paths).
#[derive(Clone, Copy, Debug, Default)]
struct TestResolver;

impl PathResolver for TestResolver {
    fn resolve(&self, path: &Path) -> io::Result<PathBuf> {
        let mut out = PathBuf::new();
        for comp in path.components() {
            match comp {
                Component::Prefix(p) => out.push(p.as_os_str()),
                Component::RootDir => out.push("/"),
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(c) => out.push(c),
            }
        }
        Ok(out)
    }
}

struct Fixture {
    keys: KernelKeys,
    /// Parent session signing key: the delegator that signs child leases.
    session_key: SigningKey,
    session_vk: VerifyingKey,
    sessions: SessionRegistry,
    ledger: BudgetLedger,
    nonces: NonceStore,
}

fn fixture() -> Fixture {
    let keys = KernelKeys::generate();
    let session_key = SigningKey::generate(&mut OsRng);
    let session_vk = session_key.verifying_key();
    let child_key = SigningKey::generate(&mut OsRng);
    let mut sessions = SessionRegistry::new();
    sessions.register("ed25519:parent-session".to_string(), None, session_vk);
    sessions.register(
        "ed25519:child-session".to_string(),
        Some("ed25519:parent-session".to_string()),
        child_key.verifying_key(),
    );
    Fixture {
        keys,
        session_key,
        session_vk,
        sessions,
        ledger: BudgetLedger::new(),
        nonces: NonceStore::new(),
    }
}

fn test_scope() -> ResourceScope {
    let r = TestResolver;
    let mut scope = ResourceScope::default();
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse("/workspace", &r, false).unwrap(),
        rights: PathRights::READ,
    });
    scope.effects.push(EffectClass::Read);
    scope
}

fn narrow_scope() -> ResourceScope {
    let r = TestResolver;
    let mut scope = ResourceScope::default();
    scope.paths.push(PathGrant {
        root: CanonicalPath::parse("/workspace/src", &r, false).unwrap(),
        rights: PathRights::READ,
    });
    scope.effects.push(EffectClass::Read);
    scope
}

fn mint_root(fx: &Fixture, lease_id: &str, nonce_str: &str) -> LeaseDocument {
    mint_root_lease(
        RootLeaseParams {
            lease_id: lease_id.to_string(),
            subject: "ed25519:parent-session".to_string(),
            scope: test_scope(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 1_000_000,
                budget: Budget::new()
                    .set(BudgetDimension::Executions, 100)
                    .set(BudgetDimension::SpendMicros, 10_000),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: nonce_str.to_string(),
            issued_at_ms: 100,
        },
        &fx.keys,
        &fx.sessions,
        &fx.ledger,
        &fx.nonces,
        100,
    )
    .unwrap()
}

fn mint_child(
    fx: &Fixture,
    root: &LeaseDocument,
    lease_id: &str,
    nonce_str: &str,
) -> LeaseDocument {
    mint_child_with_budget(
        fx,
        root,
        lease_id,
        nonce_str,
        Budget::new().set(BudgetDimension::Executions, 10),
    )
}

fn mint_child_with_budget(
    fx: &Fixture,
    root: &LeaseDocument,
    lease_id: &str,
    nonce_str: &str,
    budget: Budget,
) -> LeaseDocument {
    mint_child_lease(
        root,
        ChildLeaseParams {
            lease_id: lease_id.to_string(),
            subject: "ed25519:child-session".to_string(),
            scope: narrow_scope(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 500_000,
                budget,
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: nonce_str.to_string(),
            issued_at_ms: 200,
        },
        &fx.session_key,
        &fx.sessions,
        &RevocationIndex::new(),
        &fx.ledger,
        &fx.nonces,
        200,
    )
    .unwrap()
}

async fn test_db() -> Database {
    Database::connect_in_memory().await.unwrap()
}

/// Deterministic 64-hex action digest for tests.
fn digest(n: u64) -> String {
    format!("{n:064x}")
}

/// A workspace that actually exists in `workspaces`, satisfying the
/// kernel tables' foreign keys.
async fn test_workspace(db: &Database) -> WorkspaceId {
    let ws = WorkspaceId::new();
    sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,'kernel-test',0)")
        .bind(ws.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    ws
}

#[tokio::test]
async fn migration_0022_tables_exist() {
    let db = test_db().await;
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'kernel_%' ORDER BY name",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    for expected in [
        "kernel_audit_checkpoints",
        "kernel_audit_events",
        "kernel_budget_accounts",
        "kernel_debits",
        "kernel_executions",
        "kernel_lease_caps",
        "kernel_lease_debits",
        "kernel_leases",
        "kernel_nonces",
        "kernel_one_shot_uses",
        "kernel_reservations",
        "kernel_revocations",
    ] {
        assert!(names.iter().any(|n| n == expected), "missing {expected}");
    }
}

#[tokio::test]
async fn lease_round_trip_and_chain() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    let child = mint_child(&fx, &root, "lease-child-1", "child-nonce-1");

    db.insert_kernel_lease(&ws, &root).await.unwrap();
    db.insert_kernel_lease(&ws, &child).await.unwrap();

    let loaded = db.kernel_lease(&ws, "lease-root-1").await.unwrap().unwrap();
    assert_eq!(loaded, root);
    loaded
        .verify_signature(&fx.keys.issuer_verifying())
        .unwrap();

    // The durable child still verifies against the parent session key.
    let loaded_child = db
        .kernel_lease(&ws, "lease-child-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(loaded_child, child);
    loaded_child.verify_signature(&fx.session_vk).unwrap();

    // Chain loads leaf-first following parent links.
    let chain = db.kernel_lease_chain(&ws, "lease-child-1").await.unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].lease_id, "lease-child-1");
    assert_eq!(chain[1].lease_id, "lease-root-1");

    // Unknown lease -> None, not an error.
    assert!(db.kernel_lease(&ws, "nope").await.unwrap().is_none());
    // Workspace isolation.
    assert!(
        db.kernel_lease(&test_workspace(&db).await, "lease-root-1")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn leases_are_immutable() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();

    let upd = sqlx::query("UPDATE kernel_leases SET depth_limit=99 WHERE lease_id='lease-root-1'")
        .execute(db.pool())
        .await;
    assert!(upd.is_err(), "UPDATE on kernel_leases must be rejected");

    let del = sqlx::query("DELETE FROM kernel_leases WHERE lease_id='lease-root-1'")
        .execute(db.pool())
        .await;
    assert!(del.is_err(), "DELETE on kernel_leases must be rejected");
}

#[tokio::test]
async fn revocation_round_trip_is_idempotent() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();

    assert!(!db.is_kernel_revoked(&ws, "lease-root-1").await.unwrap());
    db.record_kernel_revocation(&ws, "lease-root-1", 500, "compromise")
        .await
        .unwrap();
    // Second record is a no-op, not an error.
    db.record_kernel_revocation(&ws, "lease-root-1", 600, "compromise")
        .await
        .unwrap();
    assert!(db.is_kernel_revoked(&ws, "lease-root-1").await.unwrap());

    let ids: HashSet<String> = db.kernel_revoked_ids(&ws).await.unwrap();
    assert_eq!(ids, HashSet::from(["lease-root-1".to_string()]));
    // Workspace isolation.
    let other = test_workspace(&db).await;
    assert!(db.kernel_revoked_ids(&other).await.unwrap().is_empty());
}

#[tokio::test]
async fn nonce_replay_and_purge() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;

    assert!(db.record_kernel_nonce(&ws, "n1", 100, 1_000).await.unwrap());
    assert!(!db.record_kernel_nonce(&ws, "n1", 200, 1_000).await.unwrap());

    // Purge only touches expired rows.
    assert_eq!(db.purge_kernel_nonces(&ws, 999).await.unwrap(), 0);
    assert!(!db.record_kernel_nonce(&ws, "n1", 999, 1_000).await.unwrap());
    assert_eq!(db.purge_kernel_nonces(&ws, 1_001).await.unwrap(), 1);
    // Expired record gone: the nonce is fresh again.
    assert!(
        db.record_kernel_nonce(&ws, "n1", 1_001, 2_000)
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn one_shot_consume_single_winner() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-oneshot-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();

    let mut handles = Vec::new();
    for _ in 0..8 {
        let dbc = db.clone();
        let wsc = ws;
        handles.push(tokio::spawn(async move {
            dbc.consume_kernel_one_shot(&wsc, "lease-oneshot-1", 100)
                .await
                .unwrap()
        }));
    }
    let mut wins = 0;
    for h in handles {
        if h.await.unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "exactly one consumer may win the one-shot");
    assert!(
        db.is_kernel_one_shot_consumed(&ws, "lease-oneshot-1")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn budget_reserve_debit_release_ledger() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();

    let caps = Budget::new()
        .set(BudgetDimension::Executions, 100)
        .set(BudgetDimension::SpendMicros, 10_000);
    db.register_kernel_budget(&ws, "lease-root-1", &caps, 100)
        .await
        .unwrap();
    // Re-registering is a conflict.
    assert!(
        db.register_kernel_budget(&ws, "lease-root-1", &caps, 100)
            .await
            .is_err()
    );

    // The durable mint flow persists child leases before reserving against
    // the parent (the reservation FK requires the child to exist).
    for (id, nonce_str) in [
        ("lease-child-1", "child-nonce-1"),
        ("lease-child-2", "child-nonce-2"),
    ] {
        let child = mint_child(&fx, &root, id, nonce_str);
        db.insert_kernel_lease(&ws, &child).await.unwrap();
    }

    // Reserve for two children.
    let r1 = db
        .reserve_kernel_budget(
            &ws,
            "lease-root-1",
            "lease-child-1",
            &Budget::new().set(BudgetDimension::Executions, 30),
            200,
        )
        .await
        .unwrap();
    // Overspend fails closed.
    assert!(
        db.reserve_kernel_budget(
            &ws,
            "lease-root-1",
            "lease-child-2",
            &Budget::new().set(BudgetDimension::Executions, 80),
            200,
        )
        .await
        .is_err()
    );
    let r2 = db
        .reserve_kernel_budget(
            &ws,
            "lease-root-1",
            "lease-child-2",
            &Budget::new().set(BudgetDimension::Executions, 40),
            200,
        )
        .await
        .unwrap();

    let remaining = db
        .kernel_budget_remaining(&ws, "lease-root-1")
        .await
        .unwrap();
    assert_eq!(remaining.get(BudgetDimension::Executions), 30);

    // Debit against the first reservation: idempotent on the same key.
    let ten = Budget::new().set(BudgetDimension::Executions, 10);
    let receipt = db
        .debit_kernel_budget(&ws, &r1, &ten, "idem-1", 300)
        .await
        .unwrap();
    assert_eq!(receipt.actual, ten);
    let receipt2 = db
        .debit_kernel_budget(&ws, &r1, &ten, "idem-1", 300)
        .await
        .unwrap();
    assert_eq!(receipt, receipt2);
    // Same key, different params -> conflict, not silent overwrite.
    assert!(
        db.debit_kernel_budget(
            &ws,
            &r1,
            &Budget::new().set(BudgetDimension::Executions, 11),
            "idem-1",
            300
        )
        .await
        .is_err()
    );
    // Debit beyond held fails closed: held 30, consumed 10, ask 25.
    assert!(
        db.debit_kernel_budget(
            &ws,
            &r1,
            &Budget::new().set(BudgetDimension::Executions, 25),
            "idem-2",
            300
        )
        .await
        .is_err()
    );

    // Release the second reservation: unspent 40 returns to the parent.
    let returned = db.release_kernel_budget(&ws, &r2, 400).await.unwrap();
    assert_eq!(returned.get(BudgetDimension::Executions), 40);
    // Releasing twice is a conflict.
    assert!(db.release_kernel_budget(&ws, &r2, 400).await.is_err());

    // Conservation: caps(100) = reserved_out(30) + consumed(10) + remaining(60).
    let remaining = db
        .kernel_budget_remaining(&ws, "lease-root-1")
        .await
        .unwrap();
    assert_eq!(remaining.get(BudgetDimension::Executions), 60);

    // Direct debit against the lease's own caps.
    let five = Budget::new().set(BudgetDimension::Executions, 5);
    db.debit_kernel_lease(&ws, "lease-root-1", &five, "direct-1", 500)
        .await
        .unwrap();
    let remaining = db
        .kernel_budget_remaining(&ws, "lease-root-1")
        .await
        .unwrap();
    assert_eq!(remaining.get(BudgetDimension::Executions), 55);

    // One active reservation left (child-1's).
    let active = db.active_kernel_reservations(&ws).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].child_lease_id, "lease-child-1");
    assert_eq!(active[0].held.get(BudgetDimension::Executions), 30);
    assert_eq!(active[0].consumed.get(BudgetDimension::Executions), 10);
}

#[tokio::test]
async fn budget_concurrent_reserve_never_overspends() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();
    db.register_kernel_budget(
        &ws,
        "lease-root-1",
        &Budget::new().set(BudgetDimension::Executions, 100),
        100,
    )
    .await
    .unwrap();

    // Persist the child leases first: reservations FK-reference them.
    for i in 0..10 {
        let child = mint_child(
            &fx,
            &root,
            &format!("lease-child-{i}"),
            &format!("child-nonce-{i}"),
        );
        db.insert_kernel_lease(&ws, &child).await.unwrap();
    }

    let mut handles = Vec::new();
    for i in 0..10 {
        let dbc = db.clone();
        let wsc = ws;
        handles.push(tokio::spawn(async move {
            dbc.reserve_kernel_budget(
                &wsc,
                "lease-root-1",
                &format!("lease-child-{i}"),
                &Budget::new().set(BudgetDimension::Executions, 30),
                200,
            )
            .await
            .is_ok()
        }));
    }
    let mut ok = 0;
    for h in handles {
        if h.await.unwrap() {
            ok += 1;
        }
    }
    // 3 x 30 = 90 fits; a 4th would exceed 100.
    assert_eq!(ok, 3);

    let active = db.active_kernel_reservations(&ws).await.unwrap();
    let held_total: u64 = active
        .iter()
        .map(|r| r.held.get(BudgetDimension::Executions))
        .sum();
    assert_eq!(held_total, 90);
    let remaining = db
        .kernel_budget_remaining(&ws, "lease-root-1")
        .await
        .unwrap();
    assert_eq!(remaining.get(BudgetDimension::Executions), 10);
}

/// Parameters for a kernel-actor policy event in tests.
fn audit_params<'a>(
    kind: AuditEventKind,
    action_digest: &'a str,
    decision: Option<&'a str>,
    timestamp_ms: i64,
    details: serde_json::Value,
) -> KernelAuditAppend<'a> {
    KernelAuditAppend {
        actor: "kernel",
        kind,
        session_id: "ed25519:test-session",
        action_digest,
        decision,
        timestamp_ms,
        details,
    }
}

/// A host-key checkpoint link over the given chain tip, signed and ready to
/// store. `AuditLink::sign` sets the key id itself.
fn checkpoint_link(keys: &KernelKeys, through_seq: u64, chain_hash: &str) -> AuditLink {
    let mut link = AuditLink {
        key_id: String::new(),
        through_seq,
        chain_hash: chain_hash.to_string(),
        signature: String::new(),
    };
    link.sign(keys);
    link
}

#[tokio::test]
async fn audit_chain_seal_checkpoint_verify() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let keys = KernelKeys::generate();

    let e0 = db
        .append_kernel_audit_event(
            &ws,
            &audit_params(
                AuditEventKind::PolicyAllowed,
                digest(0).as_str(),
                Some("allow"),
                1_000,
                json!({"api_key": "super-secret", "ok": true}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(e0.sequence, 0);
    assert_eq!(e0.kind, AuditEventKind::PolicyAllowed);
    assert_eq!(e0.decision.as_deref(), Some("allow"));
    // Secrets are redacted deterministically before sealing; the detail is
    // the canonical JSON string.
    let detail: serde_json::Value = serde_json::from_str(&e0.detail).unwrap();
    assert_eq!(detail["api_key"], json!("[REDACTED]"));
    assert_eq!(detail["ok"], json!(true));

    let e1 = db
        .append_kernel_audit_event(
            &ws,
            &audit_params(
                AuditEventKind::PolicyDenied,
                digest(1).as_str(),
                Some("deny"),
                2_000,
                json!({}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(e1.sequence, 1);
    assert_eq!(e1.prev_hash, e0.hash);

    // Provenance queries.
    let by_actor = db
        .kernel_audit_events(
            &ws,
            &KernelAuditQuery {
                actor: Some("kernel".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(by_actor.len(), 2);
    let by_decision = db
        .kernel_audit_events(
            &ws,
            &KernelAuditQuery {
                decision: Some("allow".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(by_decision.len(), 1);
    assert_eq!(by_decision[0].sequence, 0);

    // Checkpoint over the tip, signed by the host key.
    let link = checkpoint_link(&keys, e1.sequence, &e1.hash);
    db.checkpoint_kernel_audit(&ws, &link, 3_000).await.unwrap();
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id)
        .await
        .unwrap();

    // A checkpoint for an unknown seq fails closed at store time.
    let bogus = checkpoint_link(&keys, 99, &"0".repeat(64));
    assert!(
        db.checkpoint_kernel_audit(&ws, &bogus, 3_000)
            .await
            .is_err()
    );

    // A checkpoint signed by the wrong key fails verification.
    let evil = KernelKeys::generate();
    let evil_link = checkpoint_link(&evil, e0.sequence, &e0.hash);
    db.checkpoint_kernel_audit(&ws, &evil_link, 3_000)
        .await
        .unwrap();
    assert!(
        db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn audit_gaps_and_tamper_are_impossible_or_visible() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;

    for i in 0..3 {
        db.append_kernel_audit_event(
            &ws,
            &audit_params(
                AuditEventKind::PolicyAllowed,
                &digest(i as u64),
                Some("allow"),
                1_000 + i,
                json!({}),
            ),
        )
        .await
        .unwrap();
    }

    // Skipping a sequence number fails closed at the SQL level.
    let gap = sqlx::query(
        "INSERT INTO kernel_audit_events(workspace_id,seq,version,event_id,kind,actor,
         session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms)
         VALUES(?,?,1,'12345678-1234-1234-1234-123456789012','policy_allowed','kernel',
         'ed25519:test-session','digest-gap','allow','{}',?,? ,9999)",
    )
    .bind(ws.to_string())
    .bind(99_i64)
    .bind("0".repeat(64))
    .bind("1".repeat(64))
    .execute(db.pool())
    .await;
    assert!(gap.is_err(), "audit seq gaps must be rejected");

    // Deleting or updating an event fails closed.
    assert!(
        sqlx::query("DELETE FROM kernel_audit_events WHERE workspace_id=? AND seq=1")
            .bind(ws.to_string())
            .execute(db.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query(
            "UPDATE kernel_audit_events SET decision='evil' WHERE workspace_id=? AND seq=1"
        )
        .bind(ws.to_string())
        .execute(db.pool())
        .await
        .is_err()
    );

    // The intact chain still verifies.
    let keys = KernelKeys::generate();
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn mint_child_lease_is_atomic() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();
    db.register_kernel_budget(&ws, "lease-root-1", &root.limits.budget, 100)
        .await
        .unwrap();

    // Happy path: the child lease row, the parent's reservation, and the
    // child's budget account all commit together.
    let child = mint_child(&fx, &root, "lease-child-1", "child-nonce-1");
    let reservation_id = db.mint_kernel_child_lease(&ws, &child, 200).await.unwrap();
    assert!(
        db.kernel_lease(&ws, "lease-child-1")
            .await
            .unwrap()
            .is_some()
    );
    let reservations = db.active_kernel_reservations(&ws).await.unwrap();
    assert_eq!(reservations.len(), 1);
    assert_eq!(reservations[0].id, reservation_id);
    assert_eq!(reservations[0].child_lease_id, "lease-child-1");
    assert_eq!(reservations[0].parent_lease_id, "lease-root-1");
    assert_eq!(reservations[0].held.get(BudgetDimension::Executions), 10);
    let remaining = db
        .kernel_budget_remaining(&ws, "lease-root-1")
        .await
        .unwrap();
    assert_eq!(remaining.get(BudgetDimension::Executions), 90);
    let child_remaining = db
        .kernel_budget_remaining(&ws, "lease-child-1")
        .await
        .unwrap();
    assert_eq!(child_remaining.get(BudgetDimension::Executions), 10);

    // Failure path: a child the parent cannot cover (90 left, 95 wanted)
    // fails with no partial state — no lease row, no reservation, no budget
    // account, and the parent's books untouched. A fresh fixture keeps the
    // kernel-side ledger out of the way (re-registering the root there so
    // the kernel mint succeeds); the db must fail on its own arithmetic.
    let fx2 = fixture();
    fx2.ledger
        .register_lease("lease-root-1", &root.limits.budget)
        .unwrap();
    let greedy = mint_child_with_budget(
        &fx2,
        &root,
        "lease-greedy-1",
        "greedy-nonce-1",
        Budget::new().set(BudgetDimension::Executions, 95),
    );
    assert!(db.mint_kernel_child_lease(&ws, &greedy, 300).await.is_err());
    assert!(
        db.kernel_lease(&ws, "lease-greedy-1")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        db.active_kernel_reservations(&ws).await.unwrap().len(),
        1,
        "failed mint must not leave a reservation"
    );
    assert!(
        db.kernel_budget_remaining(&ws, "lease-greedy-1")
            .await
            .is_err(),
        "failed mint must not leave a budget account"
    );
    let remaining = db
        .kernel_budget_remaining(&ws, "lease-root-1")
        .await
        .unwrap();
    assert_eq!(remaining.get(BudgetDimension::Executions), 90);
}

#[tokio::test]
async fn one_shot_consume_audits_atomically() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    // The one-shot table's FK requires the lease row to exist.
    let one_shot = mint_root_lease(
        RootLeaseParams {
            lease_id: "lease-oneshot-1".to_string(),
            subject: "ed25519:parent-session".to_string(),
            scope: test_scope(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 1_000_000,
                budget: Budget::new(),
                max_executions: Some(1),
                single_use: true,
            },
            depth_limit: 4,
            lease_nonce: "oneshot-nonce-1".to_string(),
            issued_at_ms: 100,
        },
        &fx.keys,
        &fx.sessions,
        &fx.ledger,
        &fx.nonces,
        100,
    )
    .unwrap();
    db.insert_kernel_lease(&ws, &one_shot).await.unwrap();

    let d7 = digest(7);
    let allow = audit_params(
        AuditEventKind::PolicyAllowed,
        &d7,
        Some("allow"),
        1_000,
        json!({"lease_id": "lease-oneshot-1"}),
    );
    let deny = audit_params(
        AuditEventKind::PolicyDenied,
        &d7,
        Some("deny"),
        2_000,
        json!({"lease_id": "lease-oneshot-1", "reason": "replay"}),
    );

    // First call consumes and audits the allow in one transaction.
    let (consumed, e0) = db
        .consume_kernel_one_shot_and_audit(&ws, "lease-oneshot-1", &allow, &deny)
        .await
        .unwrap();
    assert!(consumed);
    assert_eq!(e0.sequence, 0);
    assert_eq!(e0.decision.as_deref(), Some("allow"));

    // Replay consumes nothing but still audits the denial, atomically tied
    // to the replay outcome.
    let (consumed, e1) = db
        .consume_kernel_one_shot_and_audit(&ws, "lease-oneshot-1", &allow, &deny)
        .await
        .unwrap();
    assert!(!consumed);
    assert_eq!(e1.sequence, 1);
    assert_eq!(e1.decision.as_deref(), Some("deny"));
    assert_eq!(e1.prev_hash, e0.hash);

    assert!(
        db.is_kernel_one_shot_consumed(&ws, "lease-oneshot-1")
            .await
            .unwrap()
    );
    let keys = KernelKeys::generate();
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn concurrent_audit_appends_stay_gapless() {
    // File-backed: the in-memory test db is a single connection, so real
    // multi-connection concurrency needs a file.
    let dir = tempfile::tempdir().unwrap();
    let db = Database::connect(dir.path().join("audit-conc.db"))
        .await
        .unwrap();
    let ws = test_workspace(&db).await;

    const WRITERS: usize = 8;
    const PER_WRITER: usize = 10;
    let mut handles = Vec::new();
    for w in 0..WRITERS {
        let db = db.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..PER_WRITER {
                let n = (w * PER_WRITER + i) as u64;
                db.append_kernel_audit_event(
                    &ws,
                    &audit_params(
                        AuditEventKind::ToolExecuted,
                        &digest(n),
                        None,
                        1_000 + n as i64,
                        json!({"writer": w, "i": i}),
                    ),
                )
                .await
                .unwrap();
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    let events = db
        .kernel_audit_events(&ws, &KernelAuditQuery::default())
        .await
        .unwrap();
    assert_eq!(events.len(), WRITERS * PER_WRITER);
    for (idx, e) in events.iter().enumerate() {
        assert_eq!(e.sequence, idx as u64, "audit seq must be gapless");
    }
    // The hash chain verifies end to end after the write storm.
    let keys = KernelKeys::generate();
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id)
        .await
        .unwrap();
}

#[tokio::test]
async fn cross_workspace_references_fail_closed() {
    let db = test_db().await;
    let ws_a = test_workspace(&db).await;
    let ws_b = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws_a, &root).await.unwrap();

    // A child naming a parent from another workspace fails at the SQL
    // layer: the composite (workspace_id, parent_id) FK has no match in ws_b.
    let child = mint_child(&fx, &root, "lease-child-x", "child-nonce-x");
    let err = db.insert_kernel_lease(&ws_b, &child).await.unwrap_err();
    assert!(
        err.to_string().contains("FOREIGN KEY"),
        "expected FK failure, got: {err}"
    );
    assert!(
        db.kernel_lease(&ws_b, "lease-child-x")
            .await
            .unwrap()
            .is_none()
    );

    // A reservation naming a parent from another workspace fails the same
    // way, even through raw SQL.
    db.register_kernel_budget(&ws_a, "lease-root-1", &root.limits.budget, 100)
        .await
        .unwrap();
    let fk = sqlx::query(
        "INSERT INTO kernel_reservations(reservation_id,workspace_id,parent_lease_id,
         child_lease_id,held_json,consumed_json,state,created_at_ms,released_at_ms)
         VALUES('res-x',?,'lease-root-1','lease-child-x','{}','{}','active',0,NULL)",
    )
    .bind(ws_b.to_string())
    .execute(db.pool())
    .await;
    assert!(fk.is_err(), "cross-workspace reservation must fail");

    // Each workspace has its own audit sequence space: both start at 0.
    let ea = db
        .append_kernel_audit_event(
            &ws_a,
            &audit_params(
                AuditEventKind::ToolExecuted,
                &digest(1),
                None,
                100,
                json!({}),
            ),
        )
        .await
        .unwrap();
    let eb = db
        .append_kernel_audit_event(
            &ws_b,
            &audit_params(
                AuditEventKind::ToolExecuted,
                &digest(2),
                None,
                100,
                json!({}),
            ),
        )
        .await
        .unwrap();
    assert_eq!(ea.sequence, 0);
    assert_eq!(eb.sequence, 0);
}

#[tokio::test]
async fn execution_reservation_durable_lifecycle() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let root = mint_root(&fx, "lease-root-1", "root-nonce-1");
    db.insert_kernel_lease(&ws, &root).await.unwrap();

    // Caps: first write wins, re-recording is a no-op.
    let caps = Budget::new().set(BudgetDimension::Executions, 100);
    db.record_kernel_lease_caps(&ws, "lease-root-1", &caps, 100)
        .await
        .unwrap();
    db.record_kernel_lease_caps(&ws, "lease-root-1", &Budget::new(), 101)
        .await
        .unwrap();
    assert_eq!(
        db.kernel_lease_caps(&ws, "lease-root-1").await.unwrap(),
        Some(caps)
    );
    assert_eq!(
        db.kernel_lease_caps(&ws, "lease-missing").await.unwrap(),
        None
    );

    // Insert a held reservation.
    let exec = ExecutionReservation {
        id: "exec_test_1".to_string(),
        lease_id: "lease-root-1".to_string(),
        action_id: "action-1".to_string(),
        held: Budget::new().set(BudgetDimension::Executions, 1),
        state: ExecutionState::Held,
        idempotency_key: "nonce-1".to_string(),
        created_at_ms: 200,
        completed_at_ms: None,
        actual: None,
    };
    db.insert_kernel_execution(&ws, &exec).await.unwrap();
    // Duplicate insert is a conflict (fail closed).
    assert!(db.insert_kernel_execution(&ws, &exec).await.is_err());

    let got = db
        .get_kernel_execution(&ws, "exec_test_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, exec);
    assert!(
        db.get_kernel_execution(&ws, "exec_missing")
            .await
            .unwrap()
            .is_none()
    );

    // Held -> settled, with measured actuals as the durable receipt.
    let mut settled = exec.clone();
    settled.state = ExecutionState::Settled;
    settled.completed_at_ms = Some(300);
    settled.actual = Some(Budget::new().set(BudgetDimension::Executions, 1));
    db.update_kernel_execution(&ws, &settled).await.unwrap();
    let got = db
        .get_kernel_execution(&ws, "exec_test_1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.state, ExecutionState::Settled);
    assert_eq!(got.actual, settled.actual);

    // Settled is terminal: settled -> released is rejected by the guard trigger.
    let mut bad = settled.clone();
    bad.state = ExecutionState::Released;
    assert!(db.update_kernel_execution(&ws, &bad).await.is_err());
    // Settling without actuals is rejected too.
    let mut bad2 = exec.clone();
    bad2.completed_at_ms = Some(300);
    bad2.state = ExecutionState::Settled;
    assert!(db.update_kernel_execution(&ws, &bad2).await.is_err());
    // Updating a missing row fails closed.
    let mut missing = exec.clone();
    missing.id = "exec_missing".to_string();
    missing.state = ExecutionState::Released;
    missing.completed_at_ms = Some(300);
    assert!(db.update_kernel_execution(&ws, &missing).await.is_err());

    // A second reservation takes the held -> released path.
    let exec2 = ExecutionReservation {
        id: "exec_test_2".to_string(),
        action_id: "action-2".to_string(),
        idempotency_key: "nonce-2".to_string(),
        ..exec.clone()
    };
    db.insert_kernel_execution(&ws, &exec2).await.unwrap();
    let mut released = exec2.clone();
    released.state = ExecutionState::Released;
    released.completed_at_ms = Some(400);
    db.update_kernel_execution(&ws, &released).await.unwrap();
    let got = db
        .get_kernel_execution(&ws, "exec_test_2")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got.state, ExecutionState::Released);
    assert_eq!(got.actual, None);

    let all = db.all_kernel_executions(&ws).await.unwrap();
    assert_eq!(all.len(), 2);
}
