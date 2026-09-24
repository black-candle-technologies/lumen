//! Durable authority-kernel tests: migration 0022, leases, revocations,
//! nonces, one-shots, the transactional budget ledger, and the hash-chained
//! audit log with checkpoints.

use std::collections::HashSet;
use std::io;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{SigningKey, VerifyingKey};
use lumen_core::{
    budget::{Budget, BudgetDimension, BudgetLedger},
    canonical::{CanonicalPath, PathGrant, PathResolver, PathRights, ResourceScope},
    identity::WorkspaceId,
    kernel_audit::checkpoint_signing_bytes,
    lease::{
        ChildLeaseParams, KernelKeys, LeaseDocument, LeaseLimits, RevocationIndex, RootLeaseParams,
        SessionRegistry, mint_child_lease, mint_root_lease,
    },
    nonce::NonceStore,
};
use lumen_db::{Database, lease::KernelAuditQuery};
use lumen_protocol::EffectClass;
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
    mint_child_lease(
        root,
        ChildLeaseParams {
            lease_id: lease_id.to_string(),
            subject: "ed25519:child-session".to_string(),
            scope: narrow_scope(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 500_000,
                budget: Budget::new().set(BudgetDimension::Executions, 10),
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

fn checkpoint_sig(keys: &KernelKeys, seq: u64, hash: &str) -> String {
    let bytes = checkpoint_signing_bytes(seq, hash, &keys.host_key_id).unwrap();
    hex_encode(&keys.host_sign(&bytes).to_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn audit_chain_seal_checkpoint_verify() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let keys = KernelKeys::generate();

    let e0 = db
        .append_kernel_audit_event(
            &ws,
            "kernel",
            digest(0).as_str(),
            "lease.allow",
            1_000,
            json!({"api_key": "super-secret", "ok": true}),
        )
        .await
        .unwrap();
    assert_eq!(e0.seq, 0);
    // Secrets are redacted deterministically before sealing.
    assert_eq!(e0.details["api_key"], json!("[REDACTED]"));
    assert_eq!(e0.details["ok"], json!(true));

    let e1 = db
        .append_kernel_audit_event(
            &ws,
            "host",
            digest(1).as_str(),
            "lease.deny",
            2_000,
            json!({}),
        )
        .await
        .unwrap();
    assert_eq!(e1.seq, 1);
    assert_eq!(e1.prev_hash, e0.hash);

    // Provenance queries.
    let by_actor = db
        .kernel_audit_events(
            &ws,
            &KernelAuditQuery {
                actor: Some("host".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(by_actor.len(), 1);
    assert_eq!(by_actor[0].seq, 1);
    let by_decision = db
        .kernel_audit_events(
            &ws,
            &KernelAuditQuery {
                decision: Some("lease.allow".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(by_decision.len(), 1);

    // Checkpoint over the tip, signed by the host key.
    db.checkpoint_kernel_audit(
        &ws,
        e1.seq,
        &e1.hash,
        &checkpoint_sig(&keys, e1.seq, &e1.hash),
        &keys.host_key_id,
        3_000,
    )
    .await
    .unwrap();
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id)
        .await
        .unwrap();

    // Checkpoint for an unknown seq fails closed at store time.
    assert!(
        db.checkpoint_kernel_audit(&ws, 99, "deadbeef", "sig", &keys.host_key_id, 3_000)
            .await
            .is_err()
    );

    // A checkpoint signed by the wrong key fails verification.
    let evil = KernelKeys::generate();
    db.checkpoint_kernel_audit(
        &ws,
        e0.seq,
        &e0.hash,
        &checkpoint_sig(&evil, e0.seq, &e0.hash),
        &keys.host_key_id,
        3_000,
    )
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
            "kernel",
            &digest(i as u64),
            "lease.allow",
            1_000 + i,
            json!({}),
        )
        .await
        .unwrap();
    }

    // Skipping a sequence number fails closed at the SQL level.
    let gap = sqlx::query(
        "INSERT INTO kernel_audit_events(seq,workspace_id,prev_hash,hash,action_digest,
         decision,actor,details_json,recorded_at) VALUES(99,?,?,?,?,?,?,?,?)",
    )
    .bind(ws.to_string())
    .bind("x")
    .bind("y")
    .bind("digest-gap")
    .bind("lease.allow")
    .bind("kernel")
    .bind("{}")
    .bind(9_999)
    .execute(db.pool())
    .await;
    assert!(gap.is_err(), "audit seq gaps must be rejected");

    // Deleting or updating an event fails closed.
    assert!(
        sqlx::query("DELETE FROM kernel_audit_events WHERE seq=1")
            .execute(db.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("UPDATE kernel_audit_events SET decision='lease.evil' WHERE seq=1")
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
