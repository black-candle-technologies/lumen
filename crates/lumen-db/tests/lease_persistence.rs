//! Lease-persistence store tests: migration 0027 (guarded generation
//! delete, kill-list, durable sessions) and the `Database` methods that
//! operate on them. All against in-memory databases.

use std::io;
use std::path::{Component, Path, PathBuf};

use ed25519_dalek::SigningKey;
use lumen_core::{
    budget::{Budget, BudgetDimension, BudgetLedger},
    canonical::{CanonicalPath, EffectClass, PathGrant, PathResolver, PathRights, ResourceScope},
    identity::WorkspaceId,
    kernel_audit::AuditLink,
    lease::{
        KernelKeys, LeaseDocument, LeaseLimits, RootLeaseParams, SessionRegistry, mint_root_lease,
    },
    nonce::NonceStore,
    pi_boundary::AuditEventKind,
};
use lumen_db::{
    Database,
    lease::{KernelAuditAppend, PurgeOutcome},
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
    sessions: SessionRegistry,
    ledger: BudgetLedger,
    nonces: NonceStore,
}

fn fixture() -> Fixture {
    let keys = KernelKeys::generate();
    let session_key = SigningKey::generate(&mut OsRng);
    let mut sessions = SessionRegistry::new();
    sessions.register(
        "ed25519:parent-session".to_string(),
        None,
        session_key.verifying_key(),
        0,
    );
    Fixture {
        keys,
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

fn mint_root(
    fx: &Fixture,
    lease_id: &str,
    nonce_str: &str,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> LeaseDocument {
    mint_root_lease(
        RootLeaseParams {
            lease_id: lease_id.to_string(),
            subject: "ed25519:parent-session".to_string(),
            scope: test_scope(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms,
                budget: Budget::new()
                    .set(BudgetDimension::Executions, 100)
                    .set(BudgetDimension::SpendMicros, 10_000),
                max_executions: None,
                single_use: false,
            },
            depth_limit: 4,
            lease_nonce: nonce_str.to_string(),
            issued_at_ms,
        },
        &fx.keys,
        &fx.sessions,
        &fx.ledger,
        &fx.nonces,
        issued_at_ms,
    )
    .unwrap()
}

async fn test_db() -> Database {
    Database::connect_in_memory().await.unwrap()
}

/// A workspace that actually exists in `workspaces`, satisfying the
/// kernel tables' foreign keys.
async fn test_workspace(db: &Database) -> WorkspaceId {
    let ws = WorkspaceId::new();
    sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,'lease-persist-test',0)")
        .bind(ws.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    ws
}

/// Deterministic 64-hex verifying key stand-in for tests.
fn vk_hex(n: u64) -> String {
    format!("{n:064x}")
}

async fn record_generation(db: &Database, ws: &WorkspaceId, key_id: &str, role: &str) {
    db.record_kernel_key_generation(ws, key_id, role, &vk_hex(1), 0)
        .await
        .unwrap();
}

async fn has_generation(db: &Database, ws: &WorkspaceId, key_id: &str) -> bool {
    db.kernel_key_generations(ws)
        .await
        .unwrap()
        .iter()
        .any(|g| g.key_id == key_id)
}

fn db_err_message<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

#[tokio::test]
async fn migration_0027_applies_cleanly() {
    // connect_in_memory already ran every migration; assert the new schema
    // objects exist and the old blanket trigger is gone.
    let db = test_db().await;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='table'
         AND name IN ('kernel_killed_generations','kernel_sessions')",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert!(tables.contains(&"kernel_killed_generations".to_string()));
    assert!(tables.contains(&"kernel_sessions".to_string()));

    let triggers: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='trigger'
         AND name IN ('kernel_key_generations_guarded_delete',
                      'kernel_key_generations_no_delete',
                      'kernel_key_generations_no_update',
                      'kernel_sessions_destroy_only',
                      'kernel_sessions_no_delete')",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert!(triggers.contains(&"kernel_key_generations_guarded_delete".to_string()));
    assert!(!triggers.contains(&"kernel_key_generations_no_delete".to_string()));
    assert!(triggers.contains(&"kernel_key_generations_no_update".to_string()));
    assert!(triggers.contains(&"kernel_sessions_destroy_only".to_string()));
    assert!(triggers.contains(&"kernel_sessions_no_delete".to_string()));
}

#[tokio::test]
async fn generation_delete_without_permit_is_rejected() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    record_generation(&db, &ws, "gen-a", "issuer").await;

    // The permit table exists but is empty: the guarded trigger must abort
    // with the permit message.
    let err = sqlx::query("DELETE FROM kernel_key_generations WHERE workspace_id=? AND key_id=?")
        .bind(ws.to_string())
        .bind("gen-a")
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(
        db_err_message(err).contains("purge permit"),
        "delete without permit must name the permit"
    );
    assert!(has_generation(&db, &ws, "gen-a").await);

    // The immutability trigger still rejects key updates.
    let err = sqlx::query(
        "UPDATE kernel_key_generations SET verifying_key_hex=? WHERE workspace_id=? AND key_id=?",
    )
    .bind(vk_hex(2))
    .bind(ws.to_string())
    .bind("gen-a")
    .execute(db.pool())
    .await
    .unwrap_err();
    assert!(db_err_message(err).contains("immutable"));
}

#[tokio::test]
async fn purge_with_no_live_refs_deletes_row() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    record_generation(&db, &ws, "gen-orphan", "issuer").await;

    let outcome = db
        .purge_key_generation(&ws, "gen-orphan", 500_000, &[])
        .await
        .unwrap();
    assert_eq!(outcome, PurgeOutcome::Purged);
    assert!(!has_generation(&db, &ws, "gen-orphan").await);
}

#[tokio::test]
async fn purge_refused_while_live_lease_references_generation() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let doc = mint_root(&fx, "lease-live", "nonce-live", 100, 1_000_000);
    db.insert_kernel_lease(&ws, &doc).await.unwrap();
    record_generation(&db, &ws, &doc.issuer_key_id, "issuer").await;

    let outcome = db
        .purge_key_generation(&ws, &doc.issuer_key_id, 500_000, &[])
        .await
        .unwrap();
    assert_eq!(outcome, PurgeOutcome::StillReferenced);
    assert!(has_generation(&db, &ws, &doc.issuer_key_id).await);
}

#[tokio::test]
async fn purge_unknown_key_is_not_found() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let outcome = db
        .purge_key_generation(&ws, "gen-missing", 500_000, &[])
        .await
        .unwrap();
    assert_eq!(outcome, PurgeOutcome::NotFound);
}

#[tokio::test]
async fn purge_permit_does_not_leak_onto_pooled_connection() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    record_generation(&db, &ws, "gen-purged", "issuer").await;
    record_generation(&db, &ws, "gen-kept", "issuer").await;

    assert_eq!(
        db.purge_key_generation(&ws, "gen-purged", 500_000, &[])
            .await
            .unwrap(),
        PurgeOutcome::Purged
    );
    // The purge connection returned to the pool; a fresh direct DELETE of a
    // different row must still be rejected — the permit must not leak.
    let err = sqlx::query("DELETE FROM kernel_key_generations WHERE workspace_id=? AND key_id=?")
        .bind(ws.to_string())
        .bind("gen-kept")
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(db_err_message(err).contains("purge permit"));
    assert!(has_generation(&db, &ws, "gen-kept").await);
    // And no permit row survives the purge: the table is empty.
    let permits: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _kernel_key_purge_permit")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(permits, 0);
}

#[tokio::test]
async fn purge_host_generation_with_retained_checkpoints_refuses() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    record_generation(&db, &ws, "host-gen-x", "host").await;

    // Anchor a checkpoint to a real audit event.
    let e0 = db
        .append_kernel_audit_event(
            &ws,
            &KernelAuditAppend {
                actor: "kernel",
                kind: AuditEventKind::PolicyAllowed,
                session_id: "ed25519:test-session",
                action_digest: &format!("{:064x}", 7),
                decision: Some("allow"),
                timestamp_ms: 1_000,
                details: json!({}),
            },
        )
        .await
        .unwrap();
    let link = AuditLink {
        key_id: "host-gen-x".to_string(),
        through_seq: e0.sequence,
        chain_hash: e0.hash.clone(),
        signature: "ab".repeat(64),
    };
    db.checkpoint_kernel_audit(&ws, &link, 3_000).await.unwrap();

    assert!(
        db.host_generation_has_checkpoints(&ws, "host-gen-x")
            .await
            .unwrap()
    );
    assert!(
        !db.host_generation_has_checkpoints(&ws, "host-gen-unreferenced")
            .await
            .unwrap()
    );

    // Any checkpoint referencing the host generation -> refuse, whatever
    // its age. Purging would make the immutable checkpoint unverifiable
    // (verify_kernel_audit fails closed on an unknown host key).
    let err = db
        .purge_key_generation(&ws, "host-gen-x", 10_000_000, &[])
        .await
        .unwrap_err();
    assert!(db_err_message(err).contains("retained checkpoints"));
    assert!(has_generation(&db, &ws, "host-gen-x").await);

    // A host generation with no checkpoints at all purges normally.
    record_generation(&db, &ws, "host-gen-unreferenced", "host").await;
    let outcome = db
        .purge_key_generation(&ws, "host-gen-unreferenced", 10_000_000, &[])
        .await
        .unwrap();
    assert_eq!(outcome, PurgeOutcome::Purged);
    assert!(!has_generation(&db, &ws, "host-gen-unreferenced").await);
}

#[tokio::test]
async fn sessions_insert_destroy_and_trigger_guards() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;

    db.insert_kernel_session(&ws, "ed25519:sess-a", None, &vk_hex(11), 1_000)
        .await
        .unwrap();
    let row = db
        .kernel_session(&ws, "ed25519:sess-a")
        .await
        .unwrap()
        .unwrap();
    assert!(row.active);
    assert_eq!(row.parent_subject, None);
    assert_eq!(row.verifying_key_hex, vk_hex(11));
    assert_eq!(row.created_at_ms, 1_000);
    assert_eq!(row.destroyed_at_ms, None);

    // Destroy transition works.
    assert!(
        db.destroy_kernel_session(&ws, "ed25519:sess-a", 2_000)
            .await
            .unwrap()
    );
    let row = db
        .kernel_session(&ws, "ed25519:sess-a")
        .await
        .unwrap()
        .unwrap();
    assert!(!row.active);
    assert_eq!(row.destroyed_at_ms, Some(2_000));

    // Second destroy is a no-op, not an error.
    assert!(
        !db.destroy_kernel_session(&ws, "ed25519:sess-a", 3_000)
            .await
            .unwrap()
    );

    // Resurrecting is rejected by the trigger.
    let err = sqlx::query("UPDATE kernel_sessions SET active=1 WHERE workspace_id=? AND subject=?")
        .bind(ws.to_string())
        .bind("ed25519:sess-a")
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(db_err_message(err).contains("destroy transition"));

    // Swapping the verifying key is rejected.
    let err = sqlx::query(
        "UPDATE kernel_sessions SET verifying_key_hex=? WHERE workspace_id=? AND subject=?",
    )
    .bind(vk_hex(12))
    .bind(ws.to_string())
    .bind("ed25519:sess-a")
    .execute(db.pool())
    .await
    .unwrap_err();
    assert!(db_err_message(err).contains("destroy transition"));

    // Rows are never deletable.
    let err = sqlx::query("DELETE FROM kernel_sessions WHERE workspace_id=? AND subject=?")
        .bind(ws.to_string())
        .bind("ed25519:sess-a")
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(db_err_message(err).contains("append-only"));
}

#[tokio::test]
async fn expire_kernel_sessions_destroys_only_old_sessions() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    db.insert_kernel_session(&ws, "ed25519:old", None, &vk_hex(21), 0)
        .await
        .unwrap();
    db.insert_kernel_session(&ws, "ed25519:young", None, &vk_hex(22), 900_000)
        .await
        .unwrap();

    let destroyed = db
        .expire_kernel_sessions(&ws, 100_000, 999_999)
        .await
        .unwrap();
    assert_eq!(destroyed, vec!["ed25519:old".to_string()]);

    let old = db
        .kernel_session(&ws, "ed25519:old")
        .await
        .unwrap()
        .unwrap();
    assert!(!old.active);
    assert_eq!(old.destroyed_at_ms, Some(999_999));
    let young = db
        .kernel_session(&ws, "ed25519:young")
        .await
        .unwrap()
        .unwrap();
    assert!(young.active);
    assert_eq!(young.destroyed_at_ms, None);

    // Only the young session hydrates as active.
    let active = db.active_kernel_sessions(&ws).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].subject, "ed25519:young");
}

#[tokio::test]
async fn expire_kernel_sessions_destroys_descendant_subtree() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    // Parent is TTL-expired; child was created recently and grandchild
    // even later — all must go, or the hydration pass would fail the
    // open on the dangling child.
    db.insert_kernel_session(&ws, "ed25519:old-parent", None, &vk_hex(31), 0)
        .await
        .unwrap();
    db.insert_kernel_session(
        &ws,
        "ed25519:young-child",
        Some("ed25519:old-parent"),
        &vk_hex(32),
        900_000,
    )
    .await
    .unwrap();
    db.insert_kernel_session(
        &ws,
        "ed25519:young-grandchild",
        Some("ed25519:young-child"),
        &vk_hex(33),
        950_000,
    )
    .await
    .unwrap();
    // An unrelated young session must survive.
    db.insert_kernel_session(&ws, "ed25519:other", None, &vk_hex(34), 900_000)
        .await
        .unwrap();

    let mut destroyed = db
        .expire_kernel_sessions(&ws, 100_000, 999_999)
        .await
        .unwrap();
    destroyed.sort();
    assert_eq!(
        destroyed,
        vec![
            "ed25519:old-parent".to_string(),
            "ed25519:young-child".to_string(),
            "ed25519:young-grandchild".to_string(),
        ]
    );

    for subject in [
        "ed25519:old-parent",
        "ed25519:young-child",
        "ed25519:young-grandchild",
    ] {
        let row = db.kernel_session(&ws, subject).await.unwrap().unwrap();
        assert!(!row.active, "{subject} must be destroyed");
        assert_eq!(row.destroyed_at_ms, Some(999_999));
    }
    let other = db
        .kernel_session(&ws, "ed25519:other")
        .await
        .unwrap()
        .unwrap();
    assert!(other.active);

    // Only the unrelated session hydrates as active.
    let active = db.active_kernel_sessions(&ws).await.unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].subject, "ed25519:other");
}

#[tokio::test]
async fn destroy_sessions_and_revoke_is_atomic() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    let doc = mint_root(&fx, "lease-term", "nonce-term", 100, 1_000_000);
    db.insert_kernel_lease(&ws, &doc).await.unwrap();
    db.insert_kernel_session(&ws, "ed25519:term-a", None, &vk_hex(31), 100)
        .await
        .unwrap();
    db.insert_kernel_session(
        &ws,
        "ed25519:term-b",
        Some("ed25519:term-a"),
        &vk_hex(32),
        100,
    )
    .await
    .unwrap();

    db.destroy_sessions_and_revoke(
        &ws,
        &["ed25519:term-a".to_string(), "ed25519:term-b".to_string()],
        &["lease-term".to_string()],
        5_000,
        "session terminated",
    )
    .await
    .unwrap();

    for subject in ["ed25519:term-a", "ed25519:term-b"] {
        let row = db.kernel_session(&ws, subject).await.unwrap().unwrap();
        assert!(!row.active, "{subject} must be destroyed");
        assert_eq!(row.destroyed_at_ms, Some(5_000));
    }
    assert!(db.is_kernel_revoked(&ws, "lease-term").await.unwrap());
    // Revocation reason is recorded.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_revocations WHERE workspace_id=? AND reason='session terminated'",
    )
    .bind(ws.to_string())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn expire_kernel_sessions_and_revoke_is_atomic() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    // Lease for the TTL-expired subject (mint_root uses
    // "ed25519:parent-session" as the subject).
    let doc = mint_root(&fx, "lease-exp", "nonce-exp", 100, 1_000_000);
    db.insert_kernel_lease(&ws, &doc).await.unwrap();
    // Old session (TTL-expired) with a young child: the whole subtree
    // must go, and every lease in it must be revoked in the same
    // transaction.
    db.insert_kernel_session(&ws, "ed25519:parent-session", None, &vk_hex(41), 0)
        .await
        .unwrap();
    db.insert_kernel_session(
        &ws,
        "ed25519:young-child",
        Some("ed25519:parent-session"),
        &vk_hex(42),
        900_000,
    )
    .await
    .unwrap();
    // An unrelated young session must survive.
    db.insert_kernel_session(&ws, "ed25519:other", None, &vk_hex(43), 900_000)
        .await
        .unwrap();

    let (mut destroyed, revoked) = db
        .expire_kernel_sessions_and_revoke(&ws, 100_000, 999_999, "session TTL expired")
        .await
        .unwrap();
    destroyed.sort();
    assert_eq!(
        destroyed,
        vec![
            "ed25519:parent-session".to_string(),
            "ed25519:young-child".to_string(),
        ]
    );
    assert_eq!(revoked, vec!["lease-exp".to_string()]);

    for subject in ["ed25519:parent-session", "ed25519:young-child"] {
        let row = db.kernel_session(&ws, subject).await.unwrap().unwrap();
        assert!(!row.active, "{subject} must be destroyed");
        assert_eq!(row.destroyed_at_ms, Some(999_999));
    }
    let other = db
        .kernel_session(&ws, "ed25519:other")
        .await
        .unwrap()
        .unwrap();
    assert!(other.active);
    assert!(db.is_kernel_revoked(&ws, "lease-exp").await.unwrap());
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_revocations WHERE workspace_id=? AND reason='session TTL expired'",
    )
    .bind(ws.to_string())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn revoke_leases_for_inactive_sessions_repairs_crash_residue() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    // Simulate the pre-atomicity crash window: the session destroy
    // transition committed, but the lease revocation never did.
    let doc = mint_root(&fx, "lease-residue", "nonce-residue", 100, 1_000_000);
    db.insert_kernel_lease(&ws, &doc).await.unwrap();
    db.insert_kernel_session(&ws, "ed25519:parent-session", None, &vk_hex(51), 100)
        .await
        .unwrap();
    assert!(
        db.destroy_kernel_session(&ws, "ed25519:parent-session", 5_000)
            .await
            .unwrap()
    );
    assert!(!db.is_kernel_revoked(&ws, "lease-residue").await.unwrap());

    // A lease for a live session must NOT be touched by the repair.
    let mut live_doc = mint_root(&fx, "lease-live", "nonce-live", 100, 1_000_000);
    live_doc.subject = "ed25519:live-session".to_string();
    db.insert_kernel_lease(&ws, &live_doc).await.unwrap();
    db.insert_kernel_session(&ws, "ed25519:live-session", None, &vk_hex(52), 100)
        .await
        .unwrap();

    let repaired = db
        .revoke_leases_for_inactive_sessions(&ws, 999_999, "boot repair")
        .await
        .unwrap();
    assert_eq!(repaired, vec!["lease-residue".to_string()]);
    assert!(db.is_kernel_revoked(&ws, "lease-residue").await.unwrap());
    assert!(!db.is_kernel_revoked(&ws, "lease-live").await.unwrap());
    // Idempotent: a second pass repairs nothing.
    let repaired = db
        .revoke_leases_for_inactive_sessions(&ws, 999_999, "boot repair")
        .await
        .unwrap();
    assert!(repaired.is_empty());
}

#[tokio::test]
async fn kill_list_is_idempotent_and_append_only() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;

    assert!(
        db.kill_key_generation(
            &ws,
            "gen-evil",
            "issuer",
            9_000,
            "suspected compromise",
            "test:operator"
        )
        .await
        .unwrap()
    );
    // Second kill is a no-op.
    assert!(
        !db.kill_key_generation(&ws, "gen-evil", "issuer", 9_001, "again", "test:operator")
            .await
            .unwrap()
    );
    let ids = db.killed_key_generation_ids(&ws).await.unwrap();
    assert!(ids.contains("gen-evil"));
    assert_eq!(ids.len(), 1);

    // Invalid role fails in Rust before the insert.
    assert!(
        db.kill_key_generation(&ws, "gen-x", "root", 9_000, "bad role", "test:operator")
            .await
            .is_err()
    );

    // Append-only: no updates, no deletes.
    let err = sqlx::query("UPDATE kernel_killed_generations SET reason='x' WHERE workspace_id=?")
        .bind(ws.to_string())
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(db_err_message(err).contains("append-only"));
    let err = sqlx::query("DELETE FROM kernel_killed_generations WHERE workspace_id=?")
        .bind(ws.to_string())
        .execute(db.pool())
        .await
        .unwrap_err();
    assert!(db_err_message(err).contains("append-only"));
}

#[tokio::test]
async fn live_lease_refs_counts_only_live_matching_leases() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let fx = fixture();
    // Live at now=500_000: unexpired, unrevoked.
    let live = mint_root(&fx, "lease-a", "nonce-a", 100, 1_000_000);
    // Expired at now=500_000 (minted valid, short-lived).
    let expired = mint_root(&fx, "lease-b", "nonce-b", 100, 200);
    // Revoked before the check.
    let revoked = mint_root(&fx, "lease-c", "nonce-c", 100, 1_000_000);
    for doc in [&live, &expired, &revoked] {
        db.insert_kernel_lease(&ws, doc).await.unwrap();
    }
    db.record_kernel_revocation(&ws, "lease-c", 300, "test revoke")
        .await
        .unwrap();
    let key_id = live.issuer_key_id.clone();
    record_generation(&db, &ws, &key_id, "issuer").await;

    assert_eq!(
        db.live_lease_refs_to_generation(&ws, &key_id, 500_000)
            .await
            .unwrap(),
        1
    );
    // A key id nothing references has zero live refs.
    assert_eq!(
        db.live_lease_refs_to_generation(&ws, "gen-nobody", 500_000)
            .await
            .unwrap(),
        0
    );

    // The re-validation self-check set: only the live lease.
    let live_docs = db.kernel_live_leases(&ws, 500_000).await.unwrap();
    assert_eq!(live_docs.len(), 1);
    assert_eq!(live_docs[0].lease_id, "lease-a");

    // Purge is refused while that one live lease exists, then allowed once
    // the clock passes its expiry.
    assert_eq!(
        db.purge_key_generation(&ws, &key_id, 500_000, &[])
            .await
            .unwrap(),
        PurgeOutcome::StillReferenced
    );
    assert_eq!(
        db.purge_key_generation(&ws, &key_id, 1_000_001, &[])
            .await
            .unwrap(),
        PurgeOutcome::Purged
    );
}

#[tokio::test]
async fn purge_refuses_current_generation() {
    // The store itself refuses to purge a live generation, even with no
    // live lease references: the kernel's purge pass already excludes
    // them, but no caller may orphan the signing key in active use.
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    record_generation(&db, &ws, "gen-current", "issuer").await;

    let outcome = db
        .purge_key_generation(&ws, "gen-current", 500_000, &["gen-current"])
        .await
        .unwrap();
    assert_eq!(outcome, PurgeOutcome::CurrentGeneration);
    assert!(has_generation(&db, &ws, "gen-current").await);

    // A retired generation with no refs still purges.
    record_generation(&db, &ws, "gen-retired", "issuer").await;
    let outcome = db
        .purge_key_generation(&ws, "gen-retired", 500_000, &["gen-current"])
        .await
        .unwrap();
    assert_eq!(outcome, PurgeOutcome::Purged);
    assert!(!has_generation(&db, &ws, "gen-retired").await);
}

#[tokio::test]
async fn time_high_water_roundtrip_and_monotonic() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;

    assert_eq!(db.time_high_water(&ws).await.unwrap(), 0);

    db.record_time_high_water(&ws, 1_000).await.unwrap();
    assert_eq!(db.time_high_water(&ws).await.unwrap(), 1_000);

    // A smaller value never lowers the mark.
    db.record_time_high_water(&ws, 500).await.unwrap();
    assert_eq!(db.time_high_water(&ws).await.unwrap(), 1_000);

    db.record_time_high_water(&ws, 2_000).await.unwrap();
    assert_eq!(db.time_high_water(&ws).await.unwrap(), 2_000);
}

#[tokio::test]
async fn kill_with_audit_commits_both_atomically() {
    use lumen_db::lease::{KernelAuditAppend, KillGenerationRequest};
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    record_generation(&db, &ws, "gen-doomed", "issuer").await;

    let audit = KernelAuditAppend {
        actor: "kernel",
        kind: AuditEventKind::PolicyDenied,
        session_id: "ed25519:test",
        action_digest: &format!("{:064x}", 42),
        decision: None,
        timestamp_ms: 9_000,
        details: json!({"host_kind": "kernel.key_generation.killed"}),
    };
    let (killed, event) = db
        .kill_key_generation_with_audit(
            &ws,
            &KillGenerationRequest {
                key_id: "gen-doomed",
                role: "issuer",
                killed_at_ms: 9_000,
                reason: "suspected compromise",
                killed_by: "test:operator",
                audit: &audit,
            },
        )
        .await
        .unwrap();
    assert!(killed);
    let event = event.expect("audit event on kill");

    // The kill row carries the authorizing actor.
    let row: (String, String) = sqlx::query_as(
        "SELECT reason, killed_by FROM kernel_killed_generations
         WHERE workspace_id=? AND key_id='gen-doomed'",
    )
    .bind(ws.to_string())
    .fetch_one(db.pool())
    .await
    .unwrap();
    assert_eq!(row.0, "suspected compromise");
    assert_eq!(row.1, "test:operator");

    // The audit event is durable in the same unit.
    let events = db
        .kernel_audit_events(&ws, &lumen_db::lease::KernelAuditQuery::default())
        .await
        .unwrap();
    assert!(events.iter().any(|e| e.event_id == event.event_id));

    // Idempotent retry: no second row, no second audit event.
    let (killed_again, event_again) = db
        .kill_key_generation_with_audit(
            &ws,
            &KillGenerationRequest {
                key_id: "gen-doomed",
                role: "issuer",
                killed_at_ms: 9_001,
                reason: "again",
                killed_by: "test:operator",
                audit: &audit,
            },
        )
        .await
        .unwrap();
    assert!(!killed_again);
    assert!(event_again.is_none());
}

#[tokio::test]
async fn session_lifecycle_checks_reject_bad_inserts() {
    let db = test_db().await;
    let ws = test_workspace(&db).await;
    let ws_s = ws.to_string();

    // A live row must not carry a destroy timestamp.
    let err = sqlx::query(
        "INSERT INTO kernel_sessions(workspace_id,subject,parent_subject,
         verifying_key_hex,active,created_at_ms,destroyed_at_ms)
         VALUES(?,?,NULL,?,1,0,100)",
    )
    .bind(&ws_s)
    .bind("ed25519:bad-live")
    .bind(vk_hex(3))
    .execute(db.pool())
    .await
    .unwrap_err();
    assert!(db_err_message(err).contains("CHECK constraint failed"));

    // A destroyed row must carry a destroy timestamp.
    let err = sqlx::query(
        "INSERT INTO kernel_sessions(workspace_id,subject,parent_subject,
         verifying_key_hex,active,created_at_ms,destroyed_at_ms)
         VALUES(?,?,NULL,?,0,0,NULL)",
    )
    .bind(&ws_s)
    .bind("ed25519:bad-dead")
    .bind(vk_hex(4))
    .execute(db.pool())
    .await
    .unwrap_err();
    assert!(db_err_message(err).contains("CHECK constraint failed"));

    // The destroy timestamp may not precede creation.
    let err = sqlx::query(
        "INSERT INTO kernel_sessions(workspace_id,subject,parent_subject,
         verifying_key_hex,active,created_at_ms,destroyed_at_ms)
         VALUES(?,?,NULL,?,0,100,50)",
    )
    .bind(&ws_s)
    .bind("ed25519:bad-time")
    .bind(vk_hex(5))
    .execute(db.pool())
    .await
    .unwrap_err();
    assert!(db_err_message(err).contains("CHECK constraint failed"));

    // A non-null parent must name a recorded session in the workspace.
    db.insert_kernel_session(&ws, "ed25519:real-parent", None, &vk_hex(6), 0)
        .await
        .unwrap();
    let err = sqlx::query(
        "INSERT INTO kernel_sessions(workspace_id,subject,parent_subject,
         verifying_key_hex,active,created_at_ms,destroyed_at_ms)
         VALUES(?,?,?, ?,1,0,NULL)",
    )
    .bind(&ws_s)
    .bind("ed25519:orphan")
    .bind("ed25519:no-such-parent")
    .bind(vk_hex(7))
    .execute(db.pool())
    .await
    .unwrap_err();
    assert!(db_err_message(err).contains("FOREIGN KEY constraint failed"));

    // The well-formed rows still insert.
    db.insert_kernel_session(
        &ws,
        "ed25519:good-child",
        Some("ed25519:real-parent"),
        &vk_hex(8),
        0,
    )
    .await
    .unwrap();
}
