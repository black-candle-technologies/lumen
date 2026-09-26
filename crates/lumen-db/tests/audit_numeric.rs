//! SQLite integers must never alias a signed audit version or sequence.
use lumen_core::{
    identity::WorkspaceId,
    kernel_audit::AuditLink,
    lease::KernelKeys,
    pi_boundary::{AuditActor, AuditEvent, AuditEventKind},
};
use lumen_db::{
    Database,
    lease::{KernelAuditAppend, KernelAuditQuery},
};
use sqlx::{migrate::Migrator, sqlite::SqlitePoolOptions};
use tempfile::TempDir;

static MIGRATIONS: Migrator = sqlx::migrate!("./migrations");

fn v30() -> Migrator {
    Migrator::with_migrations(
        MIGRATIONS
            .iter()
            .filter(|m| m.version <= 30)
            .cloned()
            .collect(),
    )
}

// The signature is over a legitimate v1 event. The legacy schema allows an
// unrelated positive i64 version in the stored row; the reader must not repair
// it through a narrowing cast before verifying the otherwise valid signature.
async fn seed(pool: &sqlx::SqlitePool, version: i64) -> (WorkspaceId, KernelKeys) {
    let ws = WorkspaceId::new();
    sqlx::query(
        "INSERT INTO workspaces(id,name,created_at) VALUES(?,'audit integer regression',0)",
    )
    .bind(ws.to_string())
    .execute(pool)
    .await
    .unwrap();
    let mut event = AuditEvent {
        version: 1,
        event_id: uuid::Uuid::new_v4(),
        sequence: 0,
        timestamp_ms: 0,
        actor: AuditActor::Kernel,
        kind: AuditEventKind::PolicyDenied,
        session_id: "fixture-session".into(),
        action_digest: "none".into(),
        decision: Some("deny".into()),
        detail: "{}".into(),
        prev_hash: "0".repeat(64),
        hash: String::new(),
    };
    event.hash = event.compute_hash(&event.prev_hash).unwrap();
    sqlx::query("INSERT INTO kernel_audit_events(workspace_id,seq,version,event_id,kind,actor,session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms) VALUES(?,0,?,?,'policy_denied','kernel',?,'none','deny','{}',?,?,0)")
        .bind(ws.to_string()).bind(version).bind(event.event_id.to_string())
        .bind(&event.session_id).bind(&event.prev_hash).bind(&event.hash)
        .execute(pool).await.unwrap();
    let keys = KernelKeys::generate();
    let mut link = AuditLink {
        key_id: String::new(),
        through_seq: 0,
        chain_hash: event.hash,
        signature: String::new(),
    };
    link.sign(&keys);
    sqlx::query("INSERT INTO kernel_audit_checkpoints(workspace_id,seq,hash,signature,key_id,created_at) VALUES(?,0,?,?,?,0)")
        .bind(ws.to_string()).bind(link.chain_hash).bind(link.signature).bind(link.key_id)
        .execute(pool).await.unwrap();
    (ws, keys)
}

#[tokio::test]
async fn persisted_versions_cannot_wrap_into_a_signed_v1_event() {
    for version in [2, 1 + (1_i64 << 32), 1 + (2_i64 << 32), i64::MAX] {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("audit.sqlite3");
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(
                sqlx::sqlite::SqliteConnectOptions::new()
                    .filename(&path)
                    .create_if_missing(true),
            )
            .await
            .unwrap();
        v30().run(&pool).await.unwrap();
        let (ws, keys) = seed(&pool, version).await;
        pool.close().await;
        let db = Database::connect(&path).await.unwrap();
        let readable = db
            .kernel_audit_events(&ws, &KernelAuditQuery::default())
            .await
            .is_ok();
        let verified = db
            .verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
            .await
            .is_ok();
        assert!(
            !readable && !verified,
            "stored version {version} must not alias v1: readable={readable}, verified={verified}"
        );
        assert!(
            db.append_kernel_audit_event(&ws, &append_params())
                .await
                .is_err(),
            "invalid historical tip must not be extended"
        );
        let stored: i64 = sqlx::query_scalar("SELECT version FROM kernel_audit_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(
            stored, version,
            "invalid historical bytes must remain evidence"
        );
    }
}

fn append_params() -> KernelAuditAppend<'static> {
    KernelAuditAppend {
        actor: "kernel",
        kind: AuditEventKind::TransportRejected,
        session_id: "unidentified",
        action_digest: "none",
        decision: None,
        timestamp_ms: 1,
        details: serde_json::json!({"reason":"fixture"}),
    }
}

async fn evidence(pool: &sqlx::SqlitePool) -> (Vec<String>, Vec<String>) {
    let events = sqlx::query_scalar("SELECT json_array(seq,version,event_id,kind,actor,session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms) FROM kernel_audit_events ORDER BY seq")
        .fetch_all(pool).await.unwrap();
    let checkpoints = sqlx::query_scalar("SELECT json_array(seq,hash,signature,key_id,created_at) FROM kernel_audit_checkpoints ORDER BY seq")
        .fetch_all(pool).await.unwrap();
    (events, checkpoints)
}

#[tokio::test]
async fn migration_preserves_signed_v1_bytes_and_rejects_older_binary() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.sqlite3");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true),
        )
        .await
        .unwrap();
    v30().run(&pool).await.unwrap();
    let (ws, keys) = seed(&pool, 1).await;
    let before = evidence(&pool).await;
    // Fail after metadata insertion: DDL failure must roll it back as well.
    sqlx::query("CREATE TRIGGER kernel_audit_events_version_guard BEFORE INSERT ON kernel_audit_events BEGIN SELECT 1; END")
        .execute(&pool).await.unwrap();
    assert!(Database::connect(&path).await.is_err());
    let metadata: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_contract_versions WHERE contract='audit_event'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let markers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version=31")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((metadata, markers), (0, 0));
    assert_eq!(evidence(&pool).await, before);
    sqlx::query("DROP TRIGGER kernel_audit_events_version_guard")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let db = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(db.pool()).await, before);
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
    assert!(matches!(
        v30().run(db.pool()).await,
        Err(sqlx::migrate::MigrateError::VersionMissing(31))
    ));
    db.close().await;
    let db = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(db.pool()).await, before);
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
    for version in [0, 2, 1 + (1_i64 << 32), i64::MAX] {
        let result = sqlx::query("INSERT INTO kernel_audit_events(workspace_id,seq,version,event_id,kind,actor,session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms) SELECT workspace_id,seq+1,?,? ,kind,actor,session_id,action_digest,decision,detail,hash,hash,timestamp_ms FROM kernel_audit_events WHERE seq=0")
            .bind(version).bind(uuid::Uuid::new_v4().to_string()).execute(db.pool()).await;
        assert!(
            result.is_err(),
            "new unknown version {version} must fail at insert"
        );
    }
    assert_eq!(evidence(db.pool()).await, before);
    assert_eq!(
        db.append_kernel_audit_event(&ws, &append_params())
            .await
            .unwrap()
            .sequence,
        1
    );
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn unsigned_query_bounds_and_limits_cannot_become_negative() {
    let db = Database::connect_in_memory().await.unwrap();
    let (ws, keys) = seed(db.pool(), 1).await;
    for value in [i64::MAX as u64 + 1, u64::MAX] {
        for query in [
            KernelAuditQuery {
                min_seq: Some(value),
                ..Default::default()
            },
            KernelAuditQuery {
                max_seq: Some(value),
                ..Default::default()
            },
            KernelAuditQuery {
                limit: Some(value),
                ..Default::default()
            },
        ] {
            assert!(db.kernel_audit_events(&ws, &query).await.is_err());
        }
        let mut link = AuditLink {
            key_id: String::new(),
            through_seq: value,
            chain_hash: "0".repeat(64),
            signature: String::new(),
        };
        link.sign(&keys);
        assert!(db.checkpoint_kernel_audit(&ws, &link, 1).await.is_err());
    }
    let all = db
        .kernel_audit_events(
            &ws,
            &KernelAuditQuery {
                min_seq: Some(0),
                max_seq: Some(i64::MAX as u64),
                limit: Some(i64::MAX as u64),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(all.len(), 1);
    assert!(
        db.kernel_audit_events(
            &ws,
            &KernelAuditQuery {
                limit: Some(0),
                ..Default::default()
            }
        )
        .await
        .unwrap()
        .is_empty()
    );
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn append_refuses_a_corrupt_tip_before_extending_it() {
    let db = Database::connect_in_memory().await.unwrap();
    let (ws, _) = seed(db.pool(), 1).await;
    // Simulate storage corruption; normal SQL clients cannot mutate history.
    sqlx::query("DROP TRIGGER kernel_audit_events_no_update")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE kernel_audit_events SET hash=?")
        .bind("f".repeat(64))
        .execute(db.pool())
        .await
        .unwrap();
    let before = evidence(db.pool()).await;
    assert!(
        db.append_kernel_audit_event(&ws, &append_params())
            .await
            .is_err()
    );
    assert_eq!(evidence(db.pool()).await, before);
}

#[tokio::test]
async fn exhausted_sql_sequence_fails_without_overflow_or_write() {
    let db = Database::connect_in_memory().await.unwrap();
    let (ws, _) = seed(db.pool(), 1).await;
    let mut event = db
        .kernel_audit_events(&ws, &KernelAuditQuery::default())
        .await
        .unwrap()
        .remove(0);
    event.sequence = i64::MAX as u64;
    event.event_id = uuid::Uuid::new_v4();
    event.prev_hash = event.hash.clone();
    event.hash = event.compute_hash(&event.prev_hash).unwrap();
    // Fault injection creates a representable terminal sequence. Normal
    // appends cannot reach it except after exhausting all prior sequences.
    sqlx::query("DROP TRIGGER kernel_audit_events_seq_gapless")
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO kernel_audit_events(workspace_id,seq,version,event_id,kind,actor,session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms) VALUES(?,?,1,?,'policy_denied','kernel',?,'none','deny','{}',?,?,0)")
        .bind(ws.to_string()).bind(i64::MAX).bind(event.event_id.to_string())
        .bind(event.session_id).bind(event.prev_hash).bind(event.hash)
        .execute(db.pool()).await.unwrap();
    let before = evidence(db.pool()).await;
    let error = db
        .append_kernel_audit_event(&ws, &append_params())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("audit sequence exhausted"));
    assert_eq!(evidence(db.pool()).await, before);
}
