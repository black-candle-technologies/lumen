//! Forward-only contract migration preserves signed historical evidence.
use lumen_core::{
    identity::WorkspaceId,
    kernel_audit::AuditLink,
    lease::{KernelKeys, LeaseDocument},
    pi_boundary::{AuditActor, AuditEvent, AuditEventKind},
};
use lumen_db::Database;
use serde_json::{Value, json};
use sqlx::{
    SqlitePool,
    migrate::{MigrateError, Migrator},
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use std::path::Path;
use tempfile::TempDir;
use uuid::Uuid;

static CURRENT: Migrator = sqlx::migrate!("./migrations");
fn previous() -> Migrator {
    Migrator::with_migrations(
        CURRENT
            .iter()
            .filter(|m| m.version <= 28)
            .cloned()
            .collect(),
    )
}
async fn old_database(path: &Path) -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap();
    previous().run(&pool).await.unwrap();
    pool
}
async fn seed(pool: &SqlitePool, ws: &WorkspaceId) -> KernelKeys {
    sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,?,0)")
        .bind(ws.to_string())
        .bind("contract migration test")
        .execute(pool)
        .await
        .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../lumen-core/tests/fixtures/lease.legacy-v2.json"
    ))
    .unwrap();
    let doc = &fixture["document"];
    sqlx::query("INSERT INTO kernel_leases(lease_id,workspace_id,parent_id,subject,issuer_key_id,issued_at_ms,protocol_version,scope_digest,scope_json,limits_json,depth,depth_limit,lease_nonce,signature,document_digest,created_at,approved_action_digest) VALUES(?,?,NULL,?,?,10,2,?,?,?,0,3,?,?,?,10,NULL)")
        .bind("fixture-lease").bind(ws.to_string()).bind("fixture-session").bind("fixture-issuer")
        .bind(fixture["scope_digest_v1"].as_str().unwrap()).bind(doc["scope"].to_string()).bind(doc["limits"].to_string())
        .bind("fixture-nonce").bind(doc["signature"].as_str().unwrap()).bind(fixture["signing_digest"].as_str().unwrap())
        .execute(pool).await.unwrap();
    sqlx::query("INSERT INTO kernel_budget_accounts(lease_id,workspace_id,caps_json,reserved_out_json,consumed_json,updated_at) VALUES('fixture-lease',?, '{\"executions\":2,\"tokens\":0}', '{\"tokens\":0}', '{\"executions\":1,\"tokens\":0}',10)")
        .bind(ws.to_string()).execute(pool).await.unwrap();
    let mut event = AuditEvent {
        version: 1,
        event_id: Uuid::new_v4(),
        sequence: 0,
        timestamp_ms: 10,
        actor: AuditActor::Kernel,
        kind: AuditEventKind::PolicyDenied,
        session_id: "legacy-session".into(),
        action_digest: "none".into(),
        decision: Some("deny".into()),
        detail: json!({"reason":"legacy fixture"}).to_string(),
        prev_hash: "0".repeat(64),
        hash: String::new(),
    };
    event.hash = event.compute_hash(&event.prev_hash).unwrap();
    sqlx::query("INSERT INTO kernel_audit_events(workspace_id,seq,version,event_id,kind,actor,session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms) VALUES(?,0,1,?,'policy_denied','kernel',?,'none','deny',?,?,?,10)")
        .bind(ws.to_string()).bind(event.event_id.to_string()).bind(&event.session_id).bind(&event.detail)
        .bind(&event.prev_hash).bind(&event.hash).execute(pool).await.unwrap();
    let keys = KernelKeys::generate();
    let mut link = AuditLink {
        key_id: String::new(),
        through_seq: 0,
        chain_hash: event.hash,
        signature: String::new(),
    };
    link.sign(&keys);
    sqlx::query("INSERT INTO kernel_audit_checkpoints(workspace_id,seq,hash,signature,key_id,created_at) VALUES(?,0,?,?,?,10)")
        .bind(ws.to_string()).bind(link.chain_hash).bind(link.signature).bind(link.key_id).execute(pool).await.unwrap();
    keys
}
async fn evidence(pool: &SqlitePool) -> Vec<String> {
    let mut values = Vec::new();
    for query in [
        "SELECT json_array(protocol_version,scope_digest,scope_json,limits_json,signature,document_digest) FROM kernel_leases ORDER BY lease_id",
        "SELECT json_array(seq,version,event_id,kind,actor,session_id,action_digest,decision,detail,prev_hash,hash,timestamp_ms) FROM kernel_audit_events ORDER BY seq",
        "SELECT json_array(seq,hash,signature,key_id,created_at) FROM kernel_audit_checkpoints ORDER BY seq",
        "SELECT json_array(lease_id,caps_json,reserved_out_json,consumed_json,updated_at) FROM kernel_budget_accounts ORDER BY lease_id",
    ] {
        values.extend(
            sqlx::query_scalar::<_, String>(query)
                .fetch_all(pool)
                .await
                .unwrap(),
        );
    }
    values
}

#[tokio::test]
async fn migration_preserves_legacy_evidence_and_refuses_old_authority_after_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("migration.sqlite3");
    let ws = WorkspaceId::from_uuid(Uuid::new_v4());
    let pool = old_database(&path).await;
    let keys = seed(&pool, &ws).await;
    let before = evidence(&pool).await;
    pool.close().await;
    let db = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(db.pool()).await, before);
    assert!(db.kernel_lease(&ws, "fixture-lease").await.is_err());
    db.verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
    let versions: Vec<(String, i64)> =
        sqlx::query_as("SELECT contract,version FROM kernel_contract_versions ORDER BY contract")
            .fetch_all(db.pool())
            .await
            .unwrap();
    assert_eq!(
        versions,
        vec![
            ("action_envelope".into(), 2),
            ("host_action_channel".into(), 2),
            ("kernel_wire".into(), 2),
            ("lease_document".into(), 3),
            ("policy_decision".into(), 3),
            ("resource_scope_digest".into(), 2)
        ]
    );
    assert!(matches!(
        previous().run(db.pool()).await,
        Err(MigrateError::VersionMissing(29))
    ));
    db.close().await;
    let reopened = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(reopened.pool()).await, before);
    assert!(reopened.kernel_lease(&ws, "fixture-lease").await.is_err());
    let states = reopened.kernel_budget_account_states(&ws).await.unwrap();
    assert_eq!(states.len(), 1);
    let (id, caps, held, consumed) = &states[0];
    assert_eq!(id, "fixture-lease");
    assert_eq!(
        serde_json::to_value(caps).unwrap(),
        json!({"executions":2,"tokens":0})
    );
    assert_eq!(serde_json::to_value(held).unwrap(), json!({"tokens":0}));
    assert_eq!(
        serde_json::to_value(consumed).unwrap(),
        json!({"executions":1,"tokens":0})
    );
    reopened
        .verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
    // New rows require the new version at both API and SQL boundaries.
    let fixture: Value = serde_json::from_str(include_str!(
        "../../lumen-core/tests/fixtures/lease.v3.json"
    ))
    .unwrap();
    let mut doc: LeaseDocument = serde_json::from_value(fixture["document"].clone()).unwrap();
    doc.lease_id = "new-lease".into();
    doc.lease_nonce = "new-nonce".into();
    let signer = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
    doc.sign(&signer).unwrap();
    reopened.insert_kernel_lease(&ws, &doc).await.unwrap();
    let restored = reopened
        .kernel_lease(&ws, "new-lease")
        .await
        .unwrap()
        .unwrap();
    restored.verify_signature(&signer.verifying_key()).unwrap();
    let mut legacy = doc.clone();
    legacy.protocol_version = 2;
    assert!(reopened.insert_kernel_lease(&ws, &legacy).await.is_err());
    assert!(sqlx::query("INSERT INTO kernel_leases SELECT 'legacy-copy',workspace_id,parent_id,subject,issuer_key_id,issued_at_ms,2,scope_digest,scope_json,limits_json,depth,depth_limit,'old-nonce',signature,document_digest,created_at,approved_action_digest FROM kernel_leases WHERE lease_id='new-lease'").execute(reopened.pool()).await.is_err());
}

#[tokio::test]
async fn action_contract_migration_is_atomic_and_legacy_evidence_survives_restart() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("action-contract.sqlite3");
    let ws = WorkspaceId::from_uuid(Uuid::new_v4());
    let pool = old_database(&path).await;
    let keys = seed(&pool, &ws).await;
    let v29 = Migrator::with_migrations(
        CURRENT
            .iter()
            .filter(|m| m.version <= 29)
            .cloned()
            .collect(),
    );
    v29.run(&pool).await.unwrap();
    let before = evidence(&pool).await;
    // Failure on the second inserted version row must roll back the first.
    sqlx::query("CREATE TRIGGER injected_contract_failure BEFORE INSERT ON kernel_contract_versions WHEN NEW.contract='kernel_wire' BEGIN SELECT RAISE(ABORT,'injected migration failure'); END")
        .execute(&pool).await.unwrap();
    assert!(Database::connect(&path).await.is_err());
    let action_rows: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM kernel_contract_versions WHERE contract='action_envelope'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version=30")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!((action_rows, applied), (0, 0));
    assert_eq!(evidence(&pool).await, before);
    sqlx::query("DROP TRIGGER injected_contract_failure")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let db = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(db.pool()).await, before);
    assert!(matches!(
        v29.run(db.pool()).await,
        Err(MigrateError::VersionMissing(30))
    ));
    db.close().await;
    let reopened = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(reopened.pool()).await, before);
    reopened
        .verify_kernel_audit(&ws, &keys.host_verifying(), &keys.host_key_id, 0)
        .await
        .unwrap();
}

#[tokio::test]
async fn failed_contract_migration_rolls_back_without_touching_evidence() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("failure.sqlite3");
    let ws = WorkspaceId::from_uuid(Uuid::new_v4());
    let pool = old_database(&path).await;
    let _keys = seed(&pool, &ws).await;
    let before = evidence(&pool).await;
    // Force failure at the final DDL statement, after version rows were
    // inserted. This exercises SQLite/SQLx's real migration transaction.
    sqlx::query("CREATE TRIGGER kernel_leases_current_contract BEFORE INSERT ON kernel_leases WHEN 0 BEGIN SELECT 1; END").execute(&pool).await.unwrap();
    assert!(Database::connect(&path).await.is_err());
    let table: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE name='kernel_contract_versions'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(table, 0);
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE version=29")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(applied, 0);
    assert_eq!(evidence(&pool).await, before);
    sqlx::query("DROP TRIGGER kernel_leases_current_contract")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    let retried = Database::connect(&path).await.unwrap();
    assert_eq!(evidence(retried.pool()).await, before);
}

#[tokio::test]
async fn persisted_depth_overflow_and_unknown_scope_are_refused() {
    let db = Database::connect_in_memory().await.unwrap();
    let ws = WorkspaceId::from_uuid(Uuid::new_v4());
    db.ensure_workspace(&ws, "strict persistence", 0)
        .await
        .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../lumen-core/tests/fixtures/lease.v3.json"
    ))
    .unwrap();
    let doc: LeaseDocument = serde_json::from_value(fixture["document"].clone()).unwrap();
    db.insert_kernel_lease(&ws, &doc).await.unwrap();
    for index in 0..2 {
        let id = format!("corrupt-{index}");
        // A typed decoder must reject these rows independently of later
        // signature verification. SQL structure is fixed; values are bound.
        sqlx::query("INSERT INTO kernel_leases SELECT ?,workspace_id,parent_id,subject,issuer_key_id,issued_at_ms,3,scope_digest,CASE WHEN ?=1 THEN json_set(scope_json,'$.future_authority',1) ELSE scope_json END,limits_json,CASE WHEN ?=0 THEN 4294967296 ELSE depth END,depth_limit,?,signature,document_digest,created_at,approved_action_digest FROM kernel_leases WHERE lease_id='fixture-lease'")
            .bind(&id).bind(index).bind(index).bind(&id).execute(db.pool()).await.unwrap();
        assert!(db.kernel_lease(&ws, &id).await.is_err());
    }
}
