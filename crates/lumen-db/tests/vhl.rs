//! Durable Phase 4 human-authority tests: migration 0023, the forward-only
//! approval state machine, append-only decisions, challenge lifecycle, and
//! the replay guards that reuse the 0022 nonce/one-shot tables.

use lumen_core::canonical::PathRights;
use lumen_core::identity::WorkspaceId;
use lumen_core::vhl::{
    ApprovalKind, ApprovalView, VhlApprovalRequest, VhlCourierMessage, VhlRequestState,
};
use lumen_db::Database;
use uuid::Uuid;

const NOW_MS: i64 = 1_780_000_000_000;

/// A workspace that actually exists in `workspaces`, satisfying the
/// VHL tables' foreign keys.
async fn test_workspace(db: &Database) -> WorkspaceId {
    let ws = WorkspaceId::new();
    sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,'vhl-test',0)")
        .bind(ws.to_string())
        .execute(db.pool())
        .await
        .expect("workspace insert");
    ws
}

fn test_request(nonce: &str) -> VhlApprovalRequest {
    VhlApprovalRequest {
        request_id: Uuid::new_v4().to_string(),
        action_digest: "a".repeat(64),
        input_hashes: vec!["sha256:input-1".to_string()],
        session_subject: "ed25519:test-session".to_string(),
        nonce: nonce.to_string(),
        created_at_ms: NOW_MS,
        expires_at_ms: NOW_MS + 300_000,
        view: ApprovalView {
            kind: ApprovalKind::OneShot,
            tool: "fs.read@1.0.0".to_string(),
            action_digest: "a".repeat(64),
            session_subject: "ed25519:test-session".to_string(),
            paths: vec!["/workspace/README.md".to_string()],
            path_rights: vec![PathRights::READ],
            destinations: vec![],
            secrets: vec![],
            effects: vec!["Read".to_string()],
            arguments_digest: "b".repeat(64),
            input_hashes: vec!["sha256:input-1".to_string()],
            budget_executions: 1,
            expires_at_ms: NOW_MS + 300_000,
            summary: "test approval".to_string(),
        },
        state: VhlRequestState::Requested,
    }
}

/// Mint and persist a real kernel lease so `lease_id` foreign keys resolve.
async fn insert_lease(db: &Database, ws: &WorkspaceId, lease_id: &str) {
    use lumen_core::budget::{Budget, BudgetDimension, BudgetLedger};
    use lumen_core::lease::{
        KernelKeys, LeaseLimits, RootLeaseParams, SessionRegistry, mint_root_lease,
    };
    use lumen_core::nonce::NonceStore;

    let keys = KernelKeys::generate();
    let mut sessions = SessionRegistry::new();
    sessions.register(
        "ed25519:parent-session".to_string(),
        None,
        keys.issuer_verifying(),
    );
    let ledger = BudgetLedger::new();
    let nonces = NonceStore::new();
    let lease = mint_root_lease(
        RootLeaseParams {
            lease_id: lease_id.to_string(),
            subject: "ed25519:parent-session".to_string(),
            scope: Default::default(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 1_000_000,
                budget: Budget::new().set(BudgetDimension::Executions, 1),
                max_executions: Some(1),
                single_use: true,
            },
            depth_limit: 1,
            lease_nonce: format!("{lease_id}-nonce"),
            issued_at_ms: 100,
        },
        &keys,
        &sessions,
        &ledger,
        &nonces,
        100,
    )
    .expect("root lease mints");
    db.insert_kernel_lease(ws, &lease)
        .await
        .expect("insert lease");
}

#[tokio::test]
async fn migration_0023_creates_vhl_tables() {
    let db = Database::connect_in_memory().await.expect("connect");
    for table in ["vhl_approval_requests", "vhl_decisions", "vhl_challenges"] {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?")
                .bind(table)
                .fetch_one(db.pool())
                .await
                .expect("query");
        assert_eq!(count, 1, "table {table} must exist");
    }
}

#[tokio::test]
async fn no_session_private_key_material_is_persisted() {
    // Schema-level guarantee: the VHL tables carry digests, hashes, and
    // public identities — never private keys.
    let db = Database::connect_in_memory().await.expect("connect");
    for table in ["vhl_approval_requests", "vhl_decisions", "vhl_challenges"] {
        let cols: Vec<(i64, String, String)> = match table {
            "vhl_approval_requests" => sqlx::query_as(
                "SELECT cid, name, type FROM pragma_table_info('vhl_approval_requests')",
            )
            .fetch_all(db.pool())
            .await
            .expect("pragma"),
            "vhl_decisions" => {
                sqlx::query_as("SELECT cid, name, type FROM pragma_table_info('vhl_decisions')")
                    .fetch_all(db.pool())
                    .await
                    .expect("pragma")
            }
            _ => sqlx::query_as("SELECT cid, name, type FROM pragma_table_info('vhl_challenges')")
                .fetch_all(db.pool())
                .await
                .expect("pragma"),
        };
        for (_, name, _) in cols {
            let lower = name.to_lowercase();
            assert!(
                !lower.contains("private") && !lower.contains("secret"),
                "table {table} must not persist key material (column {name})"
            );
        }
    }
}

#[tokio::test]
async fn insert_and_read_request_round_trip() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let request = test_request("nonce-1");
    db.vhl_insert_request(&ws, &request).await.expect("insert");
    let row = db
        .vhl_request(&ws, &request.request_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(row.request_id, request.request_id);
    assert_eq!(row.state, "requested");
    assert_eq!(row.action_digest, request.action_digest);
    assert_eq!(row.session_subject, request.session_subject);
    assert_eq!(row.nonce, "nonce-1");
    assert!(matches!(row.kind, ApprovalKind::OneShot));
    assert!(row.decided_at_ms.is_none());
    assert!(row.lease_id.is_none());
}

#[tokio::test]
async fn duplicate_request_nonce_is_rejected() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    db.vhl_insert_request(&ws, &test_request("nonce-dup"))
        .await
        .expect("first insert");
    let err = db
        .vhl_insert_request(&ws, &test_request("nonce-dup"))
        .await
        .expect_err("duplicate (workspace, nonce) must fail");
    assert!(
        format!("{err:?}").contains("UNIQUE") || format!("{err:?}").contains("unique"),
        "got {err:?}"
    );
}

#[tokio::test]
async fn state_machine_is_forward_only() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let request = test_request("nonce-fwd");
    db.vhl_insert_request(&ws, &request).await.expect("insert");
    let id = &request.request_id;

    // requested → approved goes through vhl_record_decision, which writes
    // the decision row atomically: vhl_transition rejects decision edges.
    db.vhl_record_decision(
        &ws,
        id,
        "approved",
        "human",
        Some("att-1"),
        "ok",
        NOW_MS,
        "requested",
    )
    .await
    .expect("requested→approved");
    // approved → requested is a backward edge: compare-and-swap refuses.
    let err = db
        .vhl_transition(
            &ws,
            id,
            "approved",
            "requested",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect_err("backward transition must fail");
    assert!(
        matches!(err, lumen_db::RepositoryError::VhlStateConflict),
        "got {err:?}"
    );
    // approved → minted (the lease must exist: lease_id is a foreign key)
    insert_lease(&db, &ws, "lease-1").await;
    db.vhl_transition(
        &ws,
        id,
        "approved",
        "minted",
        None,
        None,
        None,
        None,
        Some("lease-1"),
        Some(NOW_MS),
        None,
    )
    .await
    .expect("approved→minted");
    // minted → consumed
    db.vhl_transition(
        &ws,
        id,
        "minted",
        "consumed",
        None,
        None,
        None,
        None,
        None,
        None,
        Some(NOW_MS),
    )
    .await
    .expect("minted→consumed");
    // consumed is terminal.
    db.vhl_transition(
        &ws, id, "consumed", "approved", None, None, None, None, None, None, None,
    )
    .await
    .expect_err("terminal state must not move");
}

#[tokio::test]
async fn illegal_skip_transition_is_rejected_by_trigger() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let request = test_request("nonce-skip");
    db.vhl_insert_request(&ws, &request).await.expect("insert");
    // requested → consumed skips decision and mint: the transition guard
    // rejects non-mint/consume edges before the SQL trigger is even
    // reached, and the conflict surfaces as a semantic error, not a raw
    // DB fault.
    let err = db
        .vhl_transition(
            &ws,
            &request.request_id,
            "requested",
            "consumed",
            None,
            None,
            None,
            None,
            Some("lease-x"),
            None,
            Some(NOW_MS),
        )
        .await
        .expect_err("skipped states must fail");
    assert!(
        matches!(err, lumen_db::RepositoryError::VhlStateConflict),
        "got {err:?}"
    );
}

#[tokio::test]
async fn request_body_is_immutable() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let request = test_request("nonce-imm");
    db.vhl_insert_request(&ws, &request).await.expect("insert");
    let err = sqlx::query("UPDATE vhl_approval_requests SET action_digest=? WHERE request_id=?")
        .bind("b".repeat(64))
        .bind(&request.request_id)
        .execute(db.pool())
        .await
        .expect_err("immutable column change must fail");
    assert!(
        format!("{err:?}").contains("immutable column"),
        "got {err:?}"
    );
    // Requests are history: no deletes.
    sqlx::query("DELETE FROM vhl_approval_requests WHERE request_id=?")
        .bind(&request.request_id)
        .execute(db.pool())
        .await
        .expect_err("delete must fail");
}

#[tokio::test]
async fn decisions_are_append_only_and_atomic_with_transition() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let request = test_request("nonce-dec");
    db.vhl_insert_request(&ws, &request).await.expect("insert");
    let id = &request.request_id;

    db.vhl_record_decision(
        &ws,
        id,
        "approved",
        "human",
        Some("att-1"),
        "looks good",
        NOW_MS,
        "requested",
    )
    .await
    .expect("decision records");
    let row = db
        .vhl_request(&ws, id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(row.state, "approved");
    assert_eq!(row.decided_by.as_deref(), Some("human"));
    assert_eq!(row.attestation_id.as_deref(), Some("att-1"));

    // A second decision on the same request conflicts: no double decision.
    let err = db
        .vhl_record_decision(
            &ws,
            id,
            "denied",
            "human",
            None,
            "changed mind",
            NOW_MS,
            "requested",
        )
        .await
        .expect_err("double decision must fail");
    assert!(
        matches!(err, lumen_db::RepositoryError::VhlStateConflict),
        "got {err:?}"
    );

    // Decision rows are immutable history.
    sqlx::query("UPDATE vhl_decisions SET reason='tampered' WHERE request_id=?")
        .bind(id)
        .execute(db.pool())
        .await
        .expect_err("decision update must fail");
    sqlx::query("DELETE FROM vhl_decisions WHERE request_id=?")
        .bind(id)
        .execute(db.pool())
        .await
        .expect_err("decision delete must fail");
}

#[tokio::test]
async fn denial_and_expiry_persist_distinctly() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let denied = test_request("nonce-denied");
    db.vhl_insert_request(&ws, &denied).await.expect("insert");
    db.vhl_record_decision(
        &ws,
        &denied.request_id,
        "denied",
        "human",
        None,
        "too broad",
        NOW_MS,
        "requested",
    )
    .await
    .expect("denial records");
    let row = db
        .vhl_request(&ws, &denied.request_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(row.state, "denied");
    assert_eq!(row.decision_reason.as_deref(), Some("too broad"));

    let expired = test_request("nonce-expired");
    db.vhl_insert_request(&ws, &expired).await.expect("insert");
    db.vhl_record_decision(
        &ws,
        &expired.request_id,
        "expired",
        "kernel",
        None,
        "deadline passed",
        NOW_MS,
        "requested",
    )
    .await
    .expect("expiry records");
    let row = db
        .vhl_request(&ws, &expired.request_id)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(row.state, "expired");
}

#[tokio::test]
async fn attestation_claim_is_single_use() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    assert!(
        db.vhl_claim_attestation(&ws, "att-abc", NOW_MS, 300_000)
            .await
            .expect("claim"),
        "first claim succeeds"
    );
    assert!(
        !db.vhl_claim_attestation(&ws, "att-abc", NOW_MS, 300_000)
            .await
            .expect("reclaim"),
        "second claim is a replay"
    );
}

#[tokio::test]
async fn challenge_lifecycle() {
    use sha2::{Digest, Sha256};
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let digest = "c".repeat(64);
    let code = "correct-horse";
    let code_hash = hex::encode(Sha256::digest(code.as_bytes()));

    // Wrong code fails; right code completes the ceremony.
    db.vhl_insert_challenge(&ws, "ch-1", &digest, &code_hash, NOW_MS, NOW_MS + 300_000)
        .await
        .expect("insert");
    assert!(
        !db.vhl_complete_challenge(&ws, "ch-1", "wrong", &digest, NOW_MS)
            .await
            .expect("wrong code"),
        "wrong code must not complete"
    );
    assert!(
        db.vhl_complete_challenge(&ws, "ch-1", code, &digest, NOW_MS)
            .await
            .expect("right code"),
        "right code completes"
    );
    // Completion alone authorizes nothing: the ceremony is consumed exactly
    // once, and only for the action it was bound to.
    assert!(
        !db.vhl_consume_challenge(&ws, "ch-1", &"d".repeat(64), NOW_MS)
            .await
            .expect("wrong digest consume"),
        "ceremony must not authorize a different action"
    );
    assert!(
        db.vhl_consume_challenge(&ws, "ch-1", &digest, NOW_MS)
            .await
            .expect("consume"),
        "first consumption succeeds"
    );
    assert!(
        !db.vhl_consume_challenge(&ws, "ch-1", &digest, NOW_MS)
            .await
            .expect("reconsume"),
        "each ceremony authorizes at most one decision"
    );
    // A consumed challenge cannot be re-completed.
    assert!(
        !db.vhl_complete_challenge(&ws, "ch-1", code, &digest, NOW_MS)
            .await
            .expect("recomplete"),
        "consumed challenge stays dead"
    );

    // The ceremony is bound to its action digest at completion time too.
    db.vhl_insert_challenge(&ws, "ch-2", &digest, &code_hash, NOW_MS, NOW_MS + 300_000)
        .await
        .expect("insert");
    assert!(
        !db.vhl_complete_challenge(&ws, "ch-2", code, &"d".repeat(64), NOW_MS)
            .await
            .expect("wrong digest"),
        "challenge must not complete for a different action"
    );

    // Expired challenges never complete, and completion marks them dead.
    db.vhl_insert_challenge(&ws, "ch-3", &digest, &code_hash, NOW_MS, NOW_MS + 1)
        .await
        .expect("insert");
    assert!(
        !db.vhl_complete_challenge(&ws, "ch-3", code, &digest, NOW_MS + 60_000)
            .await
            .expect("expired"),
        "expired challenge must not complete"
    );
    assert!(
        !db.vhl_complete_challenge(&ws, "ch-3", code, &digest, NOW_MS)
            .await
            .expect("expired is dead"),
        "expiry burns the challenge"
    );

    // Five wrong attempts burn the challenge.
    db.vhl_insert_challenge(&ws, "ch-4", &digest, &code_hash, NOW_MS, NOW_MS + 300_000)
        .await
        .expect("insert");
    for _ in 0..5 {
        let _ = db
            .vhl_complete_challenge(&ws, "ch-4", "wrong", &digest, NOW_MS)
            .await;
    }
    assert!(
        !db.vhl_complete_challenge(&ws, "ch-4", code, &digest, NOW_MS)
            .await
            .expect("burned"),
        "burned challenge rejects even the right code"
    );
}

#[tokio::test]
async fn courier_message_encode_round_trip() {
    let request = test_request("nonce-msg");
    let msg = VhlCourierMessage::ApprovalRequest { request };
    let bytes = Database::vhl_encode_courier_message(&msg).expect("encodes");
    let decoded = VhlCourierMessage::decode(&bytes).expect("decodes");
    assert_eq!(decoded, msg);
}

#[tokio::test]
async fn one_shot_use_is_single_use() {
    use lumen_core::budget::{Budget, BudgetDimension, BudgetLedger};
    use lumen_core::lease::{
        KernelKeys, LeaseLimits, RootLeaseParams, SessionRegistry, mint_root_lease,
    };
    use lumen_core::nonce::NonceStore;

    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let keys = KernelKeys::generate();
    let mut sessions = SessionRegistry::new();
    sessions.register(
        "ed25519:parent-session".to_string(),
        None,
        keys.issuer_verifying(),
    );
    let ledger = BudgetLedger::new();
    let nonces = NonceStore::new();
    let lease = mint_root_lease(
        RootLeaseParams {
            lease_id: "lease-oneshot-1".to_string(),
            subject: "ed25519:parent-session".to_string(),
            scope: Default::default(),
            limits: LeaseLimits {
                not_before_ms: 0,
                expires_at_ms: 1_000_000,
                budget: Budget::new().set(BudgetDimension::Executions, 1),
                max_executions: Some(1),
                single_use: true,
            },
            depth_limit: 1,
            lease_nonce: "oneshot-nonce-1".to_string(),
            issued_at_ms: 100,
        },
        &keys,
        &sessions,
        &ledger,
        &nonces,
        100,
    )
    .expect("root lease mints");
    db.insert_kernel_lease(&ws, &lease)
        .await
        .expect("insert lease");

    assert!(
        db.vhl_claim_one_shot_use(&ws, "lease-oneshot-1", NOW_MS)
            .await
            .expect("claim"),
        "first consumption succeeds"
    );
    assert!(
        !db.vhl_claim_one_shot_use(&ws, "lease-oneshot-1", NOW_MS)
            .await
            .expect("reclaim"),
        "second consumption is a replay"
    );
}

#[tokio::test]
async fn approval_lease_reference_is_workspace_scoped() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws_a = test_workspace(&db).await;
    let ws_b = test_workspace(&db).await;
    let request = test_request("nonce-xws-lease");
    db.vhl_insert_request(&ws_a, &request)
        .await
        .expect("insert");
    // Decisions go through vhl_record_decision (atomic with the decision
    // row); vhl_transition only performs the post-decision edges.
    db.vhl_record_decision(
        &ws_a,
        &request.request_id,
        "approved",
        "human",
        Some("att-1"),
        "ok",
        NOW_MS,
        "requested",
    )
    .await
    .expect("requested→approved");

    // The lease lives in workspace B. Attaching it to workspace A's
    // approval must fail closed at the composite foreign key — the old
    // unscoped `REFERENCES kernel_leases(lease_id)` let this through.
    insert_lease(&db, &ws_b, "lease-in-b").await;
    let err = db
        .vhl_transition(
            &ws_a,
            &request.request_id,
            "approved",
            "minted",
            None,
            None,
            None,
            None,
            Some("lease-in-b"),
            Some(NOW_MS),
            None,
        )
        .await
        .expect_err("cross-workspace lease reference must fail");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("FOREIGN KEY") || msg.contains("foreign key"),
        "expected a foreign-key violation, got {msg}"
    );

    // The same-workspace association still works.
    insert_lease(&db, &ws_a, "lease-in-a").await;
    db.vhl_transition(
        &ws_a,
        &request.request_id,
        "approved",
        "minted",
        None,
        None,
        None,
        None,
        Some("lease-in-a"),
        Some(NOW_MS),
        None,
    )
    .await
    .expect("same-workspace lease reference");
}

#[tokio::test]
async fn vhl_transition_rejects_decision_edges() {
    let db = Database::connect_in_memory().await.expect("connect");
    let ws = test_workspace(&db).await;
    let request = test_request("nonce-no-decision-bypass");
    db.vhl_insert_request(&ws, &request).await.expect("insert");
    let id = &request.request_id;

    // requested → approved through vhl_transition would skip the
    // vhl_decisions row: the API rejects the edge with a conflict, and
    // the request stays undecided.
    let err = db
        .vhl_transition(
            &ws,
            id,
            "requested",
            "approved",
            Some(NOW_MS),
            Some("human"),
            Some("ok"),
            Some("att-1"),
            None,
            None,
            None,
        )
        .await
        .expect_err("decision edge must be rejected");
    assert!(
        matches!(err, lumen_db::RepositoryError::VhlStateConflict),
        "got {err:?}"
    );
    let row = db.vhl_request(&ws, id).await.expect("get").expect("row");
    assert_eq!(row.state, "requested");

    // The same decision through vhl_record_decision succeeds: the
    // transition and the decision row land atomically.
    db.vhl_record_decision(
        &ws,
        id,
        "approved",
        "human",
        Some("att-1"),
        "ok",
        NOW_MS,
        "requested",
    )
    .await
    .expect("decision records");
    let row = db.vhl_request(&ws, id).await.expect("get").expect("row");
    assert_eq!(row.state, "approved");
    assert_eq!(row.decided_by.as_deref(), Some("human"));
    assert_eq!(row.attestation_id.as_deref(), Some("att-1"));
}
