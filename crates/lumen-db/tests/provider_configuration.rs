use lumen_core::{
    approval::TimestampMillis,
    egress::{DataClass, DestinationScope, ProviderId},
    identity::{PrincipalId, WorkspaceId},
    provider::{
        ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId, ModelTrustZone,
        ProviderConfig, ProviderKind,
    },
    secret::SecretRefId,
};
use lumen_db::{
    Database, ModelEndpointClass, ModelProviderRevision, ProviderRegistration, RepositoryError,
    WorkspaceModelEgressRevision,
};

fn actor() -> PrincipalId {
    PrincipalId::new("local", "operator").unwrap()
}
fn at() -> TimestampMillis {
    TimestampMillis::new(1)
}
fn provider(id: &str, revision: u64, secret: SecretRefId) -> ProviderConfig {
    ProviderConfig::remote(
        ProviderId::parse(id).unwrap(),
        revision,
        ProviderKind::OpenAiCompatible,
        "https://provider.test/v1",
        true,
        secret,
    )
    .unwrap()
}
fn bundle(
    workspace: WorkspaceId,
    p: ProviderConfig,
    profile_id: &str,
    heads: [u64; 4],
) -> ProviderRegistration {
    let profile = ModelProfile::new(
        ModelProfileId::parse(profile_id).unwrap(),
        heads[1] + 1,
        p.id().clone(),
        p.revision(),
        "model",
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        32768,
        ModelTrustZone::RemoteUntrusted,
        1,
        0,
    )
    .unwrap();
    let egress = ModelProviderRevision::new(
        p.id().clone(),
        heads[2] + 1,
        ModelEndpointClass::Remote,
        DestinationScope::parse(p.endpoint()).unwrap(),
        "model",
        p.enabled(),
        0,
        p.credential_secret_ref(),
        [DataClass::Public, DataClass::Workspace],
        at(),
    )
    .unwrap();
    let workspace_policy = WorkspaceModelEgressRevision::new(
        workspace,
        p.id().clone(),
        heads[3] + 1,
        [DataClass::Public, DataClass::Workspace],
        at(),
    )
    .unwrap();
    ProviderRegistration {
        workspace,
        provider: p,
        profile,
        egress,
        workspace_policy,
        expected_provider: heads[0],
        expected_profile: heads[1],
        expected_egress: heads[2],
        expected_workspace_policy: heads[3],
    }
}
async fn fixture() -> (Database, WorkspaceId, ProviderConfig) {
    let db = Database::connect_in_memory().await.unwrap();
    let w = WorkspaceId::new();
    db.bootstrap_workspace(w, "workspace", &actor(), at())
        .await
        .unwrap();
    let p = provider("primary", 1, SecretRefId::new());
    db.reserve_provider_credential(w, &p, "primary", &actor(), at())
        .await
        .unwrap();
    db.set_provider_credential_state(w, p.credential_secret_ref().unwrap(), true, &actor(), at())
        .await
        .unwrap();
    (db, w, p)
}
#[tokio::test]
async fn atomic_registration_and_stale_heads_conflict() {
    let (db, w, p) = fixture().await;
    let r = bundle(w, p, "profile", [0; 4]);
    let receipt = db
        .register_provider_bundle(&r, &actor(), at())
        .await
        .unwrap();
    assert_eq!(receipt.provider_revision, 1);
    assert!(matches!(
        db.register_provider_bundle(&r, &actor(), at()).await,
        Err(RepositoryError::ProviderRevisionConflict)
    ));
    let snapshot = db
        .registered_model_snapshot(w, r.profile.id(), 1)
        .await
        .unwrap();
    assert_eq!(snapshot.provider, r.provider);
    assert_eq!(snapshot.profile, r.profile);
    assert!(
        db.registered_model_snapshot(WorkspaceId::new(), r.profile.id(), 1)
            .await
            .is_err()
    );
    db.verify_audit_chain().await.unwrap();
}
#[tokio::test]
async fn every_bundle_insert_and_audit_failure_roll_back_all_heads() {
    for table in [
        "model_provider_runtime_revisions",
        "model_profiles",
        "model_profile_revisions",
        "egress_model_provider_revisions",
        "egress_workspace_model_policies",
        "audit_events",
    ] {
        let (db, w, p) = fixture().await;
        let r = bundle(w, p, "profile", [0; 4]);
        // Table names come exclusively from the fixed test whitelist above.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE TRIGGER injected BEFORE INSERT ON {table} BEGIN SELECT RAISE(ABORT,'injected'); END"))).execute(db.pool()).await.unwrap();
        assert!(
            db.register_provider_bundle(&r, &actor(), at())
                .await
                .is_err()
        );
        for t in [
            "model_provider_runtime_revisions",
            "model_profiles",
            "model_profile_revisions",
            "egress_model_provider_revisions",
            "egress_workspace_model_policies",
        ] {
            let count: i64 =
                sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {t}")))
                    .fetch_one(db.pool())
                    .await
                    .unwrap();
            assert_eq!(count, 0, "{table}: {t}");
        }
        db.verify_audit_chain().await.unwrap();
    }
}
#[tokio::test]
async fn independent_heads_and_rotation_invalidate_old_selections() {
    let (db, w, p) = fixture().await;
    let r = bundle(w, p.clone(), "one", [0; 4]);
    db.register_provider_bundle(&r, &actor(), at())
        .await
        .unwrap();
    let p2 = provider("primary", 2, SecretRefId::new());
    db.reserve_provider_credential(w, &p2, "rotation", &actor(), at())
        .await
        .unwrap();
    db.set_provider_credential_state(w, p2.credential_secret_ref().unwrap(), true, &actor(), at())
        .await
        .unwrap();
    let r2 = bundle(w, p2, "two", [1, 0, 1, 1]);
    let receipt = db
        .register_provider_bundle(&r2, &actor(), at())
        .await
        .unwrap();
    assert_eq!(receipt.provider_revision, 2);
    assert_eq!(receipt.profile_revision, 1);
    assert!(
        db.registered_model_snapshot(w, r.profile.id(), 1)
            .await
            .is_err()
    );
    assert!(db.require_current_provider(w, &p).await.is_err());
    assert!(
        db.registered_model_snapshot(w, r2.profile.id(), 1)
            .await
            .is_ok()
    );
}
#[tokio::test]
async fn reference_scope_state_and_historical_ownership_fail_closed() {
    let (db, w, p) = fixture().await;
    let id = p.credential_secret_ref().unwrap();
    db.require_ready_provider_reference(w, &p, id)
        .await
        .unwrap();
    assert!(
        db.require_ready_provider_reference(WorkspaceId::new(), &p, id)
            .await
            .is_err()
    );
    assert!(
        db.require_ready_provider_reference(w, &provider("other", 1, id), id)
            .await
            .is_err()
    );
    for (kind, endpoint) in [
        (ProviderKind::OpenAi, "https://provider.test/v1/"),
        (ProviderKind::OpenAiCompatible, "https://other.test/"),
    ] {
        let wrong = ProviderConfig::remote(p.id().clone(), 1, kind, endpoint, true, id).unwrap();
        assert!(
            db.require_ready_provider_reference(w, &wrong, id)
                .await
                .is_err()
        );
    }
    assert!(
        db.require_ready_provider_reference(w, &p, SecretRefId::new())
            .await
            .is_err()
    );
    let process_id = SecretRefId::new();
    db.insert_secret_reference(
        &lumen_db::SecretReference::new(
            process_id,
            w,
            "process-only",
            "/usr/bin/tool",
            "PROCESS_KEY",
            at(),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let process_only = provider("primary", 1, process_id);
    assert!(
        db.require_ready_provider_reference(w, &process_only, process_id)
            .await
            .is_err()
    );
    assert!(
        db.register_provider_bundle(
            &bundle(w, process_only, "process-profile", [0; 4]),
            &actor(),
            at()
        )
        .await
        .is_err()
    );
    db.set_provider_credential_state(w, id, false, &actor(), at())
        .await
        .unwrap();
    assert!(
        db.require_ready_provider_reference(w, &p, id)
            .await
            .is_err()
    );
    assert!(
        db.register_provider_bundle(&bundle(w, p.clone(), "profile", [0; 4]), &actor(), at())
            .await
            .is_err()
    );
    let pending = provider("pending", 1, SecretRefId::new());
    db.reserve_provider_credential(w, &pending, "pending", &actor(), at())
        .await
        .unwrap();
    assert!(
        db.require_ready_provider_reference(w, &pending, pending.credential_secret_ref().unwrap())
            .await
            .is_err()
    );
    let historic = provider("historical", 1, SecretRefId::new());
    db.append_provider_config(&historic, at()).await.unwrap();
    assert!(matches!(
        db.reserve_provider_credential(w, &historic, "cannot adopt", &actor(), at())
            .await,
        Err(RepositoryError::ProviderScopeDenied)
    ));
    assert!(
        db.reserve_provider_credential(WorkspaceId::new(), &p, "cross workspace", &actor(), at())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn concurrent_expected_heads_have_one_winner() {
    let dir = tempfile::tempdir().unwrap();
    let db = Database::connect(dir.path().join("db")).await.unwrap();
    let w = WorkspaceId::new();
    db.bootstrap_workspace(w, "workspace", &actor(), at())
        .await
        .unwrap();
    let p = provider("primary", 1, SecretRefId::new());
    db.reserve_provider_credential(w, &p, "key", &actor(), at())
        .await
        .unwrap();
    db.set_provider_credential_state(w, p.credential_secret_ref().unwrap(), true, &actor(), at())
        .await
        .unwrap();
    let r = bundle(w, p, "profile", [0; 4]);
    let actor = actor();
    let (a, b) = tokio::join!(
        db.register_provider_bundle(&r, &actor, at()),
        db.register_provider_bundle(&r, &actor, at())
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(
        a.err().or(b.err()),
        Some(RepositoryError::ProviderRevisionConflict)
    ));
}
#[tokio::test]
async fn upgrade_populated_0031_preserves_parent_and_child_foreign_keys() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(true),
        )
        .await
        .unwrap();
    let mut old = sqlx::migrate!("./migrations");
    old.migrations =
        std::borrow::Cow::Owned(old.iter().filter(|m| m.version <= 31).cloned().collect());
    old.run(&pool).await.unwrap();
    sqlx::raw_sql("INSERT INTO egress_model_providers VALUES('local',1); INSERT INTO model_provider_runtime_revisions VALUES('local',1,'openai_compatible','local','http://127.0.0.1:8080/v1/','ollama',1,NULL,1); INSERT INTO model_profiles VALUES('local-profile','local',1); INSERT INTO model_profile_revisions VALUES('local-profile','local',1,1,'model',1,'[\"text\"]',1024,'local_trusted',1,0,1);").execute(&pool).await.unwrap();
    sqlx::raw_sql(r#"
        INSERT INTO workspaces VALUES('workspace','Historical',1);
        INSERT INTO identities VALUES('local','operator',1);
        INSERT INTO agent_runs VALUES('run','workspace','local','operator','completed',1,2);
        INSERT INTO orchestrations VALUES('orchestration','workspace','local','operator',1);
        INSERT INTO orchestration_graph_revisions VALUES('orchestration',1,printf('%064d',0),1);
        INSERT INTO orchestration_task_nodes VALUES('orchestration',1,'task','task','Historical task','text','["text"]','["local-profile"]','public','[]','[]',100,100,1,NULL);
        INSERT INTO model_data_policy_revisions VALUES('workspace','local-profile',1,1,'local_trusted','["public"]','[]',1,1);
        INSERT INTO task_projections VALUES('projection','workspace','task','local-profile',1,1,'public','[]','{}',printf('%064d',1),1);
        INSERT INTO mixed_trust_gate_evaluations VALUES('gate','workspace','orchestration',1,'task','local-profile',1,1,'local_trusted',0,1,printf('%064d',3),'{}','projection',printf('%064d',1),1);
        INSERT INTO worker_attempts VALUES('attempt','orchestration',1,'task',1,'workspace','local','operator','local',1,'local-profile',1,1,'projection',printf('%064d',1),'public','prompt','[]','[]',1,1,1000,4096,'run','completed','11111111-1111-4111-8111-111111111111',1,1,1,2,NULL);
        INSERT INTO orchestration_budget_revisions VALUES('orchestration',1,1,100,100,0,1,1000,1,1);
        INSERT INTO routing_decisions VALUES('decision','orchestration',1,'task',1,'local',1,'local-profile',1,'{}',1);
        INSERT INTO worker_artifacts VALUES('artifact','workspace','orchestration',1,'task','attempt','run','text','text/plain',X'61',printf('%064d',2),'public','[]','local',1,'local-profile',1,NULL,1,'projection',printf('%064d',1),'[]',1);
    "#).execute(&pool).await.unwrap();
    let before:Vec<(String,String,String)>=sqlx::query_as("SELECT m.name,f.\"table\",f.\"to\" FROM sqlite_schema m JOIN pragma_foreign_key_list(m.name) f WHERE m.type='table' AND f.\"table\"='model_provider_runtime_revisions' ORDER BY m.name,f.seq").fetch_all(&pool).await.unwrap();
    pool.close().await;
    let db = Database::connect(&path).await.unwrap();
    assert_eq!(
        db.latest_model_profile(&ModelProfileId::parse("local-profile").unwrap())
            .await
            .unwrap()
            .unwrap()
            .provider_revision(),
        1
    );
    let after:Vec<(String,String,String)>=sqlx::query_as("SELECT m.name,f.\"table\",f.\"to\" FROM sqlite_schema m JOIN pragma_foreign_key_list(m.name) f WHERE m.type='table' AND f.\"table\"='model_provider_runtime_revisions' ORDER BY m.name,f.seq").fetch_all(db.pool()).await.unwrap();
    assert!(!before.is_empty());
    assert_eq!(before, after);
    let historical: (i64,i64,i64)=sqlx::query_as("SELECT (SELECT COUNT(*) FROM worker_attempts WHERE provider_id='local' AND provider_revision=1), (SELECT COUNT(*) FROM routing_decisions WHERE provider_id='local' AND provider_revision=1), (SELECT COUNT(*) FROM worker_artifacts WHERE provider_id='local' AND provider_revision=1)").fetch_one(db.pool()).await.unwrap();
    assert_eq!(historical, (1, 1, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM pragma_foreign_key_check")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn failed_0032_upgrade_rolls_back_and_returns_no_database() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .foreign_keys(false),
        )
        .await
        .unwrap();
    let mut old = sqlx::migrate!("./migrations");
    old.migrations =
        std::borrow::Cow::Owned(old.iter().filter(|m| m.version <= 31).cloned().collect());
    old.run(&pool).await.unwrap();
    // A dangling historical child must abort the parent rebuild, not silently become valid.
    sqlx::raw_sql("INSERT INTO egress_model_providers VALUES('local',1); INSERT INTO model_provider_runtime_revisions VALUES('local',1,'openai_compatible','local','http://127.0.0.1:8080/v1/','ollama',1,NULL,1); INSERT INTO model_profiles VALUES('broken','local',1); INSERT INTO model_profile_revisions VALUES('broken','local',1,99,'model',1,'[\"text\"]',1024,'local_trusted',1,0,1);").execute(&pool).await.unwrap();
    pool.close().await;
    assert!(
        Database::connect(&path).await.is_err(),
        "no serving handle may escape"
    );
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new()
                .filename(&path)
                .foreign_keys(true),
        )
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM _sqlx_migrations WHERE version=32")
            .fetch_one(&pool)
            .await
            .unwrap(),
        0
    );
    assert_eq!(sqlx::query_scalar::<_,i64>("SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('model_provider_owners','model_provider_runtime_revisions_new','model_provider_secret_references')").fetch_one(&pool).await.unwrap(),0);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM model_provider_runtime_revisions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("PRAGMA foreign_keys")
            .fetch_one(&pool)
            .await
            .unwrap(),
        1
    );
    pool.close().await;
}

#[tokio::test]
async fn registration_cannot_reassign_another_providers_profile_or_mismatched_mirror() {
    let (db, w, p) = fixture().await;
    let first = bundle(w, p, "shared-profile", [0; 4]);
    db.register_provider_bundle(&first, &actor(), at())
        .await
        .unwrap();
    let other = provider("other", 1, SecretRefId::new());
    db.reserve_provider_credential(w, &other, "other", &actor(), at())
        .await
        .unwrap();
    db.set_provider_credential_state(
        w,
        other.credential_secret_ref().unwrap(),
        true,
        &actor(),
        at(),
    )
    .await
    .unwrap();
    let mut candidate = bundle(w, other, "shared-profile", [0, 1, 0, 0]);
    assert!(matches!(
        db.register_provider_bundle(&candidate, &actor(), at())
            .await,
        Err(RepositoryError::ProviderRevisionConflict)
    ));
    candidate.profile = bundle(w, candidate.provider.clone(), "new-profile", [0; 4]).profile;
    candidate.expected_profile = 0;
    candidate.egress = ModelProviderRevision::new(
        candidate.provider.id().clone(),
        1,
        ModelEndpointClass::Remote,
        DestinationScope::parse("https://other.test/").unwrap(),
        "model",
        true,
        0,
        candidate.provider.credential_secret_ref(),
        [DataClass::Public],
        at(),
    )
    .unwrap();
    assert!(
        db.register_provider_bundle(&candidate, &actor(), at())
            .await
            .is_err()
    );
    assert!(
        db.latest_provider_config(candidate.provider.id())
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        db.latest_model_profile(candidate.profile.id())
            .await
            .unwrap()
            .is_none()
    );
    db.verify_audit_chain().await.unwrap();
}
