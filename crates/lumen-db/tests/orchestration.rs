use lumen_core::{
    approval::TimestampMillis,
    context::{CompartmentId, ModelDataPolicy, ProjectionTaskKey},
    egress::{DataClass, ProviderId},
    identity::{PrincipalId, WorkspaceId},
    orchestration::{
        OrchestrationError, OrchestrationId, TaskGraph, TaskGraphProposal, TaskNodeLimits,
        TaskNodeProposal, TaskNodeState, TaskOutputKind, TaskRequirements,
    },
    provider::{
        LocalRuntimeKind, ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId,
        ModelTrustZone, ProviderConfig,
    },
};
use lumen_db::{Database, RepositoryError};
fn catalog(workspace: WorkspaceId) -> (ModelProfile, ModelDataPolicy) {
    let provider = ProviderConfig::local_openai_compatible(
        ProviderId::parse("local").unwrap(),
        1,
        "http://127.0.0.1:11434/v1/",
        LocalRuntimeKind::Ollama,
        true,
        None,
    )
    .unwrap();
    let profile = ModelProfile::new(
        ModelProfileId::parse("coder").unwrap(),
        1,
        provider.id().clone(),
        1,
        "qwen-coder",
        true,
        ModelCapabilities::new([ModelCapability::Text, ModelCapability::CodeGeneration]),
        32_768,
        ModelTrustZone::LocalRestricted,
        2,
        0,
    )
    .unwrap();
    let policy = ModelDataPolicy::new(
        workspace,
        profile.id().clone(),
        1,
        profile.trust_zone(),
        1,
        [DataClass::Workspace],
        [CompartmentId::parse("workspace/source-code").unwrap()],
        true,
        TimestampMillis::new(1),
    )
    .unwrap();
    (profile, policy)
}
fn task(key: &str, deps: &[&str]) -> TaskNodeProposal {
    TaskNodeProposal::new(
        ProjectionTaskKey::parse(key).unwrap(),
        format!("Implement {key}"),
        TaskOutputKind::Patch,
        deps.iter()
            .map(|value| ProjectionTaskKey::parse(*value).unwrap()),
        TaskRequirements::new(
            ModelCapabilities::new([ModelCapability::Text, ModelCapability::CodeGeneration]),
            [],
            DataClass::Workspace,
            [CompartmentId::parse("workspace/source-code").unwrap()],
            [],
        )
        .unwrap(),
        TaskNodeLimits::new(8_000, 4_000, 2).unwrap(),
        None,
    )
    .unwrap()
}
#[tokio::test]
async fn durable_dag_validates_reconciles_and_recovers() {
    let workspace = WorkspaceId::new();
    let actor = PrincipalId::new("local", "operator").unwrap();
    let (profile, policy) = catalog(workspace);
    assert!(matches!(
        TaskGraph::from_proposal(
            OrchestrationId::new(),
            workspace,
            1,
            actor.clone(),
            TaskGraphProposal::new(vec![task("a", &["b"]), task("b", &["a"])]),
            TimestampMillis::new(10)
        ),
        Err(OrchestrationError::CycleDetected)
    ));
    let id = OrchestrationId::new();
    let graph = TaskGraph::from_proposal(
        id,
        workspace,
        1,
        actor.clone(),
        TaskGraphProposal::new(vec![
            task("backend", &[]),
            task("integration", &["backend"]),
        ]),
        TimestampMillis::new(10),
    )
    .unwrap();
    graph
        .validate_against_catalog(
            std::slice::from_ref(&profile),
            std::slice::from_ref(&policy),
        )
        .unwrap();
    graph.verify_digest().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("lumen.sqlite3");
    let db = Database::connect(&path).await.unwrap();
    sqlx::query("INSERT INTO workspaces(id,name,created_at) VALUES(?,'Test',0)")
        .bind(workspace.to_string())
        .execute(db.pool())
        .await
        .unwrap();
    sqlx::query("INSERT INTO identities(provider,subject,created_at) VALUES(?,?,0)")
        .bind(actor.provider())
        .bind(actor.subject())
        .execute(db.pool())
        .await
        .unwrap();
    db.append_task_graph(
        &graph,
        std::slice::from_ref(&profile),
        std::slice::from_ref(&policy),
    )
    .await
    .unwrap();
    let snapshot = db.latest_orchestration_snapshot(id).await.unwrap().unwrap();
    let backend = snapshot
        .graph()
        .nodes()
        .find(|node| node.key().as_str() == "backend")
        .unwrap()
        .id();
    let integration = snapshot
        .graph()
        .nodes()
        .find(|node| node.key().as_str() == "integration")
        .unwrap()
        .id();
    let initial = snapshot.state(backend).unwrap();
    let running = db
        .transition_task_state(
            id,
            1,
            backend,
            initial.revision(),
            TaskNodeState::Running,
            TimestampMillis::new(11),
        )
        .await
        .unwrap();
    let replacement = TaskGraph::from_proposal(
        id,
        workspace,
        2,
        actor,
        TaskGraphProposal::new(vec![task("backend", &[])]),
        TimestampMillis::new(12),
    )
    .unwrap();
    assert!(matches!(
        db.append_task_graph(
            &replacement,
            std::slice::from_ref(&profile),
            std::slice::from_ref(&policy)
        )
        .await,
        Err(RepositoryError::InvalidOrchestrationState)
    ));
    db.transition_task_state(
        id,
        1,
        backend,
        running.revision(),
        TaskNodeState::Completed,
        TimestampMillis::new(12),
    )
    .await
    .unwrap();
    let updates = db
        .reconcile_task_readiness(id, TimestampMillis::new(13))
        .await
        .unwrap();
    assert_eq!(
        (updates[0].task_node_id(), updates[0].state()),
        (integration, TaskNodeState::Ready)
    );
    db.close().await;
    let db = Database::connect(&path).await.unwrap();
    let recovered = db.latest_orchestration_snapshot(id).await.unwrap().unwrap();
    assert_eq!(recovered.graph().digest(), graph.digest());
    assert_eq!(
        recovered.state(backend).unwrap().state(),
        TaskNodeState::Completed
    );
    assert_eq!(
        recovered.state(integration).unwrap().state(),
        TaskNodeState::Ready
    );
    assert!(matches!(
        db.transition_task_state(
            id,
            1,
            integration,
            recovered.state(integration).unwrap().revision() + 1,
            TaskNodeState::Running,
            TimestampMillis::new(14)
        )
        .await,
        Err(RepositoryError::InvalidOrchestrationState)
    ));
}
