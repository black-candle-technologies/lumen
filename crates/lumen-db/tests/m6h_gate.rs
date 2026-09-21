use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::TimestampMillis,
    context::{
        CompartmentId, ContextSource, ContextSourceId, ModelDataPolicy, ProjectionId,
        ProjectionTaskKey, SourceProvenance, SourceProvenanceKind, TaskProjection,
    },
    egress::{DataClass, ProviderId},
    identity::{PrincipalId, WorkspaceId},
    orchestration::{
        OrchestrationId, TaskGraph, TaskGraphProposal, TaskNodeLimits, TaskNodeProposal,
        TaskOutputKind, TaskRequirements,
    },
    provider::{
        LocalRuntimeKind, ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId,
        ModelTrustZone, ProviderConfig,
    },
    trust_gate::{GateSource, evaluate_exact_projection},
    worker::{WorkerAssignment, WorkerAttemptId, WorkerRunBudget},
};
use lumen_db::{Database, RepositoryError};
use uuid::Uuid;
#[tokio::test]
async fn worker_reservation_requires_allowed_gate_for_exact_projection() {
    let db = Database::connect_in_memory().await.unwrap();
    let w = WorkspaceId::new();
    let actor = PrincipalId::new("local", "op").unwrap();
    db.bootstrap_workspace(w, "t", &actor, TimestampMillis::new(1))
        .await
        .unwrap();
    let provider = ProviderConfig::local_openai_compatible(
        ProviderId::parse("local").unwrap(),
        1,
        "http://127.0.0.1:11434/v1/",
        LocalRuntimeKind::Ollama,
        true,
        None,
    )
    .unwrap();
    db.append_provider_config(&provider, TimestampMillis::new(2))
        .await
        .unwrap();
    let profile = ModelProfile::new(
        ModelProfileId::parse("m").unwrap(),
        1,
        provider.id().clone(),
        1,
        "m",
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        8192,
        ModelTrustZone::LocalTrusted,
        1,
        0,
    )
    .unwrap();
    db.append_model_profile(&profile, TimestampMillis::new(3))
        .await
        .unwrap();
    let compartment = CompartmentId::parse("workspace/source").unwrap();
    let policy = ModelDataPolicy::new(
        w,
        profile.id().clone(),
        1,
        profile.trust_zone(),
        1,
        [DataClass::Workspace],
        [compartment.clone()],
        false,
        TimestampMillis::new(4),
    )
    .unwrap();
    db.append_model_data_policy(&policy).await.unwrap();
    let source = ContextSource::new(
        ContextSourceId::new(),
        w,
        DataClass::Workspace,
        [compartment.clone()],
        SourceProvenance::new(SourceProvenanceKind::File, "src/lib.rs").unwrap(),
        CanonicalValue::from("safe"),
        actor.clone(),
        TimestampMillis::new(5),
    )
    .unwrap();
    db.append_context_source(&source).await.unwrap();
    let req = TaskRequirements::new(
        ModelCapabilities::new([ModelCapability::Text]),
        [],
        DataClass::Workspace,
        [compartment],
        [],
    )
    .unwrap();
    let proposal = TaskGraphProposal::new(vec![
        TaskNodeProposal::new(
            ProjectionTaskKey::parse("task").unwrap(),
            "task",
            TaskOutputKind::Text,
            [],
            req,
            TaskNodeLimits::new(100, 100, 1).unwrap(),
            None,
        )
        .unwrap(),
    ]);
    let graph = TaskGraph::from_proposal(
        OrchestrationId::new(),
        w,
        1,
        actor.clone(),
        proposal,
        TimestampMillis::new(6),
    )
    .unwrap();
    db.append_task_graph(
        &graph,
        std::slice::from_ref(&profile),
        std::slice::from_ref(&policy),
    )
    .await
    .unwrap();
    let node = graph.nodes().next().unwrap().clone();
    let projection = TaskProjection::build(
        ProjectionId::new(),
        node.key().clone(),
        &profile,
        &policy,
        vec![source.clone()],
        TimestampMillis::new(7),
    )
    .unwrap();
    db.insert_task_projection(&projection).await.unwrap();
    let assignment = WorkerAssignment::new(
        &graph,
        &node,
        actor,
        &provider,
        &profile,
        &policy,
        &projection,
        [],
        WorkerRunBudget::new(2, 1, 10_000, 4096).unwrap(),
    )
    .unwrap();
    let denied = db
        .reserve_worker_attempt(
            &assignment,
            WorkerAttemptId::new(),
            RunId::new(),
            Uuid::new_v4(),
            TimestampMillis::new(100),
            TimestampMillis::new(8),
        )
        .await;
    assert!(matches!(
        denied,
        Err(RepositoryError::InvalidTrustGateState) | Err(RepositoryError::Sqlx(_))
    ));
    let selection = evaluate_exact_projection(
        w,
        graph.orchestration_id(),
        graph.revision(),
        &node,
        &profile,
        &policy,
        vec![GateSource::instruction(source)],
        TimestampMillis::new(9),
    )
    .unwrap();
    let evaluation = selection
        .evaluation
        .bind_projection(projection.id(), projection.digest())
        .unwrap();
    db.append_trust_gate_evaluation(&evaluation).await.unwrap();
    db.reserve_worker_attempt(
        &assignment,
        WorkerAttemptId::new(),
        RunId::new(),
        Uuid::new_v4(),
        TimestampMillis::new(100),
        TimestampMillis::new(10),
    )
    .await
    .unwrap();
    let report = db
        .verify_orchestration_integrity(graph.orchestration_id(), TimestampMillis::new(11))
        .await
        .unwrap();
    assert!(!report.ok());
    db.record_recovery_integrity(&report).await.unwrap();
    assert!(
        db.orchestration_quarantine(graph.orchestration_id())
            .await
            .unwrap()
            .is_some()
    );
}
