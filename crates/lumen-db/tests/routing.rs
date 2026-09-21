use lumen_core::{
    approval::TimestampMillis,
    context::{CompartmentId, ModelDataPolicy, ProjectionTaskKey},
    egress::{DataClass, ProviderId},
    identity::{PrincipalId, WorkspaceId},
    model::{ModelGenerationConfig, ReasoningProfile, ReasoningWireFormat},
    orchestration::{
        OrchestrationId, TaskGraph, TaskGraphProposal, TaskNodeLimits, TaskNodeProposal,
        TaskOutputKind, TaskRequirements,
    },
    provider::{
        LocalRuntimeKind, ModelCapabilities, ModelCapability, ModelProfile, ModelProfileId,
        ModelTrustZone, ProviderConfig,
    },
    routing::{
        BudgetReservationRequest, CandidateEvaluation, ModelPricing, OrchestrationBudget,
        RoutingDecisionId, RoutingPlan,
    },
};
use lumen_db::Database;

#[tokio::test]
async fn concurrent_reservations_cannot_double_spend() {
    let db = Database::connect_in_memory().await.unwrap();
    let workspace = WorkspaceId::new();
    let actor = PrincipalId::new("local", "operator").unwrap();
    db.bootstrap_workspace(workspace, "routing", &actor, TimestampMillis::new(1))
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
        ModelProfileId::parse("model").unwrap(),
        1,
        provider.id().clone(),
        1,
        "model",
        true,
        ModelCapabilities::new([ModelCapability::Text]),
        4096,
        ModelTrustZone::LocalTrusted,
        2,
        0,
    )
    .unwrap();
    db.append_model_profile(&profile, TimestampMillis::new(3))
        .await
        .unwrap();
    let compartment = CompartmentId::parse("workspace/source").unwrap();
    let policy = ModelDataPolicy::new(
        workspace,
        profile.id().clone(),
        1,
        profile.trust_zone(),
        1,
        [DataClass::Workspace],
        [compartment.clone()],
        true,
        TimestampMillis::new(4),
    )
    .unwrap();
    db.append_model_data_policy(&policy).await.unwrap();
    let requirement = TaskRequirements::new(
        ModelCapabilities::new([ModelCapability::Text]),
        [],
        DataClass::Workspace,
        [compartment],
        [],
    )
    .unwrap();
    let graph = TaskGraph::from_proposal(
        OrchestrationId::new(),
        workspace,
        1,
        actor,
        TaskGraphProposal::new(
            ["a", "b"]
                .into_iter()
                .map(|key| {
                    TaskNodeProposal::new(
                        ProjectionTaskKey::parse(key).unwrap(),
                        key,
                        TaskOutputKind::Text,
                        [],
                        requirement.clone(),
                        TaskNodeLimits::new(100, 100, 1).unwrap(),
                        None,
                    )
                    .unwrap()
                })
                .collect(),
        ),
        TimestampMillis::new(5),
    )
    .unwrap();
    db.append_task_graph(
        &graph,
        std::slice::from_ref(&profile),
        std::slice::from_ref(&policy),
    )
    .await
    .unwrap();
    db.append_orchestration_budget(
        &OrchestrationBudget::new(
            graph.orchestration_id(),
            1,
            1,
            100,
            100,
            0,
            1,
            10_000,
            TimestampMillis::new(5),
            TimestampMillis::new(5),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    let plan = || RoutingPlan {
        decision_id: RoutingDecisionId::new(),
        budget_revision: 1,
        provider_id: provider.id().clone(),
        provider_revision: 1,
        profile_id: profile.id().clone(),
        profile_revision: 1,
        reasoning: ReasoningProfile::Balanced,
        generation: ModelGenerationConfig::new(
            ReasoningProfile::Balanced,
            ReasoningWireFormat::None,
            None,
            100,
        )
        .unwrap(),
        pricing: ModelPricing::new(0, 0),
        reservation: BudgetReservationRequest {
            calls: 1,
            input: 100,
            output: 100,
            remote_cost_micros: 0,
            concurrent_workers: 1,
        },
        evaluations: Vec::<CandidateEvaluation>::new(),
    };
    let nodes = graph.nodes().collect::<Vec<_>>();
    let first_plan = plan();
    let second_plan = plan();
    let (first, second) = tokio::join!(
        db.persist_route_and_reserve(
            graph.orchestration_id(),
            1,
            nodes[0].id(),
            &first_plan,
            TimestampMillis::new(6)
        ),
        db.persist_route_and_reserve(
            graph.orchestration_id(),
            1,
            nodes[1].id(),
            &second_plan,
            TimestampMillis::new(6)
        )
    );
    assert_ne!(first.is_ok(), second.is_ok());
}
