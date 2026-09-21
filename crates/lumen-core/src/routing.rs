//! Deterministic, fail-closed model selection and budget accounting types.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    approval::TimestampMillis,
    context::ModelDataPolicy,
    egress::{EndpointClass, ProviderId},
    model::{ModelGenerationConfig, ReasoningProfile, ReasoningWireFormat},
    orchestration::{ModelProfileRef, OrchestrationId, TaskNode, TaskNodeId, TaskOutputKind},
    provider::{ModelCapability, ModelProfile, ModelProfileId, ProviderConfig, ProviderKind},
    worker::WorkerRunBudget,
};

macro_rules! id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
        )]
        #[serde(transparent)]
        pub struct $name(Uuid);
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }
    };
}
id!(RoutingDecisionId);
id!(BudgetReservationId);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HealthState {
    Healthy,
    Degraded,
    Unavailable,
}
impl HealthState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "healthy" => Some(Self::Healthy),
            "degraded" => Some(Self::Degraded),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HealthObservation {
    pub state: HealthState,
    pub latency_millis: u64,
    pub observed_at: TimestampMillis,
    pub expires_at: TimestampMillis,
}
impl HealthObservation {
    pub fn new(
        state: HealthState,
        latency_millis: u64,
        observed_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Result<Self, RoutingError> {
        if expires_at.as_u64() <= observed_at.as_u64() {
            return Err(RoutingError::InvalidMetadata);
        }
        Ok(Self {
            state,
            latency_millis,
            observed_at,
            expires_at,
        })
    }
    pub fn usable(&self, now: TimestampMillis) -> bool {
        self.state != HealthState::Unavailable
            && self.observed_at.as_u64() <= now.as_u64()
            && now.as_u64() <= self.expires_at.as_u64()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelPricing {
    pub input_micros_per_million: u64,
    pub output_micros_per_million: u64,
}
impl ModelPricing {
    pub const fn new(input: u64, output: u64) -> Self {
        Self {
            input_micros_per_million: input,
            output_micros_per_million: output,
        }
    }
    pub fn cost_micros(self, input: u64, output: u64) -> u64 {
        cost(input, self.input_micros_per_million)
            .saturating_add(cost(output, self.output_micros_per_million))
    }
}
fn cost(tokens: u64, rate: u64) -> u64 {
    u64::try_from((u128::from(tokens) * u128::from(rate)).div_ceil(1_000_000)).unwrap_or(u64::MAX)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ModelRoutingMetadata {
    pub profile_id: ModelProfileId,
    pub profile_revision: u64,
    pub revision: u64,
    pub wire: ReasoningWireFormat,
    pub efforts: BTreeMap<ReasoningProfile, Option<String>>,
    pub pricing: ModelPricing,
    pub affinity: BTreeMap<TaskOutputKind, i32>,
    pub created_at: TimestampMillis,
}
impl ModelRoutingMetadata {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        profile_id: ModelProfileId,
        profile_revision: u64,
        revision: u64,
        wire: ReasoningWireFormat,
        efforts: BTreeMap<ReasoningProfile, Option<String>>,
        pricing: ModelPricing,
        affinity: BTreeMap<TaskOutputKind, i32>,
        created_at: TimestampMillis,
    ) -> Result<Self, RoutingError> {
        if profile_revision == 0 || revision == 0 || efforts.is_empty() {
            return Err(RoutingError::InvalidMetadata);
        }
        for effort in efforts.values() {
            match (wire, effort.as_deref()) {
                (ReasoningWireFormat::None, None) => {}
                (ReasoningWireFormat::None, Some(_)) => return Err(RoutingError::InvalidMetadata),
                (_, Some(v))
                    if !v.is_empty()
                        && v.len() <= 32
                        && v.bytes().all(|b| {
                            b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                        }) => {}
                _ => return Err(RoutingError::InvalidMetadata),
            }
        }
        Ok(Self {
            profile_id,
            profile_revision,
            revision,
            wire,
            efforts,
            pricing,
            affinity,
            created_at,
        })
    }
    pub fn generation(
        &self,
        reasoning: ReasoningProfile,
        max_output_tokens: u32,
    ) -> Result<ModelGenerationConfig, RoutingError> {
        ModelGenerationConfig::new(
            reasoning,
            self.wire,
            self.efforts
                .get(&reasoning)
                .ok_or(RoutingError::ReasoningUnsupported)?
                .clone(),
            max_output_tokens,
        )
        .map_err(|_| RoutingError::InvalidMetadata)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OrchestrationBudget {
    pub orchestration_id: OrchestrationId,
    pub revision: u64,
    pub max_model_calls: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_remote_cost_micros: u64,
    pub max_concurrent_workers: u32,
    pub max_wall_time_millis: u64,
    pub window_started_at: TimestampMillis,
    pub created_at: TimestampMillis,
}
impl OrchestrationBudget {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        orchestration_id: OrchestrationId,
        revision: u64,
        calls: u64,
        input: u64,
        output: u64,
        cost: u64,
        concurrent: u32,
        wall: u64,
        started: TimestampMillis,
        created: TimestampMillis,
    ) -> Result<Self, RoutingError> {
        if revision == 0
            || calls == 0
            || input == 0
            || output == 0
            || concurrent == 0
            || wall == 0
            || created.as_u64() < started.as_u64()
        {
            return Err(RoutingError::InvalidBudget);
        }
        Ok(Self {
            orchestration_id,
            revision,
            max_model_calls: calls,
            max_input_tokens: input,
            max_output_tokens: output,
            max_remote_cost_micros: cost,
            max_concurrent_workers: concurrent,
            max_wall_time_millis: wall,
            window_started_at: started,
            created_at: created,
        })
    }
    pub fn is_tightening_of(&self, old: &Self) -> bool {
        self.orchestration_id == old.orchestration_id
            && self.revision == old.revision.saturating_add(1)
            && self.window_started_at == old.window_started_at
            && self.max_model_calls <= old.max_model_calls
            && self.max_input_tokens <= old.max_input_tokens
            && self.max_output_tokens <= old.max_output_tokens
            && self.max_remote_cost_micros <= old.max_remote_cost_micros
            && self.max_concurrent_workers <= old.max_concurrent_workers
            && self.max_wall_time_millis <= old.max_wall_time_millis
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BudgetSnapshot {
    pub budget: OrchestrationBudget,
    pub remaining_calls: u64,
    pub remaining_input: u64,
    pub remaining_output: u64,
    pub remaining_cost: u64,
    pub remaining_concurrency: u32,
    pub remaining_wall_millis: u64,
    pub expired: bool,
}
impl BudgetSnapshot {
    pub fn new(
        budget: OrchestrationBudget,
        calls: u64,
        input: u64,
        output: u64,
        cost: u64,
        active: u32,
        now: TimestampMillis,
    ) -> Self {
        let deadline = budget
            .window_started_at
            .as_u64()
            .saturating_add(budget.max_wall_time_millis);
        Self {
            remaining_calls: budget.max_model_calls.saturating_sub(calls),
            remaining_input: budget.max_input_tokens.saturating_sub(input),
            remaining_output: budget.max_output_tokens.saturating_sub(output),
            remaining_cost: budget.max_remote_cost_micros.saturating_sub(cost),
            remaining_concurrency: budget.max_concurrent_workers.saturating_sub(active),
            remaining_wall_millis: deadline.saturating_sub(now.as_u64()),
            expired: now.as_u64() >= deadline,
            budget,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RoutingPolicy {
    pub remote_allowed: bool,
    pub prefer_local: bool,
}
impl RoutingPolicy {
    pub const fn new(remote_allowed: bool, prefer_local: bool) -> Self {
        Self {
            remote_allowed,
            prefer_local,
        }
    }
}
#[derive(Clone, Debug)]
pub struct RoutingRequest {
    pub orchestration_id: OrchestrationId,
    pub graph_revision: u64,
    pub task_node_id: TaskNodeId,
    pub output: TaskOutputKind,
    pub allowed_profiles: BTreeSet<ModelProfileRef>,
    pub reasoning: ReasoningProfile,
    pub max_calls: u64,
    pub max_input: u64,
    pub max_output: u64,
    pub max_wall: u64,
    pub policy: RoutingPolicy,
    pub now: TimestampMillis,
}
impl RoutingRequest {
    pub fn from_task(
        orchestration_id: OrchestrationId,
        graph_revision: u64,
        node: &TaskNode,
        reasoning: ReasoningProfile,
        budget: WorkerRunBudget,
        policy: RoutingPolicy,
        now: TimestampMillis,
    ) -> Self {
        Self {
            orchestration_id,
            graph_revision,
            task_node_id: node.id(),
            output: node.expected_output(),
            allowed_profiles: node.requirements().allowed_model_profiles().clone(),
            reasoning,
            max_calls: u64::from(budget.max_model_turns()),
            max_input: node.limits().max_input_tokens(),
            max_output: node.limits().max_output_tokens(),
            max_wall: budget.max_wall_time_millis(),
            policy,
            now,
        }
    }
}
#[derive(Clone, Debug)]
pub struct RoutingCandidate {
    pub provider: ProviderConfig,
    pub profile: ModelProfile,
    pub policy: ModelDataPolicy,
    pub metadata: ModelRoutingMetadata,
    pub provider_health: HealthObservation,
    pub model_health: HealthObservation,
    pub egress_allowed: bool,
    pub provider_active: u32,
    pub provider_capacity: u32,
    pub profile_active: u32,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EliminationReason {
    ProviderDisabled,
    ProfileDisabled,
    PinnedOut,
    Capabilities,
    Tools,
    ContextWindow,
    DataPolicy,
    ProviderEgress,
    RemoteForbidden,
    ProviderUnhealthy,
    ModelUnhealthy,
    ProviderSaturated,
    ProfileSaturated,
    ReasoningUnsupported,
    BudgetExpired,
    BudgetCalls,
    BudgetInput,
    BudgetOutput,
    BudgetCost,
    BudgetConcurrency,
    BudgetWallTime,
    MetadataMismatch,
    WireMismatch,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CandidateEvaluation {
    pub provider_id: String,
    pub provider_revision: u64,
    pub profile_id: String,
    pub profile_revision: u64,
    pub eliminated: Vec<EliminationReason>,
    pub score: Option<i64>,
    pub estimated_remote_cost_micros: u64,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BudgetReservationRequest {
    pub calls: u64,
    pub input: u64,
    pub output: u64,
    pub remote_cost_micros: u64,
    pub concurrent_workers: u32,
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutingPlan {
    pub decision_id: RoutingDecisionId,
    pub budget_revision: u64,
    pub provider_id: ProviderId,
    pub provider_revision: u64,
    pub profile_id: ModelProfileId,
    pub profile_revision: u64,
    pub reasoning: ReasoningProfile,
    pub generation: ModelGenerationConfig,
    pub pricing: ModelPricing,
    pub reservation: BudgetReservationRequest,
    pub evaluations: Vec<CandidateEvaluation>,
}
impl RoutingPlan {
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    pub fn profile_id(&self) -> &ModelProfileId {
        &self.profile_id
    }
    pub const fn profile_revision(&self) -> u64 {
        self.profile_revision
    }
}

pub fn route(
    node: &TaskNode,
    request: &RoutingRequest,
    budget: &BudgetSnapshot,
    candidates: Vec<RoutingCandidate>,
) -> Result<RoutingPlan, RoutingError> {
    if request.orchestration_id != budget.budget.orchestration_id
        || request.graph_revision == 0
        || request.task_node_id != node.id()
    {
        return Err(RoutingError::InvalidRequest);
    }
    let mut evaluations = Vec::new();
    let mut winners = Vec::new();
    for candidate in candidates {
        let provider = &candidate.provider;
        let profile = &candidate.profile;
        let mut eliminated = Vec::new();
        if !provider.enabled() {
            eliminated.push(EliminationReason::ProviderDisabled);
        }
        if !profile.enabled() {
            eliminated.push(EliminationReason::ProfileDisabled);
        }
        if profile.provider_id() != provider.id()
            || profile.provider_revision() != provider.revision()
            || candidate.metadata.profile_id != *profile.id()
            || candidate.metadata.profile_revision != profile.revision()
        {
            eliminated.push(EliminationReason::MetadataMismatch);
        }
        if !request.allowed_profiles.is_empty()
            && !request
                .allowed_profiles
                .iter()
                .any(|entry| entry.matches(profile))
        {
            eliminated.push(EliminationReason::PinnedOut);
        }
        if !node
            .requirements()
            .required_model_capabilities()
            .iter()
            .all(|capability| profile.capabilities().contains(capability))
        {
            eliminated.push(EliminationReason::Capabilities);
        }
        if !node.requirements().required_tools().is_empty()
            && !profile
                .capabilities()
                .contains(ModelCapability::ToolCalling)
        {
            eliminated.push(EliminationReason::Tools);
        }
        if request.max_input.saturating_add(request.max_output)
            > u64::from(profile.context_window_tokens())
        {
            eliminated.push(EliminationReason::ContextWindow);
        }
        if candidate.policy.validate_profile(profile).is_err()
            || !candidate
                .policy
                .allowed_data_classes()
                .contains(&node.requirements().data_class())
            || !node
                .requirements()
                .required_compartments()
                .iter()
                .all(|compartment| {
                    candidate
                        .policy
                        .allowed_compartments()
                        .contains(compartment)
                })
        {
            eliminated.push(EliminationReason::DataPolicy);
        }
        if !candidate.egress_allowed {
            eliminated.push(EliminationReason::ProviderEgress);
        }
        if provider.endpoint_class() == EndpointClass::Remote && !request.policy.remote_allowed {
            eliminated.push(EliminationReason::RemoteForbidden);
        }
        if !candidate.provider_health.usable(request.now) {
            eliminated.push(EliminationReason::ProviderUnhealthy);
        }
        if !candidate.model_health.usable(request.now) {
            eliminated.push(EliminationReason::ModelUnhealthy);
        }
        if candidate.provider_capacity == 0
            || candidate.provider_active >= candidate.provider_capacity
        {
            eliminated.push(EliminationReason::ProviderSaturated);
        }
        if candidate.profile_active >= profile.concurrency_limit() {
            eliminated.push(EliminationReason::ProfileSaturated);
        }
        if !wire_ok(provider.kind(), candidate.metadata.wire) {
            eliminated.push(EliminationReason::WireMismatch);
        }
        let generation = candidate.metadata.generation(
            request.reasoning,
            u32::try_from(request.max_output).unwrap_or(u32::MAX),
        );
        if generation.is_err() {
            eliminated.push(EliminationReason::ReasoningUnsupported);
        }
        let remote_cost = if provider.endpoint_class() == EndpointClass::Remote {
            candidate
                .metadata
                .pricing
                .cost_micros(request.max_input, request.max_output)
        } else {
            0
        };
        if budget.expired {
            eliminated.push(EliminationReason::BudgetExpired);
        }
        if request.max_calls > budget.remaining_calls {
            eliminated.push(EliminationReason::BudgetCalls);
        }
        if request.max_input > budget.remaining_input {
            eliminated.push(EliminationReason::BudgetInput);
        }
        if request.max_output > budget.remaining_output {
            eliminated.push(EliminationReason::BudgetOutput);
        }
        if remote_cost > budget.remaining_cost {
            eliminated.push(EliminationReason::BudgetCost);
        }
        if budget.remaining_concurrency == 0 {
            eliminated.push(EliminationReason::BudgetConcurrency);
        }
        if request.max_wall > budget.remaining_wall_millis {
            eliminated.push(EliminationReason::BudgetWallTime);
        }
        let score = eliminated.is_empty().then(|| {
            i64::from(
                *candidate
                    .metadata
                    .affinity
                    .get(&request.output)
                    .unwrap_or(&0),
            ) * 1000
                - i64::from(profile.priority()) * 100
                + if request.policy.prefer_local
                    && provider.endpoint_class() == EndpointClass::Local
                {
                    2500
                } else {
                    0
                }
                - i64::try_from(remote_cost).unwrap_or(i64::MAX / 4)
                - i64::try_from(
                    candidate
                        .provider_health
                        .latency_millis
                        .saturating_add(candidate.model_health.latency_millis)
                        / 10,
                )
                .unwrap_or(i64::MAX / 4)
        });
        evaluations.push(CandidateEvaluation {
            provider_id: provider.id().as_str().into(),
            provider_revision: provider.revision(),
            profile_id: profile.id().as_str().into(),
            profile_revision: profile.revision(),
            eliminated: eliminated.clone(),
            score,
            estimated_remote_cost_micros: remote_cost,
        });
        if let (Some(score), Ok(generation)) = (score, generation) {
            winners.push((
                score,
                provider.id().as_str().to_owned(),
                profile.id().as_str().to_owned(),
                provider.clone(),
                profile.clone(),
                candidate.metadata.pricing,
                generation,
                remote_cost,
            ));
        }
    }
    winners.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });
    let (_, _, _, provider, profile, pricing, generation, remote_cost) = winners
        .into_iter()
        .next()
        .ok_or(RoutingError::NoEligibleModel)?;
    Ok(RoutingPlan {
        decision_id: RoutingDecisionId::new(),
        budget_revision: budget.budget.revision,
        provider_id: provider.id().clone(),
        provider_revision: provider.revision(),
        profile_id: profile.id().clone(),
        profile_revision: profile.revision(),
        reasoning: request.reasoning,
        generation,
        pricing,
        reservation: BudgetReservationRequest {
            calls: request.max_calls,
            input: request.max_input,
            output: request.max_output,
            remote_cost_micros: remote_cost,
            concurrent_workers: 1,
        },
        evaluations,
    })
}
fn wire_ok(kind: ProviderKind, wire: ReasoningWireFormat) -> bool {
    matches!(
        (kind, wire),
        (_, ReasoningWireFormat::None)
            | (ProviderKind::OpenAi, ReasoningWireFormat::OpenAi)
            | (
                ProviderKind::Anthropic,
                ReasoningWireFormat::AnthropicAdaptive
            )
            | (
                ProviderKind::OpenAiCompatible,
                ReasoningWireFormat::OpenAiCompatible
            )
    )
}
#[derive(Debug, Error)]
pub enum RoutingError {
    #[error("routing metadata is invalid")]
    InvalidMetadata,
    #[error("orchestration budget is invalid")]
    InvalidBudget,
    #[error("routing request is invalid")]
    InvalidRequest,
    #[error("requested reasoning profile is unsupported")]
    ReasoningUnsupported,
    #[error("no eligible model profile")]
    NoEligibleModel,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cost_rounds_up() {
        assert_eq!(
            ModelPricing::new(4_000_000, 20_000_000).cost_micros(1, 1),
            24
        );
    }
    #[test]
    fn budget_never_expands() {
        let id = OrchestrationId::new();
        let a = OrchestrationBudget::new(
            id,
            1,
            10,
            100,
            100,
            10,
            2,
            1000,
            TimestampMillis::new(1),
            TimestampMillis::new(1),
        )
        .unwrap();
        let b = OrchestrationBudget::new(
            id,
            2,
            9,
            90,
            90,
            9,
            1,
            900,
            TimestampMillis::new(1),
            TimestampMillis::new(2),
        )
        .unwrap();
        assert!(b.is_tightening_of(&a));
    }
}
