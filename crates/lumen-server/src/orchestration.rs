use crate::ServiceError;
use lumen_core::{
    artifact::RetryMode,
    context::CompartmentId,
    egress::DataClass,
    identity::{PrincipalId, WorkspaceId},
    model::ReasoningProfile,
    orchestration::{ModelProfileRef, OrchestrationId, TaskNodeId},
    worker::WorkerAttemptId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{future::Future, pin::Pin};
pub type OrchestrationFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ServiceError>> + Send + 'a>>;
#[derive(Clone, Debug)]
pub struct CreateOrchestrationCommand {
    pub workspace_id: WorkspaceId,
    pub actor: PrincipalId,
    pub prompt: String,
    pub data_class: DataClass,
    pub compartments: Vec<CompartmentId>,
    pub reasoning: ReasoningProfile,
    pub remote_allowed: bool,
    pub prefer_local: bool,
    pub max_model_calls: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_remote_cost_micros: u64,
    pub max_concurrent_workers: u32,
    pub max_wall_time_millis: u64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ControlAction {
    Cancel,
    Retry {
        task_node_id: TaskNodeId,
        prior_attempt_id: WorkerAttemptId,
        mode: RetryMode,
    },
    Narrow {
        remote_allowed: Option<bool>,
        max_model_calls: Option<u64>,
        max_input_tokens: Option<u64>,
        max_output_tokens: Option<u64>,
        max_remote_cost_micros: Option<u64>,
        max_concurrent_workers: Option<u32>,
        max_wall_time_millis: Option<u64>,
    },
    Pin {
        task_node_id: TaskNodeId,
        profiles: Vec<ModelProfileRef>,
    },
}
#[derive(Clone, Debug)]
pub struct ControlOrchestrationCommand {
    pub workspace_id: WorkspaceId,
    pub actor: PrincipalId,
    pub orchestration_id: OrchestrationId,
    pub action: ControlAction,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrchestrationEvent {
    pub sequence: u64,
    pub kind: String,
    pub payload: Value,
    pub created_at: u64,
}
pub trait OrchestrationService: Send + Sync {
    fn create(&self, c: CreateOrchestrationCommand) -> OrchestrationFuture<'_, Value>;
    fn list(&self, w: WorkspaceId, a: PrincipalId) -> OrchestrationFuture<'_, Vec<Value>>;
    fn get(
        &self,
        w: WorkspaceId,
        a: PrincipalId,
        id: OrchestrationId,
    ) -> OrchestrationFuture<'_, Value>;
    fn control(&self, c: ControlOrchestrationCommand) -> OrchestrationFuture<'_, Value>;
    fn events(
        &self,
        w: WorkspaceId,
        a: PrincipalId,
        id: OrchestrationId,
        after: u64,
        limit: u16,
    ) -> OrchestrationFuture<'_, Vec<OrchestrationEvent>>;
    fn providers(&self, w: WorkspaceId, a: PrincipalId) -> OrchestrationFuture<'_, Vec<Value>>;
    fn models(&self, w: WorkspaceId, a: PrincipalId) -> OrchestrationFuture<'_, Vec<Value>>;
    fn artifacts(
        &self,
        w: WorkspaceId,
        a: PrincipalId,
        id: OrchestrationId,
    ) -> OrchestrationFuture<'_, Vec<Value>>;
}
