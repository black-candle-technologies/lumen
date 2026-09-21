use super::ApiError;
use crate::{ApiState, ControlAction, ControlOrchestrationCommand, CreateOrchestrationCommand};
use axum::{
    Extension, Json, Router,
    extract::{Path, Query, State, rejection::JsonRejection},
    response::{
        Sse,
        sse::{Event, KeepAlive},
    },
    routing::{get, post},
};
use futures_util::stream;
use lumen_core::{
    context::CompartmentId, egress::DataClass, identity::PrincipalId, model::ReasoningProfile,
    orchestration::OrchestrationId,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{convert::Infallible, time::Duration};
pub fn router() -> Router<ApiState> {
    Router::new()
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations",
            get(list).post(create),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations/providers",
            get(providers),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations/models",
            get(models),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations/{orchestration_id}",
            get(one),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations/{orchestration_id}/actions",
            post(control),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations/{orchestration_id}/events/stream",
            get(stream_events),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/orchestrations/{orchestration_id}/artifacts",
            get(artifacts),
        )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    prompt: String,
    data_class: DataClass,
    #[serde(default)]
    compartments: Vec<CompartmentId>,
    reasoning: ReasoningProfile,
    remote_allowed: bool,
    prefer_local: bool,
    max_model_calls: u64,
    max_input_tokens: u64,
    max_output_tokens: u64,
    max_remote_cost_micros: u64,
    max_concurrent_workers: u32,
    max_wall_time_millis: u64,
}
#[derive(Deserialize)]
struct Q {
    #[serde(default)]
    after: u64,
}
fn ws(s: &ApiState, v: &str) -> Result<lumen_core::identity::WorkspaceId, ApiError> {
    let w = super::parse_workspace(v)?;
    super::ensure_workspace(s, w)?;
    Ok(w)
}
async fn create(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path(w): Path<String>,
    b: Result<Json<CreateBody>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    let Json(b) = b.map_err(|_| ApiError::BadRequest("invalid orchestration body".into()))?;
    Ok(Json(
        s.orchestration_service()?
            .create(CreateOrchestrationCommand {
                workspace_id: w,
                actor: a,
                prompt: b.prompt,
                data_class: b.data_class,
                compartments: b.compartments,
                reasoning: b.reasoning,
                remote_allowed: b.remote_allowed,
                prefer_local: b.prefer_local,
                max_model_calls: b.max_model_calls,
                max_input_tokens: b.max_input_tokens,
                max_output_tokens: b.max_output_tokens,
                max_remote_cost_micros: b.max_remote_cost_micros,
                max_concurrent_workers: b.max_concurrent_workers,
                max_wall_time_millis: b.max_wall_time_millis,
            })
            .await?,
    ))
}
async fn list(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path(w): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    Ok(Json(
        json!({"orchestrations":s.orchestration_service()?.list(w,a).await?}),
    ))
}
async fn one(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path((w, o)): Path<(String, OrchestrationId)>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    Ok(Json(s.orchestration_service()?.get(w, a, o).await?))
}
async fn control(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path((w, o)): Path<(String, OrchestrationId)>,
    b: Result<Json<ControlAction>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    let Json(action) =
        b.map_err(|_| ApiError::BadRequest("invalid orchestration action".into()))?;
    Ok(Json(
        s.orchestration_service()?
            .control(ControlOrchestrationCommand {
                workspace_id: w,
                actor: a,
                orchestration_id: o,
                action,
            })
            .await?,
    ))
}
async fn stream_events(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path((w, o)): Path<(String, OrchestrationId)>,
    Query(q): Query<Q>,
) -> Result<Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let w = ws(&s, &w)?;
    let svc = s.orchestration_service()?;
    let st = stream::unfold(
        (svc, a, w, o, q.after),
        |(svc, a, w, o, mut cur)| async move {
            loop {
                match svc.events(w, a.clone(), o, cur, 100).await {
                    Ok(v) if !v.is_empty() => {
                        let x = v[0].clone();
                        cur = x.sequence;
                        return Some((
                            Ok(Event::default()
                                .id(cur.to_string())
                                .event(x.kind)
                                .json_data(x.payload)
                                .expect("json")),
                            (svc, a, w, o, cur),
                        ));
                    }
                    Ok(_) => tokio::time::sleep(Duration::from_millis(350)).await,
                    Err(_) => return None,
                }
            }
        },
    );
    Ok(Sse::new(st).keep_alive(KeepAlive::default()))
}
async fn providers(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path(w): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    Ok(Json(
        json!({"providers":s.orchestration_service()?.providers(w,a).await?}),
    ))
}
async fn models(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path(w): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    Ok(Json(
        json!({"models":s.orchestration_service()?.models(w,a).await?}),
    ))
}
async fn artifacts(
    State(s): State<ApiState>,
    Extension(a): Extension<PrincipalId>,
    Path((w, o)): Path<(String, OrchestrationId)>,
) -> Result<Json<Value>, ApiError> {
    let w = ws(&s, &w)?;
    Ok(Json(
        json!({"artifacts":s.orchestration_service()?.artifacts(w,a,o).await?}),
    ))
}
