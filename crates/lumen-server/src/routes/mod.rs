use std::str::FromStr;

use axum::{
    Extension, Json, Router,
    extract::rejection::JsonRejection,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response, Sse},
    routing::{get, post},
};
use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::ApprovalId,
    egress::DataClass,
    extension::{PluginId, PluginVersion, Sha256Digest},
    identity::{ExternalChannelIdentity, PrincipalId, WorkspaceId},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiState, ApprovalDecision, ApprovalDecisionCommand, ApprovalQuery, AuditQuery,
    CancelRunCommand, ChannelMappingCommand, ChannelMappingQuery, CreateRunCommand,
    PluginActionCommand, PluginDetailsQuery, PluginReviewQuery, ServiceError,
};

pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/api/v1/workspaces/{workspace_id}/runs", post(create_run))
        .route(
            "/api/v1/workspaces/{workspace_id}/approvals/{approval_id}/decision",
            post(decide_approval),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/approvals",
            get(list_approvals),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/cancel",
            post(cancel_run),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runs/{run_id}/events",
            get(run_events),
        )
        .route("/api/v1/workspaces/{workspace_id}/audit", get(list_audit))
        .route(
            "/api/v1/workspaces/{workspace_id}/plugins/staged",
            get(list_staged_plugins),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/plugins/{plugin_id}/versions/{plugin_version}",
            get(plugin_details),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/plugins/actions",
            post(request_plugin_action),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/runtime/capabilities",
            get(runtime_capabilities),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/egress/channels",
            get(list_channel_mappings).post(update_channel_mapping),
        )
        .layer(middleware::from_fn_with_state(state.clone(), authenticate))
        .with_state(state)
}

#[derive(Serialize)]
struct RuntimeCapabilitiesResponse {
    sandbox: crate::SandboxCapabilityReport,
}

async fn runtime_capabilities(
    State(state): State<ApiState>,
    Path(workspace): Path<String>,
) -> Result<Json<RuntimeCapabilitiesResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    Ok(Json(RuntimeCapabilitiesResponse {
        sandbox: state.sandbox().clone(),
    }))
}

#[derive(Serialize)]
struct ChannelMappingsResponse {
    mappings: Vec<crate::ChannelMappingReview>,
}

async fn list_channel_mappings(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<ChannelMappingsResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let mappings = state
        .service
        .list_channel_mappings(ChannelMappingQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(ChannelMappingsResponse { mappings }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelMappingBody {
    provider: String,
    external_workspace_id: String,
    channel_id: String,
    external_user_id: String,
    lumen_provider: String,
    lumen_subject: String,
    allowed: bool,
}

async fn update_channel_mapping(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    body: Result<Json<ChannelMappingBody>, JsonRejection>,
) -> Result<Json<crate::ChannelMappingReview>, ApiError> {
    let Json(body) =
        body.map_err(|_| ApiError::BadRequest("invalid channel mapping body".into()))?;
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let external = ExternalChannelIdentity::new(
        body.provider,
        body.external_workspace_id,
        body.channel_id,
        body.external_user_id,
    )
    .map_err(|_| ApiError::BadRequest("invalid external channel identity".into()))?;
    let principal = PrincipalId::new(body.lumen_provider, body.lumen_subject)
        .map_err(|_| ApiError::BadRequest("invalid Lumen identity".into()))?;
    let mapping = state
        .service
        .update_channel_mapping(ChannelMappingCommand::new(
            workspace_id,
            actor,
            external,
            principal,
            body.allowed,
        ))
        .await?;
    Ok(Json(mapping))
}

async fn authenticate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let Some(principal) = state.authenticate(authorization) else {
        return ApiError::Unauthorized.into_response();
    };
    request.extensions_mut().insert(principal);
    next.run(request).await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRunBody {
    prompt: String,
    data_class: Option<DataClass>,
}

async fn create_run(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    Json(body): Json<CreateRunBody>,
) -> Result<impl IntoResponse, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    if body.prompt.trim().is_empty() || body.prompt.len() > 256 * 1024 {
        return Err(ApiError::BadRequest("prompt is empty or too large".into()));
    }
    if body.data_class == Some(DataClass::Secret) {
        return Err(ApiError::BadRequest(
            "secret data may not enter model context".into(),
        ));
    }
    let result = state
        .service
        .create_run(
            CreateRunCommand::new(workspace_id, actor, body.prompt)
                .with_data_class(body.data_class.unwrap_or(DataClass::Workspace)),
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalDecisionBody {
    decision: ApprovalDecision,
}

async fn decide_approval(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path((workspace, approval)): Path<(String, String)>,
    Json(body): Json<ApprovalDecisionBody>,
) -> Result<Json<crate::ApprovalResult>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let approval_id = parse_approval(&approval)?;
    let result = state
        .service
        .decide_approval(ApprovalDecisionCommand::new(
            workspace_id,
            approval_id,
            actor,
            body.decision,
        ))
        .await?;
    Ok(Json(result))
}

#[derive(Serialize)]
struct ApprovalListResponse {
    approvals: Vec<crate::ApprovalPreview>,
}

async fn list_approvals(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<ApprovalListResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let approvals = state
        .service
        .list_approvals(ApprovalQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(ApprovalListResponse { approvals }))
}

async fn cancel_run(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path((workspace, run)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let run_id = parse_run(&run)?;
    let result = state
        .service
        .cancel_run(CancelRunCommand::new(workspace_id, run_id, actor))
        .await?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

async fn run_events(
    State(state): State<ApiState>,
    Path((workspace, run)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let run_id = parse_run(&run)?;
    let after = headers
        .get("last-event-id")
        .map(|value| {
            value
                .to_str()
                .map_err(|_| ApiError::BadRequest("invalid Last-Event-ID".into()))?
                .parse::<u64>()
                .map_err(|_| ApiError::BadRequest("invalid Last-Event-ID".into()))
        })
        .transpose()?
        .unwrap_or(0);
    Ok(Sse::new(state.events.subscribe(
        workspace_id,
        run_id,
        after,
    )))
}

#[derive(Deserialize)]
struct AuditParameters {
    #[serde(default)]
    after: i64,
    #[serde(default = "default_audit_limit")]
    limit: u16,
}

const fn default_audit_limit() -> u16 {
    100
}

#[derive(Serialize)]
struct AuditResponse {
    events: Vec<crate::AuditEntry>,
}

async fn list_audit(
    State(state): State<ApiState>,
    Path(workspace): Path<String>,
    Query(parameters): Query<AuditParameters>,
) -> Result<Json<AuditResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    if parameters.after < 0 || parameters.limit == 0 || parameters.limit > 200 {
        return Err(ApiError::BadRequest("invalid audit page bounds".into()));
    }
    let events = state
        .service
        .list_audit(AuditQuery::new(
            workspace_id,
            parameters.after,
            parameters.limit,
        ))
        .await?;
    Ok(Json(AuditResponse { events }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginPageParameters {
    #[serde(default)]
    after: u64,
    #[serde(default = "default_plugin_limit")]
    limit: u16,
}

const fn default_plugin_limit() -> u16 {
    50
}

#[derive(Serialize)]
struct StagedPluginsResponse {
    packages: Vec<crate::StagedPluginReview>,
}

async fn list_staged_plugins(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    Query(parameters): Query<PluginPageParameters>,
) -> Result<Json<StagedPluginsResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    if parameters.limit == 0 || parameters.limit > 100 {
        return Err(ApiError::BadRequest("invalid plugin page bounds".into()));
    }
    let packages = state
        .service
        .list_staged_plugins(PluginReviewQuery::new(
            workspace_id,
            actor,
            parameters.after,
            parameters.limit,
        ))
        .await?;
    Ok(Json(StagedPluginsResponse { packages }))
}

async fn plugin_details(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path((workspace, plugin_id, plugin_version)): Path<(String, String, String)>,
) -> Result<Json<crate::PluginVersionDetails>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    validate_plugin_identity(&plugin_id, &plugin_version)?;
    let details = state
        .service
        .plugin_details(PluginDetailsQuery::new(
            workspace_id,
            actor,
            plugin_id,
            plugin_version,
        ))
        .await?;
    Ok(Json(details))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginActionBody {
    kind: String,
    plugin_id: String,
    plugin_version: String,
    expected_digest: String,
    arguments: Option<CanonicalValue>,
}

async fn request_plugin_action(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    body: Result<Json<PluginActionBody>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::BadRequest("invalid plugin action body".into()))?;
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    validate_plugin_identity(&body.plugin_id, &body.plugin_version)?;
    validate_digest(&body.expected_digest)?;
    if !matches!(
        body.kind.as_str(),
        "plugin.install"
            | "plugin.enable"
            | "plugin.disable"
            | "plugin.capabilities.set"
            | "plugin.settings.set"
            | "plugin.quarantine.release"
    ) {
        return Err(ApiError::BadRequest("unsupported plugin action".into()));
    }
    let result = state
        .service
        .request_plugin_action(PluginActionCommand::new(
            workspace_id,
            actor,
            body.kind,
            body.plugin_id,
            body.plugin_version,
            body.expected_digest,
            body.arguments,
        ))
        .await?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

fn ensure_workspace(state: &ApiState, workspace_id: WorkspaceId) -> Result<(), ApiError> {
    if state.allows_workspace(workspace_id) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

fn parse_workspace(value: &str) -> Result<WorkspaceId, ApiError> {
    parse_uuid(value).map(WorkspaceId::from_uuid)
}

fn parse_run(value: &str) -> Result<RunId, ApiError> {
    parse_uuid(value).map(RunId::from_uuid)
}

fn parse_approval(value: &str) -> Result<ApprovalId, ApiError> {
    parse_uuid(value).map(ApprovalId::from_uuid)
}

fn validate_plugin_identity(plugin_id: &str, plugin_version: &str) -> Result<(), ApiError> {
    PluginId::parse(plugin_id).map_err(|_| ApiError::BadRequest("invalid plugin id".into()))?;
    PluginVersion::parse(plugin_version)
        .map_err(|_| ApiError::BadRequest("invalid plugin version".into()))?;
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), ApiError> {
    Sha256Digest::parse(value).map_err(|_| ApiError::BadRequest("invalid digest".into()))?;
    Ok(())
}

fn parse_uuid(value: &str) -> Result<Uuid, ApiError> {
    Uuid::from_str(value).map_err(|_| ApiError::BadRequest("invalid resource identifier".into()))
}

#[derive(Debug)]
enum ApiError {
    Unauthorized,
    Forbidden,
    BadRequest(String),
    Service(ServiceError),
}

impl From<ServiceError> for ApiError {
    fn from(error: ServiceError) -> Self {
        Self::Service(error)
    }
}

#[derive(Serialize)]
struct ErrorEnvelope {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: &'static str,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            Self::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "local authentication failed".to_owned(),
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "workspace_forbidden",
                "workspace is not allowlisted".to_owned(),
            ),
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, "bad_request", message),
            Self::Service(ServiceError::NotFound) => (
                StatusCode::NOT_FOUND,
                "not_found",
                "resource was not found".to_owned(),
            ),
            Self::Service(ServiceError::Conflict(message)) => {
                (StatusCode::CONFLICT, "conflict", message)
            }
            Self::Service(ServiceError::Unavailable(message)) => {
                (StatusCode::SERVICE_UNAVAILABLE, "unavailable", message)
            }
            Self::Service(ServiceError::Internal(_)) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "runtime service failed".to_owned(),
            ),
        };
        let mut response = (
            status,
            Json(ErrorEnvelope {
                error: ErrorBody { code, message },
            }),
        )
            .into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
