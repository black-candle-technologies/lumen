use std::str::FromStr;

use axum::{
    Extension, Json, Router,
    extract::rejection::JsonRejection,
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response, Sse},
    routing::{get, post},
};
use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::ApprovalId,
    automation::{JobId, ScheduleSpec, SkillId, SkillVersion},
    egress::{DataClass, DestinationScope, ProviderId},
    extension::{PluginId, PluginVersion, Sha256Digest},
    identity::{ExternalChannelIdentity, PrincipalId, WorkspaceId},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    ApiState, ApprovalDecision, ApprovalDecisionCommand, ApprovalQuery, AuditQuery,
    CancelRunCommand, CaptureWorkflowCommand, ChannelMappingCommand, ChannelMappingQuery,
    CreateRunCommand, DestinationPolicyCommand, DestinationPolicyQuery, JobActionCommand,
    JobReviewQuery, PluginActionCommand, PluginDetailsQuery, PluginReviewQuery,
    ProviderPolicyCommand, ProviderPolicyQuery, ServiceError, ServiceIdentityCommand,
    ServiceIdentityQuery, SkillActionCommand, SkillReviewQuery,
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
        .route(
            "/api/v1/workspaces/{workspace_id}/egress/destinations",
            get(list_destination_policies).post(update_destination_policy),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/egress/providers",
            get(list_provider_policies).post(update_provider_policy),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/automation/service-identities",
            get(list_service_identities).post(update_service_identity),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/automation/jobs",
            get(list_jobs),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/automation/jobs/{job_id}",
            post(request_job_action),
        )
        .route("/api/v1/workspaces/{workspace_id}/skills", get(list_skills))
        .route(
            "/api/v1/workspaces/{workspace_id}/skills/capture-drafts",
            get(list_capture_drafts).post(capture_workflow),
        )
        .route(
            "/api/v1/workspaces/{workspace_id}/skills/capture-drafts/{draft_id}/publish",
            post(publish_capture_draft),
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

#[derive(Serialize)]
struct DestinationPoliciesResponse {
    destinations: Vec<crate::DestinationPolicyReview>,
}

async fn list_destination_policies(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<DestinationPoliciesResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let destinations = state
        .service
        .list_destination_policies(DestinationPolicyQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(DestinationPoliciesResponse { destinations }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationPolicyBody {
    destination: String,
    enabled: bool,
    allowed_data_classes: Vec<DataClass>,
}

async fn update_destination_policy(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    body: Result<Json<DestinationPolicyBody>, JsonRejection>,
) -> Result<Json<crate::DestinationPolicyReview>, ApiError> {
    let Json(body) =
        body.map_err(|_| ApiError::BadRequest("invalid destination policy body".into()))?;
    if body.allowed_data_classes.is_empty()
        || body.allowed_data_classes.contains(&DataClass::Secret)
    {
        return Err(ApiError::BadRequest(
            "destination policy data classes are invalid".into(),
        ));
    }
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let destination = DestinationScope::parse(body.destination)
        .map_err(|_| ApiError::BadRequest("invalid destination scope".into()))?;
    let policy = state
        .service
        .update_destination_policy(DestinationPolicyCommand::new(
            workspace_id,
            actor,
            destination,
            body.enabled,
            body.allowed_data_classes,
        ))
        .await?;
    Ok(Json(policy))
}

#[derive(Serialize)]
struct ProviderPoliciesResponse {
    providers: Vec<crate::ProviderPolicyReview>,
}

async fn list_provider_policies(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<ProviderPoliciesResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let providers = state
        .service
        .list_provider_policies(ProviderPolicyQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(ProviderPoliciesResponse { providers }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderPolicyBody {
    provider_id: String,
    enabled: bool,
    workspace_allowed_data_classes: Vec<DataClass>,
}

async fn update_provider_policy(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    body: Result<Json<ProviderPolicyBody>, JsonRejection>,
) -> Result<Json<crate::ProviderPolicyReview>, ApiError> {
    let Json(body) =
        body.map_err(|_| ApiError::BadRequest("invalid provider policy body".into()))?;
    if body.workspace_allowed_data_classes.is_empty()
        || body
            .workspace_allowed_data_classes
            .contains(&DataClass::Secret)
    {
        return Err(ApiError::BadRequest(
            "provider policy data classes are invalid".into(),
        ));
    }
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let provider_id = ProviderId::parse(body.provider_id)
        .map_err(|_| ApiError::BadRequest("invalid provider id".into()))?;
    let policy = state
        .service
        .update_provider_policy(ProviderPolicyCommand::new(
            workspace_id,
            actor,
            provider_id,
            body.enabled,
            body.workspace_allowed_data_classes,
        ))
        .await?;
    Ok(Json(policy))
}

#[derive(Serialize)]
struct ServiceIdentitiesResponse {
    service_identities: Vec<crate::ServiceIdentityReview>,
}

async fn list_service_identities(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<ServiceIdentitiesResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let service_identities = state
        .service
        .list_service_identities(ServiceIdentityQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(ServiceIdentitiesResponse { service_identities }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceIdentityBody {
    subject: String,
    label: String,
    enabled: bool,
    grants: Vec<CanonicalValue>,
}

async fn update_service_identity(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    body: Result<Json<ServiceIdentityBody>, JsonRejection>,
) -> Result<Json<crate::ServiceIdentityReview>, ApiError> {
    let Json(body) =
        body.map_err(|_| ApiError::BadRequest("invalid service identity body".into()))?;
    if body.label.trim().is_empty() || body.label.len() > 128 || body.grants.len() > 64 {
        return Err(ApiError::BadRequest("invalid service identity".into()));
    }
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let principal = PrincipalId::new("service", body.subject)
        .map_err(|_| ApiError::BadRequest("invalid service identity".into()))?;
    let review = state
        .service
        .update_service_identity(ServiceIdentityCommand::new(
            workspace_id,
            actor,
            principal,
            body.label,
            body.enabled,
            body.grants,
        ))
        .await?;
    Ok(Json(review))
}

#[derive(Serialize)]
struct JobsResponse {
    jobs: Vec<crate::JobReview>,
}

async fn list_jobs(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<JobsResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let jobs = state
        .service
        .list_jobs(JobReviewQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(JobsResponse { jobs }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobActionBody {
    service_subject: String,
    schedule: ScheduleSpec,
    prompt: String,
    data_class: DataClass,
    max_model_turns: u32,
    max_actions: u32,
    enabled: bool,
    idempotent: bool,
}

async fn request_job_action(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path((workspace, job)): Path<(String, String)>,
    body: Result<Json<JobActionBody>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::BadRequest("invalid job body".into()))?;
    if body.prompt.trim().is_empty()
        || body.prompt.len() > 8192
        || body.data_class == DataClass::Secret
        || body.max_model_turns == 0
        || body.max_actions == 0
        || matches!(
            body.schedule,
            ScheduleSpec::Interval {
                interval_millis: 0,
                ..
            }
        )
    {
        return Err(ApiError::BadRequest("invalid job body".into()));
    }
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let job_id = parse_job(&job)?;
    let service = PrincipalId::new("service", body.service_subject)
        .map_err(|_| ApiError::BadRequest("invalid service identity".into()))?;
    let result = state
        .service
        .request_job_action(JobActionCommand::new(
            workspace_id,
            actor,
            job_id,
            service,
            body.schedule,
            body.prompt,
            body.data_class,
            body.max_model_turns,
            body.max_actions,
            body.enabled,
            body.idempotent,
        ))
        .await?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

#[derive(Serialize)]
struct SkillsResponse {
    skills: Vec<crate::SkillReview>,
}

async fn list_skills(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<SkillsResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let skills = state
        .service
        .list_skills(SkillReviewQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(SkillsResponse { skills }))
}

#[derive(Serialize)]
struct CaptureDraftsResponse {
    drafts: Vec<crate::WorkflowCaptureDraftReview>,
}

async fn list_capture_drafts(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
) -> Result<Json<CaptureDraftsResponse>, ApiError> {
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let drafts = state
        .service
        .list_capture_drafts(SkillReviewQuery::new(workspace_id, actor))
        .await?;
    Ok(Json(CaptureDraftsResponse { drafts }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureWorkflowBody {
    run_id: RunId,
}

async fn capture_workflow(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path(workspace): Path<String>,
    body: Result<Json<CaptureWorkflowBody>, JsonRejection>,
) -> Result<Json<crate::WorkflowCaptureDraftReview>, ApiError> {
    let Json(body) =
        body.map_err(|_| ApiError::BadRequest("invalid workflow capture body".into()))?;
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let draft = state
        .service
        .capture_workflow(CaptureWorkflowCommand::new(
            workspace_id,
            actor,
            body.run_id,
        ))
        .await?;
    Ok(Json(draft))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublishCaptureDraftBody {
    skill_id: SkillId,
    version: String,
    name: String,
    description: String,
}

async fn publish_capture_draft(
    State(state): State<ApiState>,
    Extension(actor): Extension<PrincipalId>,
    Path((workspace, draft)): Path<(String, String)>,
    body: Result<Json<PublishCaptureDraftBody>, JsonRejection>,
) -> Result<impl IntoResponse, ApiError> {
    let Json(body) = body.map_err(|_| ApiError::BadRequest("invalid skill publish body".into()))?;
    if body.name.trim().is_empty() || body.name.len() > 128 || body.description.len() > 2048 {
        return Err(ApiError::BadRequest("invalid skill publish body".into()));
    }
    let workspace_id = parse_workspace(&workspace)?;
    ensure_workspace(&state, workspace_id)?;
    let draft_id = Uuid::parse_str(&draft)
        .map_err(|_| ApiError::BadRequest("invalid resource identifier".into()))?;
    let version = SkillVersion::parse(body.version)
        .map_err(|_| ApiError::BadRequest("invalid skill version".into()))?;
    let result = state
        .service
        .request_skill_action(SkillActionCommand::publish(
            workspace_id,
            actor,
            draft_id,
            body.skill_id,
            version,
            body.name,
            body.description,
        ))
        .await?;
    Ok((StatusCode::ACCEPTED, Json(result)))
}

async fn authenticate(
    State(state): State<ApiState>,
    headers: HeaderMap,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    if request.method() == Method::OPTIONS {
        return with_local_cors(StatusCode::NO_CONTENT.into_response());
    }
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let Some(principal) = state.authenticate(authorization) else {
        return with_local_cors(ApiError::Unauthorized.into_response());
    };
    request.extensions_mut().insert(principal);
    with_local_cors(next.run(request).await)
}

fn with_local_cors(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET,POST,OPTIONS"),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("authorization,content-type,last-event-id"),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    response
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

fn parse_job(value: &str) -> Result<JobId, ApiError> {
    parse_uuid(value).map(JobId::from_uuid)
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
