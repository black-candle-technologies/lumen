use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use lumen_core::{
    action::{CanonicalValue, RunId},
    approval::{ApprovalId, TimestampMillis},
    audit::{AuditEventId, AuditEventKind, AuditOutcome},
    automation::{JobId, JobRevision, ScheduleSpec, SkillId, SkillVersion},
    egress::{DataClass, DestinationScope, EndpointClass, ProviderId},
    identity::{ExternalChannelIdentity, PrincipalId, WorkspaceId},
    secret::SecretRefId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;

use crate::EventBroker;

pub type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ServiceError>> + Send + 'a>>;

pub trait RuntimeService: Send + Sync {
    fn create_run(&self, command: CreateRunCommand) -> ServiceFuture<'_, RunCreated>;
    fn decide_approval(
        &self,
        command: ApprovalDecisionCommand,
    ) -> ServiceFuture<'_, ApprovalResult>;
    fn list_audit(&self, query: AuditQuery) -> ServiceFuture<'_, Vec<AuditEntry>>;
    fn list_approvals(&self, query: ApprovalQuery) -> ServiceFuture<'_, Vec<ApprovalPreview>>;
    fn cancel_run(&self, command: CancelRunCommand) -> ServiceFuture<'_, RunCancellation>;
    fn list_staged_plugins(
        &self,
        query: PluginReviewQuery,
    ) -> ServiceFuture<'_, Vec<StagedPluginReview>>;
    fn plugin_details(&self, query: PluginDetailsQuery) -> ServiceFuture<'_, PluginVersionDetails>;
    fn request_plugin_action(
        &self,
        command: PluginActionCommand,
    ) -> ServiceFuture<'_, PluginActionRequested>;
    fn list_channel_mappings(
        &self,
        query: ChannelMappingQuery,
    ) -> ServiceFuture<'_, Vec<ChannelMappingReview>>;
    fn update_channel_mapping(
        &self,
        command: ChannelMappingCommand,
    ) -> ServiceFuture<'_, ChannelMappingReview>;
    fn list_destination_policies(
        &self,
        query: DestinationPolicyQuery,
    ) -> ServiceFuture<'_, Vec<DestinationPolicyReview>>;
    fn update_destination_policy(
        &self,
        command: DestinationPolicyCommand,
    ) -> ServiceFuture<'_, DestinationPolicyReview>;
    fn list_provider_policies(
        &self,
        query: ProviderPolicyQuery,
    ) -> ServiceFuture<'_, Vec<ProviderPolicyReview>>;
    fn update_provider_policy(
        &self,
        command: ProviderPolicyCommand,
    ) -> ServiceFuture<'_, ProviderPolicyReview>;
    fn list_service_identities(
        &self,
        query: ServiceIdentityQuery,
    ) -> ServiceFuture<'_, Vec<ServiceIdentityReview>>;
    fn update_service_identity(
        &self,
        command: ServiceIdentityCommand,
    ) -> ServiceFuture<'_, ServiceIdentityReview>;
    fn list_jobs(&self, query: JobReviewQuery) -> ServiceFuture<'_, Vec<JobReview>>;
    fn request_job_action(
        &self,
        command: JobActionCommand,
    ) -> ServiceFuture<'_, AutomationActionRequested>;
    fn list_skills(&self, query: SkillReviewQuery) -> ServiceFuture<'_, Vec<SkillReview>>;
    fn request_skill_action(
        &self,
        command: SkillActionCommand,
    ) -> ServiceFuture<'_, AutomationActionRequested>;
    fn list_capture_drafts(
        &self,
        query: SkillReviewQuery,
    ) -> ServiceFuture<'_, Vec<WorkflowCaptureDraftReview>>;
    fn capture_workflow(
        &self,
        command: CaptureWorkflowCommand,
    ) -> ServiceFuture<'_, WorkflowCaptureDraftReview>;
}

#[derive(Clone)]
pub struct ApiState {
    pub(crate) service: Arc<dyn RuntimeService>,
    pub(crate) events: EventBroker,
    authentication: Arc<LocalAuthentication>,
    sandbox: SandboxCapabilityReport,
}

impl ApiState {
    pub fn new(
        service: Arc<dyn RuntimeService>,
        events: EventBroker,
        bearer_token: impl Into<String>,
        principal: PrincipalId,
        allowed_workspaces: BTreeSet<WorkspaceId>,
        sandbox: SandboxCapabilityReport,
    ) -> Result<Self, ApiStateError> {
        let bearer_token = bearer_token.into();
        if bearer_token.len() < 16 || bearer_token.len() > 4096 {
            return Err(ApiStateError::InvalidBearerToken);
        }
        if allowed_workspaces.is_empty() {
            return Err(ApiStateError::NoAllowedWorkspaces);
        }
        Ok(Self {
            service,
            events,
            authentication: Arc::new(LocalAuthentication {
                bearer_token_hash: Sha256::digest(bearer_token).into(),
                principal,
                allowed_workspaces,
            }),
            sandbox,
        })
    }

    pub(crate) fn authenticate(&self, authorization: Option<&str>) -> Option<PrincipalId> {
        let candidate = authorization?.strip_prefix("Bearer ")?;
        let candidate: [u8; 32] = Sha256::digest(candidate).into();
        let valid = bool::from(self.authentication.bearer_token_hash.ct_eq(&candidate));
        valid.then(|| self.authentication.principal.clone())
    }

    pub(crate) fn allows_workspace(&self, workspace_id: WorkspaceId) -> bool {
        self.authentication
            .allowed_workspaces
            .contains(&workspace_id)
    }

    pub(crate) const fn sandbox(&self) -> &SandboxCapabilityReport {
        &self.sandbox
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SandboxCapabilityReport {
    backend: String,
    strength: String,
    guarantees: BTreeSet<String>,
    detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginReviewQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    after: u64,
    limit: u16,
}

impl PluginReviewQuery {
    pub(crate) const fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        after: u64,
        limit: u16,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            after,
            limit,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn after(&self) -> u64 {
        self.after
    }

    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginDetailsQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    plugin_id: String,
    plugin_version: String,
}

impl PluginDetailsQuery {
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        plugin_id: String,
        plugin_version: String,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            plugin_id,
            plugin_version,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PluginActionCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    kind: String,
    plugin_id: String,
    plugin_version: String,
    expected_digest: String,
    arguments: Option<CanonicalValue>,
}

impl PluginActionCommand {
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        kind: String,
        plugin_id: String,
        plugin_version: String,
        expected_digest: String,
        arguments: Option<CanonicalValue>,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            kind,
            plugin_id,
            plugin_version,
            expected_digest,
            arguments,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn plugin_version(&self) -> &str {
        &self.plugin_version
    }

    pub fn expected_digest(&self) -> &str {
        &self.expected_digest
    }

    pub const fn arguments(&self) -> Option<&CanonicalValue> {
        self.arguments.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PrincipalSummary {
    provider: String,
    subject: String,
}

impl PrincipalSummary {
    pub fn new(principal: &PrincipalId) -> Self {
        Self {
            provider: principal.provider().to_owned(),
            subject: principal.subject().to_owned(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StagedPluginReview {
    stage_id: String,
    plugin_id: String,
    version: String,
    runtime: String,
    package_digest: String,
    manifest_digest: String,
    artifact_digest: String,
    file_hashes: BTreeMap<String, String>,
    requested_by: PrincipalSummary,
    created_at: TimestampMillis,
}

impl StagedPluginReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stage_id: impl Into<String>,
        plugin_id: impl Into<String>,
        version: impl Into<String>,
        runtime: impl Into<String>,
        package_digest: impl Into<String>,
        manifest_digest: impl Into<String>,
        artifact_digest: impl Into<String>,
        file_hashes: BTreeMap<String, String>,
        requested_by: PrincipalSummary,
        created_at: TimestampMillis,
    ) -> Self {
        Self {
            stage_id: stage_id.into(),
            plugin_id: plugin_id.into(),
            version: version.into(),
            runtime: runtime.into(),
            package_digest: package_digest.into(),
            manifest_digest: manifest_digest.into(),
            artifact_digest: artifact_digest.into(),
            file_hashes,
            requested_by,
            created_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginVersionDetails {
    plugin_id: String,
    version: String,
    state: String,
    package_digest: String,
    manifest_digest: String,
    artifact_digest: String,
    components: Vec<PluginComponentReview>,
    settings: Vec<PluginSettingReview>,
    failures: Vec<PluginFailureReview>,
}

impl PluginVersionDetails {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_id: impl Into<String>,
        version: impl Into<String>,
        state: impl Into<String>,
        package_digest: impl Into<String>,
        manifest_digest: impl Into<String>,
        artifact_digest: impl Into<String>,
        components: Vec<PluginComponentReview>,
        settings: Vec<PluginSettingReview>,
        failures: Vec<PluginFailureReview>,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            version: version.into(),
            state: state.into(),
            package_digest: package_digest.into(),
            manifest_digest: manifest_digest.into(),
            artifact_digest: artifact_digest.into(),
            components,
            settings,
            failures,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginComponentReview {
    id: String,
    kind: String,
    requested_capabilities: Vec<CanonicalValue>,
    effective_grants: Vec<CanonicalValue>,
    grant_revision: u64,
    grant_set_digest: String,
}

impl PluginComponentReview {
    pub fn new(
        id: impl Into<String>,
        kind: impl Into<String>,
        requested_capabilities: Vec<CanonicalValue>,
        effective_grants: Vec<CanonicalValue>,
        grant_revision: u64,
        grant_set_digest: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind: kind.into(),
            requested_capabilities,
            effective_grants,
            grant_revision,
            grant_set_digest: grant_set_digest.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginSettingReview {
    scope_type: String,
    scope_id: String,
    config_version: u64,
    config: serde_json::Value,
    schema_digest: String,
    settings_digest: String,
}

impl PluginSettingReview {
    pub fn new(
        scope_type: impl Into<String>,
        scope_id: impl Into<String>,
        config_version: u64,
        config: serde_json::Value,
        schema_digest: impl Into<String>,
        settings_digest: impl Into<String>,
    ) -> Self {
        Self {
            scope_type: scope_type.into(),
            scope_id: scope_id.into(),
            config_version,
            config,
            schema_digest: schema_digest.into(),
            settings_digest: settings_digest.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginFailureReview {
    class: String,
    count: u64,
    diagnostic: String,
    diagnostic_digest: String,
    last_seen_at: TimestampMillis,
}

impl PluginFailureReview {
    pub fn new(
        class: impl Into<String>,
        count: u64,
        diagnostic: impl Into<String>,
        diagnostic_digest: impl Into<String>,
        last_seen_at: TimestampMillis,
    ) -> Self {
        Self {
            class: class.into(),
            count,
            diagnostic: diagnostic.into(),
            diagnostic_digest: diagnostic_digest.into(),
            last_seen_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PluginActionRequested {
    run_id: RunId,
    state: &'static str,
}

impl PluginActionRequested {
    pub const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            state: "approval_requested",
        }
    }
}

impl SandboxCapabilityReport {
    pub fn new<I, S>(
        backend: impl Into<String>,
        strength: impl Into<String>,
        guarantees: I,
        detail: Option<String>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            backend: backend.into(),
            strength: strength.into(),
            guarantees: guarantees.into_iter().map(Into::into).collect(),
            detail,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelMappingQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl ChannelMappingQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChannelMappingCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    external: ExternalChannelIdentity,
    principal: PrincipalId,
    allowed: bool,
}

impl ChannelMappingCommand {
    pub(crate) const fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        external: ExternalChannelIdentity,
        principal: PrincipalId,
        allowed: bool,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            external,
            principal,
            allowed,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn external(&self) -> &ExternalChannelIdentity {
        &self.external
    }

    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub const fn allowed(&self) -> bool {
        self.allowed
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ChannelMappingReview {
    provider: String,
    external_workspace_id: String,
    channel_id: String,
    external_user_id: String,
    lumen_identity: PrincipalSummary,
    workspace_id: WorkspaceId,
    allowed: bool,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl ChannelMappingReview {
    pub fn new(
        external: ExternalChannelIdentity,
        lumen_identity: PrincipalSummary,
        workspace_id: WorkspaceId,
        allowed: bool,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Self {
        Self {
            provider: external.provider().to_owned(),
            external_workspace_id: external.external_workspace_id().to_owned(),
            channel_id: external.channel_id().to_owned(),
            external_user_id: external.external_user_id().to_owned(),
            lumen_identity,
            workspace_id,
            allowed,
            created_at,
            updated_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationPolicyQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl DestinationPolicyQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationPolicyCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    destination: DestinationScope,
    enabled: bool,
    allowed_data_classes: Vec<DataClass>,
}

impl DestinationPolicyCommand {
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        destination: DestinationScope,
        enabled: bool,
        allowed_data_classes: Vec<DataClass>,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            destination,
            enabled,
            allowed_data_classes,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn destination(&self) -> &DestinationScope {
        &self.destination
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn allowed_data_classes(&self) -> &[DataClass] {
        &self.allowed_data_classes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DestinationPolicyReview {
    destination: String,
    revision: u64,
    enabled: bool,
    allowed_data_classes: Vec<DataClass>,
    created_at: TimestampMillis,
}

impl DestinationPolicyReview {
    pub fn new(
        destination: DestinationScope,
        revision: u64,
        enabled: bool,
        allowed_data_classes: Vec<DataClass>,
        created_at: TimestampMillis,
    ) -> Self {
        Self {
            destination: destination.as_str().to_owned(),
            revision,
            enabled,
            allowed_data_classes,
            created_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPolicyQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl ProviderPolicyQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderPolicyCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    provider_id: ProviderId,
    enabled: bool,
    workspace_allowed_data_classes: Vec<DataClass>,
}

impl ProviderPolicyCommand {
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        provider_id: ProviderId,
        enabled: bool,
        workspace_allowed_data_classes: Vec<DataClass>,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            provider_id,
            enabled,
            workspace_allowed_data_classes,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn workspace_allowed_data_classes(&self) -> &[DataClass] {
        &self.workspace_allowed_data_classes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkspaceModelPolicyReview {
    revision: u64,
    allowed_data_classes: Vec<DataClass>,
    created_at: TimestampMillis,
}

impl WorkspaceModelPolicyReview {
    pub fn new(
        revision: u64,
        allowed_data_classes: Vec<DataClass>,
        created_at: TimestampMillis,
    ) -> Self {
        Self {
            revision,
            allowed_data_classes,
            created_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderPolicyReview {
    provider_id: String,
    revision: u64,
    endpoint_class: EndpointClass,
    endpoint: String,
    model: String,
    enabled: bool,
    priority: u32,
    credential_configured: bool,
    allowed_data_classes: Vec<DataClass>,
    workspace_policy: Option<WorkspaceModelPolicyReview>,
    created_at: TimestampMillis,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval_run_id: Option<RunId>,
}

impl ProviderPolicyReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider_id: ProviderId,
        revision: u64,
        endpoint_class: EndpointClass,
        endpoint: DestinationScope,
        model: impl Into<String>,
        enabled: bool,
        priority: u32,
        credential_configured: bool,
        allowed_data_classes: Vec<DataClass>,
        workspace_policy: Option<WorkspaceModelPolicyReview>,
        created_at: TimestampMillis,
    ) -> Self {
        Self {
            provider_id: provider_id.as_str().to_owned(),
            revision,
            endpoint_class,
            endpoint: endpoint.as_str().to_owned(),
            model: model.into(),
            enabled,
            priority,
            credential_configured,
            allowed_data_classes,
            workspace_policy,
            created_at,
            state: None,
            approval_run_id: None,
        }
    }

    pub const fn with_approval_requested(mut self, run_id: RunId) -> Self {
        self.state = Some("approval_requested");
        self.approval_run_id = Some(run_id);
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceIdentityQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl ServiceIdentityQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceIdentityCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    principal: PrincipalId,
    label: String,
    enabled: bool,
    grants: Vec<CanonicalValue>,
}

impl ServiceIdentityCommand {
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        principal: PrincipalId,
        label: String,
        enabled: bool,
        grants: Vec<CanonicalValue>,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            principal,
            label,
            enabled,
            grants,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn grants(&self) -> &[CanonicalValue] {
        &self.grants
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ServiceIdentityReview {
    principal: PrincipalSummary,
    workspace_id: WorkspaceId,
    owner: PrincipalSummary,
    label: String,
    enabled: bool,
    grants: Vec<CanonicalValue>,
    created_at: TimestampMillis,
    updated_at: TimestampMillis,
}

impl ServiceIdentityReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        principal: PrincipalSummary,
        workspace_id: WorkspaceId,
        owner: PrincipalSummary,
        label: impl Into<String>,
        enabled: bool,
        grants: Vec<CanonicalValue>,
        created_at: TimestampMillis,
        updated_at: TimestampMillis,
    ) -> Self {
        Self {
            principal,
            workspace_id,
            owner,
            label: label.into(),
            enabled,
            grants,
            created_at,
            updated_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobReviewQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl JobReviewQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JobActionCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    job_id: JobId,
    service: PrincipalId,
    schedule: ScheduleSpec,
    prompt: String,
    data_class: DataClass,
    max_model_turns: u32,
    max_actions: u32,
    enabled: bool,
    idempotent: bool,
}

impl JobActionCommand {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        job_id: JobId,
        service: PrincipalId,
        schedule: ScheduleSpec,
        prompt: String,
        data_class: DataClass,
        max_model_turns: u32,
        max_actions: u32,
        enabled: bool,
        idempotent: bool,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            job_id,
            service,
            schedule,
            prompt,
            data_class,
            max_model_turns,
            max_actions,
            enabled,
            idempotent,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn job_id(&self) -> JobId {
        self.job_id
    }

    pub const fn service(&self) -> &PrincipalId {
        &self.service
    }

    pub const fn schedule(&self) -> ScheduleSpec {
        self.schedule
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }

    pub const fn max_model_turns(&self) -> u32 {
        self.max_model_turns
    }

    pub const fn max_actions(&self) -> u32 {
        self.max_actions
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn idempotent(&self) -> bool {
        self.idempotent
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JobReview {
    job_id: JobId,
    revision: JobRevision,
    workspace_id: WorkspaceId,
    service: PrincipalSummary,
    owner: PrincipalSummary,
    schedule: ScheduleSpec,
    prompt: String,
    data_class: DataClass,
    max_model_turns: u32,
    max_actions: u32,
    enabled: bool,
    next_due_at: Option<TimestampMillis>,
    idempotent: bool,
    created_at: TimestampMillis,
}

impl JobReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        job_id: JobId,
        revision: JobRevision,
        workspace_id: WorkspaceId,
        service: PrincipalSummary,
        owner: PrincipalSummary,
        schedule: ScheduleSpec,
        prompt: impl Into<String>,
        data_class: DataClass,
        max_model_turns: u32,
        max_actions: u32,
        enabled: bool,
        next_due_at: Option<TimestampMillis>,
        idempotent: bool,
        created_at: TimestampMillis,
    ) -> Self {
        Self {
            job_id,
            revision,
            workspace_id,
            service,
            owner,
            schedule,
            prompt: prompt.into(),
            data_class,
            max_model_turns,
            max_actions,
            enabled,
            next_due_at,
            idempotent,
            created_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillReviewQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl SkillReviewQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillActionCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    kind: String,
    draft_id: Option<Uuid>,
    skill_id: SkillId,
    version: SkillVersion,
    name: String,
    description: String,
}

impl SkillActionCommand {
    pub(crate) fn publish(
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        draft_id: Uuid,
        skill_id: SkillId,
        version: SkillVersion,
        name: String,
        description: String,
    ) -> Self {
        Self {
            workspace_id,
            actor,
            kind: "skill.publish".to_owned(),
            draft_id: Some(draft_id),
            skill_id,
            version,
            name,
            description,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub const fn draft_id(&self) -> Option<Uuid> {
        self.draft_id
    }

    pub const fn skill_id(&self) -> SkillId {
        self.skill_id
    }

    pub const fn version(&self) -> &SkillVersion {
        &self.version
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SkillReview {
    skill_id: SkillId,
    version: SkillVersion,
    workspace_id: WorkspaceId,
    name: String,
    description: String,
    source_format: String,
    source_digest: String,
    reviewed: bool,
    enabled: bool,
    created_by: PrincipalSummary,
    reviewed_by: Option<PrincipalSummary>,
    created_at: TimestampMillis,
    reviewed_at: Option<TimestampMillis>,
}

impl SkillReview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        skill_id: SkillId,
        version: SkillVersion,
        workspace_id: WorkspaceId,
        name: impl Into<String>,
        description: impl Into<String>,
        source_format: impl Into<String>,
        source_digest: impl Into<String>,
        reviewed: bool,
        enabled: bool,
        created_by: PrincipalSummary,
        reviewed_by: Option<PrincipalSummary>,
        created_at: TimestampMillis,
        reviewed_at: Option<TimestampMillis>,
    ) -> Self {
        Self {
            skill_id,
            version,
            workspace_id,
            name: name.into(),
            description: description.into(),
            source_format: source_format.into(),
            source_digest: source_digest.into(),
            reviewed,
            enabled,
            created_by,
            reviewed_by,
            created_at,
            reviewed_at,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureWorkflowCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    run_id: RunId,
}

impl CaptureWorkflowCommand {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId, run_id: RunId) -> Self {
        Self {
            workspace_id,
            actor,
            run_id,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkflowCaptureDraftReview {
    draft_id: Uuid,
    workspace_id: WorkspaceId,
    title: String,
    body: String,
    created_by: PrincipalSummary,
    created_at: TimestampMillis,
}

impl WorkflowCaptureDraftReview {
    pub fn new(
        draft_id: Uuid,
        workspace_id: WorkspaceId,
        title: impl Into<String>,
        body: impl Into<String>,
        created_by: PrincipalSummary,
        created_at: TimestampMillis,
    ) -> Self {
        Self {
            draft_id,
            workspace_id,
            title: title.into(),
            body: body.into(),
            created_by,
            created_at,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AutomationActionRequested {
    run_id: RunId,
    state: &'static str,
}

impl AutomationActionRequested {
    pub const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            state: "approval_requested",
        }
    }
}

struct LocalAuthentication {
    bearer_token_hash: [u8; 32],
    principal: PrincipalId,
    allowed_workspaces: BTreeSet<WorkspaceId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRunCommand {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    prompt: String,
    data_class: DataClass,
}

impl CreateRunCommand {
    pub fn new(workspace_id: WorkspaceId, actor: PrincipalId, prompt: String) -> Self {
        Self {
            workspace_id,
            actor,
            prompt,
            data_class: DataClass::Workspace,
        }
    }

    pub const fn with_data_class(mut self, data_class: DataClass) -> Self {
        self.data_class = data_class;
        self
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub fn prompt(&self) -> &str {
        &self.prompt
    }

    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RunCreated {
    run_id: RunId,
}

impl RunCreated {
    pub const fn new(run_id: RunId) -> Self {
        Self { run_id }
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    Grant,
    Reject,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalDecisionCommand {
    workspace_id: WorkspaceId,
    approval_id: ApprovalId,
    actor: PrincipalId,
    decision: ApprovalDecision,
}

impl ApprovalDecisionCommand {
    pub const fn new(
        workspace_id: WorkspaceId,
        approval_id: ApprovalId,
        actor: PrincipalId,
        decision: ApprovalDecision,
    ) -> Self {
        Self {
            workspace_id,
            approval_id,
            actor,
            decision,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn decision(&self) -> ApprovalDecision {
        self.decision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalResult {
    approval_id: ApprovalId,
    decision: ApprovalDecision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalQuery {
    workspace_id: WorkspaceId,
    actor: PrincipalId,
}

impl ApprovalQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalPreview {
    approval_id: ApprovalId,
    run_id: RunId,
    kind: String,
    arguments: CanonicalValue,
    capabilities: Vec<CanonicalValue>,
    fingerprint: String,
    created_at: TimestampMillis,
    expires_at: TimestampMillis,
    secret_references: Vec<ApprovalSecretReference>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ApprovalSecretReference {
    id: SecretRefId,
    label: String,
    environment: String,
}

impl ApprovalSecretReference {
    pub fn new(id: SecretRefId, label: impl Into<String>, environment: impl Into<String>) -> Self {
        Self {
            id,
            label: label.into(),
            environment: environment.into(),
        }
    }
}

impl ApprovalPreview {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        approval_id: ApprovalId,
        run_id: RunId,
        kind: impl Into<String>,
        arguments: CanonicalValue,
        capabilities: Vec<CanonicalValue>,
        fingerprint: impl Into<String>,
        created_at: TimestampMillis,
        expires_at: TimestampMillis,
    ) -> Self {
        Self {
            approval_id,
            run_id,
            kind: kind.into(),
            arguments,
            capabilities,
            fingerprint: fingerprint.into(),
            created_at,
            expires_at,
            secret_references: Vec::new(),
        }
    }

    pub fn with_secret_references(
        mut self,
        references: impl IntoIterator<Item = ApprovalSecretReference>,
    ) -> Self {
        self.secret_references = references.into_iter().collect();
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelRunCommand {
    workspace_id: WorkspaceId,
    run_id: RunId,
    actor: PrincipalId,
}

impl CancelRunCommand {
    pub(crate) const fn new(workspace_id: WorkspaceId, run_id: RunId, actor: PrincipalId) -> Self {
        Self {
            workspace_id,
            run_id,
            actor,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct RunCancellation {
    run_id: RunId,
    state: &'static str,
}

impl RunCancellation {
    pub const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            state: "cancellation_requested",
        }
    }
}

impl ApprovalResult {
    pub const fn new(approval_id: ApprovalId, decision: ApprovalDecision) -> Self {
        Self {
            approval_id,
            decision,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditQuery {
    workspace_id: WorkspaceId,
    after: i64,
    limit: u16,
}

impl AuditQuery {
    pub(crate) const fn new(workspace_id: WorkspaceId, after: i64, limit: u16) -> Self {
        Self {
            workspace_id,
            after,
            limit,
        }
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn after(&self) -> i64 {
        self.after
    }

    pub const fn limit(&self) -> u16 {
        self.limit
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AuditEntry {
    sequence: i64,
    event_id: AuditEventId,
    timestamp: TimestampMillis,
    kind: AuditEventKind,
    outcome: AuditOutcome,
    workspace_id: WorkspaceId,
    payload: CanonicalValue,
}

impl AuditEntry {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        sequence: i64,
        event_id: AuditEventId,
        timestamp: TimestampMillis,
        kind: AuditEventKind,
        outcome: AuditOutcome,
        workspace_id: WorkspaceId,
        payload: CanonicalValue,
    ) -> Self {
        Self {
            sequence,
            event_id,
            timestamp,
            kind,
            outcome,
            workspace_id,
            payload,
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServiceError {
    #[error("resource was not found")]
    NotFound,
    #[error("request conflicts with current runtime state: {0}")]
    Conflict(String),
    #[error("runtime prerequisite is unavailable: {0}")]
    Unavailable(String),
    #[error("runtime service failed: {0}")]
    Internal(String),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ApiStateError {
    #[error("local bearer token must contain between 16 and 4096 bytes")]
    InvalidBearerToken,
    #[error("at least one workspace must be allowlisted")]
    NoAllowedWorkspaces,
}
