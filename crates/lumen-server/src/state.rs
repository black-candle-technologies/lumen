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
    identity::{PrincipalId, WorkspaceId},
    secret::SecretRefId,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use thiserror::Error;

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
}

impl CreateRunCommand {
    pub fn new(workspace_id: WorkspaceId, actor: PrincipalId, prompt: String) -> Self {
        Self {
            workspace_id,
            actor,
            prompt,
        }
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
