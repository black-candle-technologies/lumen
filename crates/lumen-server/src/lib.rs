//! HTTP API and streaming server surface for Lumen.

mod authd;
mod jev;
mod kernel_authority;
mod kernel_channel;
mod kernel_client;
mod kernel_convert;
mod model_gateway;
mod orchestration;
pub mod pi_supervisor;
mod routes;
mod sandbox_driver;
mod session;
mod sse;
mod state;
mod tool_catalog;

pub use authd::{
    AccountId, AccountIdentity, AuthError, AuthFuture, AuthdClient, MockAuthdClient, SessionBinding,
};
pub use jev::{
    JevError, JevFuture, JevRecommendation, JevRouter, MockJevRouter, ModelSwitchDecision,
    SizeBucket, TaskProfile, apply_recommendation,
};
pub use kernel_authority::{
    AuthorityDb, AuthorityKernel, AuthorityKernelClient, AuthorityKernelConfig, PendingApprovalView,
};
pub use kernel_channel::{
    ChannelDecision, ChannelDeps, ChannelError, ChannelFuture, ChannelRequest, ChannelResponse,
    ChannelSession, ChannelSessionResolver, KERNEL_CHANNEL_PROTOCOL, KernelChannel,
    KernelChannelConfig,
};
pub use kernel_client::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, AuditEvent, AuditRef, Decision, EffectClass,
    EnvelopeError, KernelClient, KernelError, KernelFuture, LEASE_DOCUMENT_VERSION, LeaseDocument,
    LeaseLimits, LeaseVerification, MockKernelClient, MockVerdict, Obligation, OneShotGrant,
    POLICY_DECISION_VERSION, PolicyDecision, ResourceSet, SessionEndReport,
    SessionIdentityAuthority, SessionIdentityInfo, SupervisorKernel, ToolRef, deadline_rfc3339,
    now_ms, now_rfc3339, sha256_hex,
};
pub use model_gateway::{
    ChatMessage, CredentialVault, GatewayConfig, GatewayError, GatewayResponse, MemorySpendPool,
    MockProviderAdapter, MockProviderOutcome, ModelGateway, ModelPolicy, ModelRequest,
    NormalizedUsage, ProviderAdapter, ProviderCompletion, ProviderError, ProviderFuture,
    RedactedAuditRecord, SecretString, SpendPool,
};
pub use session::{
    FaultKind, MemorySessionStore, PiCommand, PiEvent, PiEventError, RestartReport, SessionHandle,
    SessionId, SessionRef, SessionStatus, SessionStore, SessionSupervisor, StoreError,
    SupervisorConfig, SupervisorError, TerminationReport,
};
pub use tool_catalog::{
    ACTION_START_DEADLINE_SECS, Catalog, CatalogError, DecodedArgs, FailCommitSandbox,
    MockSandboxRunner, MockStagedExecution, PiToolRequest, ProjectionKind, ResourceUsage,
    SandboxError, SandboxFuture, SandboxOutcome, SandboxRunner, StagedExecution, ToolDef,
    ToolOutcome, ToolPipeline, default_catalog,
};

pub use orchestration::{
    ControlAction, ControlOrchestrationCommand, CreateOrchestrationCommand, OrchestrationEvent,
    OrchestrationFuture, OrchestrationService,
};
pub use routes::router;
pub use sandbox_driver::{DriverSandboxRunner, DriverStagedExecution, SpecBuilder};
pub use sse::{EventBroker, EventBrokerError, RunEvent};
pub use state::{
    ApiState, ApiStateError, ApprovalConflict, ApprovalDecision, ApprovalDecisionCommand,
    ApprovalPreview, ApprovalQuery, ApprovalRenewal, ApprovalRenewalCommand, ApprovalResult,
    ApprovalSecretReference, AuditEntry, AuditQuery, AutomationActionRequested, CancelRunCommand,
    CaptureWorkflowCommand, ChannelMappingCommand, ChannelMappingQuery, ChannelMappingReview,
    CreateRunCommand, DestinationPolicyCommand, DestinationPolicyQuery, DestinationPolicyReview,
    JobActionCommand, JobReview, JobReviewQuery, PluginActionCommand, PluginActionRequested,
    PluginComponentReview, PluginDetailsQuery, PluginFailureReview, PluginReviewQuery,
    PluginSettingReview, PluginVersionDetails, PrincipalSummary, ProviderPolicyCommand,
    ProviderPolicyQuery, ProviderPolicyReview, RunCancellation, RunCreated, RunReconciliation,
    RunStatus, RuntimeService, SandboxCapabilityReport, ServiceError, ServiceFuture,
    ServiceIdentityCommand, ServiceIdentityQuery, ServiceIdentityReview, SkillActionCommand,
    SkillReview, SkillReviewQuery, StagedPluginReview, WorkflowCaptureDraftReview,
    WorkspaceModelPolicyReview,
};
