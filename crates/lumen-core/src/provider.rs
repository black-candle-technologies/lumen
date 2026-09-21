use std::{collections::BTreeSet, future::Future, net::IpAddr, pin::Pin, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

use crate::{
    egress::{EndpointClass, ProviderId},
    model::{ModelFuture, ModelInput, ModelOutput, ModelPort},
    secret::SecretRefId,
};

pub const DEFAULT_PROVIDER_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_PROVIDER_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    OpenAi,
    Anthropic,
    OpenAiCompatible,
}
impl ProviderKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::OpenAiCompatible => "openai_compatible",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "openai" => Some(Self::OpenAi),
            "anthropic" => Some(Self::Anthropic),
            "openai_compatible" => Some(Self::OpenAiCompatible),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalRuntimeKind {
    Ollama,
    LlamaCpp,
    Vllm,
}
impl LocalRuntimeKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::LlamaCpp => "llama_cpp",
            Self::Vllm => "vllm",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ollama" => Some(Self::Ollama),
            "llama_cpp" => Some(Self::LlamaCpp),
            "vllm" => Some(Self::Vllm),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelCapability {
    Text,
    StructuredOutput,
    ToolCalling,
    CodeGeneration,
    LongContext,
    Reasoning,
    Streaming,
    Vision,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ModelCapabilities(BTreeSet<ModelCapability>);
impl ModelCapabilities {
    pub fn new(values: impl IntoIterator<Item = ModelCapability>) -> Self {
        Self(values.into_iter().collect())
    }
    pub fn contains(&self, value: ModelCapability) -> bool {
        self.0.contains(&value)
    }
    pub fn iter(&self) -> impl Iterator<Item = ModelCapability> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelTrustZone {
    LocalTrusted,
    LocalRestricted,
    RemoteApproved,
    RemoteUntrusted,
}
impl ModelTrustZone {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalTrusted => "local_trusted",
            Self::LocalRestricted => "local_restricted",
            Self::RemoteApproved => "remote_approved",
            Self::RemoteUntrusted => "remote_untrusted",
        }
    }
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "local_trusted" => Some(Self::LocalTrusted),
            "local_restricted" => Some(Self::LocalRestricted),
            "remote_approved" => Some(Self::RemoteApproved),
            "remote_untrusted" => Some(Self::RemoteUntrusted),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct ModelProfileId(String);
impl ModelProfileId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ProviderConfigError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
        {
            return Err(ProviderConfigError::InvalidProfileId);
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for ModelProfileId {
    type Error = ProviderConfigError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderConfig {
    id: ProviderId,
    revision: u64,
    kind: ProviderKind,
    endpoint_class: EndpointClass,
    endpoint: Url,
    enabled: bool,
    local_runtime: Option<LocalRuntimeKind>,
    credential_secret_ref: Option<SecretRefId>,
}
impl ProviderConfig {
    pub fn remote(
        id: ProviderId,
        revision: u64,
        kind: ProviderKind,
        endpoint: impl AsRef<str>,
        enabled: bool,
        secret: SecretRefId,
    ) -> Result<Self, ProviderConfigError> {
        if revision == 0 || !matches!(kind, ProviderKind::OpenAi | ProviderKind::Anthropic) {
            return Err(ProviderConfigError::InvalidShape);
        }
        let endpoint = normalize_endpoint(endpoint.as_ref())?;
        if endpoint.scheme() != "https" || is_loopback(&endpoint)? {
            return Err(ProviderConfigError::RemoteMustUseHttps);
        }
        Ok(Self {
            id,
            revision,
            kind,
            endpoint_class: EndpointClass::Remote,
            endpoint,
            enabled,
            local_runtime: None,
            credential_secret_ref: Some(secret),
        })
    }
    pub fn local_openai_compatible(
        id: ProviderId,
        revision: u64,
        endpoint: impl AsRef<str>,
        runtime: LocalRuntimeKind,
        enabled: bool,
        secret: Option<SecretRefId>,
    ) -> Result<Self, ProviderConfigError> {
        if revision == 0 {
            return Err(ProviderConfigError::InvalidRevision);
        }
        let endpoint = normalize_endpoint(endpoint.as_ref())?;
        if !is_loopback(&endpoint)? {
            return Err(ProviderConfigError::LocalMustBeLoopback);
        }
        Ok(Self {
            id,
            revision,
            kind: ProviderKind::OpenAiCompatible,
            endpoint_class: EndpointClass::Local,
            endpoint,
            enabled,
            local_runtime: Some(runtime),
            credential_secret_ref: secret,
        })
    }
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored_parts(
        id: ProviderId,
        revision: u64,
        kind: ProviderKind,
        class: EndpointClass,
        endpoint: impl AsRef<str>,
        enabled: bool,
        runtime: Option<LocalRuntimeKind>,
        secret: Option<SecretRefId>,
    ) -> Result<Self, ProviderConfigError> {
        match (kind, class, runtime, secret) {
            (
                ProviderKind::OpenAi | ProviderKind::Anthropic,
                EndpointClass::Remote,
                None,
                Some(secret),
            ) => Self::remote(id, revision, kind, endpoint, enabled, secret),
            (ProviderKind::OpenAiCompatible, EndpointClass::Local, Some(runtime), secret) => {
                Self::local_openai_compatible(id, revision, endpoint, runtime, enabled, secret)
            }
            _ => Err(ProviderConfigError::InvalidShape),
        }
    }
    pub fn id(&self) -> &ProviderId {
        &self.id
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub const fn kind(&self) -> ProviderKind {
        self.kind
    }
    pub const fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    pub const fn local_runtime(&self) -> Option<LocalRuntimeKind> {
        self.local_runtime
    }
    pub const fn credential_secret_ref(&self) -> Option<SecretRefId> {
        self.credential_secret_ref
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelProfile {
    id: ModelProfileId,
    revision: u64,
    provider_id: ProviderId,
    provider_revision: u64,
    model_name: String,
    enabled: bool,
    capabilities: ModelCapabilities,
    context_window_tokens: u32,
    trust_zone: ModelTrustZone,
    concurrency_limit: u32,
    priority: i32,
}
impl ModelProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: ModelProfileId,
        revision: u64,
        provider_id: ProviderId,
        provider_revision: u64,
        model_name: impl Into<String>,
        enabled: bool,
        capabilities: ModelCapabilities,
        context_window_tokens: u32,
        trust_zone: ModelTrustZone,
        concurrency_limit: u32,
        priority: i32,
    ) -> Result<Self, ProviderConfigError> {
        let model_name = model_name.into();
        if revision == 0 || provider_revision == 0 {
            return Err(ProviderConfigError::InvalidRevision);
        }
        if model_name.is_empty()
            || model_name.len() > 256
            || model_name.trim() != model_name
            || model_name.chars().any(char::is_control)
        {
            return Err(ProviderConfigError::InvalidModelName);
        }
        if context_window_tokens == 0 || concurrency_limit == 0 {
            return Err(ProviderConfigError::InvalidLimits);
        }
        if !capabilities.contains(ModelCapability::Text) {
            return Err(ProviderConfigError::TextRequired);
        }
        Ok(Self {
            id,
            revision,
            provider_id,
            provider_revision,
            model_name,
            enabled,
            capabilities,
            context_window_tokens,
            trust_zone,
            concurrency_limit,
            priority,
        })
    }
    pub fn id(&self) -> &ModelProfileId {
        &self.id
    }
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    pub fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }
    pub const fn provider_revision(&self) -> u64 {
        self.provider_revision
    }
    pub fn model_name(&self) -> &str {
        &self.model_name
    }
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    pub fn capabilities(&self) -> &ModelCapabilities {
        &self.capabilities
    }
    pub const fn context_window_tokens(&self) -> u32 {
        self.context_window_tokens
    }
    pub const fn trust_zone(&self) -> ModelTrustZone {
        self.trust_zone
    }
    pub const fn concurrency_limit(&self) -> u32 {
        self.concurrency_limit
    }
    pub const fn priority(&self) -> i32 {
        self.priority
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderUsage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderResponse {
    pub resolved_model: String,
    pub output: ModelOutput,
    pub usage: ProviderUsage,
}
impl ProviderResponse {
    pub fn new(
        model: impl Into<String>,
        output: ModelOutput,
        usage: ProviderUsage,
    ) -> Result<Self, ProviderError> {
        let resolved_model = model.into();
        if resolved_model.is_empty() || resolved_model.chars().any(char::is_control) {
            return Err(ProviderError::protocol("invalid resolved model"));
        }
        Ok(Self {
            resolved_model,
            output,
            usage,
        })
    }
}
pub type ProviderFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderResponse, ProviderError>> + Send + 'a>>;
pub trait ProviderAdapter: Send + Sync {
    fn config(&self) -> &ProviderConfig;
    fn generate<'a>(
        &'a self,
        profile: &'a ModelProfile,
        input: ModelInput,
        cancel: CancellationToken,
    ) -> ProviderFuture<'a>;
}
pub struct ProviderModelPort<'a> {
    provider: &'a dyn ProviderAdapter,
    profile: &'a ModelProfile,
    cancel: CancellationToken,
}
impl<'a> ProviderModelPort<'a> {
    pub fn new(
        provider: &'a dyn ProviderAdapter,
        profile: &'a ModelProfile,
    ) -> Result<Self, ProviderError> {
        validate_binding(provider.config(), profile)?;
        Ok(Self {
            provider,
            profile,
            cancel: CancellationToken::new(),
        })
    }
    pub fn with_cancellation(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }
}
impl ModelPort for ProviderModelPort<'_> {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        Box::pin(async move {
            self.provider
                .generate(self.profile, input, self.cancel.child_token())
                .await
                .map(|response| response.output)
                .map_err(|error| crate::model::ModelError::new(error.to_string()))
        })
    }
}
pub fn validate_binding(
    provider: &ProviderConfig,
    profile: &ModelProfile,
) -> Result<(), ProviderError> {
    if !provider.enabled() {
        return Err(ProviderError::configuration("provider disabled"));
    }
    if !profile.enabled() {
        return Err(ProviderError::configuration("model profile disabled"));
    }
    if profile.provider_id() != provider.id() || profile.provider_revision() != provider.revision()
    {
        return Err(ProviderError::configuration(
            "profile/provider revision mismatch",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderErrorKind {
    Cancelled,
    Transport,
    Http,
    Protocol,
    Configuration,
}
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("provider {kind:?} error: {message}")]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    pub message: String,
}
impl ProviderError {
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
    pub fn cancelled() -> Self {
        Self::new(ProviderErrorKind::Cancelled, "request cancelled")
    }
    pub fn transport(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::Transport, message)
    }
    pub fn http(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::Http, message)
    }
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::Protocol, message)
    }
    pub fn configuration(message: impl Into<String>) -> Self {
        Self::new(ProviderErrorKind::Configuration, message)
    }
}
fn normalize_endpoint(value: &str) -> Result<Url, ProviderConfigError> {
    let mut url = Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
    {
        return Err(ProviderConfigError::InvalidEndpoint);
    }
    if !url.path().ends_with('/') {
        url.set_path(&format!("{}/", url.path()));
    }
    Ok(url)
}
fn is_loopback(url: &Url) -> Result<bool, ProviderConfigError> {
    match url.host().ok_or(ProviderConfigError::InvalidEndpoint)? {
        Host::Ipv4(address) => Ok(address.is_loopback()),
        Host::Ipv6(address) => Ok(address.is_loopback()),
        Host::Domain(domain) => Ok(domain.eq_ignore_ascii_case("localhost")
            || domain
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())),
    }
}
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProviderConfigError {
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    #[error("provider revision must be > 0")]
    InvalidRevision,
    #[error("provider endpoint is invalid")]
    InvalidEndpoint,
    #[error("remote provider must use non-loopback HTTPS")]
    RemoteMustUseHttps,
    #[error("local provider must use loopback HTTP(S)")]
    LocalMustBeLoopback,
    #[error("provider shape is invalid")]
    InvalidShape,
    #[error("model profile ID is invalid")]
    InvalidProfileId,
    #[error("model name is invalid")]
    InvalidModelName,
    #[error("model limits must be > 0")]
    InvalidLimits,
    #[error("text capability is required")]
    TextRequired,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_remote_local_and_profile() {
        let provider = ProviderConfig::remote(
            ProviderId::parse("openai").unwrap(),
            1,
            ProviderKind::OpenAi,
            "https://api.openai.com/v1/",
            true,
            SecretRefId::new(),
        )
        .unwrap();
        for runtime in [
            LocalRuntimeKind::Ollama,
            LocalRuntimeKind::LlamaCpp,
            LocalRuntimeKind::Vllm,
        ] {
            assert!(
                ProviderConfig::local_openai_compatible(
                    ProviderId::parse(runtime.as_str()).unwrap(),
                    1,
                    "http://127.0.0.1:8080/v1/",
                    runtime,
                    true,
                    None
                )
                .is_ok()
            );
        }
        let profile = ModelProfile::new(
            ModelProfileId::parse("coder").unwrap(),
            1,
            provider.id().clone(),
            1,
            "model",
            true,
            ModelCapabilities::new([ModelCapability::Text]),
            32_000,
            ModelTrustZone::RemoteApproved,
            2,
            0,
        )
        .unwrap();
        assert!(validate_binding(&provider, &profile).is_ok());
    }
}
