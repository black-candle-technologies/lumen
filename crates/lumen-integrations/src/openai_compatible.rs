use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use lumen_core::{
    action::CanonicalValue,
    model::{
        ActionProposal, ModelError, ModelFuture, ModelInput, ModelMessage, ModelOutput, ModelPort,
        ModelRole, ModelTool, ModelToolCall,
    },
};
use reqwest::{Client, redirect::Policy as RedirectPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MODEL_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const MODEL_PROBE_MAX_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointPolicy {
    LoopbackOnly,
    AllowRemote,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointClass {
    Local,
    Remote,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum OllamaGpuPolicy {
    #[default]
    Off,
    RequireFull,
    AllowMixed,
}

#[derive(Clone, Debug)]
pub struct OpenAiCompatibleConfig {
    endpoint: Url,
    model: String,
    endpoint_class: EndpointClass,
    streaming: bool,
    timeout: Duration,
    max_response_bytes: usize,
    ollama_gpu_policy: OllamaGpuPolicy,
}

impl OpenAiCompatibleConfig {
    pub fn new(
        endpoint: impl AsRef<str>,
        model: impl Into<String>,
        policy: EndpointPolicy,
    ) -> Result<Self, ModelConfigError> {
        let mut endpoint = Url::parse(endpoint.as_ref())?;
        if !matches!(endpoint.scheme(), "http" | "https") {
            return Err(ModelConfigError::UnsupportedScheme);
        }
        if !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(ModelConfigError::AmbiguousEndpoint);
        }
        let endpoint_class = if is_loopback(&endpoint)? {
            EndpointClass::Local
        } else {
            EndpointClass::Remote
        };
        if endpoint_class == EndpointClass::Remote && policy != EndpointPolicy::AllowRemote {
            return Err(ModelConfigError::RemoteEndpointDenied);
        }
        if !endpoint.path().ends_with('/') {
            let path = format!("{}/", endpoint.path());
            endpoint.set_path(&path);
        }

        let model = model.into();
        if model.is_empty()
            || model.len() > 256
            || model.trim() != model
            || model.chars().any(char::is_control)
        {
            return Err(ModelConfigError::InvalidModel);
        }

        Ok(Self {
            endpoint,
            model,
            endpoint_class,
            streaming: false,
            timeout: DEFAULT_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            ollama_gpu_policy: OllamaGpuPolicy::Off,
        })
    }

    pub fn with_streaming(mut self, streaming: bool) -> Self {
        self.streaming = streaming;
        self
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    pub fn with_ollama_gpu_policy(
        mut self,
        policy: OllamaGpuPolicy,
    ) -> Result<Self, ModelConfigError> {
        if policy != OllamaGpuPolicy::Off
            && (self.endpoint_class != EndpointClass::Local
                || self.endpoint.scheme() != "http"
                || self.endpoint.path() != "/v1/")
        {
            return Err(ModelConfigError::InvalidOllamaGpuEndpoint);
        }
        self.ollama_gpu_policy = policy;
        Ok(self)
    }

    pub const fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderIdentity {
    configured_model: String,
    endpoint_class: EndpointClass,
    endpoint_origin: String,
}

impl ProviderIdentity {
    pub fn configured_model(&self) -> &str {
        &self.configured_model
    }

    pub const fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }

    pub fn endpoint_origin(&self) -> &str {
        &self.endpoint_origin
    }
}

pub struct OpenAiCompatibleClient {
    config: OpenAiCompatibleConfig,
    identity: ProviderIdentity,
    client: Client,
}

impl OpenAiCompatibleClient {
    pub fn new(config: OpenAiCompatibleConfig) -> Result<Self, ModelConfigError> {
        if config.timeout.is_zero() {
            return Err(ModelConfigError::InvalidTimeout);
        }
        if config.max_response_bytes == 0 {
            return Err(ModelConfigError::InvalidResponseLimit);
        }
        let client = Client::builder()
            .timeout(config.timeout)
            .redirect(RedirectPolicy::none())
            .no_proxy()
            .build()?;
        let endpoint_origin = config.endpoint.origin().ascii_serialization();
        let identity = ProviderIdentity {
            configured_model: config.model.clone(),
            endpoint_class: config.endpoint_class,
            endpoint_origin,
        };
        Ok(Self {
            config,
            identity,
            client,
        })
    }

    pub const fn identity(&self) -> &ProviderIdentity {
        &self.identity
    }

    pub async fn probe_local_model(&self) -> Result<bool, ModelError> {
        if self.config.endpoint_class != EndpointClass::Local {
            return Err(ModelError::new("remote model catalog probe is not allowed"));
        }
        tokio::time::timeout(MODEL_PROBE_TIMEOUT, async {
            let url =
                self.config.endpoint.join("models").map_err(|error| {
                    ModelError::new(format!("invalid model catalog URL: {error}"))
                })?;
            let response = self.client.get(url).send().await.map_err(request_error)?;
            if !response.status().is_success() {
                return Err(ModelError::new(format!(
                    "model catalog returned HTTP {}",
                    response.status()
                )));
            }
            let body = read_limited(response, MODEL_PROBE_MAX_RESPONSE_BYTES).await?;
            let catalog: ModelCatalog = serde_json::from_slice(&body)
                .map_err(|_| ModelError::new("model catalog response is invalid"))?;
            Ok(catalog
                .data
                .iter()
                .any(|model| model.id == self.config.model))
        })
        .await
        .map_err(|_| ModelError::new("model catalog probe timed out"))?
    }

    pub async fn generate_cancellable(
        &self,
        input: ModelInput,
        cancellation: CancellationToken,
    ) -> Result<ModelOutput, ModelError> {
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(ModelError::new("model request cancelled")),
            result = self.send(input) => result,
        }
    }

    async fn send(&self, input: ModelInput) -> Result<ModelOutput, ModelError> {
        if self.config.ollama_gpu_policy != OllamaGpuPolicy::Off {
            self.check_ollama_residency(true).await?;
        }
        let output = self.send_chat(input).await?;
        if self.config.ollama_gpu_policy != OllamaGpuPolicy::Off {
            self.check_ollama_residency(false).await?;
        }
        Ok(output)
    }

    async fn send_chat(&self, input: ModelInput) -> Result<ModelOutput, ModelError> {
        let url = self
            .config
            .endpoint
            .join("chat/completions")
            .map_err(|error| ModelError::new(format!("invalid model request URL: {error}")))?;
        let body = ChatRequest {
            model: &self.config.model,
            messages: input.messages().iter().map(RequestMessage::from).collect(),
            stream: self.config.streaming,
            tools: request_tools(input.tools())?,
        };
        let response = self
            .client
            .post(url)
            .json(&body)
            .send()
            .await
            .map_err(request_error)?;
        if !response.status().is_success() {
            return Err(ModelError::new(format!(
                "model endpoint returned HTTP {}",
                response.status()
            )));
        }

        if self.config.streaming {
            parse_stream(response, self.config.max_response_bytes, input.tools()).await
        } else {
            let body = read_limited(response, self.config.max_response_bytes).await?;
            let response = serde_json::from_slice::<ChatResponse>(&body).map_err(|error| {
                ModelError::new(format!("invalid model response JSON: {error}"))
            })?;
            let [choice] = response.choices.try_into().map_err(|choices: Vec<_>| {
                ModelError::new(format!(
                    "model response must contain exactly one choice, got {}",
                    choices.len()
                ))
            })?;
            output_from_parts(
                choice.message.content.unwrap_or_default(),
                choice.message.tool_calls,
                input.tools(),
            )
        }
    }

    async fn check_ollama_residency(&self, may_preload: bool) -> Result<(), ModelError> {
        let mut residency = self.ollama_residency().await?;
        if residency == OllamaResidency::NotLoaded && may_preload {
            self.preload_ollama_model().await?;
            residency = self.ollama_residency().await?;
        }
        let allowed = match self.config.ollama_gpu_policy {
            OllamaGpuPolicy::Off => true,
            OllamaGpuPolicy::RequireFull => residency == OllamaResidency::Full,
            OllamaGpuPolicy::AllowMixed => {
                matches!(residency, OllamaResidency::Full | OllamaResidency::Mixed)
            }
        };
        if allowed {
            Ok(())
        } else {
            Err(ModelError::new(format!(
                "Ollama GPU policy rejected model residency: {}",
                residency.label()
            )))
        }
    }

    async fn ollama_residency(&self) -> Result<OllamaResidency, ModelError> {
        tokio::time::timeout(MODEL_PROBE_TIMEOUT, async {
            let url = self.config.endpoint.join("/api/ps").map_err(|error| {
                ModelError::new(format!("invalid Ollama residency URL: {error}"))
            })?;
            let response = self.client.get(url).send().await.map_err(|error| {
                ModelError::new(format!("Ollama GPU telemetry unavailable: {error}"))
            })?;
            if !response.status().is_success() {
                return Err(ModelError::new(format!(
                    "Ollama GPU telemetry unavailable: HTTP {}",
                    response.status()
                )));
            }
            let body = read_limited(response, MODEL_PROBE_MAX_RESPONSE_BYTES)
                .await
                .map_err(|error| {
                    ModelError::new(format!("Ollama GPU telemetry unavailable: {error}"))
                })?;
            let status: OllamaRunningModels = serde_json::from_slice(&body)
                .map_err(|_| ModelError::new("Ollama GPU telemetry unknown: invalid response"))?;
            let Some(model) = status
                .models
                .iter()
                .find(|model| model.name == self.config.model)
            else {
                return Ok(OllamaResidency::NotLoaded);
            };
            Ok(match (model.size, model.size_vram) {
                (Some(size), Some(vram)) if size > 0 && vram == size => OllamaResidency::Full,
                (Some(size), Some(vram)) if size > 0 && vram > 0 && vram < size => {
                    OllamaResidency::Mixed
                }
                (Some(size), Some(0)) if size > 0 => OllamaResidency::CpuOnly,
                _ => OllamaResidency::Unknown,
            })
        })
        .await
        .map_err(|_| ModelError::new("Ollama GPU telemetry unavailable: timed out"))?
    }

    async fn preload_ollama_model(&self) -> Result<(), ModelError> {
        let url = self
            .config
            .endpoint
            .join("/api/generate")
            .map_err(|error| ModelError::new(format!("invalid Ollama preload URL: {error}")))?;
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({
                "model": self.config.model,
                "prompt": "",
                "stream": false
            }))
            .send()
            .await
            .map_err(|error| ModelError::new(format!("Ollama GPU preload unavailable: {error}")))?;
        if !response.status().is_success() {
            return Err(ModelError::new(format!(
                "Ollama GPU preload unavailable: HTTP {}",
                response.status()
            )));
        }
        read_limited(response, MODEL_PROBE_MAX_RESPONSE_BYTES)
            .await
            .map_err(|error| ModelError::new(format!("Ollama GPU preload unavailable: {error}")))?;
        Ok(())
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum OllamaResidency {
    Full,
    Mixed,
    CpuOnly,
    NotLoaded,
    Unknown,
}

impl OllamaResidency {
    const fn label(self) -> &'static str {
        match self {
            Self::Full => "full GPU",
            Self::Mixed => "mixed GPU/CPU",
            Self::CpuOnly => "CPU-only",
            Self::NotLoaded => "unavailable (model not loaded)",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Deserialize)]
struct OllamaRunningModels {
    models: Vec<OllamaRunningModel>,
}

#[derive(Deserialize)]
struct OllamaRunningModel {
    name: String,
    size: Option<u64>,
    size_vram: Option<u64>,
}

impl ModelPort for OpenAiCompatibleClient {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_> {
        Box::pin(async move {
            self.generate_cancellable(input, CancellationToken::new())
                .await
        })
    }
}

fn is_loopback(url: &Url) -> Result<bool, ModelConfigError> {
    match url.host().ok_or(ModelConfigError::MissingHost)? {
        Host::Ipv4(address) => Ok(address.is_loopback()),
        Host::Ipv6(address) => Ok(address.is_loopback()),
        Host::Domain(domain) => {
            if domain.eq_ignore_ascii_case("localhost") {
                Ok(true)
            } else if let Ok(address) = domain.parse::<IpAddr>() {
                Ok(address.is_loopback())
            } else {
                Ok(false)
            }
        }
    }
}

async fn parse_stream(
    response: reqwest::Response,
    max_response_bytes: usize,
    tools: &[ModelTool],
) -> Result<ModelOutput, ModelError> {
    let mut bytes_seen = 0_usize;
    let limited = response.bytes_stream().map(move |chunk| {
        let chunk = chunk.map_err(std::io::Error::other)?;
        bytes_seen = bytes_seen.saturating_add(chunk.len());
        if bytes_seen > max_response_bytes {
            return Err(std::io::Error::other("model response byte limit exceeded"));
        }
        Ok(chunk)
    });
    let mut events = limited.eventsource();
    let mut text = String::new();
    let mut tool_call = None::<AccumulatedToolCall>;

    while let Some(event) = events.next().await {
        let event =
            event.map_err(|error| ModelError::new(format!("invalid model stream: {error}")))?;
        if event.data == "[DONE]" {
            break;
        }
        let chunk: StreamChunk = serde_json::from_str(&event.data)
            .map_err(|error| ModelError::new(format!("invalid model stream JSON: {error}")))?;
        for choice in chunk.choices {
            if choice.index != 0 {
                return Err(ModelError::new(
                    "multiple model response choices are unsupported",
                ));
            }
            if let Some(content) = choice.delta.content {
                text.push_str(&content);
            }
            for tool in choice.delta.tool_calls {
                let index = tool.index.unwrap_or(0);
                let accumulated = tool_call.get_or_insert_with(|| AccumulatedToolCall {
                    index,
                    id: String::new(),
                    kind: String::new(),
                    name: String::new(),
                    arguments: String::new(),
                });
                if accumulated.index != index {
                    return Err(ModelError::new("multiple tool calls are unsupported"));
                }
                if let Some(id) = tool.id {
                    append_once(&mut accumulated.id, &id, "tool call ID")?;
                }
                if let Some(kind) = tool.kind {
                    append_once(&mut accumulated.kind, &kind, "tool call type")?;
                }
                if let Some(name) = tool.function.name {
                    accumulated.name.push_str(&name);
                }
                if let Some(arguments) = tool.function.arguments {
                    accumulated.arguments.push_str(&arguments);
                }
            }
        }
    }

    output_from_accumulated(text, tool_call, tools)
}

async fn read_limited(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, ModelError> {
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(request_error)?;
        if body.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(ModelError::new("model response byte limit exceeded"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn output_from_parts(
    text: String,
    tool_calls: Vec<ToolCall>,
    tools: &[ModelTool],
) -> Result<ModelOutput, ModelError> {
    match tool_calls.as_slice() {
        [] if text.is_empty() => Err(ModelError::new("model response contained no content")),
        [] => Ok(ModelOutput::FinalText(text)),
        [tool] => output_from_tool_call(tool, tools),
        _ => Err(ModelError::new("multiple tool calls are unsupported")),
    }
}

fn output_from_accumulated(
    text: String,
    tool_call: Option<AccumulatedToolCall>,
    tools: &[ModelTool],
) -> Result<ModelOutput, ModelError> {
    match tool_call {
        Some(tool_call) => output_from_tool_call(
            &ToolCall {
                id: Some(tool_call.id),
                kind: Some(tool_call.kind),
                function: ToolFunction {
                    name: tool_call.name,
                    arguments: tool_call.arguments,
                },
            },
            tools,
        ),
        None if text.is_empty() => Err(ModelError::new("model response contained no content")),
        None => Ok(ModelOutput::FinalText(text)),
    }
}

fn output_from_tool_call(tool: &ToolCall, tools: &[ModelTool]) -> Result<ModelOutput, ModelError> {
    if tool.kind.as_deref() != Some("function") {
        return Err(ModelError::new("unsupported tool call type"));
    }
    let id = tool
        .id
        .as_deref()
        .filter(|id| valid_call_id(id))
        .ok_or_else(|| ModelError::new("tool call ID is missing or invalid"))?;
    let definition = tools
        .iter()
        .find(|definition| definition.name() == tool.function.name)
        .ok_or_else(|| ModelError::new(format!("unknown tool: {}", tool.function.name)))?;
    let arguments = serde_json::from_str::<CanonicalValue>(&tool.function.arguments)
        .map_err(|error| ModelError::new(format!("invalid tool arguments: {error}")))?;
    let call = ModelToolCall::new(id, definition.name(), arguments.clone());
    Ok(ModelOutput::Action(
        ActionProposal::new(definition.action_kind(), arguments).with_tool_call(call),
    ))
}

fn append_once(target: &mut String, value: &str, field: &str) -> Result<(), ModelError> {
    if target.is_empty() {
        target.push_str(value);
    } else if target != value {
        return Err(ModelError::new(format!("conflicting streamed {field}")));
    }
    Ok(())
}

fn request_tools(tools: &[ModelTool]) -> Result<Vec<RequestTool>, ModelError> {
    let mut names = BTreeSet::new();
    tools
        .iter()
        .map(|tool| {
            if !valid_tool_name(tool.name()) || !names.insert(tool.name()) {
                return Err(ModelError::new("model tool name is invalid or duplicated"));
            }
            if tool.description().is_empty()
                || tool.description().len() > 1024
                || tool.description().chars().any(char::is_control)
            {
                return Err(ModelError::new("model tool description is invalid"));
            }
            match tool.input_schema() {
                CanonicalValue::Object(schema)
                    if schema.get("type") == Some(&CanonicalValue::from("object")) => {}
                _ => return Err(ModelError::new("model tool schema must describe an object")),
            }
            Ok(RequestTool {
                kind: "function",
                function: RequestToolDefinition {
                    name: tool.name().to_owned(),
                    description: tool.description().to_owned(),
                    parameters: tool.input_schema().clone(),
                },
            })
        })
        .collect()
}

fn valid_tool_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_call_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn request_error(error: reqwest::Error) -> ModelError {
    if error.is_timeout() {
        ModelError::new("model request timed out")
    } else {
        ModelError::new(format!("model request failed: {error}"))
    }
}

#[derive(Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    messages: Vec<RequestMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<RequestTool>,
}

#[derive(Serialize)]
struct RequestTool {
    #[serde(rename = "type")]
    kind: &'static str,
    function: RequestToolDefinition,
}

#[derive(Serialize)]
struct RequestToolDefinition {
    name: String,
    description: String,
    parameters: CanonicalValue,
}

#[derive(Serialize)]
struct RequestMessage {
    role: &'static str,
    content: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_calls: Vec<RequestToolCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize)]
struct RequestToolCall {
    id: String,
    #[serde(rename = "type")]
    kind: &'static str,
    function: RequestToolFunction,
}

#[derive(Serialize)]
struct RequestToolFunction {
    name: String,
    arguments: String,
}

impl From<&ModelMessage> for RequestMessage {
    fn from(message: &ModelMessage) -> Self {
        let role = match message.role() {
            ModelRole::User => "user",
            ModelRole::Assistant => "assistant",
            ModelRole::Tool => "tool",
        };
        let content = match message.content() {
            CanonicalValue::String(value) => value.clone(),
            value => {
                serde_json::to_string(value).expect("canonical value serialization cannot fail")
            }
        };
        let tool_calls = message
            .tool_call()
            .map(|call| {
                vec![RequestToolCall {
                    id: call.id().to_owned(),
                    kind: "function",
                    function: RequestToolFunction {
                        name: call.name().to_owned(),
                        arguments: serde_json::to_string(call.arguments())
                            .expect("canonical tool arguments serialization cannot fail"),
                    },
                }]
            })
            .unwrap_or_default();
        Self {
            role,
            content: message.tool_call().is_none().then_some(content),
            tool_calls,
            tool_call_id: message.tool_call_id().map(str::to_owned),
        }
    }
}

#[derive(Deserialize)]
struct ChatResponse {
    choices: Vec<ResponseChoice>,
}

#[derive(Deserialize)]
struct ResponseChoice {
    message: ResponseMessage,
}

#[derive(Deserialize)]
struct ResponseMessage {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<ToolCall>,
}

#[derive(Deserialize)]
struct ToolCall {
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    function: ToolFunction,
}

#[derive(Deserialize)]
struct ToolFunction {
    name: String,
    arguments: String,
}

#[derive(Deserialize)]
struct StreamChunk {
    choices: Vec<StreamChoice>,
}

#[derive(Deserialize)]
struct StreamChoice {
    index: usize,
    delta: StreamDelta,
}

#[derive(Deserialize)]
struct StreamDelta {
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<StreamToolCall>,
}

#[derive(Deserialize)]
struct StreamToolCall {
    index: Option<usize>,
    id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
    function: StreamToolFunction,
}

#[derive(Deserialize)]
struct ModelCatalog {
    data: Vec<ModelCatalogEntry>,
}

#[derive(Deserialize)]
struct ModelCatalogEntry {
    id: String,
}

#[derive(Deserialize)]
struct StreamToolFunction {
    name: Option<String>,
    arguments: Option<String>,
}

struct AccumulatedToolCall {
    index: usize,
    id: String,
    kind: String,
    name: String,
    arguments: String,
}

#[derive(Debug, Error)]
pub enum ModelConfigError {
    #[error(transparent)]
    InvalidUrl(#[from] url::ParseError),
    #[error("model endpoint must use HTTP or HTTPS")]
    UnsupportedScheme,
    #[error("model endpoint must not contain credentials, query parameters, or fragments")]
    AmbiguousEndpoint,
    #[error("model endpoint must include a host")]
    MissingHost,
    #[error("non-loopback model endpoint requires explicit remote policy")]
    RemoteEndpointDenied,
    #[error("model name must be non-empty, bounded, and free of control characters")]
    InvalidModel,
    #[error("model request timeout must be greater than zero")]
    InvalidTimeout,
    #[error("model response byte limit must be greater than zero")]
    InvalidResponseLimit,
    #[error("Ollama GPU policy requires an HTTP loopback /v1/ endpoint")]
    InvalidOllamaGpuEndpoint,
    #[error("could not construct HTTP client: {0}")]
    Client(#[from] reqwest::Error),
}
