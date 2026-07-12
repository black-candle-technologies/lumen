use std::{net::IpAddr, time::Duration};

use eventsource_stream::Eventsource;
use futures_util::StreamExt;
use lumen_core::{
    action::CanonicalValue,
    model::{
        ActionProposal, ModelError, ModelFuture, ModelInput, ModelMessage, ModelOutput, ModelPort,
        ModelRole,
    },
};
use reqwest::{Client, redirect::Policy as RedirectPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::{Host, Url};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

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

#[derive(Clone, Debug)]
pub struct OpenAiCompatibleConfig {
    endpoint: Url,
    model: String,
    endpoint_class: EndpointClass,
    streaming: bool,
    timeout: Duration,
    max_response_bytes: usize,
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
        let url = self
            .config
            .endpoint
            .join("chat/completions")
            .map_err(|error| ModelError::new(format!("invalid model request URL: {error}")))?;
        let body = ChatRequest {
            model: &self.config.model,
            messages: input.messages().iter().map(RequestMessage::from).collect(),
            stream: self.config.streaming,
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
            parse_stream(response, self.config.max_response_bytes).await
        } else {
            let body = read_limited(response, self.config.max_response_bytes).await?;
            let response = serde_json::from_slice::<ChatResponse>(&body).map_err(|error| {
                ModelError::new(format!("invalid model response JSON: {error}"))
            })?;
            let message = response
                .choices
                .into_iter()
                .next()
                .ok_or_else(|| ModelError::new("model response contained no choices"))?
                .message;
            output_from_parts(message.content.unwrap_or_default(), message.tool_calls)
        }
    }
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
    let mut tool_name = String::new();
    let mut tool_arguments = String::new();

    while let Some(event) = events.next().await {
        let event =
            event.map_err(|error| ModelError::new(format!("invalid model stream: {error}")))?;
        if event.data == "[DONE]" {
            break;
        }
        let chunk: StreamChunk = serde_json::from_str(&event.data)
            .map_err(|error| ModelError::new(format!("invalid model stream JSON: {error}")))?;
        for choice in chunk.choices {
            if let Some(content) = choice.delta.content {
                text.push_str(&content);
            }
            for tool in choice.delta.tool_calls {
                if let Some(name) = tool.function.name {
                    tool_name.push_str(&name);
                }
                if let Some(arguments) = tool.function.arguments {
                    tool_arguments.push_str(&arguments);
                }
            }
        }
    }

    output_from_accumulated(text, tool_name, tool_arguments)
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

fn output_from_parts(text: String, tool_calls: Vec<ToolCall>) -> Result<ModelOutput, ModelError> {
    if let Some(tool) = tool_calls.into_iter().next() {
        output_from_accumulated(text, tool.function.name, tool.function.arguments)
    } else if text.is_empty() {
        Err(ModelError::new("model response contained no content"))
    } else {
        Ok(ModelOutput::FinalText(text))
    }
}

fn output_from_accumulated(
    text: String,
    tool_name: String,
    tool_arguments: String,
) -> Result<ModelOutput, ModelError> {
    if !tool_name.is_empty() {
        let arguments = serde_json::from_str::<CanonicalValue>(&tool_arguments)
            .map_err(|error| ModelError::new(format!("invalid tool arguments: {error}")))?;
        Ok(ModelOutput::Action(ActionProposal::new(
            tool_name, arguments,
        )))
    } else if text.is_empty() {
        Err(ModelError::new("model response contained no content"))
    } else {
        Ok(ModelOutput::FinalText(text))
    }
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
}

#[derive(Serialize)]
struct RequestMessage {
    role: &'static str,
    content: String,
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
        Self { role, content }
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
    function: StreamToolFunction,
}

#[derive(Deserialize)]
struct StreamToolFunction {
    name: Option<String>,
    arguments: Option<String>,
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
    #[error("could not construct HTTP client: {0}")]
    Client(#[from] reqwest::Error),
}
