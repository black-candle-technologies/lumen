use futures_util::StreamExt;
use lumen_core::{
    action::CanonicalValue,
    model::ModelTool,
    provider::{DEFAULT_PROVIDER_MAX_RESPONSE_BYTES, DEFAULT_PROVIDER_TIMEOUT, ProviderError},
};
use reqwest::{Client, Response, redirect::Policy};
use serde_json::Value;

pub fn client() -> Result<Client, ProviderError> {
    Client::builder()
        .timeout(DEFAULT_PROVIDER_TIMEOUT)
        .redirect(Policy::none())
        .no_proxy()
        .build()
        .map_err(|error| ProviderError::transport(format!("HTTP client: {error}")))
}
pub async fn json(response: Response) -> Result<Value, ProviderError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ProviderError::http(format!("HTTP {status}")));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| ProviderError::transport(error.to_string()))?;
        if bytes.len().saturating_add(chunk.len()) > DEFAULT_PROVIDER_MAX_RESPONSE_BYTES {
            return Err(ProviderError::protocol("response byte limit exceeded"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| ProviderError::protocol(format!("invalid JSON: {error}")))
}
pub fn text(value: &CanonicalValue) -> String {
    match value {
        CanonicalValue::String(value) => value.clone(),
        value => serde_json::to_string(value).expect("canonical JSON"),
    }
}
pub fn tool<'a>(tools: &'a [ModelTool], name: &str) -> Result<&'a ModelTool, ProviderError> {
    tools
        .iter()
        .find(|tool| tool.name() == name)
        .ok_or_else(|| {
            ProviderError::protocol(format!("provider requested unadvertised tool {name}"))
        })
}
pub fn args(value: &Value) -> Result<CanonicalValue, ProviderError> {
    match value {
        Value::String(raw) => serde_json::from_str(raw),
        value => serde_json::from_value(value.clone()),
    }
    .map_err(|error| ProviderError::protocol(format!("invalid tool arguments: {error}")))
}
pub fn u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}
