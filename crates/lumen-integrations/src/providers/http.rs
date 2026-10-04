use futures_util::StreamExt;
use lumen_core::{action::CanonicalValue, model::ModelTool, provider::ProviderError};
use reqwest::{Client, Response, redirect::Policy};
use serde_json::Value;

pub fn client_with(options: super::ProviderHttpOptions) -> Result<Client, ProviderError> {
    let options = options.validate()?;
    Client::builder()
        .timeout(options.timeout)
        .redirect(Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| ProviderError::transport("provider HTTP initialization failed"))
}
pub async fn json_with(response: Response, limit: usize) -> Result<Value, ProviderError> {
    let status = response.status();
    if !status.is_success() {
        return Err(ProviderError::http(format!("HTTP {status}")));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| ProviderError::transport("provider body read failed"))?;
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(ProviderError::protocol("response byte limit exceeded"));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| ProviderError::protocol("invalid provider JSON"))
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
        .ok_or_else(|| ProviderError::protocol("provider requested unadvertised tool"))
}
pub fn args(value: &Value) -> Result<CanonicalValue, ProviderError> {
    match value {
        Value::String(raw) => serde_json::from_str(raw),
        value => serde_json::from_value(value.clone()),
    }
    .map_err(|_| ProviderError::protocol("invalid tool arguments"))
}
pub fn u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}
