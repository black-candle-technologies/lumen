use super::{ProviderCredential, ProviderHttpOptions, http};
use lumen_core::{
    model::{ActionProposal, ModelInput, ModelMessage, ModelOutput, ModelRole, ModelToolCall},
    provider::{
        ModelCapability, ModelProfile, ProviderAdapter, ProviderConfig, ProviderError,
        ProviderFuture, ProviderKind, ProviderResponse, ProviderUsage, validate_binding,
    },
};
use reqwest::Client;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub struct AnthropicAdapter {
    config: ProviderConfig,
    key: ProviderCredential,
    client: Client,
    options: ProviderHttpOptions,
}
impl AnthropicAdapter {
    pub fn new(config: ProviderConfig, key: impl Into<String>) -> Result<Self, ProviderError> {
        Self::new_with_options(
            config,
            ProviderCredential::from_keyring(Zeroizing::new(key.into().into_bytes()))?,
            ProviderHttpOptions::default(),
        )
    }
    pub fn new_with_options(
        config: ProviderConfig,
        key: ProviderCredential,
        options: ProviderHttpOptions,
    ) -> Result<Self, ProviderError> {
        if config.kind() != ProviderKind::Anthropic {
            return Err(ProviderError::configuration(
                "incompatible provider protocol",
            ));
        }
        let options = options.validate()?;
        Ok(Self {
            config,
            key,
            client: http::client_with(options)?,
            options,
        })
    }
    /// Trusted host transport injection, primarily for hermetic TLS tests.
    /// The host must retain TLS verification, no redirects, and no proxy.
    #[doc(hidden)]
    pub fn with_http_client(mut self, client: Client) -> Self {
        self.client = client;
        self
    }
    async fn send(
        &self,
        profile: &ModelProfile,
        input: ModelInput,
    ) -> Result<ProviderResponse, ProviderError> {
        if !input.tools().is_empty()
            && !profile
                .capabilities()
                .contains(ModelCapability::ToolCalling)
        {
            return Err(ProviderError::configuration(
                "model profile does not advertise tool calling",
            ));
        }
        let url = self
            .config
            .endpoint()
            .join("messages")
            .map_err(|_| ProviderError::configuration("invalid provider request path"))?;
        let mut body = json!({"model":profile.model_name(),"max_tokens":8192,"messages":messages(input.messages()),"tools":tools(input.tools())});
        if let Some(generation) = input.generation() {
            body["max_tokens"] = json!(generation.max_output_tokens());
            if generation.provider_effort().is_some() {
                body["thinking"] = json!({"type":"adaptive"});
            }
        }
        parse(
            profile,
            input.tools(),
            http::json_with(
                self.client
                    .post(url)
                    .header("x-api-key", self.key.api_key_header()?)
                    .header("anthropic-version", "2023-06-01")
                    .json(&body)
                    .send()
                    .await
                    .map_err(|_| ProviderError::transport("provider request failed"))?,
                self.options.max_response_bytes,
            )
            .await?,
        )
    }
}
impl ProviderAdapter for AnthropicAdapter {
    fn config(&self) -> &ProviderConfig {
        &self.config
    }
    fn generate<'a>(
        &'a self,
        profile: &'a ModelProfile,
        input: ModelInput,
        cancel: CancellationToken,
    ) -> ProviderFuture<'a> {
        Box::pin(async move {
            validate_binding(&self.config, profile)?;
            tokio::select! { biased; _ = cancel.cancelled() => Err(ProviderError::cancelled()), response = tokio::time::timeout(self.options.timeout,self.send(profile, input)) => response.map_err(|_|ProviderError::transport("provider request timed out"))? }
        })
    }
}
fn messages(messages: &[ModelMessage]) -> Vec<Value> {
    messages.iter().map(|message| match (message.role(), message.tool_call(), message.tool_call_id()) { (ModelRole::Assistant, Some(call), _) => json!({"role":"assistant","content":[{"type":"tool_use","id":call.id(),"name":call.name(),"input":call.arguments()}]}), (ModelRole::Tool, _, Some(id)) => json!({"role":"user","content":[{"type":"tool_result","tool_use_id":id,"content":http::text(message.content())}]}), (ModelRole::Assistant, _, _) => json!({"role":"assistant","content":http::text(message.content())}), _ => json!({"role":"user","content":http::text(message.content())}) }).collect()
}
fn tools(tools: &[lumen_core::model::ModelTool]) -> Vec<Value> {
    tools.iter().map(|tool| json!({"name":tool.name(),"description":tool.description(),"input_schema":tool.input_schema()})).collect()
}
fn parse(
    profile: &ModelProfile,
    advertised: &[lumen_core::model::ModelTool],
    value: Value,
) -> Result<ProviderResponse, ProviderError> {
    if value.get("stop_reason").and_then(Value::as_str) == Some("max_tokens") {
        return Err(ProviderError::protocol(
            "Anthropic response exhausted max_tokens",
        ));
    }
    let mut text = String::new();
    let mut call = None;
    for block in value
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| ProviderError::protocol("Anthropic response missing content"))?
    {
        match block.get("type").and_then(Value::as_str) {
            Some("text") => {
                if let Some(value) = block.get("text").and_then(Value::as_str) {
                    text.push_str(value);
                }
            }
            Some("tool_use") => {
                if call.is_some() {
                    return Err(ProviderError::protocol(
                        "multiple Anthropic tool calls are unsupported",
                    ));
                }
                let id = block
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ProviderError::protocol("tool_use missing id"))?;
                let name = block
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ProviderError::protocol("tool_use missing name"))?;
                let tool = http::tool(advertised, name)?;
                let arguments = http::args(
                    block
                        .get("input")
                        .ok_or_else(|| ProviderError::protocol("tool_use missing input"))?,
                )?;
                call = Some(ModelOutput::Action(
                    ActionProposal::new(tool.action_kind(), arguments.clone())
                        .with_tool_call(ModelToolCall::new(id, name, arguments)),
                ));
            }
            _ => {}
        }
    }
    let output = call.unwrap_or(ModelOutput::FinalText(text));
    if matches!(&output, ModelOutput::FinalText(value) if value.is_empty()) {
        return Err(ProviderError::protocol(
            "Anthropic returned neither text nor a tool call",
        ));
    }
    let usage = value.get("usage").unwrap_or(&Value::Null);
    ProviderResponse::new(
        value
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(profile.model_name()),
        output,
        ProviderUsage {
            input_tokens: http::u64_field(usage, "input_tokens"),
            output_tokens: http::u64_field(usage, "output_tokens"),
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use lumen_core::{
        action::CanonicalValue,
        egress::ProviderId,
        model::ModelTool,
        provider::{ModelCapabilities, ModelProfileId, ModelTrustZone},
    };
    #[test]
    fn parses_tool_use() {
        let profile = ModelProfile::new(
            ModelProfileId::parse("p").unwrap(),
            1,
            ProviderId::parse("anthropic").unwrap(),
            1,
            "m",
            true,
            ModelCapabilities::new([ModelCapability::Text, ModelCapability::ToolCalling]),
            1000,
            ModelTrustZone::RemoteApproved,
            1,
            0,
        )
        .unwrap();
        let tool = ModelTool::new(
            "read",
            "read",
            "fs.read",
            CanonicalValue::object([("type", CanonicalValue::from("object"))]),
        );
        assert!(matches!(
            parse(
                &profile,
                &[tool],
                json!({"content":[{"type":"tool_use","id":"c1","name":"read","input":{}}]})
            )
            .unwrap()
            .output,
            ModelOutput::Action(_)
        ));
    }
}
