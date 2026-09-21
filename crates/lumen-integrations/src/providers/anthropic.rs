use super::http;
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

pub struct AnthropicAdapter {
    config: ProviderConfig,
    key: String,
    client: Client,
}
impl AnthropicAdapter {
    pub fn new(config: ProviderConfig, key: impl Into<String>) -> Result<Self, ProviderError> {
        let key = key.into();
        if config.kind() != ProviderKind::Anthropic
            || key.is_empty()
            || key.chars().any(char::is_control)
        {
            return Err(ProviderError::configuration(
                "invalid Anthropic provider or credential",
            ));
        }
        Ok(Self {
            config,
            key,
            client: http::client()?,
        })
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
            .map_err(|error| ProviderError::configuration(error.to_string()))?;
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
            http::json(
                self.client
                    .post(url)
                    .header("x-api-key", &self.key)
                    .header("anthropic-version", "2023-06-01")
                    .json(&body)
                    .send()
                    .await
                    .map_err(|error| ProviderError::transport(error.to_string()))?,
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
            tokio::select! { biased; _ = cancel.cancelled() => Err(ProviderError::cancelled()), response = self.send(profile, input) => response }
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
