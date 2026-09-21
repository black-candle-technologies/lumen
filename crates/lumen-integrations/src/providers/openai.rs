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

pub struct OpenAiAdapter {
    config: ProviderConfig,
    key: String,
    client: Client,
}
impl OpenAiAdapter {
    pub fn new(config: ProviderConfig, key: impl Into<String>) -> Result<Self, ProviderError> {
        let key = key.into();
        if config.kind() != ProviderKind::OpenAi
            || key.is_empty()
            || key.chars().any(char::is_control)
        {
            return Err(ProviderError::configuration(
                "invalid OpenAI provider or credential",
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
            .join("responses")
            .map_err(|error| ProviderError::configuration(error.to_string()))?;
        let mut body = json!({"model": profile.model_name(), "input": messages(input.messages()), "tools": tools(input.tools()), "parallel_tool_calls": false, "store": false});
        if let Some(generation) = input.generation() {
            body["max_output_tokens"] = json!(generation.max_output_tokens());
            if let Some(effort) = generation.provider_effort() {
                body["reasoning"] = json!({"effort": effort});
            }
        }
        parse(
            profile,
            input.tools(),
            http::json(
                self.client
                    .post(url)
                    .bearer_auth(&self.key)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|error| ProviderError::transport(error.to_string()))?,
            )
            .await?,
        )
    }
}
impl ProviderAdapter for OpenAiAdapter {
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
    messages.iter().map(|message| match (message.role(), message.tool_call(), message.tool_call_id()) { (ModelRole::Assistant, Some(call), _) => json!({"type":"function_call","call_id":call.id(),"name":call.name(),"arguments":serde_json::to_string(call.arguments()).expect("canonical JSON")}), (ModelRole::Tool, _, Some(id)) => json!({"type":"function_call_output","call_id":id,"output":http::text(message.content())}), (ModelRole::User, _, _) => json!({"role":"user","content":http::text(message.content())}), (ModelRole::Assistant, _, _) => json!({"role":"assistant","content":http::text(message.content())}), (ModelRole::Tool, _, None) => json!({"role":"user","content":http::text(message.content())}) }).collect()
}
fn tools(tools: &[lumen_core::model::ModelTool]) -> Vec<Value> {
    tools.iter().map(|tool| json!({"type":"function","name":tool.name(),"description":tool.description(),"parameters":tool.input_schema()})).collect()
}
fn parse(
    profile: &ModelProfile,
    advertised: &[lumen_core::model::ModelTool],
    value: Value,
) -> Result<ProviderResponse, ProviderError> {
    if value
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| status != "completed")
    {
        return Err(ProviderError::protocol("OpenAI response was not completed"));
    }
    let mut text = String::new();
    let mut call = None;
    for item in value
        .get("output")
        .and_then(Value::as_array)
        .ok_or_else(|| ProviderError::protocol("OpenAI response missing output"))?
    {
        match item.get("type").and_then(Value::as_str) {
            Some("message") => {
                for part in item
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if part.get("type").and_then(Value::as_str) == Some("output_text")
                        && let Some(value) = part.get("text").and_then(Value::as_str)
                    {
                        text.push_str(value);
                    }
                }
            }
            Some("function_call") => {
                if call.is_some() {
                    return Err(ProviderError::protocol(
                        "multiple OpenAI tool calls are unsupported",
                    ));
                }
                let id = item
                    .get("call_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ProviderError::protocol("tool call missing call_id"))?;
                let name = item
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| ProviderError::protocol("tool call missing name"))?;
                let tool = http::tool(advertised, name)?;
                let arguments = http::args(
                    item.get("arguments")
                        .ok_or_else(|| ProviderError::protocol("tool call missing arguments"))?,
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
            "OpenAI returned neither text nor a tool call",
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
    fn parses_function_call() {
        let profile = ModelProfile::new(
            ModelProfileId::parse("p").unwrap(),
            1,
            ProviderId::parse("openai").unwrap(),
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
        assert!(matches!(parse(&profile, &[tool], json!({"status":"completed","output":[{"type":"function_call","call_id":"c1","name":"read","arguments":"{}"}]})).unwrap().output, ModelOutput::Action(_)));
    }
}
