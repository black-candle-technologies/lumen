use super::http;
use lumen_core::{
    model::{ActionProposal, ModelInput, ModelMessage, ModelOutput, ModelRole, ModelToolCall},
    provider::{
        LocalRuntimeKind, ModelCapability, ModelProfile, ProviderAdapter, ProviderConfig,
        ProviderError, ProviderFuture, ProviderKind, ProviderResponse, ProviderUsage,
        validate_binding,
    },
};
use reqwest::{Client, RequestBuilder};
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

pub struct LocalOpenAiCompatibleAdapter {
    config: ProviderConfig,
    key: Option<String>,
    client: Client,
}
impl LocalOpenAiCompatibleAdapter {
    pub fn new(config: ProviderConfig, key: Option<String>) -> Result<Self, ProviderError> {
        if config.kind() != ProviderKind::OpenAiCompatible
            || config.local_runtime().is_none()
            || key
                .as_ref()
                .is_some_and(|key| key.is_empty() || key.chars().any(char::is_control))
        {
            return Err(ProviderError::configuration(
                "invalid local OpenAI-compatible provider",
            ));
        }
        Ok(Self {
            config,
            key,
            client: http::client()?,
        })
    }
    pub fn runtime(&self) -> LocalRuntimeKind {
        self.config
            .local_runtime()
            .expect("validated local runtime")
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
            .join("chat/completions")
            .map_err(|error| ProviderError::configuration(error.to_string()))?;
        let mut body = json!({"model":profile.model_name(),"messages":messages(input.messages()),"tools":tools(input.tools()),"parallel_tool_calls":false,"stream":false});
        if let Some(generation) = input.generation() {
            body["max_tokens"] = json!(generation.max_output_tokens());
            if let Some(effort) = generation.provider_effort() {
                body["reasoning_effort"] = json!(effort);
            }
        }
        parse(
            profile,
            input.tools(),
            http::json(
                self.auth(self.client.post(url))
                    .json(&body)
                    .send()
                    .await
                    .map_err(|error| ProviderError::transport(error.to_string()))?,
            )
            .await?,
        )
    }
    fn auth(&self, request: RequestBuilder) -> RequestBuilder {
        match &self.key {
            Some(key) => request.bearer_auth(key),
            None => request,
        }
    }
}
impl ProviderAdapter for LocalOpenAiCompatibleAdapter {
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
    messages.iter().map(|message| match (message.role(), message.tool_call(), message.tool_call_id()) { (ModelRole::Assistant, Some(call), _) => json!({"role":"assistant","content":Value::Null,"tool_calls":[{"id":call.id(),"type":"function","function":{"name":call.name(),"arguments":serde_json::to_string(call.arguments()).expect("canonical JSON")}}]}), (ModelRole::Tool, _, Some(id)) => json!({"role":"tool","tool_call_id":id,"content":http::text(message.content())}), (ModelRole::Assistant, _, _) => json!({"role":"assistant","content":http::text(message.content())}), _ => json!({"role":"user","content":http::text(message.content())}) }).collect()
}
fn tools(tools: &[lumen_core::model::ModelTool]) -> Vec<Value> {
    tools.iter().map(|tool| json!({"type":"function","function":{"name":tool.name(),"description":tool.description(),"parameters":tool.input_schema()}})).collect()
}
fn parse(
    profile: &ModelProfile,
    advertised: &[lumen_core::model::ModelTool],
    value: Value,
) -> Result<ProviderResponse, ProviderError> {
    let choices = value
        .get("choices")
        .and_then(Value::as_array)
        .ok_or_else(|| ProviderError::protocol("chat response missing choices"))?;
    if choices.len() != 1 {
        return Err(ProviderError::protocol(
            "chat response must contain exactly one choice",
        ));
    }
    let choice = &choices[0];
    if matches!(
        choice.get("finish_reason").and_then(Value::as_str),
        Some("length" | "content_filter")
    ) {
        return Err(ProviderError::protocol(
            "chat response terminated without complete output",
        ));
    }
    let message = choice
        .get("message")
        .ok_or_else(|| ProviderError::protocol("chat response missing message"))?;
    let calls = message
        .get("tool_calls")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let output = if calls.is_empty() {
        let text = message
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        if text.is_empty() {
            return Err(ProviderError::protocol(
                "chat response returned neither text nor tool call",
            ));
        }
        ModelOutput::FinalText(text)
    } else {
        if calls.len() != 1 {
            return Err(ProviderError::protocol(
                "multiple local tool calls are unsupported",
            ));
        }
        let call = &calls[0];
        let id = call
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::protocol("tool call missing id"))?;
        let function = call
            .get("function")
            .ok_or_else(|| ProviderError::protocol("tool call missing function"))?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| ProviderError::protocol("tool call missing name"))?;
        let tool = http::tool(advertised, name)?;
        let arguments = http::args(
            function
                .get("arguments")
                .ok_or_else(|| ProviderError::protocol("tool call missing arguments"))?,
        )?;
        ModelOutput::Action(
            ActionProposal::new(tool.action_kind(), arguments.clone())
                .with_tool_call(ModelToolCall::new(id, name, arguments)),
        )
    };
    let usage = value.get("usage").unwrap_or(&Value::Null);
    ProviderResponse::new(
        value
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or(profile.model_name()),
        output,
        ProviderUsage {
            input_tokens: http::u64_field(usage, "prompt_tokens"),
            output_tokens: http::u64_field(usage, "completion_tokens"),
        },
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use lumen_core::egress::ProviderId;
    #[test]
    fn accepts_all_initial_local_runtimes() {
        for runtime in [
            LocalRuntimeKind::Ollama,
            LocalRuntimeKind::LlamaCpp,
            LocalRuntimeKind::Vllm,
        ] {
            let config = ProviderConfig::local_openai_compatible(
                ProviderId::parse(runtime.as_str()).unwrap(),
                1,
                "http://127.0.0.1:8080/v1/",
                runtime,
                true,
                None,
            )
            .unwrap();
            assert_eq!(
                LocalOpenAiCompatibleAdapter::new(config, None)
                    .unwrap()
                    .runtime(),
                runtime
            );
        }
    }
}
