use std::{future::Future, pin::Pin};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{action::CanonicalValue, egress::DataClass};

pub type ModelFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ModelOutput, ModelError>> + Send + 'a>>;

pub trait ModelPort: Send + Sync {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_>;
}

/// The normalized reasoning request.  Adapters never infer this from a prompt.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningProfile {
    Fast,
    Balanced,
    Deep,
    Maximum,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningWireFormat {
    None,
    OpenAi,
    AnthropicAdaptive,
    OpenAiCompatible,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModelGenerationConfig {
    reasoning: ReasoningProfile,
    wire: ReasoningWireFormat,
    provider_effort: Option<String>,
    max_output_tokens: u32,
}
impl ModelGenerationConfig {
    pub fn new(
        reasoning: ReasoningProfile,
        wire: ReasoningWireFormat,
        provider_effort: Option<String>,
        max_output_tokens: u32,
    ) -> Result<Self, ModelError> {
        if max_output_tokens == 0 {
            return Err(ModelError::new(
                "max output tokens must be greater than zero",
            ));
        }
        match (wire, provider_effort.as_deref()) {
            (ReasoningWireFormat::None, None) => {}
            (ReasoningWireFormat::None, Some(_)) => {
                return Err(ModelError::new(
                    "reasoning wire none cannot carry provider effort",
                ));
            }
            (_, Some(value))
                if !value.is_empty()
                    && value.len() <= 32
                    && value.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                    }) => {}
            _ => return Err(ModelError::new("provider reasoning effort is invalid")),
        }
        Ok(Self {
            reasoning,
            wire,
            provider_effort,
            max_output_tokens,
        })
    }
    pub const fn reasoning(&self) -> ReasoningProfile {
        self.reasoning
    }
    pub const fn wire(&self) -> ReasoningWireFormat {
        self.wire
    }
    pub fn provider_effort(&self) -> Option<&str> {
        self.provider_effort.as_deref()
    }
    pub const fn max_output_tokens(&self) -> u32 {
        self.max_output_tokens
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInput {
    messages: Vec<ModelMessage>,
    data_class: DataClass,
    tools: Vec<ModelTool>,
    generation: Option<ModelGenerationConfig>,
}

impl ModelInput {
    pub fn new(messages: Vec<ModelMessage>) -> Self {
        Self {
            messages,
            data_class: DataClass::Workspace,
            tools: Vec::new(),
            generation: None,
        }
    }

    pub fn with_data_class(mut self, data_class: DataClass) -> Self {
        self.data_class = data_class;
        self
    }

    pub fn messages(&self) -> &[ModelMessage] {
        &self.messages
    }

    pub const fn data_class(&self) -> DataClass {
        self.data_class
    }

    pub fn with_tools(mut self, tools: Vec<ModelTool>) -> Self {
        self.tools = tools;
        self
    }

    pub fn tools(&self) -> &[ModelTool] {
        &self.tools
    }

    pub fn with_generation(mut self, generation: ModelGenerationConfig) -> Self {
        self.generation = Some(generation);
        self
    }
    pub fn generation(&self) -> Option<&ModelGenerationConfig> {
        self.generation.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelTool {
    name: String,
    description: String,
    action_kind: String,
    input_schema: CanonicalValue,
}

impl ModelTool {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        action_kind: impl Into<String>,
        input_schema: CanonicalValue,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            action_kind: action_kind.into(),
            input_schema,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn action_kind(&self) -> &str {
        &self.action_kind
    }

    pub const fn input_schema(&self) -> &CanonicalValue {
        &self.input_schema
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelMessage {
    role: ModelRole,
    content: CanonicalValue,
    tool_call: Option<ModelToolCall>,
    tool_call_id: Option<String>,
}

impl ModelMessage {
    pub const fn new(role: ModelRole, content: CanonicalValue) -> Self {
        Self {
            role,
            content,
            tool_call: None,
            tool_call_id: None,
        }
    }

    pub fn assistant_tool_call(call: ModelToolCall) -> Self {
        Self {
            role: ModelRole::Assistant,
            content: CanonicalValue::Null,
            tool_call: Some(call),
            tool_call_id: None,
        }
    }

    pub fn tool_result(call_id: impl Into<String>, content: CanonicalValue) -> Self {
        Self {
            role: ModelRole::Tool,
            content,
            tool_call: None,
            tool_call_id: Some(call_id.into()),
        }
    }

    pub const fn role(&self) -> ModelRole {
        self.role
    }

    pub const fn content(&self) -> &CanonicalValue {
        &self.content
    }

    pub const fn tool_call(&self) -> Option<&ModelToolCall> {
        self.tool_call.as_ref()
    }

    pub fn tool_call_id(&self) -> Option<&str> {
        self.tool_call_id.as_deref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelToolCall {
    id: String,
    name: String,
    arguments: CanonicalValue,
}

impl ModelToolCall {
    pub fn new(id: impl Into<String>, name: impl Into<String>, arguments: CanonicalValue) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            arguments,
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn arguments(&self) -> &CanonicalValue {
        &self.arguments
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelRole {
    User,
    Assistant,
    Tool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModelOutput {
    FinalText(String),
    Action(ActionProposal),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionProposal {
    kind: String,
    arguments: CanonicalValue,
    #[serde(skip_serializing)]
    tool_call: Option<ModelToolCall>,
}

impl ActionProposal {
    pub fn new(kind: impl Into<String>, arguments: CanonicalValue) -> Self {
        Self {
            kind: kind.into(),
            arguments,
            tool_call: None,
        }
    }

    pub fn with_tool_call(mut self, tool_call: ModelToolCall) -> Self {
        self.tool_call = Some(tool_call);
        self
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub const fn tool_call(&self) -> Option<&ModelToolCall> {
        self.tool_call.as_ref()
    }

    pub fn into_arguments(self) -> CanonicalValue {
        self.arguments
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("model failed: {message}")]
pub struct ModelError {
    message: String,
}

impl ModelError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}
