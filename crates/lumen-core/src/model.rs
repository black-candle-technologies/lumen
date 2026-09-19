use std::{future::Future, pin::Pin};

use serde::Serialize;
use thiserror::Error;

use crate::{action::CanonicalValue, egress::DataClass};

pub type ModelFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ModelOutput, ModelError>> + Send + 'a>>;

pub trait ModelPort: Send + Sync {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInput {
    messages: Vec<ModelMessage>,
    data_class: DataClass,
    tools: Vec<ModelTool>,
}

impl ModelInput {
    pub fn new(messages: Vec<ModelMessage>) -> Self {
        Self {
            messages,
            data_class: DataClass::Workspace,
            tools: Vec::new(),
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
