use std::{future::Future, pin::Pin};

use serde::Serialize;
use thiserror::Error;

use crate::action::CanonicalValue;

pub type ModelFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ModelOutput, ModelError>> + Send + 'a>>;

pub trait ModelPort: Send + Sync {
    fn generate(&self, input: ModelInput) -> ModelFuture<'_>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelInput {
    messages: Vec<ModelMessage>,
}

impl ModelInput {
    pub fn new(messages: Vec<ModelMessage>) -> Self {
        Self { messages }
    }

    pub fn messages(&self) -> &[ModelMessage] {
        &self.messages
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelMessage {
    role: ModelRole,
    content: CanonicalValue,
}

impl ModelMessage {
    pub const fn new(role: ModelRole, content: CanonicalValue) -> Self {
        Self { role, content }
    }

    pub const fn role(&self) -> ModelRole {
        self.role
    }

    pub const fn content(&self) -> &CanonicalValue {
        &self.content
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
}

impl ActionProposal {
    pub fn new(kind: impl Into<String>, arguments: CanonicalValue) -> Self {
        Self {
            kind: kind.into(),
            arguments,
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
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
