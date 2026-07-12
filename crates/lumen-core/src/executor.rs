use std::{future::Future, pin::Pin};

use thiserror::Error;

use crate::{
    action::{ActionEnvelope, CanonicalValue},
    approval::DispatchAuthorization,
};

pub type ExecutorFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ExecutionOutcome, ExecutorError>> + Send + 'a>>;

pub trait ExecutorPort: Send + Sync {
    fn execute<'a>(&'a self, action: &'a AuthorizedAction) -> ExecutorFuture<'a>;
}

#[derive(Debug)]
pub struct AuthorizedAction {
    action: ActionEnvelope,
    authorization: DispatchAuthorization,
}

impl AuthorizedAction {
    pub(crate) const fn new(action: ActionEnvelope, authorization: DispatchAuthorization) -> Self {
        Self {
            action,
            authorization,
        }
    }

    pub const fn action(&self) -> &ActionEnvelope {
        &self.action
    }

    pub const fn authorization(&self) -> DispatchAuthorization {
        self.authorization
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionOutcome {
    Succeeded(CanonicalValue),
    Failed(String),
    Unknown(String),
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("executor failed before producing an outcome: {message}")]
pub struct ExecutorError {
    message: String,
}

impl ExecutorError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}
