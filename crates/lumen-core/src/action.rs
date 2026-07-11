use std::{collections::BTreeMap, fmt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    capability::Capability,
    identity::{ComponentId, PrincipalId, WorkspaceId},
};

macro_rules! uuid_id {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            pub const fn from_uuid(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

uuid_id!(ActionId);
uuid_id!(RunId);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ActionKind(String);

impl ActionKind {
    pub fn new(value: impl Into<String>) -> Result<Self, ActionError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(ActionError::InvalidKind);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum CanonicalValue {
    Null,
    Bool(bool),
    Integer(i64),
    String(String),
    Array(Vec<CanonicalValue>),
    Object(BTreeMap<String, CanonicalValue>),
}

impl CanonicalValue {
    pub fn object<K>(entries: impl IntoIterator<Item = (K, Self)>) -> Self
    where
        K: Into<String>,
    {
        Self::Object(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
        )
    }
}

impl From<&str> for CanonicalValue {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for CanonicalValue {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<i64> for CanonicalValue {
    fn from(value: i64) -> Self {
        Self::Integer(value)
    }
}

impl From<bool> for CanonicalValue {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ActionEnvelope {
    schema_version: u16,
    action_id: ActionId,
    run_id: RunId,
    workspace_id: WorkspaceId,
    actor: PrincipalId,
    requesting_component: ComponentId,
    kind: ActionKind,
    arguments: CanonicalValue,
    required_capabilities: Vec<Capability>,
}

impl ActionEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        action_id: ActionId,
        run_id: RunId,
        workspace_id: WorkspaceId,
        actor: PrincipalId,
        requesting_component: ComponentId,
        kind: ActionKind,
        arguments: CanonicalValue,
        mut required_capabilities: Vec<Capability>,
    ) -> Self {
        required_capabilities.sort_unstable();
        required_capabilities.dedup();

        Self {
            schema_version: 1,
            action_id,
            run_id,
            workspace_id,
            actor,
            requesting_component,
            kind,
            arguments,
            required_capabilities,
        }
    }

    pub fn required_capabilities(&self) -> &[Capability] {
        &self.required_capabilities
    }

    pub const fn id(&self) -> ActionId {
        self.action_id
    }

    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub const fn actor(&self) -> &PrincipalId {
        &self.actor
    }

    pub const fn requesting_component(&self) -> &ComponentId {
        &self.requesting_component
    }

    pub const fn kind(&self) -> &ActionKind {
        &self.kind
    }

    pub const fn arguments(&self) -> &CanonicalValue {
        &self.arguments
    }

    pub fn fingerprint(&self) -> ActionFingerprint {
        let encoded = serde_json::to_vec(self).expect("action envelope serialization cannot fail");
        let digest = Sha256::digest(encoded);
        ActionFingerprint(format!("{digest:x}"))
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ActionFingerprint(String);

impl ActionFingerprint {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ActionFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ActionError {
    #[error("action kind must use lowercase ASCII letters, digits, dots, underscores, or hyphens")]
    InvalidKind,
}
