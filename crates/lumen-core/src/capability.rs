use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::WorkspaceId;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CapabilityName {
    #[serde(rename = "fs.read")]
    FsRead,
    #[serde(rename = "fs.write")]
    FsWrite,
    #[serde(rename = "fs.delete")]
    FsDelete,
    #[serde(rename = "process.spawn")]
    ProcessSpawn,
    #[serde(rename = "net.connect")]
    NetConnect,
    #[serde(rename = "secret.use")]
    SecretUse,
    #[serde(rename = "message.send")]
    MessageSend,
    #[serde(rename = "schedule.create")]
    ScheduleCreate,
    #[serde(rename = "schedule.modify")]
    ScheduleModify,
    #[serde(rename = "plugin.install")]
    PluginInstall,
    #[serde(rename = "plugin.update")]
    PluginUpdate,
    #[serde(rename = "plugin.enable")]
    PluginEnable,
    #[serde(rename = "policy.modify")]
    PolicyModify,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct WorkspacePath(String);

impl WorkspacePath {
    pub fn parse(value: impl Into<String>) -> Result<Self, ScopeError> {
        let value = value.into();
        if value.is_empty()
            || value.starts_with('/')
            || value.ends_with('/')
            || value.contains('\\')
            || value.split('/').any(|segment| {
                segment.is_empty()
                    || segment == "."
                    || segment == ".."
                    || segment.chars().any(char::is_control)
            })
        {
            return Err(ScopeError::InvalidWorkspacePath(value));
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn contains(&self, requested: &Self) -> bool {
        requested == self
            || requested
                .0
                .strip_prefix(&self.0)
                .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResourceScope {
    Workspace {
        workspace_id: WorkspaceId,
    },
    Path {
        workspace_id: WorkspaceId,
        path: WorkspacePath,
    },
    Exact {
        resource_type: String,
        value: String,
    },
}

impl ResourceScope {
    pub const fn workspace(workspace_id: WorkspaceId) -> Self {
        Self::Workspace { workspace_id }
    }

    pub const fn path(workspace_id: WorkspaceId, path: WorkspacePath) -> Self {
        Self::Path { workspace_id, path }
    }

    pub fn exact(
        resource_type: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, ScopeError> {
        let resource_type = resource_type.into();
        let value = value.into();
        if !valid_exact_part(&resource_type) || !valid_exact_part(&value) {
            return Err(ScopeError::InvalidExactScope);
        }

        Ok(Self::Exact {
            resource_type,
            value,
        })
    }

    pub fn contains(&self, requested: &Self) -> bool {
        match (self, requested) {
            (
                Self::Workspace { workspace_id },
                Self::Workspace {
                    workspace_id: requested_id,
                }
                | Self::Path {
                    workspace_id: requested_id,
                    ..
                },
            ) => workspace_id == requested_id,
            (
                Self::Path { workspace_id, path },
                Self::Path {
                    workspace_id: requested_id,
                    path: requested_path,
                },
            ) => workspace_id == requested_id && path.contains(requested_path),
            (Self::Exact { .. }, Self::Exact { .. }) => self == requested,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Capability {
    name: CapabilityName,
    scope: ResourceScope,
}

impl Capability {
    pub const fn new(name: CapabilityName, scope: ResourceScope) -> Self {
        Self { name, scope }
    }

    pub const fn name(&self) -> CapabilityName {
        self.name
    }

    pub const fn scope(&self) -> &ResourceScope {
        &self.scope
    }

    fn allows(&self, requested: &Self) -> bool {
        self.name == requested.name && self.scope.contains(&requested.scope)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CapabilitySet(BTreeSet<Capability>);

impl CapabilitySet {
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        Self(capabilities.into_iter().collect())
    }

    pub fn allows(&self, requested: &Capability) -> bool {
        self.0.iter().any(|grant| grant.allows(requested))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct EffectiveCapabilities(Vec<CapabilitySet>);

impl EffectiveCapabilities {
    pub fn new(layers: impl IntoIterator<Item = CapabilitySet>) -> Self {
        Self(layers.into_iter().collect())
    }

    pub fn allows(&self, requested: &Capability) -> bool {
        !self.0.is_empty() && self.0.iter().all(|layer| layer.allows(requested))
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScopeError {
    #[error("workspace path is not canonical: {0}")]
    InvalidWorkspacePath(String),
    #[error("exact resource scope fields must be non-empty and free of control characters")]
    InvalidExactScope,
}

fn valid_exact_part(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
