use std::fmt;

use serde::Serialize;
use thiserror::Error;
use uuid::Uuid;

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

            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
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

uuid_id!(WorkspaceId);

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ExternalChannelIdentity {
    provider: String,
    external_workspace_id: String,
    channel_id: String,
    external_user_id: String,
}

impl ExternalChannelIdentity {
    pub fn new(
        provider: impl Into<String>,
        external_workspace_id: impl Into<String>,
        channel_id: impl Into<String>,
        external_user_id: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            provider: validate_channel_part("provider", provider.into())?,
            external_workspace_id: validate_channel_part(
                "external_workspace_id",
                external_workspace_id.into(),
            )?,
            channel_id: validate_channel_part("channel_id", channel_id.into())?,
            external_user_id: validate_channel_part("external_user_id", external_user_id.into())?,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn external_workspace_id(&self) -> &str {
        &self.external_workspace_id
    }

    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    pub fn external_user_id(&self) -> &str {
        &self.external_user_id
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ChannelDestination {
    provider: String,
    external_workspace_id: String,
    channel_id: String,
    scope_value: String,
}

impl ChannelDestination {
    pub fn new(
        provider: impl Into<String>,
        external_workspace_id: impl Into<String>,
        channel_id: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        let provider = validate_channel_part("provider", provider.into())?;
        let external_workspace_id =
            validate_channel_part("external_workspace_id", external_workspace_id.into())?;
        let channel_id = validate_channel_part("channel_id", channel_id.into())?;
        let scope_value = format!("{provider}:{external_workspace_id}:{channel_id}");
        Ok(Self {
            provider,
            external_workspace_id,
            channel_id,
            scope_value,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn external_workspace_id(&self) -> &str {
        &self.external_workspace_id
    }

    pub fn channel_id(&self) -> &str {
        &self.channel_id
    }

    pub fn as_scope_value(&self) -> &str {
        &self.scope_value
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct PrincipalId {
    provider: String,
    subject: String,
}

impl PrincipalId {
    pub fn new(
        provider: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, IdentityError> {
        Ok(Self {
            provider: validate_identifier_part("provider", provider.into())?,
            subject: validate_identifier_part("subject", subject.into())?,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ComponentId(String);

impl ComponentId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
        {
            return Err(IdentityError::InvalidComponentId);
        }

        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum IdentityError {
    #[error("identity {field} must be non-empty, bounded, and free of control characters")]
    InvalidPart { field: &'static str },
    #[error("channel identity {field} must be non-empty, bounded, and scope-safe")]
    InvalidChannelPart { field: &'static str },
    #[error("component ID must use lowercase ASCII letters, digits, dots, underscores, or hyphens")]
    InvalidComponentId,
}

fn validate_identifier_part(field: &'static str, value: String) -> Result<String, IdentityError> {
    if value.is_empty()
        || value.len() > 512
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(IdentityError::InvalidPart { field });
    }

    Ok(value)
}

fn validate_channel_part(field: &'static str, value: String) -> Result<String, IdentityError> {
    if value.is_empty()
        || value.len() > 256
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() || character == ':' || character == '/')
    {
        return Err(IdentityError::InvalidChannelPart { field });
    }

    Ok(value)
}
