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
