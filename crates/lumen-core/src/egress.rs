use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Workspace,
    Sensitive,
    Secret,
}

impl DataClass {
    pub const fn may_leave_runtime(self) -> bool {
        !matches!(self, Self::Secret)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct ProviderId(String);

impl ProviderId {
    pub fn parse(value: impl Into<String>) -> Result<Self, EgressError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || value
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || b"._-".contains(&byte)))
        {
            return Err(EgressError::InvalidProviderId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ProviderId {
    type Error = EgressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProviderEgressPolicy {
    provider: ProviderId,
    allowed_data_classes: BTreeSet<DataClass>,
}

impl ProviderEgressPolicy {
    pub fn new(
        provider: ProviderId,
        allowed_data_classes: impl IntoIterator<Item = DataClass>,
    ) -> Result<Self, EgressError> {
        let allowed_data_classes = allowed_data_classes.into_iter().collect::<BTreeSet<_>>();
        if allowed_data_classes.is_empty() || allowed_data_classes.contains(&DataClass::Secret) {
            return Err(EgressError::InvalidDataClassPolicy);
        }
        Ok(Self {
            provider,
            allowed_data_classes,
        })
    }

    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub fn allows(&self, data_class: DataClass) -> bool {
        self.allowed_data_classes.contains(&data_class)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct DestinationScope(String);

impl DestinationScope {
    pub fn parse(value: impl AsRef<str>) -> Result<Self, EgressError> {
        let mut url = Url::parse(value.as_ref()).map_err(|_| EgressError::InvalidDestination)?;
        if url.scheme() != "https"
            || url.host().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(EgressError::InvalidDestination);
        }
        if url.path().is_empty() {
            url.set_path("/");
        }
        Ok(Self(url.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for DestinationScope {
    type Error = EgressError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EgressError {
    #[error("provider ID is invalid")]
    InvalidProviderId,
    #[error("data class policy is invalid")]
    InvalidDataClassPolicy,
    #[error("destination scope is invalid")]
    InvalidDestination,
}
