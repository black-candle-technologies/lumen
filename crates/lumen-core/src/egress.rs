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

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointClass {
    Local,
    Remote,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderRoute {
    provider: ProviderId,
    endpoint_class: EndpointClass,
    enabled: bool,
    provider_allowed_data_classes: BTreeSet<DataClass>,
    workspace_allowed_data_classes: Option<BTreeSet<DataClass>>,
    priority: u32,
}

impl ProviderRoute {
    pub fn new(
        provider: ProviderId,
        endpoint_class: EndpointClass,
        enabled: bool,
        provider_allowed_data_classes: impl IntoIterator<Item = DataClass>,
        workspace_allowed_data_classes: Option<BTreeSet<DataClass>>,
        priority: u32,
    ) -> Result<Self, EgressError> {
        let provider_allowed_data_classes = provider_allowed_data_classes
            .into_iter()
            .collect::<BTreeSet<_>>();
        if provider_allowed_data_classes.is_empty()
            || provider_allowed_data_classes.contains(&DataClass::Secret)
            || workspace_allowed_data_classes
                .as_ref()
                .is_some_and(|classes| classes.is_empty() || classes.contains(&DataClass::Secret))
        {
            return Err(EgressError::InvalidDataClassPolicy);
        }
        Ok(Self {
            provider,
            endpoint_class,
            enabled,
            provider_allowed_data_classes,
            workspace_allowed_data_classes,
            priority,
        })
    }

    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub const fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }

    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    pub const fn priority(&self) -> u32 {
        self.priority
    }

    fn allows(&self, data_class: DataClass) -> bool {
        if !self.enabled || !self.provider_allowed_data_classes.contains(&data_class) {
            return false;
        }
        match self.endpoint_class {
            EndpointClass::Local => true,
            EndpointClass::Remote => self
                .workspace_allowed_data_classes
                .as_ref()
                .is_some_and(|classes| classes.contains(&data_class)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutingDecision {
    provider: ProviderId,
    endpoint_class: EndpointClass,
}

impl RoutingDecision {
    pub const fn local(provider: ProviderId) -> Self {
        Self {
            provider,
            endpoint_class: EndpointClass::Local,
        }
    }

    pub const fn remote(provider: ProviderId) -> Self {
        Self {
            provider,
            endpoint_class: EndpointClass::Remote,
        }
    }

    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    pub const fn endpoint_class(&self) -> EndpointClass {
        self.endpoint_class
    }

    pub const fn egress_occurred(&self) -> bool {
        matches!(self.endpoint_class, EndpointClass::Remote)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RoutingFailure {
    #[error("secret data may not enter model context")]
    SecretDataClass,
    #[error("remote egress policy denied every remote provider")]
    RemoteEgressDenied,
    #[error("no eligible model provider is configured")]
    NoEligibleProvider,
}

pub fn select_model_provider(
    data_class: DataClass,
    routes: impl IntoIterator<Item = ProviderRoute>,
) -> Result<RoutingDecision, RoutingFailure> {
    if data_class == DataClass::Secret {
        return Err(RoutingFailure::SecretDataClass);
    }

    let mut routes = routes
        .into_iter()
        .filter(|route| route.enabled)
        .collect::<Vec<_>>();
    routes.sort_by_key(|route| route.priority);

    if let Some(local) = routes
        .iter()
        .find(|route| route.endpoint_class == EndpointClass::Local && route.allows(data_class))
    {
        return Ok(RoutingDecision::local(local.provider.clone()));
    }

    let remote_available = routes
        .iter()
        .any(|route| route.endpoint_class == EndpointClass::Remote);
    if let Some(remote) = routes
        .iter()
        .find(|route| route.endpoint_class == EndpointClass::Remote && route.allows(data_class))
    {
        return Ok(RoutingDecision::remote(remote.provider.clone()));
    }
    if remote_available {
        Err(RoutingFailure::RemoteEgressDenied)
    } else {
        Err(RoutingFailure::NoEligibleProvider)
    }
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
