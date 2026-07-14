use std::fmt;

use semver::Version;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use sha2::Digest as _;
use thiserror::Error;

use crate::{
    action::{ActionId, ActionKind, CanonicalValue},
    capability::{Capability, CapabilityName},
};

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct PluginId(String);

impl PluginId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionIdentityError> {
        let value = value.into();
        let labels = value.split('.').collect::<Vec<_>>();
        if value.len() > 255
            || labels.len() < 3
            || labels.iter().any(|label| !valid_label(label, 63))
        {
            return Err(ExtensionIdentityError::InvalidPluginId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PluginId {
    type Error = ExtensionIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl fmt::Display for PluginId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct PluginComponentId(String);

impl PluginComponentId {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionIdentityError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
            })
            || !value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(ExtensionIdentityError::InvalidComponentId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PluginComponentId {
    type Error = ExtensionIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl fmt::Display for PluginComponentId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct PluginVersion(String);

impl PluginVersion {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionIdentityError> {
        let value = value.into();
        let parsed = Version::parse(&value).map_err(|_| ExtensionIdentityError::InvalidVersion)?;
        if parsed.to_string() != value {
            return Err(ExtensionIdentityError::InvalidVersion);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PluginVersion {
    type Error = ExtensionIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl fmt::Display for PluginVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "String")]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, ExtensionIdentityError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            return Err(ExtensionIdentityError::InvalidDigest);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Sha256Digest {
    type Error = ExtensionIdentityError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse(value)
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(try_from = "u16")]
pub struct ProtocolVersion(u16);

impl ProtocolVersion {
    pub const fn new(value: u16) -> Result<Self, ExtensionIdentityError> {
        if value == 0 {
            return Err(ExtensionIdentityError::InvalidProtocolVersion);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for ProtocolVersion {
    type Error = ExtensionIdentityError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginRuntime {
    WasmComponent,
    Subprocess,
}

impl PluginRuntime {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WasmComponent => "wasm-component",
            Self::Subprocess => "subprocess",
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ManifestPath(String);

impl ManifestPath {
    pub fn parse(value: impl Into<String>) -> Result<Self, ManifestError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 4096
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
            return Err(ManifestError::InvalidPath);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ManifestPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginRuntimeManifest {
    #[serde(rename = "type")]
    runtime: PluginRuntime,
    entrypoint: ManifestPath,
    protocol_version: ProtocolVersion,
}

impl PluginRuntimeManifest {
    pub const fn runtime(&self) -> PluginRuntime {
        self.runtime
    }

    pub const fn entrypoint(&self) -> &ManifestPath {
        &self.entrypoint
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PluginComponentKind {
    Tool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ManifestCapabilityScope {
    Workspace,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestCapabilityRequest {
    name: CapabilityName,
    scope: ManifestCapabilityScope,
}

impl ManifestCapabilityRequest {
    pub const fn name(&self) -> CapabilityName {
        self.name
    }

    pub const fn scope(&self) -> ManifestCapabilityScope {
        self.scope
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginComponentManifest {
    id: PluginComponentId,
    kind: PluginComponentKind,
    description: String,
    input_schema: ManifestPath,
    output_schema: ManifestPath,
    #[serde(default)]
    action_kinds: Vec<ActionKind>,
    #[serde(default)]
    capabilities: Vec<ManifestCapabilityRequest>,
}

impl PluginComponentManifest {
    pub const fn id(&self) -> &PluginComponentId {
        &self.id
    }

    pub const fn kind(&self) -> PluginComponentKind {
        self.kind
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub const fn input_schema(&self) -> &ManifestPath {
        &self.input_schema
    }

    pub const fn output_schema(&self) -> &ManifestPath {
        &self.output_schema
    }

    pub fn action_kinds(&self) -> &[ActionKind] {
        &self.action_kinds
    }

    pub fn capabilities(&self) -> &[ManifestCapabilityRequest] {
        &self.capabilities
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSettingsManifest {
    schema: ManifestPath,
}

impl PluginSettingsManifest {
    pub const fn schema(&self) -> &ManifestPath {
        &self.schema
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IntegrityAlgorithm {
    Sha256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginIntegrityManifest {
    algorithm: IntegrityAlgorithm,
    artifact: Sha256Digest,
}

impl PluginIntegrityManifest {
    pub const fn algorithm(&self) -> IntegrityAlgorithm {
        self.algorithm
    }

    pub const fn artifact(&self) -> &Sha256Digest {
        &self.artifact
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PluginManifest {
    manifest_version: u16,
    id: PluginId,
    name: String,
    version: PluginVersion,
    description: String,
    runtime: PluginRuntimeManifest,
    components: Vec<PluginComponentManifest>,
    settings: Option<PluginSettingsManifest>,
    integrity: PluginIntegrityManifest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPluginManifest {
    manifest_version: u16,
    id: PluginId,
    name: String,
    version: PluginVersion,
    description: String,
    runtime: PluginRuntimeManifest,
    components: Vec<PluginComponentManifest>,
    settings: Option<PluginSettingsManifest>,
    integrity: PluginIntegrityManifest,
}

impl<'de> Deserialize<'de> for PluginManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawPluginManifest::deserialize(deserializer)?;
        if raw.manifest_version != 1 {
            return Err(D::Error::custom(ManifestError::UnsupportedVersion));
        }
        if !valid_text(&raw.name, 128) || !valid_text(&raw.description, 1024) {
            return Err(D::Error::custom(ManifestError::InvalidText));
        }
        if raw.components.is_empty() || raw.components.len() > 128 {
            return Err(D::Error::custom(ManifestError::InvalidComponentCount));
        }
        let mut ids = std::collections::BTreeSet::new();
        for component in &raw.components {
            if !ids.insert(component.id.clone()) {
                return Err(D::Error::custom(ManifestError::DuplicateComponent));
            }
            if !valid_text(&component.description, 1024)
                || component.action_kinds.len() > 128
                || component.capabilities.len() > 128
            {
                return Err(D::Error::custom(ManifestError::InvalidComponent));
            }
        }
        Ok(Self {
            manifest_version: raw.manifest_version,
            id: raw.id,
            name: raw.name,
            version: raw.version,
            description: raw.description,
            runtime: raw.runtime,
            components: raw.components,
            settings: raw.settings,
            integrity: raw.integrity,
        })
    }
}

impl PluginManifest {
    pub const fn manifest_version(&self) -> u16 {
        self.manifest_version
    }

    pub const fn id(&self) -> &PluginId {
        &self.id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub const fn version(&self) -> &PluginVersion {
        &self.version
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub const fn runtime(&self) -> &PluginRuntimeManifest {
        &self.runtime
    }

    pub fn components(&self) -> &[PluginComponentManifest] {
        &self.components
    }

    pub const fn settings(&self) -> Option<&PluginSettingsManifest> {
        self.settings.as_ref()
    }

    pub const fn integrity(&self) -> &PluginIntegrityManifest {
        &self.integrity
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ManifestError {
    #[error("manifest path must be a canonical package-relative path")]
    InvalidPath,
    #[error("manifest version is unsupported")]
    UnsupportedVersion,
    #[error("manifest text is empty, unbounded, or contains control characters")]
    InvalidText,
    #[error("manifest must declare between one and 128 components")]
    InvalidComponentCount,
    #[error("manifest component IDs must be unique")]
    DuplicateComponent,
    #[error("manifest component metadata exceeds its bounds")]
    InvalidComponent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ExtensionInvocationLimits {
    deadline_millis: u64,
    max_result_bytes: u64,
    fuel: u64,
    max_memory_bytes: u64,
}

impl ExtensionInvocationLimits {
    pub const fn new(
        deadline_millis: u64,
        max_result_bytes: u64,
        fuel: u64,
        max_memory_bytes: u64,
    ) -> Result<Self, InvocationContractError> {
        if deadline_millis == 0 || max_result_bytes == 0 || fuel == 0 || max_memory_bytes == 0 {
            return Err(InvocationContractError::InvalidLimits);
        }
        Ok(Self {
            deadline_millis,
            max_result_bytes,
            fuel,
            max_memory_bytes,
        })
    }

    pub const fn deadline_millis(self) -> u64 {
        self.deadline_millis
    }

    pub const fn max_result_bytes(self) -> u64 {
        self.max_result_bytes
    }

    pub const fn fuel(self) -> u64 {
        self.fuel
    }

    pub const fn max_memory_bytes(self) -> u64 {
        self.max_memory_bytes
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionFailureClass {
    PluginFault,
    HostFault,
    PolicyDenied,
    Cancelled,
    ResourceExhaustion,
}

impl ExtensionFailureClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PluginFault => "plugin_fault",
            Self::HostFault => "host_fault",
            Self::PolicyDenied => "policy_denied",
            Self::Cancelled => "cancelled",
            Self::ResourceExhaustion => "resource_exhaustion",
        }
    }

    pub const fn counts_toward_health(self) -> bool {
        matches!(self, Self::PluginFault | Self::ResourceExhaustion)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionFailure {
    class: ExtensionFailureClass,
    message: String,
}

impl ExtensionFailure {
    pub fn new(
        class: ExtensionFailureClass,
        message: impl Into<String>,
    ) -> Result<Self, InvocationContractError> {
        let message = message.into();
        if message.is_empty() || message.len() > 4096 || message.chars().any(char::is_control) {
            return Err(InvocationContractError::InvalidFailure);
        }
        Ok(Self { class, message })
    }

    pub const fn class(&self) -> ExtensionFailureClass {
        self.class
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionResponse {
    Result {
        value: CanonicalValue,
    },
    Proposal {
        kind: ActionKind,
        arguments: CanonicalValue,
    },
    Failure {
        failure: ExtensionFailure,
    },
}

impl ExtensionResponse {
    pub const fn result(value: CanonicalValue) -> Self {
        Self::Result { value }
    }

    pub const fn proposal(kind: ActionKind, arguments: CanonicalValue) -> Self {
        Self::Proposal { kind, arguments }
    }

    pub const fn failure(failure: ExtensionFailure) -> Self {
        Self::Failure { failure }
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InvocationContractError {
    #[error("extension invocation limits must all be greater than zero")]
    InvalidLimits,
    #[error("extension failure text must be non-empty, bounded, and free of controls")]
    InvalidFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ExtensionProvenance {
    plugin_id: PluginId,
    plugin_version: PluginVersion,
    component_id: PluginComponentId,
    runtime: PluginRuntime,
    package_digest: Sha256Digest,
    manifest_digest: Sha256Digest,
    artifact_digest: Sha256Digest,
    settings_digest: Sha256Digest,
    grant_set_digest: Sha256Digest,
    protocol_version: ProtocolVersion,
    parent_action_id: Option<ActionId>,
}

impl ExtensionProvenance {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        plugin_id: PluginId,
        plugin_version: PluginVersion,
        component_id: PluginComponentId,
        runtime: PluginRuntime,
        package_digest: Sha256Digest,
        manifest_digest: Sha256Digest,
        artifact_digest: Sha256Digest,
        settings_digest: Sha256Digest,
        grant_set_digest: Sha256Digest,
        protocol_version: ProtocolVersion,
        parent_action_id: Option<ActionId>,
    ) -> Self {
        Self {
            plugin_id,
            plugin_version,
            component_id,
            runtime,
            package_digest,
            manifest_digest,
            artifact_digest,
            settings_digest,
            grant_set_digest,
            protocol_version,
            parent_action_id,
        }
    }

    pub fn resource_key(&self) -> String {
        format!(
            "{}@{}#{}",
            self.plugin_id, self.plugin_version, self.component_id
        )
    }

    pub fn with_settings_digest(mut self, digest: Sha256Digest) -> Self {
        self.settings_digest = digest;
        self
    }

    pub fn with_grant_set_digest(mut self, digest: Sha256Digest) -> Self {
        self.grant_set_digest = digest;
        self
    }

    pub const fn plugin_id(&self) -> &PluginId {
        &self.plugin_id
    }

    pub const fn plugin_version(&self) -> &PluginVersion {
        &self.plugin_version
    }

    pub const fn component_id(&self) -> &PluginComponentId {
        &self.component_id
    }

    pub const fn runtime(&self) -> PluginRuntime {
        self.runtime
    }

    pub const fn package_digest(&self) -> &Sha256Digest {
        &self.package_digest
    }

    pub const fn manifest_digest(&self) -> &Sha256Digest {
        &self.manifest_digest
    }

    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }

    pub const fn settings_digest(&self) -> &Sha256Digest {
        &self.settings_digest
    }

    pub const fn grant_set_digest(&self) -> &Sha256Digest {
        &self.grant_set_digest
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn parent_action_id(&self) -> Option<ActionId> {
        self.parent_action_id
    }
}

pub fn canonical_grant_set_digest(grants: &[Capability]) -> Sha256Digest {
    let mut grants = grants.to_vec();
    grants.sort_unstable();
    grants.dedup();
    let encoded = serde_json::to_vec(&grants).expect("capability serialization cannot fail");
    Sha256Digest::parse(format!("{:x}", sha2::Sha256::digest(encoded)))
        .expect("SHA-256 output is canonical")
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ExtensionIdentityError {
    #[error("plugin ID must contain at least three canonical lowercase DNS-style labels")]
    InvalidPluginId,
    #[error("plugin component ID must be a bounded canonical lowercase ASCII identifier")]
    InvalidComponentId,
    #[error("plugin version must be a canonical semantic version")]
    InvalidVersion,
    #[error("SHA-256 digest must be exactly 64 lowercase hexadecimal characters")]
    InvalidDigest,
    #[error("extension protocol version must be greater than zero")]
    InvalidProtocolVersion,
}

fn valid_label(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_text(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
