use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use lumen_core::identity::{PrincipalId, WorkspaceId};
use lumen_integrations::sandbox::{SandboxReport, SandboxStrength};
use serde::Deserialize;
use thiserror::Error;
use url::{Host, Url};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub authentication: AuthenticationConfig,
    pub database: DatabaseConfig,
    pub model: ModelConfig,
    #[serde(default)]
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub process: ProcessConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    pub workspace: WorkspaceConfig,
    pub bootstrap_admin: BootstrapAdminConfig,
}

impl Config {
    pub fn parse(contents: &str) -> Result<Self, ConfigError> {
        let config: Self =
            toml::from_str(contents).map_err(|error| ConfigError::Parse(error.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let contents = std::fs::read_to_string(path)
            .map_err(|error| ConfigError::Read(path.to_path_buf(), error.to_string()))?;
        let mut config = Self::parse(&contents)?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        resolve_relative(&mut config.database.path, base);
        resolve_relative(&mut config.workspace.path, base);
        resolve_relative(&mut config.runtime.data_directory, base);
        Ok(config)
    }

    pub fn validate_sandbox(&self, report: &SandboxReport) -> Result<(), ConfigError> {
        match self.sandbox.required_strength {
            RequiredSandboxStrength::KernelEnforced
                if report.strength() != SandboxStrength::KernelEnforced =>
            {
                let detail = report
                    .detail()
                    .unwrap_or("required strength is unavailable");
                Err(ConfigError::SandboxUnavailable(format!(
                    "{}: {detail}",
                    report.backend()
                )))
            }
            _ => Ok(()),
        }
    }

    pub fn workspace_id(&self) -> WorkspaceId {
        WorkspaceId::from_uuid(
            Uuid::parse_str(&self.workspace.id).expect("configuration validation parsed UUID"),
        )
    }

    pub fn bootstrap_principal(&self) -> PrincipalId {
        PrincipalId::new(
            &self.bootstrap_admin.provider,
            &self.bootstrap_admin.subject,
        )
        .expect("configuration validation checked principal")
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.server.bind.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackBind(self.server.bind.ip()));
        }
        let endpoint_class = classify_model_endpoint(&self.model.endpoint)?;
        if endpoint_class == ModelEndpointClass::Remote {
            if !self.model.allow_remote {
                return Err(ConfigError::RemoteModelDenied);
            }
            let provider = self
                .model
                .remote_provider
                .as_ref()
                .ok_or(ConfigError::RemoteModelPolicyRequired)?;
            validate_remote_provider(provider)?;
        }
        if self.model.model.trim().is_empty() {
            return Err(ConfigError::InvalidModel);
        }
        Uuid::parse_str(&self.workspace.id).map_err(|_| ConfigError::InvalidWorkspaceId)?;
        if self.workspace.name.trim().is_empty() || self.workspace.path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidWorkspace);
        }
        PrincipalId::new(
            &self.bootstrap_admin.provider,
            &self.bootstrap_admin.subject,
        )
        .map_err(|_| ConfigError::InvalidBootstrapIdentity)?;
        if self.authentication.token_environment.trim().is_empty()
            || self
                .authentication
                .token_environment
                .chars()
                .any(char::is_whitespace)
        {
            return Err(ConfigError::InvalidTokenEnvironment);
        }
        if self.model.timeout_seconds == 0
            || self.model.max_response_bytes == 0
            || self.process.timeout_seconds == 0
            || self.process.max_output_bytes == 0
            || self.process.max_cpu_seconds == 0
            || self.process.max_address_space_bytes == 0
            || self.process.max_file_size_bytes == 0
            || self.process.max_open_files == 0
            || self.process.max_processes == 0
            || self.runtime.file_read_limit_bytes == 0
            || self.runtime.file_write_limit_bytes == 0
            || self.runtime.max_model_turns == 0
            || self.runtime.max_actions == 0
            || self.runtime.max_wall_time_seconds == 0
            || self.runtime.max_captured_result_bytes == 0
            || self.runtime.approval_ttl_seconds == 0
        {
            return Err(ConfigError::InvalidLimit);
        }
        Ok(())
    }
}

fn resolve_relative(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

fn classify_model_endpoint(value: &str) -> Result<ModelEndpointClass, ConfigError> {
    let url = Url::parse(value).map_err(|_| ConfigError::InvalidModelEndpoint)?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(ConfigError::InvalidModelEndpoint);
    }
    let loopback = match url.host().ok_or(ConfigError::InvalidModelEndpoint)? {
        Host::Ipv4(address) => address.is_loopback(),
        Host::Ipv6(address) => address.is_loopback(),
        Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
    };
    if !loopback {
        return Ok(ModelEndpointClass::Remote);
    }
    Ok(ModelEndpointClass::Local)
}

fn validate_remote_provider(provider: &RemoteModelProviderConfig) -> Result<(), ConfigError> {
    if provider.id.is_empty()
        || provider.id.len() > 128
        || provider.id.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ':' | '/'))
        })
    {
        return Err(ConfigError::InvalidRemoteProvider);
    }
    if provider.allowed_data_classes.is_empty()
        || provider
            .allowed_data_classes
            .contains(&RemoteDataClass::Secret)
    {
        return Err(ConfigError::InvalidRemoteDataClass);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelEndpointClass {
    Local,
    Remote,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::from(([127, 0, 0, 1], 3210)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub token_environment: String,
}

impl Default for AuthenticationConfig {
    fn default() -> Self {
        Self {
            token_environment: "LUMEN_BEARER_TOKEN".into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DatabaseConfig {
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ModelConfig {
    pub endpoint: String,
    pub model: String,
    pub allow_remote: bool,
    pub remote_provider: Option<RemoteModelProviderConfig>,
    pub streaming: bool,
    pub timeout_seconds: u64,
    pub max_response_bytes: usize,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            endpoint: String::new(),
            model: String::new(),
            allow_remote: false,
            remote_provider: None,
            streaming: true,
            timeout_seconds: 120,
            max_response_bytes: 4 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RemoteModelProviderConfig {
    pub id: String,
    pub allowed_data_classes: BTreeSet<RemoteDataClass>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd)]
#[serde(rename_all = "snake_case")]
pub enum RemoteDataClass {
    Public,
    Workspace,
    Sensitive,
    Secret,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum RequiredSandboxStrength {
    KernelEnforced,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub required_strength: RequiredSandboxStrength,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            required_strength: RequiredSandboxStrength::KernelEnforced,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessConfig {
    pub allowed_programs: BTreeSet<PathBuf>,
    pub allowed_environment: BTreeSet<String>,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    pub max_cpu_seconds: u64,
    pub max_address_space_bytes: u64,
    pub max_file_size_bytes: u64,
    pub max_open_files: u64,
    pub max_processes: u64,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            allowed_programs: BTreeSet::new(),
            allowed_environment: BTreeSet::new(),
            timeout_seconds: 30,
            max_output_bytes: 1024 * 1024,
            max_cpu_seconds: 10,
            max_address_space_bytes: 512 * 1024 * 1024,
            max_file_size_bytes: 16 * 1024 * 1024,
            max_open_files: 64,
            max_processes: 512,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    pub data_directory: PathBuf,
    pub file_read_limit_bytes: usize,
    pub file_write_limit_bytes: usize,
    pub max_model_turns: u32,
    pub max_actions: u32,
    pub max_wall_time_seconds: u64,
    pub max_captured_result_bytes: usize,
    pub approval_ttl_seconds: u64,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            data_directory: PathBuf::from("runtime"),
            file_read_limit_bytes: 1024 * 1024,
            file_write_limit_bytes: 1024 * 1024,
            max_model_turns: 8,
            max_actions: 8,
            max_wall_time_seconds: 300,
            max_captured_result_bytes: 4 * 1024 * 1024,
            approval_ttl_seconds: 300,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceConfig {
    pub id: String,
    pub name: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BootstrapAdminConfig {
    pub provider: String,
    pub subject: String,
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ConfigError {
    #[error("configuration could not be read from {0}: {1}")]
    Read(PathBuf, String),
    #[error("configuration is invalid: {0}")]
    Parse(String),
    #[error("server bind address must be loopback, got {0}")]
    NonLoopbackBind(IpAddr),
    #[error("remote model endpoints are disabled")]
    RemoteModelDenied,
    #[error("remote model endpoint requires explicit provider policy")]
    RemoteModelPolicyRequired,
    #[error("remote model provider is invalid")]
    InvalidRemoteProvider,
    #[error("remote model data class policy is invalid")]
    InvalidRemoteDataClass,
    #[error("model endpoint is invalid")]
    InvalidModelEndpoint,
    #[error("model name must be non-empty")]
    InvalidModel,
    #[error("workspace ID must be a UUID")]
    InvalidWorkspaceId,
    #[error("workspace name and path must be non-empty")]
    InvalidWorkspace,
    #[error("bootstrap administrator identity is invalid")]
    InvalidBootstrapIdentity,
    #[error("authentication token environment variable is invalid")]
    InvalidTokenEnvironment,
    #[error("runtime limits must be greater than zero")]
    InvalidLimit,
    #[error("required sandbox is unavailable: {0}")]
    SandboxUnavailable(String),
}
