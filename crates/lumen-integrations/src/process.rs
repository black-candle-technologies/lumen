use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorFuture, ExecutorPort},
    identity::{ComponentId, WorkspaceId},
    model::ActionProposal,
    run::{ActionNormalizer, NormalizationError, RunContext},
    secret::SecretRefId,
};
use serde::Deserialize;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::filesystem::{PreparedFileWrite, WorkspaceReader};
use crate::sandbox::{
    MonitoredCommand, ResourceLimits, SandboxBackend, SandboxError, SandboxRequest, SandboxStrength,
};

pub struct BuiltinActionNormalizer {
    component: ComponentId,
    filesystem: Option<WorkspaceReader>,
}

impl BuiltinActionNormalizer {
    pub const fn new(component: ComponentId) -> Self {
        Self {
            component,
            filesystem: None,
        }
    }

    pub const fn with_filesystem(component: ComponentId, filesystem: WorkspaceReader) -> Self {
        Self {
            component,
            filesystem: Some(filesystem),
        }
    }
}

impl ActionNormalizer for BuiltinActionNormalizer {
    fn normalize(
        &self,
        context: &RunContext,
        proposal: ActionProposal,
    ) -> Result<ActionEnvelope, NormalizationError> {
        let kind = proposal.kind().to_owned();
        let arguments = proposal.into_arguments();
        match kind.as_str() {
            "filesystem.read" => {
                let parsed: FilesystemReadArguments = parse_arguments(&arguments)?;
                let path = WorkspacePath::parse(parsed.path)
                    .map_err(|error| NormalizationError::new(error.to_string()))?;
                Ok(ActionEnvelope::new(
                    ActionId::new(),
                    context.run_id(),
                    context.workspace_id(),
                    context.actor().clone(),
                    self.component.clone(),
                    ActionKind::new(kind)
                        .map_err(|error| NormalizationError::new(error.to_string()))?,
                    CanonicalValue::object([("path", CanonicalValue::from(path.as_str()))]),
                    vec![Capability::new(
                        CapabilityName::FsRead,
                        ResourceScope::path(context.workspace_id(), path),
                    )],
                ))
            }
            "filesystem.write" => {
                let parsed: FilesystemWriteProposal = parse_arguments(&arguments)?;
                let path = WorkspacePath::parse(parsed.path)
                    .map_err(|error| NormalizationError::new(error.to_string()))?;
                let filesystem = self.filesystem.as_ref().ok_or_else(|| {
                    NormalizationError::new("file writes are unavailable for this runtime")
                })?;
                let prepared = filesystem
                    .prepare_write(&path, parsed.content)
                    .map_err(|error| NormalizationError::new(error.to_string()))?;
                let arguments = prepared
                    .to_canonical_value()
                    .map_err(|error| NormalizationError::new(error.to_string()))?;
                Ok(ActionEnvelope::new(
                    ActionId::new(),
                    context.run_id(),
                    context.workspace_id(),
                    context.actor().clone(),
                    self.component.clone(),
                    ActionKind::new(kind)
                        .map_err(|error| NormalizationError::new(error.to_string()))?,
                    arguments,
                    vec![Capability::new(
                        CapabilityName::FsWrite,
                        ResourceScope::path(context.workspace_id(), path),
                    )],
                ))
            }
            "process.spawn" => {
                let parsed: ProcessArguments = parse_arguments(&arguments)?;
                let program = std::fs::canonicalize(&parsed.program).map_err(|error| {
                    NormalizationError::new(format!("executable could not be resolved: {error}"))
                })?;
                let program = program.to_string_lossy().into_owned();
                let scope = ResourceScope::exact("executable", &program)
                    .map_err(|error| NormalizationError::new(error.to_string()))?;
                let secret_environment = parse_secret_environment(parsed.secret_environment)?;
                if secret_environment
                    .keys()
                    .any(|name| parsed.environment.contains_key(name))
                {
                    return Err(NormalizationError::new(
                        "an environment name cannot contain both a literal and a secret reference",
                    ));
                }
                let normalized_arguments = process_arguments_value(
                    &program,
                    parsed.arguments,
                    parsed.environment,
                    secret_environment.clone(),
                );
                let mut capabilities = vec![
                    Capability::new(
                        CapabilityName::FsRead,
                        ResourceScope::workspace(context.workspace_id()),
                    ),
                    Capability::new(CapabilityName::ProcessSpawn, scope),
                ];
                for reference in secret_environment.values().collect::<BTreeSet<_>>() {
                    capabilities.push(Capability::new(
                        CapabilityName::SecretUse,
                        ResourceScope::exact("secret_reference", reference.to_string())
                            .map_err(|error| NormalizationError::new(error.to_string()))?,
                    ));
                }
                Ok(ActionEnvelope::new(
                    ActionId::new(),
                    context.run_id(),
                    context.workspace_id(),
                    context.actor().clone(),
                    self.component.clone(),
                    ActionKind::new(kind)
                        .map_err(|error| NormalizationError::new(error.to_string()))?,
                    normalized_arguments,
                    capabilities,
                ))
            }
            _ => Err(NormalizationError::new(format!(
                "unsupported built-in action: {kind}"
            ))),
        }
    }
}

pub struct BuiltinExecutor {
    filesystem: WorkspaceReader,
    process: ProcessExecutor,
    secret_resolver: Option<Arc<dyn ProcessSecretResolver>>,
}

impl BuiltinExecutor {
    pub const fn new(filesystem: WorkspaceReader, process: ProcessExecutor) -> Self {
        Self {
            filesystem,
            process,
            secret_resolver: None,
        }
    }

    pub fn with_secret_resolver(mut self, resolver: Arc<dyn ProcessSecretResolver>) -> Self {
        self.secret_resolver = Some(resolver);
        self
    }

    async fn dispatch(
        &self,
        action: &ActionEnvelope,
        cancellation: CancellationToken,
    ) -> Result<ExecutionOutcome, ExecutorError> {
        match action.kind().as_str() {
            "filesystem.read" => {
                let parsed: FilesystemReadArguments = parse_arguments(action.arguments())
                    .map_err(|error| ExecutorError::new(error.to_string()))?;
                let path = WorkspacePath::parse(parsed.path)
                    .map_err(|error| ExecutorError::new(error.to_string()))?;
                let contents = self.filesystem.read_text(&path).await;
                let contents = match contents {
                    Ok(contents) => contents,
                    Err(error) => return Ok(ExecutionOutcome::Failed(error.to_string())),
                };
                Ok(ExecutionOutcome::Succeeded(CanonicalValue::object([(
                    "contents",
                    CanonicalValue::from(contents),
                )])))
            }
            "filesystem.write" => {
                let prepared: PreparedFileWrite = parse_arguments(action.arguments())
                    .map_err(|error| ExecutorError::new(error.to_string()))?;
                match self.filesystem.replace_text(&prepared).await {
                    Ok(()) => Ok(ExecutionOutcome::Succeeded(CanonicalValue::object([
                        ("path", CanonicalValue::from(prepared.path())),
                        ("sha256", CanonicalValue::from(prepared.after().sha256())),
                        (
                            "bytes",
                            CanonicalValue::from(
                                i64::try_from(prepared.after().bytes()).unwrap_or(i64::MAX),
                            ),
                        ),
                    ]))),
                    Err(error) => Ok(ExecutionOutcome::Failed(error.to_string())),
                }
            }
            "process.spawn" => {
                let parsed: ProcessArguments = parse_arguments(action.arguments())
                    .map_err(|error| ExecutorError::new(error.to_string()))?;
                let secret_environment = parse_secret_environment(parsed.secret_environment)
                    .map_err(|error| ExecutorError::new(error.to_string()))?;
                let secret_environment_names = secret_environment.keys().cloned().collect();
                let mut environment = parsed.environment;
                if !secret_environment.is_empty() {
                    let Some(resolver) = &self.secret_resolver else {
                        return Ok(ExecutionOutcome::Failed(
                            "secret injection is unavailable for this runtime".to_owned(),
                        ));
                    };
                    let resolved = match resolver
                        .resolve(
                            action.workspace_id(),
                            Path::new(&parsed.program),
                            &secret_environment,
                        )
                        .await
                    {
                        Ok(resolved) => resolved,
                        Err(error) => return Ok(ExecutionOutcome::Failed(error.to_string())),
                    };
                    if resolved.len() != secret_environment.len()
                        || resolved
                            .keys()
                            .any(|name| !secret_environment.contains_key(name))
                        || resolved.keys().any(|name| environment.contains_key(name))
                    {
                        return Ok(ExecutionOutcome::Failed(
                            "secret resolver returned an invalid environment".to_owned(),
                        ));
                    }
                    environment.extend(resolved);
                }
                match self
                    .process
                    .execute_with_resolved_secrets(
                        ProcessRequest::new(parsed.program, parsed.arguments, environment),
                        &secret_environment_names,
                        cancellation,
                    )
                    .await
                {
                    Ok(outcome) => Ok(outcome),
                    Err(error) => Ok(ExecutionOutcome::Failed(error.to_string())),
                }
            }
            kind => Err(ExecutorError::new(format!(
                "unsupported authorized action: {kind}"
            ))),
        }
    }
}

pub type ProcessSecretFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BTreeMap<String, String>, ProcessSecretError>> + Send + 'a>>;

pub trait ProcessSecretResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        workspace_id: WorkspaceId,
        program: &'a Path,
        bindings: &'a BTreeMap<String, SecretRefId>,
    ) -> ProcessSecretFuture<'a>;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("secret resolution failed: {message}")]
pub struct ProcessSecretError {
    message: String,
}

impl ProcessSecretError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl ExecutorPort for BuiltinExecutor {
    fn execute<'a>(
        &'a self,
        action: &'a AuthorizedAction,
        cancellation: CancellationToken,
    ) -> ExecutorFuture<'a> {
        Box::pin(async move { self.dispatch(action.action(), cancellation).await })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemReadArguments {
    path: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilesystemWriteProposal {
    path: String,
    content: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessArguments {
    program: String,
    #[serde(rename = "args", default)]
    arguments: Vec<String>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    secret_environment: BTreeMap<String, String>,
}

fn parse_arguments<T: for<'de> Deserialize<'de>>(
    arguments: &CanonicalValue,
) -> Result<T, NormalizationError> {
    let encoded = serde_json::to_value(arguments)
        .map_err(|error| NormalizationError::new(error.to_string()))?;
    serde_json::from_value(encoded).map_err(|error| NormalizationError::new(error.to_string()))
}

fn process_arguments_value(
    program: &str,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
    secret_environment: BTreeMap<String, SecretRefId>,
) -> CanonicalValue {
    CanonicalValue::object([
        ("program", CanonicalValue::from(program)),
        (
            "args",
            CanonicalValue::Array(arguments.into_iter().map(CanonicalValue::from).collect()),
        ),
        (
            "environment",
            CanonicalValue::Object(
                environment
                    .into_iter()
                    .map(|(key, value)| (key, CanonicalValue::from(value)))
                    .collect(),
            ),
        ),
        (
            "secret_environment",
            CanonicalValue::Object(
                secret_environment
                    .into_iter()
                    .map(|(key, reference)| (key, CanonicalValue::from(reference.to_string())))
                    .collect(),
            ),
        ),
    ])
}

fn parse_secret_environment(
    values: BTreeMap<String, String>,
) -> Result<BTreeMap<String, SecretRefId>, NormalizationError> {
    values
        .into_iter()
        .map(|(name, value)| {
            if !valid_environment_name(&name) {
                return Err(NormalizationError::new(format!(
                    "secret environment name is invalid: {name}"
                )));
            }
            let reference = SecretRefId::parse(&value)
                .map_err(|error| NormalizationError::new(error.to_string()))?;
            Ok((name, reference))
        })
        .collect()
}

fn valid_environment_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && value.len() <= 256
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessRequest {
    program: PathBuf,
    arguments: Vec<String>,
    environment: BTreeMap<String, String>,
}

impl ProcessRequest {
    pub fn new<I, S>(
        program: impl Into<PathBuf>,
        arguments: I,
        environment: BTreeMap<String, String>,
    ) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            program: program.into(),
            arguments: arguments.into_iter().map(Into::into).collect(),
            environment,
        }
    }
}

pub struct ProcessExecutor {
    workspace: PathBuf,
    allowed_programs: BTreeSet<PathBuf>,
    allowed_environment: BTreeSet<String>,
    timeout: Duration,
    output_limit: usize,
    resource_limits: ResourceLimits,
    sandbox: Arc<dyn SandboxBackend>,
}

impl ProcessExecutor {
    pub fn new(
        workspace: impl AsRef<Path>,
        allowed_programs: impl IntoIterator<Item = PathBuf>,
        allowed_environment: BTreeSet<String>,
        timeout: Duration,
        output_limit: usize,
        resource_limits: ResourceLimits,
        sandbox: Arc<dyn SandboxBackend>,
    ) -> Result<Self, ProcessError> {
        let workspace = std::fs::canonicalize(workspace)
            .map_err(|error| ProcessError::InvalidWorkspace(error.to_string()))?;
        let allowed_programs = allowed_programs
            .into_iter()
            .map(|program| {
                std::fs::canonicalize(&program)
                    .map_err(|_| ProcessError::ProgramNotAllowed(program))
            })
            .collect::<Result<_, _>>()?;
        if timeout.is_zero() {
            return Err(ProcessError::InvalidTimeout);
        }
        if output_limit == 0 {
            return Err(ProcessError::InvalidOutputLimit);
        }

        Ok(Self {
            workspace,
            allowed_programs,
            allowed_environment,
            timeout,
            output_limit,
            resource_limits,
            sandbox,
        })
    }

    pub async fn execute(
        &self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> Result<ExecutionOutcome, ProcessError> {
        self.execute_with_resolved_secrets(request, &BTreeSet::new(), cancellation)
            .await
    }

    async fn execute_with_resolved_secrets(
        &self,
        request: ProcessRequest,
        resolved_secret_names: &BTreeSet<String>,
        cancellation: CancellationToken,
    ) -> Result<ExecutionOutcome, ProcessError> {
        let program = std::fs::canonicalize(&request.program)
            .map_err(|_| ProcessError::ProgramNotAllowed(request.program.clone()))?;
        if !self.allowed_programs.contains(&program) {
            return Err(ProcessError::ProgramNotAllowed(request.program));
        }
        if let Some(name) = request.environment.keys().find(|name| {
            !self.allowed_environment.contains(*name) && !resolved_secret_names.contains(*name)
        }) {
            return Err(ProcessError::EnvironmentNotAllowed(name.clone()));
        }

        let report = self.sandbox.report();
        if report.strength() != SandboxStrength::KernelEnforced {
            let detail = report
                .detail()
                .unwrap_or("kernel enforcement is unavailable");
            return Err(ProcessError::SandboxUnavailable(format!(
                "{}: {detail}",
                report.backend()
            )));
        }

        let command = MonitoredCommand::new(program)
            .args(request.arguments)
            .current_dir(&self.workspace)
            .envs(request.environment);
        let output = match self
            .sandbox
            .execute(SandboxRequest::new(
                command,
                self.timeout,
                self.output_limit,
                cancellation,
                self.resource_limits,
            ))
            .await
        {
            Ok(output) => output,
            Err(SandboxError::Cancelled) => return Ok(ExecutionOutcome::Cancelled),
            Err(SandboxError::TimedOut) => return Ok(ExecutionOutcome::TimedOut),
            Err(error) => return Err(ProcessError::Sandbox(error.to_string())),
        };

        let stdout = String::from_utf8_lossy(output.stdout()).into_owned();
        let stderr = String::from_utf8_lossy(output.stderr()).into_owned();
        match output.exit_code() {
            Some(0) => Ok(ExecutionOutcome::Succeeded(CanonicalValue::object([
                ("exit_code", CanonicalValue::from(0_i64)),
                ("stdout", CanonicalValue::from(stdout)),
                ("stderr", CanonicalValue::from(stderr)),
            ]))),
            Some(code) => Ok(ExecutionOutcome::Failed(format!(
                "process exited with status {code}: {stderr}"
            ))),
            None => Ok(ExecutionOutcome::Unknown(
                "process terminated without an exit status".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ProcessError {
    #[error("workspace is invalid: {0}")]
    InvalidWorkspace(String),
    #[error("program is not allowlisted: {program}", program = .0.display())]
    ProgramNotAllowed(PathBuf),
    #[error("environment variable is not allowlisted: {0}")]
    EnvironmentNotAllowed(String),
    #[error("kernel sandbox is unavailable: {0}")]
    SandboxUnavailable(String),
    #[error("sandbox execution failed: {0}")]
    Sandbox(String),
    #[error("timeout must be greater than zero")]
    InvalidTimeout,
    #[error("output limit must be greater than zero")]
    InvalidOutputLimit,
}
