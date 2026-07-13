use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use lumen_core::{
    action::{ActionEnvelope, ActionId, ActionKind, CanonicalValue},
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    executor::{AuthorizedAction, ExecutionOutcome, ExecutorError, ExecutorFuture, ExecutorPort},
    identity::ComponentId,
    model::ActionProposal,
    run::{ActionNormalizer, NormalizationError, RunContext},
};
use serde::Deserialize;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::filesystem::{PreparedFileWrite, WorkspaceReader};
use crate::sandbox::{MonitoredCommand, SandboxBackend, SandboxRequest, SandboxStrength};

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
                let normalized_arguments =
                    process_arguments_value(&program, parsed.arguments, parsed.environment);
                Ok(ActionEnvelope::new(
                    ActionId::new(),
                    context.run_id(),
                    context.workspace_id(),
                    context.actor().clone(),
                    self.component.clone(),
                    ActionKind::new(kind)
                        .map_err(|error| NormalizationError::new(error.to_string()))?,
                    normalized_arguments,
                    vec![
                        Capability::new(
                            CapabilityName::FsRead,
                            ResourceScope::workspace(context.workspace_id()),
                        ),
                        Capability::new(CapabilityName::ProcessSpawn, scope),
                    ],
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
}

impl BuiltinExecutor {
    pub const fn new(filesystem: WorkspaceReader, process: ProcessExecutor) -> Self {
        Self {
            filesystem,
            process,
        }
    }

    async fn dispatch(&self, action: &ActionEnvelope) -> Result<ExecutionOutcome, ExecutorError> {
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
                match self
                    .process
                    .execute(
                        ProcessRequest::new(parsed.program, parsed.arguments, parsed.environment),
                        CancellationToken::new(),
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

impl ExecutorPort for BuiltinExecutor {
    fn execute<'a>(&'a self, action: &'a AuthorizedAction) -> ExecutorFuture<'a> {
        Box::pin(async move { self.dispatch(action.action()).await })
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
    ])
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
    sandbox: Arc<dyn SandboxBackend>,
}

impl ProcessExecutor {
    pub fn new(
        workspace: impl AsRef<Path>,
        allowed_programs: impl IntoIterator<Item = PathBuf>,
        allowed_environment: BTreeSet<String>,
        timeout: Duration,
        output_limit: usize,
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
            sandbox,
        })
    }

    pub async fn execute(
        &self,
        request: ProcessRequest,
        cancellation: CancellationToken,
    ) -> Result<ExecutionOutcome, ProcessError> {
        let program = std::fs::canonicalize(&request.program)
            .map_err(|_| ProcessError::ProgramNotAllowed(request.program.clone()))?;
        if !self.allowed_programs.contains(&program) {
            return Err(ProcessError::ProgramNotAllowed(request.program));
        }
        if let Some(name) = request
            .environment
            .keys()
            .find(|name| !self.allowed_environment.contains(*name))
        {
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
        let output = self
            .sandbox
            .execute(SandboxRequest::new(
                command,
                self.timeout,
                self.output_limit,
                cancellation,
            ))
            .await
            .map_err(|error| ProcessError::Sandbox(error.to_string()))?;

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
