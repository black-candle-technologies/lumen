use std::{
    collections::BTreeMap,
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::Notify,
};
use tokio_util::sync::CancellationToken;

pub type SandboxFuture<'a> =
    Pin<Box<dyn Future<Output = Result<SandboxOutput, SandboxError>> + Send + 'a>>;

pub trait SandboxBackend: Send + Sync {
    fn report(&self) -> SandboxReport;
    fn execute(&self, request: SandboxRequest) -> SandboxFuture<'_>;
}

pub struct SystemSandbox {
    executable: Option<PathBuf>,
    report: SandboxReport,
}

impl SystemSandbox {
    pub fn detect() -> Self {
        #[cfg(target_os = "macos")]
        {
            let executable = PathBuf::from("/usr/bin/sandbox-exec");
            if executable.is_file() {
                return Self {
                    executable: Some(executable),
                    report: SandboxReport::new(
                        "macos-sandbox-exec",
                        SandboxStrength::KernelEnforced,
                        None,
                    ),
                };
            }
            Self {
                executable: None,
                report: SandboxReport::new(
                    "macos-sandbox-exec",
                    SandboxStrength::Unavailable,
                    Some("/usr/bin/sandbox-exec is unavailable".into()),
                ),
            }
        }

        #[cfg(target_os = "linux")]
        {
            Self {
                executable: None,
                report: SandboxReport::new(
                    "linux-sandbox",
                    SandboxStrength::Unavailable,
                    Some("Linux kernel sandbox enforcement is scheduled for Milestone 2".into()),
                ),
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            Self {
                executable: None,
                report: SandboxReport::new(
                    "unsupported-platform",
                    SandboxStrength::Unavailable,
                    Some("no kernel sandbox backend is implemented for this platform".into()),
                ),
            }
        }
    }
}

impl Default for SystemSandbox {
    fn default() -> Self {
        Self::detect()
    }
}

impl SandboxBackend for SystemSandbox {
    fn report(&self) -> SandboxReport {
        self.report.clone()
    }

    fn execute(&self, request: SandboxRequest) -> SandboxFuture<'_> {
        let executable = self.executable.clone();
        Box::pin(async move {
            let executable = executable.ok_or_else(|| {
                SandboxError::Unavailable("kernel sandbox backend is unavailable".into())
            })?;
            execute_system_sandbox(executable, request).await
        })
    }
}

#[cfg(target_os = "macos")]
async fn execute_system_sandbox(
    executable: PathBuf,
    request: SandboxRequest,
) -> Result<SandboxOutput, SandboxError> {
    let command = request.command();
    let workspace = command.current_directory().ok_or_else(|| {
        SandboxError::InvalidRequest("sandboxed commands require a working directory".into())
    })?;
    let profile = macos_profile(command.program(), workspace);
    let monitored = MonitoredCommand::new(executable)
        .args(
            ["-p".to_owned(), profile, "--".to_owned()]
                .into_iter()
                .chain(std::iter::once(
                    command.program().to_string_lossy().into_owned(),
                ))
                .chain(command.arguments().iter().cloned()),
        )
        .current_dir(workspace)
        .envs(command.environment().clone());
    ProcessMonitor::run(
        monitored,
        request.timeout(),
        request.output_limit(),
        request.cancellation(),
    )
    .await
}

#[cfg(target_os = "macos")]
fn macos_profile(program: &Path, workspace: &Path) -> String {
    let program = sandbox_literal(program);
    let workspace = sandbox_literal(workspace);
    format!(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec (literal \"{program}\"))\n\
         (allow file-read* (literal \"/\"))\n\
         (allow file-read* (literal \"{program}\"))\n\
         (allow file-read* (subpath \"{workspace}\"))\n\
         (allow file-read* (subpath \"/System/Library\"))\n\
         (allow file-read* (subpath \"/usr/lib\"))\n\
         (allow file-read* (subpath \"/private/var/db/dyld\"))"
    )
}

#[cfg(target_os = "macos")]
fn sandbox_literal(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

#[cfg(not(target_os = "macos"))]
async fn execute_system_sandbox(
    _executable: PathBuf,
    _request: SandboxRequest,
) -> Result<SandboxOutput, SandboxError> {
    Err(SandboxError::Unavailable(
        "kernel sandbox backend is unavailable".into(),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxStrength {
    KernelEnforced,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxReport {
    backend: String,
    strength: SandboxStrength,
    detail: Option<String>,
}

impl SandboxReport {
    pub fn new(
        backend: impl Into<String>,
        strength: SandboxStrength,
        detail: Option<String>,
    ) -> Self {
        Self {
            backend: backend.into(),
            strength,
            detail,
        }
    }

    pub const fn strength(&self) -> SandboxStrength {
        self.strength
    }

    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }
}

#[derive(Clone, Debug)]
pub struct SandboxRequest {
    command: MonitoredCommand,
    timeout: Duration,
    output_limit: usize,
    cancellation: CancellationToken,
}

impl SandboxRequest {
    pub fn new(
        command: MonitoredCommand,
        timeout: Duration,
        output_limit: usize,
        cancellation: CancellationToken,
    ) -> Self {
        Self {
            command,
            timeout,
            output_limit,
            cancellation,
        }
    }

    pub fn command(&self) -> &MonitoredCommand {
        &self.command
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        self.command.environment()
    }

    pub const fn timeout(&self) -> Duration {
        self.timeout
    }

    pub const fn output_limit(&self) -> usize {
        self.output_limit
    }

    pub fn cancellation(&self) -> CancellationToken {
        self.cancellation.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MonitoredCommand {
    program: PathBuf,
    arguments: Vec<String>,
    current_directory: Option<PathBuf>,
    environment: BTreeMap<String, String>,
}

impl MonitoredCommand {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            current_directory: None,
            environment: BTreeMap::new(),
        }
    }

    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn current_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_directory = Some(path.into());
        self
    }

    pub fn envs(mut self, environment: BTreeMap<String, String>) -> Self {
        self.environment = environment;
        self
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn arguments(&self) -> &[String] {
        &self.arguments
    }

    pub fn current_directory(&self) -> Option<&Path> {
        self.current_directory.as_deref()
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxOutput {
    exit_code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl SandboxOutput {
    pub fn new(exit_code: Option<i32>, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            exit_code,
            stdout,
            stderr,
        }
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }
}

pub struct ProcessMonitor;

impl ProcessMonitor {
    pub async fn run(
        command: MonitoredCommand,
        timeout: Duration,
        output_limit: usize,
        cancellation: CancellationToken,
    ) -> Result<SandboxOutput, SandboxError> {
        if output_limit == 0 {
            return Err(SandboxError::OutputLimitExceeded { limit: 0 });
        }

        let mut process = Command::new(command.program());
        process
            .args(command.arguments())
            .env_clear()
            .envs(command.environment())
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(directory) = command.current_directory() {
            process.current_dir(directory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            process.as_std_mut().process_group(0);
        }

        let mut child = process
            .spawn()
            .map_err(|error| SandboxError::Spawn(error.to_string()))?;
        let process_id = child.id();
        let stdout = child.stdout.take().ok_or(SandboxError::MissingPipe)?;
        let stderr = child.stderr.take().ok_or(SandboxError::MissingPipe)?;
        let total = Arc::new(AtomicUsize::new(0));
        let exceeded = Arc::new(AtomicBool::new(false));
        let notify = Arc::new(Notify::new());
        let stdout_task = tokio::spawn(read_output(
            stdout,
            output_limit,
            Arc::clone(&total),
            Arc::clone(&exceeded),
            Arc::clone(&notify),
        ));
        let stderr_task = tokio::spawn(read_output(
            stderr,
            output_limit,
            total,
            Arc::clone(&exceeded),
            Arc::clone(&notify),
        ));

        let wait_result = tokio::select! {
            result = child.wait() => WaitResult::Exited(result),
            () = cancellation.cancelled() => WaitResult::Cancelled,
            () = tokio::time::sleep(timeout) => WaitResult::TimedOut,
            () = notify.notified() => WaitResult::OutputLimit,
        };

        let (termination, status) = match wait_result {
            WaitResult::Exited(result) => (
                Termination::Exited,
                Some(result.map_err(|error| SandboxError::Wait(error.to_string()))?),
            ),
            WaitResult::Cancelled | WaitResult::TimedOut | WaitResult::OutputLimit => {
                terminate_process_tree(&mut child, process_id).await;
                let termination = match wait_result {
                    WaitResult::Cancelled => Termination::Cancelled,
                    WaitResult::TimedOut => Termination::TimedOut,
                    WaitResult::OutputLimit => Termination::OutputLimit,
                    WaitResult::Exited(_) => unreachable!(),
                };
                (termination, None)
            }
        };

        let stdout = stdout_task
            .await
            .map_err(|error| SandboxError::Read(error.to_string()))??;
        let stderr = stderr_task
            .await
            .map_err(|error| SandboxError::Read(error.to_string()))??;

        match termination {
            Termination::Cancelled => Err(SandboxError::Cancelled),
            Termination::TimedOut => Err(SandboxError::TimedOut),
            Termination::OutputLimit => Err(SandboxError::OutputLimitExceeded {
                limit: output_limit,
            }),
            Termination::Exited if exceeded.load(Ordering::Acquire) => {
                Err(SandboxError::OutputLimitExceeded {
                    limit: output_limit,
                })
            }
            Termination::Exited => Ok(SandboxOutput::new(
                status.and_then(|value| value.code()),
                stdout,
                stderr,
            )),
        }
    }
}

enum WaitResult {
    Exited(std::io::Result<std::process::ExitStatus>),
    Cancelled,
    TimedOut,
    OutputLimit,
}

#[derive(Clone, Copy)]
enum Termination {
    Exited,
    Cancelled,
    TimedOut,
    OutputLimit,
}

async fn read_output(
    mut reader: impl AsyncRead + Unpin,
    limit: usize,
    total: Arc<AtomicUsize>,
    exceeded: Arc<AtomicBool>,
    notify: Arc<Notify>,
) -> Result<Vec<u8>, SandboxError> {
    let mut output = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .await
            .map_err(|error| SandboxError::Read(error.to_string()))?;
        if read == 0 {
            return Ok(output);
        }

        let previous = total.fetch_add(read, Ordering::AcqRel);
        if previous < limit {
            let retained = read.min(limit - previous);
            output.extend_from_slice(&buffer[..retained]);
        }
        if previous.saturating_add(read) > limit && !exceeded.swap(true, Ordering::AcqRel) {
            notify.notify_one();
        }
    }
}

async fn terminate_process_tree(child: &mut tokio::process::Child, process_id: Option<u32>) {
    #[cfg(unix)]
    if let Some(process_id) = process_id.and_then(|value| i32::try_from(value).ok()) {
        use nix::{
            sys::signal::{Signal, killpg},
            unistd::Pid,
        };
        let _ = killpg(Pid::from_raw(process_id), Signal::SIGKILL);
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SandboxError {
    #[error("sandbox is unavailable: {0}")]
    Unavailable(String),
    #[error("sandbox request is invalid: {0}")]
    InvalidRequest(String),
    #[error("process could not be started: {0}")]
    Spawn(String),
    #[error("process output pipe was unavailable")]
    MissingPipe,
    #[error("process output could not be read: {0}")]
    Read(String),
    #[error("process wait failed: {0}")]
    Wait(String),
    #[error("process was cancelled")]
    Cancelled,
    #[error("process timed out")]
    TimedOut,
    #[error("process output exceeds the {limit}-byte limit")]
    OutputLimitExceeded { limit: usize },
}
