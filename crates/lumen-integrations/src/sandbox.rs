use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use serde::Serialize;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceLimits {
    cpu_seconds: u64,
    address_space_bytes: u64,
    file_size_bytes: u64,
    open_files: u64,
    processes: u64,
}

impl ResourceLimits {
    pub fn new(
        cpu_seconds: u64,
        address_space_bytes: u64,
        file_size_bytes: u64,
        open_files: u64,
        processes: u64,
    ) -> Result<Self, ResourceLimitError> {
        if [
            cpu_seconds,
            address_space_bytes,
            file_size_bytes,
            open_files,
            processes,
        ]
        .contains(&0)
        {
            return Err(ResourceLimitError);
        }
        Ok(Self {
            cpu_seconds,
            address_space_bytes,
            file_size_bytes,
            open_files,
            processes,
        })
    }

    pub const fn cpu_seconds(self) -> u64 {
        self.cpu_seconds
    }

    pub const fn address_space_bytes(self) -> u64 {
        self.address_space_bytes
    }

    pub const fn file_size_bytes(self) -> u64 {
        self.file_size_bytes
    }

    pub const fn open_files(self) -> u64 {
        self.open_files
    }

    pub const fn processes(self) -> u64 {
        self.processes
    }

    pub const fn with_max_address_space(mut self, max_bytes: u64) -> Self {
        if max_bytes < self.address_space_bytes {
            self.address_space_bytes = max_bytes;
        }
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("every process resource limit must be greater than zero")]
pub struct ResourceLimitError;

pub struct SystemSandbox {
    executable: Option<PathBuf>,
    report: SandboxReport,
}

#[cfg(any(target_os = "linux", test))]
const LINUX_BWRAP_PATHS: [&str; 2] = ["/usr/bin/bwrap", "/bin/bwrap"];

impl SystemSandbox {
    pub fn detect() -> Self {
        #[cfg(target_os = "macos")]
        {
            let executable = PathBuf::from("/usr/bin/sandbox-exec");
            if executable.is_file() {
                return Self {
                    executable: Some(executable),
                    report: SandboxReport::with_guarantees(
                        "macos-sandbox-exec",
                        SandboxStrength::KernelEnforced,
                        [
                            SandboxGuarantee::FilesystemIsolation,
                            SandboxGuarantee::WorkspaceReadOnly,
                            SandboxGuarantee::NetworkIsolation,
                            SandboxGuarantee::ExecutableIsolation,
                            SandboxGuarantee::EnvironmentIsolation,
                        ],
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
            if let Some(executable) = find_linux_bubblewrap(Path::is_file) {
                if probe_linux_bubblewrap(&executable) {
                    return Self {
                        report: linux_sandbox_report(executable.clone()),
                        executable: Some(executable),
                    };
                }
                return Self {
                    executable: None,
                    report: SandboxReport::new(
                        "linux-bubblewrap",
                        SandboxStrength::Unavailable,
                        Some("the complete bubblewrap isolation profile could not start".into()),
                    ),
                };
            }
            Self {
                executable: None,
                report: SandboxReport::new(
                    "linux-bubblewrap",
                    SandboxStrength::Unavailable,
                    Some("bubblewrap was not found at a trusted system path".into()),
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
    if request.profile() == SandboxProfile::Plugin && !command.environment().is_empty() {
        return Err(SandboxError::InvalidRequest(
            "plugin sandbox environment must be empty".into(),
        ));
    }
    let profile = match request.profile() {
        SandboxProfile::WorkspaceReadOnly => macos_workspace_profile(command.program(), workspace),
        SandboxProfile::Plugin => macos_plugin_profile(command.program()),
    };
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
    ProcessMonitor::run_with_stdin(
        monitored,
        request.timeout(),
        request.output_limit(),
        request.cancellation(),
        request.resource_limits(),
        request.stdin().map(ToOwned::to_owned),
    )
    .await
}

#[cfg(target_os = "linux")]
async fn execute_system_sandbox(
    executable: PathBuf,
    request: SandboxRequest,
) -> Result<SandboxOutput, SandboxError> {
    let monitored = linux_bubblewrap_command(executable, request.command(), request.profile())?;
    ProcessMonitor::run_with_stdin(
        monitored,
        request.timeout(),
        request.output_limit(),
        request.cancellation(),
        request.resource_limits(),
        request.stdin().map(ToOwned::to_owned),
    )
    .await
}

#[cfg(target_os = "macos")]
fn macos_workspace_profile(program: &Path, workspace: &Path) -> String {
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
fn macos_plugin_profile(program: &Path) -> String {
    let program = sandbox_literal(program);
    format!(
        "(version 1)\n\
         (deny default)\n\
         (allow process-exec (literal \"{program}\"))\n\
         (allow sysctl-read\n\
             (sysctl-name \"hw.pagesize_compat\")\n\
             (sysctl-name \"machdep.ptrauth_enabled\"))\n\
         (allow file-read* (literal \"/\"))\n\
         (allow file-read* (literal \"{program}\"))\n\
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

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
async fn execute_system_sandbox(
    _executable: PathBuf,
    _request: SandboxRequest,
) -> Result<SandboxOutput, SandboxError> {
    Err(SandboxError::Unavailable(
        "kernel sandbox backend is unavailable".into(),
    ))
}

#[cfg(any(target_os = "linux", test))]
fn find_linux_bubblewrap(mut available: impl FnMut(&Path) -> bool) -> Option<PathBuf> {
    LINUX_BWRAP_PATHS
        .into_iter()
        .map(PathBuf::from)
        .find(|path| available(path))
}

#[cfg(any(target_os = "linux", test))]
fn linux_sandbox_report(_executable: PathBuf) -> SandboxReport {
    SandboxReport::with_guarantees(
        "linux-bubblewrap",
        SandboxStrength::KernelEnforced,
        [
            SandboxGuarantee::FilesystemIsolation,
            SandboxGuarantee::WorkspaceReadOnly,
            SandboxGuarantee::NetworkIsolation,
            SandboxGuarantee::ProcessIsolation,
            SandboxGuarantee::IpcIsolation,
            SandboxGuarantee::UserIsolation,
            SandboxGuarantee::CgroupIsolation,
            SandboxGuarantee::CapabilitiesDropped,
            SandboxGuarantee::EnvironmentIsolation,
            SandboxGuarantee::TerminalIsolation,
            SandboxGuarantee::ParentDeathCleanup,
            SandboxGuarantee::ExecutableIsolation,
        ],
        None,
    )
}

#[cfg(any(target_os = "linux", test))]
fn linux_bubblewrap_command(
    executable: PathBuf,
    command: &MonitoredCommand,
    profile: SandboxProfile,
) -> Result<MonitoredCommand, SandboxError> {
    let workspace = command.current_directory().ok_or_else(|| {
        SandboxError::InvalidRequest("sandboxed commands require a working directory".into())
    })?;
    if !workspace.is_absolute() || !command.program().is_absolute() {
        return Err(SandboxError::InvalidRequest(
            "Linux sandbox paths must be absolute".into(),
        ));
    }

    let mut arguments = vec![
        "--die-with-parent".into(),
        "--new-session".into(),
        "--unshare-user".into(),
        "--disable-userns".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
        "--unshare-uts".into(),
        "--unshare-cgroup".into(),
        "--unshare-net".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--clearenv".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
        "--dir".into(),
        "/lumen".into(),
        "--ro-bind".into(),
        command.program().to_string_lossy().into_owned(),
        "/lumen/program".into(),
    ];
    if profile == SandboxProfile::WorkspaceReadOnly {
        arguments.extend([
            "--ro-bind".into(),
            workspace.to_string_lossy().into_owned(),
            "/workspace".into(),
        ]);
    }
    for library_directory in ["/lib", "/lib64", "/usr/lib", "/usr/lib64"] {
        if Path::new(library_directory).is_dir() {
            arguments.extend([
                "--ro-bind".into(),
                library_directory.into(),
                library_directory.into(),
            ]);
        }
    }
    if Path::new("/etc/ld.so.cache").is_file() {
        arguments.extend([
            "--dir".into(),
            "/etc".into(),
            "--ro-bind".into(),
            "/etc/ld.so.cache".into(),
            "/etc/ld.so.cache".into(),
        ]);
    }
    if profile == SandboxProfile::WorkspaceReadOnly {
        arguments.extend([
            "--setenv".into(),
            "HOME".into(),
            "/workspace".into(),
            "--setenv".into(),
            "TMPDIR".into(),
            "/tmp".into(),
        ]);
    } else if !command.environment().is_empty() {
        return Err(SandboxError::InvalidRequest(
            "plugin sandbox environment must be empty".into(),
        ));
    }
    for (name, value) in command.environment() {
        if name.is_empty()
            || name.contains('=')
            || name.chars().any(char::is_control)
            || value.contains('\0')
        {
            return Err(SandboxError::InvalidRequest(
                "sandbox environment contains an invalid name or value".into(),
            ));
        }
        arguments.extend(["--setenv".into(), name.clone(), value.clone()]);
    }
    arguments.extend([
        "--chdir".into(),
        if profile == SandboxProfile::WorkspaceReadOnly {
            "/workspace".into()
        } else {
            "/tmp".into()
        },
        "--".into(),
    ]);
    arguments.push("/lumen/program".into());
    arguments.extend(command.arguments().iter().cloned());

    Ok(MonitoredCommand::new(executable)
        .args(arguments)
        .current_dir(workspace))
}

#[cfg(any(target_os = "linux", test))]
fn probe_linux_bubblewrap(executable: &Path) -> bool {
    use std::{process::Stdio, thread, time::Instant};

    let Ok(workspace) = std::env::current_dir() else {
        return false;
    };
    let Ok(command) = linux_bubblewrap_command(
        executable.to_path_buf(),
        &MonitoredCommand::new("/bin/true").current_dir(workspace),
        SandboxProfile::WorkspaceReadOnly,
    ) else {
        return false;
    };
    let mut process = std::process::Command::new(command.program());
    process
        .args(command.arguments())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let Ok(mut child) = process.spawn() else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxStrength {
    KernelEnforced,
    Unavailable,
}

impl SandboxStrength {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KernelEnforced => "kernel_enforced",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxGuarantee {
    FilesystemIsolation,
    WorkspaceReadOnly,
    NetworkIsolation,
    ProcessIsolation,
    IpcIsolation,
    UserIsolation,
    CgroupIsolation,
    CapabilitiesDropped,
    EnvironmentIsolation,
    TerminalIsolation,
    ParentDeathCleanup,
    ExecutableIsolation,
    Seccomp,
}

impl SandboxGuarantee {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FilesystemIsolation => "filesystem_isolation",
            Self::WorkspaceReadOnly => "workspace_read_only",
            Self::NetworkIsolation => "network_isolation",
            Self::ProcessIsolation => "process_isolation",
            Self::IpcIsolation => "ipc_isolation",
            Self::UserIsolation => "user_isolation",
            Self::CgroupIsolation => "cgroup_isolation",
            Self::CapabilitiesDropped => "capabilities_dropped",
            Self::EnvironmentIsolation => "environment_isolation",
            Self::TerminalIsolation => "terminal_isolation",
            Self::ParentDeathCleanup => "parent_death_cleanup",
            Self::ExecutableIsolation => "executable_isolation",
            Self::Seccomp => "seccomp",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SandboxReport {
    backend: String,
    strength: SandboxStrength,
    guarantees: BTreeSet<SandboxGuarantee>,
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
            guarantees: BTreeSet::new(),
            detail,
        }
    }

    pub fn with_guarantees(
        backend: impl Into<String>,
        strength: SandboxStrength,
        guarantees: impl IntoIterator<Item = SandboxGuarantee>,
        detail: Option<String>,
    ) -> Self {
        Self {
            backend: backend.into(),
            strength,
            guarantees: guarantees.into_iter().collect(),
            detail,
        }
    }

    pub const fn strength(&self) -> SandboxStrength {
        self.strength
    }

    pub fn backend(&self) -> &str {
        &self.backend
    }

    pub const fn guarantees(&self) -> &BTreeSet<SandboxGuarantee> {
        &self.guarantees
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
    resource_limits: ResourceLimits,
    profile: SandboxProfile,
    stdin: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxProfile {
    WorkspaceReadOnly,
    Plugin,
}

impl SandboxRequest {
    pub fn new(
        command: MonitoredCommand,
        timeout: Duration,
        output_limit: usize,
        cancellation: CancellationToken,
        resource_limits: ResourceLimits,
    ) -> Self {
        Self {
            command,
            timeout,
            output_limit,
            cancellation,
            resource_limits,
            profile: SandboxProfile::WorkspaceReadOnly,
            stdin: None,
        }
    }

    pub fn with_profile(mut self, profile: SandboxProfile) -> Self {
        self.profile = profile;
        self
    }

    pub fn with_stdin(mut self, stdin: Vec<u8>) -> Self {
        self.stdin = Some(stdin);
        self
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

    pub const fn resource_limits(&self) -> ResourceLimits {
        self.resource_limits
    }

    pub const fn profile(&self) -> SandboxProfile {
        self.profile
    }

    pub fn stdin(&self) -> Option<&[u8]> {
        self.stdin.as_deref()
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
    termination_signal: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl SandboxOutput {
    pub fn new(exit_code: Option<i32>, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            exit_code,
            termination_signal: None,
            stdout,
            stderr,
        }
    }

    pub const fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn terminated_by_signal(signal: i32, stdout: Vec<u8>, stderr: Vec<u8>) -> Self {
        Self {
            exit_code: None,
            termination_signal: Some(signal),
            stdout,
            stderr,
        }
    }

    pub const fn termination_signal(&self) -> Option<i32> {
        self.termination_signal
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
        resource_limits: ResourceLimits,
    ) -> Result<SandboxOutput, SandboxError> {
        Self::run_with_stdin(
            command,
            timeout,
            output_limit,
            cancellation,
            resource_limits,
            None,
        )
        .await
    }

    pub async fn run_with_stdin(
        command: MonitoredCommand,
        timeout: Duration,
        output_limit: usize,
        cancellation: CancellationToken,
        resource_limits: ResourceLimits,
        stdin: Option<Vec<u8>>,
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
            .stdin(if stdin.is_some() {
                std::process::Stdio::piped()
            } else {
                std::process::Stdio::null()
            })
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(directory) = command.current_directory() {
            process.current_dir(directory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            process.as_std_mut().process_group(0);
            unsafe {
                process
                    .as_std_mut()
                    .pre_exec(move || apply_unix_resource_limits(resource_limits));
            }
        }

        let mut child = process
            .spawn()
            .map_err(|error| SandboxError::Spawn(error.to_string()))?;
        let process_id = child.id();
        let stdin_task = match stdin {
            Some(input) => {
                let mut writer = child.stdin.take().ok_or(SandboxError::MissingPipe)?;
                Some(tokio::spawn(async move {
                    let _ = writer.write_all(&input).await;
                    let _ = writer.shutdown().await;
                }))
            }
            None => None,
        };
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
        if let Some(task) = stdin_task {
            let _ = task.await;
        }

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
            Termination::Exited => {
                let exit_code = status.as_ref().and_then(std::process::ExitStatus::code);
                #[cfg(unix)]
                let termination_signal = {
                    use std::os::unix::process::ExitStatusExt;
                    status.as_ref().and_then(ExitStatusExt::signal)
                };
                #[cfg(not(unix))]
                let termination_signal = None;
                Ok(SandboxOutput {
                    exit_code,
                    termination_signal,
                    stdout,
                    stderr,
                })
            }
        }
    }
}

#[cfg(unix)]
fn apply_unix_resource_limits(limits: ResourceLimits) -> std::io::Result<()> {
    use nix::sys::resource::{Resource, rlim_t, setrlimit};

    let set = |resource, value: u64| {
        let value = rlim_t::try_from(value)
            .map_err(|_| std::io::Error::other("resource limit exceeds platform range"))?;
        setrlimit(resource, value, value).map_err(std::io::Error::other)
    };
    set(Resource::RLIMIT_CPU, limits.cpu_seconds())?;
    #[cfg(not(target_os = "macos"))]
    set(Resource::RLIMIT_AS, limits.address_space_bytes())?;
    set(Resource::RLIMIT_FSIZE, limits.file_size_bytes())?;
    set(Resource::RLIMIT_NOFILE, limits.open_files())?;
    #[cfg(any(target_os = "linux", target_os = "android"))]
    set(Resource::RLIMIT_NPROC, limits.processes())?;
    #[cfg(target_os = "macos")]
    {
        let value = nix::libc::rlim_t::try_from(limits.processes())
            .map_err(|_| std::io::Error::other("process limit exceeds platform range"))?;
        let limit = nix::libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        let result = unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_NPROC, &limit) };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use super::*;

    #[test]
    fn linux_bubblewrap_detection_uses_only_fixed_system_paths() {
        let selected = find_linux_bubblewrap(|path| path == Path::new("/bin/bwrap"));

        assert_eq!(selected, Some(PathBuf::from("/bin/bwrap")));
        assert_eq!(LINUX_BWRAP_PATHS, ["/usr/bin/bwrap", "/bin/bwrap"]);
        assert!(!probe_linux_bubblewrap(Path::new(
            "/definitely-not-a-lumen-bubblewrap"
        )));
    }

    #[test]
    fn linux_profile_isolates_namespaces_and_exposes_one_executable() {
        let command = MonitoredCommand::new("/usr/bin/example")
            .args(["--version"])
            .current_dir("/home/operator/workspace")
            .envs(BTreeMap::from([("LANG".into(), "C".into())]));

        let wrapped = linux_bubblewrap_command(
            PathBuf::from("/usr/bin/bwrap"),
            &command,
            SandboxProfile::WorkspaceReadOnly,
        )
        .expect("Linux profile builds");
        let arguments = wrapped.arguments();

        assert_eq!(wrapped.program(), Path::new("/usr/bin/bwrap"));
        for required in [
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--disable-userns",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
            "--unshare-net",
            "--cap-drop",
            "--clearenv",
        ] {
            assert!(arguments.iter().any(|argument| argument == required));
        }
        assert!(
            arguments
                .windows(3)
                .any(|values| values == ["--ro-bind", "/usr/bin/example", "/lumen/program"])
        );
        assert!(
            arguments
                .windows(3)
                .any(|values| values == ["--ro-bind", "/home/operator/workspace", "/workspace"])
        );
        assert!(
            !arguments
                .windows(3)
                .any(|values| values == ["--ro-bind", "/usr", "/usr"])
        );
        assert!(
            arguments
                .windows(3)
                .any(|values| values == ["--setenv", "LANG", "C"])
        );
        assert_eq!(arguments.last().map(String::as_str), Some("--version"));
        assert!(wrapped.environment().is_empty());
    }

    #[test]
    fn linux_plugin_profile_has_no_workspace_home_or_inherited_environment() {
        let command = MonitoredCommand::new("/lumen-data/plugins/example/tool")
            .current_dir("/lumen-data/plugins/example");
        let wrapped = linux_bubblewrap_command(
            PathBuf::from("/usr/bin/bwrap"),
            &command,
            SandboxProfile::Plugin,
        )
        .expect("plugin profile builds");
        let arguments = wrapped.arguments();

        assert!(arguments.windows(3).any(|values| {
            values
                == [
                    "--ro-bind",
                    "/lumen-data/plugins/example/tool",
                    "/lumen/program",
                ]
        }));
        assert!(!arguments.iter().any(|value| value == "/workspace"));
        assert!(!arguments.iter().any(|value| value == "HOME"));
        assert!(!arguments.iter().any(|value| value == "TMPDIR"));
        assert!(
            arguments
                .windows(2)
                .any(|values| values == ["--chdir", "/tmp"])
        );
        assert!(wrapped.environment().is_empty());

        let invalid = MonitoredCommand::new("/usr/bin/example")
            .current_dir("/")
            .envs(BTreeMap::from([("SECRET".into(), "value".into())]));
        assert!(matches!(
            linux_bubblewrap_command(
                PathBuf::from("/usr/bin/bwrap"),
                &invalid,
                SandboxProfile::Plugin,
            ),
            Err(SandboxError::InvalidRequest(_))
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_plugin_profile_exposes_only_executable_and_system_loader_roots() {
        let profile = macos_plugin_profile(Path::new("/lumen-data/plugins/example/tool"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow process-exec"));
        assert!(profile.contains("/lumen-data/plugins/example/tool"));
        assert!(!profile.contains("/workspace"));
        assert!(!profile.contains("network"));
        assert!(!profile.contains("file-write"));
    }

    #[tokio::test]
    async fn process_monitor_writes_exact_stdin_without_inheriting_terminal_input() {
        let output = ProcessMonitor::run_with_stdin(
            MonitoredCommand::new("/bin/cat").current_dir("/"),
            Duration::from_secs(1),
            1024,
            CancellationToken::new(),
            ResourceLimits::new(1, 64 * 1024 * 1024, 1024, 16, 2).unwrap(),
            Some(b"framed input".to_vec()),
        )
        .await
        .unwrap();
        assert_eq!(output.stdout(), b"framed input");
        assert_eq!(output.stderr(), b"");
    }

    #[test]
    fn linux_report_names_each_enforced_guarantee_without_claiming_seccomp() {
        let report = linux_sandbox_report(PathBuf::from("/usr/bin/bwrap"));

        assert_eq!(report.strength(), SandboxStrength::KernelEnforced);
        for guarantee in [
            SandboxGuarantee::FilesystemIsolation,
            SandboxGuarantee::WorkspaceReadOnly,
            SandboxGuarantee::NetworkIsolation,
            SandboxGuarantee::ProcessIsolation,
            SandboxGuarantee::IpcIsolation,
            SandboxGuarantee::UserIsolation,
            SandboxGuarantee::CgroupIsolation,
            SandboxGuarantee::CapabilitiesDropped,
            SandboxGuarantee::EnvironmentIsolation,
            SandboxGuarantee::TerminalIsolation,
            SandboxGuarantee::ParentDeathCleanup,
            SandboxGuarantee::ExecutableIsolation,
        ] {
            assert!(report.guarantees().contains(&guarantee));
        }
        assert!(!report.guarantees().contains(&SandboxGuarantee::Seccomp));
    }
}
