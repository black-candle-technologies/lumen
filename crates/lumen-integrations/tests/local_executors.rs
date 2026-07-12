use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use lumen_core::{
    capability::{Capability, CapabilityName, ResourceScope, WorkspacePath},
    executor::ExecutionOutcome,
    identity::{ComponentId, PrincipalId, WorkspaceId},
    model::ActionProposal,
    run::{ActionNormalizer, RunContext},
};
use lumen_integrations::{
    filesystem::{FilesystemError, WorkspaceReader},
    process::{BuiltinActionNormalizer, ProcessError, ProcessExecutor, ProcessRequest},
    sandbox::{
        MonitoredCommand, ProcessMonitor, SandboxBackend, SandboxError, SandboxFuture,
        SandboxOutput, SandboxReport, SandboxRequest, SandboxStrength, SystemSandbox,
    },
};
use tempfile::tempdir;
use tokio_util::sync::CancellationToken;

fn run_context() -> RunContext {
    RunContext::new(
        lumen_core::action::RunId::new(),
        WorkspaceId::new(),
        PrincipalId::new("local", "operator").expect("principal"),
    )
}

#[test]
fn filesystem_proposals_are_normalized_to_path_scoped_capabilities() {
    let context = run_context();
    let normalizer =
        BuiltinActionNormalizer::new(ComponentId::new("builtin.tools").expect("component ID"));

    let action = normalizer
        .normalize(
            &context,
            ActionProposal::new(
                "filesystem.read",
                lumen_core::action::CanonicalValue::object([(
                    "path",
                    lumen_core::action::CanonicalValue::from("notes/today.md"),
                )]),
            ),
        )
        .expect("proposal normalizes");

    assert_eq!(action.kind().as_str(), "filesystem.read");
    assert_eq!(
        action.required_capabilities(),
        &[Capability::new(
            CapabilityName::FsRead,
            ResourceScope::path(
                context.workspace_id(),
                WorkspacePath::parse("notes/today.md").expect("workspace path"),
            ),
        )]
    );
}

#[test]
fn process_proposals_bind_the_canonical_executable_and_read_only_workspace() {
    let context = run_context();
    let normalizer =
        BuiltinActionNormalizer::new(ComponentId::new("builtin.tools").expect("component ID"));

    let action = normalizer
        .normalize(
            &context,
            ActionProposal::new(
                "process.spawn",
                lumen_core::action::CanonicalValue::object([
                    (
                        "program",
                        lumen_core::action::CanonicalValue::from("/bin/echo"),
                    ),
                    (
                        "args",
                        lumen_core::action::CanonicalValue::Array(vec![
                            lumen_core::action::CanonicalValue::from("hello"),
                        ]),
                    ),
                    (
                        "environment",
                        lumen_core::action::CanonicalValue::Object(BTreeMap::new()),
                    ),
                ]),
            ),
        )
        .expect("proposal normalizes");

    let canonical_program = std::fs::canonicalize("/bin/echo")
        .expect("echo executable")
        .to_string_lossy()
        .into_owned();
    assert_eq!(action.kind().as_str(), "process.spawn");
    assert!(action.required_capabilities().contains(&Capability::new(
        CapabilityName::FsRead,
        ResourceScope::workspace(context.workspace_id()),
    )));
    assert!(action.required_capabilities().contains(&Capability::new(
        CapabilityName::ProcessSpawn,
        ResourceScope::exact("executable", canonical_program).expect("exact scope"),
    )));
}

#[tokio::test]
async fn system_sandbox_reports_strength_and_enforces_it_when_available() {
    let sandbox = SystemSandbox::detect();
    let report = sandbox.report();
    assert!(!report.backend().is_empty());

    if report.strength() == SandboxStrength::Unavailable {
        return;
    }

    let workspace = tempdir().expect("temporary workspace");
    let output = sandbox
        .execute(SandboxRequest::new(
            MonitoredCommand::new("/bin/echo")
                .args(["sandboxed"])
                .current_dir(workspace.path()),
            Duration::from_secs(2),
            1024,
            CancellationToken::new(),
        ))
        .await
        .expect("sandboxed command executes");

    assert_eq!(output.exit_code(), Some(0));
    assert_eq!(output.stdout(), b"sandboxed\n");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn system_sandbox_denies_workspace_writes() {
    let sandbox = SystemSandbox::detect();
    let workspace = tempdir().expect("temporary workspace");
    let marker = workspace.path().join("blocked");

    let _output = sandbox
        .execute(SandboxRequest::new(
            MonitoredCommand::new("/bin/sh")
                .args(["-c", "printf denied > blocked"])
                .current_dir(workspace.path()),
            Duration::from_secs(2),
            1024,
            CancellationToken::new(),
        ))
        .await
        .expect("sandbox reports process outcome");

    assert!(!marker.exists(), "sandbox allowed a workspace write");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn system_sandbox_denies_reads_outside_the_workspace() {
    let sandbox = SystemSandbox::detect();
    let workspace = tempdir().expect("temporary workspace");
    let outside = tempdir().expect("outside directory");
    let secret = outside.path().join("secret");
    std::fs::write(&secret, "must-not-leak").expect("secret written");
    let script = format!(
        "IFS= read -r value < '{}'; printf '%s' \"$value\"",
        secret.display()
    );

    let output = sandbox
        .execute(SandboxRequest::new(
            MonitoredCommand::new("/bin/sh")
                .args(["-c", &script])
                .current_dir(workspace.path()),
            Duration::from_secs(2),
            1024,
            CancellationToken::new(),
        ))
        .await
        .expect("sandbox reports process outcome");

    assert!(!String::from_utf8_lossy(output.stdout()).contains("must-not-leak"));
}

#[tokio::test]
async fn workspace_reader_reads_only_relative_canonical_paths() {
    let directory = tempdir().expect("temporary workspace");
    std::fs::create_dir(directory.path().join("notes")).expect("notes directory");
    std::fs::write(directory.path().join("notes/today.md"), "hello").expect("note written");
    let reader = WorkspaceReader::new(directory.path(), 1024).expect("reader opens");

    let contents = reader
        .read_text(&WorkspacePath::parse("notes/today.md").expect("valid path"))
        .await
        .expect("file read");

    assert_eq!(contents, "hello");
}

#[cfg(unix)]
#[tokio::test]
async fn workspace_reader_rejects_symlink_escape() {
    use std::os::unix::fs::symlink;

    let workspace = tempdir().expect("temporary workspace");
    let outside = tempdir().expect("outside directory");
    std::fs::write(outside.path().join("secret.txt"), "secret").expect("secret written");
    symlink(outside.path(), workspace.path().join("escape")).expect("symlink created");
    let reader = WorkspaceReader::new(workspace.path(), 1024).expect("reader opens");

    let result = reader
        .read_text(&WorkspacePath::parse("escape/secret.txt").expect("valid lexical path"))
        .await;

    assert!(matches!(result, Err(FilesystemError::AccessDenied)));
}

#[tokio::test]
async fn workspace_reader_enforces_output_limit() {
    let directory = tempdir().expect("temporary workspace");
    std::fs::write(directory.path().join("large.txt"), "x".repeat(256)).expect("file written");
    let reader = WorkspaceReader::new(directory.path(), 64).expect("reader opens");

    let result = reader
        .read_text(&WorkspacePath::parse("large.txt").expect("valid path"))
        .await;

    assert_eq!(
        result,
        Err(FilesystemError::OutputLimitExceeded { limit: 64 })
    );
}

#[derive(Clone)]
struct FakeSandbox {
    report: SandboxReport,
    requests: Arc<Mutex<Vec<SandboxRequest>>>,
    calls: Arc<AtomicUsize>,
}

impl FakeSandbox {
    fn enforced() -> Self {
        Self {
            report: SandboxReport::new("fake", SandboxStrength::KernelEnforced, None),
            requests: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn unavailable() -> Self {
        Self {
            report: SandboxReport::new(
                "fake",
                SandboxStrength::Unavailable,
                Some("not installed".into()),
            ),
            requests: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl SandboxBackend for FakeSandbox {
    fn report(&self) -> SandboxReport {
        self.report.clone()
    }

    fn execute(&self, request: SandboxRequest) -> SandboxFuture<'_> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests.lock().expect("request lock").push(request);
        Box::pin(async { Ok(SandboxOutput::new(Some(0), b"ok\n".to_vec(), Vec::new())) })
    }
}

fn process_executor(
    workspace: &std::path::Path,
    sandbox: Arc<dyn SandboxBackend>,
) -> ProcessExecutor {
    ProcessExecutor::new(
        workspace,
        [std::path::PathBuf::from("/bin/echo")],
        BTreeSet::from(["LANG".to_owned()]),
        Duration::from_secs(2),
        1024,
        sandbox,
    )
    .expect("process executor builds")
}

#[tokio::test]
async fn process_executor_enforces_program_allowlist() {
    let workspace = tempdir().expect("temporary workspace");
    let sandbox = Arc::new(FakeSandbox::enforced());
    let executor = process_executor(workspace.path(), sandbox.clone());

    let result = executor
        .execute(
            ProcessRequest::new("/bin/sh", ["-c", "echo denied"], BTreeMap::new()),
            CancellationToken::new(),
        )
        .await;

    assert!(matches!(result, Err(ProcessError::ProgramNotAllowed(_))));
    assert_eq!(sandbox.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn process_executor_rejects_unapproved_environment_variables() {
    let workspace = tempdir().expect("temporary workspace");
    let sandbox = Arc::new(FakeSandbox::enforced());
    let executor = process_executor(workspace.path(), sandbox.clone());
    let environment = BTreeMap::from([
        ("LANG".to_owned(), "C".to_owned()),
        ("SECRET".to_owned(), "must-not-pass".to_owned()),
    ]);

    let result = executor
        .execute(
            ProcessRequest::new("/bin/echo", ["hello"], environment),
            CancellationToken::new(),
        )
        .await;

    assert_eq!(
        result,
        Err(ProcessError::EnvironmentNotAllowed("SECRET".into()))
    );
    assert_eq!(sandbox.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn process_executor_passes_only_validated_request_to_sandbox() {
    let workspace = tempdir().expect("temporary workspace");
    let sandbox = Arc::new(FakeSandbox::enforced());
    let executor = process_executor(workspace.path(), sandbox.clone());

    let outcome = executor
        .execute(
            ProcessRequest::new(
                "/bin/echo",
                ["hello"],
                BTreeMap::from([("LANG".to_owned(), "C".to_owned())]),
            ),
            CancellationToken::new(),
        )
        .await
        .expect("sandbox succeeds");

    assert_eq!(
        outcome,
        ExecutionOutcome::Succeeded(lumen_core::action::CanonicalValue::object([
            ("exit_code", lumen_core::action::CanonicalValue::from(0_i64)),
            ("stdout", lumen_core::action::CanonicalValue::from("ok\n")),
            ("stderr", lumen_core::action::CanonicalValue::from("")),
        ]))
    );
    let requests = sandbox.requests.lock().expect("request lock");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].environment().get("LANG"), Some(&"C".to_owned()));
    assert!(!requests[0].environment().contains_key("SECRET"));
}

#[tokio::test]
async fn process_executor_denies_when_kernel_sandbox_is_unavailable() {
    let workspace = tempdir().expect("temporary workspace");
    let sandbox = Arc::new(FakeSandbox::unavailable());
    let executor = process_executor(workspace.path(), sandbox.clone());

    let result = executor
        .execute(
            ProcessRequest::new("/bin/echo", ["hello"], BTreeMap::new()),
            CancellationToken::new(),
        )
        .await;

    assert!(matches!(result, Err(ProcessError::SandboxUnavailable(_))));
    assert_eq!(sandbox.calls.load(Ordering::SeqCst), 0);
}

#[cfg(unix)]
#[tokio::test]
async fn process_monitor_enforces_output_limit() {
    let command = MonitoredCommand::new("/bin/sh").args(["-c", "yes x | head -c 4096"]);

    let result = ProcessMonitor::run(
        command,
        Duration::from_secs(2),
        64,
        CancellationToken::new(),
    )
    .await;

    assert_eq!(result, Err(SandboxError::OutputLimitExceeded { limit: 64 }));
}

#[cfg(unix)]
#[tokio::test]
async fn process_monitor_honors_cancellation() {
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
    });

    let result = ProcessMonitor::run(
        MonitoredCommand::new("/bin/sh").args(["-c", "sleep 10"]),
        Duration::from_secs(2),
        1024,
        cancellation,
    )
    .await;

    assert_eq!(result, Err(SandboxError::Cancelled));
}

#[cfg(unix)]
#[tokio::test]
async fn process_monitor_timeout_terminates_the_process_group() {
    let directory = tempdir().expect("temporary directory");
    let marker = directory.path().join("leaked");
    let script = format!("(sleep 0.3; printf leaked > '{}') & wait", marker.display());

    let result = ProcessMonitor::run(
        MonitoredCommand::new("/bin/sh").args(["-c", &script]),
        Duration::from_millis(30),
        1024,
        CancellationToken::new(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(result, Err(SandboxError::TimedOut));
    assert!(!marker.exists(), "grandchild survived process-group kill");
}
