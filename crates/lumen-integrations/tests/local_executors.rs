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
    secret::SecretRefId,
};
use lumen_integrations::{
    filesystem::{FilesystemError, WorkspaceReader},
    process::{BuiltinActionNormalizer, ProcessError, ProcessExecutor, ProcessRequest},
    sandbox::{
        MonitoredCommand, ProcessMonitor, ResourceLimits, SandboxBackend, SandboxError,
        SandboxFuture, SandboxOutput, SandboxReport, SandboxRequest, SandboxStrength,
        SystemSandbox,
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

fn resource_limits() -> ResourceLimits {
    ResourceLimits::new(2, 256 * 1024 * 1024, 1024 * 1024, 64, 512).expect("valid resource limits")
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
fn network_egress_proposals_are_normalized_to_destination_scoped_capabilities() {
    let context = run_context();
    let normalizer =
        BuiltinActionNormalizer::new(ComponentId::new("builtin.tools").expect("component ID"));

    let action = normalizer
        .normalize(
            &context,
            ActionProposal::new(
                "network.egress",
                lumen_core::action::CanonicalValue::object([
                    (
                        "url",
                        lumen_core::action::CanonicalValue::from("https://api.example.com/v1"),
                    ),
                    ("method", lumen_core::action::CanonicalValue::from("get")),
                ]),
            ),
        )
        .expect("proposal normalizes");

    assert_eq!(action.kind().as_str(), "network.egress");
    assert_eq!(
        action.arguments(),
        &lumen_core::action::CanonicalValue::object([
            ("method", lumen_core::action::CanonicalValue::from("GET")),
            (
                "url",
                lumen_core::action::CanonicalValue::from("https://api.example.com/v1"),
            ),
        ])
    );
    assert_eq!(
        action.required_capabilities(),
        &[Capability::new(
            CapabilityName::NetworkEgress,
            ResourceScope::exact("destination", "https://api.example.com/v1")
                .expect("destination scope"),
        )]
    );
}

#[test]
fn network_egress_proposals_reject_ambiguous_destinations_and_methods() {
    let context = run_context();
    let normalizer =
        BuiltinActionNormalizer::new(ComponentId::new("builtin.tools").expect("component ID"));

    for (url, method) in [
        ("http://api.example.com/v1", "GET"),
        ("https://api.example.com/v1?token=leak", "GET"),
        ("https://api.example.com/v1", "DELETE"),
    ] {
        let error = normalizer
            .normalize(
                &context,
                ActionProposal::new(
                    "network.egress",
                    lumen_core::action::CanonicalValue::object([
                        ("url", lumen_core::action::CanonicalValue::from(url)),
                        ("method", lumen_core::action::CanonicalValue::from(method)),
                    ]),
                ),
            )
            .expect_err("ambiguous network egress proposal must fail");
        assert!(
            error.to_string().contains("destination")
                || error.to_string().contains("method must be GET or POST"),
            "{error}"
        );
    }
}

#[test]
fn file_write_proposals_bind_trusted_before_and_after_snapshots() {
    let workspace = tempdir().expect("temporary workspace");
    std::fs::create_dir(workspace.path().join("notes")).expect("notes directory");
    std::fs::write(workspace.path().join("notes/today.md"), "before").expect("existing note");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");
    let context = run_context();
    let normalizer = BuiltinActionNormalizer::with_filesystem(
        ComponentId::new("builtin.tools").expect("component ID"),
        filesystem,
    );

    let action = normalizer
        .normalize(
            &context,
            ActionProposal::new(
                "filesystem.write",
                lumen_core::action::CanonicalValue::object([
                    (
                        "path",
                        lumen_core::action::CanonicalValue::from("notes/today.md"),
                    ),
                    ("content", lumen_core::action::CanonicalValue::from("after")),
                ]),
            ),
        )
        .expect("proposal normalizes");

    assert_eq!(action.kind().as_str(), "filesystem.write");
    assert_eq!(
        action.arguments(),
        &lumen_core::action::CanonicalValue::object([
            (
                "after",
                lumen_core::action::CanonicalValue::object([
                    ("bytes", lumen_core::action::CanonicalValue::from(5_i64)),
                    ("content", lumen_core::action::CanonicalValue::from("after"),),
                    (
                        "sha256",
                        lumen_core::action::CanonicalValue::from(
                            "f39592393ef0859cb196a52693d2cea00fb2df784b3c04ae54aa7cadb8e562f8",
                        ),
                    ),
                ]),
            ),
            (
                "before",
                lumen_core::action::CanonicalValue::object([
                    ("bytes", lumen_core::action::CanonicalValue::from(6_i64)),
                    (
                        "content",
                        lumen_core::action::CanonicalValue::from("before"),
                    ),
                    ("exists", lumen_core::action::CanonicalValue::from(true)),
                    (
                        "sha256",
                        lumen_core::action::CanonicalValue::from(
                            "6db7d803e74f1ffa7d8f5adc0bf95b3e15bf4c8373fffadf546227cc6c6742cb",
                        ),
                    ),
                ]),
            ),
            (
                "path",
                lumen_core::action::CanonicalValue::from("notes/today.md"),
            ),
        ])
    );
    assert_eq!(
        action.required_capabilities(),
        &[Capability::new(
            CapabilityName::FsWrite,
            ResourceScope::path(
                context.workspace_id(),
                WorkspacePath::parse("notes/today.md").expect("workspace path"),
            ),
        )]
    );
}

#[test]
fn new_file_write_preview_binds_target_absence() {
    let workspace = tempdir().expect("temporary workspace");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");
    let prepared = filesystem
        .prepare_write(
            &WorkspacePath::parse("new.txt").expect("workspace path"),
            "created",
        )
        .expect("new file can be prepared");

    assert!(!prepared.before().exists());
    assert_eq!(prepared.before().content(), None);
    assert_eq!(prepared.before().sha256(), None);
    assert_eq!(prepared.before().bytes(), 0);
}

#[tokio::test]
async fn prepared_file_write_atomically_replaces_unchanged_target() {
    let workspace = tempdir().expect("temporary workspace");
    std::fs::write(workspace.path().join("note.txt"), "before").expect("existing note");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");
    let prepared = filesystem
        .prepare_write(
            &WorkspacePath::parse("note.txt").expect("workspace path"),
            "after",
        )
        .expect("write prepared");

    filesystem
        .replace_text(&prepared)
        .await
        .expect("unchanged target replaced");

    assert_eq!(
        std::fs::read_to_string(workspace.path().join("note.txt")).expect("note read"),
        "after"
    );
}

#[tokio::test]
async fn prepared_file_write_rejects_a_changed_target() {
    let workspace = tempdir().expect("temporary workspace");
    std::fs::write(workspace.path().join("note.txt"), "before").expect("existing note");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");
    let prepared = filesystem
        .prepare_write(
            &WorkspacePath::parse("note.txt").expect("workspace path"),
            "after",
        )
        .expect("write prepared");
    std::fs::write(workspace.path().join("note.txt"), "concurrent change")
        .expect("concurrent change");

    let error = filesystem
        .replace_text(&prepared)
        .await
        .expect_err("stale write must fail");

    assert_eq!(error, FilesystemError::WriteConflict);
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("note.txt")).expect("note read"),
        "concurrent change"
    );
}

#[tokio::test]
async fn prepared_file_write_rejects_mutated_replacement_content() {
    let workspace = tempdir().expect("temporary workspace");
    std::fs::write(workspace.path().join("note.txt"), "before").expect("existing note");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");
    let prepared = filesystem
        .prepare_write(
            &WorkspacePath::parse("note.txt").expect("workspace path"),
            "approved content",
        )
        .expect("write prepared");
    let mut encoded = serde_json::to_value(prepared).expect("prepared write JSON");
    encoded["after"]["content"] = serde_json::Value::String("mutated content".into());
    let mutated = serde_json::from_value(encoded).expect("mutated prepared write shape");

    let error = filesystem
        .replace_text(&mutated)
        .await
        .expect_err("mutated replacement must fail");

    assert!(matches!(error, FilesystemError::InvalidPreparedWrite(_)));
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("note.txt")).expect("note read"),
        "before"
    );
}

#[tokio::test]
async fn new_file_write_rejects_a_target_created_after_preview() {
    let workspace = tempdir().expect("temporary workspace");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");
    let prepared = filesystem
        .prepare_write(
            &WorkspacePath::parse("note.txt").expect("workspace path"),
            "agent content",
        )
        .expect("write prepared");
    std::fs::write(workspace.path().join("note.txt"), "user content").expect("concurrent creation");

    let error = filesystem
        .replace_text(&prepared)
        .await
        .expect_err("new-file race must fail");

    assert_eq!(error, FilesystemError::WriteConflict);
    assert_eq!(
        std::fs::read_to_string(workspace.path().join("note.txt")).expect("note read"),
        "user content"
    );
}

#[test]
fn file_write_preparation_enforces_replacement_limit() {
    let workspace = tempdir().expect("temporary workspace");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 8).expect("workspace opens");

    let error = filesystem
        .prepare_write(
            &WorkspacePath::parse("note.txt").expect("workspace path"),
            "too large",
        )
        .expect_err("oversized replacement must fail");

    assert_eq!(
        error,
        FilesystemError::WriteLimitExceeded {
            limit: 8,
            actual: 9,
        }
    );
}

#[cfg(unix)]
#[test]
fn file_write_preparation_rejects_symlink_targets() {
    use std::os::unix::fs::symlink;

    let workspace = tempdir().expect("temporary workspace");
    let outside = tempdir().expect("outside directory");
    let outside_file = outside.path().join("secret.txt");
    std::fs::write(&outside_file, "secret").expect("outside file");
    symlink(&outside_file, workspace.path().join("linked.txt")).expect("symlink created");
    let filesystem =
        WorkspaceReader::with_limits(workspace.path(), 1024, 1024).expect("workspace opens");

    let error = filesystem
        .prepare_write(
            &WorkspacePath::parse("linked.txt").expect("workspace path"),
            "overwrite",
        )
        .expect_err("symlink target must fail");

    assert_eq!(error, FilesystemError::AccessDenied);
    assert_eq!(
        std::fs::read_to_string(outside_file).expect("outside file read"),
        "secret"
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

#[test]
fn process_secret_bindings_fingerprint_only_opaque_references() {
    let context = run_context();
    let normalizer =
        BuiltinActionNormalizer::new(ComponentId::new("builtin.tools").expect("component ID"));
    let reference =
        SecretRefId::parse("5f7cc8b4-e848-4cb4-91ef-27c5983c41a5").expect("secret reference");

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
                        "secret_environment",
                        lumen_core::action::CanonicalValue::object([(
                            "API_TOKEN",
                            lumen_core::action::CanonicalValue::from(reference.to_string()),
                        )]),
                    ),
                ]),
            ),
        )
        .expect("secret-bearing proposal normalizes");

    assert!(action.required_capabilities().contains(&Capability::new(
        CapabilityName::SecretUse,
        ResourceScope::exact("secret_reference", reference.to_string()).expect("secret scope"),
    )));
    let encoded = serde_json::to_string(&action).expect("action JSON");
    assert!(encoded.contains("API_TOKEN"));
    assert!(encoded.contains(&reference.to_string()));
    assert!(!encoded.contains("actual-secret-value"));
}

#[test]
fn process_secret_bindings_reject_non_uuid_references() {
    let normalizer =
        BuiltinActionNormalizer::new(ComponentId::new("builtin.tools").expect("component ID"));

    let error = normalizer
        .normalize(
            &run_context(),
            ActionProposal::new(
                "process.spawn",
                lumen_core::action::CanonicalValue::object([
                    (
                        "program",
                        lumen_core::action::CanonicalValue::from("/bin/echo"),
                    ),
                    (
                        "secret_environment",
                        lumen_core::action::CanonicalValue::object([(
                            "API_TOKEN",
                            lumen_core::action::CanonicalValue::from("production-token"),
                        )]),
                    ),
                ]),
            ),
        )
        .expect_err("non-UUID secret reference must fail");

    assert!(error.to_string().contains("secret reference"));
}

#[tokio::test]
async fn system_sandbox_reports_strength_and_enforces_it_when_available() {
    let sandbox = SystemSandbox::detect();
    let report = sandbox.report();
    assert!(!report.backend().is_empty());

    #[cfg(target_os = "linux")]
    assert_eq!(report.strength(), SandboxStrength::KernelEnforced);

    if report.strength() == SandboxStrength::Unavailable {
        return;
    }
    assert!(!report.guarantees().is_empty());

    let workspace = tempdir().expect("temporary workspace");
    let output = sandbox
        .execute(SandboxRequest::new(
            MonitoredCommand::new("/bin/echo")
                .args(["sandboxed"])
                .current_dir(workspace.path()),
            Duration::from_secs(2),
            1024,
            CancellationToken::new(),
            resource_limits(),
        ))
        .await
        .expect("sandboxed command executes");

    assert_eq!(output.exit_code(), Some(0));
    assert_eq!(output.stdout(), b"sandboxed\n");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
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
            resource_limits(),
        ))
        .await
        .expect("sandbox reports process outcome");

    assert!(!marker.exists(), "sandbox allowed a workspace write");
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
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
            resource_limits(),
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
    failure: Option<SandboxError>,
}

impl FakeSandbox {
    fn enforced() -> Self {
        Self {
            report: SandboxReport::new("fake", SandboxStrength::KernelEnforced, None),
            requests: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(AtomicUsize::new(0)),
            failure: None,
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
            failure: None,
        }
    }

    fn failing(error: SandboxError) -> Self {
        Self {
            report: SandboxReport::new("fake", SandboxStrength::KernelEnforced, None),
            requests: Arc::new(Mutex::new(Vec::new())),
            calls: Arc::new(AtomicUsize::new(0)),
            failure: Some(error),
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
        let failure = self.failure.clone();
        Box::pin(async move {
            match failure {
                Some(error) => Err(error),
                None => Ok(SandboxOutput::new(Some(0), b"ok\n".to_vec(), Vec::new())),
            }
        })
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
        resource_limits(),
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
    assert_eq!(requests[0].resource_limits(), resource_limits());
}

#[tokio::test]
async fn process_executor_preserves_sandbox_cancellation_and_timeout() {
    for (error, expected) in [
        (SandboxError::Cancelled, ExecutionOutcome::Cancelled),
        (SandboxError::TimedOut, ExecutionOutcome::TimedOut),
    ] {
        let workspace = tempdir().expect("temporary workspace");
        let executor = process_executor(workspace.path(), Arc::new(FakeSandbox::failing(error)));

        let outcome = executor
            .execute(
                ProcessRequest::new("/bin/echo", ["hello"], BTreeMap::new()),
                CancellationToken::new(),
            )
            .await
            .expect("terminal sandbox outcome");

        assert_eq!(outcome, expected);
    }
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
        resource_limits(),
    )
    .await;

    assert_eq!(result, Err(SandboxError::OutputLimitExceeded { limit: 64 }));
}

#[cfg(unix)]
#[tokio::test]
async fn process_monitor_honors_cancellation() {
    let directory = tempdir().expect("temporary directory");
    let marker = directory.path().join("leaked");
    let script = format!("(sleep 0.3; printf leaked > '{}') & wait", marker.display());
    let cancellation = CancellationToken::new();
    let cancel = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        cancel.cancel();
    });

    let result = ProcessMonitor::run(
        MonitoredCommand::new("/bin/sh").args(["-c", &script]),
        Duration::from_secs(2),
        1024,
        cancellation,
        resource_limits(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(result, Err(SandboxError::Cancelled));
    assert!(!marker.exists(), "grandchild survived cancellation");
}

#[test]
fn resource_limits_reject_zero_for_every_enforced_dimension() {
    for values in [
        [0, 1024, 1024, 16, 512],
        [1, 0, 1024, 16, 512],
        [1, 1024, 0, 16, 512],
        [1, 1024, 1024, 0, 512],
        [1, 1024, 1024, 16, 0],
    ] {
        assert!(
            ResourceLimits::new(values[0], values[1], values[2], values[3], values[4]).is_err()
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn process_monitor_applies_cpu_memory_file_descriptor_and_process_limits() {
    let limits =
        ResourceLimits::new(2, 256 * 1024 * 1024, 4096, 32, 8).expect("valid resource limits");
    let output = ProcessMonitor::run(
        MonitoredCommand::new("/bin/bash").args([
            "-c",
            "ulimit -t; ulimit -v; ulimit -f; ulimit -n; ulimit -u",
        ]),
        Duration::from_secs(2),
        1024,
        CancellationToken::new(),
        limits,
    )
    .await
    .expect("limited shell executes");

    assert_eq!(
        String::from_utf8_lossy(output.stdout()),
        "2\n262144\n4\n32\n8\n"
    );
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
        resource_limits(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(400)).await;

    assert_eq!(result, Err(SandboxError::TimedOut));
    assert!(!marker.exists(), "grandchild survived process-group kill");
}
