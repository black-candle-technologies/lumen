use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use lumen_core::{
    action::{ActionKind, CanonicalValue},
    extension::{
        ExtensionFailure, ExtensionFailureClass, ExtensionInvocationLimits, ExtensionResponse,
        Sha256Digest,
    },
};
use lumen_extension_sdk::{
    Failure as WireFailure, FailureClass as WireFailureClass, InvocationRequest,
    InvocationResponse, MAX_FRAME_BYTES, Response, SubprocessRequest, SubprocessResponse,
    decode_frame, encode_frame,
};
use lumen_integrations::{
    extension_process::{SubprocessHost, SubprocessHostError},
    sandbox::{
        ResourceLimits, SandboxBackend, SandboxError, SandboxFuture, SandboxOutput, SandboxProfile,
        SandboxReport, SandboxRequest, SandboxStrength, SystemSandbox,
    },
};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use tokio_util::sync::CancellationToken;

type Responder = dyn Fn(&SandboxRequest) -> Result<SandboxOutput, SandboxError> + Send + Sync;

struct FakeSandbox {
    responder: Arc<Responder>,
    requests: Mutex<Vec<SandboxRequest>>,
}

impl FakeSandbox {
    fn new(
        responder: impl Fn(&SandboxRequest) -> Result<SandboxOutput, SandboxError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            responder: Arc::new(responder),
            requests: Mutex::new(Vec::new()),
        }
    }
}

impl SandboxBackend for FakeSandbox {
    fn report(&self) -> SandboxReport {
        SandboxReport::new("fake", SandboxStrength::KernelEnforced, None)
    }

    fn execute(&self, request: SandboxRequest) -> SandboxFuture<'_> {
        let result = (self.responder)(&request);
        self.requests.lock().unwrap().push(request);
        Box::pin(async move { result })
    }
}

fn fixture() -> (TempDir, PathBuf, Sha256Digest) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plugin");
    std::fs::write(&path, b"approved executable bytes").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let digest = Sha256Digest::parse(format!(
        "{:x}",
        Sha256::digest(b"approved executable bytes")
    ))
    .unwrap();
    (directory, path, digest)
}

fn request(id: &str) -> InvocationRequest {
    InvocationRequest::new(
        id,
        "echo",
        serde_json::json!({"message": "hello"}),
        serde_json::Value::Null,
        1_000,
    )
    .unwrap()
}

fn limits() -> ExtensionInvocationLimits {
    ExtensionInvocationLimits::new(1_000, 16 * 1024, 1, 16 * 1024 * 1024).unwrap()
}

fn resource_limits() -> ResourceLimits {
    ResourceLimits::new(1, 256 * 1024 * 1024, 64 * 1024, 32, 4).unwrap()
}

fn digest_file(path: &Path) -> Sha256Digest {
    Sha256Digest::parse(format!(
        "{:x}",
        Sha256::digest(std::fs::read(path).unwrap())
    ))
    .unwrap()
}

fn sdk_subprocess_fixture() -> (TempDir, PathBuf) {
    let source = std::env::current_exe()
        .unwrap()
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join("examples/subprocess_tool");
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("subprocess_tool");
    std::fs::copy(&source, &path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let path = path.canonicalize().unwrap();
    (directory, path)
}

fn correlated_result(sandbox_request: &SandboxRequest) -> SandboxOutput {
    correlated_response(
        sandbox_request,
        Response::result(serde_json::json!({"ok": true})),
    )
}

fn correlated_response(sandbox_request: &SandboxRequest, response: Response) -> SandboxOutput {
    let request: SubprocessRequest = decode_frame(
        sandbox_request.stdin().expect("framed stdin"),
        MAX_FRAME_BYTES,
    )
    .unwrap();
    let response = SubprocessResponse::new(
        request.nonce(),
        InvocationResponse::new(request.invocation().request_id(), response).unwrap(),
    )
    .unwrap();
    SandboxOutput::new(
        Some(0),
        encode_frame(&response, MAX_FRAME_BYTES).unwrap(),
        Vec::new(),
    )
}

#[tokio::test]
async fn executes_structured_results_proposals_and_typed_failures() {
    let cases = [
        (
            Response::result(serde_json::json!("done")),
            ExtensionResponse::result(CanonicalValue::from("done")),
        ),
        (
            Response::proposal("filesystem.read", serde_json::json!({"path": "README.md"})),
            ExtensionResponse::proposal(
                ActionKind::new("filesystem.read").unwrap(),
                CanonicalValue::object([("path", CanonicalValue::from("README.md"))]),
            ),
        ),
        (
            Response::failure(
                WireFailure::new(WireFailureClass::PluginFault, "fixture failure").unwrap(),
            ),
            ExtensionResponse::failure(
                ExtensionFailure::new(ExtensionFailureClass::PluginFault, "fixture failure")
                    .unwrap(),
            ),
        ),
    ];
    let (_directory, path, digest) = fixture();
    for (index, (wire, expected)) in cases.into_iter().enumerate() {
        let wire = Arc::new(Mutex::new(Some(wire)));
        let sandbox = Arc::new(FakeSandbox::new(move |sandbox_request| {
            Ok(correlated_response(
                sandbox_request,
                wire.lock().unwrap().take().unwrap(),
            ))
        }));
        assert_eq!(
            host(sandbox)
                .invoke(
                    digest.clone(),
                    &path,
                    request(&format!("conformance-{index}")),
                    limits(),
                    CancellationToken::new(),
                )
                .await
                .unwrap(),
            expected
        );
    }
}

fn host(sandbox: Arc<dyn SandboxBackend>) -> SubprocessHost {
    SubprocessHost::new(sandbox, resource_limits(), 4 * 1024).unwrap()
}

#[tokio::test]
async fn executes_one_correlated_frame_with_plugin_sandbox_profile() {
    let sandbox = Arc::new(FakeSandbox::new(|request| Ok(correlated_result(request))));
    let (_directory, path, digest) = fixture();
    let response = host(sandbox.clone())
        .invoke(
            digest.clone(),
            &path,
            request("request-1"),
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        response,
        ExtensionResponse::result(CanonicalValue::object([("ok", CanonicalValue::Bool(true))]))
    );
    host(sandbox.clone())
        .invoke(
            digest,
            &path,
            request("request-2"),
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    let requests = sandbox.requests.lock().unwrap();
    let captured = requests.first().unwrap();
    assert_eq!(captured.profile(), SandboxProfile::Plugin);
    assert_eq!(captured.command().program(), path);
    assert_eq!(captured.command().current_directory(), Some(Path::new("/")));
    assert!(captured.environment().is_empty());
    assert!(captured.stdin().is_some());
    let first: SubprocessRequest =
        decode_frame(captured.stdin().unwrap(), MAX_FRAME_BYTES).unwrap();
    let second: SubprocessRequest =
        decode_frame(requests[1].stdin().unwrap(), MAX_FRAME_BYTES).unwrap();
    assert_ne!(first.nonce(), second.nonce());
}

#[tokio::test]
async fn rejects_digest_nonce_request_protocol_and_trailing_substitution() {
    let (_directory, path, digest) = fixture();
    let never = Arc::new(FakeSandbox::new(|_| panic!("digest mismatch dispatched")));
    assert_eq!(
        host(never)
            .invoke(
                Sha256Digest::parse("0".repeat(64)).unwrap(),
                &path,
                request("digest"),
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        SubprocessHostError::ArtifactDigestMismatch
    );

    std::fs::write(&path, b"substituted executable bytes").unwrap();
    assert_eq!(
        host(Arc::new(FakeSandbox::new(|_| panic!(
            "substituted artifact dispatched"
        ))))
        .invoke(
            digest.clone(),
            &path,
            request("substitution"),
            limits(),
            CancellationToken::new(),
        )
        .await
        .unwrap_err(),
        SubprocessHostError::ArtifactDigestMismatch
    );
    std::fs::write(&path, b"approved executable bytes").unwrap();

    #[cfg(unix)]
    {
        let symlink = path.with_file_name("symlink");
        std::os::unix::fs::symlink(&path, &symlink).unwrap();
        assert_eq!(
            host(Arc::new(FakeSandbox::new(|_| panic!(
                "symlink artifact dispatched"
            ))))
            .invoke(
                digest.clone(),
                &symlink,
                request("symlink"),
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err(),
            SubprocessHostError::InvalidArtifact
        );
        let hardlink = path.with_file_name("hardlink");
        std::fs::hard_link(&path, &hardlink).unwrap();
        assert_eq!(
            host(Arc::new(FakeSandbox::new(|_| panic!(
                "hard-link artifact dispatched"
            ))))
            .invoke(
                digest.clone(),
                &hardlink,
                request("hardlink"),
                limits(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err(),
            SubprocessHostError::InvalidArtifact
        );
        std::fs::remove_file(hardlink).unwrap();
    }

    for (expected, mutate) in [
        (SubprocessHostError::NonceMismatch, "nonce"),
        (SubprocessHostError::RequestMismatch, "request"),
        (SubprocessHostError::ProtocolMismatch, "protocol"),
        (SubprocessHostError::TrailingData, "trailing"),
    ] {
        let sandbox = Arc::new(FakeSandbox::new(move |sandbox_request| {
            let request: SubprocessRequest =
                decode_frame(sandbox_request.stdin().unwrap(), MAX_FRAME_BYTES).unwrap();
            let nonce = if mutate == "nonce" {
                "0".repeat(64)
            } else {
                request.nonce().to_owned()
            };
            let request_id = if mutate == "request" {
                "other"
            } else {
                request.invocation().request_id()
            };
            let response = SubprocessResponse::new(
                nonce,
                InvocationResponse::new(request_id, Response::result(serde_json::Value::Null))
                    .unwrap(),
            )
            .unwrap();
            let mut frame = encode_frame(&response, MAX_FRAME_BYTES).unwrap();
            if mutate == "protocol" {
                let payload = std::str::from_utf8(&frame[4..]).unwrap().replacen(
                    "\"protocol_version\":1",
                    "\"protocol_version\":2",
                    1,
                );
                frame = Vec::from((payload.len() as u32).to_be_bytes());
                frame.extend_from_slice(payload.as_bytes());
            } else if mutate == "trailing" {
                frame.push(0);
            }
            Ok(SandboxOutput::new(Some(0), frame, Vec::new()))
        }));
        assert_eq!(
            host(sandbox)
                .invoke(
                    digest.clone(),
                    &path,
                    request(mutate),
                    limits(),
                    CancellationToken::new(),
                )
                .await
                .unwrap_err(),
            expected
        );
    }
}

#[tokio::test]
async fn classifies_malformed_oversized_exit_timeout_and_cancellation() {
    let (_directory, path, digest) = fixture();
    let cases: Vec<(Result<SandboxOutput, SandboxError>, SubprocessHostError)> = vec![
        (
            Ok(SandboxOutput::new(Some(0), vec![0, 0, 0, 1, 0xff], vec![])),
            SubprocessHostError::InvalidUtf8,
        ),
        (
            Ok(SandboxOutput::new(
                Some(0),
                vec![0, 0, 0, 2, b'{', b'}'],
                vec![],
            )),
            SubprocessHostError::InvalidJson,
        ),
        (
            Ok(SandboxOutput::new(Some(0), vec![0, 0, 0, 8, b'{'], vec![])),
            SubprocessHostError::TruncatedFrame,
        ),
        (
            Ok(SandboxOutput::new(Some(0), vec![0, 1, 0, 0], vec![])),
            SubprocessHostError::ResponseTooLarge,
        ),
        (
            Err(SandboxError::OutputLimitExceeded { limit: 1 }),
            SubprocessHostError::ResourceExhaustion,
        ),
        (
            Ok(SandboxOutput::new(
                Some(0),
                vec![],
                vec![b'x'; 4 * 1024 + 1],
            )),
            SubprocessHostError::ResourceExhaustion,
        ),
        (
            Ok(SandboxOutput::new(
                Some(7),
                vec![],
                b"secret details".to_vec(),
            )),
            SubprocessHostError::NonZeroExit(7),
        ),
        (
            Ok(SandboxOutput::new(None, vec![], vec![])),
            SubprocessHostError::Crash,
        ),
        (
            Ok(SandboxOutput::terminated_by_signal(
                nix::libc::SIGXCPU,
                vec![],
                vec![],
            )),
            SubprocessHostError::ResourceExhaustion,
        ),
        (
            Err(SandboxError::TimedOut),
            SubprocessHostError::DeadlineExceeded,
        ),
        (Err(SandboxError::Cancelled), SubprocessHostError::Cancelled),
    ];
    for (result, expected) in cases {
        let result = Arc::new(Mutex::new(Some(result)));
        let sandbox = Arc::new(FakeSandbox::new(move |_| {
            result.lock().unwrap().take().unwrap()
        }));
        assert_eq!(
            host(sandbox)
                .invoke(
                    digest.clone(),
                    &path,
                    request("classification"),
                    limits(),
                    CancellationToken::new(),
                )
                .await
                .unwrap_err(),
            expected
        );
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn system_plugin_profile_denies_workspace_reads_writes_and_environment() {
    let sandbox = SystemSandbox::detect();
    assert_eq!(sandbox.report().strength(), SandboxStrength::KernelEnforced);
    let workspace = tempfile::tempdir().unwrap();
    let readable = workspace.path().join("private.txt");
    let writable = workspace.path().join("created.txt");
    std::fs::write(&readable, b"private").unwrap();
    let script = r#"
        if [ -n "${HOME+x}" ]; then exit 40; fi
        if [ -r "$1" ]; then exit 41; fi
        if printf x > "$2"; then exit 42; fi
        exit 0
    "#;
    let request = SandboxRequest::new(
        lumen_integrations::sandbox::MonitoredCommand::new("/bin/bash")
            .args([
                "-c",
                script,
                "lumen-plugin-test",
                readable.to_str().unwrap(),
                writable.to_str().unwrap(),
            ])
            .current_dir("/"),
        std::time::Duration::from_secs(2),
        8 * 1024,
        CancellationToken::new(),
        resource_limits(),
    )
    .with_profile(SandboxProfile::Plugin);
    let output = sandbox.execute(request).await.unwrap();
    assert_eq!(output.exit_code(), Some(0), "sandbox output: {output:?}");
    assert!(!writable.exists());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn system_host_executes_the_sdk_subprocess_fixture() {
    let (_directory, executable) = sdk_subprocess_fixture();
    assert!(
        executable.is_file(),
        "SDK subprocess fixture was not built at {}",
        executable.display()
    );
    let response = host(Arc::new(SystemSandbox::detect()))
        .invoke(
            digest_file(&executable),
            &executable,
            request("sdk-fixture"),
            ExtensionInvocationLimits::new(2_000, 16 * 1024, 1, 128 * 1024 * 1024).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        response,
        ExtensionResponse::result(CanonicalValue::object([(
            "message",
            CanonicalValue::from("hello"),
        )]))
    );
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn sdk_fixture_has_no_ambient_files_environment_network_or_process_execution() {
    let (_directory, executable) = sdk_subprocess_fixture();
    assert!(executable.is_file());
    let private = tempfile::tempdir().unwrap();
    let read_path = private.path().join("private.txt");
    let write_path = private.path().join("created.txt");
    std::fs::write(&read_path, b"private").unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let probe = InvocationRequest::new(
        "ambient-probe",
        "echo",
        serde_json::json!({
            "probe_ambient": true,
            "read_path": read_path,
            "socket_address": listener.local_addr().unwrap().to_string(),
            "write_path": write_path,
        }),
        serde_json::Value::Null,
        2_000,
    )
    .unwrap();
    let response = host(Arc::new(SystemSandbox::detect()))
        .invoke(
            digest_file(&executable),
            &executable,
            probe,
            ExtensionInvocationLimits::new(2_000, 16 * 1024, 1, 128 * 1024 * 1024).unwrap(),
            CancellationToken::new(),
        )
        .await
        .unwrap();
    assert_eq!(
        response,
        ExtensionResponse::result(CanonicalValue::object([
            ("environment", CanonicalValue::Bool(false)),
            ("network", CanonicalValue::Bool(false)),
            ("process", CanonicalValue::Bool(false)),
            ("read", CanonicalValue::Bool(false)),
            ("write", CanonicalValue::Bool(false)),
        ]))
    );
    assert!(!write_path.exists());
    assert!(listener.accept().is_err());
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[tokio::test]
async fn system_host_terminates_deadline_cancellation_and_cpu_exhaustion() {
    let (_directory, executable) = sdk_subprocess_fixture();
    assert!(executable.is_file());
    let forever = |id: &str| {
        InvocationRequest::new(
            id,
            "echo",
            serde_json::json!({"loop_forever": true}),
            serde_json::Value::Null,
            3_000,
        )
        .unwrap()
    };
    let sandbox: Arc<dyn SandboxBackend> = Arc::new(SystemSandbox::detect());
    let process_host = host(sandbox.clone());
    assert_eq!(
        process_host
            .invoke(
                digest_file(&executable),
                &executable,
                forever("deadline"),
                ExtensionInvocationLimits::new(50, 16 * 1024, 1, 128 * 1024 * 1024,).unwrap(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        SubprocessHostError::DeadlineExceeded
    );

    let cancellation = CancellationToken::new();
    let active_cancellation = cancellation.clone();
    let cancelled_host = process_host.clone();
    let cancelled_executable = executable.clone();
    let task = tokio::spawn(async move {
        cancelled_host
            .invoke(
                digest_file(&cancelled_executable),
                &cancelled_executable,
                forever("cancelled"),
                ExtensionInvocationLimits::new(2_000, 16 * 1024, 1, 128 * 1024 * 1024).unwrap(),
                active_cancellation,
            )
            .await
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    cancellation.cancel();
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        SubprocessHostError::Cancelled
    );

    assert_eq!(
        host(sandbox)
            .invoke(
                digest_file(&executable),
                &executable,
                forever("cpu"),
                ExtensionInvocationLimits::new(3_000, 16 * 1024, 1, 128 * 1024 * 1024,).unwrap(),
                CancellationToken::new(),
            )
            .await
            .unwrap_err(),
        SubprocessHostError::ResourceExhaustion
    );
}
