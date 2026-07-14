use std::{fs, io::Read as _, path::Path, sync::Arc, time::Duration};

use lumen_core::extension::{ExtensionInvocationLimits, ExtensionResponse, Sha256Digest};
use lumen_extension_sdk::{
    FrameError, InvocationRequest, MAX_FRAME_BYTES, SubprocessRequest, SubprocessResponse,
    WireContractError, decode_frame, encode_frame,
};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use crate::{
    extension_protocol::wire_response_to_core,
    sandbox::{
        MonitoredCommand, ResourceLimits, SandboxBackend, SandboxError, SandboxProfile,
        SandboxRequest, SandboxStrength,
    },
};

const FRAME_PREFIX_BYTES: usize = 4;

#[derive(Clone)]
pub struct SubprocessHost {
    sandbox: Arc<dyn SandboxBackend>,
    resource_limits: ResourceLimits,
    max_stderr_bytes: usize,
}

impl SubprocessHost {
    pub fn new(
        sandbox: Arc<dyn SandboxBackend>,
        resource_limits: ResourceLimits,
        max_stderr_bytes: usize,
    ) -> Result<Self, SubprocessHostError> {
        if max_stderr_bytes == 0 {
            return Err(SubprocessHostError::InvalidLimits);
        }
        Ok(Self {
            sandbox,
            resource_limits,
            max_stderr_bytes,
        })
    }

    pub async fn invoke(
        &self,
        artifact_digest: Sha256Digest,
        executable: &Path,
        request: InvocationRequest,
        limits: ExtensionInvocationLimits,
        cancellation: CancellationToken,
    ) -> Result<ExtensionResponse, SubprocessHostError> {
        if cancellation.is_cancelled() {
            return Err(SubprocessHostError::Cancelled);
        }
        if self.sandbox.report().strength() != SandboxStrength::KernelEnforced {
            return Err(SubprocessHostError::SandboxUnavailable);
        }
        verify_artifact(executable, &artifact_digest)?;

        let nonce = fresh_nonce()?;
        let expected_protocol = request.protocol_version();
        let expected_request_id = request.request_id().to_owned();
        let request = SubprocessRequest::new(&nonce, request)
            .map_err(|_| SubprocessHostError::InvalidRequest)?;
        let stdin = encode_frame(&request, MAX_FRAME_BYTES).map_err(|error| match error {
            FrameError::TooLarge => SubprocessHostError::RequestTooLarge,
            _ => SubprocessHostError::InvalidRequest,
        })?;

        let response_limit = usize::try_from(limits.max_result_bytes())
            .unwrap_or(usize::MAX)
            .min(MAX_FRAME_BYTES);
        let output_limit = FRAME_PREFIX_BYTES
            .checked_add(response_limit)
            .and_then(|value| value.checked_add(self.max_stderr_bytes))
            .ok_or(SubprocessHostError::InvalidLimits)?;
        let command = MonitoredCommand::new(executable).current_dir("/");
        let sandbox_request = SandboxRequest::new(
            command,
            Duration::from_millis(limits.deadline_millis()),
            output_limit,
            cancellation,
            self.resource_limits
                .with_max_address_space(limits.max_memory_bytes()),
        )
        .with_profile(SandboxProfile::Plugin)
        .with_stdin(stdin);
        let output = self
            .sandbox
            .execute(sandbox_request)
            .await
            .map_err(map_sandbox_error)?;
        if output.stderr().len() > self.max_stderr_bytes {
            return Err(SubprocessHostError::ResourceExhaustion);
        }
        if let Some(signal) = output.termination_signal() {
            return if is_resource_signal(signal) {
                Err(SubprocessHostError::ResourceExhaustion)
            } else {
                Err(SubprocessHostError::TerminatedBySignal(signal))
            };
        }
        match output.exit_code() {
            Some(0) => {}
            Some(code) => return Err(SubprocessHostError::NonZeroExit(code)),
            None => return Err(SubprocessHostError::Crash),
        }

        let response: SubprocessResponse =
            decode_frame(output.stdout(), response_limit).map_err(map_frame_error)?;
        let response = response
            .validate_for(&nonce, expected_protocol, &expected_request_id)
            .map_err(map_wire_error)?;
        wire_response_to_core(response).map_err(|_| SubprocessHostError::InvalidResponse)
    }
}

#[cfg(unix)]
fn is_resource_signal(signal: i32) -> bool {
    signal == nix::libc::SIGXCPU || signal == nix::libc::SIGXFSZ
}

#[cfg(not(unix))]
fn is_resource_signal(_signal: i32) -> bool {
    false
}

fn fresh_nonce() -> Result<String, SubprocessHostError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|error| SubprocessHostError::Host(format!("nonce generation failed: {error}")))?;
    let mut nonce = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut nonce, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(nonce)
}

fn verify_artifact(path: &Path, expected: &Sha256Digest) -> Result<(), SubprocessHostError> {
    if !path.is_absolute() {
        return Err(SubprocessHostError::InvalidArtifact);
    }
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| SubprocessHostError::InvalidArtifact)?;
    if !path_metadata.file_type().is_file() || has_multiple_links(&path_metadata) {
        return Err(SubprocessHostError::InvalidArtifact);
    }
    #[cfg(unix)]
    if !is_executable(&path_metadata) {
        return Err(SubprocessHostError::InvalidArtifact);
    }
    let mut file = open_no_follow(path).map_err(|_| SubprocessHostError::InvalidArtifact)?;
    let before = file
        .metadata()
        .map_err(|_| SubprocessHostError::InvalidArtifact)?;
    if StableMetadata::from(&path_metadata) != StableMetadata::from(&before) {
        return Err(SubprocessHostError::InvalidArtifact);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| SubprocessHostError::InvalidArtifact)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|_| SubprocessHostError::InvalidArtifact)?;
    let path_after =
        fs::symlink_metadata(path).map_err(|_| SubprocessHostError::InvalidArtifact)?;
    if StableMetadata::from(&before) != StableMetadata::from(&after)
        || StableMetadata::from(&after) != StableMetadata::from(&path_after)
        || has_multiple_links(&path_after)
    {
        return Err(SubprocessHostError::InvalidArtifact);
    }
    if format!("{:x}", hasher.finalize()) != expected.as_str() {
        return Err(SubprocessHostError::ArtifactDigestMismatch);
    }
    Ok(())
}

fn map_frame_error(error: FrameError) -> SubprocessHostError {
    match error {
        FrameError::Truncated => SubprocessHostError::TruncatedFrame,
        FrameError::TooLarge => SubprocessHostError::ResponseTooLarge,
        FrameError::TrailingData => SubprocessHostError::TrailingData,
        FrameError::InvalidUtf8 => SubprocessHostError::InvalidUtf8,
        FrameError::InvalidJson => SubprocessHostError::InvalidJson,
    }
}

fn map_wire_error(error: WireContractError) -> SubprocessHostError {
    match error {
        WireContractError::ProtocolMismatch => SubprocessHostError::ProtocolMismatch,
        WireContractError::RequestMismatch => SubprocessHostError::RequestMismatch,
        WireContractError::NonceMismatch => SubprocessHostError::NonceMismatch,
        _ => SubprocessHostError::InvalidResponse,
    }
}

fn map_sandbox_error(error: SandboxError) -> SubprocessHostError {
    match error {
        SandboxError::Unavailable(_) => SubprocessHostError::SandboxUnavailable,
        SandboxError::Cancelled => SubprocessHostError::Cancelled,
        SandboxError::TimedOut => SubprocessHostError::DeadlineExceeded,
        SandboxError::OutputLimitExceeded { .. } => SubprocessHostError::ResourceExhaustion,
        other => SubprocessHostError::Host(other.to_string()),
    }
}

#[cfg(unix)]
fn open_no_follow(path: &Path) -> Result<fs::File, std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
}

#[cfg(not(unix))]
fn open_no_follow(path: &Path) -> Result<fs::File, std::io::Error> {
    fs::OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn has_multiple_links(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.nlink() != 1
}

#[cfg(not(unix))]
fn has_multiple_links(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StableMetadata {
    len: u64,
    modified_nanos: u128,
    identity: u128,
}

impl From<&fs::Metadata> for StableMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let modified_nanos = (metadata.mtime() as i128)
                .saturating_mul(1_000_000_000)
                .saturating_add(metadata.mtime_nsec() as i128)
                .max(0) as u128;
            Self {
                len: metadata.len(),
                modified_nanos,
                identity: ((metadata.dev() as u128) << 64) | metadata.ino() as u128,
            }
        }
        #[cfg(not(unix))]
        {
            let modified_nanos = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(0, |value| value.as_nanos());
            Self {
                len: metadata.len(),
                modified_nanos,
                identity: 0,
            }
        }
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SubprocessHostError {
    #[error("subprocess host limits are invalid")]
    InvalidLimits,
    #[error("subprocess artifact is not a canonical executable file")]
    InvalidArtifact,
    #[error("subprocess artifact digest did not match the approved digest")]
    ArtifactDigestMismatch,
    #[error("kernel-enforced plugin sandbox is unavailable")]
    SandboxUnavailable,
    #[error("subprocess request was invalid")]
    InvalidRequest,
    #[error("subprocess request frame exceeded its limit")]
    RequestTooLarge,
    #[error("subprocess response frame was truncated")]
    TruncatedFrame,
    #[error("subprocess response frame exceeded its limit")]
    ResponseTooLarge,
    #[error("subprocess emitted trailing stdout data")]
    TrailingData,
    #[error("subprocess response was not UTF-8")]
    InvalidUtf8,
    #[error("subprocess response was not valid JSON")]
    InvalidJson,
    #[error("subprocess response protocol version did not match")]
    ProtocolMismatch,
    #[error("subprocess response request ID did not match")]
    RequestMismatch,
    #[error("subprocess response nonce did not match")]
    NonceMismatch,
    #[error("subprocess response could not be represented by the runtime contract")]
    InvalidResponse,
    #[error("subprocess exited with status {0}")]
    NonZeroExit(i32),
    #[error("subprocess crashed or was terminated by a signal")]
    Crash,
    #[error("subprocess was terminated by signal {0}")]
    TerminatedBySignal(i32),
    #[error("subprocess exhausted a resource limit")]
    ResourceExhaustion,
    #[error("subprocess exceeded its deadline")]
    DeadlineExceeded,
    #[error("subprocess invocation was cancelled")]
    Cancelled,
    #[error("subprocess host failed: {0}")]
    Host(String),
}
