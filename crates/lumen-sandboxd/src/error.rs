//! Daemon-wide error type.

use thiserror::Error;

/// Every failure mode of sandboxd. All variants fail closed: a run that
/// cannot be fully constrained is never started, and a run whose export
/// cannot be fully validated never commits.
#[derive(Debug, Error)]
pub enum SandboxdError {
    /// Caller is not authorized (bad token or peer UID).
    #[error("unauthorized caller")]
    Unauthorized,

    /// The run spec violates the contract or local policy.
    #[error("invalid run spec: {0}")]
    InvalidSpec(String),

    /// Referenced image digest is unknown, unsigned, or revoked.
    #[error("unapproved image: {0}")]
    UnapprovedImage(String),

    /// Image manifest signature verification failed.
    #[error("image signature invalid: {0}")]
    BadSignature(String),

    /// A host operation (netns, mount, nftables, jailer, ...) failed.
    #[error("host operation failed: {0}")]
    Host(String),

    /// Firecracker or the jailer exited unexpectedly.
    #[error("vmm fault: {0}")]
    Vmm(String),

    /// Guest agent handshake failed or the agent misbehaved.
    #[error("guest agent fault: {0}")]
    GuestAgent(String),

    /// The run exceeded its deadline or a quota; the guest was terminated.
    #[error("run terminated: {0}")]
    Terminated(String),

    /// Export validation rejected the change set.
    #[error("export rejected: {0}")]
    ExportRejected(String),

    /// Network policy denied an egress attempt.
    #[error("egress denied: {0}")]
    EgressDenied(String),

    /// DNS policy denied a resolution.
    #[error("dns denied: {0}")]
    DnsDenied(String),

    /// Secret use was denied (no broker, unknown handle, or policy).
    #[error("secret use denied: {0}")]
    SecretDenied(String),

    /// No such run, or the run is in a state that forbids the operation.
    #[error("run state error: {0}")]
    RunState(String),

    /// Persistent state (journal/config) is unreadable or corrupt.
    #[error("state error: {0}")]
    State(String),

    /// Local API protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// I/O error wrapper.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error wrapper.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

impl SandboxdError {
    /// Machine-readable code for API error responses and audit events.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::InvalidSpec(_) => "invalid_spec",
            Self::UnapprovedImage(_) => "unapproved_image",
            Self::BadSignature(_) => "bad_signature",
            Self::Host(_) => "host_fault",
            Self::Vmm(_) => "vmm_fault",
            Self::GuestAgent(_) => "guest_agent_fault",
            Self::Terminated(_) => "terminated",
            Self::ExportRejected(_) => "export_rejected",
            Self::EgressDenied(_) => "egress_denied",
            Self::DnsDenied(_) => "dns_denied",
            Self::SecretDenied(_) => "secret_denied",
            Self::RunState(_) => "run_state",
            Self::State(_) => "state",
            Self::Protocol(_) => "protocol",
            Self::Io(_) => "io",
            Self::Json(_) => "json",
        }
    }
}
