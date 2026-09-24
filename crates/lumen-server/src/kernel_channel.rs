//! Local kernel channel: the BCT extension's path to the host.
//!
//! Topology (per the rebuild design doc): the BCT extension runs inside
//! Pi and serializes every tool call to the kernel; the extension is a
//! stub, not a security boundary. In phase 3 the kernel client, sandbox
//! runner, and audit sink are all owned by the host process, so the
//! "kernel" the extension talks to is this channel, served by the host
//! on a Unix domain socket.
//!
//! Wire contract (framing mirrors the phase-0 `lumen-kernel/1` JSONL
//! protocol; the envelope is the phase-3 [`ActionEnvelope`]):
//!
//! ```text
//! extension -> host: {"protocol":"lumen-kernel/1","credential":"<hex>","envelope":{...}}\n
//! host -> extension: {"protocol":"lumen-kernel/1","action_digest":"...",
//!                     "decision":{"decision":"allow","version":1},
//!                     "result":{...},"usage":{...},"audit_ref":{...}}\n
//! ```
//!
//! Authentication is two layers, per the design doc's deployment rule
//! ("expose the kernel only through a local authenticated channel with
//! peer-process validation"):
//!
//! 1. A per-session channel credential (hex, 256 bit), minted at spawn,
//!    delivered to Pi via `LUMEN_KERNEL_NONCE`, and zeroized at
//!    termination. It authenticates the *session*, not the user.
//! 2. `SO_PEERCRED` peer-pid validation: the connecting process must be
//!    the session's live Pi child. A credential stolen by another local
//!    process is useless without the pid.
//!
//! One request per connection (like phase-0): simple, robust against
//! half-open sockets, cheap on loopback Unix sockets. Every failure is
//! fail-closed: no decision, no sandbox, no audit write.

use std::{
    future::Future, os::unix::fs::PermissionsExt, path::PathBuf, pin::Pin, sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

use crate::{
    kernel_client::{ActionEnvelope, AuditRef, KernelClient},
    session::SessionId,
    tool_catalog::{ResourceUsage, ToolOutcome, ToolPipeline},
};

/// Wire protocol name. Kept from phase-0; the envelope version inside is
/// authoritative for the action schema.
pub const KERNEL_CHANNEL_PROTOCOL: &str = "lumen-kernel/1";

/// One JSONL request line on the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelRequest {
    pub protocol: String,
    pub credential: String,
    pub envelope: ActionEnvelope,
}

/// The kernel decision, rendered for the extension. Mirrors phase-0's
/// decision shapes; `result`/`usage`/`audit_ref` are phase-3 additions
/// because the host (not the extension) executes the action.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum ChannelDecision {
    Allow {
        version: u32,
    },
    Deny {
        version: u32,
        reason: String,
    },
    PendingApproval {
        version: u32,
        approval_request_id: String,
        reason: String,
    },
}

/// One JSONL response line on the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelResponse {
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<ChannelDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<ResourceUsage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audit_ref: Option<AuditRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ChannelError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelError {
    pub code: String,
    pub detail: String,
}

impl ChannelResponse {
    fn error(code: &str, detail: String, digest: Option<String>) -> Self {
        Self {
            protocol: KERNEL_CHANNEL_PROTOCOL.to_string(),
            action_digest: digest,
            decision: None,
            result: None,
            usage: None,
            audit_ref: None,
            error: Some(ChannelError {
                code: code.to_string(),
                detail,
            }),
        }
    }
}

/// Configuration for the channel listener.
#[derive(Debug, Clone)]
pub struct KernelChannelConfig {
    /// Filesystem path of the Unix socket. The operator owns the parent
    /// directory; the socket file itself is created mode 0600.
    pub socket_path: PathBuf,
    /// Maximum bytes read for one request line. Larger input is
    /// rejected before parsing: no unbounded allocation from the peer.
    pub max_request_bytes: usize,
    /// Bound for reading the request line and for the whole mediation.
    pub request_timeout: Duration,
    /// Maximum concurrent connections. The accept loop holds a permit
    /// per live handler, so excess peers wait in the socket backlog
    /// instead of spawning unbounded tasks.
    pub max_connections: usize,
    /// Verify the peer pid against the session's live child
    /// (`SO_PEERCRED`). Disable only in tests, where the test process
    /// plays the extension's role.
    pub verify_peer_pid: bool,
}

impl Default for KernelChannelConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from("/run/lumen/kernel.sock"),
            max_request_bytes: 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            max_connections: 64,
            verify_peer_pid: true,
        }
    }
}

/// A session the channel resolved from a credential.
#[derive(Debug, Clone)]
pub struct ChannelSession {
    pub session_id: SessionId,
    pub subject: String,
    /// Pid of the session's live Pi child, for peer validation.
    pub child_pid: Option<u32>,
}

/// Object-safe boxed future for the resolver.
pub type ChannelFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Resolves a channel credential to its live session. Implemented by the
/// session supervisor, which owns the credential registry.
pub trait ChannelSessionResolver: Send + Sync {
    fn resolve_session<'a>(
        &'a self,
        credential: &'a str,
    ) -> ChannelFuture<'a, Option<ChannelSession>>;
}

/// Everything the channel needs beyond its config. The kernel and
/// sandbox are the host's real seams; the resolver is the supervisor.
pub struct ChannelDeps {
    pub kernel: Arc<dyn KernelClient>,
    pub sandbox: Arc<dyn crate::tool_catalog::SandboxRunner>,
    pub catalog: Arc<crate::tool_catalog::Catalog>,
    pub sessions: Arc<dyn ChannelSessionResolver>,
}

/// The listening channel. Dropping it stops accepting; in-flight
/// connections run to completion.
pub struct KernelChannel {
    _listener_task: tokio::task::JoinHandle<()>,
    socket_path: PathBuf,
}

impl KernelChannel {
    /// Bind the socket and spawn the accept loop.
    pub async fn serve(config: KernelChannelConfig, deps: ChannelDeps) -> std::io::Result<Self> {
        if let Some(parent) = config.socket_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // A stale socket file from a previous run would make bind fail;
        // the operator owns this path, so removing it is safe.
        let _ = std::fs::remove_file(&config.socket_path);
        let listener = UnixListener::bind(&config.socket_path)?;
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(0o600))?;

        let shared = Arc::new(ChannelShared {
            semaphore: Arc::new(Semaphore::new(config.max_connections)),
            config: config.clone(),
            pipeline: Arc::new(ToolPipeline::new(deps.catalog, deps.kernel, deps.sandbox)),
            sessions: deps.sessions,
        });

        let listener_task = tokio::spawn(async move {
            loop {
                // Acquire before accepting: at most `max_connections`
                // handlers ever exist. Excess peers wait in the socket
                // backlog instead of spawning unbounded tasks.
                let permit = match shared.semaphore.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break, // semaphore closed; shutting down
                };
                let (stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let _permit = permit;
                    handle_connection(&shared, stream).await;
                });
            }
        });

        Ok(Self {
            _listener_task: listener_task,
            socket_path: config.socket_path.clone(),
        })
    }

    pub fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }
}

struct ChannelShared {
    config: KernelChannelConfig,
    pipeline: Arc<ToolPipeline<dyn KernelClient, dyn crate::tool_catalog::SandboxRunner>>,
    sessions: Arc<dyn ChannelSessionResolver>,
    semaphore: Arc<Semaphore>,
}

/// Serve one connection: exactly one request line in, one response line
/// out, then close. Every error path responds with a typed error (or
/// nothing, if the peer vanished) and never touches the sandbox.
async fn handle_connection(shared: &Arc<ChannelShared>, stream: UnixStream) {
    // Capture peer credentials before splitting: the halves do not
    // expose them on all platforms.
    let peer_pid: Option<u32> = stream
        .peer_cred()
        .map(|cred| cred.pid())
        .unwrap_or(None)
        .map(|pid| pid as u32);

    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = Vec::new();

    // One line, bounded, with a deadline: a peer that trickles bytes
    // forever cannot hold the connection open.
    let head: Result<(), ChannelResponse> = async {
        let n = tokio::time::timeout(
            shared.config.request_timeout,
            reader.read_until(b'\n', &mut line),
        )
        .await
        .map_err(|_| {
            ChannelResponse::error("timeout", "request line read timed out".to_string(), None)
        })?
        .map_err(|e| ChannelResponse::error("io", format!("request read failed: {e}"), None))?;
        if n == 0 {
            return Err(ChannelResponse::error(
                "empty",
                "peer closed without sending a request".to_string(),
                None,
            ));
        }
        if line.len() > shared.config.max_request_bytes {
            return Err(ChannelResponse::error(
                "too_large",
                format!(
                    "request line {} exceeds {} bytes",
                    line.len(),
                    shared.config.max_request_bytes
                ),
                None,
            ));
        }
        Ok(())
    }
    .await;

    let response = match head {
        Ok(()) => serve_request(shared, &line, peer_pid).await,
        Err(e) => e,
    };

    let mut bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    // Best effort: the peer may have gone away; there is nothing to do
    // about a failed write.
    let _ = write_half.write_all(&bytes).await;
    let _ = write_half.shutdown().await;
}

/// Parse, authenticate, and mediate one request line.
async fn serve_request(
    shared: &Arc<ChannelShared>,
    line: &[u8],
    peer_pid: Option<u32>,
) -> ChannelResponse {
    let request: ChannelRequest = match serde_json::from_slice(line) {
        Ok(request) => request,
        Err(e) => {
            return ChannelResponse::error(
                "malformed",
                format!("request is not valid JSON: {e}"),
                None,
            );
        }
    };
    if request.protocol != KERNEL_CHANNEL_PROTOCOL {
        return ChannelResponse::error(
            "protocol",
            format!("unsupported protocol {:?}", request.protocol),
            None,
        );
    }

    // Authenticate the session.
    let session = match shared.sessions.resolve_session(&request.credential).await {
        Some(session) => session,
        None => {
            return ChannelResponse::error(
                "auth",
                "unknown or expired channel credential".to_string(),
                None,
            );
        }
    };

    // Peer-process validation: the credential is only valid in the hands
    // of the session's live Pi child. A credential exfiltrated to any
    // other local process is useless.
    if shared.config.verify_peer_pid {
        match (peer_pid, session.child_pid) {
            (Some(peer), Some(child)) if peer == child => {}
            _ => {
                return ChannelResponse::error(
                    "auth",
                    "peer process is not the session's Pi child".to_string(),
                    None,
                );
            }
        }
    }

    let digest = request.envelope.digest().ok();
    let outcome = match tokio::time::timeout(
        shared.config.request_timeout,
        shared
            .pipeline
            .execute_envelope(&request.envelope, &session.subject),
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(_) => {
            return ChannelResponse::error("timeout", "mediation timed out".to_string(), digest);
        }
    };

    map_outcome(outcome, digest)
}

/// Render a pipeline outcome as the channel response.
fn map_outcome(outcome: ToolOutcome, digest: Option<String>) -> ChannelResponse {
    let base = ChannelResponse {
        protocol: KERNEL_CHANNEL_PROTOCOL.to_string(),
        action_digest: digest,
        decision: None,
        result: None,
        usage: None,
        audit_ref: None,
        error: None,
    };
    match outcome {
        ToolOutcome::Completed {
            result,
            usage,
            audit_ref,
        } => ChannelResponse {
            decision: Some(ChannelDecision::Allow { version: 1 }),
            result: Some(result),
            usage: Some(usage),
            audit_ref: Some(audit_ref),
            ..base
        },
        ToolOutcome::Denied { reason } => ChannelResponse {
            decision: Some(ChannelDecision::Deny { version: 1, reason }),
            ..base
        },
        ToolOutcome::PendingApproval {
            approval_request_id,
            reason,
        } => ChannelResponse {
            decision: Some(ChannelDecision::PendingApproval {
                version: 1,
                approval_request_id,
                reason,
            }),
            ..base
        },
        ToolOutcome::InvalidRequest { reason } => {
            ChannelResponse::error("invalid_request", reason, base.action_digest)
        }
        ToolOutcome::Fault { reason } => {
            ChannelResponse::error("fault", reason, base.action_digest)
        }
    }
}
