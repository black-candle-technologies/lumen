//! Authenticated legacy host action channel, kept disabled by Pi admission.
//!
//! This channel carries the host ActionEnvelope v2 representation. It uses
//! `lumen-host-action/2`, distinct from the authoritative `lumen-kernel/2`
//! protocol and from the proposed intent-only PiBridge v2. It must not be
//! exposed to a Pi runtime without the Phase 3 integration gate.
//!
//! Session credentials and peer-process checks are required before mediation.
//! The host owns execution and audit; the response's v1 ChannelDecision is an
//! outcome rendering, not the kernel PolicyDecision v3 or a reusable grant.
//! Malformed authority is rejected with static diagnostics and audited without
//! trusting or persisting caller-provided identity, keys, values or credentials.

use std::{
    future::Future, os::unix::fs::PermissionsExt, path::PathBuf, pin::Pin, sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
};

use crate::{
    kernel_client::{ActionEnvelope, AuditRef, KernelClient},
    session::SessionId,
    tool_catalog::{ResourceUsage, ToolOutcome, ToolPipeline},
};

/// Distinct host action-view protocol (ADR-0011).
pub const KERNEL_CHANNEL_PROTOCOL: &str = "lumen-host-action/2";

fn current_channel_protocol<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<String, D::Error> {
    let protocol = String::deserialize(decoder)?;
    if protocol != KERNEL_CHANNEL_PROTOCOL {
        return Err(serde::de::Error::custom("unsupported host action channel"));
    }
    Ok(protocol)
}

/// One JSONL request line on the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelRequest {
    #[serde(deserialize_with = "current_channel_protocol")]
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
    #[serde(deserialize_with = "current_channel_protocol")]
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
    /// directory; the socket file itself is parent-owned, group
    /// `sandbox_gid`, mode 0620 (group members may only connect).
    pub socket_path: PathBuf,
    /// Group that may `connect(2)` to the socket. A Pi child mapped to
    /// the dedicated sandbox identity has gid 0 -> `sandbox_gid` in its
    /// user namespace, so group write is its connect path; a 1:1
    /// fallback child connects as the owner. Must be the same gid the
    /// Pi sandbox is configured with.
    pub sandbox_gid: u32,
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
            sandbox_gid: 65534,
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
        // Parent-owned, group-mediated socket: it stays owned by the
        // supervisor's uid, group `sandbox_gid`, mode 0620. A 1:1
        // fallback child connects as the owner; a dedicated-map child
        // (gid 0 -> `sandbox_gid` in its user namespace) connects via
        // group write, which is all `connect(2)` needs. No child-side
        // chown: a dedicated-map child has no privilege over this
        // supervisor-owned inode, so it could never take ownership.
        //
        // A non-root supervisor cannot chown to an arbitrary group --
        // but it also cannot map the dedicated sandbox uid, so the
        // owner-only fallback mode is exactly right there. Only a root
        // supervisor that *can* chown but fails must fail closed.
        let uid = unsafe { libc::getuid() };
        let socket_cstr = std::ffi::CString::new(config.socket_path.as_os_str().as_encoded_bytes())
            .map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("socket path is not a valid C string: {e}"),
                )
            })?;
        let group_ok = unsafe { libc::chown(socket_cstr.as_ptr(), uid, config.sandbox_gid) } == 0;
        if !group_ok && uid == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mode = if group_ok { 0o620 } else { 0o600 };
        std::fs::set_permissions(&config.socket_path, std::fs::Permissions::from_mode(mode))?;

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
///
/// The request line is read through [`read_bounded_line`]: the size
/// bound is enforced *during* the read, so a peer that streams an
/// unbounded line (or never sends a newline) cannot grow the buffer
/// past `max_bytes + 1` before the size check runs.
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

    // One line, bounded, with a deadline: a peer that trickles bytes
    // forever cannot hold the connection open, and a peer that floods
    // bytes cannot grow the buffer past the bound (enforced inside
    // `read_bounded_line`, during the read).
    let head: Result<Vec<u8>, ChannelResponse> = async {
        let line = tokio::time::timeout(
            shared.config.request_timeout,
            read_bounded_line(&mut reader, shared.config.max_request_bytes),
        )
        .await
        .map_err(|_| {
            ChannelResponse::error("timeout", "request line read timed out".to_string(), None)
        })?
        .map_err(|e| ChannelResponse::error("io", format!("request read failed: {e}"), None))?;
        if line.is_empty() {
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
        Ok(line)
    }
    .await;

    let response = match head {
        Ok(line) => serve_request(shared, &line, peer_pid).await,
        Err(e) => e,
    };

    let mut bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
    bytes.push(b'\n');
    // Best effort: the peer may have gone away; there is nothing to do
    // about a failed write.
    let _ = write_half.write_all(&bytes).await;
    let _ = write_half.shutdown().await;
}

/// Read one `\n`-terminated line, enforcing `max_bytes` *during* the
/// read: `take(max_bytes + 1)` caps how much `read_until` can pull
/// from the peer, so the returned buffer never exceeds `max_bytes + 1`
/// bytes even if the peer never sends a newline. Callers still check
/// `line.len() > max_bytes` to reject the over-long line; that check
/// can no longer observe an unbounded allocation.
async fn read_bounded_line(
    reader: &mut (impl tokio::io::AsyncBufRead + Unpin),
    max_bytes: usize,
) -> std::io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut limited = reader.take(max_bytes as u64 + 1);
    limited.read_until(b'\n', &mut line).await?;
    Ok(line)
}

/// Parse, authenticate, and mediate one request line.
async fn serve_request(
    shared: &Arc<ChannelShared>,
    line: &[u8],
    peer_pid: Option<u32>,
) -> ChannelResponse {
    let request: ChannelRequest = match serde_json::from_slice(line) {
        Ok(request) => request,
        Err(_) => {
            // Parser diagnostics may echo arbitrary keys or values. Record
            // a static event and fail closed if audit cannot complete.
            let audited = tokio::time::timeout(
                shared.config.request_timeout,
                shared.pipeline.audit_malformed_request(),
            )
            .await;
            return match audited {
                Ok(Ok(_)) => {
                    ChannelResponse::error("malformed", "invalid authority request".into(), None)
                }
                _ => ChannelResponse::error(
                    "audit",
                    "request denied; audit unavailable".into(),
                    None,
                ),
            };
        }
    };

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
    // Mediation runs in a detached task: if the deadline elapses, the
    // task is left running to completion -- its audit and completion
    // records still land -- while the channel replies `Uncertain`
    // immediately. Cancelling the future instead would drop in-flight
    // commit/audit writes and lose the records the timeout is meant to
    // protect.
    let pipeline = Arc::clone(&shared.pipeline);
    let envelope = request.envelope;
    let subject = session.subject.clone();
    let mediation =
        tokio::spawn(async move { pipeline.execute_envelope(&envelope, &subject).await });
    let outcome = match tokio::time::timeout(shared.config.request_timeout, mediation).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(join_error)) => {
            // The mediation task panicked: it may have panicked before,
            // during, or after the commit, so the effect is unknown --
            // mapping this to `Fault` would wrongly assert the effect
            // did NOT commit. Report `Uncertain` (fail closed) so the
            // client reconciles by action digest instead of blindly
            // retrying and double-executing.
            mediation_panic_outcome(digest.as_deref(), join_error)
        }
        Err(_) => {
            // Deadline elapsed: the detached task keeps running, so its
            // records still land. A plain timeout error would invite the
            // extension to blindly retry and double-execute; report
            // `Uncertain` instead so the client reconciles by digest.
            mediation_timeout_outcome(digest.as_deref(), shared.config.request_timeout)
        }
    };

    map_outcome(outcome, digest)
}

/// Build the outcome for a mediation task that panicked.
///
/// A panic may have landed before, during, or after the effect commit,
/// so the effect state is unknown -- the same unknown-effect state as a
/// timeout. This is the same [`ToolOutcome::Uncertain`] the pipeline
/// itself produces, so the client must reconcile by action digest
/// (re-query, never re-submit) rather than retry the action.
fn mediation_panic_outcome(
    digest: Option<&str>,
    join_error: tokio::task::JoinError,
) -> ToolOutcome {
    ToolOutcome::Uncertain {
        result: serde_json::Value::Null,
        usage: ResourceUsage {
            cpu_ms: 0,
            memory_bytes_max: 0,
            egress_bytes: 0,
        },
        reason: format!(
            "mediation task failed: {join_error}; the effect may have committed \
             -- reconcile by action digest, do not blindly retry"
        ),
        action_digest: digest.unwrap_or_default().to_string(),
        // No staged audit ref exists: the mediation never got far
        // enough to produce one (or its handle was lost to the panic).
        // The digest alone keys reconciliation.
        staged_audit_ref: AuditRef {
            event_id: String::new(),
            chain_hash: String::new(),
        },
    }
}

/// Build the outcome for a mediation that exceeded its deadline.
///
/// The detached mediation task is left running, but the deadline may
/// have fired while the commit or its audit write was in flight, so
/// the effect may already have landed. Cancellation is not proof the
/// effect did not happen: this is the same unknown-effect state as the
/// pipeline's own [`ToolOutcome::Uncertain`], so the client must
/// reconcile by action digest (re-query, never re-submit) rather than
/// retry the action.
fn mediation_timeout_outcome(digest: Option<&str>, timeout: Duration) -> ToolOutcome {
    ToolOutcome::Uncertain {
        result: serde_json::Value::Null,
        usage: ResourceUsage {
            cpu_ms: 0,
            memory_bytes_max: 0,
            egress_bytes: 0,
        },
        reason: format!(
            "mediation timed out after {timeout:?}; the effect may have committed \
             -- reconcile by action digest, do not blindly retry"
        ),
        action_digest: digest.unwrap_or_default().to_string(),
        // No staged audit ref exists: the mediation never got far
        // enough to produce one (or its handle was lost to the
        // timeout). The digest alone keys reconciliation.
        staged_audit_ref: AuditRef {
            event_id: String::new(),
            chain_hash: String::new(),
        },
    }
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
        // The effect committed but its completion record is not
        // durable. This is a distinct reconciliation error, not a
        // fault (the effect may have landed) and not a success: the
        // response carries no result and no completed audit ref. The
        // action digest plus the staged audit ref locate the audit gap
        // for recovery.
        ToolOutcome::Uncertain {
            reason,
            action_digest,
            staged_audit_ref,
            ..
        } => {
            let mut response = ChannelResponse::error(
                "effect_uncertain",
                format!(
                    "{reason}; reconcile with action_digest={action_digest} staged_audit_ref={staged_audit_ref:?}"
                ),
                base.action_digest,
            );
            response.audit_ref = Some(staged_audit_ref);
            response
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncertain_outcome_maps_to_reconciliation_error() {
        let staged_ref = AuditRef {
            event_id: "evt-staged-1".to_string(),
            chain_hash: "chain-abc".to_string(),
        };
        let response = map_outcome(
            ToolOutcome::Uncertain {
                result: serde_json::json!({"exit_code": 0}),
                usage: ResourceUsage {
                    cpu_ms: 12,
                    memory_bytes_max: 1024,
                    egress_bytes: 0,
                },
                reason: "tool_committed audit write failed".to_string(),
                action_digest: "digest-1".to_string(),
                staged_audit_ref: staged_ref.clone(),
            },
            Some("digest-1".to_string()),
        );
        // Not a decision: no Allow/Deny, and no result payload that
        // could be mistaken for a successful completion.
        assert!(response.decision.is_none());
        assert!(response.result.is_none());
        assert!(response.usage.is_none());
        let error = response
            .error
            .expect("uncertain outcome must render a channel error");
        assert_eq!(error.code, "effect_uncertain");
        assert!(error.detail.contains("tool_committed"));
        assert!(error.detail.contains("digest-1"));
        // The staged audit ref is attached for reconciliation.
        assert_eq!(response.audit_ref, Some(staged_ref));
        assert_eq!(response.action_digest.as_deref(), Some("digest-1"));
    }

    #[test]
    fn mediation_timeout_maps_to_uncertain_not_a_timeout_error() {
        let outcome = mediation_timeout_outcome(Some("digest-9"), Duration::from_secs(30));
        let (reason, action_digest) = match &outcome {
            ToolOutcome::Uncertain {
                reason,
                action_digest,
                ..
            } => (reason.clone(), action_digest.clone()),
            other => panic!("mediation timeout must map to Uncertain, got {other:?}"),
        };
        assert_eq!(action_digest, "digest-9");
        assert!(reason.contains("timed out"), "got: {reason}");
        assert!(
            reason.contains("may have committed"),
            "the client must be warned the effect may have landed: {reason}"
        );

        // Rendered on the wire as the reconciliation error, never as a
        // plain "timeout": no decision, no result, digest attached.
        let response = map_outcome(outcome, Some("digest-9".to_string()));
        let error = response
            .error
            .expect("timeout outcome must render a channel error");
        assert_eq!(error.code, "effect_uncertain");
        assert_ne!(error.code, "timeout");
        assert!(error.detail.contains("digest-9"));
        assert!(response.decision.is_none());
        assert!(response.result.is_none());
        assert_eq!(response.action_digest.as_deref(), Some("digest-9"));
    }

    #[tokio::test]
    async fn bounded_read_caps_allocation_during_read() {
        // A peer that streams 10x the bound without ever sending a
        // newline: the old unbounded `read_until` buffered all of it
        // before the size check ran. The bounded read must stop at
        // max+1 bytes.
        let data = vec![b'x'; 640];
        let mut reader = BufReader::new(&data[..]);
        let line = read_bounded_line(&mut reader, 64).await.unwrap();
        assert_eq!(line.len(), 65, "read must stop at max+1 bytes");
        assert!(!line.ends_with(b"\n"));

        // A well-formed short line still reads fully, newline included.
        let data = b"{\"a\":1}\n";
        let mut reader = BufReader::new(&data[..]);
        let line = read_bounded_line(&mut reader, 64).await.unwrap();
        assert_eq!(line, b"{\"a\":1}\n");

        // A line of exactly max bytes + newline is read in full so the
        // caller's `line.len() > max` check rejects it as too large.
        let mut data = vec![b'y'; 64];
        data.push(b'\n');
        let mut reader = BufReader::new(&data[..]);
        let line = read_bounded_line(&mut reader, 64).await.unwrap();
        assert_eq!(line.len(), 65);
        assert!(line.len() > 64);

        // EOF with no data reads as empty (the "peer closed" path).
        let data: &[u8] = b"";
        let mut reader = BufReader::new(data);
        let line = read_bounded_line(&mut reader, 64).await.unwrap();
        assert!(line.is_empty());
    }
}
