//! Pi session supervisor (3A).
//!
//! The host owns Pi session lifecycle. Pi runs as a long-lived subprocess
//! speaking JSONL over stdin/stdout (RPC mode); Pi events are untrusted
//! input and are parsed strictly.
//!
//! The supervisor:
//! - pins the Pi binary and the BCT extension by SHA-256 digest and refuses
//!   to spawn on mismatch,
//! - spawns Pi with `--no-builtin-tools` (only the pinned BCT extension's
//!   mediated tools are available),
//! - enforces bounded RPC queues, stream sizes, idle time, and total
//!   lifetime,
//! - recovers cleanly from malformed events and child exit (fail closed:
//!   an interrupted session never silently resumes authority),
//! - terminates any session that executes a tool outside the mediated
//!   catalog (no direct fallback path),
//! - persists session *references* separately from authority state (the
//!   reference carries no lease material),
//! - destroys the session identity and revokes the session's leases at
//!   termination.

use std::{
    collections::{HashMap, VecDeque},
    fmt,
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{broadcast, mpsc, oneshot},
};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    authd::{AccountIdentity, SessionBinding},
    kernel_channel::{ChannelFuture, ChannelSession, ChannelSessionResolver},
    kernel_client::{KernelError, SupervisorKernel, now_ms, sha256_hex},
    tool_catalog::Catalog,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Supervisor tunables. Every bound is explicit; nothing is unbounded.
#[derive(Debug, Clone)]
pub struct SupervisorConfig {
    pub pi_binary: PathBuf,
    /// Full argv for the Pi subprocess, excluding the binary itself.
    pub pi_args: Vec<String>,
    pub pi_version: String,
    /// SHA-256 hex of the Pi binary. Spawn is refused on mismatch.
    pub pi_digest: String,
    pub extension_path: PathBuf,
    /// SHA-256 hex of the BCT extension bundle. Spawn is refused on mismatch.
    pub extension_digest: String,
    pub session_dir: PathBuf,
    /// Bound on queued outbound commands (backpressure, not buffering).
    pub outbound_queue_depth: usize,
    /// Maximum accepted JSONL line length; longer lines are an output-flood
    /// fault, never truncated.
    pub max_line_bytes: usize,
    /// Malformed lines tolerated before the session is failed closed.
    pub malformed_threshold: u32,
    pub idle_timeout: Duration,
    pub max_lifetime: Duration,
    pub shutdown_grace: Duration,
    pub watchdog_interval: Duration,
    /// Timeout for request/response RPC correlation (get_state, prompt
    /// acknowledgement). A Pi that cannot answer in time is treated as
    /// failed, not waited on forever.
    pub rpc_timeout: Duration,
    /// Broadcast buffer per session for event consumers.
    pub event_buffer: usize,
    /// Cap on retained stderr lines per session (diagnostics only).
    pub stderr_line_cap: usize,
    /// Path of the kernel channel socket the BCT extension dials. When
    /// set, the supervisor mints a per-session channel credential and
    /// exports `LUMEN_KERNEL_SOCKET` / `LUMEN_KERNEL_NONCE` to the Pi
    /// child. The operator must serve [`crate::kernel_channel::KernelChannel`]
    /// on this path with the supervisor's channel resolver; without a
    /// listener the extension cannot mediate and every tool call fails
    /// closed inside the extension.
    pub channel_socket_path: Option<PathBuf>,
}

impl SupervisorConfig {
    /// Production argv for Pi RPC mode: no session restore, no built-in
    /// tools, no discovered extensions -- only the pinned BCT extension.
    pub fn pi_rpc_argv(extension_path: &Path, session_dir: &Path) -> Vec<String> {
        vec![
            "--mode".to_string(),
            "rpc".to_string(),
            "--no-session".to_string(),
            "--no-builtin-tools".to_string(),
            "--no-extensions".to_string(),
            "--extension".to_string(),
            extension_path.to_string_lossy().into_owned(),
            "--session-dir".to_string(),
            session_dir.to_string_lossy().into_owned(),
        ]
    }
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            pi_binary: PathBuf::from("pi"),
            pi_args: Vec::new(),
            pi_version: "unpinned".to_string(),
            pi_digest: String::new(),
            extension_path: PathBuf::new(),
            extension_digest: String::new(),
            session_dir: PathBuf::from("/tmp/lumen-pi-sessions"),
            outbound_queue_depth: 32,
            max_line_bytes: 1024 * 1024,
            malformed_threshold: 10,
            idle_timeout: Duration::from_secs(1800),
            max_lifetime: Duration::from_secs(8 * 3600),
            shutdown_grace: Duration::from_secs(5),
            watchdog_interval: Duration::from_secs(5),
            rpc_timeout: Duration::from_secs(10),
            event_buffer: 256,
            stderr_line_cap: 100,
            channel_socket_path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Identity, references, store
// ---------------------------------------------------------------------------

/// Opaque session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(Uuid);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

/// Lifecycle status of a supervised session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Paused,
    Interrupted { reason: String },
    Terminated,
}

/// The persisted session reference. Carries NO authority material: no
/// leases, no secrets, no capabilities. Authority state lives with the
/// kernel; this is only a pointer the host and UI can list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRef {
    pub session_id: SessionId,
    pub owner_account_id: String,
    pub session_subject: String,
    pub identity_fingerprint: String,
    pub pi_session_id: Option<String>,
    pub pi_version: String,
    pub status: SessionStatus,
    pub created_at_ms: i64,
    pub ended_at_ms: Option<i64>,
}

/// Session reference store seam. lumen-db wires the durable implementation
/// at integration; the supervisor only ever stores references here.
pub trait SessionStore: Send + Sync {
    fn save(&self, session_ref: &SessionRef) -> Result<(), StoreError>;
    fn get(&self, id: &SessionId) -> Result<Option<SessionRef>, StoreError>;
    fn update_status(
        &self,
        id: &SessionId,
        status: SessionStatus,
        ended_at_ms: Option<i64>,
    ) -> Result<(), StoreError>;
    fn list_by_owner(&self, owner_account_id: &str) -> Result<Vec<SessionRef>, StoreError>;
    /// Record Pi's own session reference on an existing reference.
    /// Authority material is never stored here; this is a pointer only.
    fn update_pi_reference(&self, id: &SessionId, pi_session_id: &str) -> Result<(), StoreError>;
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("session store failure: {0}")]
    Backend(String),
}

/// In-memory reference store for tests and single-host deployments.
#[derive(Debug, Default)]
pub struct MemorySessionStore {
    refs: Mutex<HashMap<SessionId, SessionRef>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionStore for MemorySessionStore {
    fn save(&self, session_ref: &SessionRef) -> Result<(), StoreError> {
        self.refs
            .lock()
            .unwrap()
            .insert(session_ref.session_id, session_ref.clone());
        Ok(())
    }

    fn get(&self, id: &SessionId) -> Result<Option<SessionRef>, StoreError> {
        Ok(self.refs.lock().unwrap().get(id).cloned())
    }

    fn update_status(
        &self,
        id: &SessionId,
        status: SessionStatus,
        ended_at_ms: Option<i64>,
    ) -> Result<(), StoreError> {
        let mut refs = self.refs.lock().unwrap();
        match refs.get_mut(id) {
            Some(session_ref) => {
                session_ref.status = status;
                session_ref.ended_at_ms = ended_at_ms;
                Ok(())
            }
            None => Err(StoreError::Backend(format!("unknown session {id}"))),
        }
    }

    fn list_by_owner(&self, owner_account_id: &str) -> Result<Vec<SessionRef>, StoreError> {
        Ok(self
            .refs
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.owner_account_id == owner_account_id)
            .cloned()
            .collect())
    }

    fn update_pi_reference(&self, id: &SessionId, pi_session_id: &str) -> Result<(), StoreError> {
        let mut refs = self.refs.lock().unwrap();
        match refs.get_mut(id) {
            Some(session_ref) => {
                session_ref.pi_session_id = Some(pi_session_id.to_string());
                Ok(())
            }
            None => Err(StoreError::Backend(format!("unknown session {id}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Pi RPC protocol (host-side view, strict)
// ---------------------------------------------------------------------------

/// Maximum accepted JSONL line length is enforced by the reader before
/// parsing; see [`SupervisorConfig::max_line_bytes`].
///
/// Field names are camelCase on the wire (Pi's RPC convention); the
/// `type` discriminator values are snake_case. Both are pinned here so a
/// Pi upgrade that renames fields fails closed at parse time instead of
/// silently misreading events.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PiEvent {
    Response {
        #[serde(default)]
        id: Option<String>,
        #[serde(default)]
        command: Option<String>,
        #[serde(default)]
        success: bool,
        #[serde(default)]
        data: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<String>,
    },
    AgentStart,
    AgentEnd {
        #[serde(default, rename = "willRetry")]
        will_retry: bool,
    },
    AgentSettled,
    TurnStart,
    TurnEnd,
    MessageStart,
    MessageUpdate {
        #[serde(default)]
        usage: Option<serde_json::Value>,
    },
    MessageEnd,
    ToolExecutionStart {
        #[serde(rename = "toolCallId")]
        tool_call_id: String,
        #[serde(rename = "toolName")]
        tool_name: String,
        #[serde(default)]
        args: serde_json::Value,
    },
    ToolExecutionUpdate {
        #[serde(default, rename = "toolCallId")]
        tool_call_id: String,
        #[serde(default, rename = "toolName")]
        tool_name: String,
    },
    ToolExecutionEnd {
        #[serde(default, rename = "toolCallId")]
        tool_call_id: String,
        #[serde(default, rename = "toolName")]
        tool_name: String,
        #[serde(default, rename = "isError")]
        is_error: bool,
    },
    QueueUpdate,
    EntryAppended,
    SessionInfoChanged {
        #[serde(default)]
        name: Option<String>,
    },
    ThinkingLevelChanged,
    CompactionStart,
    CompactionEnd,
    AutoRetryStart,
    AutoRetryEnd,
    SummarizationRetryScheduled,
    SummarizationRetryAttemptStart,
    SummarizationRetryFinished,
    BashExecutionUpdate {
        #[serde(default)]
        id: Option<String>,
    },
    ExtensionError {
        #[serde(default, rename = "extensionPath")]
        extension_path: Option<String>,
        #[serde(default)]
        event: Option<String>,
        #[serde(default)]
        error: Option<String>,
    },
    ExtensionUiRequest,
    ExtensionUiResponse,
}

#[derive(Debug, Error)]
pub enum PiEventError {
    #[error("line exceeds {0} bytes: output flood")]
    LineTooLong(usize),
    #[error("malformed JSONL: {0}")]
    Malformed(String),
    #[error("unknown event kind")]
    UnknownKind,
}

/// Parse one stdout line from Pi. Unknown `type` values are rejected: the
/// protocol is closed as seen by the host, matching PiBridge v1 semantics.
pub fn parse_pi_event(line: &str) -> Result<PiEvent, PiEventError> {
    serde_json::from_str::<PiEvent>(line).map_err(|e| {
        let message = e.to_string();
        if message.contains("unknown variant") {
            PiEventError::UnknownKind
        } else {
            PiEventError::Malformed(message)
        }
    })
}

/// Commands the host sends to Pi over stdin (JSONL).
///
/// Pi's RPC wire shape is `{ "command": "<name>", ...params }` (see
/// Phase-0 `pi_supervisor.rs`, which was built against the real Pi).
/// `set_model`'s exact parameter shape is Pi-version-specific; the host
/// sends `{ "command": "set_model", "model": "<name>" }` and treats a
/// negative `response` as a failed switch. If a Pi version renames this
/// command the response correlation below surfaces the failure instead
/// of silently assuming the switch happened.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum PiCommand {
    Prompt { id: String, message: String },
    GetState { id: String },
    Abort,
    SetModel { id: String, model: String },
}

fn encode_command(command: &PiCommand) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(command).expect("command serialization");
    bytes.push(b'\n');
    bytes
}

/// An event delivered to host consumers, with its session attached.
#[derive(Debug, Clone)]
pub struct SupervisorEvent {
    pub session_id: SessionId,
    pub event: PiEvent,
    pub received_at_ms: i64,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SupervisorError {
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
    #[error("pin mismatch: {0}")]
    PinMismatch(String),
    #[error("session not running (status: {0:?})")]
    NotRunning(SessionStatus),
    #[error("session not found")]
    SessionNotFound,
    #[error("outbound queue full or write timed out: backpressure")]
    Backpressure,
    #[error("session already terminated")]
    AlreadyTerminated,
    #[error("rpc timed out waiting for Pi response to {0}")]
    RpcTimeout(String),
    #[error("Pi command {command} failed: {error:?}")]
    PiCommandFailed {
        command: String,
        error: Option<String>,
    },
    #[error("Pi did not report a session reference in get_state")]
    NoPiReference,
    #[error("session cannot be restarted from status {0:?}")]
    NotRestartable(SessionStatus),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("kernel error: {0}")]
    Kernel(#[from] KernelError),
    #[error("interrupted: {0}")]
    Interrupted(String),
    #[error("termination failed: {0}")]
    TerminateFailed(String),
}

/// Why a session was failed closed.
#[derive(Debug, Clone)]
pub enum FaultKind {
    /// A stdout line exceeded the size bound.
    OutputFlood { bytes: usize },
    /// Too many malformed or unknown-kind lines.
    MalformedStream { count: u32 },
    /// Pi executed a tool outside the mediated catalog.
    UntrustedTool { tool: String },
    /// The child process exited unexpectedly.
    ChildExited { code: Option<i32> },
    /// Restart failed partway (new child would not spawn, or Pi would
    /// not report a reference): the session has no live child.
    RestartFailed { reason: String },
}

impl FaultKind {
    fn reason(&self) -> String {
        match self {
            FaultKind::OutputFlood { bytes } => format!("output flood: line of {bytes} bytes"),
            FaultKind::MalformedStream { count } => {
                format!("malformed event stream: {count} bad lines")
            }
            FaultKind::UntrustedTool { tool } => {
                format!("untrusted tool executed: {tool}")
            }
            FaultKind::ChildExited { code } => format!("child exited: {code:?}"),
            FaultKind::RestartFailed { reason } => format!("restart failed: {reason}"),
        }
    }
}

/// Report produced by [`SessionHandle::restart`].
#[derive(Debug, Clone)]
pub struct RestartReport {
    pub session_id: SessionId,
    /// Always true on `Ok`: a revocation failure aborts the restart
    /// before any new authority is minted (fail closed) and surfaces as
    /// `Err`, so a successful report never carries stale authority.
    pub leases_revoked: bool,
    pub revoke_error: Option<String>,
}

/// Report produced by [`SessionHandle::terminate`].
#[derive(Debug, Clone)]
pub struct TerminationReport {
    pub session_id: SessionId,
    pub leases_revoked: bool,
    pub revoke_error: Option<String>,
    pub identity_destroyed: bool,
}

/// Termination lifecycle of a session.
///
/// A failed termination attempt returns to [`TerminationState::Active`]
/// so the next `terminate()` retries the incomplete steps (vault identity
/// destruction, lease revocation, child shutdown) instead of falsely
/// reporting success. Only [`TerminationState::Terminated`] — set after
/// every step has completed — yields the idempotent success report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminationState {
    Active,
    Terminating,
    Terminated,
}

/// Kernel channel material handed to a freshly spawned Pi child.
struct ChannelLaunch<'a> {
    socket_path: &'a Path,
    nonce_hex: &'a str,
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

struct SessionInner {
    id: SessionId,
    binding: SessionBinding,
    /// Hex of the vault-minted identity's verifying key (the identity
    /// fingerprint). The secret material lives in the kernel vault, not
    /// here; destruction happens through the vault.
    identity_fingerprint: Option<String>,
    status: SessionStatus,
    /// Pi's own reference for this session (from `get_state`), kept
    /// separate from the host's authority material. `None` until the
    /// first successful `get_state` after (re)spawn.
    pi_session_id: Option<String>,
    /// Child generation: incremented on every restart so the exit
    /// monitor and readers of a previous generation never fault the
    /// session for the old child's death.
    generation: u64,
    /// Shared with the exit monitor: `start_kill` needs `&mut Child`, and
    /// the monitor's `try_wait` poll needs short borrows. The child is
    /// never moved out, so terminate can always reach it.
    child: Option<Arc<tokio::sync::Mutex<Child>>>,
    /// Fired by the exit monitor when the child is reaped.
    exit_notified: Arc<tokio::sync::Notify>,
    cmd_tx: mpsc::Sender<Vec<u8>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    last_activity: Instant,
    created_at: Instant,
    malformed_count: u32,
    termination: TerminationState,
    event_tx: broadcast::Sender<SupervisorEvent>,
    stderr_tail: VecDeque<String>,
    /// Per-session kernel channel credential (hex). `None` when the
    /// channel is not configured. Minted at spawn, rotated at restart,
    /// zeroized at termination. Authenticates the *session* to the
    /// kernel channel; never leaves the host except via the
    /// `LUMEN_KERNEL_NONCE` environment of the Pi child it belongs to.
    channel_credential: Option<ChannelCredential>,
}

/// The kernel channel credential: 256 bits of entropy, hex-encoded.
/// Zeroized on drop; the hex string is the only form that ever exists.
struct ChannelCredential {
    hex: String,
}

impl ChannelCredential {
    fn generate() -> Result<Self, SupervisorError> {
        let mut bytes = [0u8; 32];
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut bytes))
            .map_err(|e| SupervisorError::SpawnFailed(format!("entropy failure: {e}")))?;
        let mut hex = String::with_capacity(64);
        for b in bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        bytes.zeroize();
        Ok(Self { hex })
    }

    fn hex(&self) -> &str {
        &self.hex
    }
}

impl Drop for ChannelCredential {
    fn drop(&mut self) {
        self.hex.zeroize();
    }
}

struct SupervisorInner {
    config: SupervisorConfig,
    kernel: Arc<dyn SupervisorKernel>,
    catalog: Arc<Catalog>,
    store: Arc<dyn SessionStore>,
    sessions: Mutex<HashMap<SessionId, Arc<tokio::sync::Mutex<SessionInner>>>>,
    /// Kernel channel credential hex -> session id. Entries live only
    /// while the session is Running; removed at termination, restart
    /// rotation, and forget.
    channel_credentials: Mutex<HashMap<String, SessionId>>,
}

impl SupervisorInner {
    async fn session(
        &self,
        id: &SessionId,
    ) -> Result<Arc<tokio::sync::Mutex<SessionInner>>, SupervisorError> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or(SupervisorError::SessionNotFound)
    }

    fn session_ids(&self) -> Vec<SessionId> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }

    /// Mint a kernel channel credential for a session and register it.
    /// Returns `None` when the channel is not configured. The registry
    /// entry is removed (and the credential zeroized on drop) by
    /// [`Self::revoke_channel_credential`].
    fn mint_channel_credential(
        &self,
        id: &SessionId,
    ) -> Result<Option<ChannelCredential>, SupervisorError> {
        if self.config.channel_socket_path.is_none() {
            return Ok(None);
        }
        let credential = ChannelCredential::generate()?;
        self.channel_credentials
            .lock()
            .unwrap()
            .insert(credential.hex().to_string(), *id);
        Ok(Some(credential))
    }

    /// Remove a session's channel credential from the registry. The
    /// credential itself is zeroized when its owner drops it.
    fn revoke_channel_credential(&self, id: &SessionId) {
        self.channel_credentials
            .lock()
            .unwrap()
            .retain(|_, session_id| session_id != id);
    }

    /// Mark a session interrupted: fail closed, no implicit retry. The
    /// first fault wins: a later fault (e.g. the exit monitor observing
    /// the kill) never overwrites the original reason.
    async fn fault_session(&self, id: &SessionId, fault: FaultKind) {
        let session = match self.session(id).await {
            Ok(session) => session,
            Err(_) => return,
        };
        let child = {
            let mut inner = session.lock().await;
            if !matches!(inner.termination, TerminationState::Active)
                || matches!(
                    inner.status,
                    SessionStatus::Interrupted { .. } | SessionStatus::Terminated
                )
            {
                return;
            }
            inner.status = SessionStatus::Interrupted {
                reason: fault.reason(),
            };
            // Drop stdin so the child sees EOF, then kill it: a faulted
            // session keeps no subprocess alive.
            inner.shutdown_tx.take();
            inner.child.clone()
        };
        if let Some(child) = child {
            let _ = child.lock().await.start_kill();
        }
        let _ = self.store.update_status(
            id,
            SessionStatus::Interrupted {
                reason: fault.reason(),
            },
            Some(now_ms()),
        );
    }
}

/// Owns Pi session lifecycle for the host.
#[derive(Clone)]
pub struct SessionSupervisor {
    inner: Arc<SupervisorInner>,
}

impl SessionSupervisor {
    pub fn new(
        config: SupervisorConfig,
        kernel: Arc<dyn SupervisorKernel>,
        catalog: Arc<Catalog>,
        store: Arc<dyn SessionStore>,
    ) -> Self {
        let inner = Arc::new(SupervisorInner {
            config,
            kernel,
            catalog,
            store,
            sessions: Mutex::new(HashMap::new()),
            channel_credentials: Mutex::new(HashMap::new()),
        });
        let supervisor = Self { inner };
        supervisor.spawn_watchdog();
        supervisor
    }

    fn spawn_watchdog(&self) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(inner.config.watchdog_interval);
            loop {
                ticker.tick().await;
                for id in inner.session_ids() {
                    Self::watchdog_check(&inner, &id).await;
                }
            }
        });
    }

    /// Ids of currently tracked in-memory sessions.
    pub fn list_sessions(&self) -> Vec<SessionId> {
        self.inner.session_ids()
    }

    async fn watchdog_check(inner: &Arc<SupervisorInner>, id: &SessionId) {
        let session = {
            let sessions = inner.sessions.lock().unwrap();
            match sessions.get(id).cloned() {
                Some(session) => session,
                None => return,
            }
        };
        let (status, idle_for, age, termination) = {
            let inner_session = session.lock().await;
            (
                inner_session.status.clone(),
                inner_session.last_activity.elapsed(),
                inner_session.created_at.elapsed(),
                inner_session.termination,
            )
        };
        if !matches!(termination, TerminationState::Active)
            || !matches!(status, SessionStatus::Running | SessionStatus::Paused)
        {
            return;
        }
        if age > inner.config.max_lifetime {
            if let Err(e) = Self::terminate_inner(inner, &session, "lifetime exceeded").await {
                eprintln!("watchdog lifetime termination failed: {e}");
            }
            return;
        }
        if idle_for > inner.config.idle_timeout && matches!(status, SessionStatus::Running) {
            // Auto-pause on idle: reversible, keeps the process alive.
            let mut inner_session = session.lock().await;
            if matches!(inner_session.status, SessionStatus::Running) {
                inner_session.status = SessionStatus::Paused;
                let id = inner_session.id;
                let status = inner_session.status.clone();
                drop(inner_session);
                let _ = inner.store.update_status(&id, status, None);
            }
        }
    }

    /// Spawn the Pi subprocess and its IO tasks for a session. The
    /// session must already be registered in `inner.sessions` so the
    /// reader/monitor tasks can find it. `generation` tags the tasks so a
    /// restart's stale tasks never fault the session for the old child's
    /// behavior.
    fn start_child(
        inner: &Arc<SupervisorInner>,
        id: SessionId,
        generation: u64,
        session_subject: &str,
        channel: Option<&ChannelLaunch>,
        cmd_rx: mpsc::Receiver<Vec<u8>>,
        shutdown_rx: oneshot::Receiver<()>,
    ) -> Result<Arc<tokio::sync::Mutex<Child>>, SupervisorError> {
        let mut cmd = Command::new(&inner.config.pi_binary);
        cmd.args(&inner.config.pi_args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LUMEN_SESSION_ID", id.to_string())
            .env("LUMEN_SESSION_SUBJECT", session_subject);
        // Kernel channel contract (phase-0 names): the socket the BCT
        // extension dials, and this session's credential for it.
        if let Some(channel) = channel {
            cmd.env("LUMEN_KERNEL_SOCKET", channel.socket_path.as_os_str())
                .env("LUMEN_KERNEL_NONCE", channel.nonce_hex);
        }
        let mut child = cmd
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| SupervisorError::SpawnFailed(e.to_string()))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| SupervisorError::SpawnFailed("no stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SupervisorError::SpawnFailed("no stdout".to_string()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| SupervisorError::SpawnFailed("no stderr".to_string()))?;

        Self::spawn_writer(stdin, cmd_rx, shutdown_rx);
        Self::spawn_reader(Arc::clone(inner), id, generation, stdout);
        Self::spawn_stderr_drain(Arc::clone(inner), id, stderr);
        Self::spawn_exit_monitor(Arc::clone(inner), id, generation);

        Ok(Arc::new(tokio::sync::Mutex::new(child)))
    }

    /// Kill a child and reap it with a bounded wait: no zombies.
    /// `start_kill` on an already-exited child is a harmless no-op, and
    /// `wait` on a reaped child returns immediately.
    async fn kill_and_reap(handle: &Arc<tokio::sync::Mutex<Child>>) {
        {
            let _ = handle.lock().await.start_kill();
        }
        let mut guard = handle.lock().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), guard.wait()).await;
    }

    /// Remove a never-persisted session after a failed spawn: kill the
    /// child (if any) and drop the in-memory entry so no stale Running
    /// state survives the failure.
    async fn destroy_unpersisted(&self, id: &SessionId) {
        self.inner.revoke_channel_credential(id);
        let session = { self.inner.sessions.lock().unwrap().remove(id) };
        if let Some(session) = session {
            let child = session.lock().await.child.clone();
            // Drop stdin first for an orderly shutdown attempt.
            session.lock().await.shutdown_tx.take();
            if let Some(child) = child {
                Self::kill_and_reap(&child).await;
            }
        }
    }

    /// Spawn a new Pi session for an authenticated account.
    ///
    /// The store reference is persisted only AFTER the child is alive and
    /// Pi has reported its session reference: a failed spawn leaves no
    /// stale `Running` reference behind.
    pub async fn spawn_session(
        &self,
        owner: &AccountIdentity,
    ) -> Result<SessionHandle, SupervisorError> {
        crate::pi_launch::require_confinement()
            .map_err(|reason| SupervisorError::SpawnFailed(reason.to_string()))?;
        self.spawn_session_inner(owner).await
    }

    /// Tests of lifecycle mechanics use a fake child, never real Pi. This
    /// method and its call sites do not exist in non-test library builds.
    #[cfg(test)]
    pub(crate) async fn spawn_session_fixture(
        &self,
        owner: &AccountIdentity,
    ) -> Result<SessionHandle, SupervisorError> {
        self.spawn_session_inner(owner).await
    }

    async fn spawn_session_inner(
        &self,
        owner: &AccountIdentity,
    ) -> Result<SessionHandle, SupervisorError> {
        verify_pin(&self.inner.config.pi_binary, &self.inner.config.pi_digest)
            .map_err(SupervisorError::PinMismatch)?;
        verify_pin(
            &self.inner.config.extension_path,
            &self.inner.config.extension_digest,
        )
        .map_err(SupervisorError::PinMismatch)?;

        let id = SessionId::new();
        // Real vault identity: the kernel mints an ephemeral `ed25519:`
        // subject. A vault failure fails the spawn — no fake subject is
        // ever used.
        let identity = self
            .inner
            .kernel
            .start_session_identity(None)
            .await
            .map_err(|e| {
                SupervisorError::SpawnFailed(format!("vault identity mint failed: {e}"))
            })?;
        let binding = SessionBinding {
            session_id: id.to_string(),
            account_id: owner.account_id.clone(),
            session_subject: identity.subject.clone(),
        };
        // Kernel channel credential, minted before any state exists so a
        // mint failure leaves nothing behind.
        let channel_credential = self.inner.mint_channel_credential(&id)?;

        let (cmd_tx, cmd_rx) = mpsc::channel::<Vec<u8>>(self.inner.config.outbound_queue_depth);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let (event_tx, _) = broadcast::channel::<SupervisorEvent>(self.inner.config.event_buffer);

        let session = Arc::new(tokio::sync::Mutex::new(SessionInner {
            id,
            binding: binding.clone(),
            identity_fingerprint: Some(identity.verifying_key_hex.clone()),
            status: SessionStatus::Running,
            pi_session_id: None,
            generation: 0,
            child: None,
            exit_notified: Arc::new(tokio::sync::Notify::new()),
            cmd_tx,
            shutdown_tx: Some(shutdown_tx),
            last_activity: Instant::now(),
            created_at: Instant::now(),
            malformed_count: 0,
            termination: TerminationState::Active,
            event_tx,
            stderr_tail: VecDeque::new(),
            channel_credential,
        }));
        self.inner
            .sessions
            .lock()
            .unwrap()
            .insert(id, Arc::clone(&session));

        // Borrow the channel material for the child environment. The
        // credential lives in the session; the registry already maps it.
        // The guard is held across the synchronous spawn; start_child
        // does not await.
        let child_result = {
            let guard = session.lock().await;
            let channel = match (
                self.inner.config.channel_socket_path.as_deref(),
                guard.channel_credential.as_ref(),
            ) {
                (Some(socket_path), Some(credential)) => Some(ChannelLaunch {
                    socket_path,
                    nonce_hex: credential.hex(),
                }),
                _ => None,
            };
            Self::start_child(
                &self.inner,
                id,
                0,
                &binding.session_subject,
                channel.as_ref(),
                cmd_rx,
                shutdown_rx,
            )
        };
        let child = match child_result {
            Ok(child) => child,
            Err(e) => {
                self.destroy_unpersisted(&id).await;
                return Err(e);
            }
        };
        session.lock().await.child = Some(child);

        let handle = SessionHandle {
            supervisor: self.clone(),
            id,
        };

        // Pi's own session reference, separate from our authority
        // material. Fail the spawn if Pi cannot report it: a session we
        // cannot reference is not a session we can supervise.
        let pi_session_id = match handle.refresh_pi_reference().await {
            Ok(pi_session_id) => pi_session_id,
            Err(e) => {
                self.destroy_unpersisted(&id).await;
                return Err(e);
            }
        };

        // Persist only now that the session is real.
        let session_ref = SessionRef {
            session_id: id,
            owner_account_id: owner.account_id.as_str().to_string(),
            session_subject: binding.session_subject.clone(),
            identity_fingerprint: session
                .lock()
                .await
                .identity_fingerprint
                .clone()
                .unwrap_or_default(),
            pi_session_id: Some(pi_session_id),
            pi_version: self.inner.config.pi_version.clone(),
            status: SessionStatus::Running,
            created_at_ms: now_ms(),
            ended_at_ms: None,
        };
        if let Err(e) = self.inner.store.save(&session_ref) {
            self.destroy_unpersisted(&id).await;
            return Err(SupervisorError::Store(e));
        }

        Ok(handle)
    }

    fn spawn_writer(
        mut stdin: tokio::process::ChildStdin,
        mut cmd_rx: mpsc::Receiver<Vec<u8>>,
        mut shutdown_rx: oneshot::Receiver<()>,
    ) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = cmd_rx.recv() => {
                        let Some(bytes) = command else { break };
                        if stdin.write_all(&bytes).await.is_err() {
                            break;
                        }
                        if stdin.flush().await.is_err() {
                            break;
                        }
                    }
                    _ = &mut shutdown_rx => break,
                }
            }
            // Dropping stdin sends EOF: Pi shuts down orderly.
            drop(stdin);
        });
    }

    /// Read stdout as raw bytes and split strictly on LF. A generic line
    /// reader would also split on U+2028/U+2029, which are legal inside
    /// JSON strings and would corrupt framing.
    fn spawn_reader(
        inner: Arc<SupervisorInner>,
        id: SessionId,
        generation: u64,
        mut stdout: tokio::process::ChildStdout,
    ) {
        tokio::spawn(async move {
            let max_line = inner.config.max_line_bytes;
            let mut buf: Vec<u8> = Vec::with_capacity(8192);
            let mut chunk = [0u8; 8192];
            loop {
                let read = stdout.read(&mut chunk).await;
                let n = match read {
                    Ok(0) => break, // EOF
                    Ok(n) => n,
                    Err(_) => break,
                };
                buf.extend_from_slice(&chunk[..n]);
                // Enforce the line bound incrementally: fail as soon as a
                // line exceeds it, before unbounded buffering.
                while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                    let mut line = buf.drain(..=pos).collect::<Vec<u8>>();
                    if line.last() == Some(&b'\n') {
                        line.pop();
                    }
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    if line.len() > max_line {
                        // A stale generation's flood must not fault the
                        // restarted session.
                        if Self::is_current_generation(&inner, &id, generation).await {
                            let this = Arc::clone(&inner);
                            this.fault_session(&id, FaultKind::OutputFlood { bytes: line.len() })
                                .await;
                        }
                        return;
                    }
                    match String::from_utf8(line) {
                        Ok(text) => Self::dispatch_line(&inner, &id, generation, &text).await,
                        Err(_) => Self::note_malformed(&inner, &id, generation).await,
                    }
                    // A flood fault ends the reader.
                    if Self::is_failed(&inner, &id).await {
                        return;
                    }
                }
                if buf.len() > max_line && !buf.contains(&b'\n') {
                    if Self::is_current_generation(&inner, &id, generation).await {
                        let this = Arc::clone(&inner);
                        this.fault_session(&id, FaultKind::OutputFlood { bytes: buf.len() })
                            .await;
                    }
                    return;
                }
            }
        });
    }

    /// True when `generation` is still the session's live child generation.
    /// Stale tasks (previous child after a restart) use this to avoid
    /// faulting the session for the old child's behavior.
    async fn is_current_generation(
        inner: &Arc<SupervisorInner>,
        id: &SessionId,
        generation: u64,
    ) -> bool {
        // Clone the session Arc inside a scope: the std sessions lock
        // is not `Send` and must not be held across the await below.
        let session = {
            let sessions = inner.sessions.lock().unwrap();
            let Some(session) = sessions.get(id).cloned() else {
                return false;
            };
            session
        };
        session.lock().await.generation == generation
    }

    async fn dispatch_line(
        inner: &Arc<SupervisorInner>,
        id: &SessionId,
        generation: u64,
        line: &str,
    ) {
        if line.trim().is_empty() {
            return;
        }
        // A stale generation's events must not fault the restarted
        // session (the tool guard below included).
        if !Self::is_current_generation(inner, id, generation).await {
            return;
        }
        match parse_pi_event(line) {
            Ok(event) => {
                // Touch activity and enforce the tool guard.
                let session = {
                    let sessions = inner.sessions.lock().unwrap();
                    sessions.get(id).cloned()
                };
                let Some(session) = session else { return };
                let untrusted_tool = {
                    let mut guard = session.lock().await;
                    guard.last_activity = Instant::now();
                    match &event {
                        PiEvent::ToolExecutionStart { tool_name, .. }
                            if !inner.catalog.contains(tool_name) =>
                        {
                            Some(tool_name.clone())
                        }
                        _ => None,
                    }
                };
                {
                    let guard = session.lock().await;
                    let _ = guard.event_tx.send(SupervisorEvent {
                        session_id: *id,
                        event,
                        received_at_ms: now_ms(),
                    });
                }
                if let Some(tool) = untrusted_tool {
                    inner
                        .fault_session(id, FaultKind::UntrustedTool { tool })
                        .await;
                }
            }
            Err(_) => Self::note_malformed(inner, id, generation).await,
        }
    }

    async fn note_malformed(inner: &Arc<SupervisorInner>, id: &SessionId, generation: u64) {
        if !Self::is_current_generation(inner, id, generation).await {
            return;
        }
        let session = {
            let sessions = inner.sessions.lock().unwrap();
            sessions.get(id).cloned()
        };
        let Some(session) = session else { return };
        let (count, threshold) = {
            let mut guard = session.lock().await;
            guard.malformed_count += 1;
            guard.last_activity = Instant::now();
            (guard.malformed_count, inner.config.malformed_threshold)
        };
        // Malformed lines are counted, never silently skipped into policy;
        // past the threshold the session fails closed.
        if count >= threshold {
            inner
                .fault_session(id, FaultKind::MalformedStream { count })
                .await;
        }
    }

    async fn is_failed(inner: &Arc<SupervisorInner>, id: &SessionId) -> bool {
        let session = {
            let sessions = inner.sessions.lock().unwrap();
            sessions.get(id).cloned()
        };
        let Some(session) = session else {
            return true;
        };
        let guard = session.lock().await;
        matches!(
            guard.status,
            SessionStatus::Interrupted { .. } | SessionStatus::Terminated
        )
    }

    fn spawn_stderr_drain(
        inner: Arc<SupervisorInner>,
        id: SessionId,
        stderr: tokio::process::ChildStderr,
    ) {
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut lines = tokio::io::BufReader::new(stderr).lines();
            let cap = inner.config.stderr_line_cap;
            while let Ok(Some(line)) = lines.next_line().await {
                let session = {
                    let sessions = inner.sessions.lock().unwrap();
                    sessions.get(&id).cloned()
                };
                let Some(session) = session else { break };
                let mut guard = session.lock().await;
                guard.stderr_tail.push_back(line);
                while guard.stderr_tail.len() > cap {
                    guard.stderr_tail.pop_front();
                }
            }
        });
    }

    /// Poll the child with `try_wait`: short borrows only, so terminate()
    /// can still reach the handle to kill it. An unexpected exit fails
    /// the session closed; no implicit retry. Exits from a stale
    /// generation (after a restart replaced the child) are ignored.
    fn spawn_exit_monitor(inner: Arc<SupervisorInner>, id: SessionId, generation: u64) {
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let entry = {
                    let sessions = inner.sessions.lock().unwrap();
                    sessions.get(&id).cloned()
                };
                let (child, exit_notified, current) = match entry {
                    Some(session) => {
                        let guard = session.lock().await;
                        (
                            guard.child.clone(),
                            guard.exit_notified.clone(),
                            guard.generation == generation,
                        )
                    }
                    None => return,
                };
                if !current {
                    // Restart replaced this child; the new generation has
                    // its own monitor.
                    return;
                }
                let Some(child) = child else { return };
                let exited = {
                    let mut guard = child.lock().await;
                    match guard.try_wait() {
                        Ok(Some(status)) => Some(status.code()),
                        Ok(None) => None,
                        Err(_) => Some(None),
                    }
                };
                let Some(code) = exited else { continue };
                // `notify_one` (not `notify_waiters`): the permit is
                // stored when no waiter is registered yet, so a
                // terminate that arms its `notified()` future after the
                // exit still observes it. There is exactly one waiter
                // (terminate_inner), so one permit is the right count.
                exit_notified.notify_one();
                // If termination already ran, the exit is expected. A
                // restart bumps the generation: the old monitor must not
                // fault the session for the old child's death even if it
                // observes the exit after the bump.
                let entry = {
                    let sessions = inner.sessions.lock().unwrap();
                    sessions.get(&id).cloned()
                };
                let (expected, current) = match entry {
                    Some(session) => {
                        let guard = session.lock().await;
                        (
                            !matches!(guard.termination, TerminationState::Active),
                            guard.generation == generation,
                        )
                    }
                    None => (true, false),
                };
                if !expected && current {
                    inner
                        .fault_session(&id, FaultKind::ChildExited { code })
                        .await;
                }
                return;
            }
        });
    }

    async fn send_command(
        &self,
        id: &SessionId,
        command: &PiCommand,
    ) -> Result<(), SupervisorError> {
        let session = self.inner.session(id).await?;
        let guard = session.lock().await;
        if !matches!(guard.status, SessionStatus::Running) {
            return Err(SupervisorError::NotRunning(guard.status.clone()));
        }
        let bytes = encode_command(command);
        // Bounded queue: backpressure surfaces as an error, never as
        // unbounded buffering.
        match tokio::time::timeout(Duration::from_secs(5), guard.cmd_tx.send(bytes)).await {
            Ok(Ok(())) => Ok(()),
            _ => Err(SupervisorError::Backpressure),
        }
    }

    /// Kill and reap the Pi child if present. Used on termination failure
    /// paths: the untrusted agent loop must not keep running after the
    /// kernel-side teardown failed, even though the termination itself
    /// remains retryable.
    async fn kill_and_reap_child(session: &Arc<tokio::sync::Mutex<SessionInner>>) {
        if let Some(child) = session.lock().await.child.clone() {
            let _ = child.lock().await.start_kill();
            let mut guard = child.lock().await;
            // `wait` on an already-exited child returns immediately and
            // reaps it; the timeout bounds the pathological case.
            let _ = tokio::time::timeout(Duration::from_secs(2), guard.wait()).await;
        }
    }

    async fn terminate_inner(
        inner: &Arc<SupervisorInner>,
        session: &Arc<tokio::sync::Mutex<SessionInner>>,
        _reason: &str,
    ) -> Result<TerminationReport, SupervisorError> {
        // Termination is a one-way latch with a retryable middle state,
        // checked and armed under a single lock acquisition so two
        // concurrent callers cannot both own the cleanup:
        // - `Terminated`: every step completed; report idempotent success.
        // - `Terminating`: another call owns the in-flight cleanup; report
        //   honestly instead of claiming success.
        // - `Active`: this call owns the cleanup. A failed attempt drops
        //   back to `Active` so the next `terminate()` retries the
        //   incomplete steps (vault identity destruction, lease
        //   revocation, child shutdown) rather than falsely reporting
        //   that the identity was destroyed and all leases revoked.
        let session_id = {
            let mut guard = session.lock().await;
            match guard.termination {
                TerminationState::Terminated => {
                    return Ok(TerminationReport {
                        session_id: guard.id,
                        leases_revoked: true,
                        revoke_error: None,
                        identity_destroyed: true,
                    });
                }
                TerminationState::Terminating => {
                    return Err(SupervisorError::TerminateFailed(
                        "termination already in progress".to_string(),
                    ));
                }
                TerminationState::Active => {
                    guard.termination = TerminationState::Terminating;
                    guard.id
                }
            }
        };

        // 1. Destroy the session identity through the vault FIRST. The
        //    vault reports the destroyed subject plus every vault-known
        //    descendant whose authority died with it. Destroying before
        //    revoking ensures no new authority can be minted from a
        //    subject whose leases are about to die.
        let subject = { session.lock().await.binding.session_subject.clone() };
        let end_report = match inner.kernel.destroy_session_identity(&subject).await {
            Ok(report) => report,
            Err(e) => {
                // The identity may still be live (e.g. transient vault
                // failure): drop back to `Active` so the next
                // `terminate()` retries instead of reporting success.
                // Kill and reap the child first: the untrusted agent loop
                // must not keep running after teardown failed.
                Self::kill_and_reap_child(session).await;
                session.lock().await.termination = TerminationState::Active;
                return Err(SupervisorError::TerminateFailed(format!(
                    "vault destroy failed: {e}"
                )));
            }
        };

        // 2. Revoke leases for EVERY affected subject (parent + all
        //    descendants). A revocation failure is fatal: the session
        //    faults as Interrupted, the error propagates, and the report
        //    never claims clean termination.
        let mut revoke_error: Option<String> = None;
        for affected in &end_report.affected_subjects {
            if let Err(e) = inner.kernel.revoke_session(affected).await {
                revoke_error = Some(format!("revoke {affected} failed: {e}"));
                break;
            }
        }
        if let Some(error) = revoke_error {
            // Kill and reap the child: the untrusted agent loop must not
            // keep running after lease revocation failed, even though the
            // termination remains retryable.
            Self::kill_and_reap_child(session).await;
            let mut guard = session.lock().await;
            guard.status = SessionStatus::Interrupted {
                reason: error.clone(),
            };
            // Leases may still be live: drop back to `Active` so the next
            // `terminate()` retries the revocation (and the vault
            // destroy, which is idempotent) instead of reporting success.
            guard.termination = TerminationState::Active;
            let _ = inner.store.update_status(
                &guard.id,
                SessionStatus::Interrupted {
                    reason: error.clone(),
                },
                Some(now_ms()),
            );
            return Err(SupervisorError::TerminateFailed(error));
        }

        // 3. Terminate and reap Pi. Arm the exit notification BEFORE
        //    signaling shutdown so an exit observed before this point is
        //    still seen.
        let exit_notified = { session.lock().await.exit_notified.clone() };
        let notified = exit_notified.notified();
        tokio::pin!(notified);
        // Signal the writer to drop stdin (orderly Pi shutdown: Pi
        // disposes the active runtime on stdin EOF).
        {
            session.lock().await.shutdown_tx.take();
        }
        // Wait for the exit monitor to observe the child; kill on grace
        // expiry. Either way the child is reaped with a bounded wait: a
        // killed-but-unwaited child would linger as a zombie.
        let exited = tokio::time::timeout(inner.config.shutdown_grace, &mut notified)
            .await
            .is_ok();
        if let Some(child) = session.lock().await.child.clone() {
            if !exited {
                let _ = child.lock().await.start_kill();
            }
            let mut guard = child.lock().await;
            // `wait` on an already-exited child returns immediately and
            // reaps it; the timeout bounds the pathological case.
            let _ = tokio::time::timeout(Duration::from_secs(2), guard.wait()).await;
        }

        // 4. Cleanup: clear the local fingerprint (the vault holds no more
        //    material for this subject) and persist the terminal state.
        //    Only now is termination complete: a later `terminate()`
        //    observes `Terminated` and reports the idempotent success.
        {
            let mut guard = session.lock().await;
            guard.identity_fingerprint = None;
            guard.status = SessionStatus::Terminated;
            guard.termination = TerminationState::Terminated;
            let _ = inner
                .store
                .update_status(&guard.id, SessionStatus::Terminated, Some(now_ms()));
        }

        Ok(TerminationReport {
            session_id,
            leases_revoked: true,
            revoke_error: None,
            identity_destroyed: true,
        })
    }

    /// Remove a terminated session's control state from the supervisor.
    /// The persisted [`SessionRef`] remains for audit.
    pub async fn forget(&self, id: &SessionId) -> Result<(), SupervisorError> {
        let session = self.inner.session(id).await?;
        let terminated = {
            let guard = session.lock().await;
            matches!(guard.termination, TerminationState::Terminated)
                && matches!(guard.status, SessionStatus::Terminated)
        };
        if !terminated {
            return Err(SupervisorError::Interrupted(
                "forget requires a terminated session; call terminate() first".to_string(),
            ));
        }
        self.inner.revoke_channel_credential(id);
        self.inner.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}

impl ChannelSessionResolver for SessionSupervisor {
    fn resolve_session<'a>(
        &'a self,
        credential_hex: &'a str,
    ) -> ChannelFuture<'a, Option<ChannelSession>> {
        Box::pin(async move {
            let id = {
                self.inner
                    .channel_credentials
                    .lock()
                    .unwrap()
                    .get(credential_hex)
                    .cloned()
            }?;
            let session = { self.inner.sessions.lock().unwrap().get(&id).cloned() }?;
            let guard = session.lock().await;
            // Only live sessions authenticate. Termination revokes the
            // credential first, but the check stays: fail closed.
            if !matches!(guard.termination, TerminationState::Active) {
                return None;
            }
            let child_pid = match guard.child.as_ref() {
                Some(child) => child.lock().await.id(),
                None => None,
            };
            Some(ChannelSession {
                session_id: id,
                subject: guard.binding.session_subject.clone(),
                child_pid,
            })
        })
    }
}

impl SessionSupervisor {
    /// Resolver the operator hands to [`crate::kernel_channel::KernelChannel`]
    /// so Pi-to-host requests authenticate against live sessions.
    pub fn channel_resolver(&self) -> Arc<dyn ChannelSessionResolver> {
        Arc::new(self.clone())
    }

    /// Test-only: read a session's channel credential hex.
    #[cfg(test)]
    pub fn test_channel_credential_hex(&self, id: &SessionId) -> Option<String> {
        let session = self.inner.sessions.lock().unwrap().get(id).cloned()?;
        session
            .try_lock()
            .ok()?
            .channel_credential
            .as_ref()
            .map(|c| c.hex().to_string())
    }
}

/// Cloneable handle to one supervised session.
///
/// The binding (owner, subject) is read live from the supervisor: a
/// restart replaces the session identity, and stale handle clones must
/// not keep serving the old subject.#[derive(Clone)]
pub struct SessionHandle {
    supervisor: SessionSupervisor,
    id: SessionId,
}

// SessionHandle is Debug for tests and operator diagnostics; it carries
// no secrets. The supervisor itself is not Debug (dyn seams), so this
// only reports the session id.
impl std::fmt::Debug for SessionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionHandle")
            .field("id", &self.id)
            .finish()
    }
}

impl SessionHandle {
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// The session's current authority binding.
    pub async fn binding(&self) -> Result<SessionBinding, SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        Ok(session.lock().await.binding.clone())
    }

    /// Pi's own reference for this session (`None` until the first
    /// successful `get_state`).
    pub async fn pi_session_id(&self) -> Result<Option<String>, SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        Ok(session.lock().await.pi_session_id.clone())
    }

    pub async fn status(&self) -> Result<SessionStatus, SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        Ok(session.lock().await.status.clone())
    }

    /// Subscribe to the session's event stream.
    pub async fn subscribe(&self) -> Result<broadcast::Receiver<SupervisorEvent>, SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        Ok(session.lock().await.event_tx.subscribe())
    }

    /// Send a user prompt to Pi. Rejected unless the session is running.
    pub async fn prompt(&self, message: impl Into<String>) -> Result<String, SupervisorError> {
        let cmd_id = Uuid::new_v4().to_string();
        self.supervisor
            .send_command(
                &self.id,
                &PiCommand::Prompt {
                    id: cmd_id.clone(),
                    message: message.into(),
                },
            )
            .await?;
        Ok(cmd_id)
    }

    /// Ask Pi to switch models. The caller must have run the Jev
    /// recommendation through the host recheck first.
    pub async fn set_model(&self, model: impl Into<String>) -> Result<String, SupervisorError> {
        let cmd_id = Uuid::new_v4().to_string();
        self.supervisor
            .send_command(
                &self.id,
                &PiCommand::SetModel {
                    id: cmd_id.clone(),
                    model: model.into(),
                },
            )
            .await?;
        Ok(cmd_id)
    }

    pub async fn abort(&self) -> Result<(), SupervisorError> {
        self.supervisor
            .send_command(&self.id, &PiCommand::Abort)
            .await
    }

    /// Pause the session: abort in-flight work, keep the process alive.
    /// Reversible with [`SessionHandle::resume`].
    pub async fn pause(&self) -> Result<(), SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        // Abort first while the status is still Running, then flip the
        // status; a failed abort leaves the session Running (honest).
        self.supervisor
            .send_command(&self.id, &PiCommand::Abort)
            .await?;
        let mut guard = session.lock().await;
        if !matches!(guard.status, SessionStatus::Running) {
            return Err(SupervisorError::NotRunning(guard.status.clone()));
        }
        guard.status = SessionStatus::Paused;
        let id = guard.id;
        let status = guard.status.clone();
        drop(guard);
        let _ = self.supervisor.inner.store.update_status(&id, status, None);
        Ok(())
    }

    pub async fn resume(&self) -> Result<(), SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        let mut guard = session.lock().await;
        if !matches!(guard.status, SessionStatus::Paused) {
            return Err(SupervisorError::NotRunning(guard.status.clone()));
        }
        guard.status = SessionStatus::Running;
        guard.last_activity = Instant::now();
        let id = guard.id;
        let status = guard.status.clone();
        drop(guard);
        let _ = self.supervisor.inner.store.update_status(&id, status, None);
        Ok(())
    }

    /// Terminate the session: vault identity destruction, lease revocation,
    /// orderly child shutdown, terminal reference persisted. Idempotent.
    /// A revocation failure faults the session as Interrupted and returns
    /// an error — the report never claims clean termination.
    pub async fn terminate(&self) -> Result<TerminationReport, SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        SessionSupervisor::terminate_inner(&self.supervisor.inner, &session, "host terminate").await
    }

    /// Query Pi's own state over RPC and return the `data` payload.
    /// Correlates the `response` event by command id with a bounded
    /// timeout: a Pi that cannot answer is a failed Pi, not a hang.
    pub async fn get_state(&self) -> Result<serde_json::Value, SupervisorError> {
        let cmd_id = Uuid::new_v4().to_string();
        // Subscribe BEFORE sending: broadcast has no history.
        let mut events = self.subscribe().await?;
        self.supervisor
            .send_command(&self.id, &PiCommand::GetState { id: cmd_id.clone() })
            .await?;
        let deadline = Instant::now() + self.supervisor.inner.config.rpc_timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = tokio::time::timeout(remaining, events.recv())
                .await
                .map_err(|_| SupervisorError::RpcTimeout("get_state".to_string()))?
                .map_err(|_| {
                    SupervisorError::Interrupted("event stream closed during get_state".to_string())
                })?;
            if let PiEvent::Response {
                id: Some(rid),
                success,
                data,
                error,
                ..
            } = event.event
            {
                if rid != cmd_id {
                    continue;
                }
                if !success {
                    return Err(SupervisorError::PiCommandFailed {
                        command: "get_state".to_string(),
                        error,
                    });
                }
                return Ok(data.unwrap_or(serde_json::Value::Null));
            }
        }
    }

    /// Ask Pi for its session reference and persist it on the session,
    /// separate from the host's authority material. Returns the Pi
    /// reference.
    pub async fn refresh_pi_reference(&self) -> Result<String, SupervisorError> {
        let data = self.get_state().await?;
        // Pi's get_state payload carries its session id as `sessionId`
        // (camelCase RPC convention). Absent means this Pi cannot be
        // referenced: fail, don't invent one.
        let pi_session_id = data
            .get("sessionId")
            .and_then(|v| v.as_str())
            .ok_or(SupervisorError::NoPiReference)?
            .to_string();
        {
            let session = self.supervisor.inner.session(&self.id).await?;
            session.lock().await.pi_session_id = Some(pi_session_id.clone());
        }
        // Best effort: the in-memory reference is authoritative for the
        // supervisor; a store failure here must not kill the session.
        let _ = self
            .supervisor
            .inner
            .store
            .update_pi_reference(&self.id, &pi_session_id);
        Ok(pi_session_id)
    }

    /// Restart the session's Pi child with FRESH authority: the old
    /// child's leases are revoked kernel-side and the old identity
    /// secret is destroyed before the new child spawns. The session id
    /// and subject are stable across restarts (the subject is
    /// session-id-derived in phase 3; the Courier identity that will
    /// make rotation meaningful lands in phase 4); freshness comes from
    /// the rotated secret and the revocation of every outstanding lease
    /// for that subject.
    ///
    /// The restarted session is `Running`. Terminal sessions cannot be
    /// restarted.
    pub async fn restart(&self) -> Result<RestartReport, SupervisorError> {
        let inner = Arc::clone(&self.supervisor.inner);
        // 1. Detach the old child under the lock; bump the generation so
        //    the old child's monitor/readers can never fault the session.
        let (old_child, old_subject, generation) = {
            let session = inner.session(&self.id).await?;
            let mut guard = session.lock().await;
            if matches!(guard.status, SessionStatus::Terminated) {
                return Err(SupervisorError::NotRestartable(guard.status.clone()));
            }
            guard.generation += 1;
            let generation = guard.generation;
            guard.shutdown_tx.take();
            let old_child = guard.child.take();
            let old_subject = guard.binding.session_subject.clone();
            guard.malformed_count = 0;
            guard.pi_session_id = None;
            guard.last_activity = Instant::now();
            guard.created_at = Instant::now();
            (old_child, old_subject, generation)
        };

        // 2. Kill and reap the old child (bounded; no zombies).
        if let Some(old_child) = old_child {
            SessionSupervisor::kill_and_reap(&old_child).await;
        }

        // 3. Destroy the old identity through the vault FIRST, then revoke
        //    leases for every affected subject (parent + descendants).
        //    Fail closed: if the vault cannot destroy or the kernel cannot
        //    revoke, the old generation's authority may still be live —
        //    fault the session and abort before any new authority is
        //    minted.
        let end_report = inner
            .kernel
            .destroy_session_identity(&old_subject)
            .await
            .map_err(|e| {
                let reason = format!("vault destroy failed; restart aborted: {e}");
                reason.clone()
            });
        let end_report = match end_report {
            Ok(report) => report,
            Err(reason) => {
                inner
                    .fault_session(
                        &self.id,
                        FaultKind::RestartFailed {
                            reason: reason.clone(),
                        },
                    )
                    .await;
                return Err(SupervisorError::SpawnFailed(reason));
            }
        };
        for affected in &end_report.affected_subjects {
            if let Err(e) = inner.kernel.revoke_session(affected).await {
                let reason = format!("lease revocation failed; restart aborted: {e}");
                inner
                    .fault_session(
                        &self.id,
                        FaultKind::RestartFailed {
                            reason: reason.clone(),
                        },
                    )
                    .await;
                return Err(SupervisorError::SpawnFailed(reason));
            }
        }

        // 4. Mint a fresh vault identity. The session id stays stable; the
        //    new `ed25519:` subject and the revocation above are what make
        //    the new generation's authority fresh. A mint failure faults
        //    the session: the old identity is destroyed and the new one
        //    was never created, so the session cannot continue.
        let (binding, fingerprint) = {
            let identity = match inner.kernel.start_session_identity(None).await {
                Ok(identity) => identity,
                Err(e) => {
                    let reason = format!("vault mint failed; restart aborted: {e}");
                    inner
                        .fault_session(
                            &self.id,
                            FaultKind::RestartFailed {
                                reason: reason.clone(),
                            },
                        )
                        .await;
                    return Err(SupervisorError::SpawnFailed(reason));
                }
            };
            let fingerprint = identity.verifying_key_hex.clone();
            let session = inner.session(&self.id).await?;
            let mut guard = session.lock().await;
            guard.binding = SessionBinding {
                session_id: guard.id.to_string(),
                account_id: guard.binding.account_id.clone(),
                session_subject: identity.subject.clone(),
            };
            guard.identity_fingerprint = Some(fingerprint.clone());
            (guard.binding.clone(), fingerprint)
        };

        // 5. Rotate the kernel channel credential: the old child's
        //    credential dies with the old generation and is unregistered
        //    before the new child spawns, so it can never authenticate
        //    the new generation's channel. A mint failure faults the
        //    session: without a credential the new child cannot be
        //    distinguished from the old generation.
        inner.revoke_channel_credential(&self.id);
        let new_channel_credential = match inner.mint_channel_credential(&self.id) {
            Ok(credential) => credential,
            Err(e) => {
                let reason = format!("channel credential mint failed; restart aborted: {e}");
                inner
                    .fault_session(
                        &self.id,
                        FaultKind::RestartFailed {
                            reason: reason.clone(),
                        },
                    )
                    .await;
                return Err(SupervisorError::SpawnFailed(reason));
            }
        };
        // 6. Spawn the replacement child.
        let (cmd_tx, cmd_rx) = mpsc::channel::<Vec<u8>>(inner.config.outbound_queue_depth);
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let new_child_result = {
            let session = inner.session(&self.id).await?;
            let mut guard = session.lock().await;
            guard.channel_credential = new_channel_credential;
            // Fresh exit notification for the new generation, installed
            // before start_child spawns the new monitor: the old
            // generation's monitor may have stored a `notify_one`
            // permit on the previous Notify, and a stale permit would
            // make a later terminate skip its kill step.
            guard.exit_notified = Arc::new(tokio::sync::Notify::new());
            let channel = match (
                inner.config.channel_socket_path.as_deref(),
                guard.channel_credential.as_ref(),
            ) {
                (Some(socket_path), Some(credential)) => Some(ChannelLaunch {
                    socket_path,
                    nonce_hex: credential.hex(),
                }),
                _ => None,
            };
            SessionSupervisor::start_child(
                &inner,
                self.id,
                generation,
                &binding.session_subject,
                channel.as_ref(),
                cmd_rx,
                shutdown_rx,
            )
        };
        let new_child = match new_child_result {
            Ok(child) => child,
            Err(e) => {
                let reason = e.to_string();
                inner
                    .fault_session(&self.id, FaultKind::RestartFailed { reason })
                    .await;
                return Err(e);
            }
        };
        {
            let session = inner.session(&self.id).await?;
            let mut guard = session.lock().await;
            guard.child = Some(new_child);
            guard.cmd_tx = cmd_tx;
            guard.shutdown_tx = Some(shutdown_tx);
            guard.status = SessionStatus::Running;
            let id = guard.id;
            let status = guard.status.clone();
            drop(guard);
            let _ = inner.store.update_status(&id, status, None);
        }

        // 7. Re-acquire Pi's session reference for the new child.
        if let Err(e) = self.refresh_pi_reference().await {
            let reason = e.to_string();
            inner
                .fault_session(&self.id, FaultKind::RestartFailed { reason })
                .await;
            return Err(e);
        }

        // 8. Persist the refreshed reference (upsert).
        let session_ref = {
            let session = inner.session(&self.id).await?;
            let guard = session.lock().await;
            SessionRef {
                session_id: guard.id,
                owner_account_id: guard.binding.account_id.as_str().to_string(),
                session_subject: binding.session_subject.clone(),
                identity_fingerprint: fingerprint,
                pi_session_id: guard.pi_session_id.clone(),
                pi_version: inner.config.pi_version.clone(),
                status: SessionStatus::Running,
                created_at_ms: now_ms(),
                ended_at_ms: None,
            }
        };
        if let Err(e) = inner.store.save(&session_ref) {
            let reason = format!("store save failed after restart: {e}");
            inner
                .fault_session(
                    &self.id,
                    FaultKind::RestartFailed {
                        reason: reason.clone(),
                    },
                )
                .await;
            return Err(SupervisorError::Store(e));
        }
        Ok(RestartReport {
            session_id: self.id,
            // Revocation failure aborts the restart before this point
            // (fail closed), so reaching here means the old leases were
            // revoked.
            leases_revoked: true,
            revoke_error: None,
        })
    }

    /// Last stderr lines from the child (diagnostics only, never protocol).
    pub async fn stderr_tail(&self) -> Result<Vec<String>, SupervisorError> {
        let session = self.supervisor.inner.session(&self.id).await?;
        Ok(session.lock().await.stderr_tail.iter().cloned().collect())
    }
}

/// Verify a pinned file digest. An empty expected digest is a
/// configuration error: pins are mandatory, never optional.
fn verify_pin(path: &Path, expected_hex: &str) -> Result<(), String> {
    if expected_hex.trim().is_empty() {
        return Err(format!("no digest pinned for {}", path.display()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let actual = sha256_hex(&bytes);
    if actual != expected_hex.trim().to_lowercase() {
        return Err(format!(
            "digest mismatch for {}: expected {expected_hex}, got {actual}",
            path.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests (subprocess-backed)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authd::{AccountIdentity, AuthdClient, MockAuthdClient};
    use crate::kernel_client::MockKernelClient;
    use crate::tool_catalog::default_catalog;

    /// Path to the fake-Pi fixture script.
    fn fixture_script() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("fake-pi.sh")
    }

    fn test_config_with_mode(mode: Option<&str>) -> SupervisorConfig {
        let script = fixture_script();
        let digest = sha256_hex(&std::fs::read(&script).unwrap());
        let mut pi_args = Vec::new();
        if let Some(mode) = mode {
            pi_args.push(mode.to_string());
        }
        SupervisorConfig {
            pi_binary: script.clone(),
            pi_args,
            pi_version: "fake-0.0.0".to_string(),
            pi_digest: digest.clone(),
            extension_path: script.clone(),
            extension_digest: digest,
            outbound_queue_depth: 8,
            max_line_bytes: 4096,
            malformed_threshold: 3,
            idle_timeout: Duration::from_secs(3600),
            max_lifetime: Duration::from_secs(3600),
            shutdown_grace: Duration::from_secs(2),
            watchdog_interval: Duration::from_millis(50),
            event_buffer: 64,
            stderr_line_cap: 16,
            ..SupervisorConfig::default()
        }
    }

    fn test_config() -> SupervisorConfig {
        test_config_with_mode(None)
    }

    fn supervisor(config: SupervisorConfig) -> (SessionSupervisor, Arc<MockKernelClient>) {
        let kernel = Arc::new(MockKernelClient::new());
        let supervisor = SessionSupervisor::new(
            config,
            kernel.clone(),
            Arc::new(default_catalog()),
            Arc::new(MemorySessionStore::new()),
        );
        (supervisor, kernel)
    }

    async fn owner() -> AccountIdentity {
        let authd = MockAuthdClient::new().with_token("tok", "acct-test");
        // Resolve through the mock to prove the wiring, not the constructor.
        authd.authenticate("tok").await.unwrap()
    }

    /// Store decorator that counts `save` calls: a failed spawn must
    /// never persist a `Running` reference.
    struct CountingStore {
        inner: MemorySessionStore,
        saves: std::sync::atomic::AtomicUsize,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                inner: MemorySessionStore::new(),
                saves: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn saves(&self) -> usize {
            self.saves.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SessionStore for CountingStore {
        fn save(&self, session_ref: &SessionRef) -> Result<(), StoreError> {
            self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.save(session_ref)
        }

        fn get(&self, id: &SessionId) -> Result<Option<SessionRef>, StoreError> {
            self.inner.get(id)
        }

        fn update_status(
            &self,
            id: &SessionId,
            status: SessionStatus,
            ended_at_ms: Option<i64>,
        ) -> Result<(), StoreError> {
            self.inner.update_status(id, status, ended_at_ms)
        }

        fn list_by_owner(&self, owner_account_id: &str) -> Result<Vec<SessionRef>, StoreError> {
            self.inner.list_by_owner(owner_account_id)
        }

        fn update_pi_reference(
            &self,
            id: &SessionId,
            pi_session_id: &str,
        ) -> Result<(), StoreError> {
            self.inner.update_pi_reference(id, pi_session_id)
        }
    }

    async fn wait_for_interrupted(handle: &SessionHandle, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            match handle.status().await.unwrap() {
                SessionStatus::Interrupted { reason } => return reason,
                SessionStatus::Terminated => panic!("session terminated instead of interrupted"),
                _ => {}
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for interruption");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn spawn_prompt_pause_resume_terminate() {
        let (supervisor, _kernel) = supervisor(test_config());
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        assert_eq!(handle.status().await.unwrap(), SessionStatus::Running);

        let mut events = handle.subscribe().await.unwrap();
        handle.prompt("hello").await.unwrap();
        // The fake Pi answers with message_end + agent_settled.
        let mut saw_settled = false;
        let deadline = Instant::now() + Duration::from_secs(5);
        while !saw_settled && Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_secs(1), events.recv()).await {
                Ok(Ok(SupervisorEvent {
                    event: PiEvent::AgentSettled,
                    ..
                })) => saw_settled = true,
                Ok(Ok(_)) => {}
                _ => break,
            }
        }
        assert!(saw_settled, "expected agent_settled from fake Pi");

        handle.pause().await.unwrap();
        assert_eq!(handle.status().await.unwrap(), SessionStatus::Paused);
        assert!(matches!(
            handle.prompt("nope").await,
            Err(SupervisorError::NotRunning(_))
        ));

        handle.resume().await.unwrap();
        assert_eq!(handle.status().await.unwrap(), SessionStatus::Running);

        let report = handle.terminate().await.unwrap();
        assert!(report.identity_destroyed);
        assert!(report.leases_revoked);
        assert_eq!(handle.status().await.unwrap(), SessionStatus::Terminated);
        // Idempotent.
        let report2 = handle.terminate().await.unwrap();
        assert!(report2.identity_destroyed);
    }

    #[tokio::test]
    async fn pin_mismatch_refuses_spawn() {
        let mut config = test_config();
        config.pi_digest = "0".repeat(64);
        let (supervisor, _) = supervisor(config);
        match supervisor.spawn_session_fixture(&owner().await).await {
            Err(SupervisorError::PinMismatch(_)) => {}
            other => panic!("expected PinMismatch, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn missing_pin_refuses_spawn() {
        let mut config = test_config();
        config.pi_digest = String::new();
        let (supervisor, _) = supervisor(config);
        match supervisor.spawn_session_fixture(&owner().await).await {
            Err(SupervisorError::PinMismatch(_)) => {}
            other => panic!("expected PinMismatch, got {:?}", other.map(|_| ())),
        }
    }

    #[tokio::test]
    async fn untrusted_tool_fails_session_closed() {
        let (supervisor, _) = supervisor(test_config_with_mode(Some("evil")));
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let reason = wait_for_interrupted(&handle, Duration::from_secs(5)).await;
        assert!(
            reason.contains("untrusted tool executed: bash"),
            "unexpected reason: {reason}"
        );
        // The session reference persists the interruption for audit.
        supervisor.forget(&handle.id()).await.unwrap_err();
    }

    #[tokio::test]
    async fn malformed_stream_fails_closed_after_threshold() {
        let (supervisor, _) = supervisor(test_config_with_mode(Some("garbage")));
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let reason = wait_for_interrupted(&handle, Duration::from_secs(5)).await;
        assert!(reason.contains("malformed"), "unexpected reason: {reason}");
    }

    #[tokio::test]
    async fn output_flood_fails_closed_without_truncation() {
        let (supervisor, _) = supervisor(test_config_with_mode(Some("flood")));
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let reason = wait_for_interrupted(&handle, Duration::from_secs(5)).await;
        assert!(
            reason.contains("output flood"),
            "unexpected reason: {reason}"
        );
    }

    #[tokio::test]
    async fn child_exit_before_reference_fails_spawn() {
        // exit-fast dies before get_state can be answered: the spawn
        // fails instead of leaving an unreferenceable session.
        let store = Arc::new(CountingStore::new());
        let kernel = Arc::new(MockKernelClient::new());
        let supervisor = SessionSupervisor::new(
            test_config_with_mode(Some("exit-fast")),
            kernel,
            Arc::new(default_catalog()),
            store.clone(),
        );
        supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap_err();
        assert_eq!(store.saves(), 0);
        assert!(store.list_by_owner("acct-test").unwrap().is_empty());
        assert!(supervisor.list_sessions().is_empty());
    }

    #[tokio::test]
    async fn unexpected_child_exit_interrupts_without_retry() {
        let (supervisor, _) = supervisor(test_config_with_mode(Some("exit-slow")));
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let reason = wait_for_interrupted(&handle, Duration::from_secs(5)).await;
        assert!(
            reason.contains("child exited"),
            "unexpected reason: {reason}"
        );
    }

    #[tokio::test]
    async fn session_reference_persisted_separately() {
        let store = Arc::new(MemorySessionStore::new());
        let kernel = Arc::new(MockKernelClient::new());
        let supervisor = SessionSupervisor::new(
            test_config(),
            kernel,
            Arc::new(default_catalog()),
            store.clone(),
        );
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let session_ref = store.get(&handle.id()).unwrap().unwrap();
        assert_eq!(session_ref.owner_account_id, "acct-test");
        assert_eq!(session_ref.status, SessionStatus::Running);
        assert!(!session_ref.identity_fingerprint.is_empty());
        // Pi's own reference is populated from get_state and persisted
        // separately from authority material.
        assert!(session_ref.pi_session_id.is_some());
        assert_eq!(
            handle.pi_session_id().await.unwrap(),
            session_ref.pi_session_id
        );
        // The reference carries no authority material: serialize it and
        // assert nothing lease-shaped is present.
        let serialized = serde_json::to_string(&session_ref).unwrap();
        assert!(!serialized.contains("lease"));
        handle.terminate().await.unwrap();
        let session_ref = store.get(&handle.id()).unwrap().unwrap();
        assert_eq!(session_ref.status, SessionStatus::Terminated);
        assert!(session_ref.ended_at_ms.is_some());
    }

    #[tokio::test]
    async fn restart_replaces_authority_and_revokes_old_leases() {
        let store = Arc::new(MemorySessionStore::new());
        let kernel = Arc::new(MockKernelClient::new());
        let supervisor = SessionSupervisor::new(
            test_config(),
            kernel.clone(),
            Arc::new(default_catalog()),
            store.clone(),
        );
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let old_binding = handle.binding().await.unwrap();
        let old_pi_ref = handle.pi_session_id().await.unwrap();
        let old_fingerprint = store
            .get(&handle.id())
            .unwrap()
            .unwrap()
            .identity_fingerprint;

        let report = handle.restart().await.unwrap();
        assert_eq!(report.session_id, handle.id());
        assert!(report.leases_revoked);
        assert!(report.revoke_error.is_none());

        // Fresh authority: the vault identity is destroyed and a new one
        // minted (new subject + fingerprint), and the old generation's
        // leases were revoked. The subject CHANGES: restart mints a fresh
        // `ed25519:` identity; the old subject is dead.
        let new_binding = handle.binding().await.unwrap();
        assert_eq!(new_binding.session_id, old_binding.session_id);
        assert_eq!(new_binding.account_id, old_binding.account_id);
        assert_ne!(
            new_binding.session_subject, old_binding.session_subject,
            "restart must mint a fresh vault identity"
        );
        assert!(
            new_binding.session_subject.starts_with("ed25519:"),
            "new subject must be a vault identity"
        );
        assert!(
            kernel
                .revoked_subjects()
                .contains(&old_binding.session_subject)
        );
        assert_eq!(handle.status().await.unwrap(), SessionStatus::Running);
        // Pi reference re-acquired for the new child and persisted.
        let new_pi_ref = handle.pi_session_id().await.unwrap();
        assert!(new_pi_ref.is_some());
        assert_ne!(old_pi_ref, None);
        let session_ref = store.get(&handle.id()).unwrap().unwrap();
        assert_eq!(session_ref.session_subject, new_binding.session_subject);
        assert_eq!(session_ref.pi_session_id, new_pi_ref);
        // The identity secret rotated: the fingerprint changed.
        assert_ne!(session_ref.identity_fingerprint, old_fingerprint);

        // The restarted session still supervises: a fast-exiting child
        // after restart is an interruption, tested via a fresh spawn.
        handle.terminate().await.unwrap();
    }

    #[tokio::test]
    async fn restart_aborts_when_revocation_fails() {
        let (supervisor, kernel) = supervisor(test_config());
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        let subject = handle.binding().await.unwrap().session_subject;
        assert!(handle.pi_session_id().await.unwrap().is_some());

        // The kernel cannot revoke: restart must fail closed -- fault
        // the session before any new authority is minted, never spawn
        // a replacement child onto a subject with stale leases.
        kernel.fail_revoke(true);
        let err = handle.restart().await.unwrap_err();
        assert!(err.to_string().contains("revocation failed"), "got: {err}");

        match handle.status().await.unwrap() {
            SessionStatus::Interrupted { reason } => {
                assert!(reason.contains("revocation failed"), "got: {reason}");
            }
            other => panic!("expected Interrupted, got {other:?}"),
        }
        // No replacement child was spawned: no Pi reference was
        // re-acquired for a new generation.
        assert_eq!(handle.pi_session_id().await.unwrap(), None);
        // The failed revoke left no revocation record behind.
        assert!(!kernel.revoked_subjects().contains(&subject));

        kernel.fail_revoke(false);
        handle.terminate().await.unwrap();
    }

    #[tokio::test]
    async fn terminate_retries_after_revoke_failure() {
        let (supervisor, kernel) = supervisor(test_config());
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();

        // First attempt: lease revocation fails. Termination must surface
        // the failure, not claim success.
        kernel.fail_revoke(true);
        let err = handle
            .terminate()
            .await
            .expect_err("revoke failure must fail terminate");
        assert!(
            matches!(err, SupervisorError::TerminateFailed(_)),
            "unexpected error: {err:?}"
        );
        assert!(matches!(
            handle.status().await.unwrap(),
            SessionStatus::Interrupted { .. }
        ));
        assert!(
            kernel.revoked_subjects().is_empty(),
            "failed revocation must not record subjects"
        );

        // Second attempt: the incomplete termination is retried for real
        // and completes. (The old code returned a success report here
        // without revoking anything.)
        kernel.fail_revoke(false);
        let report = handle.terminate().await.unwrap();
        assert!(report.identity_destroyed);
        assert!(report.leases_revoked);
        assert_eq!(handle.status().await.unwrap(), SessionStatus::Terminated);
        assert!(
            !kernel.revoked_subjects().is_empty(),
            "retry must actually revoke"
        );
    }

    #[tokio::test]
    async fn restart_of_terminated_session_is_rejected() {
        let (supervisor, _kernel) = supervisor(test_config());
        let handle = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap();
        handle.terminate().await.unwrap();
        assert!(matches!(
            handle.restart().await,
            Err(SupervisorError::NotRestartable(SessionStatus::Terminated))
        ));
    }

    #[tokio::test]
    async fn spawn_fails_when_pi_reports_no_reference() {
        // The "no-state" fixture never answers get_state: the spawn
        // must fail rather than leave an unreferenceable session.
        let mut config = test_config_with_mode(Some("no-state"));
        config.rpc_timeout = Duration::from_millis(300);
        let store = Arc::new(CountingStore::new());
        let kernel = Arc::new(MockKernelClient::new());
        let supervisor =
            SessionSupervisor::new(config, kernel, Arc::new(default_catalog()), store.clone());
        let err = supervisor
            .spawn_session_fixture(&owner().await)
            .await
            .unwrap_err();
        assert!(
            matches!(err, SupervisorError::RpcTimeout(_)),
            "unexpected error: {err:?}"
        );
        // No Running reference was ever persisted, and no in-memory
        // session survives the failure.
        assert_eq!(store.saves(), 0);
        assert!(store.list_by_owner("acct-test").unwrap().is_empty());
        assert!(supervisor.list_sessions().is_empty());
    }

    #[test]
    fn pi_event_parsing_is_strict_on_kind() {
        // Wire format is camelCase fields (Pi's RPC convention).
        let event = parse_pi_event(
            r#"{"type":"tool_execution_start","toolCallId":"c1","toolName":"bct.fs.read","args":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            event,
            PiEvent::ToolExecutionStart { ref tool_name, .. } if tool_name == "bct.fs.read"
        ));
        // snake_case fields are NOT accepted: the wire shape is pinned.
        assert!(matches!(
            parse_pi_event(
                r#"{"type":"tool_execution_start","tool_call_id":"c1","tool_name":"bct.fs.read"}"#
            ),
            Err(PiEventError::Malformed(_))
        ));
        assert!(matches!(
            parse_pi_event(r#"{"type":"nope"}"#),
            Err(PiEventError::UnknownKind)
        ));
        assert!(matches!(
            parse_pi_event(r#"{"type":"tool_execution_start"}"#),
            Err(PiEventError::Malformed(_))
        ));
        // Unknown *fields* are tolerated; unknown *kinds* are not.
        let event = parse_pi_event(r#"{"type":"agent_start","future_field":123}"#).unwrap();
        assert!(matches!(event, PiEvent::AgentStart));
    }

    #[test]
    fn pi_commands_use_pi_rpc_wire_shape() {
        // Pi's RPC shape is `{ "command": "<name>", ... }`, not a
        // `type`-tagged envelope.
        let bytes = encode_command(&PiCommand::Prompt {
            id: "1".to_string(),
            message: "hi".to_string(),
        });
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["command"], "prompt");
        assert_eq!(value["message"], "hi");
        assert!(value.get("type").is_none());

        let bytes = encode_command(&PiCommand::GetState {
            id: "2".to_string(),
        });
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["command"], "get_state");

        let bytes = encode_command(&PiCommand::Abort);
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["command"], "abort");
    }
}
