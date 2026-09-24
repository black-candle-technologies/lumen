//! Phase-0 architecture spike: Pi RPC subprocess supervisor.
//!
//! The supervisor launches Pi as a long-lived `--mode rpc` subprocess,
//! speaks strict JSONL on its stdin/stdout, and normalizes Pi's session
//! events onto the [`BridgeEvent`] vocabulary from
//! `lumen_core::pi_boundary`.
//!
//! Hardening properties (all observable in tests):
//! - Byte-oriented JSONL framing: split on LF only, strip one trailing CR,
//!   never treat Unicode separators as record boundaries.
//! - Output flood protection: any record longer than `max_line_bytes` kills
//!   the child and surfaces [`SupervisorEvent::LineTooLong`].
//! - Malformed records are reported as [`SupervisorEvent::MalformedLine`];
//!   past `max_consecutive_malformed`, the child is killed.
//! - Unexpected death triggers the [`RestartPolicy`] (bounded restarts with
//!   backoff); exhaustion surfaces [`SupervisorEvent::Exited`] with
//!   `restarted: false`.
//! - Command/response correlation by id; responses for unknown ids are
//!   dropped loudly via [`SupervisorEvent::StreamIssue`].
//!
//! The supervisor never issues effectful RPC commands itself (no `bash`,
//! `export_html`, …): its public API only offers the read-only / lifecycle
//! commands Pi documents for RPC clients. Raw shell access through the RPC
//! channel is closed by construction, and the BCT extension additionally
//! blocks `user_bash` (see `lumen-integrations/bct-pi-extension`).

use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use lumen_core::pi_boundary::{BridgeEvent, PIBRIDGE_VERSION};
use serde_json::Value;
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{mpsc, oneshot},
    time::{sleep, timeout},
};
use uuid::Uuid;

/// Bounded restart behavior after unexpected child death.
#[derive(Clone, Debug)]
pub struct RestartPolicy {
    pub max_restarts: u32,
    pub base_backoff: Duration,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            base_backoff: Duration::from_millis(250),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PiSupervisorConfig {
    pub pi_binary: PathBuf,
    /// Full argv after the binary (e.g. `--mode rpc --no-session
    /// --no-builtin-tools --extension …`).
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub cwd: PathBuf,
    /// Kill the child when a single record exceeds this many bytes.
    pub max_line_bytes: usize,
    /// Kill the child after this many consecutive malformed records.
    pub max_consecutive_malformed: u32,
    pub restart: RestartPolicy,
}

impl Default for PiSupervisorConfig {
    fn default() -> Self {
        Self {
            pi_binary: PathBuf::from("pi"),
            args: vec![
                "--mode".to_string(),
                "rpc".to_string(),
                "--no-session".to_string(),
                "--no-builtin-tools".to_string(),
            ],
            env: Vec::new(),
            cwd: PathBuf::from("."),
            max_line_bytes: 8 * 1024 * 1024,
            max_consecutive_malformed: 50,
            restart: RestartPolicy::default(),
        }
    }
}

impl PiSupervisorConfig {
    /// Fail closed: the supervisor will not launch Pi with effectful
    /// built-in tools (`bash`, `read`, `write`, `edit`, …). Callers that
    /// override `args` must keep `--no-builtin-tools`.
    fn validate(&self) -> Result<(), SupervisorError> {
        if !self.args.iter().any(|a| a == "--no-builtin-tools") {
            return Err(SupervisorError::Config(
                "refusing to spawn pi without --no-builtin-tools".to_string(),
            ));
        }
        Ok(())
    }
}

/// One correlated RPC command response.
#[derive(Clone, Debug)]
pub struct PiResponse {
    pub id: Option<String>,
    pub command: String,
    pub success: bool,
    pub data: Option<Value>,
    pub error: Option<String>,
}

/// Events produced by the supervisor.
#[derive(Clone, Debug)]
pub enum SupervisorEvent {
    /// A `type: "response"` record, correlated by id.
    Response(PiResponse),
    /// A normalized PiBridge session event.
    Bridge(BridgeEvent),
    /// A record that was not valid JSON.
    MalformedLine { line_number: u64, bytes: usize },
    /// A record that exceeded `max_line_bytes`; the child was killed.
    LineTooLong { line_number: u64, bytes: usize },
    /// The child died unexpectedly and is being restarted.
    Restarting { attempt: u32, reason: String },
    /// The child exited and will not be restarted.
    Exited { code: Option<i32>, restarted: bool },
    /// The stdout reader reached EOF. Carries the reader generation so stale
    /// events from a previous child incarnation can be ignored.
    StreamEnded { generation: u64 },
    /// The supervisor itself hit a fatal condition.
    Fatal(String),
}

#[derive(Clone, Debug, Error)]
pub enum SupervisorError {
    #[error("failed to spawn pi: {0}")]
    Spawn(String),
    #[error("pi stdin is closed")]
    StdinClosed,
    #[error("io error: {0}")]
    Io(String),
    #[error("timed out waiting for {0}")]
    Timeout(String),
    #[error("no response arrived for command {0}")]
    NoResponse(String),
    #[error("supervisor is stopped")]
    Stopped,
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("refused by boundary policy: {0}")]
    Config(String),
}

/// The complete allowlist of RPC commands the supervisor may send.
///
/// Pi's RPC surface includes effectful commands the supervisor MUST NEVER
/// send: `bash` (raw shell), `export_html` (arbitrary file write), and
/// anything that changes providers, models, session state, or the tool set.
/// Those commands have no variant here and no public sender: the type system
/// plus `send_command`'s privacy makes sending one unrepresentable.
/// `SupervisorCommand::from_raw` exists only so tests can prove a hostile
/// caller string cannot be smuggled in.
#[derive(Debug, Clone)]
enum SupervisorCommand {
    /// `{ "command": "prompt", "message": ... }`
    Prompt { message: serde_json::Value },
    /// `{ "command": "get_state" }`
    GetState,
    /// `{ "command": "abort" }`
    Abort,
}

impl SupervisorCommand {
    /// Parse a caller-supplied command name. Only the safe allowlist parses;
    /// everything else — including `bash` and `export_html` — is rejected.
    /// `pub(crate)` so the boundary test can prove the rejection.
    pub(crate) fn from_raw(name: &str) -> Result<Self, SupervisorError> {
        match name {
            "get_state" => Ok(SupervisorCommand::GetState),
            "abort" => Ok(SupervisorCommand::Abort),
            other => Err(SupervisorError::Config(format!(
                "RPC command '{other}' is not on the supervisor allowlist and is rejected"
            ))),
        }
    }

    fn name(&self) -> &'static str {
        match self {
            SupervisorCommand::Prompt { .. } => "prompt",
            SupervisorCommand::GetState => "get_state",
            SupervisorCommand::Abort => "abort",
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            SupervisorCommand::Prompt { message } => {
                serde_json::json!({ "command": "prompt", "message": message })
            }
            SupervisorCommand::GetState => serde_json::json!({ "command": "get_state" }),
            SupervisorCommand::Abort => serde_json::json!({ "command": "abort" }),
        }
    }
}

struct ChildHandles {
    child: Child,
    stdin: ChildStdin,
    reader: tokio::task::JoinHandle<()>,
}

pub struct PiSupervisor {
    config: PiSupervisorConfig,
    child: Option<ChildHandles>,
    /// Reader generation: incremented on every (re)spawn so stale
    /// `StreamEnded` events from a previous child are ignored.
    generation: u64,
    events: mpsc::UnboundedReceiver<SupervisorEvent>,
    events_tx: mpsc::UnboundedSender<SupervisorEvent>,
    pending: HashMap<String, oneshot::Sender<PiResponse>>,
    queued: VecDeque<SupervisorEvent>,
    restarts: u32,
    stopped: bool,
}

impl PiSupervisor {
    pub async fn spawn(config: PiSupervisorConfig) -> Result<Self, SupervisorError> {
        config.validate()?;
        let (events_tx, events) = mpsc::unbounded_channel();
        let mut supervisor = Self {
            config,
            child: None,
            generation: 0,
            events,
            events_tx,
            pending: HashMap::new(),
            queued: VecDeque::new(),
            restarts: 0,
            stopped: false,
        };
        supervisor.spawn_child().await?;
        Ok(supervisor)
    }

    fn pi_binary(&self) -> &Path {
        &self.config.pi_binary
    }

    async fn spawn_child(&mut self) -> Result<(), SupervisorError> {
        let mut command = Command::new(self.pi_binary());
        command
            .args(&self.config.args)
            .envs(self.config.env.iter().cloned())
            .current_dir(&self.config.cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|e| SupervisorError::Spawn(format!("{}: {e}", self.pi_binary().display())))?;
        let stdin = child.stdin.take().ok_or(SupervisorError::StdinClosed)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| SupervisorError::Spawn("pi stdout was not captured".to_string()))?;
        // Drain stderr so a chatty child can never block on a full pipe.
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(async move {
                let mut reader = BufReader::new(stderr);
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line).await {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                }
            });
        }
        let events_tx = self.events_tx.clone();
        let max_line_bytes = self.config.max_line_bytes;
        let max_malformed = self.config.max_consecutive_malformed;
        let generation = self.generation;
        let reader = tokio::spawn(async move {
            read_loop(stdout, events_tx, max_line_bytes, max_malformed, generation).await;
        });
        self.child = Some(ChildHandles {
            child,
            stdin,
            reader,
        });
        Ok(())
    }

    /// Send one allowlisted command record. A unique id is assigned when the
    /// payload lacks one. Returns the id used.
    ///
    /// Private: callers use [`PiSupervisor::prompt`], [`PiSupervisor::get_state`],
    /// or [`PiSupervisor::abort`]. There is no public path that can send an
    /// effectful RPC command (`bash`, `export_html`, …).
    async fn send_command(
        &mut self,
        command: SupervisorCommand,
    ) -> Result<String, SupervisorError> {
        if self.stopped {
            return Err(SupervisorError::Stopped);
        }
        let mut fields = match command.to_json() {
            Value::Object(map) => map,
            _ => unreachable!("SupervisorCommand::to_json always builds an object"),
        };
        let id = format!("cmd-{}", Uuid::new_v4());
        fields.insert("id".to_string(), Value::String(id.clone()));
        fields.insert(
            "type".to_string(),
            Value::String(command.name().to_string()),
        );
        let mut bytes = serde_json::to_vec(&Value::Object(fields))
            .map_err(|e| SupervisorError::Serialization(e.to_string()))?;
        bytes.push(b'\n');
        let handles = self.child.as_mut().ok_or(SupervisorError::Stopped)?;
        handles
            .stdin
            .write_all(&bytes)
            .await
            .map_err(|e| SupervisorError::Io(format!("write to pi stdin: {e}")))?;
        handles
            .stdin
            .flush()
            .await
            .map_err(|e| SupervisorError::Io(format!("flush pi stdin: {e}")))?;
        Ok(id)
    }

    /// Send an allowlisted command and wait for its correlated response.
    async fn round_trip(
        &mut self,
        command: SupervisorCommand,
        await_timeout: Duration,
    ) -> Result<PiResponse, SupervisorError> {
        let name = command.name();
        let (tx, mut rx) = oneshot::channel();
        let id = self.send_command(command).await?;
        self.pending.insert(id.clone(), tx);
        // Drive the event loop while waiting; correlation in next_event
        // routes other commands' responses to their own waiters.
        timeout(await_timeout, async {
            loop {
                tokio::select! {
                    biased;
                    result = &mut rx => {
                        return result.map_err(|_| SupervisorError::NoResponse(id.clone()));
                    }
                    event = self.next_event() => {
                        match event {
                            Some(_) => continue,
                            None => return Err(SupervisorError::Stopped),
                        }
                    }
                }
            }
        })
        .await
        .map_err(|_| SupervisorError::Timeout(format!("response to {name}")))?
    }

    /// Send a user/model turn to Pi and wait for the correlated response.
    pub async fn prompt(
        &mut self,
        message: serde_json::Value,
        await_timeout: Duration,
    ) -> Result<PiResponse, SupervisorError> {
        self.round_trip(SupervisorCommand::Prompt { message }, await_timeout)
            .await
    }

    /// Ask Pi for its current session state (read-only).
    pub async fn get_state(
        &mut self,
        await_timeout: Duration,
    ) -> Result<PiResponse, SupervisorError> {
        self.round_trip(SupervisorCommand::GetState, await_timeout)
            .await
    }

    /// Abort the in-flight agent turn (control-plane only).
    pub async fn abort(&mut self, await_timeout: Duration) -> Result<PiResponse, SupervisorError> {
        self.round_trip(SupervisorCommand::Abort, await_timeout)
            .await
    }

    /// Next supervisor event, handling child death and restart internally.
    /// Returns `None` only when the supervisor is permanently stopped.
    pub async fn next_event(&mut self) -> Option<SupervisorEvent> {
        if let Some(event) = self.queued.pop_front() {
            return Some(event);
        }
        loop {
            // Reap the child if it exited.
            if let Some(handles) = self.child.as_mut() {
                match handles.child.try_wait() {
                    Ok(Some(status)) => {
                        let code = status.code();
                        return Some(self.handle_exit(code).await);
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.stopped = true;
                        self.kill_child().await;
                        return Some(SupervisorEvent::Fatal(format!(
                            "failed to poll pi child: {e}"
                        )));
                    }
                }
            }
            if self.stopped && self.child.is_none() {
                return None;
            }
            match self.events.recv().await {
                Some(SupervisorEvent::Response(response)) => {
                    if let Some(id) = response.id.clone() {
                        if let Some(tx) = self.pending.remove(&id) {
                            let _ = tx.send(response.clone());
                        }
                    }
                    return Some(SupervisorEvent::Response(response));
                }
                Some(SupervisorEvent::LineTooLong { line_number, bytes }) => {
                    // Flood: kill the child observably, then report the
                    // restart verdict as the *next* event so both are visible.
                    self.kill_child().await;
                    self.generation += 1;
                    let verdict = if self.restarts < self.config.restart.max_restarts {
                        self.restarts += 1;
                        let reason = format!("output flood: record {line_number} exceeded limit");
                        self.restart_child(&reason).await;
                        SupervisorEvent::Restarting {
                            attempt: self.restarts,
                            reason,
                        }
                    } else {
                        self.stopped = true;
                        SupervisorEvent::Exited {
                            code: None,
                            restarted: false,
                        }
                    };
                    self.queued.push_back(verdict);
                    return Some(SupervisorEvent::LineTooLong { line_number, bytes });
                }
                Some(SupervisorEvent::Fatal(detail)) => {
                    self.kill_child().await;
                    self.stopped = true;
                    return Some(SupervisorEvent::Fatal(detail));
                }
                Some(SupervisorEvent::StreamEnded { generation }) => {
                    if generation != self.generation {
                        // Stale: from a previous child incarnation. Ignore.
                        continue;
                    }
                    // EOF on stdout can precede process teardown (a child
                    // may close stdout before it finishes exiting), so wait
                    // for the real exit instead of assuming a live child is
                    // broken.
                    let code: Option<i32> = if let Some(handles) = self.child.as_mut() {
                        match timeout(Duration::from_secs(10), handles.child.wait()).await {
                            Ok(Ok(status)) => status.code(),
                            Ok(Err(_)) => None,
                            Err(_) => {
                                // Stdout hit EOF but the child would not exit:
                                // kill it so the supervisor cannot hang.
                                let _ = handles.child.kill().await;
                                None
                            }
                        }
                    } else {
                        None
                    };
                    return Some(self.handle_exit(code).await);
                }
                Some(event) => return Some(event),
                None => {
                    // Event channel closed: reader task ended. Check the child.
                    if let Some(handles) = self.child.as_mut() {
                        match handles.child.try_wait() {
                            Ok(Some(status)) => {
                                let code = status.code();
                                return Some(self.handle_exit(code).await);
                            }
                            _ => {}
                        }
                    }
                    if self.stopped {
                        return None;
                    }
                    // Reader died but the child lives on (should not happen);
                    // treat as fatal so the failure is observable.
                    self.kill_child().await;
                    self.stopped = true;
                    return Some(SupervisorEvent::Fatal(
                        "pi stdout reader ended while the child was alive".to_string(),
                    ));
                }
            }
        }
    }

    async fn handle_exit(&mut self, code: Option<i32>) -> SupervisorEvent {
        // Drain the old handles.
        if let Some(handles) = self.child.take() {
            handles.reader.abort();
        }
        self.pending.clear();
        // The next spawn gets a fresh generation so the dead reader's
        // StreamEnded (if it arrives late) is ignored as stale.
        self.generation += 1;
        if self.restarts < self.config.restart.max_restarts {
            self.restarts += 1;
            let reason = format!("pi exited with code {code:?}");
            self.restart_child(&reason).await;
            SupervisorEvent::Restarting {
                attempt: self.restarts,
                reason,
            }
        } else {
            self.stopped = true;
            SupervisorEvent::Exited {
                code,
                restarted: false,
            }
        }
    }

    async fn restart_child(&mut self, reason: &str) {
        let backoff = self.config.restart.base_backoff * self.restarts.max(1);
        sleep(backoff).await;
        match self.spawn_child().await {
            Ok(()) => {}
            Err(e) => {
                let _ = self.events_tx.send(SupervisorEvent::Fatal(format!(
                    "restart failed after {reason}: {e}"
                )));
                self.stopped = true;
            }
        }
    }

    async fn kill_child(&mut self) {
        if let Some(mut handles) = self.child.take() {
            let _ = handles.child.kill().await;
            handles.reader.abort();
        }
        self.pending.clear();
    }

    /// Wait until `agent_settled` arrives or the timeout elapses.
    pub async fn wait_settled(&mut self, await_timeout: Duration) -> Result<(), SupervisorError> {
        timeout(await_timeout, async {
            loop {
                match self.next_event().await {
                    Some(SupervisorEvent::Bridge(BridgeEvent::AgentSettled { .. })) => {
                        return Ok(());
                    }
                    Some(SupervisorEvent::Exited { .. }) | Some(SupervisorEvent::Fatal(_)) => {
                        return Err(SupervisorError::Stopped);
                    }
                    Some(_) => continue,
                    None => return Err(SupervisorError::Stopped),
                }
            }
        })
        .await
        .map_err(|_| SupervisorError::Timeout("agent_settled".to_string()))?
    }

    /// Orderly shutdown: close stdin, wait for exit, kill on timeout.
    pub async fn shutdown(mut self) -> Result<(), SupervisorError> {
        if let Some(mut handles) = self.child.take() {
            drop(handles.stdin);
            match timeout(Duration::from_secs(10), handles.child.wait()).await {
                Ok(Ok(_)) => {}
                _ => {
                    let _ = handles.child.kill().await;
                }
            }
            handles.reader.abort();
        }
        self.stopped = true;
        Ok(())
    }
}

/// Byte-oriented stdout reader. Splits strictly on LF, strips one trailing
/// CR, enforces the record size cap, and reports malformed records.
async fn read_loop(
    stdout: impl tokio::io::AsyncRead + Unpin,
    events_tx: mpsc::UnboundedSender<SupervisorEvent>,
    max_line_bytes: usize,
    max_malformed: u32,
    generation: u64,
) {
    let mut reader = BufReader::new(stdout);
    let mut line_number: u64 = 0;
    let mut malformed_streak: u32 = 0;
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        // Read one LF-terminated record without treating Unicode separators
        // as boundaries.
        let bytes_read = match read_until_lf(&mut reader, &mut buf, max_line_bytes).await {
            Ok(n) => n,
            Err(ReadRecordError::TooLong(n)) => {
                let _ = events_tx.send(SupervisorEvent::LineTooLong {
                    line_number: line_number + 1,
                    bytes: n,
                });
                return;
            }
            // An I/O error reading stdout is terminal for the stream: report
            // it as StreamEnded so the supervisor reaps/watches the child
            // instead of blocking on the event channel forever.
            Err(ReadRecordError::Io) => {
                let _ = events_tx.send(SupervisorEvent::StreamEnded { generation });
                return;
            }
        };
        if bytes_read == 0 {
            // EOF: the child closed stdout. Report it so the supervisor can
            // reap the child promptly instead of blocking on the event
            // channel.
            let _ = events_tx.send(SupervisorEvent::StreamEnded { generation });
            return;
        }
        line_number += 1;
        // Strip one trailing LF and one optional preceding CR.
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
        let record: Value = match serde_json::from_slice(&buf) {
            Ok(record) => record,
            Err(_) => {
                malformed_streak += 1;
                let _ = events_tx.send(SupervisorEvent::MalformedLine {
                    line_number,
                    bytes: bytes_read,
                });
                if malformed_streak >= max_malformed {
                    let _ = events_tx.send(SupervisorEvent::Fatal(format!(
                        "{malformed_streak} consecutive malformed records; giving up"
                    )));
                    return;
                }
                continue;
            }
        };
        malformed_streak = 0;
        dispatch_record(record, &events_tx);
    }
}

enum ReadRecordError {
    TooLong(usize),
    Io,
}

/// Read until LF (inclusive), stopping early when the cap is exceeded.
async fn read_until_lf(
    reader: &mut BufReader<impl tokio::io::AsyncRead + Unpin>,
    buf: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<usize, ReadRecordError> {
    use tokio::io::AsyncReadExt;
    let mut chunk = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut chunk)
            .await
            .map_err(|_| ReadRecordError::Io)?;
        if n == 0 {
            return Ok(buf.len());
        }
        for &byte in &chunk[..n] {
            buf.push(byte);
            if buf.len() > max_bytes {
                return Err(ReadRecordError::TooLong(buf.len()));
            }
            if byte == b'\n' {
                return Ok(buf.len());
            }
        }
    }
}

/// Map one Pi JSONL record onto supervisor events.
fn dispatch_record(record: Value, events_tx: &mpsc::UnboundedSender<SupervisorEvent>) {
    let record_type = record.get("type").and_then(Value::as_str).unwrap_or("");
    match record_type {
        "response" => {
            let response = PiResponse {
                id: record.get("id").and_then(Value::as_str).map(str::to_string),
                command: record
                    .get("command")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                success: record
                    .get("success")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                data: record.get("data").cloned(),
                error: record
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            };
            let _ = events_tx.send(SupervisorEvent::Response(response));
        }
        "agent_start" => {
            let _ = events_tx.send(SupervisorEvent::Bridge(BridgeEvent::SessionStarted {
                version: PIBRIDGE_VERSION,
                session_id: String::new(),
                pi_version: String::new(),
            }));
        }
        "agent_settled" => {
            let _ = events_tx.send(SupervisorEvent::Bridge(BridgeEvent::AgentSettled {
                version: PIBRIDGE_VERSION,
            }));
        }
        "tool_execution_start" => {
            let _ = events_tx.send(SupervisorEvent::Bridge(BridgeEvent::ToolCallObserved {
                version: PIBRIDGE_VERSION,
                call_id: record
                    .get("toolCallId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                tool_name: record
                    .get("toolName")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            }));
        }
        "tool_execution_end" => {
            let _ = events_tx.send(SupervisorEvent::Bridge(BridgeEvent::ToolResultObserved {
                version: PIBRIDGE_VERSION,
                call_id: record
                    .get("toolCallId")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                success: !record
                    .get("isError")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            }));
        }
        _ => {
            // Session events we do not normalize are intentionally ignored;
            // message deltas are not needed by the spike.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_raw_allows_only_the_safe_commands() {
        assert!(matches!(
            SupervisorCommand::from_raw("get_state"),
            Ok(SupervisorCommand::GetState)
        ));
        assert!(matches!(
            SupervisorCommand::from_raw("abort"),
            Ok(SupervisorCommand::Abort)
        ));
    }

    #[test]
    fn from_raw_rejects_effectful_commands() {
        for hostile in [
            "bash",
            "export_html",
            "auth",
            "provider",
            "models",
            "tools",
            "set_model",
            "set_active_tools",
            "set_thinking_level",
            "session",
            "prompt", // prompt needs a message; use Supervisor::prompt
            "",
            "BASH",
        ] {
            assert!(
                SupervisorCommand::from_raw(hostile).is_err(),
                "command '{hostile}' must be rejected"
            );
        }
    }

    #[test]
    fn command_serialization_uses_pi_rpc_shape() {
        let json = SupervisorCommand::GetState.to_json();
        assert_eq!(
            json.get("command").and_then(Value::as_str),
            Some("get_state")
        );
        assert_eq!(
            SupervisorCommand::Abort
                .to_json()
                .get("command")
                .and_then(Value::as_str),
            Some("abort")
        );
    }

    #[tokio::test]
    async fn spawn_refuses_effectful_builtin_tools() {
        let mut config = PiSupervisorConfig::default();
        config.args.retain(|a| a != "--no-builtin-tools");
        let err = match PiSupervisor::spawn(config).await {
            Ok(_) => panic!("must refuse to spawn without --no-builtin-tools"),
            Err(e) => e,
        };
        assert!(
            matches!(err, SupervisorError::Config(_)),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn spawn_refuses_missing_binary() {
        let mut config = PiSupervisorConfig::default();
        config.pi_binary = PathBuf::from("/nonexistent/lumen-test-pi-binary");
        let err = match PiSupervisor::spawn(config).await {
            Ok(_) => panic!("must fail to spawn a missing binary"),
            Err(e) => e,
        };
        assert!(
            matches!(err, SupervisorError::Spawn(_)),
            "unexpected error: {err:?}"
        );
    }
}
