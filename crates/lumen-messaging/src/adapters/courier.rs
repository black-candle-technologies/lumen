//! Courier baseline adapter: the native, first-class channel.
//!
//! # Transport decision
//!
//! There is no Rust client for Courier (`black-candle-technologies/courier`
//! is Go-only; verified via the crates.io API and GitHub code search on
//! 2026-09-23 — no Rust crate or client module exists). This adapter
//! therefore shells out to the `courier` CLI as a **supervised subprocess**
//! over its documented JSON-lines agent bridge (`courier stdio`), which
//! exposes exactly the surface an agent needs:
//!
//! - `health` — liveness check
//! - `address` — this identity's Courier address
//! - `send {to, body, reply_to?}` — send; returns the provider message id
//! - `inbox {after?, limit?}` — poll messages after a cursor
//!
//! Message wire form (`stdioMessage`): `{id, from, body, sent_at,
//! received_at, flags?, request?, reply_to?, reply_quote?, bridged?}` with
//! Unix-second timestamps. Courier verifies Ed25519 signatures on receipt;
//! the adapter treats as authenticated only bytes actually emitted by the
//! supervised bridge child, which must be the digest-pinned reviewed binary
//! (`courier version` >= `min_version`, mandatory expected SHA-256,
//! absolute path — PATH resolution is rejected). The public `ingest` entry
//! point fails closed on any bytes the bridge did not deliver, before
//! parsing and before dedupe, so forged bytes can neither map a sender nor
//! preempt legitimate messages via event-ID dedupe.
//!
//! Key material never enters the Pi process: the kernel materializes the
//! ephemeral per-session identity into a kernel-owned directory and the
//! adapter spawns the child with `HOME` pointed at it, so the CLI reads
//! `<identity_dir>/.courier/config.json`. The adapter receives the directory
//! path only — never key bytes. The child runs with a scrubbed environment
//! (only `HOME` plus the proxy variables the courier client honors — no
//! ambient secrets), and the identity dir must be mode 0700.
//!
//! Long-term direction: replace the key file with a brokered signing
//! interface (kernel-held key, sign-via-IPC) so the helper never sees key
//! material at all. The courier CLI fundamentally needs the key file today,
//! so the mandatory digest pin + absolute path + scrubbed environment is the
//! containment boundary for this phase.
//!
//! TODO(PHASE4): phase-4 owns the session-identity API (issuing the
//! ephemeral per-session Courier keypair and materializing it). When it
//! lands, the host will call [`CourierAdapter::bind_session`] with the
//! issued [`SessionIdentityBinding`]; until then session binding is explicit
//! operator configuration.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, Command},
    sync::{Mutex, mpsc, oneshot},
};

use crate::{
    MessagingConfig,
    adapters::{
        AdapterCapabilities, AdapterDescriptor, AdapterError, AdapterVersion, ConnectionBinding,
        ConnectionState, DedupeDecision, IngestError, MessagingAdapter, ProviderReceipt,
    },
    dedupe::DedupeStore,
    envelope::{
        ConnectionId, Conversation, DedupeKey, MessageEnvelope, Provenance, Provider,
        ProviderMessageId, ReplyContext, SenderIdentity, TransportTrust,
    },
    outbound::OutboundRequest,
    principals::{PrincipalMappingRegistry, PrincipalResolution},
};

/// Reviewed adapter version for audit provenance.
pub const ADAPTER_VERSION: &str = "0.1.0";

/// Courier addresses are `ed25519:<base64url>` (see Courier INSTALL.md).
const ADDRESS_PREFIX: &str = "ed25519:";

/// A validated Courier address.
#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct CourierAddress(String);

impl CourierAddress {
    pub fn new(value: impl Into<String>) -> Result<Self, CourierError> {
        let value = value.into();
        if !value.starts_with(ADDRESS_PREFIX) || value.len() <= ADDRESS_PREFIX.len() {
            return Err(CourierError::InvalidAddress);
        }
        if value.len() > 128 || value.chars().any(char::is_control) {
            return Err(CourierError::InvalidAddress);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Binds a Lumen session to its ephemeral Courier identity.
///
/// TODO(PHASE4): the address (and the materialized keypair behind it) is
/// issued by phase-4's session-identity API. The adapter binds it; it never
/// mints identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionIdentityBinding {
    pub session_id: String,
    pub address: CourierAddress,
}

impl SessionIdentityBinding {
    pub fn new(
        session_id: impl Into<String>,
        address: CourierAddress,
    ) -> Result<Self, CourierError> {
        let session_id = session_id.into();
        if session_id.is_empty() || session_id.len() > 128 {
            return Err(CourierError::InvalidSession);
        }
        Ok(Self {
            session_id,
            address,
        })
    }
}

/// Adapter configuration.
///
/// The helper binary is a trust root: Courier verifies Ed25519 signatures
/// on receipt and the adapter's sender-authentication rests on the bridge
/// being the reviewed binary. `bind` therefore fails closed unless `binary`
/// is absolute (no PATH resolution) and `expected_binary_sha256` carries a
/// well-formed pin.
#[derive(Clone, Debug)]
pub struct CourierConfig {
    /// Absolute path to the reviewed `courier` binary. Relative paths are
    /// rejected at bind: PATH resolution would let a substituted executable
    /// impersonate the bridge.
    pub binary: PathBuf,
    /// Minimum accepted `courier version` (e.g. `0.13.0`).
    pub min_version: String,
    /// Mandatory pinned SHA-256 (64 hex characters) of the binary. Bind
    /// fails closed when absent or malformed; spawn re-hashes before exec.
    pub expected_binary_sha256: Option<String>,
    /// Kernel-owned directory holding the materialized session identity
    /// (`<dir>/.courier/config.json`). The child runs with `HOME` set here.
    ///
    /// TODO(PHASE4): populated by the kernel's identity materialization.
    pub identity_dir: Option<PathBuf>,
    /// Timeout for a single stdio round-trip.
    pub request_timeout: Duration,
}

impl Default for CourierConfig {
    fn default() -> Self {
        Self {
            binary: PathBuf::from("courier"),
            min_version: "0.13.0".to_owned(),
            expected_binary_sha256: None,
            identity_dir: None,
            request_timeout: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// stdio wire protocol (grounded in courier's cmd/courier/main.go, `courier
// stdio` bridge; schema pinned by `courier version` at bind time)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct StdioRequest {
    id: i64,
    cmd: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    after: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reply_to: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct StdioResponse {
    id: i64,
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    address: Option<String>,
    #[serde(default)]
    message_id: Option<i64>,
    #[serde(default)]
    messages: Option<Vec<StdioMessage>>,
}

/// One message as delivered by `courier stdio` / `courier wake`.
/// Timestamps are Unix seconds (grounded: `time.Now().Unix()` in the Go
/// client). Unknown fields are ignored so newer CLI fields don't break
/// ingest; the schema is pinned by the version check at bind time.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StdioMessage {
    pub id: i64,
    pub from: String,
    #[serde(default)]
    pub body: String,
    pub sent_at: i64,
    pub received_at: i64,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub request: bool,
    #[serde(default)]
    pub reply_to: Option<i64>,
    #[serde(default)]
    pub reply_quote: Option<String>,
    /// True when the message arrived via a non-E2E bridge: untrusted input.
    #[serde(default)]
    pub bridged: bool,
    /// Optional group/channel context when delivered via group/channel inbox.
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub channel_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Supervised stdio transport
// ---------------------------------------------------------------------------

struct PendingCalls {
    inner: Mutex<HashMap<i64, oneshot::Sender<StdioResponse>>>,
}

/// Supervised `courier stdio` subprocess. The child is owned here; dropping
/// the transport kills it. All credential material stays inside the child
/// (kernel-materialized identity dir); this struct only holds the pipe.
pub struct CourierStdioTransport {
    _child: Child,
    tx: mpsc::Sender<String>,
    pending: Arc<PendingCalls>,
    next_id: AtomicI64,
    dead: Arc<AtomicBool>,
    timeout: Duration,
}

impl CourierStdioTransport {
    pub async fn spawn(config: &CourierConfig) -> Result<Self, CourierError> {
        // The pin is mandatory (validated at bind); re-verify here so a
        // direct spawn can never run an unpinned helper either.
        verify_binary_digest(config)?;
        if !config.binary.is_absolute() {
            return Err(CourierError::RelativeBinaryPath);
        }
        if let Some(dir) = &config.identity_dir {
            // The session private key lives here: 0700 or no child.
            check_identity_dir(dir)?;
        }

        let mut command = Command::new(&config.binary);
        command
            .arg("stdio")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            // Revocation and drop must terminate the bridge: without this,
            // dropping the Child would orphan the CLI process.
            .kill_on_drop(true);
        // Scrubbed environment: the child sees only HOME (the
        // kernel-materialized identity dir, or the ambient HOME when no
        // session identity is bound) and the proxy variables the courier
        // client honors. Ambient secrets never reach the helper.
        command.env_clear();
        for (key, value) in child_env(config.identity_dir.as_ref()) {
            command.env(key, value);
        }

        let mut child = command.spawn().map_err(|e| CourierError::Transport {
            reason: format!("failed to spawn courier stdio: {e}"),
        })?;
        let stdin = child.stdin.take().ok_or(CourierError::Transport {
            reason: "courier stdio stdin unavailable".to_owned(),
        })?;
        let stdout = child.stdout.take().ok_or(CourierError::Transport {
            reason: "courier stdio stdout unavailable".to_owned(),
        })?;

        let pending = Arc::new(PendingCalls {
            inner: Mutex::new(HashMap::new()),
        });
        let dead = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel::<String>(64);

        spawn_writer(stdin, rx, Arc::clone(&dead));
        spawn_reader(stdout, Arc::clone(&pending), Arc::clone(&dead));

        let transport = Self {
            _child: child,
            tx,
            pending,
            next_id: AtomicI64::new(1),
            dead,
            timeout: config.request_timeout,
        };

        // The bridge must answer health before we trust it.
        transport.health().await?;
        Ok(transport)
    }

    pub fn is_live(&self) -> bool {
        !self.dead.load(Ordering::SeqCst)
    }

    fn check_live(&self) -> Result<(), CourierError> {
        if self.is_live() {
            Ok(())
        } else {
            Err(CourierError::Transport {
                reason: "courier stdio subprocess is dead".to_owned(),
            })
        }
    }

    async fn round_trip(&self, request: StdioRequest) -> Result<StdioResponse, CourierError> {
        self.check_live()?;
        let id = request.id;
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.inner.lock().await;
            pending.insert(id, tx);
        }
        let line = serde_json::to_string(&request).map_err(|e| CourierError::Transport {
            reason: format!("failed to encode stdio request: {e}"),
        })?;
        self.tx
            .send(line)
            .await
            .map_err(|_| CourierError::Transport {
                reason: "courier stdio writer task is gone".to_owned(),
            })?;

        let response = match tokio::time::timeout(self.timeout, rx).await {
            Ok(rx_result) => rx_result,
            Err(_) => {
                // Timeout: drop the registration so a late response cannot
                // be misattributed and the map cannot grow without bound.
                self.pending.inner.lock().await.remove(&id);
                return Err(CourierError::Transport {
                    reason: format!("courier stdio request {id} timed out"),
                });
            }
        }
        .map_err(|_| CourierError::Transport {
            reason: "courier stdio response channel closed".to_owned(),
        })?;
        if response.id != id {
            return Err(CourierError::Transport {
                reason: format!("courier stdio id mismatch: sent {id}, got {}", response.id),
            });
        }
        if !response.ok {
            return Err(CourierError::Transport {
                reason: response
                    .error
                    .unwrap_or_else(|| "courier stdio reported failure".to_owned()),
            });
        }
        Ok(response)
    }

    pub async fn health(&self) -> Result<(), CourierError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        self.round_trip(StdioRequest {
            id,
            cmd: "health",
            to: None,
            body: None,
            after: None,
            limit: None,
            reply_to: None,
        })
        .await
        .map(|_| ())
    }

    pub async fn address(&self) -> Result<CourierAddress, CourierError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let response = self
            .round_trip(StdioRequest {
                id,
                cmd: "address",
                to: None,
                body: None,
                after: None,
                limit: None,
                reply_to: None,
            })
            .await?;
        let address = response.address.ok_or(CourierError::Transport {
            reason: "courier stdio address returned no address".to_owned(),
        })?;
        CourierAddress::new(address)
    }

    /// Sends a message. Returns the provider message id for receipt
    /// correlation.
    pub async fn send(
        &self,
        to: &CourierAddress,
        body: &str,
        reply_to: Option<i64>,
    ) -> Result<i64, CourierError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let response = self
            .round_trip(StdioRequest {
                id,
                cmd: "send",
                to: Some(to.as_str().to_owned()),
                body: Some(body.to_owned()),
                after: None,
                limit: None,
                reply_to,
            })
            .await?;
        response.message_id.ok_or(CourierError::Transport {
            reason: "courier stdio send returned no message id".to_owned(),
        })
    }

    /// Polls messages after the cursor (provider message id).
    pub async fn inbox(
        &self,
        after: Option<i64>,
        limit: i32,
    ) -> Result<Vec<StdioMessage>, CourierError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let response = self
            .round_trip(StdioRequest {
                id,
                cmd: "inbox",
                to: None,
                body: None,
                after,
                limit: Some(limit),
                reply_to: None,
            })
            .await?;
        Ok(response.messages.unwrap_or_default())
    }
}

fn spawn_writer(mut stdin: ChildStdin, mut rx: mpsc::Receiver<String>, dead: Arc<AtomicBool>) {
    tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if stdin.write_all(line.as_bytes()).await.is_err()
                || stdin.write_all(b"\n").await.is_err()
                || stdin.flush().await.is_err()
            {
                dead.store(true, Ordering::SeqCst);
                break;
            }
        }
    });
}

fn spawn_reader(
    stdout: tokio::process::ChildStdout,
    pending: Arc<PendingCalls>,
    dead: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let response: Result<StdioResponse, _> = serde_json::from_str(&line);
                    match response {
                        Ok(response) => {
                            let sender = {
                                let mut pending = pending.inner.lock().await;
                                pending.remove(&response.id)
                            };
                            if let Some(sender) = sender {
                                let _ = sender.send(response);
                            }
                        }
                        Err(_) => {
                            // Unparseable line from the child: ignore; the
                            // timed-out caller fails closed on its own.
                        }
                    }
                }
                _ => {
                    // EOF or read error: the child is gone. Fail every
                    // in-flight caller at once instead of letting each wait
                    // out the full request timeout: dropping the senders
                    // makes each waiting `rx` return a closed-channel error
                    // immediately.
                    dead.store(true, Ordering::SeqCst);
                    pending.inner.lock().await.clear();
                    break;
                }
            }
        }
    });
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Maximum digests of bridge-delivered messages retained for the public
/// `ingest` gate. `poll()` registers-then-ingests immediately, so this only
/// needs to cover host re-ingest shortly after delivery.
const MAX_BRIDGE_DELIVERED: usize = 2048;

/// Digests of raw messages actually emitted by the supervised, digest-pinned
/// bridge child. This is the adapter-side half of the authenticated
/// transport binding: the public `ingest` entry point only accepts bytes the
/// bridge delivered, so a caller with crafted JSON cannot map a sender or
/// preempt legitimate messages via event-ID dedupe.
#[derive(Default)]
struct BridgeDeliveryLog {
    digests: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}

impl BridgeDeliveryLog {
    fn note(&mut self, raw_event: &[u8]) {
        let digest: [u8; 32] = Sha256::digest(raw_event).into();
        if self.digests.insert(digest) {
            self.order.push_back(digest);
            while self.order.len() > MAX_BRIDGE_DELIVERED {
                if let Some(old) = self.order.pop_front() {
                    self.digests.remove(&old);
                }
            }
        }
    }

    fn contains(&self, raw_event: &[u8]) -> bool {
        let digest: [u8; 32] = Sha256::digest(raw_event).into();
        self.digests.contains(&digest)
    }
}

/// Verifies the configured helper binary against its mandatory SHA-256 pin.
/// Runs before anything executes the binary: a substituted helper must never
/// get a single execution, not even `courier version`.
fn verify_binary_digest(config: &CourierConfig) -> Result<(), CourierError> {
    let expected = config
        .expected_binary_sha256
        .as_ref()
        .ok_or(CourierError::BinaryPinRequired)?;
    let actual = sha256_file(&config.binary).map_err(|e| CourierError::Transport {
        reason: format!("cannot hash courier binary: {e}"),
    })?;
    if actual != expected.to_ascii_lowercase() {
        return Err(CourierError::BinaryHashMismatch {
            expected: expected.clone(),
            actual,
        });
    }
    Ok(())
}

/// Validates the helper-binary trust root before anything executes it:
/// absolute path (no PATH resolution), a well-formed mandatory digest pin,
/// and a parent directory that a non-root actor cannot write to (so the
/// digest verified at bind cannot be swapped for a different file between
/// hash and exec). Fail-closed: an unpinned, PATH-resolved, or swappable
/// helper must never run.
fn validate_binary_config(config: &CourierConfig) -> Result<(), CourierError> {
    if !config.binary.is_absolute() {
        return Err(CourierError::RelativeBinaryPath);
    }
    validate_binary_parent(&config.binary)?;
    match &config.expected_binary_sha256 {
        None => Err(CourierError::BinaryPinRequired),
        Some(pin) => {
            let well_formed = pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit());
            if well_formed {
                Ok(())
            } else {
                Err(CourierError::MalformedBinaryPin)
            }
        }
    }
}

/// The digest check and the exec are two separate syscalls: without a
/// trust-rooted parent, the file could be replaced between them (TOCTOU).
/// The parent must not be writable by group/other (checked first, so the
/// writable case is deterministic) and must be root-owned, so a non-root
/// actor cannot rename a different file into the verified path.
#[cfg(unix)]
fn validate_binary_parent(binary: &std::path::Path) -> Result<(), CourierError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = binary.parent().ok_or(CourierError::RelativeBinaryPath)?;
    let meta = std::fs::metadata(parent).map_err(|e| CourierError::Transport {
        reason: format!("cannot stat courier binary parent: {e}"),
    })?;
    if meta.permissions().mode() & 0o022 != 0 {
        return Err(CourierError::BinaryParentWritable(
            parent.display().to_string(),
        ));
    }
    if meta.uid() != 0 {
        return Err(CourierError::BinaryParentNotRootOwned(
            parent.display().to_string(),
        ));
    }
    Ok(())
}

/// Non-unix targets cannot express the root-owned-parent trust root; the
/// digest pin is the only check there.
#[cfg(not(unix))]
fn validate_binary_parent(_binary: &std::path::Path) -> Result<(), CourierError> {
    Ok(())
}

/// Environment for the supervised `courier` child: scrubbed, not inherited.
///
/// A substituted helper must not see ambient secrets (API keys, tokens),
/// so the child gets only `HOME` — the kernel-owned identity dir, or the
/// ambient `HOME` when no session identity is bound — plus the proxy
/// variables the courier client honors. Everything else is dropped.
fn child_env(identity_dir: Option<&PathBuf>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    let home = match identity_dir {
        Some(dir) => dir.to_string_lossy().into_owned(),
        None => std::env::var("HOME").unwrap_or_default(),
    };
    if !home.is_empty() {
        env.push(("HOME".to_owned(), home));
    }
    for var in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        if let Ok(value) = std::env::var(var) {
            env.push((var.to_owned(), value));
        }
    }
    env
}

/// The kernel-owned identity dir holds the session private key; it must be
/// a mode-0700 directory or the child is not spawned.
#[cfg(unix)]
fn check_identity_dir(dir: &PathBuf) -> Result<(), CourierError> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(dir).map_err(|e| CourierError::Transport {
        reason: format!("cannot stat courier identity dir: {e}"),
    })?;
    if !metadata.is_dir() {
        return Err(CourierError::Transport {
            reason: format!("courier identity dir is not a directory: {}", dir.display()),
        });
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        return Err(CourierError::IdentityDirInsecure(dir.display().to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_identity_dir(dir: &PathBuf) -> Result<(), CourierError> {
    let metadata = std::fs::metadata(dir).map_err(|e| CourierError::Transport {
        reason: format!("cannot stat courier identity dir: {e}"),
    })?;
    if !metadata.is_dir() {
        return Err(CourierError::Transport {
            reason: format!("courier identity dir is not a directory: {}", dir.display()),
        });
    }
    Ok(())
}

/// Checks `courier version` output against the minimum version.
///
/// Runs with the same scrubbed environment as the supervised child: even
/// though the digest is verified before this executes, a substituted binary
/// must never see ambient secrets.
fn check_cli_version(
    binary: &PathBuf,
    min_version: &str,
    identity_dir: Option<&PathBuf>,
) -> Result<String, CourierError> {
    let mut command = std::process::Command::new(binary);
    command.arg("version").env_clear();
    for (key, value) in child_env(identity_dir) {
        command.env(key, value);
    }
    let output = command.output().map_err(|e| CourierError::Transport {
        reason: format!("failed to run courier version: {e}"),
    })?;
    if !output.status.success() {
        return Err(CourierError::Transport {
            reason: "courier version exited non-zero".to_owned(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let found = extract_version(&stdout).ok_or(CourierError::Transport {
        reason: format!("could not parse version from courier version output: {stdout}"),
    })?;
    if version_gte(&found, min_version) {
        Ok(found)
    } else {
        Err(CourierError::UnsupportedCliVersion {
            found,
            min: min_version.to_owned(),
        })
    }
}

fn extract_version(output: &str) -> Option<String> {
    // First `v?X.Y.Z` token in the output.
    for token in output.split(|c: char| c.is_whitespace() || c == ',') {
        let token = token.trim_start_matches('v');
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() >= 2 && parts.iter().all(|p| p.chars().all(|c| c.is_ascii_digit())) {
            return Some(token.to_owned());
        }
    }
    None
}

fn version_gte(found: &str, min: &str) -> bool {
    let parse = |v: &str| {
        v.split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect::<Vec<_>>()
    };
    let (mut f, mut m) = (parse(found), parse(min));
    f.resize(3, 0);
    m.resize(3, 0);
    f >= m
}

// ---------------------------------------------------------------------------
// VHL request carriage
// ---------------------------------------------------------------------------

/// VHL approval request carried natively in a Courier message body.
///
/// The kernel mints the approval (immutable action digest + nonce); this
/// type only serializes the carriage into the message and parses it back.
/// Use [`VhlCourierCarriage::from_vhl_request`] to build it from the
/// phase-4 backend's real [`lumen_core::vhl::VhlApprovalRequest`], and
/// [`VhlCourierCarriage::verify_against`] to check a received carriage
/// against that backend before acting on it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VhlCourierCarriage {
    pub approval_id: String,
    pub action_digest: String,
    pub nonce: String,
    pub expires_at_millis: i64,
}

#[derive(Debug, Deserialize, Serialize)]
struct VhlBody {
    lumen_vhl: VhlCourierCarriage,
    #[serde(default)]
    text: String,
}

impl VhlCourierCarriage {
    pub fn from_approval(approval: &crate::outbound::VhlApprovalCarriage) -> Self {
        Self {
            approval_id: approval.approval_id.clone(),
            action_digest: approval.action_digest.clone(),
            nonce: approval.nonce.clone(),
            expires_at_millis: approval.expires_at_millis,
        }
    }

    /// Encodes the carriage + human-readable text into the message body.
    pub fn encode_body(&self, text: &str) -> String {
        serde_json::to_string(&VhlBody {
            lumen_vhl: self.clone(),
            text: text.to_owned(),
        })
        .expect("VHL body serialization cannot fail")
    }

    /// Splits a received body into an optional carriage and the text.
    /// Plain-text bodies yield `(None, body)`.
    pub fn decode_body(body: &str) -> (Option<Self>, String) {
        match serde_json::from_str::<VhlBody>(body) {
            Ok(decoded) => (Some(decoded.lumen_vhl), decoded.text),
            Err(_) => (None, body.to_owned()),
        }
    }

    /// Build the carriage from the phase-4 backend's real approval request.
    /// The kernel mints the request; the adapter only carries it.
    pub fn from_vhl_request(request: &lumen_core::vhl::VhlApprovalRequest) -> Self {
        Self {
            approval_id: request.request_id.clone(),
            action_digest: request.action_digest.clone(),
            nonce: request.nonce.clone(),
            expires_at_millis: request.expires_at_ms,
        }
    }

    /// Verify a received carriage against the phase-4 backend's approval
    /// request: id, action digest, and nonce must match, and the approval
    /// must not be expired at `now_ms`. This is the host-side half of the
    /// old `TODO(PHASE4)`; the kernel-side half (the request state machine,
    /// attestation verification, one-shot minting) stays in
    /// `lumen_core::vhl` and is never reimplemented here.
    pub fn verify_against(
        &self,
        request: &lumen_core::vhl::VhlApprovalRequest,
        now_ms: i64,
    ) -> Result<(), CourierError> {
        // These are identifiers, not secrets (they travel in the message),
        // so plain equality is the right comparison.
        if self.approval_id != request.request_id {
            return Err(CourierError::Vhl {
                reason: "approval id does not match the kernel approval request".to_string(),
            });
        }
        if self.action_digest != request.action_digest {
            return Err(CourierError::Vhl {
                reason: "action digest does not match the kernel approval request".to_string(),
            });
        }
        if self.nonce != request.nonce {
            return Err(CourierError::Vhl {
                reason: "nonce does not match the kernel approval request".to_string(),
            });
        }
        if now_ms >= request.expires_at_ms {
            return Err(CourierError::Vhl {
                reason: "approval expired".to_string(),
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// VHL protocol payloads as native Courier message types
// ---------------------------------------------------------------------------

/// Body envelope for a phase-4 VHL protocol payload carried as a native
/// Courier message type. The payload's own
/// [`lumen_core::vhl::VhlCourierMessage::message_type`] travels alongside
/// the payload so the receiver can dispatch on the type without parsing
/// the payload first; the payload bytes are the phase-4 backend's
/// canonical JSON, re-serialized through `serde_json::Value` so the body
/// stays a single JSON document.
#[derive(Debug, Deserialize, Serialize)]
struct VhlNativeBody {
    lumen_vhl_type: String,
    lumen_vhl_payload: serde_json::Value,
}

/// Encode a phase-4 [`lumen_core::vhl::VhlCourierMessage`] as a Courier
/// message body. The phase-4 backend constructs (and on receipt, verifies)
/// the payload; the adapter only carries it. Transport is unchanged.
pub fn encode_vhl_message(
    msg: &lumen_core::vhl::VhlCourierMessage,
) -> Result<String, CourierError> {
    let bytes = msg.encode().map_err(|e| CourierError::Vhl {
        reason: e.to_string(),
    })?;
    let payload =
        serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| CourierError::Vhl {
            reason: e.to_string(),
        })?;
    serde_json::to_string(&VhlNativeBody {
        lumen_vhl_type: msg.message_type().to_string(),
        lumen_vhl_payload: payload,
    })
    .map_err(|e| CourierError::Vhl {
        reason: e.to_string(),
    })
}

/// Decode a body produced by [`encode_vhl_message`]. Returns `None` for
/// anything else (plain text, approval carriages, foreign bodies). The
/// envelope type must agree with the payload's own message type; the
/// payload itself is parsed by the phase-4 backend's
/// [`lumen_core::vhl::VhlCourierMessage::decode`].
pub fn decode_vhl_message(body: &str) -> Option<lumen_core::vhl::VhlCourierMessage> {
    let env: VhlNativeBody = serde_json::from_str(body).ok()?;
    let bytes = lumen_core::pi_boundary::canonical_json(&env.lumen_vhl_payload).ok()?;
    let msg = lumen_core::vhl::VhlCourierMessage::decode(&bytes).ok()?;
    (msg.message_type() == env.lumen_vhl_type).then_some(msg)
}

// ---------------------------------------------------------------------------
// Signed handoff artifacts
// ---------------------------------------------------------------------------

/// Countersigned session-handoff artifact carried as a Courier message.
///
/// The artifact binds a payload digest to the handing-off and receiving
/// sessions. Signatures are *carried*, not verified, here: verification
/// needs the session keys owned by phase-4.
///
/// TODO(PHASE4): verify signatures against the session-identity registry and
/// require countersignature acceptance before the handoff takes effect.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffArtifact {
    pub artifact_id: String,
    pub from_session: String,
    pub to_session: String,
    /// SHA-256 hex of the handoff payload.
    pub payload_digest: String,
    /// Opaque payload bytes (kept small; size-capped on decode).
    pub payload: Vec<u8>,
    pub signatures: Vec<HandoffSignature>,
}

/// Maximum handoff payload: 1 MiB.
pub const MAX_HANDOFF_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HandoffSignature {
    pub signer_address: String,
    /// Hex-encoded Ed25519 signature over the canonical artifact bytes.
    pub signature: String,
}

impl HandoffArtifact {
    /// Canonical bytes that signatures cover:
    /// `artifact_id | from_session | to_session | payload_digest`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        format!(
            "{}|{}|{}|{}",
            self.artifact_id, self.from_session, self.to_session, self.payload_digest
        )
        .into_bytes()
    }

    pub fn new(
        artifact_id: impl Into<String>,
        from_session: impl Into<String>,
        to_session: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Self, CourierError> {
        if payload.len() > MAX_HANDOFF_PAYLOAD_BYTES {
            return Err(CourierError::HandoffTooLarge {
                bytes: payload.len(),
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        Ok(Self {
            artifact_id: artifact_id.into(),
            from_session: from_session.into(),
            to_session: to_session.into(),
            payload_digest: format!("{:x}", hasher.finalize()),
            payload,
            signatures: Vec::new(),
        })
    }

    /// Attaches a countersignature. Callers must have verified the signature
    /// against the signer's session key; this only records it.
    ///
    /// TODO(PHASE4): perform verification here once the session-identity API
    /// exposes the session public keys.
    pub fn countersign(&mut self, signature: HandoffSignature) {
        self.signatures.push(signature);
    }

    pub fn encode_body(&self) -> Result<String, CourierError> {
        serde_json::to_string(self).map_err(|e| CourierError::Transport {
            reason: format!("failed to encode handoff artifact: {e}"),
        })
    }

    pub fn decode_body(body: &str) -> Result<Self, CourierError> {
        let artifact: Self =
            serde_json::from_str(body).map_err(|_| CourierError::MalformedHandoff)?;
        if artifact.payload.len() > MAX_HANDOFF_PAYLOAD_BYTES {
            return Err(CourierError::HandoffTooLarge {
                bytes: artifact.payload.len(),
            });
        }
        // Recompute the digest; a tampered payload fails closed here.
        let mut hasher = Sha256::new();
        hasher.update(&artifact.payload);
        let digest = format!("{:x}", hasher.finalize());
        if digest != artifact.payload_digest {
            return Err(CourierError::HandoffDigestMismatch);
        }
        Ok(artifact)
    }
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/// One message in a [`CourierAdapter::poll`] batch that failed to ingest.
/// The batch continues past rejections; the caller must surface these to
/// the operator/audit trail.
#[derive(Debug)]
pub struct PollRejection {
    /// Provider message id of the rejected message.
    pub message_id: i64,
    pub error: IngestError,
}

/// Outcome of [`CourierAdapter::poll`]: the envelopes that ingested, plus
/// the messages that were rejected without disturbing the batch.
#[derive(Debug, Default)]
pub struct PollOutcome {
    pub envelopes: Vec<MessageEnvelope>,
    pub rejected: Vec<PollRejection>,
}

/// Courier baseline adapter.
pub struct CourierAdapter {
    descriptor: AdapterDescriptor,
    config: CourierConfig,
    registry: Arc<PrincipalMappingRegistry>,
    dedupe: Arc<dyn DedupeStore>,
    transport: Option<CourierStdioTransport>,
    binding: Option<ConnectionBinding>,
    session: Option<SessionIdentityBinding>,
    state: ConnectionState,
    /// Cursor for inbox polling: last seen provider message id.
    inbox_cursor: Option<i64>,
    /// Digests of raw messages actually emitted by the supervised bridge.
    /// The public `ingest` entry point fails closed on any bytes absent
    /// here; see [`BridgeDeliveryLog`].
    bridge_delivered: std::sync::Mutex<BridgeDeliveryLog>,
}

impl CourierAdapter {
    pub fn new(
        config: CourierConfig,
        registry: Arc<PrincipalMappingRegistry>,
        dedupe: Arc<dyn DedupeStore>,
    ) -> Self {
        Self {
            descriptor: AdapterDescriptor::new(
                "courier",
                AdapterVersion::new(ADAPTER_VERSION).expect("adapter version is valid"),
                AdapterCapabilities {
                    inbound_events: vec![
                        "message.created".to_owned(),
                        "message.request".to_owned(),
                    ],
                    outbound_verbs: vec!["send".to_owned()],
                },
            ),
            config,
            registry,
            dedupe,
            transport: None,
            binding: None,
            session: None,
            state: ConnectionState::Unbound,
            inbox_cursor: None,
            bridge_delivered: std::sync::Mutex::new(BridgeDeliveryLog::default()),
        }
    }

    /// Binds the adapter's Lumen session to its ephemeral Courier identity.
    ///
    /// TODO(PHASE4): the host calls this with the identity issued by the
    /// session-identity API. The adapter verifies the CLI's `address`
    /// matches; it never mints or holds key material.
    pub async fn bind_session(
        &mut self,
        session: SessionIdentityBinding,
    ) -> Result<(), AdapterError> {
        if !matches!(self.state, ConnectionState::Bound) {
            return Err(AdapterError::NotBound);
        }
        let transport = self.transport.as_ref().ok_or(AdapterError::NotBound)?;
        let actual = transport.address().await.map_err(|e: CourierError| {
            AdapterError::IdentityUnavailable {
                reason: e.to_string(),
            }
        })?;
        if actual != session.address {
            return Err(AdapterError::IdentityUnavailable {
                reason: "courier address does not match the bound session identity".to_owned(),
            });
        }
        self.session = Some(session);
        Ok(())
    }

    /// Polls the CLI inbox after the cursor and ingests each message.
    ///
    /// One bad message must not discard the batch: serialization and ingest
    /// failures are recorded per message (with the message id) and the loop
    /// continues. The caller must surface `rejected` to the operator/audit
    /// trail — a rejection is terminal for that poll position.
    pub async fn poll(&mut self, limit: i32, now_millis: i64) -> Result<PollOutcome, IngestError> {
        let transport = self.transport.as_ref().ok_or(IngestError::AuthLost {
            reason: "courier adapter not bound".to_owned(),
        })?;
        let messages = transport
            .inbox(self.inbox_cursor, limit)
            .await
            .map_err(|e| IngestError::AuthLost {
                reason: e.to_string(),
            })?;
        let mut outcome = PollOutcome::default();
        for message in messages {
            self.inbox_cursor = Some(message.id);
            let raw = match serde_json::to_vec(&message) {
                Ok(raw) => raw,
                Err(e) => {
                    outcome.rejected.push(PollRejection {
                        message_id: message.id,
                        error: IngestError::MalformedEvent {
                            reason: e.to_string(),
                        },
                    });
                    continue;
                }
            };
            // These bytes came from the supervised, digest-pinned bridge:
            // record them so the public ingest gate accepts exactly them.
            self.note_bridge_delivery(&raw);
            // Known redeliveries collapse to None and never disturb the batch.
            match self.ingest_message(&raw, &message, now_millis) {
                Ok(Some(envelope)) => outcome.envelopes.push(envelope),
                Ok(None) => {}
                Err(error) => outcome.rejected.push(PollRejection {
                    message_id: message.id,
                    error,
                }),
            }
        }
        Ok(outcome)
    }

    /// Records raw bytes emitted by the supervised bridge. Only registered
    /// bytes pass the public `ingest` gate.
    fn note_bridge_delivery(&self, raw_event: &[u8]) {
        if let Ok(mut log) = self.bridge_delivered.lock() {
            log.note(raw_event);
        }
    }

    /// Whether these exact bytes were delivered by the supervised bridge.
    fn was_bridge_delivered(&self, raw_event: &[u8]) -> bool {
        self.bridge_delivered
            .lock()
            .map(|log| log.contains(raw_event))
            .unwrap_or(false)
    }

    fn ingest_message(
        &self,
        raw_event: &[u8],
        message: &StdioMessage,
        now_millis: i64,
    ) -> Result<Option<MessageEnvelope>, IngestError> {
        if !matches!(self.state, ConnectionState::Bound) {
            return Err(IngestError::AdapterDisabled);
        }

        let from =
            CourierAddress::new(message.from.clone()).map_err(|_| IngestError::MalformedEvent {
                reason: "invalid sender address".to_owned(),
            })?;
        let message_id = ProviderMessageId::new(message.id.to_string()).map_err(|e| {
            IngestError::MalformedEvent {
                reason: e.to_string(),
            }
        })?;

        // Explicit principal mapping; fail closed on ambiguity or absence.
        // This is a pure lookup with no side effects, so it runs BEFORE the
        // dedupe insert: a message rejected here must not record a dedupe
        // key, otherwise a redelivery after the operator maps the identity
        // would collapse to Skip and the message would be lost.
        let resolution = self.registry.resolve(Provider::Courier, from.as_str());
        if matches!(resolution, PrincipalResolution::Ambiguous) {
            return Err(IngestError::AmbiguousIdentity);
        }
        if matches!(resolution, PrincipalResolution::Unknown) {
            return Err(IngestError::UnknownIdentity);
        }

        // Deduplicate BEFORE the event may enter a Pi session.
        let connection_id = self
            .binding
            .as_ref()
            .ok_or(IngestError::AuthLost {
                reason: "no connection binding".to_owned(),
            })?
            .connection_id
            .clone();
        let dedupe_key = DedupeKey::compute(Provider::Courier, &connection_id, &message_id);
        match DedupeDecision::decide(self.dedupe.check_and_insert(&dedupe_key))? {
            DedupeDecision::Proceed => {}
            // Known redelivery: the first delivery already entered the
            // pipeline. Skip without disturbing the batch.
            DedupeDecision::Skip => return Ok(None),
        }

        // VHL carriage: split the body; the carriage is carried, not trusted.
        // Verification against the kernel approval store is TODO(PHASE4).
        let (vhl_carriage, text) = VhlCourierCarriage::decode_body(&message.body);
        let _ = vhl_carriage;

        let conversation = match (&message.group_id, &message.channel_id) {
            (Some(group), _) => {
                Conversation::channel(format!("courier:group:{group}")).map_err(|e| {
                    IngestError::MalformedEvent {
                        reason: e.to_string(),
                    }
                })?
            }
            (None, Some(channel)) => Conversation::channel(format!("courier:channel:{channel}"))
                .map_err(|e| IngestError::MalformedEvent {
                    reason: e.to_string(),
                })?,
            (None, None) => {
                Conversation::direct(from.as_str()).map_err(|e| IngestError::MalformedEvent {
                    reason: e.to_string(),
                })?
            }
        };

        let mut reply_context = ReplyContext::default();
        if let Some(reply_to) = message.reply_to {
            reply_context.quotes_message_id = Some(reply_to.to_string());
        }

        let sender =
            SenderIdentity::new(from.as_str(), resolution.verification()).map_err(|e| {
                IngestError::MalformedEvent {
                    reason: e.to_string(),
                }
            })?;

        let provenance = Provenance::new("courier", ADAPTER_VERSION, raw_event).map_err(|e| {
            IngestError::MalformedEvent {
                reason: e.to_string(),
            }
        })?;

        // Courier timestamps are Unix seconds (grounded in the Go client).
        let received_at_millis = message.received_at.saturating_mul(1000);

        Ok(Some(
            MessageEnvelope::new(
                Provider::Courier,
                connection_id,
                conversation,
                sender,
                message_id,
                text,
                Vec::new(),
                reply_context,
                received_at_millis,
                provenance,
                if message.bridged {
                    TransportTrust::ProviderTerminated
                } else {
                    TransportTrust::EndToEndEncrypted
                },
                now_millis,
            )
            .map_err(|e| IngestError::MalformedEvent {
                reason: e.to_string(),
            })?,
        ))
    }

    fn transport(&self) -> Result<&CourierStdioTransport, AdapterError> {
        if !matches!(self.state, ConnectionState::Bound) {
            return Err(AdapterError::NotBound);
        }
        self.transport.as_ref().ok_or(AdapterError::NotBound)
    }
}

#[async_trait]
impl MessagingAdapter for CourierAdapter {
    fn descriptor(&self) -> &AdapterDescriptor {
        &self.descriptor
    }

    fn descriptor_provider(&self) -> Provider {
        Provider::Courier
    }

    fn state(&self) -> ConnectionState {
        // A dead child is lost authentication: block outbound effects.
        if matches!(self.state, ConnectionState::Bound)
            && let Some(transport) = &self.transport
            && !transport.is_live()
        {
            return ConnectionState::AuthLost {
                reason: "courier stdio subprocess died".to_owned(),
            };
        }
        self.state.clone()
    }

    fn bound_connection_id(&self) -> Option<&ConnectionId> {
        self.binding.as_ref().map(|b| &b.connection_id)
    }

    async fn bind(
        &mut self,
        binding: ConnectionBinding,
        config: &MessagingConfig,
    ) -> Result<(), AdapterError> {
        if !config.courier_enabled {
            return Err(AdapterError::Disabled);
        }
        // The helper binary is a trust root: validate it before executing
        // anything. Absolute path (no PATH resolution), a root-owned
        // non-writable parent (no hash/exec swap), and a well-formed
        // mandatory digest pin, or bind fails closed here.
        validate_binary_config(&self.config).map_err(|e: CourierError| {
            AdapterError::Transport {
                reason: e.to_string(),
            }
        })?;
        // Verify the actual digest BEFORE the binary runs even once: the
        // version check below executes the helper, so a substituted binary
        // must be rejected here, not after its first execution.
        verify_binary_digest(&self.config).map_err(|e: CourierError| AdapterError::Transport {
            reason: e.to_string(),
        })?;
        // Pin the reviewed CLI before trusting it with anything. This is a
        // blocking child process call; run it off the async executor.
        let binary = self.config.binary.clone();
        let min_version = self.config.min_version.clone();
        let identity_dir = self.config.identity_dir.clone();
        let version = tokio::task::spawn_blocking(move || {
            check_cli_version(&binary, &min_version, identity_dir.as_ref())
        })
        .await
        .map_err(|e| AdapterError::Transport {
            reason: format!("courier version check panicked: {e}"),
        })?
        .map_err(|e: CourierError| AdapterError::Transport {
            reason: e.to_string(),
        })?;
        let _ = version;

        let transport =
            CourierStdioTransport::spawn(&self.config)
                .await
                .map_err(|e: CourierError| AdapterError::Transport {
                    reason: e.to_string(),
                })?;

        self.transport = Some(transport);
        self.binding = Some(binding);
        self.state = ConnectionState::Bound;
        Ok(())
    }

    fn revoke(&mut self) {
        // Dropping the transport kills the supervised child; the credential
        // handle (kernel-brokered) is invalidated by dropping the binding.
        self.transport = None;
        self.binding = None;
        self.session = None;
        self.state = ConnectionState::Revoked {
            reason: "operator revoked the Courier connection".to_owned(),
        };
    }

    fn ingest(
        &self,
        raw_event: &[u8],
        now_millis: i64,
    ) -> Result<Option<MessageEnvelope>, IngestError> {
        // Authenticated-transport gate: only bytes actually emitted by the
        // supervised, digest-pinned bridge may enter. Courier's Ed25519
        // signatures are verified by the CLI on receipt; the adapter's half
        // is proving these bytes came from that CLI. This runs before
        // parsing and before dedupe, so forged bytes can neither map a
        // sender nor preempt legitimate messages via event-ID dedupe.
        if !self.was_bridge_delivered(raw_event) {
            return Err(IngestError::SignatureVerificationFailed);
        }
        let message: StdioMessage =
            serde_json::from_slice(raw_event).map_err(|e| IngestError::MalformedEvent {
                reason: format!("not courier message JSON: {e}"),
            })?;
        self.ingest_message(raw_event, &message, now_millis)
    }

    async fn execute_outbound(
        &self,
        request: &OutboundRequest,
    ) -> Result<ProviderReceipt, AdapterError> {
        let transport = self.transport()?;
        if request.provider != Provider::Courier {
            return Err(AdapterError::Transport {
                reason: "courier adapter received a non-courier request".to_owned(),
            });
        }

        match request.verb {
            crate::outbound::OutboundVerb::Send => {}
            _ => {
                return Err(AdapterError::Transport {
                    reason: format!(
                        "courier transport supports only the send verb (requested {})",
                        request.verb.as_str()
                    ),
                });
            }
        }

        let to = match &request.target {
            crate::outbound::OutboundTarget::DirectRecipient { external_id } => {
                CourierAddress::new(external_id.clone()).map_err(|_| AdapterError::Transport {
                    reason: "invalid courier recipient address".to_owned(),
                })?
            }
            crate::outbound::OutboundTarget::Conversation(_) => {
                return Err(AdapterError::Transport {
                    reason: "courier group/channel sends are not yet mapped; use direct recipients"
                        .to_owned(),
                });
            }
        };

        let body = match &request.approval {
            Some(approval) => VhlCourierCarriage::from_approval(approval)
                .encode_body(request.text.as_deref().unwrap_or("")),
            None => request.text.clone().unwrap_or_default(),
        };

        let reply_to = request
            .target_message_id
            .as_ref()
            .map(|id| {
                id.as_str()
                    .parse::<i64>()
                    .map_err(|_| AdapterError::Transport {
                        reason: "courier reply target is not a numeric message id".to_owned(),
                    })
            })
            .transpose()?;

        let message_id =
            transport
                .send(&to, &body, reply_to)
                .await
                .map_err(|e| AdapterError::Transport {
                    reason: e.to_string(),
                })?;

        Ok(ProviderReceipt::now(
            Provider::Courier,
            message_id.to_string(),
        ))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum CourierError {
    #[error("invalid courier address")]
    InvalidAddress,
    #[error("invalid session binding")]
    InvalidSession,
    #[error("courier binary hash mismatch: expected {expected}, got {actual}")]
    BinaryHashMismatch { expected: String, actual: String },
    #[error("courier binary must be an absolute path; PATH resolution is not allowed")]
    RelativeBinaryPath,
    #[error(
        "courier binary digest pin (expected_binary_sha256) is required; refusing to run an unpinned helper"
    )]
    BinaryPinRequired,
    #[error("malformed courier binary digest pin: expected 64 hex characters")]
    MalformedBinaryPin,
    #[error("courier binary parent directory is writable by group/other (swap risk): {0}")]
    BinaryParentWritable(String),
    #[error("courier binary parent directory is not root-owned (swap risk): {0}")]
    BinaryParentNotRootOwned(String),
    #[error("courier identity dir must be a mode-0700 directory: {0}")]
    IdentityDirInsecure(String),
    #[error("unsupported courier CLI version: found {found}, minimum {min}")]
    UnsupportedCliVersion { found: String, min: String },
    #[error("courier transport error: {reason}")]
    Transport { reason: String },
    #[error("handoff payload too large: {bytes} bytes")]
    HandoffTooLarge { bytes: usize },
    #[error("malformed handoff artifact")]
    MalformedHandoff,
    #[error("handoff payload digest mismatch")]
    HandoffDigestMismatch,
    #[error("vhl payload error: {reason}")]
    Vhl { reason: String },
}

impl From<CourierError> for AdapterError {
    fn from(error: CourierError) -> Self {
        AdapterError::Transport {
            reason: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::CredentialHandle;
    use crate::dedupe::MemoryDedupeStore;
    use crate::envelope::{ConnectionId, TransportTrust};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_millis() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    fn test_adapter() -> CourierAdapter {
        let mut registry = PrincipalMappingRegistry::new();
        registry
            .register(
                Provider::Courier,
                "ed25519:sender",
                lumen_core::identity::PrincipalId::new("bct", "sender").unwrap(),
            )
            .unwrap();
        let mut adapter = CourierAdapter::new(
            CourierConfig::default(),
            Arc::new(registry),
            Arc::new(MemoryDedupeStore::new(60_000)),
        );
        // Simulate a bound adapter without spawning a child: tests target
        // ingest logic, not the subprocess.
        adapter.state = ConnectionState::Bound;
        adapter.binding = Some(
            ConnectionBinding::new(
                ConnectionId::new("conn-1").unwrap(),
                "bct-account",
                CredentialHandle::new("handle-1").unwrap(),
            )
            .unwrap(),
        );
        adapter
    }

    fn wake_json(from: &str, id: i64, body: &str, bridged: bool) -> Vec<u8> {
        let now_secs = now_millis() / 1000;
        serde_json::to_vec(&serde_json::json!({
            "id": id,
            "from": from,
            "body": body,
            "sent_at": now_secs,
            "received_at": now_secs,
            "bridged": bridged,
        }))
        .unwrap()
    }

    #[test]
    fn ingest_verifies_maps_and_dedupes() {
        let adapter = test_adapter();
        let now = now_millis();
        let raw = wake_json("ed25519:sender", 42, "hello", false);
        // The bytes must have come from the supervised bridge.
        adapter.note_bridge_delivery(&raw);
        let env = adapter
            .ingest(&raw, now)
            .unwrap()
            .expect("first delivery ingests");
        assert_eq!(env.provider, Provider::Courier);
        assert_eq!(env.content, "hello");
        assert!(env.sender_is_verified());
        assert_eq!(env.transport_trust, TransportTrust::EndToEndEncrypted);
        assert_eq!(env.received_at_millis, (now / 1000) * 1000);

        // Duplicate delivery collapses to None: the batch continues and the
        // envelope is not re-emitted.
        assert_eq!(adapter.ingest(&raw, now).unwrap(), None);
    }

    #[test]
    fn duplicate_in_batch_does_not_disturb_siblings() {
        let adapter = test_adapter();
        let now = now_millis();
        let a = wake_json("ed25519:sender", 42, "a", false);
        let b = wake_json("ed25519:sender", 43, "b", false);
        adapter.note_bridge_delivery(&a);
        adapter.note_bridge_delivery(&b);
        // Batch: A, A-redelivery, B — the redelivery must not abort the batch.
        let mut envelopes = Vec::new();
        for raw in [&a, &a, &b] {
            if let Some(env) = adapter.ingest(raw, now).unwrap() {
                envelopes.push(env);
            }
        }
        assert_eq!(envelopes.len(), 2);
        assert_eq!(envelopes[0].content, "a");
        assert_eq!(envelopes[1].content, "b");
    }

    #[test]
    fn ingest_fails_closed_on_unknown_sender() {
        let adapter = test_adapter();
        let raw = wake_json("ed25519:stranger", 43, "hello", false);
        adapter.note_bridge_delivery(&raw);
        assert_eq!(
            adapter.ingest(&raw, now_millis()).unwrap_err(),
            IngestError::UnknownIdentity
        );
    }

    #[test]
    fn bridged_messages_are_marked_provider_terminated() {
        let adapter = test_adapter();
        let raw = wake_json("ed25519:sender", 44, "hello", true);
        adapter.note_bridge_delivery(&raw);
        let env = adapter
            .ingest(&raw, now_millis())
            .unwrap()
            .expect("first delivery ingests");
        assert!(env.transport_is_untrusted());
    }

    #[test]
    fn ingest_rejects_bytes_never_delivered_by_bridge() {
        let adapter = test_adapter();
        let now = now_millis();
        // Well-formed JSON from a mapped sender — but the supervised bridge
        // never emitted these bytes.
        let forged = wake_json("ed25519:sender", 42, "forged command", false);
        assert_eq!(
            adapter.ingest(&forged, now).unwrap_err(),
            IngestError::SignatureVerificationFailed
        );

        // The same bytes, once genuinely delivered by the bridge, ingest.
        adapter.note_bridge_delivery(&forged);
        assert!(adapter.ingest(&forged, now).unwrap().is_some());
    }

    #[test]
    fn forged_event_id_cannot_preempt_dedupe() {
        let adapter = test_adapter();
        let now = now_millis();
        // Forged bytes reuse a legitimate event id but were never delivered.
        let forged = wake_json("ed25519:sender", 99, "forged", false);
        assert_eq!(
            adapter.ingest(&forged, now).unwrap_err(),
            IngestError::SignatureVerificationFailed
        );

        // The gate runs before dedupe, so the forged bytes did not consume
        // the dedupe slot: the real delivery still ingests exactly once.
        let legit = wake_json("ed25519:sender", 99, "legit", false);
        adapter.note_bridge_delivery(&legit);
        let env = adapter
            .ingest(&legit, now)
            .unwrap()
            .expect("legit delivery ingests");
        assert_eq!(env.content, "legit");
        assert_eq!(adapter.ingest(&legit, now).unwrap(), None);
    }

    #[test]
    fn vhl_carriage_round_trips_through_body() {
        let carriage = VhlCourierCarriage {
            approval_id: "approval-1".to_owned(),
            action_digest: "digest-abc".to_owned(),
            nonce: "nonce-1".to_owned(),
            expires_at_millis: 1_000_000,
        };
        let body = carriage.encode_body("please approve");
        let (decoded, text) = VhlCourierCarriage::decode_body(&body);
        assert_eq!(decoded, Some(carriage));
        assert_eq!(text, "please approve");

        let (none, plain) = VhlCourierCarriage::decode_body("just text");
        assert_eq!(none, None);
        assert_eq!(plain, "just text");
    }

    #[test]
    fn handoff_artifact_digest_is_verified_on_decode() {
        let mut artifact =
            HandoffArtifact::new("a1", "session-a", "session-b", b"state".to_vec()).unwrap();
        artifact.countersign(HandoffSignature {
            signer_address: "ed25519:sender".to_owned(),
            signature: "00".repeat(64),
        });
        let body = artifact.encode_body().unwrap();
        let decoded = HandoffArtifact::decode_body(&body).unwrap();
        assert_eq!(decoded, artifact);
        assert_eq!(decoded.signatures.len(), 1);

        // Tampered payload fails closed.
        let mut tampered: serde_json::Value = serde_json::from_str(&body).unwrap();
        tampered["payload"] = serde_json::json!([9, 9, 9]);
        let tampered_body = serde_json::to_string(&tampered).unwrap();
        assert_eq!(
            HandoffArtifact::decode_body(&tampered_body).unwrap_err(),
            CourierError::HandoffDigestMismatch
        );
    }

    #[test]
    fn version_parsing_and_comparison() {
        assert_eq!(
            extract_version("courier version v0.13.1").as_deref(),
            Some("0.13.1")
        );
        assert_eq!(extract_version("0.11.0").as_deref(), Some("0.11.0"));
        assert!(version_gte("0.13.1", "0.13.0"));
        assert!(version_gte("0.13.0", "0.13.0"));
        assert!(!version_gte("0.12.9", "0.13.0"));
        assert!(!version_gte("1.0.0", "2.0.0"));
    }

    #[test]
    fn address_validation() {
        assert!(CourierAddress::new("ed25519:abc").is_ok());
        assert!(CourierAddress::new("not-an-address").is_err());
        assert!(CourierAddress::new("ed25519:").is_err());
    }

    #[tokio::test]
    async fn bind_refuses_when_disabled() {
        let mut adapter = test_adapter();
        adapter.state = ConnectionState::Unbound;
        adapter.binding = None;
        let binding = ConnectionBinding::new(
            ConnectionId::new("conn-1").unwrap(),
            "bct-account",
            CredentialHandle::new("handle-1").unwrap(),
        )
        .unwrap();
        let config = MessagingConfig {
            courier_enabled: false,
            ..Default::default()
        };
        assert_eq!(
            adapter.bind(binding, &config).await.unwrap_err(),
            AdapterError::Disabled
        );
    }

    fn bind_config() -> (CourierAdapter, ConnectionBinding, MessagingConfig) {
        let adapter = test_adapter();
        let binding = ConnectionBinding::new(
            ConnectionId::new("conn-1").unwrap(),
            "bct-account",
            CredentialHandle::new("handle-1").unwrap(),
        )
        .unwrap();
        let config = MessagingConfig {
            courier_enabled: true,
            ..Default::default()
        };
        (adapter, binding, config)
    }

    #[tokio::test]
    async fn bind_rejects_unpinned_binary() {
        let (mut adapter, binding, config) = bind_config();
        // Absolute path but no digest pin: bind must fail closed before the
        // binary is ever executed (no `courier` on disk needed).
        //
        // The dummy path lives under /usr/bin (not /usr/local/bin): the
        // parent-directory trust check runs before the pin checks, and
        // /usr/local/bin is group-writable for unprivileged users on some
        // hosts (e.g. GitHub Actions runners), which would fail the test
        // with BinaryParentWritable instead of exercising the pin check.
        // /usr/bin is root-owned and non-writable on every supported
        // platform, so the pin check is what actually fires here.
        adapter.config.binary = PathBuf::from("/usr/bin/courier");
        let err = adapter.bind(binding, &config).await.unwrap_err();
        assert_eq!(
            err,
            AdapterError::Transport {
                reason: CourierError::BinaryPinRequired.to_string(),
            }
        );
    }

    #[tokio::test]
    async fn bind_rejects_relative_binary_path() {
        let (mut adapter, binding, config) = bind_config();
        adapter.config.binary = PathBuf::from("courier");
        adapter.config.expected_binary_sha256 = Some("a".repeat(64));
        let err = adapter.bind(binding, &config).await.unwrap_err();
        assert_eq!(
            err,
            AdapterError::Transport {
                reason: CourierError::RelativeBinaryPath.to_string(),
            }
        );
    }

    #[tokio::test]
    async fn bind_rejects_malformed_pin() {
        let (mut adapter, binding, config) = bind_config();
        // /usr/bin, not /usr/local/bin: see bind_rejects_unpinned_binary
        // for why the dummy path must sit under a root-owned,
        // non-group-writable parent on every host.
        adapter.config.binary = PathBuf::from("/usr/bin/courier");
        adapter.config.expected_binary_sha256 = Some("not-hex".to_owned());
        let err = adapter.bind(binding, &config).await.unwrap_err();
        assert_eq!(
            err,
            AdapterError::Transport {
                reason: CourierError::MalformedBinaryPin.to_string(),
            }
        );
    }

    #[test]
    fn child_env_is_scrubbed() {
        // SAFETY: no other test in this binary reads these variables, and
        // they are removed before the test returns.
        unsafe {
            std::env::set_var("LUMEN_COURIER_TEST_SECRET", "s3cr3t");
            std::env::set_var("https_proxy", "http://proxy:8080");
        }

        let env = child_env(None);
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());

        // Ambient secrets never reach the helper.
        assert_eq!(get("LUMEN_COURIER_TEST_SECRET"), None);
        // Proxy variables pass through so the client keeps working.
        assert_eq!(get("https_proxy").as_deref(), Some("http://proxy:8080"));
        // No session identity bound: ambient HOME is preserved.
        assert_eq!(
            get("HOME").as_deref(),
            std::env::var("HOME").ok().as_deref()
        );

        // Bound session identity: HOME points at the kernel-owned dir.
        let dir = PathBuf::from("/run/lumen/session-1");
        let env = child_env(Some(&dir));
        let get = |k: &str| env.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
        assert_eq!(get("HOME").as_deref(), Some("/run/lumen/session-1"));

        // SAFETY: paired with the setup above; no other test reads these.
        unsafe {
            std::env::remove_var("LUMEN_COURIER_TEST_SECRET");
            std::env::remove_var("https_proxy");
        }
    }

    #[cfg(unix)]
    #[test]
    fn binary_parent_must_not_be_group_writable() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("lumen-courier-parent-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();

        // Writable by group/other: the verified file could be swapped
        // between the digest check and exec.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            validate_binary_parent(&dir.join("courier")),
            Err(CourierError::BinaryParentWritable(_))
        ));

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn identity_dir_requires_0700() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "lumen-courier-identity-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            check_identity_dir(&dir),
            Err(CourierError::IdentityDirInsecure(_))
        ));

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(check_identity_dir(&dir).is_ok());

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
