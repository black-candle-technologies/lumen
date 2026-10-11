//! Proposed PiBridge v2 tool transport. Pi sends intent over its existing RPC
//! extension-dialog channel; authority and execution remain on the host.
//!
//! This codec is not launch admission. Both reference launchers remain disabled
//! until confinement and the real-sandbox vertical slice pass the Phase-0 gate.

use std::{
    collections::HashSet,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KernelClient, PiToolRequest, SandboxRunner, ToolOutcome, ToolPipeline};

/// Maximum dialog-id length; Pi's ids are short strings and the probe
/// enforces the same bound against the real pinned Pi runtime.
const MAX_DIALOG_ID_CHARS: usize = 128;
const MAX_DIALOG_TITLE_CHARS: usize = 256;

pub const PI_TOOL_BRIDGE_VERSION: u32 = 2;
pub const PI_TOOL_BRIDGE_TITLE: &str = "lumen.pi-bridge/2";
pub const MAX_BRIDGE_REQUEST_BYTES: usize = 16 * 1024;
// PiBridge v2 budget, mirrored in host-client.ts and checked against
// lumen-protocol/fixtures/pibridge_reply_budget.v2.json by both test suites.
pub const MAX_BRIDGE_READ_BYTES: u32 = 1_048_576;
pub const MAX_BRIDGE_METADATA_BYTES: usize = 16 * 1024;
pub const MAX_BRIDGE_REPLY_BYTES: usize =
    6 * MAX_BRIDGE_READ_BYTES as usize + MAX_BRIDGE_METADATA_BYTES;
pub const MAX_SESSION_TOOL_CALLS: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadArguments {
    pub path: String,
    pub max_bytes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiReadRequest {
    pub version: u32,
    pub tool_call_id: String,
    pub tool: String,
    pub arguments: ReadArguments,
}

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("invalid PiBridge v2 request")]
    InvalidRequest,
    #[error("duplicate tool call; a new request is required")]
    Replay,
    #[error("session tool request limit reached")]
    Limit,
    #[error("host bridge unavailable")]
    Unavailable,
    #[error("host reply exceeded PiBridge v2 budget")]
    ReplyLimit,
}

impl PiReadRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, BridgeError> {
        if bytes.len() > MAX_BRIDGE_REQUEST_BYTES {
            return Err(BridgeError::InvalidRequest);
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| BridgeError::InvalidRequest)?;
        if request.version != PI_TOOL_BRIDGE_VERSION
            || request.tool != "bct.read_file"
            || request.tool_call_id.is_empty()
            || request.tool_call_id.len() > 128
            || !request
                .tool_call_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || !request.arguments.path.starts_with('/')
            || request.arguments.path.len() > 4096
            || request.arguments.path.contains('\0')
            || !(1..=MAX_BRIDGE_READ_BYTES).contains(&request.arguments.max_bytes)
        {
            return Err(BridgeError::InvalidRequest);
        }
        Ok(request)
    }
}

/// Result bytes, usage, and audit reference are produced only by the host's
/// pipeline. An allow-only response has no representation in this protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PiToolReply {
    pub version: u32,
    pub tool_call_id: String,
    pub action_digest: crate::kernel_client::CoreActionDigest,
    pub outcome: ToolOutcome,
}

/// One `extension_ui_request` dialog frame from Pi's documented RPC
/// (`{"type":"extension_ui_request", "id", "method", "title",
/// "placeholder", "timeout"}`). The field set is validated against the
/// real pinned Pi v0.87.1 by the phase-0 denial probe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PiDialogRequest {
    pub id: String,
    pub method: String,
    pub title: String,
    pub placeholder: String,
    pub timeout: u64,
}

impl PiDialogRequest {
    /// Strict dialog decode from the event's raw JSON value: exact field
    /// set and bounded lengths. Authority-bearing fields are ipso facto
    /// none — the dialog carries intent only.
    pub fn decode(value: &serde_json::Value) -> Result<Self, BridgeError> {
        let map = value.as_object().ok_or(BridgeError::InvalidRequest)?;
        let fields = ["id", "method", "title", "placeholder", "timeout"];
        if fields.iter().any(|field| !map.contains_key(*field))
            || map.iter().any(|(key, _)| !fields.contains(&key.as_str()))
        {
            return Err(BridgeError::InvalidRequest);
        }
        let dialog: Self =
            serde_json::from_value(value.clone()).map_err(|_| BridgeError::InvalidRequest)?;
        if dialog.id.is_empty()
            || dialog.id.len() > MAX_DIALOG_ID_CHARS
            || !dialog
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.:-".contains(&b))
            || dialog.method.is_empty()
            || dialog.method.len() > 64
            || dialog.title.is_empty()
            || dialog.title.len() > MAX_DIALOG_TITLE_CHARS
            || dialog.timeout == 0
        {
            return Err(BridgeError::InvalidRequest);
        }
        Ok(dialog)
    }

    /// The machine rejection value sent for unknown or unusable dialogs
    /// (unknown titles/methods, undecodable intent, bridge errors). It is
    /// deliberately outside the v2 reply shape: without a decoded intent
    /// there is no tool call id to correlate a v2 outcome to, and an
    /// explicit bounded refusal still fails the extension closed.
    pub fn machine_rejection(reason: &str) -> String {
        serde_json::json!({"rejected": reason}).to_string()
    }
}

/// Encode one `extension_ui_response` frame line for Pi's child stdin.
pub fn encode_dialog_response(dialog_id: &str, value: &str) -> Vec<u8> {
    let frame = serde_json::json!({
        "type": "extension_ui_response",
        "id": dialog_id,
        "value": value,
    });
    let mut bytes = serde_json::to_vec(&frame).expect("dialog response serialization");
    bytes.push(b'\n');
    bytes
}

/// Generation-scoped tool bridge seam for the session supervisor. One
/// instance exists per live child generation; the supervisor drops and
/// recreates it on every spawn, so claim sets never cross a restart and
/// a terminated child's bridge is unreachable.
pub trait SessionToolBridge: Send + Sync {
    /// Drive exactly one bounded stdio v2 intent through the host's
    /// kernel-owned authority and sandbox path.
    fn dispatch<'a>(&'a self, intent: &'a [u8]) -> BridgeFuture<'a>;
}

pub type BridgeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PiToolReply, BridgeError>> + Send + 'a>>;

/// Bridge factory: the supervisor calls it once per freshly minted
/// kernel identity. Implementations resolve the subject's lease chain
/// through the kernel, never from caller-supplied runtime state.
pub trait SessionToolBridgeFactory: Send + Sync {
    fn create(&self, subject: &str) -> Result<Arc<dyn SessionToolBridge>, BridgeError>;
}

/// Concrete bridge binding one pipeline to one subject generation.
pub struct PipelineToolBridge<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized> {
    bridge: PiToolBridge,
    pipeline: Arc<ToolPipeline<K, S>>,
}

impl<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized> PipelineToolBridge<K, S> {
    pub fn new(
        subject: impl Into<String>,
        lease_chain: Vec<String>,
        pipeline: Arc<ToolPipeline<K, S>>,
    ) -> Self {
        Self {
            bridge: PiToolBridge::new(subject.into(), lease_chain),
            pipeline,
        }
    }
}

impl<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized> SessionToolBridge
    for PipelineToolBridge<K, S>
{
    fn dispatch<'a>(&'a self, intent: &'a [u8]) -> BridgeFuture<'a> {
        Box::pin(self.bridge.dispatch(self.pipeline.as_ref(), intent))
    }
}

/// Factory over a fixed lease chain resolved outside the session: the
/// operator-plane integrates the kernel lease issuance for the new
/// identity before supervision starts. Lease minting itself belongs to
/// the kernel; this factory only binds an already-minted chain.
pub struct PipelineBridgeFactory<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized> {
    lease_chain: Vec<String>,
    catalog: Arc<crate::tool_catalog::Catalog>,
    kernel: Arc<K>,
    sandbox: Arc<S>,
}

impl<K: KernelClient + ?Sized + 'static, S: SandboxRunner + ?Sized + 'static>
    PipelineBridgeFactory<K, S>
{
    pub fn new(
        lease_chain: Vec<String>,
        catalog: Arc<crate::tool_catalog::Catalog>,
        kernel: Arc<K>,
        sandbox: Arc<S>,
    ) -> Self {
        Self {
            lease_chain,
            catalog,
            kernel,
            sandbox,
        }
    }
}

impl<K: KernelClient + ?Sized + 'static, S: SandboxRunner + ?Sized + 'static>
    SessionToolBridgeFactory for PipelineBridgeFactory<K, S>
{
    fn create(&self, subject: &str) -> Result<Arc<dyn SessionToolBridge>, BridgeError> {
        let pipeline = ToolPipeline::new(
            Arc::clone(&self.catalog),
            Arc::clone(&self.kernel),
            Arc::clone(&self.sandbox),
        );
        Ok(Arc::new(PipelineToolBridge::new(
            subject,
            self.lease_chain.clone(),
            Arc::new(pipeline),
        )))
    }
}

impl std::fmt::Debug for dyn SessionToolBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToolBridge")
    }
}

impl std::fmt::Debug for dyn SessionToolBridgeFactory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionToolBridgeFactory")
    }
}

impl PiToolReply {
    /// Encode the inner dialog reply with both decoded and wire bounds.
    pub fn encode(&self, max_bytes: u32) -> Result<Vec<u8>, BridgeError> {
        if !(1..=MAX_BRIDGE_READ_BYTES).contains(&max_bytes) {
            return Err(BridgeError::ReplyLimit);
        }
        if let ToolOutcome::Completed { result, .. } | ToolOutcome::Uncertain { result, .. } =
            &self.outcome
        {
            let output = result["output_tail"]
                .as_str()
                .ok_or(BridgeError::ReplyLimit)?;
            if output.len() > max_bytes as usize {
                return Err(BridgeError::ReplyLimit);
            }
        }
        let mut metadata = serde_json::to_value(self).map_err(|_| BridgeError::Unavailable)?;
        if matches!(
            self.outcome,
            ToolOutcome::Completed { .. } | ToolOutcome::Uncertain { .. }
        ) {
            metadata["outcome"]["result"]["output_tail"] = "".into();
        }
        if serde_json::to_vec(&metadata)
            .map_err(|_| BridgeError::Unavailable)?
            .len()
            > MAX_BRIDGE_METADATA_BYTES
        {
            return Err(BridgeError::ReplyLimit);
        }
        // JSON can escape each decoded UTF-8 byte as six bytes (e.g. U+0001).
        // 6 * 1,048,576 + 16,384 = 6,307,840 wire bytes. The metadata bound
        // includes the envelope and empty output string, leaving 16 KiB of margin
        // beyond the worst-case escaped payload. Keep the decoded bound above too.
        let bytes = serde_json::to_vec(self).map_err(|_| BridgeError::Unavailable)?;
        if bytes.len() > MAX_BRIDGE_REPLY_BYTES {
            return Err(BridgeError::ReplyLimit);
        }
        Ok(bytes)
    }
}

/// Created by the host for one live child generation. Pi cannot supply the
/// subject, lease chain, resources, effects, nonce, or action deadline.
/// Never reuse this object for a restarted Pi process.
pub struct PiToolBridge {
    subject: String,
    lease_chain: Vec<String>,
    seen: Mutex<HashSet<String>>,
}

impl PiToolBridge {
    pub fn new(subject: String, lease_chain: Vec<String>) -> Self {
        Self {
            subject,
            lease_chain,
            seen: Mutex::new(HashSet::new()),
        }
    }

    pub async fn dispatch<K: KernelClient + ?Sized, S: SandboxRunner + ?Sized>(
        &self,
        pipeline: &ToolPipeline<K, S>,
        bytes: &[u8],
    ) -> Result<PiToolReply, BridgeError> {
        let request = PiReadRequest::decode(bytes)?;
        let max_bytes = request.arguments.max_bytes;
        // Claim before any await: concurrent duplicates cannot both create an
        // action. Retain failed attempts too; there is no hidden retry.
        {
            let mut seen = self.seen.lock().map_err(|_| BridgeError::Unavailable)?;
            if seen.contains(&request.tool_call_id) {
                return Err(BridgeError::Replay);
            }
            if seen.len() >= MAX_SESSION_TOOL_CALLS {
                return Err(BridgeError::Limit);
            }
            seen.insert(request.tool_call_id.clone());
        }
        let intent = PiToolRequest {
            id: request.tool_call_id.clone(),
            tool: request.tool,
            arguments: serde_json::to_value(request.arguments)
                .map_err(|_| BridgeError::InvalidRequest)?,
        };
        let envelope = pipeline
            .build_envelope(&intent, &self.subject, &self.lease_chain)
            .map_err(|_| BridgeError::InvalidRequest)?;
        // Use the same kernel identity as the pipeline's execution audits
        // and uncertain outcome, including kernels using the trait default.
        let digest = pipeline
            .kernel()
            .authoritative_action_digest(&envelope)
            .map_err(|_| BridgeError::Unavailable)?;
        let outcome = pipeline.execute_envelope(&envelope, &self.subject).await;
        let reply = PiToolReply {
            version: PI_TOOL_BRIDGE_VERSION,
            tool_call_id: request.tool_call_id,
            action_digest: digest,
            outcome,
        };
        reply.encode(max_bytes)?;
        Ok(reply)
    }
}
