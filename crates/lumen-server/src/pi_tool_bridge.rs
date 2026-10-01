//! Proposed PiBridge v2 tool transport. Pi sends intent over its existing RPC
//! extension-dialog channel; authority and execution remain on the host.
//!
//! This codec is not launch admission. Both reference launchers remain disabled
//! until confinement and the real-sandbox vertical slice pass the Phase-0 gate.

use std::collections::HashSet;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{KernelClient, PiToolRequest, SandboxRunner, ToolOutcome, ToolPipeline};

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
    pub action_digest: String,
    pub outcome: ToolOutcome,
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
