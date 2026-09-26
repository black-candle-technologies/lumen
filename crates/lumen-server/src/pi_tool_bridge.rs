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
            || !(1..=1_048_576).contains(&request.arguments.max_bytes)
        {
            return Err(BridgeError::InvalidRequest);
        }
        Ok(request)
    }
}

/// Result bytes, usage, and audit reference are produced only by the host's
/// pipeline. An allow-only response has no representation in this protocol.
#[derive(Debug, Clone, Serialize)]
pub struct PiToolReply {
    pub version: u32,
    pub tool_call_id: String,
    pub action_digest: String,
    pub outcome: ToolOutcome,
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
        let digest = envelope.digest().map_err(|_| BridgeError::InvalidRequest)?;
        let outcome = pipeline.execute_envelope(&envelope, &self.subject).await;
        Ok(PiToolReply {
            version: PI_TOOL_BRIDGE_VERSION,
            tool_call_id: request.tool_call_id,
            action_digest: digest,
            outcome,
        })
    }
}
