//! Guest agent protocol (vsock, host ↔ guest).
//!
//! The guest agent (`lumen-guest-agent` binary) runs inside the microVM and
//! is the ONLY guest component the host trusts to speak for the workload.
//! It is baked into the signed read-only guest image, so its bytes are
//! covered by image provenance ([`crate::provenance`]).
//!
//! Transport: vsock, guest dials host CID 2 on a per-run port. The port and
//! the 128-bit run id are both unpredictable; the host binds the accepted
//! connection to the expected run id on first message and drops anything
//! else.
//!
//! Framing: `u32` big-endian length prefix + JSON body, capped at
//! [`MAX_FRAME_BYTES`]. Binary payloads (stdio chunks, file data) travel as
//! base64 inside the JSON — simple to audit, bounded by the frame cap.
//!
//! Message flow:
//!
//! ```text
//! guest: Hello { version, run_id, nonce }
//! host:  Welcome { run_id, argv, env, deadline_ms } | Deny { reason }
//! guest: Stdout/Stderr chunks … (bounded by policy)
//! guest: ExportBegin { files } → per file: ExportFile meta, ExportData*
//! host:  ExportAck { path } | ExportReject { reason }  (whole export dies)
//! guest: ExportEnd
//! guest: Exit { code }
//! either: Heartbeat (keepalive; missed heartbeats trip the host watchdog)
//! host:  Cancel (deadline / kernel cancel → agent SIGKILLs the workload)
//! ```

use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::SandboxdError;

/// Protocol version. The host rejects any other version at handshake.
pub const PROTOCOL_VERSION: u32 = 1;
/// AF_VSOCK port the guest agent listens on. The host dials it through
/// Firecracker's vsock UDS with a `CONNECT <port>` preamble.
pub const VSOCK_PORT: u32 = 1234;
/// Largest single frame (length prefix + JSON). Bounds memory per message.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;
/// Largest base64 payload inside one frame (keeps JSON parse bounded).
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;

/// Guest → host messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum AgentMsg {
    Hello {
        version: u32,
        run_id: String,
        nonce: String,
    },
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Exit {
        code: i32,
    },
    ExportBegin {
        files: u32,
    },
    ExportFile {
        path: String,
        size: u64,
        sha256: String,
    },
    ExportData {
        data: String,
    },
    ExportEnd,
    Heartbeat,
}

/// Host → guest messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum HostMsg {
    Welcome {
        run_id: String,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        /// Secret-derived environment: (var_name, value). The agent places
        /// these in the workload environment and redacts the values from
        /// every stdio byte it relays. Sent over vsock (host-local).
        #[serde(default)]
        secrets: Vec<(String, String)>,
        deadline_ms: u64,
    },
    Deny {
        reason: String,
    },
    ExportAck {
        path: String,
    },
    ExportReject {
        reason: String,
    },
    Cancel,
}

impl AgentMsg {
    pub fn stdout(bytes: &[u8]) -> Self {
        AgentMsg::Stdout {
            data: B64.encode(bytes),
        }
    }
    pub fn stderr(bytes: &[u8]) -> Self {
        AgentMsg::Stderr {
            data: B64.encode(bytes),
        }
    }
    pub fn export_data(bytes: &[u8]) -> Self {
        AgentMsg::ExportData {
            data: B64.encode(bytes),
        }
    }
    /// Decode the base64 payload of a data-carrying message.
    pub fn payload(&self) -> Result<Vec<u8>, SandboxdError> {
        let s = match self {
            AgentMsg::Stdout { data }
            | AgentMsg::Stderr { data }
            | AgentMsg::ExportData { data } => data,
            _ => {
                return Err(SandboxdError::Protocol("message carries no payload".into()));
            }
        };
        if s.len() > MAX_CHUNK_BYTES * 4 / 3 + 8 {
            return Err(SandboxdError::Protocol("chunk too large".into()));
        }
        B64.decode(s)
            .map_err(|e| SandboxdError::Protocol(format!("bad base64: {e}")))
    }
}

/// Write one length-prefixed JSON frame.
pub async fn write_msg<W, M>(w: &mut W, msg: &M) -> Result<(), SandboxdError>
where
    W: AsyncWrite + Unpin,
    M: Serialize,
{
    let body = serde_json::to_vec(msg).map_err(|e| SandboxdError::Protocol(e.to_string()))?;
    if body.len() > MAX_FRAME_BYTES {
        return Err(SandboxdError::Protocol(format!(
            "frame too large: {}",
            body.len()
        )));
    }
    w.write_u32(body.len() as u32)
        .await
        .map_err(SandboxdError::Io)?;
    w.write_all(&body).await.map_err(SandboxdError::Io)?;
    w.flush().await.map_err(SandboxdError::Io)?;
    Ok(())
}

/// Read one length-prefixed JSON frame. `Ok(None)` = clean EOF.
pub async fn read_msg<R, M>(r: &mut R) -> Result<Option<M>, SandboxdError>
where
    R: AsyncRead + Unpin,
    M: for<'de> Deserialize<'de>,
{
    let len = match r.read_u32().await {
        Ok(n) => n as usize,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(SandboxdError::Io(e)),
    };
    if len == 0 || len > MAX_FRAME_BYTES {
        return Err(SandboxdError::Protocol(format!("bad frame length: {len}")));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf).await.map_err(SandboxdError::Io)?;
    serde_json::from_slice(&buf)
        .map(Some)
        .map_err(|e| SandboxdError::Protocol(format!("bad frame JSON: {e}")))
}

/// Validate the opening handshake. Returns the run id on success.
pub fn check_hello(msg: &AgentMsg, expect_run_id: &str) -> Result<String, SandboxdError> {
    match msg {
        AgentMsg::Hello {
            version,
            run_id,
            nonce,
        } => {
            if *version != PROTOCOL_VERSION {
                return Err(SandboxdError::Protocol(format!(
                    "agent protocol version {version} != {PROTOCOL_VERSION}"
                )));
            }
            if run_id != expect_run_id {
                return Err(SandboxdError::Protocol("run id mismatch".into()));
            }
            if nonce.len() > 128 {
                return Err(SandboxdError::Protocol("nonce too long".into()));
            }
            Ok(run_id.clone())
        }
        _ => Err(SandboxdError::Protocol("expected Hello".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        let msg = AgentMsg::Hello {
            version: PROTOCOL_VERSION,
            run_id: "lmn-abc".into(),
            nonce: "n".into(),
        };
        write_msg(&mut a, &msg).await.unwrap();
        let back: Option<AgentMsg> = read_msg(&mut b).await.unwrap();
        assert!(matches!(back, Some(AgentMsg::Hello { .. })));
    }

    #[tokio::test]
    async fn oversize_frame_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        a.write_u32((MAX_FRAME_BYTES + 1) as u32).await.unwrap();
        let res: Result<Option<AgentMsg>, _> = read_msg(&mut b).await;
        assert!(matches!(res, Err(SandboxdError::Protocol(_))));
    }

    #[tokio::test]
    async fn clean_eof_is_none() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a);
        let res: Result<Option<AgentMsg>, _> = read_msg(&mut b).await;
        assert!(matches!(res, Ok(None)));
    }

    #[test]
    fn hello_validation() {
        let good = AgentMsg::Hello {
            version: PROTOCOL_VERSION,
            run_id: "lmn-1".into(),
            nonce: "x".into(),
        };
        assert_eq!(check_hello(&good, "lmn-1").unwrap(), "lmn-1");
        assert!(check_hello(&good, "lmn-2").is_err());
        let bad_ver = AgentMsg::Hello {
            version: 999,
            run_id: "lmn-1".into(),
            nonce: "x".into(),
        };
        assert!(check_hello(&bad_ver, "lmn-1").is_err());
        assert!(check_hello(&AgentMsg::Heartbeat, "lmn-1").is_err());
    }

    #[test]
    fn payload_round_trip_and_cap() {
        let m = AgentMsg::stdout(b"hello");
        assert_eq!(m.payload().unwrap(), b"hello");
        let big = AgentMsg::Stdout {
            data: "A".repeat(MAX_CHUNK_BYTES * 4 / 3 + 100),
        };
        assert!(big.payload().is_err());
    }
}
