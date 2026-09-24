//! Authenticated Unix-socket API (kernel -> sandboxd).
//!
//! Wire protocol: length-prefixed JSON (u32 big-endian length, max 1 MiB).
//! Each connection must first send an auth message:
//! `{ "auth": "Bearer <redacted>" }`.
//! Then JSON-RPC-style requests:
//! `{ "id": 1, "method": "prepare", "params": { ... } }`
//! Responses: `{ "id": 1, "result": ... }` or `{ "id": 1, "error": { "code": "...", "message": "..." } }`.
//!
//! Authentication is defense-in-depth:
//! 1. SO_PEERCRED UID must be in `allowed_uids` (kernel service account).
//! 2. Bearer token must match (constant-time compare).
//! 3. Socket file is 0600, owned by the daemon user.

use std::{os::unix::fs::PermissionsExt, path::Path, sync::Arc, time::Duration};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use crate::{
    config::ApiConfig,
    contracts::{SandboxDriver, SandboxError, SandboxHandle, SandboxSpec},
    driver::Driver,
    error::SandboxdError,
};

/// Max message size: 1 MiB.
const MAX_MSG_BYTES: u32 = 1024 * 1024;

/// Auth message (first on every connection).
#[derive(Debug, Deserialize)]
struct AuthMsg {
    auth: String,
}

/// JSON-RPC-style request.
#[derive(Debug, Deserialize)]
struct ApiRequest {
    id: u64,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Success response.
#[derive(Debug, Serialize)]
struct ApiResponse {
    id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ApiError>,
}

/// Error response.
#[derive(Debug, Serialize)]
struct ApiError {
    code: String,
    message: String,
}

/// Load the bearer token from file. The file must be 0600 (or stricter).
fn load_token(path: &Path) -> Result<Vec<u8>, SandboxdError> {
    let meta = std::fs::metadata(path).map_err(SandboxdError::Io)?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(SandboxdError::Host(format!(
            "token file {path:?} is group/other-accessible (mode {mode:o}); must be 0600"
        )));
    }
    let token = std::fs::read(path).map_err(SandboxdError::Io)?;
    // Trim trailing newline (common for token files).
    let token = if token.last() == Some(&b'\n') {
        &token[..token.len() - 1]
    } else {
        &token[..]
    };
    if token.is_empty() {
        return Err(SandboxdError::Host("token file is empty".into()));
    }
    Ok(token.to_vec())
}

/// Constant-time token comparison.
fn tokens_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Get peer UID via SO_PEERCRED.
fn peer_uid(stream: &UnixStream) -> Result<u32, SandboxdError> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(SandboxdError::Host(format!(
            "SO_PEERCRED failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(cred.uid)
}

/// Read one length-prefixed message (bounded).
async fn read_msg(stream: &mut UnixStream) -> Result<Vec<u8>, SandboxdError> {
    let mut len_buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| SandboxdError::Protocol("read timeout".into()))?
        .map_err(|e| SandboxdError::Protocol(format!("read length: {e}")))?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_MSG_BYTES {
        return Err(SandboxdError::Protocol(format!(
            "message too large: {len} > {MAX_MSG_BYTES}"
        )));
    }
    if len == 0 {
        return Err(SandboxdError::Protocol("empty message".into()));
    }
    let mut buf = vec![0u8; len as usize];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut buf))
        .await
        .map_err(|_| SandboxdError::Protocol("read timeout".into()))?
        .map_err(|e| SandboxdError::Protocol(format!("read body: {e}")))?;
    Ok(buf)
}

/// Write one length-prefixed message.
async fn write_msg(stream: &mut UnixStream, msg: &[u8]) -> Result<(), SandboxdError> {
    if msg.len() > MAX_MSG_BYTES as usize {
        return Err(SandboxdError::Protocol("response too large".into()));
    }
    let len = (msg.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .map_err(|e| SandboxdError::Protocol(format!("write length: {e}")))?;
    stream
        .write_all(msg)
        .await
        .map_err(|e| SandboxdError::Protocol(format!("write body: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| SandboxdError::Protocol(format!("flush: {e}")))?;
    Ok(())
}

/// Handle one authenticated connection.
async fn handle_conn(
    mut stream: UnixStream,
    driver: Arc<Driver>,
    token: Arc<Vec<u8>>,
    allowed_uids: Arc<Vec<u32>>,
) -> Result<(), SandboxdError> {
    // 1. SO_PEERCRED UID check.
    let uid = peer_uid(&stream)?;
    if !allowed_uids.contains(&uid) {
        return Err(SandboxdError::Host(format!(
            "peer UID {uid} not in allowed_uids"
        )));
    }

    // 2. Bearer token auth (first message).
    let auth_bytes = read_msg(&mut stream).await?;
    let auth: AuthMsg = serde_json::from_slice(&auth_bytes)
        .map_err(|e| SandboxdError::Protocol(format!("bad auth message: {e}")))?;
    let presented = auth
        .auth
        .strip_prefix("Bearer ")
        .ok_or_else(|| SandboxdError::Protocol("auth must be 'Bearer <redacted>'".into()))?;
    if !tokens_equal(presented.as_bytes(), &token) {
        // Constant-time compare already; just reject.
        return Err(SandboxdError::Host("invalid bearer token".into()));
    }

    // 3. Request loop.
    loop {
        let req_bytes = match read_msg(&mut stream).await {
            Ok(b) => b,
            Err(SandboxdError::Protocol(msg)) if msg.contains("read length") => {
                // Clean EOF.
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let req: ApiRequest = serde_json::from_slice(&req_bytes)
            .map_err(|e| SandboxdError::Protocol(format!("bad request: {e}")))?;
        let resp = dispatch(&driver, req).await;
        let resp_bytes = serde_json::to_vec(&resp)
            .map_err(|e| SandboxdError::Host(format!("response encode: {e}")))?;
        write_msg(&mut stream, &resp_bytes).await?;
    }
}

/// Map a SandboxError to an API error code.
fn sandbox_error_code(e: &SandboxError) -> String {
    match e {
        SandboxError::Unavailable(_) => "unavailable",
        SandboxError::RunFailed(_) => "run_failed",
        SandboxError::QuotaExceeded(_) => "quota_exceeded",
    }
    .to_string()
}

/// Parse the frozen [`SandboxHandle`] from request params.
fn get_handle(params: &serde_json::Value) -> Option<SandboxHandle> {
    params
        .get("handle")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
}

/// Dispatch one API request to the driver.
///
/// The method set mirrors the frozen [`SandboxDriver`] trait 1:1
/// (`prepare`/`start`/`stream`/`cancel`/`export`/`destroy`); params carry
/// the frozen wire types (`SandboxSpec` for prepare, `SandboxHandle` for
/// the rest).
async fn dispatch(driver: &Arc<Driver>, req: ApiRequest) -> ApiResponse {
    // Helper: run a handle-taking driver method and wrap errors.
    async fn with_handle<F, Fut>(
        driver: &Arc<Driver>,
        params: &serde_json::Value,
        f: F,
    ) -> Result<serde_json::Value, ApiError>
    where
        F: FnOnce(Arc<Driver>, SandboxHandle) -> Fut,
        Fut: std::future::Future<Output = Result<serde_json::Value, SandboxError>> + Send,
    {
        match get_handle(params) {
            Some(h) => f(driver.clone(), h).await.map_err(|e| ApiError {
                code: sandbox_error_code(&e),
                message: e.to_string(),
            }),
            None => Err(ApiError {
                code: "invalid_params".into(),
                message: "missing or malformed handle".into(),
            }),
        }
    }

    let result = match req.method.as_str() {
        "prepare" => {
            let spec: Result<SandboxSpec, _> = serde_json::from_value(req.params);
            match spec {
                Ok(s) => driver
                    .prepare(&s)
                    .await
                    .and_then(|h| {
                        serde_json::to_value(&h)
                            .map_err(|e| SandboxError::RunFailed(format!("handle encode: {e}")))
                    })
                    .map(|h| serde_json::json!({ "handle": h }))
                    .map_err(|e| ApiError {
                        code: sandbox_error_code(&e),
                        message: e.to_string(),
                    }),
                Err(e) => Err(ApiError {
                    code: "invalid_params".into(),
                    message: format!("bad spec: {e}"),
                }),
            }
        }
        "start" => {
            with_handle(driver, &req.params, |d, h| async move {
                d.start(&h).await.map(|_| serde_json::json!({}))
            })
            .await
        }
        "stream" => {
            // Uses the Send inherent method, not the trait's `stream`
            // (whose future is !Send by construction of the frozen
            // contract): connection tasks are spawned.
            with_handle(driver, &req.params, |d, h| async move {
                let (chunks, stats) = d.stream_collect(&h).await?;
                Ok(serde_json::json!({
                    "chunks": chunks,
                    "stats": stats,
                }))
            })
            .await
        }
        "cancel" => {
            with_handle(driver, &req.params, |d, h| async move {
                d.cancel(&h).await.map(|_| serde_json::json!({}))
            })
            .await
        }
        "export" => {
            with_handle(driver, &req.params, |d, h| async move {
                let files = d.export(&h).await?;
                Ok(serde_json::json!({ "files": files }))
            })
            .await
        }
        "destroy" => {
            with_handle(driver, &req.params, |d, h| async move {
                d.destroy(&h).await.map(|_| serde_json::json!({}))
            })
            .await
        }
        _ => Err(ApiError {
            code: "method_not_found".into(),
            message: format!("unknown method: {}", req.method),
        }),
    };

    match result {
        Ok(v) => ApiResponse {
            id: req.id,
            result: Some(v),
            error: None,
        },
        Err(e) => ApiResponse {
            id: req.id,
            result: None,
            error: Some(e),
        },
    }
}

/// Serve the API on the configured socket. Never returns (except on fatal error).
pub async fn serve(config: &ApiConfig, driver: Arc<Driver>) -> Result<(), SandboxdError> {
    let token = Arc::new(load_token(&config.token_file)?);
    let allowed_uids = Arc::new(config.allowed_uids.clone());
    if allowed_uids.is_empty() {
        return Err(SandboxdError::Host(
            "allowed_uids is empty; refusing to serve with no authorized peers".into(),
        ));
    }

    // Remove stale socket.
    let _ = std::fs::remove_file(&config.socket);
    if let Some(parent) = config.socket.parent() {
        std::fs::create_dir_all(parent).map_err(SandboxdError::Io)?;
    }

    let listener = UnixListener::bind(&config.socket).map_err(SandboxdError::Io)?;
    // 0600: only the daemon user (and root) can connect. SO_PEERCRED provides
    // the second factor (UID allowlist).
    std::fs::set_permissions(&config.socket, std::fs::Permissions::from_mode(0o600))
        .map_err(SandboxdError::Io)?;

    loop {
        let (stream, _) = listener.accept().await.map_err(SandboxdError::Io)?;
        let driver = driver.clone();
        let token = token.clone();
        let allowed_uids = allowed_uids.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, driver, token, allowed_uids).await {
                // Log and drop; one bad client must not kill the daemon.
                eprintln!("api: connection error: {e}");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    #[test]
    fn token_rejects_group_readable() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");
        std::fs::write(&path, b"secret").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_token(&path).is_err());
    }

    #[test]
    fn token_accepts_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("token");
        std::fs::write(&path, b"secret\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let tok = load_token(&path).unwrap();
        assert_eq!(tok, b"secret");
    }

    #[test]
    fn token_constant_time() {
        assert!(tokens_equal(b"abc", b"abc"));
        assert!(!tokens_equal(b"abc", b"abd"));
        assert!(!tokens_equal(b"abc", b"abcd"));
    }

    #[test]
    fn auth_rejects_missing_bearer_prefix() {
        let msg = serde_json::json!({ "auth": "Token xyz" });
        let bytes = serde_json::to_vec(&msg).unwrap();
        let auth: AuthMsg = serde_json::from_slice(&bytes).unwrap();
        assert!(auth.auth.strip_prefix("Bearer ").is_none());
    }

    // Hostile client: oversized length prefix is rejected before allocation.
    #[tokio::test]
    async fn hostile_oversized_length_rejected() {
        let (a, mut b) = UnixStream::pair().unwrap();
        // Write a length prefix claiming 16 MiB.
        let len = (16 * 1024 * 1024u32).to_be_bytes();
        {
            use std::io::Write;
            use std::os::unix::io::AsRawFd;
            let mut std_a = unsafe { StdUnixStream::from_raw_fd(a.as_raw_fd()) };
            std_a.write_all(&len).unwrap();
            std::mem::forget(std_a); // Don't close the fd.
        }
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, SandboxdError::Protocol(_)));
    }

    // Hostile client: empty message rejected.
    #[tokio::test]
    async fn hostile_empty_message_rejected() {
        let (a, mut b) = UnixStream::pair().unwrap();
        {
            use std::io::Write;
            use std::os::unix::io::AsRawFd;
            let mut std_a = unsafe { StdUnixStream::from_raw_fd(a.as_raw_fd()) };
            std_a.write_all(&0u32.to_be_bytes()).unwrap();
            std::mem::forget(std_a);
        }
        let err = read_msg(&mut b).await.unwrap_err();
        assert!(matches!(err, SandboxdError::Protocol(_)));
    }
}
