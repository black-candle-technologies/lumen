//! Brokered secrets.
//!
//! The strict profile never lets a workload see a secret it was not
//! granted, and never lets a granted secret leak into logs, prompts, or
//! environment snapshots:
//!
//! - Policies name secrets by **opaque handle** only (`"github-token"`).
//!   Values live in an external secret broker (a host-side Unix-socket
//!   service); sandboxd fetches them at `prepare` time.
//! - If the policy requests secrets and **no broker is configured**,
//!   `prepare` fails closed ([`SandboxdError::SecretDenied`]).
//! - Values are held in [`Secret`], which overwrites its bytes on drop.
//! - The guest agent receives values over vsock (host-local), places them
//!   in the workload environment, and **redacts** them from every
//!   stdout/stderr byte it relays ([`Redactor`]).
//! - [`filter_env_snapshot`] strips secret-derived variables from any
//!   environment snapshot the API serves.
//!
//! The daemon's own logs only ever name handles.

use std::{
    collections::HashSet,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::error::SandboxdError;

/// A secret value that is overwritten with zeros on drop.
pub struct Secret {
    bytes: Vec<u8>,
}

// Debug never prints the bytes.
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Volatile writes so the optimizer cannot elide the wipe.
        for b in self.bytes.iter_mut() {
            // SAFETY: `b` is a valid exclusive reference; the volatile
            // write only affects this allocation.
            unsafe { std::ptr::write_volatile(b, 0) };
        }
        // Keep the compiler from reordering the wipe past the free.
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Broker wire protocol: newline-delimited JSON.
#[derive(Serialize)]
struct BrokerRequest<'a> {
    v: u32,
    op: &'a str,
    handle: &'a str,
}

#[derive(Deserialize)]
struct BrokerResponse {
    ok: bool,
    value: Option<String>,
    error: Option<String>,
}

/// Client for the host secret broker.
pub struct SecretBroker {
    socket_path: String,
    timeout: Duration,
}

impl SecretBroker {
    pub fn new(socket_path: String) -> Self {
        Self {
            socket_path,
            timeout: Duration::from_secs(5),
        }
    }

    /// Fetch one secret by handle. The handle (not the value) appears in
    /// error messages.
    pub fn fetch(&self, handle: &str) -> Result<Secret, SandboxdError> {
        if handle.is_empty() || handle.len() > 256 {
            return Err(SandboxdError::SecretDenied(
                "bad handle length for broker request".to_string(),
            ));
        }
        let mut sock = UnixStream::connect(&self.socket_path)
            .map_err(|e| SandboxdError::SecretDenied(format!("broker unreachable: {e}")))?;
        sock.set_read_timeout(Some(self.timeout)).ok();
        sock.set_write_timeout(Some(self.timeout)).ok();
        let req = BrokerRequest {
            v: 1,
            op: "get",
            handle,
        };
        let mut line = serde_json::to_vec(&req)
            .map_err(|e| SandboxdError::SecretDenied(format!("broker request encode: {e}")))?;
        if line.len() > 4096 {
            return Err(SandboxdError::SecretDenied("handle too long".into()));
        }
        line.push(b'\n');
        sock.write_all(&line)
            .map_err(|e| SandboxdError::SecretDenied(format!("broker write: {e}")))?;

        // Bounded response read (values are secrets; keep them small).
        let mut reader = BufReader::new(sock);
        let mut resp_line = Vec::with_capacity(4096);
        // Read up to 64 KiB + newline.
        let mut limited = std::io::Read::take(&mut reader, 65536 + 1);
        limited
            .read_until(b'\n', &mut resp_line)
            .map_err(|e| SandboxdError::SecretDenied(format!("broker read: {e}")))?;
        if resp_line.len() > 65536 + 1 || !resp_line.ends_with(b"\n") {
            return Err(SandboxdError::SecretDenied(
                "broker response too large".into(),
            ));
        }
        let resp: BrokerResponse = serde_json::from_slice(&resp_line)
            .map_err(|e| SandboxdError::SecretDenied(format!("broker response decode: {e}")))?;
        if !resp.ok {
            return Err(SandboxdError::SecretDenied(format!(
                "broker refused handle {handle}: {}",
                resp.error.as_deref().unwrap_or("unknown")
            )));
        }
        let value = resp
            .value
            .ok_or_else(|| SandboxdError::SecretDenied("broker ok without value".into()))?;
        if value.len() > 65536 {
            return Err(SandboxdError::SecretDenied("secret too large".into()));
        }
        Ok(Secret::new(value.into_bytes()))
    }
}

/// Fetch every handle the policy grants. `broker == None` with a non-empty
/// handle list is a fail-closed error. Duplicate handles are fetched once.
pub fn fetch_granted_secrets(
    broker: Option<&SecretBroker>,
    handles: &[String],
) -> Result<Vec<(String, Secret)>, SandboxdError> {
    let mut seen = HashSet::new();
    let mut wanted: Vec<&String> = Vec::new();
    for h in handles {
        if seen.insert(h.as_str()) {
            wanted.push(h);
        }
    }
    if wanted.is_empty() {
        return Ok(Vec::new());
    }
    let broker = broker.ok_or_else(|| {
        SandboxdError::SecretDenied(
            "policy grants secrets but no secret broker is configured".into(),
        )
    })?;
    wanted
        .into_iter()
        .map(|h| broker.fetch(h).map(|s| (h.clone(), s)))
        .collect()
}

/// Streaming redactor: replaces every occurrence of any secret value with
/// `***`. Operates on bytes; holds back `max_needle_len - 1` tail bytes
/// between `feed` calls so a secret split across chunk boundaries is still
/// caught. Call [`Redactor::finish`] at EOF to flush the tail.
pub struct Redactor {
    needles: Vec<Vec<u8>>,
    max_len: usize,
    tail: Vec<u8>,
}

impl Redactor {
    pub fn new(secrets: &[Secret]) -> Self {
        let mut needles: Vec<Vec<u8>> = secrets
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .filter(|v| v.len() >= 4)
            .collect();
        // Longest first so overlapping secrets redact greedily.
        needles.sort_by_key(|v| std::cmp::Reverse(v.len()));
        needles.dedup();
        let max_len = needles.iter().map(|v| v.len()).max().unwrap_or(0);
        Self {
            needles,
            max_len,
            tail: Vec::new(),
        }
    }

    pub fn is_active(&self) -> bool {
        !self.needles.is_empty()
    }

    /// Redact one chunk; returns bytes safe to emit now.
    ///
    /// Algorithm: hold back the last `max_len - 1` bytes unexamined, redact
    /// complete occurrences in the emit region, then look for occurrences
    /// that *cross* the emit boundary (start in the head, end in the held
    /// region) and pull those head bytes back. The retained tail is bounded
    /// by ~2× the longest secret, so adversarial output cannot grow memory
    /// without bound, and each `feed` is O(chunk + max_len²).
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<u8> {
        if self.needles.is_empty() {
            return chunk.to_vec();
        }
        self.tail.extend_from_slice(chunk);
        let hold = self.max_len.saturating_sub(1);
        if self.tail.len() <= hold {
            return Vec::new();
        }
        let split = self.tail.len() - hold;
        let raw_head = &self.tail[..split];
        let held = &self.tail[split..];

        // Find the largest emit_end <= split such that no secret occurrence
        // starts before emit_end and ends after it. Walk emit_end down to
        // the start of any crossing occurrence (fixpoint). Each step only
        // inspects a ~2*max_len window, so this is cheap; it terminates
        // because emit_end strictly decreases.
        let mut emit_end = split;
        loop {
            let win_start = emit_end.saturating_sub(self.max_len);
            // Combined view so occurrences extending into `held` are seen.
            let mut buf = Vec::with_capacity((split - win_start) + held.len());
            buf.extend_from_slice(&raw_head[win_start..]);
            buf.extend_from_slice(held);
            let rel_emit = emit_end - win_start;
            let mut new_end = emit_end;
            for n in &self.needles {
                let mut s = 0;
                while s < rel_emit {
                    if buf[s..].starts_with(n) {
                        if s + n.len() > rel_emit {
                            // Crosses the emit boundary: pull it back.
                            new_end = new_end.min(win_start + s);
                        }
                        s += 1;
                    } else {
                        s += 1;
                    }
                }
            }
            if new_end == emit_end {
                break;
            }
            emit_end = new_end;
        }

        let out = redact_once(&self.tail[..emit_end], &self.needles);
        // Retain everything from emit_end on for the next round.
        self.tail = self.tail[emit_end..].to_vec();
        out
    }

    /// Flush remaining tail bytes (redacted).
    pub fn finish(&mut self) -> Vec<u8> {
        let tail = std::mem::take(&mut self.tail);
        if self.needles.is_empty() {
            return tail;
        }
        redact_once(&tail, &self.needles)
    }
}

/// Replace all occurrences of any needle with `***`.
fn redact_once(haystack: &[u8], needles: &[Vec<u8>]) -> Vec<u8> {
    if needles.is_empty() {
        return haystack.to_vec();
    }
    let mut out = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        let mut matched = 0;
        for n in needles {
            if haystack[i..].starts_with(n) {
                matched = n.len();
                break;
            }
        }
        if matched > 0 {
            out.extend_from_slice(b"***");
            i += matched;
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    out
}

/// Remove secret-derived variables from an environment snapshot.
/// `secret_names` are the env var names the agent populated from secrets.
pub fn filter_env_snapshot(
    env: &[(String, String)],
    secret_names: &HashSet<String>,
) -> Vec<(String, String)> {
    env.iter()
        .filter(|(k, _)| !secret_names.contains(k))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn secret(s: &str) -> Secret {
        Secret::new(s.as_bytes().to_vec())
    }

    #[test]
    fn redactor_basic() {
        let mut r = Redactor::new(&[secret("hunter2")]);
        let out = r.feed(b"token=hunter2 ok");
        let mut fin = r.finish();
        let mut all = out;
        all.append(&mut fin);
        assert_eq!(all, b"token=*** ok");
    }

    #[test]
    fn redactor_split_across_chunks() {
        let mut r = Redactor::new(&[secret("supersecret")]);
        let a = r.feed(b"xxsupers");
        let b = r.feed(b"ecretYY");
        let c = r.finish();
        let mut all = a;
        all.extend_from_slice(&b);
        all.extend_from_slice(&c);
        assert_eq!(all, b"xx***YY");
    }

    #[test]
    fn redactor_no_secrets_is_passthrough() {
        let mut r = Redactor::new(&[]);
        assert_eq!(r.feed(b"abc"), b"abc");
        assert_eq!(r.finish(), b"");
    }

    #[test]
    fn redactor_short_secrets_ignored() {
        // Needles < 4 bytes are ignored (too collision-prone).
        let r = Redactor::new(&[secret("ab")]);
        assert!(!r.is_active());
    }

    #[test]
    fn redactor_multiple_and_overlap() {
        let mut r = Redactor::new(&[secret("abcdef"), secret("abcd")]);
        let mut out = r.feed(b"abcdef abcd");
        out.extend_from_slice(&r.finish());
        assert_eq!(out, b"*** ***");
    }

    #[test]
    fn no_broker_denies_granted_secrets() {
        let err = fetch_granted_secrets(None, &["tok".to_string()]).unwrap_err();
        assert!(matches!(err, SandboxdError::SecretDenied(_)));
    }

    #[test]
    fn no_handles_no_broker_ok() {
        assert!(fetch_granted_secrets(None, &[]).unwrap().is_empty());
    }

    #[test]
    fn broker_fetch_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("broker.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let v: serde_json::Value = serde_json::from_str(&line).unwrap();
            assert_eq!(v["handle"], "tok");
            let resp = serde_json::json!({"ok": true, "value": "s3cr3t"});
            s.write_all(serde_json::to_vec(&resp).unwrap().as_slice())
                .unwrap();
            s.write_all(b"\n").unwrap();
        });
        let broker = SecretBroker::new(sock_path.display().to_string());
        let got = broker.fetch("tok").unwrap();
        assert_eq!(got.as_bytes(), b"s3cr3t");
        server.join().unwrap();
    }

    #[test]
    fn broker_refusal_is_error_naming_handle_not_value() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("b2.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let resp = serde_json::json!({"ok": false, "error": "unknown handle"});
            s.write_all(serde_json::to_vec(&resp).unwrap().as_slice())
                .unwrap();
            s.write_all(b"\n").unwrap();
        });
        let broker = SecretBroker::new(sock_path.display().to_string());
        let err = broker.fetch("nope").unwrap_err().to_string();
        assert!(err.contains("nope"), "handle named: {err}");
        assert!(!err.contains("s3cr3t"));
        server.join().unwrap();
    }

    #[test]
    fn env_snapshot_filtered() {
        let env = vec![
            ("PATH".to_string(), "/bin".to_string()),
            ("API_TOKEN".to_string(), "s3cr3t".to_string()),
        ];
        let names: HashSet<String> = ["API_TOKEN".to_string()].into_iter().collect();
        let snap = filter_env_snapshot(&env, &names);
        assert_eq!(snap, vec![("PATH".to_string(), "/bin".to_string())]);
        // Original untouched.
        assert_eq!(env.len(), 2);
    }
}
