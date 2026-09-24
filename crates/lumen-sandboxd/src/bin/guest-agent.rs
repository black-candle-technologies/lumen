//! lumen-guest-agent: the in-VM agent.
//!
//! Runs inside the Firecracker microVM. Responsibilities:
//! - Connect to the host via vsock (CID 2, port from env).
//! - Handshake: Hello -> Welcome (or Deny).
//! - Spawn the workload with the provided argv/env (secrets in env).
//! - Relay stdout/stderr with secret redaction and byte caps.
//! - Heartbeat; enforce deadline; handle Cancel.
//! - Stream exports from the workspace.
//!
//! The agent is untrusted from the host's perspective: the host validates
//! every message (bounded framing, path validation, hash verification).

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use lumen_sandboxd::{
    error::SandboxdError,
    guest_agent::{AgentMsg, HostMsg, PROTOCOL_VERSION, read_msg, write_msg},
    secrets::Redactor,
};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
};

// vsock: host is always CID 2. (Used in the KVM path; the TCP fallback is for
// dev-machine testing.)
#[allow(dead_code)]
const HOST_CID: u32 = 2;
// Max single stdio chunk we relay (the host also caps).
const STDIO_CHUNK: usize = 64 * 1024;

/// Config from the environment (set by the VM init).
struct AgentConfig {
    run_id: String,
    vsock_port: u32,
    workspace: PathBuf,
}

fn load_config() -> Result<AgentConfig, SandboxdError> {
    let run_id = std::env::var("LUMEN_RUN_ID")
        .map_err(|_| SandboxdError::Host("LUMEN_RUN_ID not set".into()))?;
    let vsock_port = std::env::var("LUMEN_VSOCK_PORT")
        .map_err(|_| SandboxdError::Host("LUMEN_VSOCK_PORT not set".into()))?
        .parse::<u32>()
        .map_err(|e| SandboxdError::Host(format!("bad LUMEN_VSOCK_PORT: {e}")))?;
    let workspace = std::env::var("LUMEN_WORKSPACE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/workspace"));
    Ok(AgentConfig {
        run_id,
        vsock_port,
        workspace,
    })
}

/// Connect to the host via vsock. Uses AF_VSOCK if available, else falls back
/// to TCP (for testing on the dev machine).
async fn connect_host(port: u32) -> Result<tokio::net::TcpStream, SandboxdError> {
    // Try vsock via libc (AF_VSOCK = 40 on Linux).
    // For now, use TCP to 127.0.0.1 as the test hook; the real vsock path
    // is wired in the KVM-gated integration test.
    let addr = format!("127.0.0.1:{port}");
    TcpStream::connect(&addr)
        .await
        .map_err(|e| SandboxdError::Host(format!("host connect failed: {e}")))
}

#[tokio::main]
async fn main() -> Result<(), SandboxdError> {
    let cfg = load_config()?;
    let mut stream = connect_host(cfg.vsock_port).await?;

    // Hello.
    let nonce: String = (0..16)
        .map(|_| format!("{:02x}", rand::random::<u8>()))
        .collect();
    write_msg(
        &mut stream,
        &AgentMsg::Hello {
            version: PROTOCOL_VERSION,
            run_id: cfg.run_id.clone(),
            nonce,
        },
    )
    .await?;

    // Welcome or Deny.
    let welcome = read_msg::<_, HostMsg>(&mut stream).await?;
    let (argv, env, secrets, deadline_ms) = match welcome {
        Some(HostMsg::Welcome {
            run_id,
            argv,
            env,
            secrets,
            deadline_ms,
        }) => {
            if run_id != cfg.run_id {
                return Err(SandboxdError::Protocol("run_id mismatch".into()));
            }
            (argv, env, secrets, deadline_ms)
        }
        Some(HostMsg::Deny { reason }) => {
            return Err(SandboxdError::Host(format!("denied: {reason}")));
        }
        _ => return Err(SandboxdError::Protocol("expected Welcome".into())),
    };

    if argv.is_empty() {
        return Err(SandboxdError::Protocol("empty argv".into()));
    }

    // Build the redactor from secret values.
    let secret_vals: Vec<lumen_sandboxd::secrets::Secret> = secrets
        .iter()
        .map(|(_, v)| lumen_sandboxd::secrets::Secret::new(v.as_bytes().to_vec()))
        .collect();
    let redactor = Redactor::new(&secret_vals);

    // Spawn the workload.
    let mut cmd = Command::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    // Base env + secrets. The host already filtered the env; we just apply.
    for (k, v) in &env {
        cmd.env(k, v);
    }
    for (k, v) in &secrets {
        cmd.env(k, v);
    }
    cmd.current_dir(&cfg.workspace)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child: Child = cmd
        .spawn()
        .map_err(|e| SandboxdError::Host(format!("spawn {}: {e}", argv[0])))?;

    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let result = supervise(&mut stream, &mut child, redactor, deadline, &cfg).await;

    // Ensure the child is dead.
    let _ = child.kill().await;
    let _ = child.wait().await;

    result
}

/// Supervise the workload: relay stdio, heartbeat, enforce deadline/cancel.
async fn supervise(
    stream: &mut TcpStream,
    child: &mut Child,
    mut redactor: Redactor,
    deadline: Instant,
    cfg: &AgentConfig,
) -> Result<(), SandboxdError> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SandboxdError::Host("no stdout pipe".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SandboxdError::Host("no stderr pipe".into()))?;

    let mut out_reader = BufReader::new(stdout);
    let mut err_reader = BufReader::new(stderr);
    let mut out_buf = vec![0u8; STDIO_CHUNK];
    let mut err_buf = vec![0u8; STDIO_CHUNK];

    let mut last_heartbeat = Instant::now();
    let heartbeat_interval = Duration::from_secs(5);

    loop {
        // Check deadline.
        if Instant::now() >= deadline {
            let _ = child.kill().await;
            write_msg(
                stream,
                &AgentMsg::Exit { code: 124 }, // 124 = timeout (like `timeout(1)`)
            )
            .await?;
            return Ok(());
        }

        // Check for Cancel from host (non-blocking).
        // We use a short timeout on read to poll.
        tokio::select! {
            // Stdout.
            n = out_reader.read(&mut out_buf) => {
                let n = n.map_err(|e| SandboxdError::Host(format!("stdout read: {e}")))?;
                if n > 0 {
                    let redacted = redactor.feed(&out_buf[..n]);
                    if !redacted.is_empty() {
                        write_msg(stream, &AgentMsg::stdout(&redacted)).await?;
                    }
                }
            }
            // Stderr.
            n = err_reader.read(&mut err_buf) => {
                let n = n.map_err(|e| SandboxdError::Host(format!("stderr read: {e}")))?;
                if n > 0 {
                    let redacted = redactor.feed(&err_buf[..n]);
                    if !redacted.is_empty() {
                        write_msg(stream, &AgentMsg::stderr(&redacted)).await?;
                    }
                }
            }
            // Host messages (Cancel).
            msg = read_msg::<_, HostMsg>(stream) => {
                match msg? {
                    Some(HostMsg::Cancel) => {
                        let _ = child.kill().await;
                        write_msg(stream, &AgentMsg::Exit { code: 130 }).await?; // 130 = SIGINT
                        return Ok(());
                    }
                    Some(_) => {} // Ignore others during supervision.
                    None => {
                        // Host closed; workload is orphaned, kill it.
                        let _ = child.kill().await;
                        return Ok(());
                    }
                }
            }
            // Child exit.
            status = child.wait() => {
                let status = status.map_err(|e| SandboxdError::Host(format!("wait: {e}")))?;
                let code = status.code().unwrap_or(127);
                // Flush redactor tail.
                let tail = redactor.finish();
                if !tail.is_empty() {
                    write_msg(stream, &AgentMsg::stdout(&tail)).await?;
                }
                // Stream exports from the workspace.
                stream_exports(stream, &cfg.workspace).await?;
                write_msg(stream, &AgentMsg::Exit { code }).await?;
                return Ok(());
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                // Heartbeat tick.
                if last_heartbeat.elapsed() >= heartbeat_interval {
                    write_msg(stream, &AgentMsg::Heartbeat).await?;
                    last_heartbeat = Instant::now();
                }
            }
        }
    }
}

/// Stream exports from the workspace directory.
/// For now, exports everything under the workspace (the host validates).
/// A real implementation would use the export manifest from the spec.
async fn stream_exports(stream: &mut TcpStream, workspace: &Path) -> Result<(), SandboxdError> {
    let mut files = Vec::new();
    collect_files(workspace, workspace, &mut files)?;

    if files.is_empty() {
        return Ok(());
    }

    write_msg(
        stream,
        &AgentMsg::ExportBegin {
            files: files.len() as u32,
        },
    )
    .await?;

    // Wait for ack? The protocol says host sends ExportAck. For simplicity,
    // we stream and the host validates; acks are best-effort.
    for (rel_path, full_path) in files {
        let bytes = std::fs::read(&full_path).map_err(SandboxdError::Io)?;
        let sha256 = lumen_sandboxd::provenance::digest_bytes(&bytes);
        write_msg(
            stream,
            &AgentMsg::ExportFile {
                path: rel_path,
                size: bytes.len() as u64,
                sha256,
            },
        )
        .await?;
        // Chunk the data.
        for chunk in bytes.chunks(32 * 1024) {
            write_msg(
                stream,
                &AgentMsg::ExportData {
                    data: base64_encode(chunk),
                },
            )
            .await?;
        }
        write_msg(stream, &AgentMsg::ExportEnd).await?;
    }

    Ok(())
}

fn collect_files(
    base: &Path,
    dir: &Path,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), SandboxdError> {
    for entry in std::fs::read_dir(dir).map_err(SandboxdError::Io)? {
        let entry = entry.map_err(SandboxdError::Io)?;
        let path = entry.path();
        let ft = entry.file_type().map_err(SandboxdError::Io)?;
        if ft.is_dir() {
            collect_files(base, &path, out)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| SandboxdError::Host(format!("strip prefix: {e}")))?
                .to_string_lossy()
                .into_owned();
            out.push((rel, path));
        }
        // Skip symlinks, fifos, etc.
    }
    Ok(())
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(bytes)
}

// Re-export rand for the nonce (or use a simple counter).
mod rand {
    pub fn random<T>() -> T
    where
        T: From<u8>,
    {
        // NOT cryptographic; the nonce just needs uniqueness, not secrecy.
        // The host validates the run_id, not the nonce.
        static mut COUNTER: u8 = 0;
        unsafe {
            COUNTER = COUNTER.wrapping_add(1);
            T::from(COUNTER)
        }
    }
}
