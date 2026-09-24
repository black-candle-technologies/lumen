//! lumen-guest-agent: the in-VM agent.
//!
//! Runs inside the Firecracker microVM. Responsibilities:
//! - Listen on AF_VSOCK; the host dials in through Firecracker's vsock
//!   UDS (`CONNECT <port>` preamble).
//! - Handshake: Hello -> Welcome (or Deny).
//! - Spawn the workload with the provided argv/env (secrets in env).
//! - Relay stdout/stderr with secret redaction and byte caps.
//! - Heartbeat; enforce deadline; handle Cancel.
//! - Stream exports from the workspace.
//!
//! Run identity and addressing come from the kernel command line
//! (`lumen.run_id=`, `lumen.vsock_port=`, ...), set by the host in the
//! Firecracker boot args and read from `/proc/cmdline`.
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
    guest_agent::{AgentMsg, HostMsg, PROTOCOL_VERSION, VSOCK_PORT, read_msg, write_msg},
    secrets::Redactor,
};
use tokio::{
    io::{AsyncReadExt, BufReader},
    net::TcpStream,
    process::{Child, Command},
};

// Max single stdio chunk we relay (the host also caps).
const STDIO_CHUNK: usize = 64 * 1024;

/// Config from the kernel command line (set by the host in the Firecracker
/// boot args; the guest's `/init` mounts `/proc` before exec'ing us).
struct AgentConfig {
    run_id: String,
    vsock_port: u32,
    workspace: PathBuf,
}

fn load_config() -> Result<AgentConfig, SandboxdError> {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let value = |key: &str| {
        cmdline
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix(key))
            .map(|v| v.to_owned())
    };
    let run_id = value("lumen.run_id=").ok_or_else(|| {
        SandboxdError::Host(format!(
            "lumen.run_id= missing from kernel cmdline: {cmdline}"
        ))
    })?;
    let vsock_port = match value("lumen.vsock_port=") {
        Some(v) => v
            .parse::<u32>()
            .map_err(|e| SandboxdError::Host(format!("bad lumen.vsock_port=: {e}")))?,
        None => VSOCK_PORT,
    };
    Ok(AgentConfig {
        run_id,
        vsock_port,
        workspace: PathBuf::from("/workspace"),
    })
}

/// Bind the AF_VSOCK listen socket. Returns the listen fd.
///
/// Host-initiated flow (see Firecracker docs/vsock.md): the host connects to
/// the vsock UDS, sends `CONNECT <port>\n`, reads `OK <host-port>\n`, and the
/// UDS connection becomes the data stream. From the guest's perspective this
/// is a plain vsock listen + accept.
fn vsock_bind(port: u32) -> Result<i32, SandboxdError> {
    let os_err =
        |op: &str| SandboxdError::Host(format!("vsock {op}: {}", std::io::Error::last_os_error()));
    // SAFETY: straightforward libc socket setup; the fd is closed on error.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            return Err(os_err("socket"));
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        let rc = libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        if rc != 0 {
            libc::close(fd);
            return Err(os_err("bind"));
        }
        if libc::listen(fd, 8) != 0 {
            libc::close(fd);
            return Err(os_err("listen"));
        }
        Ok(fd)
    }
}

/// Accept one host connection on a bound vsock listen fd. Retries on
/// transient accept errors. Blocking accept runs in `spawn_blocking`.
async fn vsock_accept(listen_fd: i32) -> Result<TcpStream, SandboxdError> {
    use std::os::unix::io::FromRawFd;

    loop {
        let cfd: i32 = tokio::task::spawn_blocking(move || unsafe {
            libc::accept(listen_fd, std::ptr::null_mut(), std::ptr::null_mut())
        })
        .await
        .map_err(|e| SandboxdError::Host(format!("vsock accept task: {e}")))?;
        if cfd < 0 {
            eprintln!(
                "lumen-guest-agent: accept failed ({}); retrying",
                std::io::Error::last_os_error()
            );
            continue;
        }
        // SAFETY: cfd is an accepted vsock stream we own; set non-blocking
        // for Tokio.
        let std_stream = unsafe {
            let flags = libc::fcntl(cfd, libc::F_GETFL);
            if flags >= 0 {
                libc::fcntl(cfd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
            std::net::TcpStream::from_raw_fd(cfd)
        };
        match TcpStream::from_std(std_stream) {
            Ok(s) => return Ok(s),
            Err(e) => {
                eprintln!("lumen-guest-agent: vsock from_std failed ({e}); retrying");
            }
        }
    }
}

/// Nonce that does not need kernel entropy: a freshly booted VM may block
/// in `getrandom` until the CRNG initializes, which would stall the
/// handshake while the host times out and retries. Uniqueness per boot is
/// all the handshake needs.
fn make_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(1);
    format!(
        "{}-{}",
        std::process::id(),
        CTR.fetch_add(1, Ordering::Relaxed)
    )
}

#[tokio::main]
async fn main() -> Result<(), SandboxdError> {
    let cfg = load_config()?;
    let listen_fd = vsock_bind(cfg.vsock_port)?;
    eprintln!(
        "lumen-guest-agent: listening on vsock port {}",
        cfg.vsock_port
    );

    // Handshake loop. The host may retry its CONNECT; if a handshake
    // attempt fails partway (the host went away), drop the connection and
    // go back to accept.
    let (mut stream, argv, env, secrets, deadline_ms) = loop {
        let mut stream = vsock_accept(listen_fd).await?;

        // Hello.
        let hello = AgentMsg::Hello {
            version: PROTOCOL_VERSION,
            run_id: cfg.run_id.clone(),
            nonce: make_nonce(),
        };
        if let Err(e) = write_msg(&mut stream, &hello).await {
            eprintln!("lumen-guest-agent: hello send failed ({e}); re-accepting");
            continue;
        }

        // Welcome or Deny, with a timeout so a dead peer cannot wedge us.
        let welcome: Option<HostMsg> =
            match tokio::time::timeout(Duration::from_secs(30), read_msg(&mut stream)).await {
                Ok(Ok(m)) => m,
                Ok(Err(e)) => {
                    eprintln!("lumen-guest-agent: welcome read failed ({e}); re-accepting");
                    continue;
                }
                Err(_) => {
                    eprintln!("lumen-guest-agent: welcome timeout; re-accepting");
                    continue;
                }
            };
        match welcome {
            Some(HostMsg::Welcome {
                run_id,
                argv,
                env,
                secrets,
                deadline_ms,
            }) => {
                if run_id != cfg.run_id {
                    eprintln!("lumen-guest-agent: run_id mismatch; re-accepting");
                    continue;
                }
                if argv.is_empty() {
                    eprintln!("lumen-guest-agent: empty argv; re-accepting");
                    continue;
                }
                break (stream, argv, env, secrets, deadline_ms);
            }
            Some(HostMsg::Deny { reason }) => {
                return Err(SandboxdError::Host(format!("denied: {reason}")));
            }
            _ => {
                eprintln!("lumen-guest-agent: expected Welcome; re-accepting");
                continue;
            }
        }
    };

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
                // Drain both pipes to EOF now that the child is dead. The
                // `select!` above races pipe reads against `child.wait()`;
                // when the wait branch wins, output written just before exit
                // would otherwise be lost.
                loop {
                    let n = out_reader.read(&mut out_buf).await
                        .map_err(|e| SandboxdError::Host(format!("stdout drain: {e}")))?;
                    if n == 0 {
                        break;
                    }
                    let redacted = redactor.feed(&out_buf[..n]);
                    if !redacted.is_empty() {
                        write_msg(stream, &AgentMsg::stdout(&redacted)).await?;
                    }
                }
                loop {
                    let n = err_reader.read(&mut err_buf).await
                        .map_err(|e| SandboxdError::Host(format!("stderr drain: {e}")))?;
                    if n == 0 {
                        break;
                    }
                    let redacted = redactor.feed(&err_buf[..n]);
                    if !redacted.is_empty() {
                        write_msg(stream, &AgentMsg::stderr(&redacted)).await?;
                    }
                }
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
