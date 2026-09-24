//! OS-enforced confinement for the Pi agent-loop subprocess.
//!
//! Pi is untrusted: the model, its extensions, and any child process it
//! spawns must not reach the host network, ambient credentials, or host
//! files outside an explicit allowlist. This module applies three
//! independent layers, all enforced by the OS kernel rather than by Pi's
//! cooperation:
//!
//! 1. **Environment scrubbing.** The child starts with an empty
//!    environment; only `PATH`, `HOME`, `TMPDIR`, and the `LUMEN_*`
//!    contract variables are set. Ambient credentials (`AWS_*`,
//!    `GH_TOKEN`, `*_API_KEY`, proxy variables, …) never cross the
//!    spawn boundary, and `HOME`/`TMPDIR` point inside the session
//!    sandbox so `~/.aws`-style credential files resolve there instead
//!    of in the operator's home.
//! 2. **Network namespace** (Linux). The child is moved into a fresh
//!    network namespace with no interfaces and no routes: it cannot
//!    open any INET socket to the outside world, including the host's
//!    loopback services. Unix-domain sockets (the kernel channel) and
//!    the inherited stdio pipes are unaffected by the namespace.
//! 3. **Landlock filesystem policy** (Linux 5.13+). The child may read
//!    and execute the system hierarchy, read/write only the session
//!    directory, the per-session tmp dir, and the kernel-channel socket
//!    directory, and open a handful of device nodes (`/dev/null`,
//!    `/dev/zero`, `/dev/urandom`). Everything else — the host `/tmp`,
//!    the operator's home, other sessions' state — is denied by the
//!    kernel.
//!
//! Layers 2 and 3 are applied in the child after `fork(2)` and before
//! `exec(2)` via [`std::os::unix::process::CommandExt::pre_exec`]. Any
//! failure aborts the spawn: the child never runs unsandboxed
//! (fail closed). The sandbox is configurable
//! ([`PiSandboxConfig`]) but every layer defaults to on; disabling a
//! layer is an explicit, reviewable weakening of the posture, not a
//! silent fallback.
//!
//! # Residual risks (documented, not ignored)
//!
//! - `/proc` is readable (runtimes inspect their own process). Another
//!   process's `cmdline`/`environ` remains visible to a privileged
//!   supervisor deployment; run the supervisor as a dedicated non-root
//!   uid so the kernel's usual ptrace/filesystem permissions apply.
//! - When the supervisor itself runs as root, the child keeps uid 0
//!   (1:1 id map). The Landlock policy still confines its filesystem
//!   view and the network namespace still denies egress, but device
//!   nodes outside the policy are only as protected as the policy's
//!   allowlist. Prefer a dedicated non-root uid in production.
//! - Landlock is allowlist-based: any path not covered by a rule is
//!   denied. If Pi's runtime needs a path outside the policy (e.g. a
//!   non-FHS install prefix), the spawn fails loudly rather than
//!   running half-confined; extend `extra_read_only_paths`.

use std::{
    ffi::CString,
    io,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
};

use thiserror::Error;

/// Confinement switches for the Pi subprocess. Every layer defaults to
/// enabled; each can be disabled explicitly for platforms that cannot
/// provide it (old kernels, containers without user namespaces). A
/// disabled layer is a documented weakening, never a silent fallback.
#[derive(Debug, Clone)]
pub struct PiSandboxConfig {
    /// Move the child into a fresh network namespace (no interfaces, no
    /// routes). Unix-domain sockets and pipes keep working.
    pub network_isolation: bool,
    /// Apply the Landlock filesystem policy (Linux 5.13+).
    pub filesystem_restriction: bool,
    /// Additional read-only paths for the Landlock policy, beyond the
    /// built-in system set. Used by tests for the fixture scripts and by
    /// operators for non-FHS install prefixes.
    pub extra_read_only_paths: Vec<PathBuf>,
}

impl Default for PiSandboxConfig {
    fn default() -> Self {
        Self {
            network_isolation: true,
            filesystem_restriction: true,
            extra_read_only_paths: Vec::new(),
        }
    }
}

/// Paths the sandbox policy is built from. All are resolved (and, where
/// needed, created) by the supervisor before the spawn.
pub struct PiSandboxPaths<'a> {
    /// The Pi binary (or wrapper script) to execute.
    pub pi_binary: &'a Path,
    /// Lumen-owned session state directory (also used as the child's
    /// `HOME` so credential files resolve inside the sandbox).
    pub session_dir: &'a Path,
    /// Per-session writable scratch dir (also the child's `TMPDIR` and
    /// working directory).
    pub tmp_dir: &'a Path,
    /// Parent directory of the kernel-channel Unix socket, when the
    /// channel is configured. The child needs it to dial the kernel.
    pub socket_dir: Option<&'a Path>,
}

/// Errors from sandbox setup. Any of these aborts the spawn: Pi never
/// runs unsandboxed.
#[derive(Debug, Error)]
pub enum PiSandboxError {
    #[error("failed to prepare session dir {path}: {source}")]
    SessionDir { path: PathBuf, source: io::Error },
    #[error("failed to prepare session tmp dir {path}: {source}")]
    TmpDir { path: PathBuf, source: io::Error },
    #[error("failed to prepare socket dir {path}: {source}")]
    SocketDir { path: PathBuf, source: io::Error },
    #[error("network isolation failed: {0}")]
    Network(String),
    #[error("filesystem restriction failed: {0}")]
    Filesystem(String),
    // Only constructed on non-Linux targets (the Linux branch is
    // compiled out there); the variant documents the platform contract.
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    #[error("OS process sandboxing is only supported on Linux")]
    UnsupportedPlatform,
}

/// Apply the Pi sandbox to a child command: scrub the environment, set
/// the contract variables, and install the pre-`exec` confinement hook.
///
/// `extra_env` carries the `LUMEN_*` contract variables; they are the
/// only caller-controlled variables the child receives.
pub fn configure_child(
    cmd: &mut std::process::Command,
    config: &PiSandboxConfig,
    paths: &PiSandboxPaths<'_>,
    extra_env: &[(&str, &str)],
) -> Result<(), PiSandboxError> {
    // The policy needs real paths: the session dirs must exist before
    // any Landlock rule can reference them.
    std::fs::create_dir_all(paths.session_dir).map_err(|e| PiSandboxError::SessionDir {
        path: paths.session_dir.to_path_buf(),
        source: e,
    })?;
    std::fs::create_dir_all(paths.tmp_dir).map_err(|e| PiSandboxError::TmpDir {
        path: paths.tmp_dir.to_path_buf(),
        source: e,
    })?;
    if let Some(dir) = paths.socket_dir {
        std::fs::create_dir_all(dir).map_err(|e| PiSandboxError::SocketDir {
            path: dir.to_path_buf(),
            source: e,
        })?;
    }

    // Layer 1: scrub the environment. The child inherits nothing — not
    // even the variables the supervisor itself was started with.
    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    // Credential files resolve inside the sandbox, never in the
    // operator's home.
    cmd.env("HOME", paths.session_dir);
    cmd.env("TMPDIR", paths.tmp_dir);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    // The supervisor's cwd is outside the Landlock policy; start the
    // child somewhere it is allowed to be.
    cmd.current_dir(paths.tmp_dir);

    // Layers 2+3: Linux-only, applied after fork, before exec.
    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let policy = FilesystemPolicy::build(config, paths)?;
        let network_isolation = config.network_isolation;
        let filesystem_restriction = config.filesystem_restriction;
        // SAFETY: `pre_exec` runs in the child after `fork(2)`. The
        // closure performs only syscalls and file writes on
        // already-resolved owned data; on error the spawn fails and the
        // child never execs.
        unsafe {
            cmd.pre_exec(move || {
                if network_isolation {
                    isolate_network(uid, gid)
                        .map_err(PiSandboxError::Network)
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
                        })?;
                }
                if filesystem_restriction {
                    policy
                        .apply()
                        .map_err(PiSandboxError::Filesystem)
                        .map_err(|e| {
                            io::Error::new(io::ErrorKind::PermissionDenied, e.to_string())
                        })?;
                }
                Ok(())
            });
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (config, paths, extra_env);
        Err(PiSandboxError::UnsupportedPlatform)
    }
}

// ---------------------------------------------------------------------------
// Layer 2: network namespace
// ---------------------------------------------------------------------------

/// Move the calling process into a fresh network namespace: no
/// interfaces come up, so no INET traffic can leave (or enter).
fn isolate_network(uid: u32, gid: u32) -> Result<(), String> {
    // Privileged fast path: a bare network namespace keeps the child's
    // uid/gid and drops all network interfaces.
    // SAFETY: `unshare` with a single namespace flag has no
    // memory-safety implications.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() != Some(libc::EPERM) {
        return Err(format!("unshare(CLONE_NEWNET): {err}"));
    }
    // Unprivileged fallback: a user namespace first grants the
    // capability to create the network namespace. The 1:1 id map keeps
    // the child's filesystem view identical to the supervisor's.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET) } != 0 {
        return Err(format!(
            "unshare(CLONE_NEWUSER|CLONE_NEWNET): {}",
            io::Error::last_os_error()
        ));
    }
    // `setgroups` must be denied before the gid map can be written by a
    // non-root userns owner; failure here surfaces as the gid_map error
    // below, so the result is intentionally unchecked.
    let _ = std::fs::write("/proc/self/setgroups", b"deny");
    std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n").as_bytes())
        .map_err(|e| format!("write /proc/self/uid_map: {e}"))?;
    std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n").as_bytes())
        .map_err(|e| format!("write /proc/self/gid_map: {e}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Layer 3: Landlock filesystem policy
// ---------------------------------------------------------------------------

// Landlock access rights (linux/landlock.h). Bits 0-12 are ABI v1,
// bit 13 is ABI v2, bit 14 is ABI v3.
const LL_EXECUTE: u64 = 1 << 0;
const LL_WRITE_FILE: u64 = 1 << 1;
const LL_READ_FILE: u64 = 1 << 2;
const LL_READ_DIR: u64 = 1 << 3;
const LL_REMOVE_DIR: u64 = 1 << 4;
const LL_REMOVE_FILE: u64 = 1 << 5;
const LL_MAKE_CHAR: u64 = 1 << 6;
const LL_MAKE_DIR: u64 = 1 << 7;
const LL_MAKE_REG: u64 = 1 << 8;
const LL_MAKE_SOCK: u64 = 1 << 9;
const LL_MAKE_FIFO: u64 = 1 << 10;
const LL_MAKE_BLOCK: u64 = 1 << 11;
const LL_MAKE_SYM: u64 = 1 << 12;
const LL_REFER: u64 = 1 << 13;
const LL_TRUNCATE: u64 = 1 << 14;

/// Read + list + traverse: the system hierarchy grant.
const RO_EXEC: u64 = LL_READ_FILE | LL_READ_DIR | LL_EXECUTE;
/// Everything: the session-area grant.
const ALL_FS: u64 = LL_EXECUTE
    | LL_WRITE_FILE
    | LL_READ_FILE
    | LL_READ_DIR
    | LL_REMOVE_DIR
    | LL_REMOVE_FILE
    | LL_MAKE_CHAR
    | LL_MAKE_DIR
    | LL_MAKE_REG
    | LL_MAKE_SOCK
    | LL_MAKE_FIFO
    | LL_MAKE_BLOCK
    | LL_MAKE_SYM
    | LL_REFER
    | LL_TRUNCATE;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

struct FsRule {
    path: PathBuf,
    access: u64,
    /// Built-in system paths may be absent on some distributions
    /// (e.g. no `/sbin`); session paths must always exist.
    required: bool,
}

struct FilesystemPolicy {
    rules: Vec<FsRule>,
}

impl FilesystemPolicy {
    fn build(config: &PiSandboxConfig, paths: &PiSandboxPaths<'_>) -> Result<Self, PiSandboxError> {
        let mut rules = Vec::new();
        // System hierarchy: readable and executable, never writable.
        // Absent dirs are skipped — distributions vary.
        for dir in [
            "/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt", "/sys", "/proc",
        ] {
            rules.push(FsRule {
                path: PathBuf::from(dir),
                access: RO_EXEC,
                required: false,
            });
        }
        // Device nodes: no blanket /dev access. The child gets exactly
        // the nodes a userspace runtime needs.
        for (node, access) in [
            ("/dev/null", LL_READ_FILE | LL_WRITE_FILE),
            ("/dev/zero", LL_READ_FILE),
            ("/dev/urandom", LL_READ_FILE),
        ] {
            rules.push(FsRule {
                path: PathBuf::from(node),
                access,
                required: false,
            });
        }
        // The Pi binary itself: read + execute. (For a wrapper script
        // the interpreter comes from the /bin rule above.)
        rules.push(FsRule {
            path: paths.pi_binary.to_path_buf(),
            access: LL_READ_FILE | LL_EXECUTE,
            required: true,
        });
        // Writable sandbox areas.
        rules.push(FsRule {
            path: paths.session_dir.to_path_buf(),
            access: ALL_FS,
            required: true,
        });
        rules.push(FsRule {
            path: paths.tmp_dir.to_path_buf(),
            access: ALL_FS,
            required: true,
        });
        if let Some(dir) = paths.socket_dir {
            rules.push(FsRule {
                path: dir.to_path_buf(),
                access: ALL_FS,
                required: true,
            });
        }
        for extra in &config.extra_read_only_paths {
            rules.push(FsRule {
                path: extra.clone(),
                access: RO_EXEC,
                required: true,
            });
        }
        Ok(Self { rules })
    }

    /// Highest supported Landlock ABI version, via the
    /// `LANDLOCK_CREATE_RULESET_VERSION` query.
    fn abi_version() -> Result<u32, String> {
        // SAFETY: version query takes no pointers.
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                0,
                0,
                LANDLOCK_CREATE_RULESET_VERSION as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(format!(
                "Landlock unavailable: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(ret as u32)
    }

    /// Install the policy on the calling process. Deny-by-default: any
    /// path without a matching rule is inaccessible afterwards.
    fn apply(&self) -> Result<(), String> {
        let handled: u64 = match Self::abi_version()? {
            1 => (1 << 13) - 1,
            2 => (1 << 14) - 1,
            v if v >= 3 => (1 << 15) - 1,
            v => return Err(format!("unsupported Landlock ABI version {v}")),
        };
        let attr = LandlockRulesetAttr {
            handled_access_fs: handled & ALL_FS,
        };
        // SAFETY: `attr` is a valid ruleset attribute struct; size is exact.
        let ruleset_fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0,
            )
        };
        if ruleset_fd < 0 {
            return Err(format!(
                "landlock_create_ruleset: {}",
                io::Error::last_os_error()
            ));
        }
        let ruleset_fd = ruleset_fd as i32;
        for rule in &self.rules {
            let access = rule.access & handled;
            if access == 0 {
                continue;
            }
            let fd = match open_rule_fd(&rule.path, rule.required)? {
                Some(fd) => fd,
                None => continue,
            };
            let rule_attr = LandlockPathBeneathAttr {
                allowed_access: access,
                parent_fd: fd,
            };
            // SAFETY: `rule_attr` is a valid path-beneath rule; the fd is
            // open and valid for the duration of the call.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH as libc::c_ulong,
                    &rule_attr as *const LandlockPathBeneathAttr,
                    0,
                )
            };
            // SAFETY: fd was returned by `open`.
            unsafe { libc::close(fd) };
            if r != 0 {
                // SAFETY: ruleset_fd was returned by the kernel.
                unsafe { libc::close(ruleset_fd) };
                return Err(format!(
                    "landlock_add_rule({}): {}",
                    rule.path.display(),
                    io::Error::last_os_error()
                ));
            }
        }
        // SAFETY: ruleset_fd is valid; on success the restriction
        // persists on the process independently of the fd.
        let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
        unsafe { libc::close(ruleset_fd) };
        if r != 0 {
            return Err(format!(
                "landlock_restrict_self: {}",
                io::Error::last_os_error()
            ));
        }
        Ok(())
    }
}

/// Open a path for use as a Landlock rule fd. Missing paths are
/// tolerated only for non-required (built-in system) entries.
fn open_rule_fd(path: &Path, required: bool) -> Result<Option<i32>, String> {
    let cpath = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("landlock path contains NUL: {}", path.display()))?;
    // SAFETY: `cpath` is a valid NUL-terminated string; O_PATH opens
    // without requiring read permission on the target.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if !required && err.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!(
            "cannot open landlock path {}: {err}",
            path.display()
        ));
    }
    Ok(Some(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    fn test_paths(tag: &str) -> PiSandboxPaths<'static> {
        // Leaked on purpose: the tests need 'static paths and the
        // TempDir must outlive the child. The OS reclaims /tmp.
        let dir: &'static tempfile::TempDir =
            Box::leak(Box::new(tempfile::TempDir::new().unwrap()));
        let session_dir: &'static Path = Box::leak(dir.path().join("sessions").into_boxed_path());
        let tmp_dir: &'static Path =
            Box::leak(dir.path().join(format!("tmp-{tag}")).into_boxed_path());
        std::fs::create_dir_all(session_dir).unwrap();
        PiSandboxPaths {
            pi_binary: Path::new("/bin/sh"),
            session_dir,
            tmp_dir,
            socket_dir: None,
        }
    }

    fn run_sandboxed(
        extra_env: &[(&str, &str)],
        sh_cmd: &str,
        paths: &PiSandboxPaths<'_>,
    ) -> String {
        let mut cmd = std::process::Command::new("/bin/sh");
        // A canary the sandbox must strip: proves pre-existing
        // environment does not leak into the child.
        cmd.env("LUMEN_TEST_CANARY", "super-secret-canary");
        cmd.args(["-c", sh_cmd]);
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_child(&mut cmd, &PiSandboxConfig::default(), paths, extra_env)
            .expect("sandbox setup must succeed in tests");
        let out = cmd.output().expect("spawn must succeed");
        assert!(
            out.status.success(),
            "sandboxed sh failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_scrubs_inherited_environment() {
        let paths = test_paths("env");
        let out = run_sandboxed(&[("LUMEN_SESSION_ID", "sess-123")], "env | sort", &paths);
        // The contract variable survives.
        assert!(
            out.contains("LUMEN_SESSION_ID=sess-123"),
            "contract env missing:\n{out}"
        );
        // The canary must not.
        assert!(
            !out.contains("LUMEN_TEST_CANARY"),
            "ambient env leaked into child:\n{out}"
        );
        // PATH is the scrubbed minimal value.
        assert!(
            out.contains("PATH=/usr/bin:/bin"),
            "PATH not scrubbed:\n{out}"
        );
        // HOME/TMPDIR point inside the sandbox.
        assert!(
            out.contains(&format!("HOME={}", paths.session_dir.display())),
            "HOME not redirected:\n{out}"
        );
        assert!(
            out.contains(&format!("TMPDIR={}", paths.tmp_dir.display())),
            "TMPDIR not redirected:\n{out}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_denies_host_tmp_writes() {
        let paths = test_paths("tmpw");
        let out = run_sandboxed(
            &[],
            "touch /tmp/lumen-sandbox-probe && echo VULNERABLE || echo DENIED",
            &paths,
        );
        assert!(
            out.contains("DENIED"),
            "child wrote to host /tmp! output:\n{out}"
        );
        assert!(
            !std::path::Path::new("/tmp/lumen-sandbox-probe").exists(),
            "probe file exists on host /tmp"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_allows_session_tmp_writes() {
        let paths = test_paths("tmprw");
        let out = run_sandboxed(&[], "touch \"$TMPDIR/probe\" && echo WRITABLE", &paths);
        assert!(
            out.contains("WRITABLE"),
            "child could not write TMPDIR:\n{out}"
        );
        assert!(paths.tmp_dir.join("probe").exists());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_has_no_network_interfaces() {
        let paths = test_paths("net");
        // A fresh network namespace contains only the (down) loopback.
        // NOTE: /sys/class/net is not namespace-filtered on this
        // kernel, so /proc/net/dev is the reliable source.
        let out = run_sandboxed(
            &[],
            "awk -F: '/:/ {gsub(/ /, \"\", $1); print $1}' /proc/net/dev | grep -v '^Inter' | sort",
            &paths,
        );
        let ifaces: Vec<&str> = out.split_whitespace().collect();
        assert_eq!(
            ifaces,
            vec!["lo"],
            "expected only loopback in sandbox netns, saw: {ifaces:?}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_denies_host_filesystem_reads() {
        let paths = test_paths("home");
        // The crate's own manifest is guaranteed to exist and be
        // readable — but it lives outside the sandbox policy.
        let manifest = env!("CARGO_MANIFEST_DIR");
        let probe =
            format!("cat {manifest}/Cargo.toml >/dev/null 2>&1 && echo VULNERABLE || echo DENIED");
        let out = run_sandboxed(&[], &probe, &paths);
        assert!(
            out.contains("DENIED"),
            "child read host files outside the policy! output:\n{out}"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_setup_failure_aborts_before_fork() {
        // session_dir nested under a regular file: create_dir_all
        // fails with ENOTDIR, so configure_child must refuse before
        // any child exists — Pi never runs half-confined.
        let dir = tempfile::TempDir::new().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let mut cmd = std::process::Command::new("/bin/sh");
        let err = configure_child(
            &mut cmd,
            &PiSandboxConfig::default(),
            &PiSandboxPaths {
                pi_binary: Path::new("/bin/sh"),
                session_dir: &file.join("sessions"),
                tmp_dir: &dir.path().join("tmp"),
                socket_dir: None,
            },
            &[],
        )
        .expect_err("sandbox setup must fail");
        assert!(
            matches!(err, PiSandboxError::SessionDir { .. }),
            "unexpected error: {err:?}"
        );
    }
}
