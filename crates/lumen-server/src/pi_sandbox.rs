//! OS-enforced confinement for the Pi agent-loop subprocess.
//!
//! Pi is untrusted: the model, its extensions, and any child process it
//! spawns must not reach the host network, ambient credentials, or host
//! files outside an explicit allowlist. This module applies four
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
//! 2. **User, network, and mount namespaces** (Linux). The child is moved
//!    into a fresh user namespace where it is uid/gid 0, mapped to a
//!    dedicated unprivileged host uid/gid (default `65534:nobody`) —
//!    never the supervisor's uid and never host root. (A non-root
//!    supervisor can only 1:1-map its own uid, and so can a supervisor
//!    that is uid 0 inside a container user namespace; the dedicated
//!    map is attempted first and the 1:1 self-map is the fallback.
//!    Every other layer still applies, so the fallback is confined, not
//!    unsandboxed.) It also enters a fresh network
//!    namespace with no interfaces and no routes — no INET traffic can
//!    leave or enter — and a private mount namespace in which a fresh
//!    `procfs` with `hidepid=2` is mounted over `/proc`, so Pi sees only
//!    its own processes. (Deliberately no PID namespace:
//!    `unshare(CLONE_NEWPID)` only affects subsequently forked children,
//!    so it cannot take effect inside the `pre_exec` hook — a correct PID
//!    namespace needs a double-fork trampoline, which is fragile in a
//!    post-fork child. The fresh `hidepid=2` procfs provides the same
//!    security property: host processes are invisible, and the user
//!    namespace already makes them unsignallable/unptraceable.)
//!    Unix-domain sockets (the kernel channel) and the inherited stdio
//!    pipes are unaffected.
//! 3. **Landlock filesystem policy** (Linux 5.13+). Minimal allowlist:
//!    the system library/binary hierarchy (`/usr`, `/bin`, `/sbin`,
//!    `/lib`, `/lib64`) read/execute; the fresh `/proc` read-only; a
//!    handful of device nodes (`/dev/null`, `/dev/zero`, `/dev/urandom`);
//!    the Pi binary read/execute; the per-session directories
//!    read/write; the kernel-socket directory traversable with file
//!    write (so the child can `connect(2)` to the socket) but never
//!    create/remove/rename. `/etc`, `/opt`, `/sys`, and the host `/tmp`
//!    are deliberately NOT granted — any path without a rule is denied
//!    by the kernel. Runtimes needing extra files (CA bundles, config)
//!    declare them in `extra_read_only_paths`.
//! 4. **No-new-privs.** `PR_SET_NO_NEW_PRIVS` is set before the Landlock
//!    policy is installed, so the child can never gain privilege via
//!    setuid binaries after `exec`.
//!
//! Layers 2–4 are applied in the child after `fork(2)` and before
//! `exec(2)` via [`std::os::unix::process::CommandExt::pre_exec`]. That
//! closure runs in a child of a multithreaded tokio process, so it uses
//! only async-signal-safe raw syscalls with stack buffers — no
//! allocation, no locks. Any failure aborts the spawn: the child never
//! runs unsandboxed (fail closed). The sandbox is configurable
//! ([`PiSandboxConfig`]) but every layer defaults to on; disabling a
//! layer is an explicit, reviewable weakening of the posture, not a
//! silent fallback.
//!
//! # Residual risks (documented, not ignored)
//!
//! - `/proc/self/mountinfo` reveals the host's mount *paths* (not file
//!   contents); file access outside the policy is still denied by
//!   Landlock.
//! - Sharing the host PID namespace leaves a PID-liveness oracle:
//!   `kill(pid, 0)` answers EPERM for a live host PID vs ESRCH for a
//!   free one, and PID values are scannable by repeated probing, so an
//!   attacker can enumerate *which PIDs are live*. What the oracle does
//!   not give: any identity for those PIDs. The fresh `hidepid=2`
//!   procfs hides other users' processes, and no signal, ptrace, or
//!   `/proc/<pid>/environ` read can cross the user namespace -- verified
//!   empirically: even with a 1:1 uid map, opening another userns's
//!   `/proc/<pid>/environ` fails with EPERM. So the residual is a
//!   liveness-only oracle (an attacker learns that host processes
//!   exist, not what they are), not a process-information leak.
//!   A PID namespace would additionally close the oracle itself, but
//!   `unshare(CLONE_NEWPID)` cannot take effect inside the `pre_exec`
//!   hook (it only affects subsequently forked children), so a correct
//!   implementation needs a double-fork trampoline: the supervisor's
//!   tracked PID would become the trampoline rather than Pi, and kills
//!   would have to be forwarded across the namespace boundary in
//!   async-signal-safe post-fork code. A SIGKILLed trampoline orphans
//!   Pi outside supervision -- a genuine escape risk traded for closing
//!   a liveness-only oracle. The deviation is deliberate and
//!   documented here, not an oversight.
//! - A supervisor that cannot map the dedicated sandbox uid (a non-root
//!   supervisor, or uid 0 inside a container user namespace -- the
//!   kernel only permits a 1:1 self-map there) falls back to mapping
//!   its own uid 1:1. Prefer running the supervisor as root on the
//!   host so the child maps to the dedicated sandbox uid.
//! - Sandbox paths are group-mediated, never child-chowned: the session
//!   dirs are `(supervisor_uid, sandbox_gid)` mode 0770, the socket dir
//!   `(supervisor_uid, sandbox_gid)` mode 0750, and the socket itself
//!   `(supervisor_uid, sandbox_gid)` mode 0620. A 1:1 fallback child
//!   reaches them as the owner; a dedicated-map child via the group.
//!   A dedicated-map child has no privilege over supervisor-owned
//!   inodes, so a child-side chown could never work -- ownership is
//!   established parent-side in `configure_child`, before the spawn.
//!   Files the child creates are owned by the sandbox uid on the host;
//!   the Pi binary and its runtime must be readable/executable by that
//!   uid. `sandbox_uid`/`sandbox_gid` must be dedicated to Lumen: the
//!   group grants write on every session dir and connect on the
//!   kernel socket.
//! - Landlock is allowlist-based: any path not covered by a rule is
//!   denied. If Pi's runtime needs a path outside the policy (e.g. a
//!   non-FHS install prefix, `/etc/ssl/certs`), the spawn fails loudly
//!   rather than running half-confined; extend `extra_read_only_paths`.

use std::{
    io,
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
};

use thiserror::Error;

/// Unprivileged host identity the sandboxed child maps to. `65534` is
/// `nobody`/`nogroup` on virtually every Linux distribution.
pub const SANDBOX_UID: u32 = 65534;
pub const SANDBOX_GID: u32 = 65534;

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
    /// built-in minimal set. Used by tests for the fixture scripts, by
    /// operators for non-FHS install prefixes, and for runtime-specific
    /// files such as CA bundles (`/etc/ssl/certs`).
    pub extra_read_only_paths: Vec<PathBuf>,
    /// Host uid the child maps to inside its user namespace (the child
    /// is uid 0 inside). Must be unprivileged (non-zero). Only used
    /// when the supervisor itself runs as root; a non-root supervisor
    /// can only 1:1-map its own uid.
    pub sandbox_uid: u32,
    /// Host gid, same contract as `sandbox_uid`.
    pub sandbox_gid: u32,
}

impl Default for PiSandboxConfig {
    fn default() -> Self {
        Self {
            network_isolation: true,
            filesystem_restriction: true,
            extra_read_only_paths: Vec::new(),
            sandbox_uid: SANDBOX_UID,
            sandbox_gid: SANDBOX_GID,
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
    /// The socket file itself is parent-owned, group `sandbox_gid`,
    /// mode 0620 (see `kernel_channel::KernelChannel::serve`); the
    /// directory is group-traversable but never group-writable, so the
    /// child can reach the socket but cannot replace it.
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
    #[error("invalid sandbox config: {0}")]
    Config(String),
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    #[error("OS process sandboxing is only supported on Linux")]
    UnsupportedPlatform,
}

/// Parent-side group mediation for a sandbox path: chown to
/// `(supervisor_uid, sandbox_gid)` and set `mode`.
///
/// Both user-namespace outcomes must keep working, and the parent --
/// unlike the child -- can set this up before the spawn:
/// - a 1:1 fallback child is the owner (`supervisor_uid`);
/// - a dedicated-map child reaches the path via the group
///   (`sandbox_gid`).
///
/// A child-side chown cannot do this job: a dedicated-map child has no
/// privilege over supervisor-owned inodes, so it could never take
/// ownership of them.
///
/// A non-root supervisor cannot chown to an arbitrary group, but it
/// also cannot map the dedicated sandbox uid, so leaving the path
/// owner-only is exactly right there (`Ok(false)`). Only failure as
/// root is unexpected and fails the spawn.
#[cfg(target_os = "linux")]
fn mediate_sandbox_path(
    path: &Path,
    supervisor_uid: u32,
    sandbox_gid: u32,
    mode: u32,
) -> Result<bool, PiSandboxError> {
    use std::os::unix::fs::PermissionsExt;
    let cstr = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| {
        PiSandboxError::Config(format!("path is not a valid C string: {}", path.display()))
    })?;
    let group_ok = unsafe { libc::chown(cstr.as_ptr(), supervisor_uid, sandbox_gid) } == 0;
    if !group_ok && supervisor_uid == 0 {
        return Err(PiSandboxError::Config(format!(
            "could not chown {} to sandbox group {sandbox_gid}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        PiSandboxError::Config(format!(
            "could not chmod {} to {mode:o}: {e}",
            path.display()
        ))
    })?;
    Ok(group_ok)
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
    if config.sandbox_uid == 0 || config.sandbox_gid == 0 {
        return Err(PiSandboxError::Config(
            "sandbox_uid/sandbox_gid must be unprivileged (non-zero)".to_string(),
        ));
    }
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

    #[cfg(target_os = "linux")]
    {
        // Parent-side ownership, before the spawn: the sandbox dirs and
        // the socket dir are `(supervisor_uid, sandbox_gid)`. A 1:1
        // fallback child reaches them as the owner; a dedicated-map
        // child reaches them via the group. This must happen here, not
        // in the child: a dedicated-map child has no privilege over
        // supervisor-owned inodes and could never chown them itself.
        let supervisor_uid = unsafe { libc::getuid() };
        mediate_sandbox_path(paths.session_dir, supervisor_uid, config.sandbox_gid, 0o770)?;
        mediate_sandbox_path(paths.tmp_dir, supervisor_uid, config.sandbox_gid, 0o770)?;
        if let Some(dir) = paths.socket_dir {
            // Traversable, never writable: the child reaches the
            // pre-created socket but cannot create, replace, or remove
            // files here (Landlock denies that too, belt and braces).
            mediate_sandbox_path(dir, supervisor_uid, config.sandbox_gid, 0o750)?;
        }
    }

    cmd.env_clear();
    cmd.env("PATH", "/usr/bin:/bin");
    cmd.env("HOME", paths.session_dir);
    cmd.env("TMPDIR", paths.tmp_dir);
    for (key, value) in extra_env {
        cmd.env(key, value);
    }
    cmd.current_dir(paths.tmp_dir);

    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::getuid() };
        let gid = unsafe { libc::getgid() };
        let policy = FilesystemPolicy::build(config, paths)?;
        let sandbox_uid = config.sandbox_uid;
        let sandbox_gid = config.sandbox_gid;
        let network_isolation = config.network_isolation;
        let filesystem_restriction = config.filesystem_restriction;
        unsafe {
            cmd.pre_exec(move || {
                isolate_child(uid, gid, sandbox_uid, sandbox_gid, network_isolation)
                    .map_err(io::Error::from_raw_os_error)?;
                // Directory and socket ownership was established
                // parent-side in `configure_child` (group-mediated, so
                // both userns outcomes work). Nothing to chown here: a
                // dedicated-map child has no privilege over
                // supervisor-owned inodes.
                if filesystem_restriction {
                    policy.apply().map_err(io::Error::from_raw_os_error)?;
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

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(target_os = "linux")]
fn write_file_raw(path: &std::ffi::CStr, data: &[u8]) -> Result<(), i32> {
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(last_errno());
    }
    let mut written = 0usize;
    while written < data.len() {
        let r = unsafe {
            libc::write(
                fd,
                data[written..].as_ptr() as *const libc::c_void,
                (data.len() - written) as libc::size_t,
            )
        };
        if r < 0 {
            let e = last_errno();
            unsafe { libc::close(fd) };
            return Err(e);
        }
        written += r as usize;
    }
    unsafe { libc::close(fd) };
    Ok(())
}

#[cfg(target_os = "linux")]
fn push_u32(buf: &mut [u8], mut v: u32) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut rev = [0u8; 10];
    let mut len = 0usize;
    while v > 0 {
        rev[len] = b'0' + (v % 10) as u8;
        v /= 10;
        len += 1;
    }
    for i in 0..len {
        buf[i] = rev[len - 1 - i];
    }
    len
}

#[cfg(target_os = "linux")]
fn write_id_map(path: &std::ffi::CStr, inner: u32, outer: u32) -> Result<(), i32> {
    let mut buf = [0u8; 32];
    let mut n = 0usize;
    n += push_u32(&mut buf[n..], inner);
    buf[n] = b' ';
    n += 1;
    n += push_u32(&mut buf[n..], outer);
    buf[n] = b' ';
    n += 1;
    buf[n] = b'1';
    n += 1;
    buf[n] = b'\n';
    n += 1;
    write_file_raw(path, &buf[..n])
}

#[cfg(target_os = "linux")]
fn isolate_child(
    uid: u32,
    gid: u32,
    sandbox_uid: u32,
    sandbox_gid: u32,
    network_isolation: bool,
) -> Result<(), i32> {
    let mut flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS;
    if network_isolation {
        flags |= libc::CLONE_NEWNET;
    }
    if unsafe { libc::unshare(flags) } != 0 {
        return Err(last_errno());
    }
    write_file_raw(c"/proc/self/setgroups", b"deny")?;
    // Identity for the new user namespace: the dedicated unprivileged
    // sandbox uid when the supervisor can map it, else a 1:1 map of
    // the supervisor's own uid. A supervisor that is uid 0 inside a
    // container user namespace cannot map arbitrary uids -- the kernel
    // only permits a 1:1 self-map there -- so the dedicated map is
    // attempted first and the 1:1 map is the fallback, not a failure:
    // every other layer (network/mount namespaces, Landlock,
    // no-new-privs) still applies, so the fallback is confined, not
    // unsandboxed.
    let (outer_uid, outer_gid) = if uid == 0 {
        (sandbox_uid, sandbox_gid)
    } else {
        (uid, gid)
    };
    let uid_ok = write_id_map(c"/proc/self/uid_map", 0, outer_uid).is_ok();
    let gid_ok = write_id_map(c"/proc/self/gid_map", 0, outer_gid).is_ok();
    if !(uid_ok && gid_ok) {
        if uid_ok {
            // The uid map landed but the gid map did not: no coherent
            // identity can be established. Fail closed. (In practice
            // the kernel accepts or rejects both maps together.)
            return Err(libc::EPERM);
        }
        // Neither map landed, so the dedicated identity was refused: a
        // failed map write does not consume the one-shot, so retry
        // with the 1:1 self map.
        write_id_map(c"/proc/self/uid_map", 0, uid)?;
        write_id_map(c"/proc/self/gid_map", 0, gid)?;
    }
    if unsafe {
        libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(last_errno());
    }
    if unsafe {
        libc::mount(
            c"proc".as_ptr(),
            c"/proc".as_ptr(),
            c"proc".as_ptr(),
            (libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NODEV) as libc::c_ulong,
            c"hidepid=2".as_ptr() as *const libc::c_void,
        )
    } != 0
    {
        return Err(last_errno());
    }
    Ok(())
}

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

const RO_EXEC: u64 = LL_READ_FILE | LL_READ_DIR | LL_EXECUTE;
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
const SOCKET_DIR: u64 = LL_READ_FILE | LL_READ_DIR | LL_EXECUTE | LL_WRITE_FILE;

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
    required: bool,
}

struct FilesystemPolicy {
    rules: Vec<FsRule>,
}

impl FilesystemPolicy {
    fn build(config: &PiSandboxConfig, paths: &PiSandboxPaths<'_>) -> Result<Self, PiSandboxError> {
        let mut rules = Vec::new();
        for dir in ["/usr", "/bin", "/sbin", "/lib", "/lib64"] {
            rules.push(FsRule {
                path: PathBuf::from(dir),
                access: RO_EXEC,
                required: false,
            });
        }
        rules.push(FsRule {
            path: PathBuf::from("/proc"),
            access: RO_EXEC,
            required: false,
        });
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
        rules.push(FsRule {
            path: paths.pi_binary.to_path_buf(),
            access: LL_READ_FILE | LL_EXECUTE,
            required: true,
        });
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
                access: SOCKET_DIR,
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

    fn abi_version() -> Result<u32, i32> {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                0,
                0,
                LANDLOCK_CREATE_RULESET_VERSION as libc::c_ulong,
            )
        };
        if ret < 0 {
            return Err(last_errno());
        }
        Ok(ret as u32)
    }

    fn apply(&self) -> Result<(), i32> {
        if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(last_errno());
        }
        let handled: u64 = match Self::abi_version()? {
            1 => (1 << 13) - 1,
            2 => (1 << 14) - 1,
            v if v >= 3 => (1 << 15) - 1,
            _ => return Err(libc::EINVAL),
        };
        let attr = LandlockRulesetAttr {
            handled_access_fs: handled & ALL_FS,
        };
        let ruleset_fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0,
            )
        };
        if ruleset_fd < 0 {
            return Err(last_errno());
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
            let r = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH as libc::c_ulong,
                    &rule_attr as *const LandlockPathBeneathAttr,
                    0,
                )
            };
            unsafe { libc::close(fd) };
            if r != 0 {
                unsafe { libc::close(ruleset_fd) };
                return Err(last_errno());
            }
        }
        let r = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
        unsafe { libc::close(ruleset_fd) };
        if r != 0 {
            return Err(last_errno());
        }
        Ok(())
    }
}

fn open_rule_fd(path: &Path, required: bool) -> Result<Option<i32>, i32> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0) {
        return Err(libc::EINVAL);
    }
    let mut buf = [0u8; 4096];
    if bytes.len() + 1 > buf.len() {
        return Err(libc::ENAMETOOLONG);
    }
    buf[..bytes.len()].copy_from_slice(bytes);
    let fd = unsafe {
        libc::open(
            buf.as_ptr() as *const libc::c_char,
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        let e = last_errno();
        if !required && e == libc::ENOENT {
            return Ok(None);
        }
        return Err(e);
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
        let socket_dir: &'static Path =
            Box::leak(dir.path().join(format!("sock-{tag}")).into_boxed_path());
        std::fs::create_dir_all(session_dir).unwrap();
        PiSandboxPaths {
            pi_binary: Path::new("/bin/sh"),
            session_dir,
            tmp_dir,
            socket_dir: Some(socket_dir),
        }
    }

    /// `configure_child` establishes sandbox ownership parent-side:
    /// session/tmp dirs `(supervisor_uid, sandbox_gid)` mode 0770, the
    /// socket dir `(supervisor_uid, sandbox_gid)` mode 0750. A 1:1
    /// fallback child reaches them as the owner; a dedicated-map child
    /// via the group. No child-side chown is needed (or possible: a
    /// dedicated-map child has no privilege over supervisor-owned
    /// inodes).
    #[test]
    fn configure_child_mediates_sandbox_paths_parent_side() {
        use std::os::unix::fs::MetadataExt;
        let paths = test_paths("mediate");
        let mut cmd = std::process::Command::new("/bin/sh");
        configure_child(&mut cmd, &PiSandboxConfig::default(), &paths, &[])
            .expect("sandbox setup must succeed");
        let is_root = unsafe { libc::getuid() } == 0;
        for dir in [paths.session_dir, paths.tmp_dir] {
            let meta = std::fs::metadata(dir).unwrap();
            assert_eq!(meta.mode() & 0o777, 0o770, "dir mode: {}", dir.display());
            if is_root {
                assert_eq!(meta.uid(), 0, "dir owner: {}", dir.display());
                assert_eq!(meta.gid(), SANDBOX_GID, "dir group: {}", dir.display());
            }
        }
        let sockdir = paths.socket_dir.expect("test sets socket_dir");
        let meta = std::fs::metadata(sockdir).unwrap();
        // Traversable, never writable: the child reaches the socket
        // but cannot create or replace files here.
        assert_eq!(meta.mode() & 0o777, 0o750, "socket dir mode");
        if is_root {
            assert_eq!(meta.gid(), SANDBOX_GID, "socket dir group");
        }
    }

    fn run_sandboxed(
        extra_env: &[(&str, &str)],
        sh_cmd: &str,
        paths: &PiSandboxPaths<'_>,
    ) -> String {
        let mut cmd = std::process::Command::new("/bin/sh");
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
        assert!(
            out.contains("LUMEN_SESSION_ID=sess-123"),
            "contract env missing:\n{out}"
        );
        assert!(
            !out.contains("LUMEN_TEST_CANARY"),
            "ambient env leaked:\n{out}"
        );
        assert!(
            out.contains("PATH=/usr/bin:/bin"),
            "PATH not scrubbed:\n{out}"
        );
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
        assert!(out.contains("DENIED"), "child wrote to host /tmp!:\n{out}");
        assert!(!std::path::Path::new("/tmp/lumen-sandbox-probe").exists());
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
        let out = run_sandboxed(
            &[],
            "awk -F: '/:/ {gsub(/ /, \"\", $1); print $1}' /proc/net/dev | grep -v '^Inter' | sort",
            &paths,
        );
        let ifaces: Vec<&str> = out.split_whitespace().collect();
        assert_eq!(ifaces, vec!["lo"], "expected only lo, saw: {ifaces:?}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_denies_host_filesystem_reads() {
        let paths = test_paths("home");
        let manifest = env!("CARGO_MANIFEST_DIR");
        let probe =
            format!("cat {manifest}/Cargo.toml >/dev/null 2>&1 && echo VULNERABLE || echo DENIED");
        let out = run_sandboxed(&[], &probe, &paths);
        assert!(out.contains("DENIED"), "child read host files!:\n{out}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_hides_host_processes() {
        let paths = test_paths("prochide");
        if unsafe { libc::getuid() } == 0 {
            let host_pid = std::process::id();
            let out = run_sandboxed(
                &[],
                &format!("test -d /proc/{host_pid} && echo VISIBLE || echo HIDDEN"),
                &paths,
            );
            assert!(
                out.contains("HIDDEN"),
                "child saw host PID {host_pid}!:\n{out}"
            );
        }
        let out = run_sandboxed(&[], "test -d /proc/self && echo SELF_OK", &paths);
        assert!(out.contains("SELF_OK"), "child lost /proc/self!:\n{out}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_denies_etc_wholesale() {
        let paths = test_paths("etcdeny");
        let out = run_sandboxed(
            &[],
            "test -r /etc/passwd && echo VULNERABLE || echo DENIED",
            &paths,
        );
        assert!(out.contains("DENIED"), "child read /etc/passwd!:\n{out}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_denies_sys_wholesale() {
        let paths = test_paths("sysdeny");
        let out = run_sandboxed(
            &[],
            "test -r /sys/kernel/hostname && echo VULNERABLE || echo DENIED",
            &paths,
        );
        assert!(out.contains("DENIED"), "child read /sys!:\n{out}");
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_child_files_owned_by_sandbox_uid() {
        let paths = test_paths("uidmap");
        let out = run_sandboxed(&[], "touch \"$TMPDIR/owner-probe\" && echo DONE", &paths);
        assert!(out.contains("DONE"), "child write failed:\n{out}");
        let meta = std::fs::metadata(paths.tmp_dir.join("owner-probe")).unwrap();
        use std::os::unix::fs::MetadataExt;
        let owner = meta.uid();
        let supervisor_uid = unsafe { libc::getuid() };
        // Dedicated sandbox uid when the kernel permits the map; the
        // 1:1 fallback to the supervisor's own uid when it does not
        // (e.g. uid 0 inside a container user namespace). Either way
        // the child runs as a known, non-escalated identity.
        assert!(
            owner == SANDBOX_UID || owner == supervisor_uid,
            "owner {owner} is neither the sandbox uid nor the supervisor uid"
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_socket_dir_is_not_writable() {
        let paths = test_paths("sockdir");
        let socket_dir = paths.socket_dir.expect("test sets socket_dir");
        let out = run_sandboxed(
            &[("LUMEN_TEST_SOCKDIR", socket_dir.to_str().unwrap())],
            r#"d="$LUMEN_TEST_SOCKDIR"
               ls "$d" >/dev/null 2>&1 && echo LIST_OK
               touch "$d/evil" 2>/dev/null && echo VULNERABLE || echo DENIED_CREATE
               mkdir "$d/evildir" 2>/dev/null && echo VULNERABLE || echo DENIED_MKDIR"#,
            &paths,
        );
        assert!(out.contains("LIST_OK"), "list failed:\n{out}");
        assert!(out.contains("DENIED_CREATE"), "create allowed!:\n{out}");
        assert!(out.contains("DENIED_MKDIR"), "mkdir allowed!:\n{out}");
    }

    /// Pure-logic test: the Landlock rule set is verified without
    /// spawning (no namespaces needed), so it runs even where the
    /// kernel forbids nested user namespaces.
    #[test]
    fn filesystem_policy_builds_minimal_allowlist() {
        let dir = tempfile::TempDir::new().unwrap();
        let paths = PiSandboxPaths {
            pi_binary: Path::new("/bin/sh"),
            session_dir: &dir.path().join("sessions"),
            tmp_dir: &dir.path().join("tmp"),
            socket_dir: Some(dir.path()),
        };
        let policy =
            FilesystemPolicy::build(&PiSandboxConfig::default(), &paths).expect("policy builds");

        let rule = |p: &str| {
            policy
                .rules
                .iter()
                .find(|r| r.path == Path::new(p))
                .unwrap_or_else(|| panic!("missing rule for {p}"))
        };

        // System hierarchy: read/execute only.
        for dir in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc"] {
            assert_eq!(rule(dir).access, RO_EXEC, "{dir} must be read/execute-only");
        }
        // Broad sensitive trees get NO rule: access is denied by default.
        for dir in ["/etc", "/opt", "/sys", "/tmp", "/home", "/root"] {
            assert!(
                policy.rules.iter().all(|r| r.path != Path::new(dir)),
                "{dir} must have no Landlock rule"
            );
        }
        // The kernel-socket directory: traversable with file write (so
        // the child can connect(2) to the socket) but never
        // create/remove/rename -- the socket file itself cannot be
        // replaced or unlinked by Pi.
        let sock = rule(dir.path().to_str().unwrap());
        assert_eq!(sock.access, SOCKET_DIR);
        assert_eq!(
            sock.access & (LL_MAKE_REG | LL_MAKE_SOCK | LL_MAKE_FIFO | LL_MAKE_SYM),
            0
        );
        assert_eq!(sock.access & (LL_REMOVE_FILE | LL_REMOVE_DIR), 0);
        assert_ne!(
            sock.access & LL_WRITE_FILE,
            0,
            "connect(2) needs write on the socket"
        );
        // Per-session dirs are fully writable; the Pi binary is
        // read/execute.
        assert_eq!(
            rule(dir.path().join("sessions").to_str().unwrap()).access,
            ALL_FS
        );
        assert_eq!(
            rule(dir.path().join("tmp").to_str().unwrap()).access,
            ALL_FS
        );
        assert_eq!(
            rule("/bin/sh").access,
            LL_READ_FILE | LL_EXECUTE,
            "pi binary must be read/execute-only"
        );
    }

    #[test]
    fn sandbox_rejects_zero_sandbox_ids() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut cmd = std::process::Command::new("/bin/sh");
        let config = PiSandboxConfig {
            sandbox_uid: 0,
            ..PiSandboxConfig::default()
        };
        let err = configure_child(
            &mut cmd,
            &config,
            &PiSandboxPaths {
                pi_binary: Path::new("/bin/sh"),
                session_dir: &dir.path().join("sessions"),
                tmp_dir: &dir.path().join("tmp"),
                socket_dir: None,
            },
            &[],
        )
        .expect_err("zero sandbox_uid must be rejected");
        assert!(matches!(err, PiSandboxError::Config(_)));
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn sandbox_setup_failure_aborts_before_fork() {
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
        assert!(matches!(err, PiSandboxError::SessionDir { .. }));
    }
}
