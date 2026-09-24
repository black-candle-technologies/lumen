//! Seccomp filter generation for the Firecracker VMM process.
//!
//! Format reference: Firecracker `docs/seccompiler.md`. The JSON maps thread
//! categories (`vmm`, `api`, `vcpu`) to filters:
//!
//! ```json
//! {
//!   "vmm": {
//!     "default_action": "Trap",
//!     "filter_action": "Allow",
//!     "filter": [ { "syscall": "read", "comment": "..." } ]
//!   },
//!   "api": { ... },
//!   "vcpu": { ... }
//! }
//! ```
//!
//! `default_action: Trap` makes the filter fail closed: any syscall not on
//! the allowlist kills the VMM thread with SIGSYS. The allowlist below is
//! derived from Firecracker's published default filters for
//! `x86_64-unknown-linux-musl`. If it omits a syscall the pinned Firecracker
//! needs, the VMM dies at boot with SIGSYS — the KVM-gated boot test treats
//! that as a hard failure, so the list is validated against ground truth on
//! lane-vps. Operators may also substitute Firecracker's own published
//! filter JSON for the pinned release via config (`seccomp_filter_override`).

use serde::Serialize;

/// One JSON filter object: default action on miss, action on match, rules.
#[derive(Debug, Clone, Serialize)]
pub struct ThreadFilter {
    pub default_action: &'static str,
    pub filter_action: &'static str,
    pub filter: Vec<SyscallRule>,
}

/// One allowlist rule: a syscall name plus optional argument conditions
/// (AND-bound). Without `args`, any call of that name matches.
#[derive(Debug, Clone, Serialize)]
pub struct SyscallRule {
    pub syscall: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<ArgCond>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArgCond {
    pub index: u32,
    pub r#type: &'static str,
    pub op: &'static str,
    pub val: u64,
}

fn rule(syscall: &'static str, comment: &'static str) -> SyscallRule {
    SyscallRule {
        syscall,
        comment: Some(comment),
        args: None,
    }
}

/// Syscalls the VMM thread needs: KVM ioctls, epoll/eventfd/timerfd based
/// device emulation, vsock + API socket handling, memory management.
fn vmm_allowlist() -> Vec<SyscallRule> {
    let mut v = Vec::new();
    let mut add = |s: &'static str, c: &'static str| v.push(rule(s, c));

    add("accept4", "vsock/API socket accept");
    add("bind", "vsock/API socket bind");
    add("brk", "heap management");
    add("clock_gettime", "timers");
    add("clock_nanosleep", "timers");
    add("clone", "thread spawn");
    add("close", "fd cleanup");
    add("connect", "vsock connect");
    add("dup", "fd duplication");
    add("epoll_create1", "event loop");
    add("epoll_ctl", "event loop");
    add("epoll_pwait", "event loop");
    add("epoll_wait", "event loop");
    add("eventfd2", "event notification");
    add("exit", "thread exit");
    add("exit_group", "process exit");
    add("faccessat2", "path checks during setup");
    add("fallocate", "disk image preallocation");
    add("fcntl", "fd flags (nonblocking, cloexec)");
    add("flock", "image file locking");
    add("fstat", "fd metadata");
    add("fstatfs", "filesystem checks");
    add("fsync", "durable writes");
    add("ftruncate", "disk sizing");
    add("futex", "thread synchronization");
    add("getdents64", "directory iteration");
    add("getrandom", "entropy");
    add("getrlimit", "rlimit queries");
    add("ioctl", "KVM ioctls (KVM_RUN, KVM_SET_REGS, virtio)");
    add("listen", "socket listen");
    add("lseek", "disk image seeks");
    add("madvise", "memory hints");
    add("memfd_create", "sealed memory fds");
    add("mincore", "snapshot page tracking");
    add("mkdirat", "jail dir setup");
    add("mmap", "guest memory mapping");
    add("mprotect", "guest memory protection");
    add("munmap", "memory unmap");
    add("nanosleep", "backoff sleeps");
    add("newfstatat", "path metadata");
    add("openat", "image/config opens (jail-relative)");
    add("openat2", "image/config opens with resolve flags");
    add("pipe2", "internal pipes");
    add("poll", "fd polling");
    add("ppoll", "fd polling");
    add("prctl", "thread naming, no-new-privs checks");
    add("pread64", "disk reads");
    add("preadv", "disk reads");
    add("pwrite64", "disk writes");
    add("pwritev", "disk writes");
    add("read", "socket/disk reads");
    add("readv", "socket/disk reads");
    add("recvfrom", "socket receive");
    add("recvmsg", "socket receive");
    add("restart_syscall", "restarted syscalls");
    add("rt_sigaction", "signal handlers");
    add("rt_sigprocmask", "signal masking");
    add("rt_sigreturn", "signal return");
    add("sched_getaffinity", "vcpu pinning queries");
    add("sched_yield", "cooperative yield");
    add("sendmsg", "socket send");
    add("sendto", "socket send");
    add("set_robust_list", "futex robustness");
    add("set_tid_address", "thread setup");
    add("shutdown", "socket shutdown");
    add("sigaltstack", "signal stacks");
    add("socket", "vsock/unix sockets");
    add("socketpair", "internal channels");
    add("statx", "file metadata");
    add("sysinfo", "host memory queries");
    add("tgkill", "thread signaling");
    add("timerfd_create", "timers");
    add("timerfd_settime", "timers");
    add("uname", "arch queries");
    add("unlinkat", "socket cleanup");
    add("userfaultfd", "snapshot page faults");
    add("write", "socket/disk writes");
    add("writev", "socket/disk writes");
    v
}

/// The API thread serves the local REST socket inside the jail. Tighter
/// than vmm: no disk image ioctls, no userfaultfd.
fn api_allowlist() -> Vec<SyscallRule> {
    let mut v = Vec::new();
    let mut add = |s: &'static str, c: &'static str| v.push(rule(s, c));

    add("accept4", "API socket accept");
    add("bind", "API socket bind");
    add("brk", "heap");
    add("clock_gettime", "timers");
    add("clone", "thread spawn");
    add("close", "fd cleanup");
    add("dup", "fd duplication");
    add("epoll_create1", "event loop");
    add("epoll_ctl", "event loop");
    add("epoll_pwait", "event loop");
    add("epoll_wait", "event loop");
    add("eventfd2", "event notification");
    add("exit", "thread exit");
    add("exit_group", "process exit");
    add("fcntl", "fd flags");
    add("fstat", "fd metadata");
    add("futex", "synchronization");
    add("getrandom", "entropy");
    add("listen", "socket listen");
    add("mmap", "memory mapping");
    add("mprotect", "memory protection");
    add("munmap", "memory unmap");
    add("nanosleep", "sleeps");
    add("openat", "config opens");
    add("poll", "fd polling");
    add("ppoll", "fd polling");
    add("prctl", "thread naming");
    add("read", "socket reads");
    add("readv", "socket reads");
    add("recvfrom", "socket receive");
    add("recvmsg", "socket receive");
    add("restart_syscall", "restarted syscalls");
    add("rt_sigaction", "signal handlers");
    add("rt_sigprocmask", "signal masking");
    add("rt_sigreturn", "signal return");
    add("sched_yield", "yield");
    add("sendmsg", "socket send");
    add("sendto", "socket send");
    add("set_robust_list", "futex robustness");
    add("set_tid_address", "thread setup");
    add("shutdown", "socket shutdown");
    add("sigaltstack", "signal stacks");
    add("socket", "unix sockets");
    add("socketpair", "internal channels");
    add("tgkill", "thread signaling");
    add("write", "socket writes");
    add("writev", "socket writes");
    v
}

/// The vCPU threads run guest code via KVM_RUN. This is the tightest
/// filter and the one that matters most: MMIO exits are serviced inline
/// here, so this is where a guest-escape attempt would first touch the
/// host syscall surface.
fn vcpu_allowlist() -> Vec<SyscallRule> {
    let mut v = Vec::new();
    let mut add = |s: &'static str, c: &'static str| v.push(rule(s, c));

    add("brk", "heap");
    add("clock_gettime", "timers");
    add("exit", "thread exit");
    add("exit_group", "process exit");
    add("futex", "synchronization");
    add("ioctl", "KVM_RUN and KVM MMIO servicing");
    add("madvise", "memory hints");
    add("mmap", "memory mapping");
    add("mprotect", "memory protection");
    add("munmap", "memory unmap");
    add("pread64", "disk reads for MMIO");
    add("pwrite64", "disk writes for MMIO");
    add("read", "eventfd reads");
    add("restart_syscall", "restarted syscalls");
    add("rt_sigreturn", "signal return");
    add("sched_yield", "yield on HLT");
    add("sigaltstack", "signal stacks");
    add("write", "eventfd writes");
    v
}

/// Render the complete seccomp JSON for the pinned Firecracker build.
pub fn render_filter() -> serde_json::Value {
    let mk = |rules: Vec<SyscallRule>| ThreadFilter {
        default_action: "Trap",
        filter_action: "Allow",
        filter: rules,
    };
    serde_json::json!({
        "vmm": mk(vmm_allowlist()),
        "api": mk(api_allowlist()),
        "vcpu": mk(vcpu_allowlist()),
    })
}

/// Pretty-printed filter file content.
pub fn render_filter_pretty() -> Result<String, crate::error::SandboxdError> {
    serde_json::to_string_pretty(&render_filter()).map_err(crate::error::SandboxdError::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn filter_shape_matches_seccompiler_schema() {
        let f = render_filter();
        for thread in ["vmm", "api", "vcpu"] {
            let t = &f[thread];
            assert_eq!(t["default_action"], "Trap", "{thread}");
            assert_eq!(t["filter_action"], "Allow", "{thread}");
            assert!(t["filter"].as_array().unwrap().len() > 10, "{thread}");
            for rule in t["filter"].as_array().unwrap() {
                assert!(
                    rule.get("syscall").and_then(|s| s.as_str()).is_some(),
                    "rule without syscall name in {thread}"
                );
            }
        }
    }

    #[test]
    fn vcpu_filter_is_tightest() {
        let v: HashSet<&str> = vcpu_allowlist().iter().map(|r| r.syscall).collect();
        let vmm: HashSet<&str> = vmm_allowlist().iter().map(|r| r.syscall).collect();
        assert!(v.len() < vmm.len());
        // vCPU threads must not open new files, create sockets, or fork.
        for banned in [
            "openat", "openat2", "socket", "clone", "execve", "mount", "ptrace",
        ] {
            assert!(!v.contains(banned), "vcpu allows {banned}");
        }
    }

    #[test]
    fn dangerous_syscalls_absent_everywhere() {
        for rules in [vmm_allowlist(), api_allowlist(), vcpu_allowlist()] {
            let names: HashSet<&str> = rules.iter().map(|r| r.syscall).collect();
            for banned in [
                "execve",
                "execveat",
                "mount",
                "umount2",
                "ptrace",
                "process_vm_writev",
                "kexec_load",
                "init_module",
                "finit_module",
                "delete_module",
                "reboot",
                "swapon",
                "swapoff",
            ] {
                assert!(!names.contains(banned), "filter allows {banned}");
            }
        }
    }

    #[test]
    fn pretty_renders_valid_json() {
        let s = render_filter_pretty().unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("vmm").is_some());
    }
}
