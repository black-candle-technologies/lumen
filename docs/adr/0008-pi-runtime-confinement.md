# ADR-0008: Pi runtime confinement prototype

Status: proposed; experimental tests only. Production admission remains disabled.
Owner reviews pending: host, sandbox, kernel, Pi integration. This is not an
independent security review or approval to enlarge the production trusted base.

## Decision being tested

Run the unmodified pinned Pi CLI in Linux namespaces created by a fixed
bubblewrap invocation. Its root is a verified read-only runtime snapshot. The
snapshot contains Node and its dynamic-loader dependencies, the pinned Pi build,
explicitly admitted extensions, and a small native syscall filter. The only
writable mount is disposable private state. No repository, host home, host /proc,
credential file, network namespace, or host Unix socket is exposed. Only stdin,
stdout, and stderr cross the runtime boundary.

Before the Pi entrypoint runs, Node loads an immutable `--require` bootstrap.
That bootstrap requires a pinned native addon, which installs an architecture-
checked seccomp allowlist with TSYNC across all existing Node threads. Loading or
installation failure terminates before Pi code is imported. There is no soft
preload failure: a dynamic loader ignoring an unavailable LD_PRELOAD library
would be insufficient. The addon denies exec, fork/vfork, sockets, namespace
changes, ptrace, process memory access, BPF, keyrings, mount, and io_uring. The
only clone permitted creates threads in the existing address space; clone3
returns ENOSYS so libc can use the inspectable clone flags. Unknown syscalls are
denied, and other syscall architectures are fatal.

A transient systemd user service denies `io_uring_setup`, `io_uring_enter`, and
`io_uring_register` before Node starts (ENOSYS). This is necessary because the
lane-vps libuv initializes an io_uring path before the Node bootstrap; an
environment variable alone did not disable that path. The later TSYNC filter
also denies these calls. No ring created before sealing is inherited by Pi.

The service sets MemoryMax=768M, MemorySwapMax=0, TasksMax=64, CPUQuota=100%,
RuntimeMaxSec=90, KillMode=control-group, and disables core dumps. The launcher
checks effective cgroup files in tests, bounds both output streams and elapsed
time, and stops the complete unit on normal cancellation/timeout. The original
root-owned `/usr/bin/bwrap` path is retained for its distro AppArmor profile;
copying that executable to a private path lost the required namespace permission
on lane-vps. Its digest and immutable root-owned path are checked before launch.

Runtime reads needed to load Pi are limited to that snapshot; private temporary
state is discarded. These are not authority to inspect or mutate a repository.
Pi tool filesystem reads must still use the host/kernel path. Per-action
Firecracker remains mandatory for external effects; this process confinement is
for the long-lived untrusted agent loop and does not replace effect isolation.

The experimental launcher checks every regular file against an exact manifest,
rejects symlinks/special files/unknown fields, snapshots verified bytes again into
a private launch directory, clears the environment, closes inherited descriptors,
and uses a fixed Node command. It does not accept arbitrary launcher flags or
environment assignments. Production signature/admission verification and host
supervisor integration remain separate acceptance work.

## Threat-model review before prototype implementation

This is an implementation review of the proposed mechanism, not independent
acceptance. The attacker controls all Pi code, extensions, model text, and tool
arguments after the bootstrap. Linux, bubblewrap, the dynamic loader, Node's
pre-bootstrap initialization, the native addon, systemd, and the host launcher are in the
prototype's trusted base. A new runtime manifest requires review; hashes alone
do not prove benign behavior. An operator/root compromise is outside this test.

| Threat | Required mechanism and negative evidence |
|---|---|
| Skip/break native preload | Mandatory trusted require before Pi; deliberately invalid addon must prevent the entrypoint marker |
| Replace a runtime file or inject an extra file | Exact manifest including native addon/bootstrap; corruption, extra path, symlink and unknown-field tests |
| Race verification against execution | Read bytes into a new private snapshot; recheck digest of copied bytes; original paths are never mounted |
| Read/write host files or traverse links | No host mounts, no host /proc; hostile fs/readlink/traversal tests and host sentinel unchanged |
| Spawn a shell or another Node | Exec and process clone denied, including native syscall probes; thread creation remains functional |
| Open internet, metadata, loopback or Unix sockets | Separate network namespace plus socket/connect denial; test each address family and native path |
| Steal credentials or inherited descriptors | Clean environment, only three inherited pipes, no host home/proc/socket mounts; canary tests |
| Bypass via worker threads | TSYNC at installation and inherited filters for CLONE_THREAD; worker repeats malicious operations |
| Change namespaces, mount, ptrace, ioctl, io_uring | Default-deny syscall filter; explicit architecture guard and narrow ioctl allowance |
| Resource exhaustion / orphaned child | Effective transient cgroup quotas plus managed timeout teardown; abrupt supervisor death and restart remain unaccepted |

Residual risks to resolve before admission: independent review of the native
filter and snapshot builder; signed runtime provenance; production cgroups and
crash recovery; host/Pi generation binding and cancellation; a repeatable real Pi
request that receives a real kernel verdict and audit. Node runtime initialization
before the filter is trusted and therefore must be pinned as part of the runtime.
systemd's user manager, its transient-unit API, and the bootstrap io_uring filter
are also part of this proposed trusted mechanism. **Abrupt host-supervisor death
is not yet a zero-orphan guarantee:** systemd parents the service, so bubblewrap's
parent-death behavior does not follow the Python process. RuntimeMaxSec bounds
that case; a parent-liveness/crash-recovery protocol and fault injection are still
required before production admission. Do not interpret the successful managed
timeout cleanup test as host-restart evidence.

References: [Linux seccomp documentation](https://docs.kernel.org/userspace-api/seccomp_filter.html)
and [bubblewrap design](https://github.com/containers/bubblewrap/blob/main/README.md).
Seccomp constrains syscalls; mount and network namespaces separately constrain
what the remaining calls can access. Neither mechanism alone proves this boundary.
