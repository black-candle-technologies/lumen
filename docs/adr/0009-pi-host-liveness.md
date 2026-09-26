# ADR-0009: fail-closed Pi host liveness and preparation recovery

Status: proposed experiment, not production admission. This decision and the
implementation threat review below precede the prototype. Host, sandbox and
kernel owner acceptance and independent review remain pending.

## Decision

Add a small pinned native monitor outside Pi's namespaces. It starts only
`/usr/bin/bwrap` and watches a private FIFO whose sole writer belongs to the host
launcher. The FIFO is outside the guest's read-only root and is never inherited
by Pi. Before forking, the monitor must read the launcher's one-byte startup
marker. EOF, unexpected input or any setup error denies launch. A host dying
before the monitor starts therefore cannot leave a waiting orphan. After startup,
closing the writer kills the child and ends the service; normal child exit is
observed with a pidfd and reaped. No PID read from a file is used to signal a
process. The monitor is the service's main process, and KillMode=control-group
remains mandatory. Bubblewrap's parent-death control and RuntimeMaxSec remain
additional bounds, not substitutes for liveness.

The service owns its private snapshot through systemd RuntimeDirectory (0700,
not preserved after stop). The host prepopulates this directory, and the manager
removes it when the service stops. A private per-runtime flock marks a live host
owner. Creation and recovery use a shared registry lock to cover the crash window
between directory creation and owner-lock acquisition. Recovery, before a new
launch, stops only an unowned, strictly named Lumen unit and verifies it is
inactive before deleting its corresponding directory. Manager unavailability,
unrecognized states, symlinks, unsafe ownership or permissions fail closed.
Never kill a process based on a recycled numeric PID or delete a live owner's
snapshot. Runtime-directory inventory and lock acquisition are bounded.

The candidate runtime manifest becomes **v2** with a fixed liveness profile and
a mandatory monitor binary digest. v1 remains historical evidence and is rejected
by this launcher. This changes no ActionEnvelope, PiBridge or audit payload, and
needs no database migration. Runtime locks track ephemeral cleanup ownership;
session identities, leases and audit remain kernel/SQLite responsibilities.
Drain and stop v1 test units before switching profiles. There is no rolling
compatibility mode or fallback to v1 on monitor failure.

## Threat review before implementation

The native monitor and host-side cleanup code enlarge the proposed trusted base.
They run unprivileged, parse no model/tool data, hold no credentials or lease keys,
and accept only host-constructed paths and argv. Pi, including native extensions,
remains untrusted. The monitor is outside that address space so Pi cannot patch
it or close its liveness descriptor. Its FIFO descriptor is close-on-exec, and
the launcher closes all non-stdio descriptors when starting systemd-run. Pi has
neither a writer nor a path/proc/socket route to obtain one. FIFO ownership/type
checks and a startup marker are required, not an assumption that poll reports an
initial hangup. The parent owns its unreaped child until waitpid; a pidfd observes
exit without PID reuse. Any monitor failure must stop its cgroup.

Cleanup is constrained to a private user runtime directory, exact generated
names and owned regular lock files. Linux fd-based, symlink-resistant rmtree is
required. The registry lock serializes creators against recovery; the per-run
flock protects active and concurrently starting hosts. A missing lock is stale
only while the registry lock is held. A broken service-manager connection must
not be mistaken for an absent unit. An operator/root compromise is outside this
profile; a hostile Pi is inside the threat model.

Required fault evidence: SIGKILL the host before service startup and during an
active non-cooperative guest; kill the monitor; corrupt/remove its pinned binary;
verify no surviving cgroup tasks and no runtime snapshot after teardown/recovery;
repeat startup after each fault; run concurrent hosts while recovering a stale
preparation; reject symlink/foreign cleanup targets. Record measured teardown
latency. Preserve the full native escape suite and real Pi/kernel/audit probe.
This is not Firecracker fault evidence and does not prove kernel session-lease
reconciliation after a host crash; that remains a separate integration gate.

## Prototype observations

The [lane-vps development record](../rebuild/evidence/phase0-liveness.json)
identifies the tested implementation and runtime digests. All 25 tests passed:
13 native confinement tests, ten liveness/recovery tests and two independent
audit-verifier tests. Three actual host SIGKILL trials removed the cgroup and
snapshot within 21–35 ms; monitor SIGKILL cleanup took 42 ms. Measurements begin
before the kill request and end at passive cleanup observation. These are sample
observations, not a production latency guarantee. The test deadline is five
seconds. No prototype units or per-runtime directories remained after the suite.
Real Pi repeated its mediated kernel denial with seven signed audit checkpoints.
This evidence does not change the proposed status or supply owner sign-off.

Mechanism references: [Linux FIFO semantics](https://man7.org/linux/man-pages/man7/fifo.7.html),
[pidfd lifetime guarantees](https://man7.org/linux/man-pages/man2/pidfd_open.2.html),
and [systemd runtime directories](https://github.com/systemd/systemd/blob/v259/man/systemd.exec.xml).
