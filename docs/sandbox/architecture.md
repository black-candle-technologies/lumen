# Strict Sandbox Architecture & Threat Model

## Overview

The strict sandbox runs each untrusted action in a disposable Firecracker
microVM. The host (`sandboxd`) brokers all resources: network, storage,
secrets, and lifecycle. The guest agent is untrusted; the host validates
every message.

## Components

- **sandboxd** (host daemon): Owns the lifecycle. Exposes an authenticated
  Unix-socket API to the kernel. Manages Firecracker via the jailer,
  network namespaces, and cgroups. Firecracker runs with its own default
  seccomp filters; sandboxd does not install custom seccomp filters.
- **lumen-guest-agent** (in-VM): Spawns the workload, relays stdio (redacted),
  streams exports, enforces deadlines. Untrusted.
- **Image store**: Signed guest images (kernel + rootfs + workspace template).
  Only images with a valid signature from a trusted key are booted.

## Trust Boundaries

1. **Host vs. Guest**: The guest is fully untrusted. The host validates:
   - Agent handshake (version, run_id, nonce).
   - All stdio is bounded and redacted (secrets never leak).
   - Export paths are validated (no `..`, no absolute, no symlinks).
   - Export hashes are verified against the manifest.
2. **Kernel vs. sandboxd**: The kernel authenticates via Unix socket with
   SO_PEERCRED (UID allowlist) + bearer token. The socket is 0600.
3. **Image provenance**: The image digest in the run spec must match a
   manifest signed by a trusted key. The rootfs and kernel hashes are
   verified before boot.

## Network Isolation

- Each run gets a dedicated network namespace with a veth pair.
- The guest sees only a TAP device; the host bridges it to the veth.
- nftables default-deny: only DNS (to the host resolver) and the HTTP
  CONNECT proxy (to allowed destinations) are permitted.
- The proxy validates destinations against the allowlist, pins DNS, and
  re-validates literals (defense against DNS rebinding).
- Metadata endpoints (169.254.169.254) and private ranges are always denied.

## Resource Limits

- cgroups v2, applied by the jailer to the host-side VMM process: CPU
  (`cpu.max` hard cap + `cpu.weight` fair share), memory (`memory.max`,
  swap disabled via `memory.swap.max=0`), and host process count
  (`pids.max`). No I/O (`io.max`) limit is set. `pids.max` counts the
  VMM process and its host children; guest processes inside the microVM
  are vCPU threads of the VMM, not host processes, so `pids.max` does
  not count them. Host-side fork-bomb containment is the quota monitor
  (`pids.current >= max_processes` triggers termination via
  `cgroup.kill`, which kills the VMM and any forked children).
- Disk: per-run sparse copy of a raw ext4 workspace template
  (`workspace.raw` in the jail chroot), capped by `max_disk_mib`; the
  quota monitor watches the file's allocated blocks. The template is a
  raw image, not CoW qcow2 — Firecracker's virtio-blk is raw-only, so a
  run can never fill the host disk beyond the template's provisioned
  size.
- Output: stdout/stderr capped at `max_output_bytes`; the agent drops
  excess (the host is notified of truncation).

## Secrets

- Secrets are fetched from a broker at `prepare` time (fail-closed if no
  broker and secrets are requested).
- Values are held in locked memory (mlock) and zeroed on drop.
- The guest agent receives values over vsock and places them in the
  workload environment.
- Every stdio byte is redacted (streaming, handles split boundaries).
- The daemon's logs only name secret handles, never values.

## Crash Safety

- All state transitions are journaled before effects.
- On startup, `reconcile` reclaims orphans (runs, netns, TAPs, cgroups,
  jail dirs) before listening.
- `destroy` is idempotent; a missing run is a no-op.
