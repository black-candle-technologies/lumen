# Strict Sandbox Architecture & Threat Model

## Overview

The strict sandbox runs each untrusted action in a disposable Firecracker
microVM. The host (`sandboxd`) brokers all resources: network, storage,
secrets, and lifecycle. The guest agent is untrusted; the host validates
every message.

## Components

- **sandboxd** (host daemon): Owns the lifecycle. Exposes an authenticated
  Unix-socket API to the kernel. Manages Firecracker via the jailer,
  network namespaces, cgroups, and seccomp.
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

- cgroups v2: CPU, memory, pids, I/O.
- Disk: CoW qcow2 with a size cap; the guest cannot fill the host disk.
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
