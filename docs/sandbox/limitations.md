# Known Limitations

## Phase 2 Scope

- **Strict profile only**: The `Stateful` profile is not implemented.
  Each run is a disposable microVM; no state persists across runs.
- **No GPU**: Guests have no GPU access. GPU workloads are out of scope.
- **x86_64 only**: The guest kernel and Firecracker are x86_64. ARM hosts
  are not supported.

## Security

- **Side channels**: Firecracker provides process isolation, not
  side-channel resistance. Do not run mutually untrusted workloads on
  the same host if side channels are in your threat model.
- **CPU template**: We use `cpu_template: "None"` (host CPU passthrough
  with Firecracker's default feature hiding). For stronger determinism,
  use a static template (C3, T2, etc.) — see `docs/sandbox/build.md`.
- **Secrets in env**: Secret values are passed to the workload via
  environment variables. A workload that dumps its environment will
  expose them (but the agent redacts them from relayed stdio).

## Operational

- **Single host**: sandboxd is not clustered. For HA, run multiple hosts
  behind the kernel's scheduler.
- **No live migration**: Runs cannot migrate between hosts.
- **Image size**: The rootfs is 64 MiB; larger workloads need a bigger
  image (rebuild via `build-guest.sh`).

## Protocol

- **Agent protocol v1**: The Hello/Welcome handshake is versioned. v1
  does not support resumption; a dropped vsock connection kills the run.
- **Export**: The guest streams all files under `/workspace`. There is
  no selective export yet (the host validates, but the guest decides
  what to send).
