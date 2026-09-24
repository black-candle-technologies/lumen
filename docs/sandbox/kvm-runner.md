# KVM Runner (lane-vps)

## Why Gated?

KVM tests require `/dev/kvm` and root. The dev machine has neither.
They run on lane-vps (147.135.112.67), which has KVM.

## Running

On lane-vps, as root:

```bash
cd /opt/lumen
sudo ./scripts/sandbox/kvm-runner.sh [--image DIR] [--dl-dir DIR]
```

`--image DIR` (or `IMAGE_DIR`, default `/var/lib/lumen/images/stable`)
points at the guest build output directory (`manifest.json`, `vmlinux`,
`rootfs.ext4`, `workspace-template.raw`); it is passed to the tests as
`LUMEN_KVM_GUEST_OUT`. `--dl-dir DIR` (or `LUMEN_KVM_DL_DIR`) points at
the Firecracker/jailer binaries (`firecracker-v1.10.1-x86_64`,
`jailer-v1.10.1-x86_64`). The script sets both explicitly for the test
run, so `sudo`'s environment scrubbing does not matter.

The script:
1. Verifies `/dev/kvm` and root.
2. Verifies the image signature.
3. Builds with `--features kvm`.
4. Runs `cargo test --features kvm -- --test-threads=1 kvm_`
   (single-threaded).

## What the Tests Cover

- **Boot & handshake**: VM boots, agent connects, Hello/Welcome succeeds.
- **Default-deny**: Guest cannot reach the internet; DNS fails for
  non-allowlisted domains.
- **Metadata**: 169.254.169.254 is unreachable.
- **Fork bomb**: a guest fork bomb does not take down the run or spike
  host load. (Host cgroup `pids.max` applies to the VMM process, not to
  guest processes; the VM boundary is what contains the bomb.)
- **Disk fill**: Workspace quota enforced; host disk not filled.
- **VMM isolation**: Guest cannot access the Firecracker API socket
  (`fc-api.sock`) or the vsock socket (`v.sock`).
- **Export**: Files are staged, hashed, and validated.
- **Cleanup**: After destroy, no artifacts remain (no leaked netns, TAPs,
  or jail dirs).

Not covered — `#[ignore]` stubs that verify nothing (the promotion gate
must not rely on them):

- **Proxy allowlist** (`kvm_proxy_allowlist`): host egress proxy is not
  functional; allowlist enforcement cannot be verified.
- **DNS rebinding** (`kvm_dns_rebinding_blocked`): host DNS
  forwarder/proxy is not functional; rebinding protection cannot be
  verified.
- **Restart** (`kvm_restart_reclaims`): daemon reconciliation path is
  not exercised (the suite drives `Driver`, not the daemon).
- **Orphan sweep** (`kvm_orphan_sweep`): daemon startup sweep is not
  exercised (the suite drives `Driver`, not the daemon).

## CI

The KVM tests run nightly on lane-vps via cron. Results are posted to
the `lumen-sandbox` channel. A failure blocks promotion (see
`promotion.md`).
