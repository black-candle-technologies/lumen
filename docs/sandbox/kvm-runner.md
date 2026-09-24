# KVM Runner (lane-vps)

## Why Gated?

KVM tests require `/dev/kvm` and root. The dev machine has neither.
They run on lane-vps (147.135.112.67), which has KVM.

## Running

On lane-vps, as root:

```bash
cd /opt/lumen
sudo ./scripts/sandbox/kvm-runner.sh
```

The script:
1. Verifies `/dev/kvm` and root.
2. Verifies the image signature.
3. Builds with `--features kvm`.
4. Runs `cargo test --features kvm kvm::` (single-threaded).

## What the Tests Cover

- **Boot & handshake**: VM boots, agent connects, Hello/Welcome succeeds.
- **Default-deny**: Guest cannot reach the internet; DNS fails for
  non-allowlisted domains.
- **Proxy**: CONNECT to allowlisted hosts works; others get 403.
- **Metadata**: 169.254.169.254 is unreachable.
- **Rebinding**: DNS TTL is honored; rebinding to private IPs is blocked.
- **Fork bomb**: cgroup pids.max kills the run; host is unaffected.
- **Disk fill**: Workspace quota enforced; host disk not filled.
- **Restart**: Killing sandboxd mid-run; reconciliation reclaims.
- **Orphan cleanup**: Stale netns/TAPs/cgroups are swept.
- **VMM isolation**: Guest cannot access the Firecracker API socket.
- **Export**: Files are staged, hashed, and validated.
- **Cleanup**: After destroy, no artifacts remain.

## CI

The KVM tests run nightly on lane-vps via cron. Results are posted to
the `lumen-sandbox` channel. A failure blocks promotion (see
`promotion.md`).
