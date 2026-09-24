# Recovery Runbook

## sandboxd Won't Start

1. Check config: `sandboxd /etc/lumen/sandboxd.toml` (it validates on startup).
2. Check permissions: the socket dir, state dir, and token file must be
   owned by the sandboxd user.
3. Check `/dev/kvm`: `ls -l /dev/kvm` (should be `kvm` group, sandboxd user
   in the group).

## Orphaned Runs

If `sandboxd` died, restart it. Reconciliation runs automatically before
listening and reclaims:

- Runs in non-terminal states (marked Orphaned, then Destroyed).
- Network namespaces (`ip netns list | grep lmn-`).
- TAP devices (`ip link show | grep lmn-`).
- Cgroups (`/sys/fs/cgroup/lumen/lmn-*`).
- Jailer chroots (`/var/lib/lumen/jails/*`).

Manual sweep (if reconciliation missed something):

```bash
# Kill Firecracker pids
pgrep -f firecracker | xargs -r sudo kill -9
# Delete netns
sudo ip netns list | grep lmn- | cut -d' ' -f1 | xargs -r -n1 sudo ip netns delete
# Delete TAPs
ip -o link show | grep -o 'lmn-[^:]*' | xargs -r -n1 sudo ip link delete
```

## Disk Full

The workspace disks are qcow2 with quotas. If the host disk fills:

1. Check for leaked images: `ls -lh /var/lib/lumen/runs/*/workspace.qcow2`
2. Run reconciliation: `sudo systemctl restart lumen-sandboxd`
3. If a run is stuck, `sandboxd` API `destroy` is idempotent.

## Network Issues

- Guest has no network: check the TAP is up (`ip link show <tap>`),
  the veth pair exists, and nftables allows the DNS/proxy.
- DNS fails: check the host resolver is running on the veth host IP.
- Proxy 403s: check the allowlist in the run spec.

## Key Rotation

- **API token**: generate a new token, write to the token file (0600),
  restart sandboxd. The kernel must be updated with the new token.
- **Image signing key**: see `promotion.md` (emergency revoke).
