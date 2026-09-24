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
- Runs stuck in `TeardownFailed` (retried with bounded backoff; see
  below).
- Network namespaces (`ip netns list | grep lmn-`).
- TAP devices (`ip link show | grep lmnt-`).
- Cgroups (`/sys/fs/cgroup/lumen/<run_id>`).
- Jailer chroots (`<chroot_base>/<exec_file_name>/*`, e.g.
  `/srv/jailer/firecracker/*`).

Manual sweep (if reconciliation missed something). Scope the kill to
sandboxd's own Firecracker processes: a process is ours only if its
`/proc/<pid>/root` is under the jailer chroot base. Never
`pgrep -f firecracker | xargs kill -9` — that also kills unrelated VMMs
on a shared host.

```bash
CHROOT_BASE=/srv/jailer  # the daemon's firecracker.chroot_base
for pid in $(pgrep -f firecracker); do
  root=$(readlink "/proc/$pid/root" 2>/dev/null) || continue
  case "$root" in "$CHROOT_BASE"*)
    echo "killing $pid (root=$root)"
    sudo kill -9 "$pid" ;;
  esac
done
# Delete netns (prefix is lmn-)
sudo ip netns list | grep lmn- | cut -d' ' -f1 | xargs -r -n1 sudo ip netns delete
# Delete TAPs (prefix is lmnt-, not lmn-)
ip -o link show | grep -oE 'lmnt-[^:@ ]*' | sort -u | xargs -r -n1 sudo ip link delete
```

## TeardownFailed Runs

Reconcile can leave a run in the non-terminal `TeardownFailed` state when
a teardown artifact could not be confirmed removed. The run's UID stays
allocated and an alert is journaled.

Find them:

```bash
# Per-run journals record every state transition.
grep -l 'TeardownFailed' <state_dir>/runs/*/journal.jsonl
# The daemon also logs: "sandboxd: ERROR teardown of run <id> unconfirmed (attempt N): ..."
```

Retry: restart sandboxd (or otherwise trigger another reconcile). Runs
in `TeardownFailed` are retried with bounded backoff — 5s, 10s, 20s, …
capped at 5 minutes. A run whose backoff has not elapsed is kept for a
later reconcile, so a restart may need to be followed by another one.

## Disk Full

Workspace disks are raw ext4 copies, quota-enforced by the daemon
(`max_disk_mib`). If the host disk fills:

1. Check for leaked disks:
   `ls -lsh <chroot_base>/<exec_file_name>/*/root/workspace.raw`
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
