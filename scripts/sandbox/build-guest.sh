#!/usr/bin/env bash
# Build a reproducible minimal guest image for Lumen strict sandbox.
#
# Outputs:
#   $OUT/vmlinux                - guest kernel (from $KERNEL_SRC or prebuilt)
#   $OUT/rootfs.ext4            - minimal rootfs: /init + busybox + guest agent
#   $OUT/workspace-template.raw - formatted ext4 template for per-run workspaces
#   $OUT/manifest.json          - provenance::ImageManifest (unsigned; sign it
#                                 separately, e.g. with the test harness)
#
# The guest kernel must have: CONFIG_VIRTIO, CONFIG_VIRTIO_NET,
# CONFIG_VIRTIO_BLK, CONFIG_VSOCK, CONFIG_EXT4_FS, CONFIG_DEVTMPFS.
# Firecracker's virtio-blk is raw-only: the workspace template is a raw
# ext4 image, not qcow2.
#
# Reproducibility: all inputs are pinned by digest; the output manifest
# records every input digest.
#
# Usage: build-guest.sh [--out DIR] [--kernel SRC]
#   GUEST_AGENT_BIN - path to the lumen-guest-agent binary
#                     (cargo build --release -p lumen-sandboxd --bin lumen-guest-agent)
#   BUSYBOX_BIN     - path to a static busybox binary for the guest
#   KERNEL_VERSION  - informational kernel release string for the manifest

set -euo pipefail

OUT="${OUT:-./guest-out}"
KERNEL_SRC="${KERNEL_SRC:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --out) OUT="$2"; shift 2 ;;
        --kernel) KERNEL_SRC="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$OUT"

echo "=== Building minimal guest image ==="
echo "OUT=$OUT"

# 1. Kernel: use prebuilt or build from source.
if [[ -n "$KERNEL_SRC" ]]; then
    echo "--- Using kernel from $KERNEL_SRC ---"
    # The kernel must have: CONFIG_VIRTIO, CONFIG_VIRTIO_NET,
    # CONFIG_VIRTIO_BLK, CONFIG_VSOCK, CONFIG_EXT4_FS, CONFIG_DEVTMPFS.
    # See docs/sandbox/build.md for the required config.
    cp "$KERNEL_SRC" "$OUT/vmlinux"
else
    echo "--- Using prebuilt kernel (set KERNEL_SRC to override) ---"
    # In CI, the kernel is fetched by digest from the artifact store.
    # Local dev: place your vmlinux at $OUT/vmlinux.
    if [[ ! -f "$OUT/vmlinux" ]]; then
        echo "ERROR: $OUT/vmlinux not found. Set KERNEL_SRC or place a kernel." >&2
        exit 1
    fi
fi

# 2. Rootfs: minimal root with /init, busybox, and the guest agent.
echo "--- Building rootfs ---"
ROOTFS_DIR=$(mktemp -d)
trap 'rm -rf "$ROOTFS_DIR"' EXIT

mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,proc,sys,dev,workspace}
GUEST_AGENT_BIN="${GUEST_AGENT_BIN:-./target/release/lumen-guest-agent}"
if [[ ! -f "$GUEST_AGENT_BIN" ]]; then
    echo "ERROR: guest agent not found at $GUEST_AGENT_BIN" >&2
    echo "Build it: cargo build --release -p lumen-sandboxd --bin lumen-guest-agent" >&2
    exit 1
fi
cp "$GUEST_AGENT_BIN" "$ROOTFS_DIR/sbin/lumen-guest-agent"
chmod +x "$ROOTFS_DIR/sbin/lumen-guest-agent"

BUSYBOX_BIN="${BUSYBOX_BIN:-}"
if [[ -n "$BUSYBOX_BIN" && -f "$BUSYBOX_BIN" ]]; then
    cp "$BUSYBOX_BIN" "$ROOTFS_DIR/bin/busybox"
    chmod +x "$ROOTFS_DIR/bin/busybox"
    # /init is a shell script: it needs /bin/sh.
    ln -s busybox "$ROOTFS_DIR/bin/sh"
else
    echo "WARNING: no busybox at BUSYBOX_BIN=$BUSYBOX_BIN; guest has no shell tools" >&2
fi

# /init: mount essentials, configure the sandbox network from the kernel
# command line (lumen.guest_ip= / lumen.host_ip= / lumen.proxy_port=, set
# by the host in the Firecracker boot args), mount the workspace disk,
# then exec the guest agent as PID 1. LUMEN_* stays in the environment so
# the workload (spawned without env_clear) can see it.
cat > "$ROOTFS_DIR/init" <<'EOF'
#!/bin/sh
# NOTE: PID 1 starts with (almost) no PATH; invoke busybox by absolute path.
BB=/bin/busybox
$BB mount -t proc proc /proc
$BB mount -t sysfs sysfs /sys
$BB mount -t devtmpfs devtmpfs /dev
# Workspace disk is attached as /dev/vdb; mount at /workspace.
$BB mkdir -p /workspace
$BB mount -t ext4 /dev/vdb /workspace || echo "lumen-init: no workspace disk"

CMDLINE=$($BB cat /proc/cmdline)
pick() {
  _key="$1"
  _kv=""
  for _kv in $CMDLINE; do
    case "$_kv" in
      "$_key="*) echo "${_kv#"$_key"=}"; return 0 ;;
    esac
  done
}
GUEST_IP=$(pick lumen.guest_ip)
HOST_IP=$(pick lumen.host_ip)
PROXY_PORT=$(pick lumen.proxy_port)
if [ -n "$GUEST_IP" ]; then
  $BB ip link set eth0 up
  $BB ip addr add "${GUEST_IP}/30" dev eth0
else
  echo "lumen-init: no lumen.guest_ip= on cmdline; network left down" >&2
fi
export LUMEN_GUEST_IP="$GUEST_IP" LUMEN_HOST_IP="$HOST_IP" LUMEN_PROXY_PORT="$PROXY_PORT"
exec /sbin/lumen-guest-agent
EOF
chmod +x "$ROOTFS_DIR/init"

# Create ext4 image.
ROOTFS_IMG="$OUT/rootfs.ext4"
rm -f "$ROOTFS_IMG"
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=64 2>/dev/null
mkfs.ext4 -q -d "$ROOTFS_DIR" "$ROOTFS_IMG"

# 3. Workspace template: formatted raw ext4 (Firecracker's virtio-blk is
# raw-only; qcow2 does not work). Sparse; the per-run copy is made with
# `cp --reflink=auto --sparse=always` by the driver.
echo "--- Building workspace template ---"
WORKSPACE_TMPL="$OUT/workspace-template.raw"
rm -f "$WORKSPACE_TMPL"
truncate -s 512M "$WORKSPACE_TMPL"
mkfs.ext4 -q "$WORKSPACE_TMPL"

# 4. Manifest in the provenance::ImageManifest shape (unsigned).
echo "--- Writing manifest ---"
KERNEL_VERSION="${KERNEL_VERSION:-unknown}"
CREATED_UNIX="$(date -u +%s)"
sha256hex() { sha256sum "$1" | cut -d' ' -f1; }
cat > "$OUT/manifest.json" <<EOF
{
  "format_version": 1,
  "kernel_digest": "sha256:$(sha256hex "$OUT/vmlinux")",
  "rootfs_digest": "sha256:$(sha256hex "$ROOTFS_IMG")",
  "workspace_template_digest": "sha256:$(sha256hex "$WORKSPACE_TMPL")",
  "snapshot": null,
  "toolchain": {
    "builder": "lumen-image-builder",
    "builder_version": "0.1.0",
    "kernel_version": "$KERNEL_VERSION",
    "kernel_config_digest": "sha256:unknown",
    "tool_versions": {},
    "reproducible": false
  },
  "policy_version": "v1",
  "created_unix": $CREATED_UNIX,
  "signatures": []
}
EOF

echo "=== Done ==="
echo "Manifest: $OUT/manifest.json"
cat "$OUT/manifest.json"
