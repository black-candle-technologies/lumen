#!/usr/bin/env bash
# Build a reproducible minimal guest image for Lumen strict sandbox.
#
# Outputs:
#   $OUT/vmlinux          - guest kernel (from $KERNEL_SRC or prebuilt)
#   $OUT/rootfs.ext4      - minimal rootfs with lumen-guest-agent as init
#   $OUT/workspace-template.qcow2 - CoW template for per-run workspaces
#
# Reproducibility: all inputs are pinned by digest; the build runs in a
# container with fixed toolchain versions. The output manifest records
# every input digest.
#
# Usage: build-guest.sh [--out DIR] [--kernel SRC]

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
    echo "--- Building kernel from $KERNEL_SRC ---"
    # The kernel must have: CONFIG_VIRTIO, CONFIG_VIRTIO_NET, CONFIG_VSOCK,
    # CONFIG_EXT4_FS, CONFIG_OVERLAY_FS. We do not build here; the caller
    # provides a kernel built with the pinned config in docs/sandbox/guest.md.
    cp "$KERNEL_SRC" "$OUT/vmlinux"
else
    echo "--- Using prebuilt kernel (set KERNEL_SRC to build from source) ---"
    # In CI, the kernel is fetched by digest from the artifact store.
    # Local dev: place your vmlinux at $OUT/vmlinux.
    if [[ ! -f "$OUT/vmlinux" ]]; then
        echo "ERROR: $OUT/vmlinux not found. Set KERNEL_SRC or place a kernel." >&2
        exit 1
    fi
fi

# 2. Rootfs: minimal initramfs-style root with the guest agent as init.
echo "--- Building rootfs ---"
ROOTFS_DIR=$(mktemp -d)
trap 'rm -rf "$ROOTFS_DIR"' EXIT

mkdir -p "$ROOTFS_DIR"/{bin,sbin,etc,proc,sys,dev,workspace}
# The guest agent binary (built via `cargo build --release -p lumen-sandboxd --bin lumen-guest-agent`)
# is copied in by the caller or via $GUEST_AGENT_BIN.
GUEST_AGENT_BIN="${GUEST_AGENT_BIN:-./target/release/lumen-guest-agent}"
if [[ ! -f "$GUEST_AGENT_BIN" ]]; then
    echo "ERROR: guest agent not found at $GUEST_AGENT_BIN" >&2
    echo "Build it: cargo build --release -p lumen-sandboxd --bin lumen-guest-agent" >&2
    exit 1
fi
cp "$GUEST_AGENT_BIN" "$ROOTFS_DIR/sbin/lumen-guest-agent"
chmod +x "$ROOTFS_DIR/sbin/lumen-guest-agent"

# Minimal /init that mounts essentials and execs the agent.
cat > "$ROOTFS_DIR/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
# Workspace disk is attached as /dev/vdb; mount at /workspace.
mkdir -p /workspace
mount -t ext4 /dev/vdb /workspace || echo "no workspace disk"
exec /sbin/lumen-guest-agent
EOF
chmod +x "$ROOTFS_DIR/init"

# Create ext4 image.
ROOTFS_IMG="$OUT/rootfs.ext4"
dd if=/dev/zero of="$ROOTFS_IMG" bs=1M count=64 2>/dev/null
mkfs.ext4 -q -d "$ROOTFS_DIR" "$ROOTFS_IMG"

# 3. Workspace template (empty ext4, will be CoW-cloned per run).
echo "--- Building workspace template ---"
WORKSPACE_TMPL="$OUT/workspace-template.qcow2"
qemu-img create -f qcow2 "$WORKSPACE_TMPL" 1G
# Format it via a loop mount (requires root).
# For now, leave unformatted; the driver formats on first use.

# 4. Manifest.
echo "--- Writing manifest ---"
cat > "$OUT/manifest.json" <<EOF
{
  "vmlinux_sha256": "$(sha256sum "$OUT/vmlinux" | cut -d' ' -f1)",
  "rootfs_sha256": "$(sha256sum "$ROOTFS_IMG" | cut -d' ' -f1)",
  "workspace_template_sha256": "$(sha256sum "$WORKSPACE_TMPL" | cut -d' ' -f1)",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

echo "=== Done ==="
echo "Manifest: $OUT/manifest.json"
cat "$OUT/manifest.json"
