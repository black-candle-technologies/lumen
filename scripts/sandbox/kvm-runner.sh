#!/usr/bin/env bash
# KVM runner for lane-vps: executes the KVM-gated test suite.
#
# These tests require /dev/kvm and root. They are NEVER run on the dev
# machine. This script is invoked on lane-vps via SSH.
#
# Usage (on lane-vps, as root):
#   sudo ./scripts/sandbox/kvm-runner.sh [--image DIR] [--dl-dir DIR]
#
# The tests read their inputs from the environment:
#   LUMEN_KVM_GUEST_OUT - directory with manifest.json, vmlinux,
#                         rootfs.ext4, workspace-template.raw
#                         (from scripts/sandbox/build-guest.sh --out DIR)
#   LUMEN_KVM_DL_DIR    - directory with the Firecracker/jailer binaries
#                         (firecracker-v1.10.1-x86_64, jailer-v1.10.1-x86_64)
#
# sudo(8) scrubs the environment by default, so this script re-exports
# both variables explicitly (from --image/--dl-dir or IMAGE_DIR /
# LUMEN_KVM_DL_DIR) before invoking cargo test.
#
# The script:
# 1. Verifies /dev/kvm exists and we are root.
# 2. Verifies the image signature.
# 3. Builds the sandboxd binary and guest agent.
# 4. Runs the KVM-gated tests (cargo test --features kvm).
# 5. Reports results.

set -euo pipefail

# Resolve paths relative to this script, not the caller's CWD:
# sign-image.sh is invoked from the repo root, the script dir, or anywhere.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

IMAGE_DIR="${IMAGE_DIR:-/var/lib/lumen/images/stable}"
DL_DIR="${LUMEN_KVM_DL_DIR:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE_DIR="$2"; shift 2 ;;
        --dl-dir) DL_DIR="$2"; shift 2 ;;
        *) echo "unknown arg: $1 (usage: kvm-runner.sh [--image DIR] [--dl-dir DIR])" >&2; exit 1 ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

if [[ ! -e /dev/kvm ]]; then
    echo "ERROR: /dev/kvm not found. KVM is required." >&2
    exit 1
fi

echo "=== KVM-gated test runner ==="
echo "Image: $IMAGE_DIR"
echo "Firecracker binaries: ${DL_DIR:-<unset>}"

# Verify the image signature before testing.
if [[ -f "$IMAGE_DIR/manifest.json" ]]; then
    echo "--- Verifying image signature ---"
    "$SCRIPT_DIR/sign-image.sh" verify \
        --manifest "$IMAGE_DIR/manifest.json" \
        --key /etc/lumen/image-verify.key
fi

echo "--- Building ---"
cargo build --release -p lumen-sandboxd --features kvm --offline

echo "--- Running KVM-gated tests ---"
# The tests are gated by the `kvm` feature and a runtime check for /dev/kvm.
# They boot real microVMs and verify isolation properties.
# Export the fixture inputs explicitly: sudo scrubs the caller's
# environment, so values set before `sudo` would otherwise be lost.
export LUMEN_KVM_GUEST_OUT="$IMAGE_DIR"
if [[ -n "$DL_DIR" ]]; then
    export LUMEN_KVM_DL_DIR="$DL_DIR"
elif [[ -z "${LUMEN_KVM_DL_DIR:-}" ]]; then
    echo "WARNING: LUMEN_KVM_DL_DIR not set; the fixture will fail with instructions" >&2
fi
cargo test --release -p lumen-sandboxd --features kvm --offline -- \
    --test-threads=1 \
    kvm_

echo "=== All KVM tests passed ==="
