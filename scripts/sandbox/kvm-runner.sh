#!/usr/bin/env bash
# KVM runner for lane-vps: executes the KVM-gated test suite.
#
# These tests require /dev/kvm and root. They are NEVER run on the dev
# machine. This script is invoked on lane-vps via SSH.
#
# Usage (on lane-vps):
#   sudo ./kvm-runner.sh [--image DIR]
#
# The script:
# 1. Verifies /dev/kvm exists and we are root.
# 2. Builds the sandboxd binary and guest agent.
# 3. Runs the KVM-gated tests (cargo test --features kvm).
# 4. Reports results.

set -euo pipefail

IMAGE_DIR="${IMAGE_DIR:-/var/lib/lumen/images/stable}"

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

# Verify the image signature before testing.
if [[ -f "$IMAGE_DIR/manifest.json" ]]; then
    echo "--- Verifying image signature ---"
    ./scripts/sandbox/sign-image.sh verify \
        --manifest "$IMAGE_DIR/manifest.json" \
        --sig "$IMAGE_DIR/manifest.sig" \
        --key /etc/lumen/image-verify.key
fi

echo "--- Building ---"
cargo build --release -p lumen-sandboxd --features kvm --offline

echo "--- Running KVM-gated tests ---"
# The tests are gated by the `kvm` feature and a runtime check for /dev/kvm.
# They boot real microVMs and verify isolation properties.
cargo test --release -p lumen-sandboxd --features kvm --offline -- \
    --test-threads=1 \
    kvm_

echo "=== All KVM tests passed ==="
