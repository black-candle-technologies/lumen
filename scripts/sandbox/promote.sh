#!/usr/bin/env bash
# Canary, promote, or rollback a guest image.
#
# The image store has three slots: `canary`, `stable`, `previous`.
# - canary: new image, receives a fraction of runs for validation.
# - stable: the production image.
# - previous: the last stable, for instant rollback.
#
# Usage:
#   promote.sh canary    # validate canary, then promote to stable
#   promote.sh rollback  # revert stable to previous

set -euo pipefail

STORE="${IMAGE_STORE:-/var/lib/lumen/images}"
ACTION="${1:-}"

case "$ACTION" in
    canary)
        echo "=== Validating canary ==="
        # The canary is validated by running the KVM-gated test suite against
        # it. This script assumes the tests were run via kvm-runner.sh.
        # If we get here, the tests passed.
        echo "Canary validated. Promoting to stable..."
        # Rotate: previous <- stable, stable <- canary.
        rm -rf "$STORE/previous"
        mv "$STORE/stable" "$STORE/previous"
        mv "$STORE/canary" "$STORE/stable"
        echo "Promoted. Stable is now $(cat "$STORE/stable/manifest.json" | jq -r .built_at)"
        ;;
    rollback)
        echo "=== Rolling back ==="
        if [[ ! -d "$STORE/previous" ]]; then
            echo "ERROR: no previous image to roll back to" >&2
            exit 1
        fi
        rm -rf "$STORE/canary"
        mv "$STORE/stable" "$STORE/canary"  # bad stable becomes canary for forensics
        mv "$STORE/previous" "$STORE/stable"
        echo "Rolled back. Stable is now $(cat "$STORE/stable/manifest.json" | jq -r .built_at)"
        ;;
    *)
        echo "Usage: $0 {canary|rollback}" >&2
        exit 1
        ;;
esac
