#!/usr/bin/env bash
# Promote a guest image through slots: canary -> stable -> previous.
#
# The image store is digest-keyed: <store>/<image_digest>/manifest.json
# plus the artifacts. sandboxd resolves ONLY full digests from run specs
# (see provenance::resolve_image); the slots below do not change which
# image a given run boots. Slots are atomic pointer files that the
# operator/kernel reads to choose the digest for NEW runs:
#   <store>/slots/canary, <store>/slots/stable, <store>/slots/previous
#
# Flow:
#   1. Build + sign the image (see docs/sandbox/build.md), install the
#      artifacts under <store>/<digest>/.
#   2. promote.sh canary <digest>     # verify signature, point canary at it
#   3. Run the KVM suite against canary (kvm-runner.sh --image <store>/<digest>)
#   4. promote.sh promote --kvm-ok    # canary -> stable, stable -> previous
#   5. promote.sh rollback           # previous -> stable (bad stable -> canary)
#
# Every pointer update is atomic (write temp + rename). stable is never
# removed or moved until the canary pointer is confirmed to exist.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

STORE="${IMAGE_STORE:-/var/lib/lumen/images}"
SLOT_DIR="$STORE/slots"
VERIFY_KEY="${IMAGE_VERIFY_KEY:-/etc/lumen/image-verify.key}"

ACTION="${1:-}"
shift || true

usage() {
    echo "Usage: $0 canary <digest> | promote --kvm-ok | rollback" >&2
    exit 1
}

# point <slot> at <digest> atomically.
point_slot() {
    local slot="$1" digest="$2"
    mkdir -p "$SLOT_DIR"
    local tmp
    tmp="$(mktemp "$SLOT_DIR/.tmp.XXXXXX")"
    printf '%s\n' "$digest" > "$tmp"
    mv -f "$tmp" "$SLOT_DIR/$slot"
}

read_slot() {
    local slot="$1"
    if [[ -f "$SLOT_DIR/$slot" ]]; then
        cat "$SLOT_DIR/$slot"
    fi
}

is_digest() {
    [[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

case "$ACTION" in
    canary)
        DIGEST="${1:-}"
        [[ -n "$DIGEST" ]] || { echo "ERROR: canary requires a digest" >&2; usage; }
        is_digest "$DIGEST" || { echo "ERROR: malformed digest: $DIGEST" >&2; exit 1; }
        MANIFEST="$STORE/$DIGEST/manifest.json"
        [[ -f "$MANIFEST" ]] || { echo "ERROR: no manifest at $MANIFEST" >&2; exit 1; }
        # Verify the embedded signature before the slot points anywhere.
        echo "--- Verifying image signature ---"
        "$SCRIPT_DIR/sign-image.sh" verify --manifest "$MANIFEST" --key "$VERIFY_KEY"
        point_slot canary "$DIGEST"
        CREATED="$(jq -r .created_unix "$MANIFEST")"
        echo "Canary now $DIGEST (manifest created_unix=$CREATED)"
        echo "Next: run the KVM suite: sudo ./scripts/sandbox/kvm-runner.sh --image $STORE/$DIGEST"
        echo "Then: $0 promote --kvm-ok"
        ;;
    promote)
        KVM_OK=0
        for arg in "$@"; do
            [[ "$arg" == "--kvm-ok" ]] && KVM_OK=1
        done
        [[ $KVM_OK -eq 1 ]] || {
            echo "ERROR: refusing to promote without KVM evidence." >&2
            echo "Run the KVM suite against the canary image, then pass --kvm-ok." >&2
            exit 1
        }
        CANARY="$(read_slot canary)"
        [[ -n "$CANARY" ]] || { echo "ERROR: no canary slot set; stage one with: $0 canary <digest>" >&2; exit 1; }
        [[ -d "$STORE/$CANARY" ]] || { echo "ERROR: canary digest $CANARY has no store directory" >&2; exit 1; }
        # Confirm the signature again at promotion time (key may have rotated).
        "$SCRIPT_DIR/sign-image.sh" verify --manifest "$STORE/$CANARY/manifest.json" --key "$VERIFY_KEY"
        STABLE="$(read_slot stable)"
        if [[ -n "$STABLE" ]]; then
            point_slot previous "$STABLE"
            echo "previous <- $STABLE"
        else
            echo "note: no stable slot set yet; previous left unset"
        fi
        point_slot stable "$CANARY"
        echo "stable <- $CANARY"
        ;;
    rollback)
        PREVIOUS="$(read_slot previous)"
        [[ -n "$PREVIOUS" ]] || { echo "ERROR: no previous slot set; nothing to roll back to" >&2; exit 1; }
        [[ -d "$STORE/$PREVIOUS" ]] || { echo "ERROR: previous digest $PREVIOUS has no store directory" >&2; exit 1; }
        STABLE="$(read_slot stable)"
        if [[ -n "$STABLE" ]]; then
            # Bad stable is preserved as canary for forensics.
            point_slot canary "$STABLE"
            echo "canary <- $STABLE (bad stable, for forensics)"
        fi
        point_slot stable "$PREVIOUS"
        echo "stable <- $PREVIOUS"
        ;;
    *) usage ;;
esac
