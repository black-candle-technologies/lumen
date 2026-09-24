#!/usr/bin/env bash
# Sign a guest image manifest and verify signatures.
#
# Signatures are EMBEDDED in the manifest's `signatures[]` array:
# {key_id, signature} — hex key id of the verifying key, hex 64-byte
# Ed25519 signature over the canonical manifest bytes. This is the exact
# format provenance::ImageManifest::verify checks when sandboxd resolves
# an image. All crypto is done by the `lumen-image-sign` helper (a small
# Rust bin in lumen-sandboxd); this script only handles arguments.
#
# Usage:
#   sign-image.sh sign   --manifest M --key signing.key [--out O]
#   sign-image.sh verify --manifest M --key verify.key
#
# sign writes the signed manifest back to --manifest in place (or to
# --out when given) and prints the image digest. verify exits 0 on a
# valid signature from the given key.
#
# Keys are Ed25519 seeds/public keys as 64-char hex or 32 raw bytes
# (see provenance::load_signing_key / load_verifying_key). PEM is NOT
# accepted, and detached manifest.sig files are no longer used.

set -euo pipefail

MODE="${1:-}"
shift || true

# Locate the helper: prefer PATH, else the release build next to this repo.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$(command -v lumen-image-sign || true)"
if [[ -z "$HELPER" ]]; then
    CANDIDATE="$SCRIPT_DIR/../../../target/release/lumen-image-sign"
    if [[ -x "$CANDIDATE" ]]; then
        HELPER="$CANDIDATE"
    fi
fi
if [[ -z "$HELPER" ]]; then
    echo "ERROR: lumen-image-sign not found on PATH or at $SCRIPT_DIR/../../../target/release/lumen-image-sign" >&2
    echo "Build it: cargo build --release -p lumen-sandboxd --bin lumen-image-sign" >&2
    exit 1
fi

ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest | --key | --out) ARGS+=("$1" "$2"); shift 2 ;;
        --sig)
            echo "ERROR: detached manifest.sig files are no longer used; signatures are embedded in the manifest's signatures[] array" >&2
            exit 1
            ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

case "$MODE" in
    sign | verify) exec "$HELPER" "$MODE" "${ARGS[@]}" ;;
    *) echo "Usage: $0 {sign|verify} --manifest M --key K [--out O]" >&2; exit 1 ;;
esac
