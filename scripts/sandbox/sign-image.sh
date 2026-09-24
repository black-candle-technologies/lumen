#!/usr/bin/env bash
# Sign a guest image manifest and verify signatures.
#
# Usage:
#   sign-image.sh --manifest manifest.json --key signing.key --out manifest.sig
#   verify-image.sh --manifest manifest.json --sig manifest.sig --key verify.key
#
# The signing key is an Ed25519 private key (PEM). The verify key is the
# corresponding public key. Keys are managed out-of-band; this script never
# generates them (use `openssl genpkey` or your KMS).

set -euo pipefail

MODE="${1:-}"
shift || true

MANIFEST=""
KEY=""
SIG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manifest) MANIFEST="$2"; shift 2 ;;
        --key) KEY="$2"; shift 2 ;;
        --sig) SIG="$2"; shift 2 ;;
        --out) SIG="$2"; shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 1 ;;
    esac
done

if [[ "$MODE" == "sign" ]]; then
    [[ -n "$MANIFEST" && -n "$KEY" && -n "$SIG" ]] || { echo "missing args" >&2; exit 1; }
    # Sign the canonical JSON (sorted keys, no whitespace).
    CANONICAL=$(mktemp)
    trap 'rm -f "$CANONICAL"' EXIT
    jq -S -c . "$MANIFEST" > "$CANONICAL"
    openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$CANONICAL" -out "$SIG"
    echo "Signed $MANIFEST -> $SIG"
elif [[ "$MODE" == "verify" ]]; then
    [[ -n "$MANIFEST" && -n "$KEY" && -n "$SIG" ]] || { echo "missing args" >&2; exit 1; }
    CANONICAL=$(mktemp)
    trap 'rm -f "$CANONICAL"' EXIT
    jq -S -c . "$MANIFEST" > "$CANONICAL"
    if openssl pkeyutl -verify -pubin -inkey "$KEY" -rawin -in "$CANONICAL" -sigfile "$SIG"; then
        echo "Signature OK"
    else
        echo "Signature FAILED" >&2
        exit 1
    fi
else
    echo "Usage: $0 {sign|verify} --manifest M --key K --sig S" >&2
    exit 1
fi
