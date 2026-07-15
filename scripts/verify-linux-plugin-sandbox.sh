#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/verify-linux-plugin-sandbox.sh [--dry-run]

Runs the Milestone 3 privileged Linux plugin-sandbox verification gate.
This command must run on Linux with bubblewrap available and with enough
kernel/container privileges for bubblewrap to create the configured namespaces.

Options:
  --dry-run  Print the commands without executing them.
EOF
}

dry_run=0
case "${1:-}" in
  "")
    ;;
  --dry-run)
    dry_run=1
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

commands=(
  "cargo build -p lumen-extension-sdk --example subprocess_tool --locked"
  "cargo test -p lumen-integrations --no-default-features --lib sandbox::tests --locked"
  "cargo test -p lumen-integrations --no-default-features --test extension_process --locked -- --nocapture"
  "cargo test -p lumen-integrations --no-default-features --test local_executors system_sandbox --locked -- --nocapture"
)

if (( dry_run )); then
  printf '%s\n' "${commands[@]}"
  exit 0
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Linux plugin-sandbox verification must run on Linux." >&2
  exit 1
fi

if ! command -v bwrap >/dev/null 2>&1; then
  echo "bubblewrap (bwrap) is required for Linux plugin-sandbox verification." >&2
  exit 1
fi

for command in "${commands[@]}"; do
  printf '+ %s\n' "$command"
  eval "$command"
done
