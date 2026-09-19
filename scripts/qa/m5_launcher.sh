#!/usr/bin/env bash
set -euo pipefail

if ! grep -qi microsoft /proc/version; then
  echo 'M5 QA launcher requires WSL Linux; use m5_launcher.ps1 from Windows PowerShell.' >&2
  exit 2
fi
if ! command -v python3 >/dev/null || ! python3 -c 'import tomllib' 2>/dev/null; then
  echo 'M5 QA launcher requires Python 3.11+ with sqlite3 and tomllib.' >&2
  exit 2
fi

exec python3 "$(dirname "${BASH_SOURCE[0]}")/m5_launcher.py" "$@"
