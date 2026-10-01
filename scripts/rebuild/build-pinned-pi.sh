#!/usr/bin/env bash
# Build the candidate upstream source in a disposable development tree.
# Does not install Pi, launch the Pi CLI, or change the deployed Lumen service.
set -euo pipefail
umask 077

# Exact source gitHead for the 0.87.1 registry release. The earlier reference
# candidate b455975 has incompatible, unshipped model-data schema v6.
pi_commit=f07218c4d4bbc12bef056a7058c3dd49dfe41abe
pi_lock=95dbf4d7aa54eebf235edccd6926efac42fbf4e1c6a92c625c9ac706a8b367f7
pi_output=${1:?usage: build-pinned-pi.sh OUTPUT_DIRECTORY [--resume-build]}
pi_resume=${2:-}
[[ "$pi_output" = /* && ( ! -e "$pi_output" || "$pi_resume" = --resume-build ) ]] || { echo 'Use a new absolute output directory' >&2; exit 2; }
[[ -z "$pi_resume" || "$pi_resume" = --resume-build ]] || exit 2
[[ $(uname -s) = Linux && $(id -u) != 0 ]] || { echo 'Unprivileged Linux is required' >&2; exit 2; }
mkdir -p "$pi_output/empty-home" "$pi_output/repo" "$pi_output/npm-cache"
pi_user_runtime=/run/user/$(id -u)
pi_unit=lumen-pi-build-$(cat /proc/sys/kernel/random/uuid)
cleanup() { XDG_RUNTIME_DIR="$pi_user_runtime" systemctl --user stop "$pi_unit-deps.service" "$pi_unit-compile.service" >/dev/null 2>&1 || true; }
trap cleanup EXIT INT TERM

verify_source_contents() {
    # Read the pinned tree and actual bytes without consulting index flags or
    # Git clean filters. Hash in-process to avoid a Git process per source file.
    /usr/bin/python3 - "$pi_output/repo" "$pi_commit" <<'PY'
import hashlib
import os
import stat
import subprocess
import sys

repo, commit = sys.argv[1:]
tree = subprocess.check_output(
    ["git", "-C", repo, "ls-tree", "-rz", "--full-tree", commit])
for entry in tree.split(b"\0"):
    if not entry:
        continue
    metadata, name = entry.split(b"\t", 1)
    mode, kind, expected = metadata.split()
    path = os.path.join(os.fsencode(repo), name)
    label = repr(os.fsdecode(name))
    try:
        file_stat = os.lstat(path)
        if kind != b"blob":
            raise ValueError("unsupported pinned entry type " + kind.decode())
        if mode == b"120000" and stat.S_ISLNK(file_stat.st_mode):
            # Git stores a symlink's target bytes, not the target file contents.
            contents = os.readlink(path)
            actual = hashlib.sha1(
                b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()
        elif mode in (b"100644", b"100755") and stat.S_ISREG(file_stat.st_mode):
            digest = hashlib.sha1(b"blob " + str(file_stat.st_size).encode() + b"\0")
            with open(path, "rb") as source:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    digest.update(chunk)
            actual = digest.hexdigest()
        else:
            raise ValueError("worktree file type differs from pinned mode " + mode.decode())
    except (OSError, ValueError) as error:
        sys.exit(f"Pinned Pi source {label} diverged: content hash check failed: {error}")
    if actual != expected.decode():
        sys.exit(f"Pinned Pi source {label} diverged: content hash mismatch "
                 f"(expected {expected.decode()}, found {actual})")
PY
}

if [[ -z "$pi_resume" ]]; then
env -i PATH=/usr/bin:/bin HOME="$pi_output/empty-home" /usr/bin/git \
    -c core.hooksPath=/dev/null -C "$pi_output/repo" init -q
env -i PATH=/usr/bin:/bin HOME="$pi_output/empty-home" /usr/bin/git \
    -c core.hooksPath=/dev/null -C "$pi_output/repo" fetch --depth=1 \
    https://github.com/earendil-works/pi.git "$pi_commit"
env -i PATH=/usr/bin:/bin HOME="$pi_output/empty-home" /usr/bin/git \
    -c core.hooksPath=/dev/null -C "$pi_output/repo" checkout --detach -q FETCH_HEAD
fi
[[ $(git -C "$pi_output/repo" rev-parse HEAD) = "$pi_commit" ]]
[[ $(sha256sum "$pi_output/repo/package-lock.json" | cut -d' ' -f1) = "$pi_lock" ]]
git -C "$pi_output/repo" diff --exit-code --quiet || { echo 'Pinned Pi source working tree is dirty' >&2; exit 1; }
git -C "$pi_output/repo" diff --cached --exit-code --quiet "$pi_commit" -- || { echo 'Pinned Pi source index is dirty' >&2; exit 1; }
verify_source_contents
env -i PATH=/usr/bin:/bin /usr/bin/python3 \
    "$(dirname "$0")/hydrate-pinned-model-data.py" "$pi_output/repo"

pi_bwrap=(/usr/bin/bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL
    --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
    --dev /dev --proc /proc --tmpfs /tmp --bind "$pi_output" /work --chdir /work/repo
    --clearenv --setenv PATH /usr/bin:/bin --setenv HOME /tmp --setenv TMPDIR /tmp)

# Only the trusted package manager runs here; dependency lifecycle scripts are
# disabled. The lockfile was verified before any packages were fetched.
env -i PATH=/usr/bin:/bin XDG_RUNTIME_DIR="$pi_user_runtime" \
    /usr/bin/systemd-run --user --quiet --wait --pipe --collect --expand-environment=no --unit="$pi_unit-deps" \
    -p MemoryMax=1536M -p MemorySwapMax=0 -p CPUQuota=100% -p TasksMax=128 -p RuntimeMaxSec=600 \
    -p KillMode=control-group -p TimeoutStopSec=3 -- \
    "${pi_bwrap[@]}" --share-net --ro-bind /etc/resolv.conf /etc/resolv.conf \
    --ro-bind /etc/ssl/certs /etc/ssl/certs -- \
    /usr/bin/npm ci --ignore-scripts --no-audit --no-fund --cache /work/npm-cache

# Repository build code runs with no network and no host home/credentials.
# No network-enabled fallback if the upstream offline build cannot succeed.
env -i PATH=/usr/bin:/bin XDG_RUNTIME_DIR="$pi_user_runtime" \
    /usr/bin/systemd-run --user --quiet --wait --pipe --collect --expand-environment=no --unit="$pi_unit-compile" \
    -p MemoryMax=1536M -p MemorySwapMax=0 -p CPUQuota=100% -p TasksMax=128 -p RuntimeMaxSec=600 \
    -p KillMode=control-group -p TimeoutStopSec=3 -- \
    "${pi_bwrap[@]}" --setenv NODE_OPTIONS '--import /work/repo/node_modules/tsx/dist/loader.mjs' \
    -- /usr/bin/npm run build:offline

git -C "$pi_output/repo" diff --exit-code --quiet || { echo 'Pinned Pi source working tree is dirty' >&2; exit 1; }
git -C "$pi_output/repo" diff --cached --exit-code --quiet "$pi_commit" -- || { echo 'Pinned Pi source index is dirty' >&2; exit 1; }
verify_source_contents
sha256sum "$pi_output/repo/package-lock.json" \
    "$pi_output/repo/packages/coding-agent/dist/bundle/cli.js"
echo 'Candidate build complete; runtime manifest and independent admission review still required.'
