# M5 Windows/WSL Cargo cache guide

This is the current QA build procedure for [issue #24](https://github.com/black-candle-technologies/lumen/issues/24), not a rewrite of the September 12 [F18 observation](M5_QA_2026-09-12.md#f18). That session switched from `/tmp/lumen-functional-target` to the worktree's `target` directory, which explains one cold build. Its other minute-long recompilations lack enough recorded environment/fingerprint data to assign a cause.

## Cache policy

Keep Windows artifacts in this worktree's `target/` (set explicitly with `--target-dir target`) and WSL artifacts in a persistent directory on the Linux filesystem. Use the same target, `--locked` lockfile, toolchain, features, profile, and flags for consecutive builds. Do not put the WSL target under `/mnt/c`, share it with Windows, or delete it when removing disposable runtime data. Cargo's [build-cache reference](https://doc.rust-lang.org/cargo/reference/build-cache.html) documents `CARGO_TARGET_DIR` and `--target-dir`; this repository has no committed Cargo target override.

Record the revision with Windows Git before entering WSL: this Windows-linked worktree's `.git` pointer is not resolved by WSL Git. From PowerShell in this worktree:

```powershell
git status --short
git rev-parse HEAD
Get-FileHash -Algorithm SHA256 Cargo.lock
cargo -Vv
rustc -Vv
cargo build --locked -p lumen-cli --bin lumen --target-dir target -j 4
Get-FileHash -Algorithm SHA256 .\target\debug\lumen.exe
# Re-run the identical build to check cache reuse.
cargo build --locked -p lumen-cli --bin lumen --target-dir target -j 4
```

In WSL Bash, from this same source tree, keep the build output on WSL's Linux filesystem (check `df -T "$HOME/.cache"` on your host):

```bash
export CARGO_TARGET_DIR="$HOME/.cache/lumen-m5-cargo-target"
cargo -Vv
rustc -Vv
sha256sum Cargo.lock
cargo build --locked -p lumen-cli --bin lumen -j 4
sha256sum "$CARGO_TARGET_DIR/debug/lumen"
cargo build --locked -p lumen-cli --bin lumen -j 4
# In a new WSL shell, set the same target again before building.
export CARGO_TARGET_DIR="$HOME/.cache/lumen-m5-cargo-target"
cargo build --locked -p lumen-cli --bin lumen -j 4
```

Build once for a tested revision, then run that exact binary for `migrate`, `serve`, `audit verify`, and other operational checks. For example, with your own disposable `lumen.toml` and token already set in the environment:

```bash
"$CARGO_TARGET_DIR/debug/lumen" --config /path/to/owned/lumen.toml migrate
"$CARGO_TARGET_DIR/debug/lumen" --config /path/to/owned/lumen.toml serve
"$CARGO_TARGET_DIR/debug/lumen" --config /path/to/owned/lumen.toml audit verify
```

These commands do not invoke Cargo. Record the binary hash, revision, config/fixture identity, environment, expected and actual result for each acceptance run. Never put a real bearer token in a command line, report, or committed file. Inspect and remove only a specifically owned disposable runtime fixture; do not run `cargo clean` or erase the build cache as routine cleanup.

## Measured on September 16, 2026

Source: clean `qa-m5-24-cargo-cache` at parent commit `d6af7da2a38db6e23c0d055f6a229afb2ba0141f`; `Cargo.lock` SHA-256 `2d8d64b4acdaed7c14e505f19da364cb2fdaac056e75f86fdf64da23cb6d5ee0`. Both used the default `dev` profile and default features for `lumen-cli --bin lumen`, `--locked`, and four build jobs. No `RUSTFLAGS`, `RUSTC_WRAPPER`, `CARGO_TARGET_DIR`, or target-triple override was present in the inherited shell before the WSL-only target was set. Windows was built in `target/`; the explicit `--target-dir target` form above also verifies that output path when a user-level override exists.

| Host | Cargo/rustc; host triple | Target | First measured build | Identical repeats |
| --- | --- | --- | --- | --- |
| WSL Ubuntu 24.04 | 1.97.0 / 1.97.0; `x86_64-unknown-linux-gnu` | Linux filesystem `$HOME/.cache/lumen-m5-cargo-target` | Fresh target: 84.31 s, dependencies compiled | 0.52 s; new shell 0.53 s, no `Compiling` lines |
| Windows | 1.97.1 / 1.97.1; `x86_64-pc-windows-msvc` | Worktree `target/` | Existing cache: 20.52 s, only `lumen-cli` compiled | 0.51 s, no `Compiling` lines |

The WSL target occupied 3.5 GiB. The WSL binary SHA-256 was `afe3ad2aa242c50357eb8d9aded7af6a6380f9f7e91c8c3c58a225e38057e7ae`; the Windows `.exe` SHA-256 was `e7862b118bb3f764d4c89a0cf13fe025ea20e3b468047bb94d1a554639716bba`. They are separate binaries and targets. A disposable WSL fixture was migrated (`Migrated`), audited (`AuditVerified`), and served with `server_started` then `server_stopped result=ok` using the same Linux binary; a bounded interrupt helper returned 1 after sending SIGINT, so that helper exit is not reported as a zero exit. Port `39743` was no longer listening afterward. The fixture was removed after inspection, while a repeat build stayed cache-warm (1.47 s, no `Compiling` lines). No model inference or production data was used.

A temporary comment in `crates/lumen-cli/src/main.rs` caused only `lumen-cli` to recompile (6.18 s); restoring the source caused the same targeted rebuild (2.76 s). Cargo's fingerprint log named the changed file and an outdated dep-info timestamp. The source was restored, the Git worktree was clean, and the Linux binary hash returned to its original value. This demonstrates expected source invalidation, not a recurring full rebuild.

## If an unchanged build recompiles

First confirm the same source revision and `Cargo.lock` hash, target directory, toolchain/host triple, profile/features, flags, `RUSTC_WRAPPER`, and build environment. In WSL Bash, run the **unexpectedly rebuilding** command with:

```bash
CARGO_LOG=cargo::core::compiler::fingerprint=info cargo build --locked -p lumen-cli --bin lumen -j 4
```

On Windows PowerShell, set the diagnostic only for the build and restore any existing setting:

```powershell
$previousCargoLog = $env:CARGO_LOG
$env:CARGO_LOG = 'cargo::core::compiler::fingerprint=info'
try { cargo build --locked -p lumen-cli --bin lumen --target-dir target -j 4 }
finally { $env:CARGO_LOG = $previousCargoLog }
```

Capture the `stale`/`dirty` reason and the exact changed path or setting before changing anything. Cargo's [fingerprint guidance](https://doc.rust-lang.org/cargo/faq.html) notes that this must be done during the rebuild, not after it. A Windows-mounted source may add metadata/timestamp overhead even with Linux-side artifacts; a dedicated Linux checkout can be compared if needed, but is not required by these warm-build results and must not replace or modify Riley's checkout. Do not infer a Lumen source defect or promise universal build times from this one controlled run. The unexplained historical rebuilds remain an unreplicated observation until their original environment or a new fingerprint trace is available.
