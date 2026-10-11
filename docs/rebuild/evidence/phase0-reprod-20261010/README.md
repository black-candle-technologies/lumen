# Phase-0 reproduction record — 2026-10-10 (independent re-run)

This is a **new reproduction record**, captured fresh on a scratch Linux host.
It does not overwrite, supersede, or replace any prior evidence record under
`docs/rebuild/evidence/`; those remain immutable. Signed artifact admission and
owner acceptance remain pending and are documented in `../phase-0.md`.

## Pipeline (all commands from scripts/rebuild, run against HEAD 61b5f90)

Environment: unprivileged x86-64 Linux lane host (Ubuntu 26.04, kernel 6.x),
systemd user session, bubblewrap 0.11.1, Node 22.22.1, gcc 15.2, Python 3.14.
The full phase-0 confinement pipeline executed locally rather than only in CI:

1. `bash scripts/rebuild/build-pinned-pi.sh <scratch>/upstream`
2. `python3 scripts/rebuild/confinement/prepare_pi.py <upstream>/repo <scratch>/runtime`
3. `cargo build -p lumen-server --example phase0_kernel_probe`
4. `python3 scripts/rebuild/confinement/probe_pi.py <runtime> <digest> target/debug/examples/phase0_kernel_probe <scratch>/evidence`
5. `python3 scripts/rebuild/confinement/verify_audit.py evidence/kernel-evidence.json evidence/audit-anchor.json`

## Reproduced digests

| Artifact | Reproduced value | Match |
|---|---|---|
| pinned `package.json` lockfile (pi_lock in build script) | `95dbf4d7aa54eebf235edccd6926efac42fbf4e1c6a92c625c9ac706a8b367f7` | matches pinned constant |
| upstream bundle `packages/coding-agent/dist/bundle/cli.js` | `e79626f2dd6f94aa45d30f3fa63cd84319a6eefcd150b353cfaf274366926774` | matches `spike-e2e-evidence.json` `pi.artifact_sha256` |
| prepared runtime manifest digest | `f498a7b4a6b7478cb65473b5db1cab52ba9db2313121e46d6c8612c166d5c185` | fresh capture (recorded here) |

## Probe outcome (real pinned Pi v0.87.1)

```json
{"real_pi": true, "kernel_denied": true, "session_destroyed": true,
 "audit_verified": true,
 "runtime_manifest": "f498a7b4a6b7478cb65473b5db1cab52ba9db2313121e46d6c8612c166d5c185",
 "events": 24}
```

`verify_audit.py`: "Audit chain, exact denial digest, signed checkpoints and
trusted head verified."

Files in this directory are copied verbatim from the reproduced run:
`kernel-evidence.json`, `audit-anchor.json`, `rpc-events.json`.

## Native suite

`python3 -m unittest -v test_runtime test_liveness test_audit` on the same
host: **31 tests, OK** (`test_runtime.py` includes the phase-0 exclusion scope
and denial probes; `test_liveness.py` the v2 SIGKILL/liveness suite;
`test_audit.py` the verifier including its tamper-rejection cases).

## Standing limitations (unchanged from phase-0 gate policy)

- This is a **mediated denial** reproduction on a scratch host. It is not
  signed artifact admission, not a machine-reboot/Firecracker observation, and
  not owner-accepted Phase-0 gate evidence on its own.
- The runtime candidate remains unsigned and not admitted; production Pi
  admission stays disabled (`pi_launch::require_confinement`).
- The confinement guard's reviewed architecture covers Linux x86-64 only; the
  arm64 container shell of the pinned pipeline fails at `guard.c` compile by
  design (see `guard.c` `#error`), and no allowlist was changed or ported.
