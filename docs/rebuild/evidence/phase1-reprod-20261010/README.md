# Phase-1 reproduction record — 2026-10-10 (re-run + latency measurement)

New record; overwrites no prior phase-1 evidence. Owner review and phase
acceptance remain pending per `../phase-1.md`.

## Documented verification commands, re-run at HEAD `61b5f90` (with the dated
uncommitted task changes applied: CI trigger/log hygiene, wasmtime interrupter
hardening, acceptance-job CI, Phase-0 dialog wiring)

Two unprivileged Linux environments:

- **Lane x86-64 scratch host** (Ubuntu, lane-vps-style toolchain, rustc
  1.99.0, warm target dir at the HEAD commit). Results:
  - `cargo clippy --workspace --all-targets -- -D warnings` — **exit 0**
  - `cargo fmt --all -- --check` — clean
  - `python3 scripts/rebuild/verify_authority_fixtures.py` — "Verified scope
    digest, lease signatures, historical/v2 actions, and distinct host/kernel
    transport bindings independently"
  - `transitive_revocation_latency_over_deep_chain` — passed, measured 3.97 s
    for 2001 leases (see below)
  - The host's own full test-matrix run did not complete: the shared disk was
    already 93% full before this work and the parallel test-compile pass
    exhausted it. Only this task's own scratch artifacts were cleaned; the
    matrix run is deferred to CI on a pristine runner.
- **Sandboxed Linux container** (arm64, rustc 1.99.0, shared repo checkout).
  Results:
  - `cargo test -p lumen-core -p lumen-db -p lumen-protocol -p lumen-server
    --lib --tests` — **37 result-ok suites, 0 failures** (~600 tests),
    `CARGO_INCREMENTAL=0`
  - `cargo test -p lumen-acceptance` (whole crate incl. bypass inventory) —
    0 lib tests, 14/14 bypass-inventory tests, 5/5 spike-evidence tests
  - the workspace pass over the remaining crates plus clippy/fmt were also
    exercised in the same environment during development of the dated changes

## Measured transitive revocation latency (remaining-gate item closed)

New test `lumen_db::tests::lease_persistence::transitive_revocation_latency_over_deep_chain`
builds a depth-2000 descendant lease chain under one active root session and
drives the atomic destroy-and-revoke transition
(`Database::invalidate_kernel_sessions_and_revoke`), asserting every
descendant is transitively revoked, historical rows are preserved as
evidence, and the wall-clock latency stays within a documented 5 s bound.

Measured:
- macOS arm64 (local): 2001 leases in 494 ms (~246 µs/lease)
- lane x86-64 host (concurrent cargo load): 2001 leases in 3.97 s
  (~1983 µs/lease)

The measured numbers are reporting data only; the gate criterion is the
asserted bound plus transitive correctness.
