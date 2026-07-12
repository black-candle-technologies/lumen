# Local Runtime Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Milestone 1 as a local-model agent loop whose file and process actions cannot bypass capability checks, approvals, isolated dispatch, or audit recording.

**Architecture:** Domain types and orchestration live in `lumen-core`; `lumen-db` implements transactional SQLite repositories; `lumen-integrations` supplies the local model client and built-in executors; `lumen-server` exposes the core service over HTTP and SSE. Implementation proceeds in security-complete slices, beginning with deny-by-default domain behavior before adding transports or side effects.

**Tech Stack:** Rust 2024, Tokio, Axum, SQLite with SQLx, Serde, UUID, tracing, SvelteKit, Tauri 2

---

## File Structure

The first milestone should grow the existing crates using focused modules. Exact filenames may change only when a task discovers an established local convention that does not exist in the current scaffold.

```text
crates/lumen-core/src/
  lib.rs
  identity.rs
  capability.rs
  action.rs
  policy.rs
  approval.rs
  audit.rs
  model.rs
  executor.rs
  run.rs
crates/lumen-db/src/
  lib.rs
  migrations.rs
  repositories.rs
  audit.rs
crates/lumen-db/migrations/
crates/lumen-integrations/src/
  lib.rs
  openai_compatible.rs
  filesystem.rs
  process.rs
  sandbox.rs
crates/lumen-server/src/
  lib.rs
  state.rs
  routes/
  sse.rs
crates/lumen-cli/src/
  main.rs
  config.rs
apps/web/src/routes/
  +page.svelte
  approvals/
  audit/
```

## Task 1: Core Security Types

**Files:** `crates/lumen-core/src/{identity,capability,action,policy}.rs`, `crates/lumen-core/src/lib.rs`

- [x] Write unit tests for canonical action fingerprints, resource scopes, capability intersection, and deny-by-default policy.
- [x] Run `cargo test -p lumen-core` and confirm the tests fail for missing behavior.
- [x] Implement typed identities, action envelopes, capability scopes, and policy decisions without infrastructure dependencies.
- [x] Run `cargo test -p lumen-core` and confirm the tests pass.
- [x] Commit as `feat(core): define action and capability model`.

## Task 2: Approval State Machine

**Files:** `crates/lumen-core/src/approval.rs`, `crates/lumen-core/src/action.rs`

- [x] Write tests for one-shot consumption, expiry, fingerprint mutation, policy-version changes, rejection, and replay.
- [x] Run the focused tests and confirm they fail.
- [x] Implement the approval state machine and dispatch precondition checks.
- [x] Run `cargo test -p lumen-core` and confirm the tests pass.
- [x] Commit as `feat(core): bind approvals to immutable actions`.

## Task 3: Audit Domain And SQLite Foundation

**Files:** `crates/lumen-core/src/audit.rs`, `crates/lumen-db/src/{lib,migrations,repositories,audit}.rs`, `crates/lumen-db/migrations/*`

- [x] Write database tests for empty migration, foreign keys, ordered append, hash continuity, and tamper detection.
- [x] Run `cargo test -p lumen-db` and confirm they fail.
- [x] Implement SQLite setup, the Milestone 1 schema, repository transactions, and audit hash chaining.
- [x] Add an atomic test proving one-shot approval consumption and execution reservation cannot race.
- [x] Run `cargo test -p lumen-db` and confirm all database tests pass.
- [x] Commit as `feat(db): add runtime state and chained audit log`.

## Task 4: Run Orchestrator With Fakes

**Files:** `crates/lumen-core/src/{model,executor,run}.rs`

- [x] Write async tests using fake model, executor, approval, and audit ports.
- [x] Cover text completion, denied action, approval pause/resume, budget exhaustion, cancellation, executor failure, and unknown outcome.
- [x] Run the focused tests and confirm they fail.
- [x] Implement the bounded agent loop and non-bypassable dispatch sequence.
- [x] Run `cargo test -p lumen-core` and confirm all tests pass.
- [x] Commit as `feat(core): orchestrate policy-bound agent runs`.

## Task 5: Local Model Integration

**Files:** `crates/lumen-integrations/src/openai_compatible.rs`, `crates/lumen-integrations/src/lib.rs`

- [x] Write contract tests against a local mock HTTP server for streaming, structured actions, malformed output, deadlines, and cancellation.
- [x] Confirm tests fail before the client exists.
- [x] Implement the loopback-restricted OpenAI-compatible client and provider identity recording.
- [x] Verify that no remote fallback exists and non-loopback endpoints require explicit configuration.
- [x] Run `cargo test -p lumen-integrations` and confirm tests pass.
- [x] Commit as `feat(integrations): add local model provider`.

## Task 6: Built-In Filesystem And Process Executors

**Files:** `crates/lumen-integrations/src/{filesystem,process,sandbox}.rs`

- [x] Write tests for workspace path canonicalization, symlink escape, command allowlisting, environment filtering, output limits, timeout, cancellation, and process-tree termination.
- [x] Confirm the tests fail before implementation.
- [x] Implement read-only workspace access and the sandbox backend contract.
- [x] Implement process dispatch only through validated action envelopes.
- [x] Add platform capability reporting and deny when required enforcement is unavailable.
- [x] Run `cargo test -p lumen-integrations` and confirm tests pass.
- [x] Commit as `feat(integrations): add constrained local executors`.

## Task 7: HTTP And SSE Surface

**Files:** `crates/lumen-server/src/{lib,state,sse}.rs`, `crates/lumen-server/src/routes/*`

- [x] Write route tests for local authentication, workspace rejection, run creation, approval grant/reject, SSE replay, audit listing, and direct-dispatch rejection.
- [x] Confirm route tests fail before implementation.
- [x] Implement Axum handlers as adapters over the core application service.
- [x] Ensure no handler can construct an approved execution attempt directly.
- [x] Run `cargo test -p lumen-server` and confirm tests pass.
- [x] Commit as `feat(server): expose secured local runtime API`.

## Task 8: Configuration And Process Composition

**Files:** `crates/lumen-cli/src/{main,config}.rs`, workspace `Cargo.toml` files

- [x] Write tests for strict `lumen.toml` parsing, unknown fields, secure defaults, loopback binding, and missing sandbox guarantees.
- [x] Confirm tests fail before implementation.
- [x] Wire database, core services, integrations, server, graceful shutdown, and audit verification.
- [x] Add `lumen migrate`, `lumen serve`, and `lumen audit verify` commands.
- [x] Run `cargo test --workspace` and `cargo check --workspace`.
- [x] Commit as `feat(cli): compose the local runtime`.

## Task 9: Minimal Control Surface

**Files:** `apps/web/src/routes/+page.svelte`, `apps/web/src/routes/approvals/*`, `apps/web/src/routes/audit/*`

- [x] Write component and browser tests for chat streaming, exact approval preview, changed-action invalidation, cancellation, and audit inspection.
- [x] Confirm tests fail before implementation.
- [x] Implement the chat, approval, and audit workflows without adding unrelated dashboard features.
- [x] Run `pnpm check:web`, frontend tests, and Playwright at desktop and mobile viewports.
- [x] Commit as `feat(web): add chat approvals and audit views`.

## Task 10: End-To-End Security Verification

**Files:** new integration tests under the owning crates or a focused workspace test package if shared setup justifies it

- [ ] Add an end-to-end test where hostile retrieved content proposes an out-of-scope command and receives a denial.
- [ ] Add an approval mutation and replay test across the HTTP and database boundaries.
- [ ] Add symlink escape, secret-redaction, cancellation, crash-recovery, and audit-tampering scenarios.
- [ ] Run `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all -- --check`, and `pnpm check:web`.
- [ ] Update the roadmap only for behavior demonstrated by the verification suite.
- [ ] Commit as `test: verify runtime security boundaries end to end`.
