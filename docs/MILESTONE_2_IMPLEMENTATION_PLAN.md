# Hardened Local Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Roadmap Milestone 2 with approval-bound file writes, Linux isolation, scoped OS-keychain secrets, enforced quotas, and a least-privilege desktop approval surface.

**Architecture:** Extend the Milestone 1 action lifecycle instead of adding alternate dispatch paths. Domain contracts remain in `lumen-core`; SQLite metadata stays in `lumen-db`; filesystem, sandbox, and credential-store adapters live in `lumen-integrations`; `lumen-cli` composes scoped authority; `lumen-server` and the shared SvelteKit application expose only authenticated control and visibility.

**Tech Stack:** Rust 2024, Tokio, Axum, SQLite/SQLx, cap-std, bubblewrap on Linux, OS credential stores through keyring, SvelteKit, Tauri 2, Vitest, Playwright

---

## File Structure

```text
crates/lumen-core/src/
  capability.rs          # fs.write and secret.use policy behavior
  executor.rs            # cancellation-aware executor contract
  run.rs                 # wall-time and captured-byte quotas
crates/lumen-db/migrations/
  0002_hardened_tools.sql # opaque secret-reference metadata
crates/lumen-db/src/
  repositories.rs        # secret reference CRUD and recovery invariants
crates/lumen-integrations/src/
  filesystem.rs          # trusted snapshots and atomic replacement
  process.rs             # write normalization and secret reference arguments
  sandbox.rs             # platform reports, Linux bwrap, rlimits
  secrets.rs             # SecretStore and OS keyring adapter
crates/lumen-cli/src/
  config.rs              # write, quota, sandbox, and resource limits
  runtime.rs             # composition and scoped secret injection
  lib.rs                 # secret and sandbox operator commands
crates/lumen-server/src/
  state.rs               # capability-report service port
  routes/mod.rs          # authenticated capability report
apps/web/src/lib/components/
  ApprovalItem.svelte    # effect-specific approval preview
apps/desktop/src-tauri/
  capabilities/main.json # explicit empty/minimal capability set
  tauri.conf.json        # production CSP and fixed main window
  src/lib.rs             # command-free shell
docs/
  MILESTONE_2_DESIGN.md
  MILESTONE_2_IMPLEMENTATION_PLAN.md
```

## Task 1: Approval-Bound File Write Domain

**Files:** `crates/lumen-core/src/{capability,policy}.rs`, `crates/lumen-core/tests/core_security.rs`, `crates/lumen-integrations/src/{filesystem,process}.rs`, `crates/lumen-integrations/tests/local_executors.rs`

- [x] Add failing tests proving `fs.write` requires approval and exact path authority.
- [x] Add failing tests for trusted new-file and replacement snapshots, canonical hashes, size limits, and symlink rejection.
- [x] Add failing tests proving a changed target or mutated preview cannot be written.
- [x] Run `cargo test -p lumen-core -p lumen-integrations` and confirm the new tests fail for missing behavior.
- [x] Implement canonical `filesystem.write` normalization with trusted before/after content and hashes.
- [x] Implement same-directory atomic replacement with a final precondition check.
- [x] Grant workspace-scoped `fs.write` in composition while retaining approval-required policy.
- [x] Run the focused tests and strict Clippy.
- [x] Commit as `feat(tools): add approval-bound file writes`.

## Task 2: Linux Sandbox And Capability Reporting

**Files:** `crates/lumen-integrations/src/sandbox.rs`, `crates/lumen-integrations/tests/local_executors.rs`, `crates/lumen-cli/src/{config,lib}.rs`, `crates/lumen-cli/tests/{config,commands}.rs`, `crates/lumen-server/src/state.rs`, `crates/lumen-server/src/routes/mod.rs`, `crates/lumen-server/tests/routes.rs`

- [x] Add failing profile tests for fixed-path bubblewrap detection, namespace isolation, read-only mounts, network isolation, cleared environment, dropped capabilities, new session, and parent-death cleanup.
- [x] Add failing tests for structured per-guarantee platform reporting and default fail-closed validation.
- [x] Add failing CLI and authenticated API tests for capability reporting.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement the Linux bubblewrap command builder without action-controlled wrapper paths.
- [x] Implement structured `SandboxReport` guarantees and expose them through CLI and API adapters.
- [x] Run Linux-specific tests in a Linux container or CI-compatible target when available; keep non-Linux profile construction tests platform-independent.
- [x] Run focused tests and strict Clippy.
- [x] Commit as `feat(sandbox): enforce and report Linux isolation`.

## Task 3: OS-Keychain Secret References

**Files:** `crates/lumen-core/src/{capability,action}.rs`, `crates/lumen-db/migrations/0002_hardened_tools.sql`, `crates/lumen-db/src/repositories.rs`, `crates/lumen-db/tests/database.rs`, `crates/lumen-integrations/src/{lib,secrets,process}.rs`, `crates/lumen-integrations/tests/secrets.rs`

- [x] Add failing type and policy tests for opaque `secret.use` resources.
- [x] Add failing migration/repository tests proving SQL stores only reference metadata and enforces workspace/program/environment scope.
- [x] Add failing adapter contract tests for put, resolve, delete, missing entries, and unavailable credential stores.
- [x] Add failing process tests proving secret reference IDs are fingerprinted while values are absent from actions and previews.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement the append-only migration and typed secret-reference repository.
- [x] Implement `SecretStore`, the OS-keyring adapter, and an in-memory test adapter.
- [x] Extend process normalization with secret-reference bindings and `secret.use` requirements.
- [x] Run migration-from-0001, focused tests, and strict Clippy.
- [x] Commit as `feat(secrets): add scoped OS-keychain references`.

## Task 4: Secret Operator Commands And Injection

**Files:** `crates/lumen-cli/src/{lib,runtime}.rs`, `crates/lumen-cli/tests/commands.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`

- [x] Add failing CLI tests for create/list/delete commands, standard-input value handling, duplicate labels, and deletion ordering.
- [x] Add failing end-to-end tests for exact workspace/program/environment scope, missing references, and approval replay.
- [x] Add a failing leak test covering database rows, action JSON, approval JSON, audit JSON, and SSE events.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement operator commands without accepting secret values in arguments or ordinary config.
- [x] Load secret-reference capability grants for the owning workspace.
- [x] Resolve and inject values only inside the executor after final authorization.
- [x] Redact injected values from all bounded outputs before persistence or publication.
- [x] Run focused tests and strict Clippy.
- [x] Commit as `feat(runtime): inject scoped action secrets`.

## Task 5: Cancellation, Quotas, And Resource Limits

**Files:** `crates/lumen-core/src/{executor,run}.rs`, `crates/lumen-core/tests/run_orchestrator.rs`, `crates/lumen-integrations/src/{process,sandbox}.rs`, `crates/lumen-integrations/tests/local_executors.rs`, `crates/lumen-cli/src/{config,runtime}.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`

- [x] Add failing core tests for wall-clock and cumulative captured-result quotas.
- [x] Add failing integration tests proving the run cancellation token reaches an executing process and terminates descendants.
- [x] Add failing tests for CPU, address-space, file-size, descriptor, process-count, output, and timeout limits.
- [x] Add a recovery regression proving terminal attempts are not changed and incomplete attempts become unknown exactly once without retry.
- [x] Confirm the focused tests fail before implementation.
- [x] Make `ExecutorPort` cancellation-aware and preserve cancelled, timed-out, failed, and unknown outcomes distinctly.
- [x] Add explicit run quota accounting and audit payloads.
- [x] Apply Unix rlimits before sandbox wrapper launch and validate all configured limits.
- [x] Run focused tests and strict Clippy.
- [x] Commit as `feat(runtime): enforce cancellation and resource quotas`.

## Task 6: Desktop Security Boundary

**Files:** `apps/desktop/src-tauri/{Cargo.toml,tauri.conf.json,capabilities/main.json,src/lib.rs}`, `apps/desktop/src-tauri/tests/security_config.rs`, `pnpm-lock.yaml`

- [x] Add a failing Rust configuration test that rejects null CSP, global Tauri exposure, remote capabilities, opener/shell/process/filesystem permissions, and registered commands.
- [x] Confirm `cargo test -p lumen-desktop` fails against the scaffold configuration.
- [x] Remove the opener plugin dependency, sample command, and global Tauri object.
- [x] Add an explicit production CSP, development CSP, fixed `main` label, and one least-privilege capability file.
- [x] Validate the generated Tauri schema/configuration and build the desktop crate.
- [x] Run desktop tests and strict Clippy.
- [x] Commit as `security(desktop): minimize the Tauri authority surface`.

## Task 7: Exact Approval UX

**Files:** `apps/web/src/lib/components/ApprovalItem.svelte`, `apps/web/src/routes/approvals/+page.svelte`, `apps/web/src/lib/components/ApprovalItem.test.ts`, `apps/web/tests/control-surface.spec.ts`

- [x] Add failing component tests for file before/after content, hashes, byte counts, new-file state, and secret reference labels without values.
- [x] Add failing browser tests at desktop and mobile viewports for file-write review and changed-action conflicts.
- [x] Confirm the tests fail before implementation.
- [x] Implement action-specific semantic previews while retaining the canonical fingerprint and raw normalized data where useful.
- [x] Verify long paths, large previews, and mobile controls do not overflow or overlap.
- [x] Run Svelte diagnostics, unit tests, Playwright, and production build.
- [x] Commit as `feat(web): show exact local action previews`.

## Task 8: Milestone 2 Security Verification

**Files:** security tests under owning crates, `README.md`, `docs/{ROADMAP,REPOSITORY,SECURITY}.md`, this plan

- [x] Add a model-to-HTTP-to-executor write test proving mutation and concurrent file changes fail closed.
- [x] Add a secret exfiltration attempt proving values cannot enter persisted or streamed records.
- [x] Add platform report, Linux profile, process cancellation, resource exhaustion, and crash-recovery adversarial scenarios.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] Run `cargo test --workspace`.
- [x] Run `pnpm check:web`, frontend unit tests, production builds, and Playwright desktop/mobile tests.
- [x] Inspect the rendered approval UI and validate Tauri configuration.
- [x] Update Roadmap Milestone 2 only for behavior proven by the suite.
- [x] Commit as `test: verify hardened local tool boundaries`.
- [x] Push `feat/milestone-2-hardened-local-tools` after confirming the worktree is clean and the remote ref matches local HEAD.
