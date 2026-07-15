# Extension Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Roadmap Milestone 3 with reviewed local plugin packages, immutable versions, narrow grants and settings, WASM-component and supervised-subprocess hosts, approval-bound invocation, exact provenance, quarantine, operator APIs, and a usable Plugins control surface.

**Architecture:** Add one runtime-neutral extension contract in `lumen-core`. Keep immutable plugin metadata and lifecycle state in `lumen-db`; package I/O, schema validation, Wasmtime, and subprocess supervision in `lumen-integrations`; compose every administrative action, invocation, and returned proposal through the existing action lifecycle in `lumen-cli`; expose authenticated workspace adapters in `lumen-server` and the shared SvelteKit application. Neither host receives ambient workspace or secret authority.

**Tech Stack:** Rust 2024, Tokio, Axum, SQLite/SQLx, serde/TOML, SHA-256, semver, a bounded JSON Schema validator, Wasmtime component model/WIT, cap-std, existing platform sandboxes, SvelteKit, Vitest, Playwright, Tauri 2

---

## File Structure

```text
crates/lumen-core/src/
  action.rs                 # optional immutable plugin provenance in fingerprints
  capability.rs             # plugin administrative and invocation capability names
  extension.rs              # IDs, manifests, invocation/result/proposal contracts
  policy.rs                 # action-specific approval defaults
crates/lumen-db/migrations/
  0003_extension_runtime.sql # staged packages, versions, grants, settings, failures
crates/lumen-db/src/
  extensions.rs             # transactional extension repositories
crates/lumen-integrations/src/
  extension_package.rs      # bounded stage, strict manifest, hashes, immutable install
  extension_schema.rs       # bounded compile and runtime JSON validation
  extension_wasm.rs         # Wasmtime component host with no WASI imports
  extension_process.rs      # one-shot framed subprocess supervisor
  sandbox.rs                # plugin-specific no-workspace native profile
crates/lumen-extension-sdk/
  wit/lumen-extension.wit   # versioned guest contract
  src/lib.rs                # shared protocol and guest/subprocess helpers
  examples/                 # conformance components
crates/lumen-cli/src/
  extension_runtime.rs      # admin service, host router, quarantine, child proposals
  lib.rs                    # stage/review/install/enable/grant/settings commands
  runtime.rs                # lifecycle composition through normal action ports
crates/lumen-server/src/
  state.rs                  # extension service commands and views
  routes/mod.rs             # authenticated workspace plugin routes
apps/web/src/
  lib/api.ts                # typed plugin API client
  lib/components/           # authority, provenance, settings, failure views
  routes/plugins/+page.svelte
docs/
  MILESTONE_3_DESIGN.md
  MILESTONE_3_IMPLEMENTATION_PLAN.md
```

## Task 1: Extension Identity And Action Provenance

**Files:** `crates/lumen-core/src/{lib,action,capability,extension,policy}.rs`, `crates/lumen-core/tests/extension_contract.rs`, `crates/lumen-core/tests/core_security.rs`

- [x] Add failing tests for bounded reverse-domain plugin IDs, component IDs, canonical semantic versions, lowercase SHA-256 digests, runtime/protocol versions, strict manifest fields, and canonical ordering.
- [x] Add failing tests proving `plugin.install`, `plugin.enable`, `plugin.capabilities.set`, `plugin.settings.set`, `plugin.quarantine.release`, and `plugin.invoke` carry exact resource scopes and authority-expanding operations require approval.
- [x] Add failing fingerprint tests proving plugin/version/component, package/manifest/artifact/settings/grant digests, protocol, parent action, and input all bind an action while diagnostic text does not.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement runtime-neutral extension identity, manifest, invocation, result, proposal, failure, limits, and provenance types with private fields and validated constructors.
- [x] Extend action envelopes with optional typed provenance while preserving built-in action serialization and existing fingerprints.
- [x] Run focused tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): define identity and provenance contracts`.

## Task 2: Strict Packages, Schemas, And Quarantine Staging

**Files:** `crates/lumen-integrations/Cargo.toml`, `crates/lumen-integrations/src/{lib,extension_package,extension_schema}.rs`, `crates/lumen-integrations/tests/extension_packages.rs`, `crates/lumen-integrations/tests/fixtures/packages/`

- [x] Add failing fixtures for valid WASM/subprocess packages and unknown manifest fields, invalid IDs/versions/digests, absolute/traversal paths, symlinks, hard links, devices, duplicate canonical paths, file mutation, excessive counts, and byte limits; prove additional bounded regular files are included in package identity.
- [x] Add failing schema tests for unsupported keywords, remote/external/recursive references, regex/resource-heavy constructs, excessive schema depth/size, and bounded input/output validation.
- [x] Add failing staging tests proving verified bytes are copied into a Lumen-owned quarantine, never execute, and produce deterministic file/package/manifest/artifact/schema hashes.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement strict TOML parsing, normalized package walking without link following, stable hashing, race checks, bounded schema compilation, and immutable staged-package descriptors.
- [x] Reopen and rehash staged bytes through directory capabilities before returning any install input.
- [x] Run focused tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): stage strict local packages`.

## Task 3: Append-Only Extension Persistence

**Files:** `crates/lumen-db/migrations/0003_extension_runtime.sql`, `crates/lumen-db/src/{lib,extensions}.rs`, `crates/lumen-db/tests/{database,extensions}.rs`

- [x] Add failing migration-from-0002 and fresh-database tests for all Milestone 3 tables, constraints, indexes, and foreign keys.
- [x] Add failing repository tests for immutable staged records, idempotent identical installs, duplicate identity with different bytes, content-relative artifact paths, components, capability requests, and exact provenance.
- [x] Add failing tests for one enabled version per plugin/workspace, atomic side-by-side switches, global artifact quarantine, workspace health quarantine, and restart-persistent rolling failure windows.
- [x] Add failing tests for revisioned global/workspace grants, scoped optimistic settings updates, and constraints preventing grants outside manifest requests.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement the append-only migration and typed transactional repositories without storing executable bytes, secrets, or ambient source paths in SQL.
- [x] Run migration tests, focused repository tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): persist immutable plugin state`.

## Task 4: Grants And Deterministic Settings

**Files:** `crates/lumen-core/src/extension.rs`, `crates/lumen-core/tests/extension_contract.rs`, `crates/lumen-db/src/extensions.rs`, `crates/lumen-db/tests/extensions.rs`, `crates/lumen-integrations/src/extension_schema.rs`, `crates/lumen-integrations/tests/extension_packages.rs`

- [x] Add failing tests proving global grants cannot exceed manifest requests and workspace grants can only narrow global grants.
- [x] Add failing tests for actor/workspace/agent/run plus global/workspace/component/action intersections and independent exact `plugin.invoke` authority.
- [x] Add failing settings tests for `global -> workspace -> user -> agent`, recursive object merge, scalar/array replacement, optimistic revisions, canonical hashes, unknown fields, depth/byte limits, and secret-reference metadata only.
- [x] Add failing tests proving grant or settings revision changes alter invocation fingerprints, invalidate pending approvals bound to prior revisions, and revoke new effects immediately.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement canonical grant-set hashing, settings merge/validation, revision writes, and effective invocation context loading.
- [x] Run focused tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): enforce grants and scoped settings`.

## Task 5: Administrative Lifecycle Through Actions

**Files:** `crates/lumen-cli/src/{lib,runtime,extension_runtime}.rs`, `crates/lumen-cli/tests/{commands,extensions}.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `crates/lumen-integrations/src/extension_package.rs`

- [x] Add failing CLI/service tests for stage, review, install, enable, disable, grant updates, setting updates, side-by-side switches, and quarantine release.
- [x] Add failing tests proving stage is acquisition only and every state-changing operation except allowed narrowing/disablement persists, evaluates, approves when required, pre-audits, reserves, executes, and records a terminal outcome.
- [x] Add failing substitution and crash-recovery tests proving exact approved hashes are rechecked and administrative actions are never direct SQL updates or automatic retries.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement the transport-neutral administrative service and executor; make CLI commands thin authenticated adapters.
- [x] Copy an unchanged approved package into a content-addressed immutable directory transactionally and leave new versions disabled with no grants.
- [x] Run focused tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): route plugin lifecycle through approvals`.

## Task 6: Extension SDK And WASM Component Host

**Files:** `Cargo.toml`, `Cargo.lock`, `crates/lumen-extension-sdk/**`, `crates/lumen-integrations/Cargo.toml`, `crates/lumen-integrations/src/extension_wasm.rs`, `crates/lumen-integrations/tests/{extension_wasm,extension_conformance}.rs`

- [x] Add a failing common conformance suite for structured results, returned proposals, typed failures, protocol mismatch, request correlation, and response bounds.
- [x] Add failing Wasmtime tests for valid fixture execution, unknown imports, WASI filesystem/socket/environment/clock/random/process denial, fresh state, memory/table/instance/result limits, fuel exhaustion, epoch deadline, cancellation, and traps.
- [x] Confirm the focused tests fail before implementation.
- [x] Add the versioned WIT world, generated guest bindings, ergonomic SDK result/proposal types, and an executable component fixture.
- [x] Implement the Wasmtime component host with component-model validation, no WASI linker, resource limiter, fuel, epoch interruption, cancellation, and digest-keyed compilation cache metadata.
- [x] Run SDK docs, conformance tests, focused tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): execute bounded WASM components`.

## Task 7: Supervised Subprocess Host

**Files:** `crates/lumen-extension-sdk/src/lib.rs`, `crates/lumen-extension-sdk/examples/subprocess_tool.rs`, `crates/lumen-integrations/src/{extension_process,sandbox}.rs`, `crates/lumen-integrations/tests/{extension_process,extension_conformance,local_executors}.rs`

- [x] Add failing protocol tests for one four-byte big-endian frame, protocol/request/nonce correlation, exact one response, trailing data, malformed UTF-8/JSON, oversized frames/stdout/stderr, nonzero exit, crash, timeout, and cancellation.
- [x] Add failing sandbox tests proving the plugin profile mounts the executable and loader files only, with no workspace, home, Lumen data, package directory, inherited environment, network, or write access.
- [x] Add failing process-tree tests for deadline/cancellation termination and distinct resource-exhaustion outcomes.
- [x] Confirm the focused tests fail before implementation.
- [x] Implement bounded SDK frame helpers and the one-shot subprocess fixture.
- [x] Implement the plugin-specific sandbox request/profile and supervisor with digest recheck, empty environment, fresh nonce, bounded diagnostic redaction, and typed outcomes.
- [x] Run the shared conformance suite, focused tests, formatting, and strict Clippy.
- [x] Commit as `feat(extensions): supervise native plugin processes`.

## Task 8: Approval-Bound Invocation And Child Proposals

**Files:** `crates/lumen-core/src/{extension,run}.rs`, `crates/lumen-core/tests/run_orchestrator.rs`, `crates/lumen-cli/src/{runtime,extension_runtime}.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `crates/lumen-db/src/extensions.rs`

- [x] Add failing tests proving no host byte executes before a persisted, policy-evaluated, approved where required, pre-audited, reserved `plugin.invoke` action with exact provenance.
- [x] Add failing end-to-end tests for WASM and subprocess results plus returned filesystem/process action proposals re-entering normalization, budgets, capability intersection, approval, execution, and audit as attributed child actions.
- [x] Add failing tests for disabled/missing/tampered/quarantined versions, undeclared action kinds, broader normalized requirements, late responses, changed settings/grants, cancellation, unknown recovery, and no automatic non-idempotent retry.
- [x] Add failing tests for three counted faults in ten minutes, workspace-only health quarantine, global artifact quarantine, exclusions for policy denial/user cancellation, approval-bound release, and cancellation of active invocations when a material grant is revoked or their workspace/version enters quarantine.
- [x] Confirm the focused tests fail before implementation.
- [x] Compose a host router behind `ExecutorPort`, pin immutable invocation context, normalize plugin responses as child work, persist failure accounting, and emit exact audit provenance.
- [x] Run both host conformance suites, end-to-end security tests, formatting, and strict Clippy.
- [x] Commit as `feat(runtime): invoke plugins through the action lifecycle`.

## Task 9: Authenticated Plugin API

**Files:** `crates/lumen-server/src/{state,routes/mod}.rs`, `crates/lumen-server/tests/routes.rs`, `crates/lumen-cli/src/extension_runtime.rs`

- [x] Add failing route tests for staged reviews, installed versions, components, requested/effective grants, scoped settings/revisions, failure history, and lifecycle action requests.
- [x] Add failing authentication, workspace isolation, unknown-field, body/page bound, secret-value and sensitive-diagnostic redaction, conflict, and unavailable-runtime tests while proving full package, manifest, artifact, settings, and grant digests remain visible for review.
- [x] Confirm the focused tests fail before implementation.
- [x] Extend the transport-neutral service contract and authenticated workspace routes; keep handlers free of filesystem, host, and direct lifecycle-table access.
- [x] Return exact hashes and requested authority while exposing no plugin-controlled markup or diagnostic secrets.
- [x] Run server/CLI integration tests, formatting, and strict Clippy.
- [x] Commit as `feat(api): expose workspace plugin controls`.

## Task 10: Plugins Control Surface

**Files:** `apps/web/src/lib/api.ts`, `apps/web/src/lib/api.test.ts`, `apps/web/src/lib/components/{PluginReview,PluginAuthority,PluginSettings,PluginFailures}.svelte`, component tests, `apps/web/src/routes/{+layout,plugins/+page}.svelte`, `apps/web/tests/control-surface.spec.ts`, `apps/web/src/app.css`

- [x] Add failing API/component tests for staged-package review, full hashes, requested-versus-granted authority, immutable versions, schema-backed scoped settings, optimistic conflicts, failure history, and action-specific approval previews.
- [x] Add failing browser tests for install, enable, grant, settings, and quarantine workflows at desktop and mobile viewports, including long IDs/hashes and loading/empty/error/conflict states.
- [x] Confirm the frontend tests fail before implementation.
- [x] Add a compact Plugins navigation item and work-focused page using familiar icons, native controls, bounded tables/lists, and no plugin-supplied HTML/CSS/JS/images.
- [x] Route sensitive commands to the existing Approvals view and display exact fingerprint-changing inputs.
- [x] Run Svelte diagnostics, unit tests, production build, Playwright, and desktop/mobile screenshot inspection.
- [x] Commit as `feat(web): add secure plugin controls`.

## Task 11: Milestone 3 Security Verification

**Files:** security tests under owning crates, `README.md`, `docs/{ARCHITECTURE,DATA_MODEL,PLUGIN_SYSTEM,REPOSITORY,ROADMAP,RUNTIME_EXECUTION,SECURITY}.md`, this plan

- [x] Add a full stage-to-review-to-approval-to-install-to-grant-to-enable-to-invoke test for both hosts, including approved child effects and exact audit provenance.
- [x] Add adversarial substitution, traversal/link, malformed schema/protocol, capability escalation, secret exfiltration, ambient-access, resource exhaustion, crash, restart recovery, revocation, side-by-side upgrade, and quarantine scenarios.
- [x] Run `cargo fmt --all -- --check`.
- [x] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [x] Run `CARGO_INCREMENTAL=0 cargo test --workspace`.
- [x] Run SDK documentation and both host conformance fixtures.
- [ ] Run Linux plugin-sandbox tests in a privileged Linux container or equivalent CI-compatible Linux target; failure to run or pass this mandatory gate blocks milestone completion.
- [x] Run `pnpm check:web`, frontend unit tests, production builds, and Playwright desktop/mobile tests.
- [x] Inspect rendered plugin and approval UI at desktop and mobile sizes and validate Tauri configuration.
- [x] Update Roadmap Milestone 3 only for behavior proven by the suite and reconcile all extension/security documentation.
- [x] Run `git diff --check` before the final commit.
- [x] Commit as `test: verify extension runtime boundaries`.
- [x] Push `feat/milestone-3-extension-runtime`.
- [x] Confirm the worktree is clean and verify the remote ref matches local HEAD after push.

Verification note: `CARGO_INCREMENTAL=0 cargo test --workspace` covered SDK doc tests, host conformance tests, macOS plugin-sandbox execution tests, Linux sandbox construction/unit tests, route tests, Tauri security configuration, and the full runtime security suite. The mandatory privileged Linux plugin-sandbox execution gate was not run in this macOS environment because Docker is installed but the daemon socket is unavailable.

Linux gate attempt: Docker Desktop was started on this macOS host and reported a Linux/aarch64 daemon. A privileged `rust:slim` container installed `bubblewrap` and began compiling the Linux integration test graph, but Docker Desktop failed before tests could execute with containerd content and metadata `input/output error` failures while the system volume had only about 202 MiB free. After clearing cache-only data to bring the system volume to about 4.9 GiB free and restarting Docker Desktop, the Docker API still returned HTTP 500 for `version`, `ps`, and `images`. The remaining gate requires a healthy Docker Desktop reset or an equivalent CI Linux target; do not treat the macOS attempt as passing the Linux plugin-sandbox execution requirement.

Lean Linux gate command: `lumen-integrations` now supports a sandbox-only build with `--no-default-features`, leaving model-client, native-secret, and WASM-host dependencies out of the privileged Linux check. On a healthy Linux target, run `scripts/verify-linux-plugin-sandbox.sh`; the same command is wired into `.github/workflows/milestone3-linux-sandbox.yml`.
