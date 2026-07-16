# Durable Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Roadmap Milestone 5 with durable scheduled jobs, owned service identities, reviewed versioned skills, workflow capture, and audited fail-closed automation.

**Architecture:** Treat jobs and skills as runtime inputs, not authority sources. Persist automation state in SQLite; compose job-created work through the existing run lifecycle; load skills only after digest validation and review. Keep the first scheduler local and lease-based, with no distributed worker protocol.

**Tech Stack:** Rust 2024, Tokio, Axum, SQLite/SQLx, SvelteKit, Vitest, Playwright, Tauri 2

---

## File Structure

```text
crates/lumen-core/src/
  automation.rs             # schedule specs, job IDs, service identity helpers, skill IDs
  capability.rs             # service identity and skill admin capability names if needed
  run.rs                    # job attribution in run context
crates/lumen-db/migrations/
  0005_durable_automation.sql
crates/lumen-db/src/
  automation.rs             # transactional job, lease, service identity, skill repositories
crates/lumen-cli/src/
  runtime.rs                # scheduler composition, job-created runs, skill loading
  lib.rs                    # operator commands for jobs and skills if CLI coverage is needed
crates/lumen-server/src/
  routes/mod.rs             # authenticated job, service identity, skill, capture routes
  state.rs                  # runtime service contracts and review DTOs
apps/web/src/
  lib/api.ts                # job, service identity, skill, capture API client methods
  routes/automation/+page.svelte
  routes/skills/+page.svelte
  tests/control-surface.spec.ts
docs/
  DATA_MODEL.md
  RUNTIME_EXECUTION.md
  SECURITY.md
  ROADMAP.md
  MILESTONE_5_DESIGN.md
  MILESTONE_5_IMPLEMENTATION_PLAN.md
```

## Task 1: Core Automation Types

**Files:** `crates/lumen-core/src/{lib,automation,identity}.rs`, `crates/lumen-core/tests/automation.rs`, `docs/{RUNTIME_EXECUTION,SECURITY}.md`

- [x] Add failing tests for `JobId`, `JobRevision`, `SkillId`, `SkillVersion`, `OccurrenceKey`, and service-principal parsing.
- [x] Add failing tests proving service principals do not compare equal to local users and cannot be constructed from empty or control-character labels.
- [x] Add failing tests for `ScheduleSpec::Once` and `ScheduleSpec::Interval`, including next-due calculation, disabled jobs, zero interval rejection, and bounded timestamp parsing.
- [x] Add failing tests proving occurrence keys are deterministic over job ID, revision, and scheduled timestamp.
- [x] Confirm focused tests fail before implementation: `cargo test -p lumen-core --test automation`.
- [x] Implement the automation types in `crates/lumen-core/src/automation.rs` and export them from `lib.rs`.
- [x] Extend `RunContext` or its metadata with optional job occurrence attribution without changing interactive run behavior.
- [x] Run `cargo test -p lumen-core --test automation` and `cargo test -p lumen-core --test run_orchestrator`.
- [x] Commit as `feat(core): define durable automation types`.

## Task 2: SQL Automation State

**Files:** `crates/lumen-db/migrations/0005_durable_automation.sql`, `crates/lumen-db/src/{lib,automation}.rs`, `crates/lumen-db/tests/{database,automation}.rs`, `docs/DATA_MODEL.md`

- [ ] Add failing migration tests for `service_identities`, `scheduled_jobs`, `scheduled_job_revisions`, `scheduled_job_runs`, `scheduled_job_leases`, `agent_skills`, `skill_versions`, `skill_workspace_state`, and `workflow_capture_drafts`.
- [ ] Add failing repository tests proving service identities are workspace-scoped, owner-linked, enableable, disableable, explicitly grant-scoped, and never inherit owner grants.
- [ ] Add failing repository tests proving job revisions are append-only, next-due updates are transactional, and stale revisions cannot overwrite newer revisions.
- [ ] Add failing lease tests proving one occurrence can be claimed once, expired leases can be recovered, active leases cannot be stolen, and duplicate occurrence keys do not create duplicate runs.
- [ ] Add failing skill tests proving version metadata is immutable, source digests are required, disabled skill versions are not loadable, and capture drafts are separate from published skills.
- [ ] Confirm focused tests fail before implementation: `cargo test -p lumen-db --test automation`.
- [ ] Implement the migration and typed repositories.
- [ ] Update `DATA_MODEL.md` with service identity, job, lease, skill, and capture invariants.
- [ ] Run `cargo test -p lumen-db --test database` and `cargo test -p lumen-db --test automation`.
- [ ] Commit as `feat(db): persist durable automation state`.

## Task 3: Scheduler Runtime

**Files:** `crates/lumen-cli/src/runtime.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `crates/lumen-core/src/run.rs`

- [ ] Add failing runtime tests proving a due one-shot job creates exactly one agent run attributed to the configured service identity.
- [ ] Add failing runtime tests proving interval jobs advance `next_due_at` only after a job run is reserved.
- [ ] Add failing runtime tests proving disabled jobs and disabled service identities do not create runs.
- [ ] Add failing crash-recovery tests proving a claimed occurrence without a run is retried once and a claimed occurrence with a run is reconciled without duplication.
- [ ] Add failing tests proving job-created runs use configured data class, budget, and workspace policy.
- [ ] Add failing tests proving scheduler dispatch fails closed when service identity policy or capability grants cannot be loaded.
- [ ] Confirm focused tests fail before implementation: `cargo test -p lumen-cli runtime::security_tests::scheduled`.
- [ ] Implement a local scheduler loop with bounded polling, SQLite lease claiming, cancellation on service shutdown, and no distributed worker assumptions.
- [ ] Create job-originated runs through the existing `LocalRuntimeService` run path rather than a scheduler-specific executor path.
- [ ] Record job ID, revision, occurrence key, service principal, and owner in audit payloads.
- [ ] Run focused runtime security tests and `cargo test -p lumen-cli`.
- [ ] Commit as `feat(runtime): execute leased scheduled jobs`.

## Task 4: Job Policy, Approval, And Idempotency

**Files:** `crates/lumen-core/src/{approval,run}.rs`, `crates/lumen-db/src/automation.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`

- [ ] Add failing tests proving schedule creation, job enablement, and authority expansion require approval.
- [ ] Add failing tests proving job edits create a new revision and pending occurrences keep the revision they were created with.
- [ ] Add failing tests proving idempotent job actions may retry after unknown outcomes while non-idempotent unknown outcomes require operator reconciliation.
- [ ] Add failing tests proving approval replay cannot create duplicate job occurrences or duplicate runs.
- [ ] Confirm focused tests fail before implementation.
- [ ] Implement idempotency policy fields and dispatch-time checks.
- [ ] Connect job admin actions to the existing action, capability, approval, reservation, execution, and audit lifecycle.
- [ ] Run focused runtime and core approval tests.
- [ ] Commit as `feat(automation): bind jobs to approval and idempotency`.

## Task 5: Reviewed Skills

**Files:** `crates/lumen-core/src/automation.rs`, `crates/lumen-db/src/automation.rs`, `crates/lumen-cli/src/runtime.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `docs/RUNTIME_EXECUTION.md`

- [ ] Add failing tests proving unreviewed skill drafts are never loaded into model context.
- [ ] Add failing tests proving reviewed skill versions load only when the stored digest matches the source content.
- [ ] Add failing tests proving skills cannot add capabilities, approve actions, change policy, or bypass plugin grants.
- [ ] Add failing tests proving skill retrieval is workspace-scoped and records loaded skill IDs, versions, and digests in audit metadata.
- [ ] Confirm focused tests fail before implementation.
- [ ] Implement skill version storage, digest validation, workspace enablement, and bounded context rendering.
- [ ] Include reviewed skill content in model input as untrusted procedure context with explicit source metadata.
- [ ] Run focused runtime security tests and `cargo test -p lumen-db --test automation`.
- [ ] Commit as `feat(skills): load reviewed versioned skills`.

## Task 6: Workflow Capture

**Files:** `crates/lumen-cli/src/runtime.rs`, `crates/lumen-db/src/automation.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `docs/RUNTIME_EXECUTION.md`

- [ ] Add failing tests proving capture is rejected when the source run is not terminal successful or the audit chain does not verify.
- [ ] Add failing tests proving captured drafts redact secret values, approval tokens, raw diagnostics, and sensitive payload fragments.
- [ ] Add failing tests proving captured drafts include source run IDs, action kinds, artifact digests, required variables, expected outputs, and failure notes.
- [ ] Add failing tests proving publishing a capture draft creates a reviewed skill version only after explicit approval.
- [ ] Confirm focused tests fail before implementation.
- [ ] Implement capture draft generation from persisted run/action/audit records.
- [ ] Implement publish flow through the existing action lifecycle.
- [ ] Run focused capture and skill tests.
- [ ] Commit as `feat(skills): capture audited workflows as drafts`.

## Task 7: Automation APIs And Web Controls

**Files:** `crates/lumen-server/src/{routes/mod,state}.rs`, `crates/lumen-server/tests/routes.rs`, `apps/web/src/lib/api.ts`, `apps/web/src/lib/api.test.ts`, `apps/web/src/routes/{automation,skills}/+page.svelte`, `apps/web/tests/control-surface.spec.ts`

- [ ] Add failing server route tests for listing, creating, reviewing, enabling, disabling, and updating service identities, jobs, skills, and capture drafts.
- [ ] Add failing server route tests for authentication, workspace scoping, unknown-field rejection, body limits, secret redaction, conflict states, and disabled-service behavior.
- [ ] Add failing web API tests for job and skill endpoints.
- [ ] Add failing Playwright tests proving operators can inspect job state, pause jobs, review skill versions, publish capture drafts, and see audit provenance without secret values or layout overflow.
- [ ] Confirm frontend tests fail before implementation.
- [ ] Implement server route DTOs and `RuntimeService` methods following the plugin and egress route patterns.
- [ ] Implement compact Automation and Skills pages with dense tables, review dialogs, status badges, and icon controls.
- [ ] Run `pnpm --dir apps/web check`, `pnpm --dir apps/web test`, `pnpm --dir apps/web build`, and `pnpm --dir apps/web test:e2e`.
- [ ] Commit as `feat(web): add durable automation controls`.

## Task 8: Milestone 5 Verification

**Files:** security tests under owning crates, `README.md`, `docs/{ARCHITECTURE,DATA_MODEL,MODEL_ROUTING,PLUGIN_SYSTEM,ROADMAP,RUNTIME_EXECUTION,SECURITY}.md`, this plan

- [ ] Add adversarial tests for duplicate due occurrences, lease stealing, crash recovery, disabled service identities, stale job revisions, policy revocation during execution, approval replay, skill digest tampering, unreviewed skill loading, prompt-injected skill edits, secret leakage during capture, unknown job owners, and audit failure.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Run `CARGO_INCREMENTAL=0 cargo test --workspace`.
- [ ] Run frontend checks, unit tests, production build, and Playwright.
- [ ] Update Roadmap Milestone 5 only for behavior proven by the suite.
- [ ] Run `git diff --check`.
- [ ] Commit and push the completed milestone branch.
