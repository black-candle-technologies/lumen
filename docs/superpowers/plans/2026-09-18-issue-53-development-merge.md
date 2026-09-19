# Issue 53 Development-Merge Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and verify the finite lifecycle, authority, immutable-publication, and model-finality merge gates from issue #53.

**Architecture:** Preserve existing accepted repairs and add only shared durable state needed by real runtime call paths. Each gate is landed with its failing regression, focused implementation, and bounded verification before moving to dependent contracts.

**Tech Stack:** Rust, Tokio, SQLx/SQLite, Axum, OpenAI-compatible SSE.

**Spec:** GitHub issue #53 body and comments 5735717024, 5735733419, 5735749570, 5735765518, and 5735797896.

## Global Constraints

- Continue `qa-m5-second-pass-repairs` from `d976d8e` or newer; only forward migrations.
- Never widen authority, replay uncertain effects, alter applied migrations, or merge the branch.
- Record exact commands/results; distinguish PASS, FAIL, BLOCKED, and NOT RUN.

### Task 1: Scheduler start and retained regressions

**Files:** `crates/lumen-cli/src/runtime.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `crates/lumen-db/tests/database.rs`

- [ ] Add RED scheduler-to-advance, deterministic writer-contention, and authenticated rejected-write regressions.
- [ ] Add an owned scheduled-start disposition; retain generic run CAS restrictions.
- [ ] Verify targeted CLI/DB regressions and commit.

### Task 2: Durable lifecycle and bounded ownership

**Files:** `crates/lumen-db/migrations`, `crates/lumen-db/src/repositories.rs`, `crates/lumen-cli/src/runtime.rs`, `crates/lumen-server/src/state.rs`

- [ ] Add RED durable terminal/reconciliation and admission/shutdown regressions.
- [ ] Implement lifecycle records, terminal audit outbox, owned admission, bounded drain, and restart reconciliation.
- [ ] Verify lifecycle suites and commit.

### Task 3: Current authority and pins

**Files:** `crates/lumen-db/src/automation.rs`, `crates/lumen-db/src/repositories.rs`, `crates/lumen-cli/src/runtime.rs`, `crates/lumen-integrations/src/process.rs`

- [ ] Add RED reservation-fence, renewal, and required-pin regressions.
- [ ] Implement transaction-bound authority, renewal linkage, and mandatory pins.
- [ ] Verify DB/CLI/integration paths and commit.

### Task 4: Immutable publication

**Files:** `crates/lumen-db/migrations`, `crates/lumen-db/src/automation.rs`, `crates/lumen-cli/src/runtime.rs`

- [ ] Add RED intent, owned-stage, no-clobber, and restart-recovery regressions.
- [ ] Implement publication intent/finalization/recovery on the reserved execution path.
- [ ] Verify publication suites and commit.

### Task 5: Model response finality and integration evidence

**Files:** `crates/lumen-integrations/src/openai_compatible.rs`, its tests, runtime fixtures, QA report

- [ ] Add RED protocol-finality tests and real HTTP no-partial-action regression.
- [ ] Implement strict stream/nonstream validation and correct positive fixtures.
- [ ] Run the final supported combined-tree matrix and post the issue #53 report.
