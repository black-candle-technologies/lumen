# M5 second-pass shared contracts implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair the shared terminal-transition and authorization-clock contracts that every later second-pass lifecycle packet depends on.

**Architecture:** Repository transitions become compare-and-set operations with named expected states, while runtime terminalization derives certainty from `RunOutcome` and uses one typed terminal description. Approval dispatch samples the injected wall clock only after the protected registry and SQLite transaction boundaries. Later #9/#10/#13/#16/#20 work will consume these contracts rather than invent parallel state strings or stale timestamps.

**Tech Stack:** Rust, Tokio, SQLx/SQLite, Lumen core runtime, existing security and repository tests.

**Spec:** GitHub issue #8 master packet comment `5733228096`; #11 packet `5733087572`; #12 packet `5733096313`.

## Global Constraints

- Base all changes on `000a709836216187bc202f586eaaa07703bcc5bc` in `qa-m5-second-pass-repairs`.
- Preserve #51's register-before-predicate approval-parking Notify loop and all existing security tests.
- Do not widen capabilities, auto-grant/rebind approvals, retry uncertain effects, or treat unknown effects as ordinary failures.
- Use wall time only for persisted expiry/facts and monotonic time for run budgets/deadlines.
- Keep durable state transitions and event publication distinct; state/persistence failure remains reconciliation-required.

---

### Task 1: Compare-and-set run lifecycle and rejected action terminalization

**Files:**
- Modify: `crates/lumen-db/src/repositories.rs`
- Modify: `crates/lumen-cli/src/runtime.rs`
- Test: `crates/lumen-db/tests/database.rs`
- Test: `crates/lumen-cli/src/runtime/security_tests.rs`

**Interfaces:**
- Produces a repository transition API that accepts a run ID, an explicit allowed source-state set, target state, and optional completion timestamp.
- Produces one transactional rejection primitive that validates an exact pending approval/action/workspace/fingerprint and records a `denied` action before terminalizing the corresponding run/occurrence.

- [ ] **Step 1: Write failing CAS and rejection regressions**

Add a two-connection test that terminalizes a `running` run and then attempts a stale `running` transition; assert `ExecutionStateConflict`, terminal state and completion timestamp remain unchanged. Add an approval-rejection test that creates a normalized write action and pending approval, rejects it, and asserts rejected approval, `denied` action, zero execution attempts and terminal failed run.

- [ ] **Step 2: Run the new tests to verify RED**

Run: `cargo test -p lumen-db --test database stale_run_start_cannot_resurrect_terminal_row --locked` and `cargo test -p lumen-db --test database rejected_approval_terminalizes_normalized_action --locked`.

Expected: the first test exposes the unconditional `update_run_state` write; the second exposes the missing rejected-action state transition.

- [ ] **Step 3: Implement the minimal conditional transitions**

Replace free-form `update_run_state` callers with a constrained repository method that uses `WHERE id = ? AND state IN (...)`; reject zero rows except identical terminal replay. Add the rejection transaction: validate approval/action/workspace/fingerprint/pending state, set approval rejected and action denied only when unreserved, then return the run identity for common terminalization. Route both first-entry and resumed rejection through it; do not create an execution attempt.

- [ ] **Step 4: Verify GREEN and preserve terminal audit semantics**

Run the two named tests, then `cargo test -p lumen-db --test database --locked` and the affected runtime security rejection tests. Assert the action is never returned to normalized/running and a terminal row cannot be changed back to running.

- [ ] **Step 5: Commit**

Commit: `fix(runtime): make run transitions and rejection terminalization atomic`.

### Task 2: Typed terminal outcome and durable primary diagnostics

**Files:**
- Modify: `crates/lumen-cli/src/runtime.rs`
- Modify: `crates/lumen-db/src/repositories.rs`
- Test: `crates/lumen-cli/src/runtime/security_tests.rs`
- Test: `crates/lumen-db/tests/automation.rs`

**Interfaces:**
- Produces a validated terminal result with run state, optional scheduled state, event kind, certainty, primary bounded diagnostic and optional reconciliation failure.
- Consumes the CAS/rejection contract from Task 1.

- [ ] **Step 1: Write failing unknown/diagnostic regressions**

Add interactive and scheduled `ExecutionUnknown` cases. Both must persist unknown certainty rather than make interactive unknown an ordinary failure. Add an event-buffer eviction/restart-style read assertion that the bounded primary provider/executor diagnostic remains available after transient SSE delivery is absent.

- [ ] **Step 2: Run the new tests to verify RED**

Run the exact new runtime security tests with `cargo test -p lumen-cli --lib runtime::security_tests::<name> --locked -- --exact`.

Expected: interactive unknown is classified as failure and primary diagnostic is not discoverable after transient output is gone.

- [ ] **Step 3: Implement one typed terminal description**

Replace `terminalize_stored_run`'s independent state/event arguments with one constructor constrained by `RunOutcome`. Persist the bounded primary diagnostic with run identity through existing durable repository state/reconciliation facilities; secondary audit/event persistence failures remain separate and never replace the primary cause. Publish terminal success only after required durable facts succeed.

- [ ] **Step 4: Verify GREEN**

Run core orchestrator, DB automation/repository and affected CLI security tests. Confirm repeated identical terminalization is idempotent and conflicting terminal outcomes are rejected.

- [ ] **Step 5: Commit**

Commit: `fix(runtime): retain truthful terminal outcome diagnostics`.

### Task 3: Fresh wall-clock authorization at dispatch reservation

**Files:**
- Modify: `crates/lumen-cli/src/runtime.rs`
- Modify: `crates/lumen-db/src/repositories.rs`
- Test: `crates/lumen-db/tests/database.rs`
- Test: `crates/lumen-cli/src/runtime/security_tests.rs`

**Interfaces:**
- Produces `reserve_execution_with_clock`, which enters `BEGIN IMMEDIATE` before calling a synchronous injected wall-clock supplier and conditionally consumes the exact approval using that sample.
- Consumes `Clock` from `lumen-core` without changing monotonic `RunBudget` behavior.

- [ ] **Step 1: Write failing lock-contention expiry tests**

Create a fake wall clock and file-backed SQLite fixture. Hold the approval registry lock in one test and a separate `BEGIN IMMEDIATE` writer in another; start reservation while valid, advance clock beyond expiry, release the boundary, and assert typed expired/conflict, zero attempts/effects and no consumed approval. Cover exact expiry and just-before expiry.

- [ ] **Step 2: Run the new tests to verify RED**

Run the named DB and runtime tests with `--locked`; the old path uses its pre-wait timestamp and consumes the approval.

- [ ] **Step 3: Implement clock-at-boundary reservation**

Thread an injected `Clock` into the approval registry. Inside the registry, sample only after locking the record. Inside the repository, start `BEGIN IMMEDIATE`, then call the synchronous supplier immediately before the conditional update and attempt reservation. Update in-memory state only after the transaction commits; map expiry/consumed/stale outcomes distinctly.

- [ ] **Step 4: Verify GREEN**

Run `cargo test -p lumen-core --locked`, affected DB tests, CLI approval security tests, `cargo fmt --all -- --check`, and strict affected Clippy. Retain backward-wall-clock audit tests and monotonic budget tests.

- [ ] **Step 5: Commit**

Commit: `fix(approvals): sample expiry clock at reservation boundary`.

### Task 4: Report the shared contract evidence

**Files:**
- Modify: GitHub issues #11 and #12 comments

- [ ] **Step 1: Record exact revision and verification**

Comment on #11 and #12 with branch, commit(s), named tests, precise PASS/FAIL/BLOCKED distinction and remaining dependent validation. Do not close either issue unless every packet closure condition is independently satisfied.

