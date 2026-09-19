# M5 QA Launcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make M5 manual QA setup, service lifecycle and evidence preservation repeatable without cross-shell state or unsafe fixture cleanup.

**Architecture:** A PowerShell WSL entry and a Bash entry feed one stdlib Python core. A selected, marker-owned WSL fixture stores nonsecret identity; credentials are separate, and evidence is outside the deletable fixture.

**Tech Stack:** PowerShell, Bash, Python 3.11+ standard library (`tomllib`, `sqlite3`, `unittest`), WSL Ubuntu, existing Lumen CLI and Cargo.

**Spec:** [M5 disposable QA launcher design](../specs/2026-09-16-m5-qa-launcher-design.md)

## Global Constraints

- Exact branch `qa-m5-21-qa-launcher`, parent `qa-m5-26-wsl-memory`; no base/ui or Riley checkout edits.
- No auto-grant, weakened policy, raw token in evidence, full WSL shutdown, or cleanup outside the selected fixture.
- Use stable WSL Cargo target; SQLite backup API for WAL-safe snapshots; bounded network/process waits.
- Preserve source SHA, environment, expected/actual results and honest unrun cases.

---

### Task 1: Fixture identity, selection and credentials

**Files:** Create `scripts/qa/m5_launcher.py`, `scripts/qa/test_m5_launcher.py`.

**Interfaces:** `init(name, source_sha, dirty, model, endpoint, port)` creates a manifest and mode-0600 token; `load_selected()` validates marker, paths and IDs; `select(name)` persists the selected fixture.

- [ ] Write tests that init produces one stable UUID/token across repeated selection, rejects invalid/empty names, symlink/foreign fixture roots and occupied ports, and never emits the token to stdout/manifest/evidence.
- [ ] Run `python3 -m unittest discover -s scripts/qa -p test_m5_launcher.py -v`; confirm the expected missing implementation failure.
- [ ] Implement only the validated fixed-root fixture and selection flow, then rerun the tests to green.

### Task 2: Build and owned service lifecycle

**Files:** Modify `scripts/qa/m5_launcher.py`, `scripts/qa/test_m5_launcher.py`.

**Interfaces:** `build` records a binary hash in the manifest, `start` owns an exact PID/start-time and polls authenticated readiness, `status` reports it, and `stop` signals only the verified process.

- [ ] Add tests with a tiny owned HTTP/process fixture for source/hash reuse, bounded readiness, 401/403/HTTP failure, changed PID identity, normal SIGINT exit and token redaction.
- [ ] Run the focused suite and observe those assertions fail for absent behavior.
- [ ] Implement build/start/status/stop with the existing stable Cargo target, the CLI readiness route, Linux `/proc` identity and bounded deadlines; rerun to green.

### Task 3: Evidence, polling and SQLite recovery

**Files:** Modify `scripts/qa/m5_launcher.py`, `scripts/qa/test_m5_launcher.py`.

**Interfaces:** `snapshot` and `restore` operate only on the selected fixture; `poll` records bounded state transitions; `record` stores redacted machine-readable results; `cleanup` removes only fixture data.

- [ ] Add tests using a WAL-active SQLite fixture and real files: snapshot contains committed WAL rows, restore recovers them, missing DB never creates one, wrong snapshot ID and symlink cleanup fail, evidence survives cleanup, malformed ID/HTTP error/deadline do not report success.
- [ ] Run focused tests and confirm failure for missing behavior.
- [ ] Implement the smallest guarded backup/restore, poll, evidence and cleanup paths; rerun focused tests to green.

### Task 4: Platform entries, operator guide and live check

**Files:** Create `scripts/qa/m5_launcher.ps1`, `scripts/qa/m5_launcher.sh`, `docs/qa/M5_QA_LAUNCHER_GUIDE.md`; modify `docs/qa/README.md`.

**Interfaces:** PowerShell explicitly invokes a chosen WSL distro and passes Windows Git metadata; Bash requires WSL and invokes Python core. The guide maps shell roles and exact commands, including manual approval and browser connection.

- [ ] Add wrapper tests for wrong platform, explicit distro, argument forwarding and Bash entry; run them red, then implement wrappers and rerun.
- [ ] Document fresh setup, new-shell resume, build/start/status/stop, healthy snapshot before tamper, restore/cleanup, evidence paths and unrun/live limitations.
- [ ] Run `python3 -m unittest discover -s scripts/qa -p test_m5_launcher.py -v`, PowerShell syntax/invocation checks and a real WSL owned fixture; run `git diff --check` and review the complete scoped diff.
