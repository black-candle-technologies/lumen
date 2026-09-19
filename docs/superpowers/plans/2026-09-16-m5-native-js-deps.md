# M5 Native JavaScript Dependencies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give Windows x64 and WSL Linux x64/glibc separate frozen pnpm dependency trees, with an actionable native-binding preflight.

**Architecture:** Declare the tested Node/pnpm versions in root `engines` without changing the frozen lockfile. Use a nested, ignored detached QA worktree for WSL so Windows and Linux never rewrite the same `node_modules`. A Node-stdlib preflight resolves and loads Rolldown and Tauri's expected native packages from their real parent package contexts; it reports the frozen-install repair if either is missing or unloadable.

**Tech Stack:** Node 24.18–24.x, Corepack, pnpm 12.4.1/12.4.2, Node built-in test runner, Vite 8, Tauri CLI 2.

**Spec:** GitHub issue #25, `docs/qa/M5_QA_2026-09-12.md` F18/T56–T58, and the user's continuous M5 QA instruction in the Codex attachment.

## Global Constraints

- Work only in `C:\Users\laneb\lumen-m5-windows`, branch `qa-m5-25-js-deps`, stacked on `qa-m5-24-cargo-cache`.
- Do not change or delete `pnpm-lock.yaml`, install global Node/pnpm, edit the original checkout, or make Vite listen on a non-loopback interface.
- Preserve frozen-lockfile installs; clean only this checkout's generated dependency directories if repair requires it.
- Complete Windows/WSL checks and the requested full-stack checkpoint before final push and normal non-draft PR; leave issue #25 open.

---

### Task 1: Native dependency preflight

**Files:** Create `scripts/qa/check_native_deps.mjs`, `scripts/qa/check_native_deps.test.mjs`; modify root `package.json`.

**Interfaces:** The command `corepack pnpm check:native` exits zero after loading this host's Rolldown and Tauri native packages; otherwise it names the missing package and says to run `corepack pnpm install --frozen-lockfile`. Its platform scope is Windows x64 and Linux x64/glibc.

- [ ] Write a Node built-in test that runs the preflight in a disposable miniature workspace with Vite/Rolldown and Tauri parent packages but only the *other* platform's native packages. Assert nonzero status and the current platform's exact expected package name. Add the expected native packages in the fixture and assert zero status.
- [ ] Run `node --test scripts/qa/check_native_deps.test.mjs`; confirm the wrong-platform fixture fails because the preflight does not yet exist.
- [ ] Implement the preflight with `createRequire`/`require.resolve` and actual `require` of both native modules, plus a root `check:native` script; keep normal output concise and failure advice specific to the workspace and `corepack pnpm install --frozen-lockfile`.
- [ ] Run the same test to green; run preflight under Windows and WSL before reinstall to confirm Windows passes and WSL reports missing Linux Rolldown and Tauri packages.

### Task 2: Frozen cross-platform install and operator procedure

**Files:** Modify `package.json`, `docs/qa/README.md`; create `docs/qa/M5_JS_DEPENDENCIES_GUIDE.md`.

**Interfaces:** Root `engines` declares Node >=24.18.0 <25 and pnpm 12.4.1/12.4.2. The guide gives host-version/preflight/frozen-install/dev/build commands and scoped repair for two distinct checkouts.

- [ ] Keep the tested engine ranges, restore the Windows tree using only generated `node_modules` in this isolated checkout, and run `corepack pnpm install --frozen-lockfile` on Windows. After an implementation commit, create a detached QA worktree under ignored `.worktrees/`, then run the same frozen install there from WSL using Node 24.19.0; compare lockfile SHA-256 before and after.
- [ ] Run `corepack pnpm check:native`, web check/test/build, and a loopback-only dev readiness probe from Windows and WSL. Check Tauri CLI version where supported; do not call a web build a desktop build.
- [ ] Document the observed cold-start versus native-failure difference, reproducible repair, generated-directory deletion scope, and limitations. Link the guide from `docs/qa/README.md`.
- [ ] Run the full-stack checkpoint: Windows Rust workspace tests and web checks/test/build/Playwright; WSL CLI/DB/integrations automation. Record each exact pass or environment block honestly.
- [ ] Review diff and native-binding test, commit, push, open a normal stacked PR, and post the issue evidence comment without closing the issue.
