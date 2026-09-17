# M5 Windows/WSL JavaScript dependencies

Use Node 24 (`>=24.18.0 <25`) and Corepack pnpm 12.4.1 or 12.4.2, as declared in the root `package.json` engines. The committed `pnpm-lock.yaml` is authoritative. Install from each checkout's root with `corepack pnpm install --frozen-lockfile`; do not add a platform binding as a direct dependency or delete the lockfile.

Windows and WSL need **separate checkouts**, not just both optional packages in one `node_modules`. In the September 16 QA attempt, pnpm's `supportedArchitectures` fetched both native bindings, but a subsequent WSL install rewrote generated links so Windows pnpm failed to read `apps/web/node_modules/@sveltejs/.ignored_adapter-static/package.json` (OS error 1920). That setting was removed. The original September 12 Vite failure named the missing Linux Rolldown binding; the shared tree was consistent with the failure but not proven to be its only possible cause.

From Windows PowerShell in the committed, isolated Lumen worktree:

```powershell
node --version
corepack pnpm --version
corepack pnpm install --frozen-lockfile
corepack pnpm check:native
corepack pnpm --dir apps/web check
corepack pnpm --dir apps/web build
git worktree add --detach .worktrees/m5-wsl HEAD
```

`.worktrees/` is ignored. Create the detached WSL QA checkout **after committing** the source revision to be tested. Do not run Windows pnpm in that checkout. From WSL, change to the mounted path of `.worktrees/m5-wsl`, then:

```bash
node --version
corepack pnpm --version
corepack pnpm install --frozen-lockfile
corepack pnpm check:native
corepack pnpm --dir apps/web check
corepack pnpm --dir apps/web build
```

`check:native` loads the host's Rolldown/Vite and Tauri CLI optional bindings and names a missing or unloadable package. Windows x64 expects `@rolldown/binding-win32-x64-msvc` and `@tauri-apps/cli-win32-x64-msvc`; WSL Linux x64/glibc expects their `linux-x64-gnu` counterparts. It does not claim the native Tauri desktop app builds; that requires separate platform SDK/GTK prerequisites. A clean install with only this host's optional packages is expected in each checkout. Run `corepack pnpm --dir apps/desktop tauri --version` for a CLI smoke test.

If preflight fails, first confirm the shell is in its own platform's checkout. In a contaminated **QA checkout only**, move aside that checkout's generated `node_modules`, `apps/web/node_modules`, and `apps/desktop/node_modules` into a named backup under ignored `.worktrees/`; then repeat its host's frozen install and preflight. Never remove tracked files, another checkout's dependency tree, or a lockfile for this repair. A normal first Vite launch can show dependency re-optimization and take longer before `ready`; a thrown `Cannot find native binding` is a failure, not slow startup. `corepack pnpm --dir apps/web dev` uses Vite's default loopback host; do not add `--host 0.0.0.0` for local QA.

## September 16 verification

At parent `a5352cbcfe85ce56ac9b4be89f4ec3651c2fb143`, Windows Node 24.19.0 and pnpm 12.4.2 initially loaded both Windows bindings. WSL Node 24.19.0 and pnpm 12.4.1 in that same tree failed `vite build` with missing `@rolldown/binding-linux-x64-gnu`, and `check:native` named both missing Linux packages. After separating the dependency trees, the Windows frozen install resolved 151 packages without changing the lockfile (SHA-256 `2f8155606aad6bafa323dc120f6326e3fae7c9ac28c7acbfaaf8e1cf9cbb8679`). Windows preflight, Svelte check (0 errors, 0 warnings), Vitest (21/21), Vite build, Tauri CLI 2.11.2, and default Vite dev (`http://localhost:5173/`, HTTP 200, `::1` listener only) passed. The dev process was stopped and port 5173 closed. WSL's separate-checkout results are recorded in the issue #25 PR; do not infer them from this Windows result.
