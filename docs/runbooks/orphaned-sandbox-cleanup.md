# Runbook: orphaned sandbox cleanup

## Purpose

Find and reclaim sandbox runs, quarantine directories, and worker state left
behind by crashes, kills, or failed shutdowns — without touching live work.

## Preconditions

- `lumen` CLI with the runtime's `lumen.toml`.
- The runtime (`lumen serve`) is **stopped** before destructive cleanup, or
  you have confirmed the target runs are not owned by a live scheduler.

## Procedure

1. **List runs needing reconciliation.** These are runs the lifecycle
   tracker flagged as abandoned or inconsistent:
   ```
   curl -s $LUMEN_URL/api/v1/workspaces/<ws>/runs/reconciliation \
     -H "Authorization: Bearer $LUMEN_TOKEN"
   ```
   Each entry carries a diagnostic (e.g. `owner_dead`, `terminal_audit_pending`).
   Cross-check with `lumen run show <run-id>`: only act on runs whose phase
   is terminal (`completed`, `failed`, `cancelled`) or explicitly
   reconciliation-required.

2. **Reconcile abandoned owned runs.** On the next `lumen serve` start, the
   control plane's `recover()` pass reconciles abandoned owned runs
   automatically (marks unknown failures, records integrity reports). For a
   manual pass without starting the full runtime, there is no destructive
   delete: orphaned runs are terminalized in place so the audit trail is
   preserved. Never `DELETE` rows from `runs` or `run_lifecycle` — the audit
   chain references them.

3. **Clean quarantine staging debris.** Failed `plugin submit` operations can
   leave `.staging-<uuid>` temp directories under
   `<data>/plugins/quarantine/`. These are safe to remove **only** if no
   `lumen plugin submit` is running and no staged package references them:
   ```
   # list staged packages and their quarantine paths first
   sqlite3 <db> "SELECT stage_id, quarantine_path FROM plugin_staged_packages;"
   # remove only .staging-* directories NOT referenced above
   ```
   Never remove a content-addressed quarantine directory
   (`<data>/plugins/quarantine/<package-digest>/`) that is referenced by a
   staged package — re-verification (`lumen plugin test`) depends on those
   bytes.

4. **Verify sandbox backend health** after cleanup:
   ```
   lumen sandbox report
   lumen health
   ```

## Verification

- `runs/reconciliation` returns an empty list (or only entries you
  deliberately deferred, each with a recorded reason).
- `lumen health` passes, including the audit-chain check.
- No `.staging-*` directories remain under the quarantine root.

## Failure posture

- If reconciliation reports `terminal_audit_pending`, do **not** delete the
  run: flush the terminal audit first (`lumen serve` recovery does this), then
  re-check. Deleting a run with a pending terminal audit destroys evidence.
- If `lumen health` fails the audit-chain check after cleanup, stop and follow
  `audit-chain-verification-export.md` — the chain is append-only and cleanup
  must never break it.
