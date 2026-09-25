# Runbook: emergency stop and feature-flag shutdown

## Purpose

Stop all agent activity **now** — cancel in-flight work, block new runs, and,
if needed, disable whole subsystems — while preserving the audit trail for
after-action review.

## Preconditions

- Operator with host access to the runtime. In a true emergency, host-level
  stop does not require the API token; API-level steps do.

## Procedure

### Level 1 — Stop new work (graceful)

1. Stop the runtime service so no new runs are admitted and the admission
   gate seals (in-flight tasks are aborted, owned runs are settled, never
   orphaned):
   ```
   systemctl stop lumen        # or: pkill -TERM -f 'lumen serve'
   ```
2. Confirm the process is gone and the port is closed:
   ```
   systemctl is-active lumen    # expect: inactive
   ss -ltn | grep <bind-port>   # expect: no output
   ```

### Level 2 — Cancel in-flight runs (if the API is still up)

For each active run (find them via `lumen run show` / the reconciliation
endpoint before stopping, or from the dashboard):

```
curl -X POST $LUMEN_URL/api/v1/workspaces/<ws>/runs/<run-id>/cancel \
  -H "Authorization: Bearer $LUMEN_TOKEN"
```

Cancellation is approval-free by design — it only *removes* authority, never
grants it. A cancelled run's terminal audit is still recorded.

### Level 3 — Feature-flag shutdown (partial stop)

When only one subsystem is misbehaving, disable it instead of stopping
everything. All of these are **deny-by-default** flips — the safe state when
the flag store is unreachable is "disabled":

| Subsystem | How to disable | Effect |
|---|---|---|
| Remote models | Set `[model] allow_remote = false` and restart, or narrow the orchestration control policy (`remote_allowed: false`) | No new remote calls; in-flight remote calls finish or time out |
| A messaging adapter | Follow `adapter-disablement.md` | Outbound on that channel blocked; credentials invalidated |
| A plugin digest | `lumen plugin revoke <id> <version> --reason ...` (see `plugin-revocation.md`) | Digest disabled; future installs/enables refused |
| Scheduled jobs | Disable the job via the automation API (`enabled: false`) | No new scheduled runs; the in-flight run is unaffected |

Feature-flag changes go through the normal approval-bound config path
**except** during an active incident, where the operator may apply them
directly — every direct change must still be recorded as an audit event
afterwards (who, what, why, incident reference).

### Level 4 — Full stop (host)

If the runtime does not stop gracefully, or the host itself is suspect:

Record the operator identity and reason in the incident log **before**
the kill — after SIGKILL the runtime cannot append anything itself.

```
systemctl kill -s KILL lumen
```

Then treat every run as reconciliation-required on next start (the control
plane's `recover()` pass handles this) and verify the audit chain before
resuming: `lumen audit verify`.

## Verification

- No `lumen` runtime process is running; the API port is closed.
- `lumen audit verify` passes — the stop itself must not corrupt the chain.
- The audit log shows the stop/cancellation events with operator identity
  for graceful stops (Levels 1–3). After a Level 4 SIGKILL, expect the
  startup recovery records instead: recovered executions are recorded as
  `ExecutionUnknown` without an operator identity (the runtime was dead
  and could not attribute them). The operator identity for the kill itself
  lives in the incident log recorded before the kill, not in the audit
  chain.

## Failure posture

- If the process respawns (supervisor restart loop), disable the unit
  (`systemctl disable --now lumen`) before investigating — a flapping
  runtime admitting work intermittently is worse than a stopped one.
- If `lumen audit verify` fails after an emergency stop, follow
  `audit-chain-verification-export.md` before restarting. Never restart a
  runtime over a broken audit chain to "see if it recovers".

## Resuming

1. `lumen health` — all checks pass.
2. `lumen audit verify` — chain intact.
3. Start the runtime; its `recover()` pass reconciles abandoned runs and
   records integrity reports.
4. Re-enable feature flags one at a time, verifying each subsystem before
   the next.
