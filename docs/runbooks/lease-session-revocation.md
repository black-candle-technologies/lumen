# Runbook: lease and session revocation

## Purpose

Cut off authority that has already been granted: revoke a lease (and its
descendants) or terminate a session (and its ephemeral identity) so no further
actions can be authorized under it.

## Current build status

> **Scaffolded.** Leases and Pi sessions are Phase-1 authority-kernel
> concepts. This build has no lease store and no session table, so
> `lumen lease` / `lumen session` report that revocation is unavailable rather
> than pretending to revoke. Use the procedure below once the Phase-1
> authority kernel lands; until then, the closest available controls are run
> cancellation and approval invalidation (steps 1-3).

## Preconditions

- Operator identity with authority over the workspace.
- The lease id (or session id) to revoke, copied from `lumen lease show` /
  `lumen session show` — never retyped from memory.

## Procedure

1. **Inspect before revoking.** Show the lease scope, budget, ancestry, and
   every active run or session bound to it:
   ```
   lumen lease show <lease-id>
   ```
   Confirm the descendants listed are the ones you intend to cut off. Child
   leases are always narrower than their parent (scope, budget, expiry); a
   parent revocation cascades to all descendants — there is no way to revoke a
   parent while keeping a child alive, by design.

2. **CONFIRM — revoke the lease.**
   ```
   lumen lease revoke <lease-id> --reason "<incident reference>"
   ```
   The CLI prints the exact lease digest, scope, and descendant count and
   requires `--yes` (or an interactive confirmation). The revocation is
   committed as an immutable record; the commit is blocked if the lease was
   already revoked (no silent no-op — the CLI reports `already_revoked`).

3. **Terminate affected sessions.** Sessions bound to a revoked lease lose
   authority immediately, but terminate them explicitly for a clean record:
   ```
   lumen session terminate <session-id> --reason "lease <lease-id> revoked"
   ```
   The session's ephemeral identity key is deleted at termination and cannot
   be reused.

4. **Cancel in-flight runs.** Revocation blocks *new* commits, but runs that
   already hold a reserved execution may need explicit cancellation:
   ```
   lumen run show <run-id>        # confirm it is still active
   curl -X POST $LUMEN_URL/api/v1/workspaces/<ws>/runs/<run-id>/cancel \
     -H "Authorization: Bearer $LUMEN_TOKEN"
   ```

## Verification

- `lumen lease show <lease-id>` reports state `revoked` with the revocation
  record (revoked_by, revoked_at, reason).
- `lumen lease show <lease-id>` for each descendant reports `revoked`
  (cascade).
- No run bound to the lease reports an `active` phase in
  `lumen run show <run-id>`.
- The audit log contains the revocation event; chain still verifies:
  `lumen audit verify`.

## Failure posture

- If the commit is blocked after revoke (a run still commits), treat it as a
  kernel integrity failure: stop the runtime (`emergency-stop.md`) and
  escalate — do not retry the revocation.
- If the lease id is unknown, the command fails closed with `not_found`; it
  never revokes "the closest match".

## Until Phase-1 lands (available today)

- Cancel a run: `POST /runs/{run-id}/cancel` (approval-free; the run's owner
  or the operator may cancel).
- Invalidate a pending approval so it can never be granted:
  decide `reject` on it from the Approvals page, or `lumen approvals list`
  to find it first. Rejected approvals are terminal.
- Expired approvals can never be granted; `renew` creates a *new* request
  with a new digest that must be reviewed again.
