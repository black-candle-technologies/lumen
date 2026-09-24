# Runbook: messaging adapter disablement

## Purpose

Cut off a messaging channel (Courier, Discord, future Signal) when its
credential is compromised, its behavior is anomalous, or its provider is
down — without affecting the kernel or other channels.

## Current build status

> **Forward-looking.** Messaging adapters are a Phase-5 surface. The uniform
> authority rule already applies to everything in this tree: *a signed or
> authenticated message proves where a request came from; it never grants the
> requested action.* No adapter can extend a lease, approve its own request,
> or bypass VHL. When Phase-5 lands, each adapter gets an enable/disable
> switch following this runbook.

## Preconditions

- The adapter/provider name (e.g. `courier`, `discord`).
- Operator authority over egress policy for the workspace.

## Procedure

1. **Disable the adapter.** The disable is a policy change, so it goes
   through the approval-bound egress path (Egress page → provider policy,
   or the API):
   ```
   # provider policy update with enabled=false for the adapter's provider id
   ```
   In an active incident where waiting for approval is unsafe, the operator
   may disable directly and must record the decision as an audit event
   afterwards (who, what, why, incident reference).

2. **Invalidate the credential.** Disabling stops the adapter from *sending*;
   invalidating the credential stops the provider from accepting anything
   *as* the adapter:
   - Courier: rotate/revoke the bridge credential; confirm the dashboard
     shows the connection down.
   - Discord: reset the bot token in the developer portal and update the
     stored secret (`lumen secret delete` the old reference only after the
     new one is proven — see `credential-host-key-rotation.md`).
   - Any adapter: the stored credential reference must be deleted or
     re-pointed; a disabled adapter with a live credential is one config
     flip away from resurrection.

3. **Drain and verify.** Confirm no outbound traffic:
   - The adapter's outbox/queue is empty or explicitly drained.
   - Provider-side dashboards show no new sends from the adapter identity.
   - `lumen audit verify` passes; the disablement and credential rotation
     are in the log.

4. **Decide the re-enable bar before re-enabling.** Write down what "safe to
   re-enable" means (new credential proven, anomalous behavior explained,
   provider incident resolved). Re-enable is a fresh policy decision with a
   new approval — never an automatic revert.

## Verification

- Outbound messages on the channel are blocked: a test send is refused with
  the adapter-disabled reason (not silently dropped — refusals are visible).
- The kernel and all other channels are unaffected (spot-check: approvals
  still list, audit still appends, other adapters still deliver).
- The old credential no longer authenticates (expect `401`/rejected at the
  provider).

## Failure posture

- If messages were already exfiltrated through the channel before
  disablement, this runbook is containment, not remediation — rotate every
  secret the adapter could observe and review the audit trail for what left.
- If the adapter cannot be disabled because the policy store is unreachable,
  the safe default is deny: stop the runtime (`emergency-stop.md`) rather
  than leaving a compromised channel half-disabled.
- Signal specifically: per the plan, if no official supported surface
  satisfies the credential/identity/audit/lifecycle requirements, the
  adapter stays disabled and the gap is documented — "temporarily enabled
  with a workaround" is not an option.
