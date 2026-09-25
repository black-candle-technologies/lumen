# Web UI — explicit follow-up (not built)

The desktop app (`apps/desktop`) was removed in phase 6. The operator
surfaces that exist today are:

- `lumen` CLI (`crates/lumen-cli`): `approvals list`, `audit list`,
  `plugin admit/test/approve/install`, `health`, `support-bundle`.
- Control-plane API: the decision endpoint for pending approvals
  (grant/reject with attestation).

There is **no web UI**. The CLI's pending-approval output used to point
the operator at a "web UI approvals page"; that text now points at the
control-plane API and this document instead.

## What a web UI would need

1. **Approvals page**: list pending approvals with the exact normalized
   arguments, capability scope, action fingerprint, and expiry (the same
   data `lumen approvals list` shows); grant/reject with the operator's
   attestation bound to the action digest (see `lumen_core::vhl`).
2. **Audit view**: hash-chained audit log with chain verification
   (see `docs/runbooks/audit-chain-verification-export.md`).
3. **Session identities**: per-session ephemeral identity status and
   explicit destroy (see `SessionIdentityVault` in
   `crates/lumen-core/src/session_identity.rs`).
4. **Plugin admission**: review queue for plugin digests, test results,
   and approval-bound installs (see `docs/runbooks/plugin-revocation.md`).

## Constraints for the future build

- Read-only inspection must never require broader authority than the
  operator already holds; approval *decisions* must go through the same
  attestation path as the API (no bypass, no separate auth).
- The web UI is a control-plane client, not a new authority: it must
  not mint leases, identities, or approvals itself.
- Do not rebuild `apps/desktop`; the decision was to kill it.
