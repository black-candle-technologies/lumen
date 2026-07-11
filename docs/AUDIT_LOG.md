# Audit Log

The audit log is the runtime's structured account of security-relevant activity. It is distinct from diagnostic application logs.

## Guarantees

Within the documented operating-system trust assumptions, the audit system aims to provide:

- Attribution to authenticated actor, workspace, run, plugin, and executor
- Ordered records of policy, approval, dispatch, and outcome
- Detection of database edits, deletion, or reordering through hash chaining
- Enough artifact and configuration identity to explain what executed
- Explicit redaction and omission metadata

It does not provide immutability against an operating-system administrator. External signed checkpoints may be added later for deployments needing an off-host trust anchor.

## Event Envelope

Every event contains:

- Event ID, schema version, and monotonic sequence
- Timestamp
- Event type and outcome
- Actor, workspace, request, run, action, and attempt IDs as applicable
- Plugin ID, version, artifact hash, and configuration hash as applicable
- Policy version, decision, matched rule IDs, and required capabilities
- Approval ID and approver when applicable
- Structured resource descriptors and systems touched
- Redacted event payload
- Previous event hash and current event hash

The current hash covers the canonical event envelope and previous hash. Large artifacts are referenced by content hash rather than embedded.

## Event Types

Initial event families include:

- Authentication accepted or rejected
- Run created, completed, cancelled, or budget-exhausted
- Model provider selected and model turn completed
- Action proposed and normalized
- Policy allowed, denied, or required approval
- Approval created, granted, rejected, expired, invalidated, or consumed
- Execution started, succeeded, failed, timed out, cancelled, or became unknown
- Plugin installed, enabled, disabled, updated, quarantined, or removed
- Capability and policy changed or revoked
- Secret reference used
- Audit chain verified or found inconsistent

## Write Path

Only the runtime audit service appends authoritative events. Plugins and adapters can attach bounded observations, but they cannot choose event attribution or omit the runtime's start and outcome records.

Actions requiring audit persistence fail closed if their pre-dispatch audit event cannot be committed. Post-dispatch persistence failures stop new work and trigger a visible degraded state; uncertain outcomes are reconciled when persistence returns.

## Redaction And Retention

Secret values, authorization headers, raw credentials, and configured sensitive fields are removed before persistence. The event records which redaction rules ran without preserving the removed value. Payload retention is workspace-configurable, but identity, decision, artifact hash, and outcome metadata have a protected minimum retention period.

## Verification

Lumen verifies chain continuity at startup and periodically. Verification failures are surfaced prominently, audited in a new recovery segment when possible, and block high-risk actions until acknowledged by an authorized administrator.
