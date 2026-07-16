# Runtime Execution

This document defines the authoritative lifecycle for agent runs and sensitive actions.

## Core Entities

- **Request context:** authenticated actor, channel or job origin, workspace, request ID, and trust metadata.
- **Agent run:** one bounded model-and-tool loop with model, token, action, time, and cost budgets.
- **Action proposal:** untrusted structured output from a model, user, job, or plugin.
- **Action envelope:** runtime-normalized immutable description of an intended effect.
- **Policy decision:** allow, deny, or require approval, plus policy version and reasons.
- **Approval:** an authorization bound to an action fingerprint and use constraints.
- **Execution attempt:** one isolated dispatch of an approved action.
- **Result:** bounded structured output with outcome and redaction metadata.

## Action Envelope

Every action envelope includes:

- Unique action ID and schema version
- Run, workspace, actor, and requesting component IDs
- Canonical action kind
- Normalized arguments and resource identifiers
- Required capabilities
- Plugin artifact and effective-configuration hashes when applicable
- Referenced-content hashes when the content determines the effect
- Deadline, resource budget, and idempotency classification
- Creation timestamp and parent action where applicable

Canonical serialization produces the action fingerprint. Secret values are excluded; stable secret reference IDs are included.

## State Machine

An action moves through these states:

```text
proposed -> normalized -> evaluating
evaluating -> denied
evaluating -> approved
evaluating -> awaiting_approval
awaiting_approval -> rejected
awaiting_approval -> expired
awaiting_approval -> approved
approved -> dispatching -> running
running -> succeeded
running -> failed
running -> cancelled
running -> timed_out
running -> unknown
```

`approved` means both policy and any required human approval are valid. The runtime re-evaluates policy and recomputes the fingerprint during `dispatching`.

## Agent Loop

1. Persist the authenticated request and create a run with explicit budgets.
2. Select the model under the routing policy.
3. Assemble context with source and sensitivity metadata.
4. Stream text output or parse a structured action proposal.
5. Reject malformed or unavailable actions without invoking an executor.
6. Normalize the proposal and persist its action envelope.
7. Evaluate effective capabilities and policy.
8. Deny, approve, or create an approval request.
9. Dispatch only after the final fingerprint and policy checks pass.
10. Bound, redact, and persist the result.
11. Return the result to the model as untrusted content if budgets allow another turn.
12. Finish the run with a terminal reason.

The loop cannot exceed configured limits for model turns, actions, wall time, tokens, remote cost, or captured bytes.

## Job-Originated Runs

A scheduled job creates an ordinary run with explicit job origin metadata. The run context may carry job ID, job revision, scheduled timestamp, and deterministic occurrence key, while interactive runs keep no job origin.

The occurrence key is derived from `job_id + job_revision + scheduled_for`. It is stable across crash recovery and is the idempotency anchor for scheduler lease and duplicate-run prevention.

The local scheduler claims due occurrences through SQLite leases, creates runs as the service principal, and advances `next_due_at` only after a run has been reserved for the occurrence. Disabled jobs, disabled service identities, active leases, existing non-unknown occurrence run IDs, and unreadable service grants fail closed before a duplicate run can be created.

When a scheduled occurrence reaches a terminal run outcome, the occurrence row is updated to `succeeded`, `failed`, `cancelled`, or `unknown`. Idempotent jobs may replace an `unknown` occurrence run with a new retry run. Non-idempotent jobs leave the unknown run attached to the occurrence for operator reconciliation.

## Approval Concurrency

Approval uses an atomic compare-and-set transition. Only a pending, unexpired request with a matching fingerprint may be granted. Consumption and dispatch reservation occur transactionally so concurrent workers cannot reuse a one-shot approval.

## Execution And Recovery

Before starting a side effect, the runtime persists an execution attempt and dispatch reservation. On success or known failure it records the terminal outcome. If the runtime loses contact after dispatch, the outcome is `unknown`.

Automatic retry is allowed only when:

- The action kind is declared idempotent.
- Policy permits retry.
- The retry remains within the original envelope and approval.
- The executor supplies an idempotency key where the target supports one.

Unknown non-idempotent actions require user reconciliation rather than blind retry.

## Reviewed Skills

Reviewed, enabled skill versions are loaded as untrusted procedure context before the first model turn. The runtime reads skill source from local runtime storage, verifies the content digest against SQL metadata, bounds the rendered context, and skips unreviewed, disabled, wrong-workspace, missing, or digest-mismatched skills.

Skill context does not grant capabilities, approve actions, change policy, or bypass plugin grants. Any model action influenced by a skill still re-enters normal normalization, capability evaluation, approval, dispatch, and audit. Run audit metadata records loaded skill IDs, versions, and digests.

## Workflow Capture

Workflow capture creates draft skill material only from completed source runs whose audit chain verifies. Draft bodies are generated from persisted run, action, and audit records, include source run IDs, action kinds, action argument digests, required-variable notes, expected outputs, and failure notes, and avoid copying raw action arguments or known secret values.

Publishing a capture draft as a reviewed skill is a `skill.publish` action. It requires the `skill.publish` capability, goes through approval, dispatch reservation, execution, and audit, writes immutable local skill source, stores the reviewed skill version digest in SQL, and enables the version for the workspace only after approval is consumed.

## Automation API

The local API exposes workspace-scoped control-surface routes for service identities, scheduled jobs, reviewed skills, and capture drafts. Review/list routes read SQL state and return redacted summaries suitable for operator inspection.

Mutating scheduled jobs and publishing capture drafts do not bypass the action lifecycle. Job create/update requests become `schedule.job.create` or `schedule.job.update` actions with `schedule.create` or `schedule.modify` capabilities. Capture-draft publishing becomes `skill.publish`. These actions require approval under the runtime policy and are applied only after approval consumption, dispatch reservation, and audit.

Service identity updates are bounded to service principals and canonical capability grants. Job routes reject secret data classes, zero budgets, invalid schedules, unknown fields, and out-of-workspace access before service dispatch.

## Cancellation

Cancellation stops further model turns, revokes pending dispatch reservations, sends protocol cancellation, and terminates the isolated process tree after a grace period. Cancellation is an outcome, not deletion; all prior records remain auditable.

## Result Handling

Results are schema-validated, byte-bounded, and scanned for known secret values before persistence or model reuse. Binary or large artifacts are stored separately with content hashes and references. Diagnostic stderr remains distinct from user-facing structured output.

Tool results never directly alter identity, policy, approvals, plugin state, or runtime configuration.

## Extension Invocation

Plugin invocation is just another action lifecycle, not a shortcut around it:

1. The runtime loads the enabled immutable plugin version for the workspace.
2. It computes effective grants and settings from persisted revisions.
3. It persists a `plugin.invoke` action with plugin ID, version, component, runtime type, package digest, manifest digest, artifact digest, settings digest, grant-set digest, protocol version, and input fingerprint.
4. Policy and approval are evaluated against that exact envelope.
5. Dispatch rechecks the artifact digest and current plugin state before host entry.
6. WASM or subprocess output is decoded, correlated to the original request, schema-validated, bounded, and redacted.
7. Returned action proposals re-enter the same normalization, capability, approval, execution, and audit path as child actions attributed to the parent plugin action.

Disabled, missing, tampered, quarantined, stale-grant, stale-setting, malformed, late, or broader-than-granted plugin effects fail closed. Material grant revocation cancels affected active invocations, and repeated counted plugin faults quarantine only the affected workspace/version unless an artifact digest mismatch requires global artifact quarantine.
