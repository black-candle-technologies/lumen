# Milestone 5: Durable Automation

## Status

Accepted for implementation after Milestone 4 controlled egress verification passed.

## Goal

Milestone 5 lets Lumen run approved work later, repeat routine work safely, and turn completed workflows into reviewed reusable skills without inheriting ambient authority.

The milestone is complete only when scheduled jobs, reviewed skills, and workflow capture all reuse the same identity, capability, approval, execution, and audit path as interactive runs.

## Scope

Milestone 5 includes:

- Durable one-shot and fixed-interval scheduled jobs.
- Service identities owned by human principals or workspaces.
- SQLite-backed job leases, job runs, idempotency keys, and crash recovery.
- Job proposals that create ordinary agent runs with explicit data class, budget, and actor metadata.
- Reviewed, versioned agent skills with immutable source digests and enablement state.
- Skill retrieval as context only, not authority.
- Workflow capture from completed audited runs into reviewed skill drafts.
- Operator APIs and web controls for jobs, service identities, skills, and captured drafts.

Milestone 5 does not include distributed workers, calendar integrations, hosted queues, browser automation, public skill marketplaces, automatic skill publication, cron grammar, or unreviewed self-modifying agents.

## Chosen Approach

Lumen will treat automation as another source of authenticated requests, not a shortcut around the runtime.

Alternatives considered:

1. **Runtime-owned durable scheduler (chosen).** Jobs are persisted in SQL, leased by the local runtime, and execute by creating normal runs attributed to explicit service identities.
2. **External cron invoking the CLI.** This is simple but loses lease, ownership, idempotency, and audit continuity.
3. **Agent self-scheduling from prompts.** This is flexible but too easy to turn into unreviewed authority expansion.

The implementation proceeds in vertical slices: core identity and schedule types, persistence, scheduler leasing, run creation, skills, workflow capture, operator controls, and adversarial verification.

## Service Identities

A service identity is a non-human principal used only for automation.

Each service identity has:

- Stable principal ID, using provider `service`.
- Human-readable label.
- Owning workspace.
- Owner principal.
- Enabled state.
- Created, updated, and disabled timestamps.
- Explicit capability grants and policy scope.

Service identities do not inherit the owner user's capabilities. An owner can review, disable, or delete the automation configuration, but execution authority is the intersection of the service identity's grants, workspace policy, plugin grants, egress policy, and action policy.

## Scheduled Jobs

The first schedule grammar is intentionally small:

- `once`: run once at an absolute timestamp.
- `interval`: run repeatedly after a start timestamp and fixed duration.

Cron expressions are deferred until there is a stronger reason to add them. Fixed intervals are easier to explain, test, and make idempotent.

A scheduled job has:

- Job ID and revision.
- Workspace ID.
- Service principal ID.
- Owner principal ID.
- Enabled state.
- Schedule spec and next due timestamp.
- Prompt or structured run template.
- Data class.
- Run budgets.
- Optional plugin, skill, or conversation context references.
- Idempotency policy.
- Created, updated, and disabled timestamps.

Changing a job creates a new revision. Existing due occurrences keep their original revision and idempotency key.

## Leases And Idempotency

The scheduler uses SQLite leases so only one local runtime instance claims a due occurrence at a time.

The occurrence key is deterministic:

```text
job_id + job_revision + scheduled_for
```

Before creating a run, the scheduler inserts a job-run row with that occurrence key under a unique constraint. If the process crashes after claiming a lease but before creating a run, recovery can safely retry the same occurrence. If a run exists, recovery reconciles the job-run state instead of creating a duplicate.

Retries are allowed only when the original action and job policy are idempotent. Non-idempotent unknown outcomes remain visible for operator reconciliation.

## Skills

Skills are reviewed procedure/context artifacts that help the agent avoid rediscovering repeatable workflows.

A skill has:

- Skill ID.
- Human-readable name and description.
- Version.
- Source format.
- Source digest.
- Review state.
- Workspace scope.
- Created by, reviewed by, and timestamps.
- Optional tags and retrieval metadata.

Skills do not grant capabilities, bypass approvals, or execute directly. A skill can influence model context, but every resulting action still goes through normal normalization, policy, approval, execution, and audit.

Skill source may live on disk for operator editing, but SQL stores the immutable version metadata and digest. Runtime retrieval uses the reviewed version and validates the digest before including content in model context.

## Workflow Capture

Workflow capture starts only from a completed run whose audit chain verifies.

Capture produces a draft skill, not an enabled skill. The draft includes:

- Goal summary.
- Redacted steps.
- Referenced action kinds.
- Required input variables.
- Expected outputs.
- Known failure modes.
- Source run and audit event references.
- Source digests for captured artifacts.

Capture excludes secret values, approval decisions as authority, transient credentials, raw diagnostics, and policy grants. Publishing the draft as a skill requires explicit review and approval.

## Audit And Failure Behavior

Automation audit events must answer:

- Which job, job revision, and occurrence created the run?
- Which service identity acted?
- Who owns the automation?
- Which schedule and idempotency key were used?
- Which skill versions were loaded into context?
- Whether workflow capture redacted secret or sensitive material.
- Whether a lease expired, was stolen, or was recovered.
- Whether execution succeeded, failed, was cancelled, timed out, or became unknown.

If policy cannot be loaded, a service identity is disabled, a job lease cannot be safely claimed, a skill digest does not match, the audit chain cannot be verified, or capture redaction fails, Milestone 5 behavior fails closed.

## Completion Gates

Milestone 5 is complete only after:

- Service identities are explicit, owned, enableable, disableable, and non-inheriting.
- Scheduled jobs persist revisions, leases, occurrences, idempotency keys, and recovery state.
- Job execution creates ordinary agent runs with service identity attribution.
- Reviewed skills can be versioned, enabled, loaded, and audited without granting authority.
- Workflow capture creates reviewed drafts from completed audited runs only.
- Operator APIs and web controls expose jobs and skills without secret values.
- Adversarial tests cover duplicate leases, crash recovery, disabled service identities, stale job revisions, skill digest tampering, secret redaction, approval replay, and audit failure.
- Full workspace tests, frontend checks, Playwright, and diff hygiene pass.
