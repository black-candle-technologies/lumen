# Data Model

Lumen uses SQLite as its only initial database target. The persistence layer uses migrations and repositories, but avoids speculative PostgreSQL compatibility work.

## Storage Rules

- IDs are application-generated UUIDs represented consistently.
- Timestamps are UTC and stored in one canonical format.
- Security state changes occur in explicit transactions.
- Foreign keys are enabled and enforced.
- Enum-like values are validated by schema constraints and Rust types.
- JSON is reserved for versioned payloads whose structure is validated at the boundary.
- Secrets are stored as opaque references, never plaintext values.
- Destructive cleanup is separate from audit retention.

## Core Areas

### Identity and scope

- `users`
- `identities`
- `workspaces`
- `workspace_memberships`
- `allowed_channels`

### Conversations and execution

- `conversations`
- `messages`
- `agent_runs`
- `model_turns`
- `actions`
- `policy_decisions`
- `approval_requests`
- `execution_attempts`
- `artifacts`

### Authority and configuration

- `policies`
- `capability_grants`
- `model_providers`
- `model_routing_policies`
- `scheduled_jobs`

### Extensions

- `plugins`
- `plugin_versions`
- `plugin_components`
- `plugin_capability_requests`
- `plugin_settings`
- `agent_skills`
- `skill_versions`

### Audit

- `audit_events`
- `audit_checkpoints`

## Transactional Invariants

- A one-shot approval can be consumed once.
- Dispatch requires a current allow decision and a valid approval when one is required.
- Execution attempt creation and approval consumption are atomic.
- Enabled plugin versions reference installed immutable artifacts.
- Capability grants reference an existing principal and scope.
- Every action terminal state has a corresponding audit event.
- Audit sequence numbers and hash-chain links are committed in order.

## Configuration Precedence

Scoped plugin and agent settings merge in this order:

```text
global -> workspace -> user -> agent
```

Narrower settings override broader settings only for schema-declared keys. Effective configuration is canonicalized and hashed before action evaluation.

## Migration Policy

Migrations are append-only after release, run under an exclusive application migration lock, and are tested against both an empty database and the previous released schema. Downgrade migrations are not required initially; backups and explicit recovery are required before destructive migrations.
