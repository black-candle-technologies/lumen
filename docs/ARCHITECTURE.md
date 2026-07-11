# Architecture

Lumen is a local-first AI agent runtime for user-owned infrastructure. Its product center is a small security kernel that coordinates models, tools, plugins, jobs, permissions, approvals, and audit records. The web and desktop applications are control surfaces over that runtime.

## Product Position

Lumen prioritizes predictable authority over integration count:

- Local models and local storage are the default.
- Remote inference and network egress are explicit, visible choices.
- Models propose actions but never authorize them.
- Plugins request capabilities but never grant or enforce them.
- Every path to a sensitive resource passes through the same runtime policy boundary.
- An action can be explained from authenticated request through policy decision, approval, execution, and result.

Lumen is not intended to protect a host from its operating-system administrator or from an already-compromised operating system. See [Security Model](SECURITY.md) for the complete threat model.

## Architectural Invariants

The following rules are requirements, not implementation suggestions:

1. `lumen-core` is the only authority for policy decisions, approvals, capability grants, and action dispatch.
2. Models, plugins, integrations, API handlers, and user interfaces cannot execute sensitive actions directly.
3. Third-party code never loads into the Lumen runtime process.
4. An approval authorizes one immutable action envelope or an explicitly bounded reusable grant.
5. Changing an approved action invalidates its approval.
6. Remote model fallback is never silent.
7. Secrets are resolved at the executor boundary and are withheld from models whenever possible.
8. Audit events are emitted by the runtime around the action, not trusted to the plugin performing it.
9. Skills provide instructions, not authority. Installing or invoking a skill cannot expand capabilities.
10. Default policy denies any capability that has not been granted explicitly.

## System Shape

### Security kernel

The security kernel lives in `lumen-core` and contains:

- Identity and request context
- Agent-run orchestration
- Normalized action envelopes
- Capability and policy evaluation
- Approval lifecycle
- Executor dispatch
- Cancellation, budgets, and deadlines
- Audit event construction

It acts as a reference monitor: every sensitive operation must be complete, non-bypassable, and mediated by this layer.

### Persistence

`lumen-db` owns SQLite migrations, repositories, and transactional persistence. It stores runtime state but does not make authorization decisions. The initial target is SQLite only; portability abstractions for PostgreSQL are deferred until there is a demonstrated need.

### Integrations and executors

`lumen-integrations` contains model-provider clients, plugin protocols, tool adapters, sandbox backends, and external channel adapters. These implementations translate between external protocols and core types. They are not trusted to approve themselves or to write authoritative audit history.

Third-party extensions use one of two execution boundaries:

- WASM components for portable extensions that fit a capability-oriented host API.
- Supervised subprocesses for native tools, MCP servers, model runners, and platform integrations.

Dynamic in-process libraries are not a supported plugin type.

### Server and control surfaces

`lumen-server` owns HTTP routing, authentication transport, SSE streaming, and API serialization. It calls `lumen-core`; it does not contain policy logic.

`apps/web` and `apps/desktop` provide chat, approvals, jobs, audit inspection, and settings. Tauri is a packaging boundary, not an alternate runtime or authorization path.

## Trust Boundaries

Lumen treats these inputs as untrusted even when they originate locally:

- User prompts and inbound channel messages
- Model output and proposed tool calls
- Web pages, files, email, tool results, and retrieved context
- Skills and plugin-supplied prompt content
- Third-party plugin code and subprocess output
- Remote provider responses

The runtime core, its policy configuration, and the configured secret store are trusted within the stated operating-system assumptions.

## Request And Action Flow

All agent work follows the same high-level flow:

1. An ingress adapter authenticates an identity and creates a request context.
2. The runtime rejects identities or channels that are not allowed for the selected workspace.
3. The runtime selects a model under the workspace's routing and data-egress policy.
4. The model may produce text or propose a structured action.
5. The runtime normalizes the proposal into an immutable action envelope.
6. The policy engine returns `allow`, `deny`, or `require_approval` with reasons.
7. When required, the user reviews the exact action envelope and grants or rejects it.
8. The runtime verifies that the action still matches the policy and approval.
9. An isolated executor receives only the capabilities and secrets needed for that action.
10. The runtime records the outcome, filters the result, and decides whether the agent loop may continue.

The detailed state machine is defined in [Runtime Execution](RUNTIME_EXECUTION.md).

## Configuration Boundaries

Host boot configuration lives in one `lumen.toml` file, with environment variables allowed only for bootstrap overrides and secret-store bootstrap references. Lumen will not support multiple equivalent YAML, TOML, and dotenv configuration formats.

Boot configuration includes:

- Bind address and port
- Database path
- Log level
- Runtime data directory
- Enabled sandbox backend
- Local model endpoint bootstrap settings
- Bootstrap administrator identity
- Secret-store backend

Mutable, queryable, or auditable product state lives in SQL:

- Identities, workspaces, memberships, and allowlists
- Conversations, messages, runs, and actions
- Policies, capability grants, and approvals
- Plugins, versions, hashes, settings, and enabled state
- Model provider configurations and routing policies
- Scheduled jobs
- Skills and provenance
- Audit events and chain checkpoints

Secrets do not live in either ordinary configuration files or plugin settings. SQL stores opaque secret references.

## Deployment Model

The first supported deployment is a single Lumen runtime process with a local SQLite database, local control surface, and supervised child executors. The runtime may connect to a separately managed local model server over loopback.

The first release is single-host and workspace-aware. It does not claim hostile multi-tenant isolation between operating-system users. Remote access, external chat channels, and distributed workers are later capabilities and must not weaken local defaults.

## Related Documents

- [Documentation Index](README.md)
- [Security Model](SECURITY.md)
- [Runtime Execution](RUNTIME_EXECUTION.md)
- [Plugin System](PLUGIN_SYSTEM.md)
- [Model Routing](MODEL_ROUTING.md)
- [Data Model](DATA_MODEL.md)
- [Audit Log](AUDIT_LOG.md)
- [Repository Map](REPOSITORY.md)
- [Roadmap](ROADMAP.md)
- [Implementation Plan](IMPLEMENTATION_PLAN.md)
