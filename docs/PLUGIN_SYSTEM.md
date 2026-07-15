# Plugin System

Plugins extend Lumen without becoming part of its security kernel. They can describe and request capabilities, but only the runtime can grant authority, obtain approval, resolve secrets, execute sensitive host operations, and write authoritative audit events.

## Extension Categories

A plugin package may provide one or more typed components:

- Model provider adapter
- Inbound or outbound channel adapter
- Tool provider
- Workflow integration
- Scheduled-job handler
- Skill bundle
- User-interface metadata

These categories share installation and provenance metadata but do not share implicit permissions. A model provider does not gain filesystem access because another component in the same package declares a file tool.

## Execution Types

Lumen supports two third-party execution types:

### WASM component

Preferred for portable tools and transformations. The runtime exposes a narrow versioned host interface. Filesystem, network, clock, randomness, secrets, and other resources are available only through explicitly granted host capabilities.

### Supervised subprocess

Used for MCP servers, native binaries, model runners, and integrations that cannot fit the WASM host interface. The runtime starts the process with a minimal environment, explicit resource limits, an authenticated local protocol channel, and a platform sandbox profile.

Native dynamic libraries and arbitrary in-process Rust plugins are not supported. Built-in Rust functionality is compiled as part of Lumen and is reviewed and released with the runtime rather than installed as a plugin.

## Manifest

Every package contains a canonical `lumen-plugin.toml`. The initial schema is:

```toml
manifest_version = 1
id = "dev.example.git-tools"
name = "Git Tools"
version = "1.2.0"
description = "Workspace-scoped Git operations"

[runtime]
type = "wasm-component" # or "subprocess"
entrypoint = "plugin.wasm"
protocol_version = 1

[[components]]
id = "status"
kind = "tool"
description = "Read repository status"

[[components.capabilities]]
name = "fs.read"
scope = "workspace"

[integrity]
algorithm = "sha256"
artifact = "<hex digest>"
```

Manifests are parsed as structured data with unknown security-relevant fields rejected. Plugin ID is stable across versions and independent of directory name. Component IDs are stable within a plugin.

## Installation Lifecycle

Installation is a staged and approval-bound transaction:

1. Acquire the package into a quarantine directory.
2. Parse and validate the manifest without executing plugin code.
3. Compute hashes for the canonical manifest and every executable artifact.
4. Record local source provenance and the authenticated reviewer identity.
5. Present requested capabilities and version changes for approval.
6. Atomically install an immutable version directory.
7. Create a disabled plugin-version record.
8. Enable components only after grants and settings pass validation.

Updates install side by side and never replace an executing artifact. A changed executable, manifest, grant set, or effective configuration produces a new action fingerprint and invalidates prior approvals that depend on it. Disablement and quarantine release are explicit lifecycle actions.

Hashes establish artifact identity, not trust. Signature verification is not part of the current local-package slice. Future signatures should establish publisher continuity only when the signer is trusted, and they must not replace sandboxing or least privilege.

## Capability Grants

Manifest capabilities are requests. Administrators grant a subset at global or workspace scope, and users may further restrict them for an agent or run. The runtime computes the intersection before each action.

Plugin-defined permission names are not allowed for host authority. Plugins may define descriptive feature flags, but all sensitive effects map to runtime-owned capability namespaces from [Security Model](SECURITY.md).

## Settings And Secrets

Settings support `global`, `workspace`, `user`, and `agent` scopes. Effective configuration is a deterministic merge from broadest to narrowest scope and is hashed for each action. Unknown keys and type mismatches are rejected against the plugin's versioned settings schema.

Secret values are never stored in plugin settings. A setting may contain a secret reference, and the runtime resolves it only for an approved action with `secret.use` authority.

## Protocol Boundary

Both runtime types use a versioned request/response contract built around typed components and structured action proposals. Protocol messages have request IDs, deadlines, size limits, and cancellation. A plugin cannot ask the runtime to execute an arbitrary undeclared operation.

The runtime is responsible for:

- Authentication of the plugin process or instance
- Schema validation
- Capability evaluation
- Approval handling
- Secret resolution
- Deadlines and resource limits
- Audit emission
- Result-size enforcement and redaction

Plugin logs are diagnostic input and are never treated as audit truth.

## Failure And Health

Plugin crashes fail the current action without crashing the runtime. Restart policy is bounded and uses backoff. Repeated failures quarantine the component until an authorized user re-enables it. Non-idempotent actions are not retried automatically.

## Skills

Skill bundles contain versioned instructions and supporting resources. Skill content is hashed, attributed, scoped, and audited when loaded. Skills cannot call host APIs directly and cannot expand the capability set of the agent using them. A workflow-derived skill is disabled until reviewed and explicitly enabled.

## Current Boundary

The current vertical slice supports local package staging, review, approval-bound installation, immutable versions, WASM-component execution, supervised subprocess execution, global and workspace grants, deterministic scoped settings, runtime-owned audit provenance, authenticated plugin review APIs, and privileged Linux plugin-sandbox verification through the repository CI gate. It does not yet support public marketplaces, automatic updates, remote signature trust, plugin-supplied UI, external channel adapters, scheduled-job plugins, or remote network egress.
