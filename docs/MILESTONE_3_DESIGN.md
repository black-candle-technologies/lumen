# Milestone 3: Extension Runtime

## Status

Accepted for implementation. The project owner approved the contract-first dual-runtime approach and delegated implementation decisions. Work proceeds on `feat/milestone-3-extension-runtime` with incremental commits.

## Goal

Milestone 3 allows locally reviewed third-party plugins to extend Lumen without entering the runtime process or bypassing the action lifecycle. It ships one package and protocol contract across WASM components and supervised subprocesses, immutable side-by-side versions, explicit capability grants and settings, failure quarantine, provenance, and a small extension SDK.

The milestone is complete only when a plugin can be staged, reviewed, approved, installed, granted a subset of its requested authority, enabled, invoked, audited, upgraded side by side, and quarantined through the same identity, policy, approval, execution, and audit boundaries used by built-in actions.

## Scope

Milestone 3 includes:

- Strict local plugin packages described by `lumen-plugin.toml`.
- Bounded quarantine and locally reviewed installation.
- Immutable, content-addressed, side-by-side plugin versions.
- Tool components executed by a WASM component host or supervised subprocess protocol.
- Plugin-returned action proposals that re-enter the normal runtime action path.
- Workspace capability grants that can only narrow manifest requests.
- Global, workspace, user, and agent settings with deterministic merge and schema validation.
- Exact artifact, manifest, settings, grant, and protocol provenance in action fingerprints and audit events.
- Failure accounting and automatic quarantine after a bounded threshold.
- Authenticated local APIs and a web control surface for package review, versions, grants, settings, enablement, and quarantine state.
- A small Rust SDK, WIT contract, subprocess protocol types, and executable examples used by the integration suite.

It does not include remote package acquisition, a public marketplace, automatic updates, publisher trust management, arbitrary UI code, in-process dynamic libraries, persistent MCP server lifecycle, external channels, remote model providers, or scheduled plugin jobs. Cryptographic signatures may be recorded as unverified source metadata in a future schema, but Milestone 3 establishes trust through explicit local hash review. Lumen must not imply that an unverified signature establishes trust.

## Chosen Approach

Lumen will implement one extension contract with two execution adapters.

Alternatives considered:

1. **Contract-first WASM plus subprocess runtimes (chosen).** This gives both runtimes identical identity, protocol, capability, provenance, deadline, and result rules while keeping execution details replaceable.
2. **WASM-only first.** This would minimize the initial native surface but leave the roadmap's native and MCP-oriented boundary undefined.
3. **Subprocess/MCP-first.** This would reach existing tools quickly but make a broad native protocol the de facto contract before the portable host interface is stable.

The implementation is divided into security-complete vertical slices: package identity, persistence, reviewed installation, common invocation contracts, WASM execution, subprocess execution, composed runtime invocation, operator surfaces, SDK, and adversarial verification.

## Architectural Invariants

The existing architecture remains authoritative:

1. Plugin code never loads into the Lumen process.
2. A manifest capability is a request, never a grant.
3. Installation, authority expansion, enablement, and quarantine release are sensitive runtime actions.
4. Plugin execution cannot call built-in executors directly.
5. A plugin-returned action proposal is untrusted input and re-enters normalization, capability intersection, policy, approval, reservation, execution, and audit.
6. Every invocation is pinned to an immutable plugin version, artifact hash, manifest hash, effective settings hash, grant-set hash, protocol version, workspace, actor, run, and component.
7. Changing any pinned value changes the action fingerprint and invalidates prior approval.
8. Non-active, missing, tampered, or quarantined versions cannot start new invocations.
9. A plugin process or WASM trap cannot crash the runtime.
10. Extension logs are diagnostics and never authoritative audit records.

## Package And Manifest

A local package is a directory containing one canonical `lumen-plugin.toml` and only bounded regular files. Staging walks the package without following symlinks. Symlinks, hard-link ambiguity, devices, sockets, FIFOs, traversal segments, absolute manifest paths, duplicate canonical paths, files that change while hashing, excessive file counts, and excessive aggregate or per-file bytes are rejected.

The manifest uses strict TOML deserialization with unknown fields rejected. The initial schema is:

```toml
manifest_version = 1
id = "dev.example.git-tools"
name = "Git Tools"
version = "1.2.0"
description = "Workspace-scoped Git inspection"

[runtime]
type = "wasm-component" # or "subprocess"
entrypoint = "plugin.wasm"
protocol_version = 1

[[components]]
id = "status"
kind = "tool"
description = "Read repository status"
input_schema = "schemas/status-input.json"
output_schema = "schemas/status-output.json"
action_kinds = ["filesystem.read"]

[[components.capabilities]]
name = "fs.read"
scope = "workspace"

[settings]
schema = "schemas/settings.json"

[integrity]
algorithm = "sha256"
artifact = "<lowercase hex digest>"
```

Plugin IDs and component IDs use stable reverse-domain-style identifiers with bounded ASCII syntax. Versions use canonical semantic versions. Entrypoints and schemas are normalized package-relative paths. The runtime type is package-wide in Milestone 3; a package that needs both runtimes uses separate plugin IDs. The integrity algorithm is exactly `sha256` in this version, and the declared artifact digest must match the staged entrypoint before the package can enter quarantine.

Each tool component declares the canonical action kinds it may return. An empty list means the component may return structured results only. Returned proposals must name a declared kind, and the runtime-owned normalizer determines that kind's required capabilities. Every normalized requirement must be contained by both the component's manifest requests and its effective grants. The manifest cannot define a capability-to-action mapping or override runtime normalization.

Component input, output, and settings schemas use the same runtime-owned bounded JSON Schema subset. Installation parses and compiles every referenced schema before accepting the package. Unknown or unsupported keywords, external references, recursive references, remote identifiers, unbounded regular expressions, excessive schema depth or size, and resource-heavy combinators are rejected rather than ignored. Runtime validation applies explicit depth, property-count, array-length, string-length, and serialized-byte limits before plugin execution and again before accepting a result or proposal.

Every regular file receives a SHA-256 digest. A package digest is computed from a canonical ordered sequence of normalized path, byte length, and file digest. The canonical parsed manifest receives a separate digest. The executable artifact digest is stored separately so audit records can answer which executable bytes ran without reinterpreting the package.

## Quarantine And Installation

Installation begins with `plugin stage <local-directory>`. Staging is acquisition, not installation: it copies verified bytes into a Lumen-owned quarantine directory, writes no enabled plugin version, grants no capability, and executes nothing. The CLI records the source as `local`, the package digest, manifest digest, artifact digest, requested capabilities, and the authenticated operator in SQL and audit history.

The staged record is immutable. The API and control surface show exact package identity, runtime, components, every requested capability, and full digests. Requesting installation creates a `plugin.install` action bound to that staged record. Default policy requires one-shot approval. Granting approval atomically:

1. Reopens the quarantined files without following links.
2. Recomputes and compares every recorded digest.
3. Copies or renames the package into a content-addressed immutable version directory.
4. Creates plugin, version, component, capability-request, and provenance rows transactionally.
5. Marks the version installed but disabled.
6. Retains the quarantine record for audit correlation.

A digest mismatch, existing version with different bytes, filesystem race, database failure, or audit failure prevents installation. Existing identical content is idempotently recognized; different content may never reuse the same plugin ID and version.

Local review satisfies the roadmap's initial trust path. The reviewer approves the exact hashes and requested authority. Hashes establish identity, not safety. Remote download, publisher keys, signature trust, and transparency logs are deferred.

## Persistence

An append-only migration adds:

- `plugin_staged_packages`
- `plugins`
- `plugin_versions`
- `plugin_components`
- `plugin_capability_requests`
- `plugin_capability_grants`
- `plugin_workspace_versions`
- `plugin_settings`
- `plugin_failures`

Plugin and component IDs are stable strings. Installed version rows contain immutable identity, package metadata, artifact paths, and hashes. Artifact paths stored in SQL are Lumen-data-relative paths, never ambient source paths. A version may enter global `artifact_quarantine` only when its installed bytes no longer match its recorded identity; ordinary enablement and health state never mutate the immutable version row.

`plugin_workspace_versions` owns workspace activation. Its states are `enabled`, `disabled`, and `health_quarantine`, and a partial unique index permits at most one enabled version per plugin and workspace. Enabling a side-by-side update atomically disables the previously active workspace version and enables the reviewed target; existing runs remain pinned to the version and hashes already in their action envelopes. Disabling prevents new invocations but does not rewrite historical actions. Uninstall is deferred; immutable artifacts remain available while referenced by runs or audit retention.

Capability grants are revisioned at global-default and workspace scope and keyed by plugin version, component, capability name, and canonical resource scope. A workspace grant may only narrow the global default; absence at either required layer denies the effect. Settings are keyed by plugin version, scope type, and scope ID with optimistic `config_version` updates. Database constraints reject grants that do not correspond to a manifest request.

## Administrative Action Path

Milestone 3 introduces a transport-neutral administrative action service rather than performing sensitive changes inside HTTP handlers or CLI parsing. It constructs normal action envelopes for:

- `plugin.install`
- `plugin.enable`
- `plugin.disable`
- `plugin.capabilities.set`
- `plugin.settings.set`
- `plugin.quarantine.release`

These envelopes use the same persistence, policy, approval registry, fingerprint, dispatch reservation, executor, and audit ports as model-originated actions. Authority-expanding actions require approval by default. Disablement may be immediately allowed because it only removes authority, but it remains authenticated and audited. `plugin.settings.set` is schema-validated and version-checked; settings that introduce secret references or otherwise expand authority require approval, while strictly narrowing changes may be policy-allowed. Every settings change remains audited.

The CLI and HTTP API are adapters over this service. Neither may update plugin lifecycle or grant tables directly.

## Common Invocation Contract

`lumen-core` owns runtime-neutral extension identity and invocation types. An invocation includes:

- Request ID and parent run/action IDs.
- Workspace and authenticated actor.
- Plugin ID, semantic version, component ID, and runtime type.
- Manifest, package, and artifact digests.
- Effective settings and settings digest.
- Effective capability grants and grant-set digest.
- Protocol version, deadline, result-byte limit, and cancellation token.
- Schema-validated structured input.

The host returns one of:

- A schema-validated structured result.
- An untrusted structured action proposal.
- A typed failure.

An action proposal response never reaches an executor from inside the host. The run orchestrator normalizes it as a child action attributed to the plugin component and pinned provenance. It consumes the normal action budget and must pass the component's declared-and-granted capability subset, actor/workspace capability intersection, policy, approval, and audit path.

The invocation itself is always a normal `plugin.invoke` action before any plugin byte runs. Its immutable arguments contain the exact plugin/version/component identity, all provenance hashes, input hash and bounded input, protocol version, and execution limits. It requires the authenticated principal's exact `plugin.invoke` capability for that component. The runtime persists and evaluates the action, obtains approval when policy requires it, writes the pre-dispatch audit event, reserves an execution attempt, and only then calls the extension host through the normal executor port. Invocation success, failure, cancellation, timeout, resource exhaustion, and uncertain post-dispatch state use the existing terminal outcome and crash-recovery rules. No orchestrator or transport adapter may call a host directly.

The runtime rejects undeclared action kinds, capabilities broader than the grant, malformed JSON, unknown protocol variants, duplicate or mismatched request IDs, late responses, excessive frames, and oversized results.

## WASM Component Host

The WASM runtime uses Wasmtime's component model and a versioned WIT world shipped with the SDK. Milestone 3 exposes no ambient WASI filesystem, socket, environment, clock, randomness, or process interfaces. A component receives invocation metadata and structured JSON input through generated component bindings and returns the common result variant.

The host enforces:

- Component validation before installation completes.
- Exact WIT world and protocol-version compatibility.
- Store memory, table, instance, and result limits.
- Fuel accounting and epoch interruption for CPU and wall time.
- Cancellation through epoch interruption.
- No inherited environment or preopened directories.
- Fresh store state per invocation.

Compiled module caching may key on Wasmtime version, target, and artifact digest, but cache files are not authoritative artifacts and may be deleted safely. A trap, fuel exhaustion, deadline, cancellation, invalid response, or host shutdown becomes a typed invocation outcome and failure record.

## Supervised Subprocess Protocol

The subprocess runtime launches only the installed canonical entrypoint through a plugin-specific profile built on the existing platform sandbox and resource-limit machinery. Unlike the built-in process profile, this profile mounts only the executable and required dynamic-loader/runtime files. It does not mount the workspace, user home, Lumen data directory, package schemas, settings files, quarantine, or other plugin artifacts. All workspace filesystem access, including reads, is expressed as a returned action proposal and executed by runtime-owned adapters after authorization. The initial protocol is one bounded invocation per child process. This avoids hidden cross-request state while still defining the protocol later persistent MCP adapters can reuse.

The host writes a four-byte big-endian length followed by one UTF-8 JSON request frame to standard input, then closes input. The child writes exactly one framed JSON response and exits. Frames contain protocol version, request ID, a per-launch 256-bit nonce, component identity, deadline, input, and the common response variant. The nonce is delivered in the request frame, must be echoed, and prevents accidental cross-talk or response substitution inside supervisor plumbing; it is not a trust boundary against the launched plugin itself.

The supervisor enforces:

- A fixed installed executable path and digest recheck before launch.
- Empty inherited environment plus explicitly defined protocol variables.
- A plugin-specific mount profile with no ambient workspace, home, Lumen-data, or package-directory access.
- Existing sandbox guarantees and Unix resource limits.
- Bounded stdin, stdout, stderr, frame, and aggregate output sizes.
- One response, exact request ID and nonce, valid UTF-8 and JSON, and clean protocol framing.
- Deadline and cancellation with process-group termination.
- Distinct crash, nonzero exit, protocol, timeout, cancellation, and resource-exhaustion outcomes.

Diagnostic stderr is redacted and bounded. It is not passed to the model as a successful result. Native plugins receive no workspace write or network access merely because their manifest requests those capabilities; sensitive effects are expressed as returned action proposals and executed by runtime-owned adapters only after authorization.

## Capability Grants

Manifest effect-capability requests use runtime-owned names and canonical scopes. Milestone 3 adds plugin-resource scopes for `plugin.install`, `plugin.enable`, and `plugin.invoke` while reusing existing filesystem, process, secret, and future network scopes for returned proposals.

Invocation authority and effect authority are separate. The authenticated actor, workspace, agent, and run layers must contain an exact `plugin.invoke` capability for the selected plugin version and component before the invocation action can dispatch. That authority does not allow any returned side effect.

For effects, an administrator may grant a strict subset of the manifest request as a global default, and a workspace administrator may narrow it further for that workspace and component. The effective set for a returned proposal is the intersection of:

```text
actor -> workspace -> agent -> run -> global plugin grant -> workspace plugin grant -> component request -> action requirement
```

Grant changes are immutable revisions with canonical hashes. Expanding a grant requires approval and invalidates pending approvals or cached invocation fingerprints that reference the prior grant hash. Narrowing or revoking a grant prevents new child actions immediately and cancels an in-flight invocation when the revoked authority is material to it.

Plugin-defined strings can describe features but cannot create host authority namespaces.

## Scoped Settings

The optional settings schema is a bounded JSON Schema subset validated at installation. Unsupported schema keywords are rejected rather than ignored. Settings support `global`, `workspace`, `user`, and `agent` scopes.

Effective settings merge broadest to narrowest:

```text
global -> workspace -> user -> agent
```

Objects merge recursively only for schema-declared object properties. Scalars and arrays replace the broader value. Unknown keys, type mismatches, invalid secret-reference fields, excessive depth, and excessive serialized bytes are rejected. The canonical effective object and the ordered contributing setting revisions produce the settings digest.

Secret values never enter settings. A schema may mark a field as a Lumen secret reference. The runtime validates the reference metadata and resolves its value only for a separately approved child action with exact `secret.use` authority.

## Provenance And Audit

Every plugin administrative and invocation event records, as applicable:

- Plugin, version, component, and runtime type.
- Package, manifest, artifact, settings, and grant-set digests.
- Source type and staging record ID.
- Workspace, actor, run, parent action, and invocation request IDs.
- Requested and effective capabilities.
- Approval and execution-attempt IDs.
- Sandbox backend and reported guarantees for subprocesses.
- Outcome, systems touched, failure class, and quarantine transition.

Audit records never trust plugin-supplied log text for identity or outcome. Installed artifact verification is repeated at invocation. A mismatch quarantines the version before any plugin byte executes and emits a tamper event.

## Failure Quarantine

Failures are classified as plugin faults, host faults, policy denials, cancellations, or resource exhaustion. Policy denials and user cancellations do not count against plugin health. Traps, crashes, invalid frames, schema-invalid results, and repeated resource exhaustion do. An artifact digest mismatch bypasses health counting and places the immutable version directly into global `artifact_quarantine` because no workspace may safely execute altered bytes.

Counted failures are persisted by workspace, plugin version, component, invocation, class, and timestamp. Three counted failures within a rolling ten-minute window move that workspace version to `health_quarantine` through an atomic transaction. The window survives process restarts because it is computed from persisted rows. Health quarantine stops new invocations in the affected workspace and cancels its active invocations without disabling the version elsewhere. Re-enablement requires a `plugin.quarantine.release` action and begins a new window without deleting failure history. No non-idempotent action is retried automatically.

## API And Control Surface

Authenticated workspace APIs expose:

- Staged package and exact review details.
- Installed plugins, immutable versions, components, and lifecycle state.
- Requested and granted capabilities.
- Scoped settings schemas, current revisions, and validation errors.
- Install, enable, disable, grant-change, setting-change, and quarantine-release requests.

The Svelte control surface adds a work-focused Plugins view. It shows staged reviews, version provenance, artifact hashes, requested versus granted authority, settings by scope, failure history, and enabled/quarantined state. Sensitive changes flow into the existing approval view with action-specific previews. The UI never loads plugin JavaScript, HTML, CSS, remote images, or arbitrary manifest markup.

## Extension SDK

The repository adds `lumen-extension-sdk`, containing:

- Shared manifest identity helpers.
- Generated WIT guest bindings and ergonomic result/proposal types.
- Subprocess frame types and bounded read/write helpers.
- Protocol constants and compatibility checks.
- Example WASM and subprocess tool components used as test fixtures.

The SDK is deliberately small. It does not expose policy internals, database types, runtime service objects, direct filesystem/network/process access, or a way to write audit events. Its public contract is considered stable only after both example runtimes pass the same conformance suite.

## Security Verification

Milestone 3 must prove:

- Strict manifest parsing and canonical package identity.
- Symlink, traversal, file-race, size, duplicate-version, and post-review substitution rejection.
- Transactional installation of an unchanged quarantined package only after exact approval.
- Side-by-side versions with runs pinned to immutable hashes.
- Capability grants cannot exceed requests and revocation prevents new effects.
- Settings merge deterministically, validates against schema, and changes fingerprints.
- WASM components have no ambient WASI authority and stop on memory, fuel, deadline, and cancellation limits.
- Subprocess frames authenticate request correlation, enforce all bounds, and terminate process trees on timeout or cancellation.
- Plugin-returned actions re-enter policy and cannot dispatch directly.
- Artifact/config/grant mutation invalidates approval or quarantines the version.
- Crashes and malformed responses cannot crash Lumen and trigger bounded quarantine.
- Secret values remain absent from plugin input unless an exact approved child action requires them, and remain absent from SQL, API, SSE, model, diagnostic, and audit records.
- Plugin APIs are authenticated and workspace-scoped.
- Desktop and mobile UIs display exact installation, authority, version, and quarantine information without overflow or executing plugin-controlled UI.

The final gate is formatting, strict Clippy, all workspace tests, WASM and subprocess conformance fixtures, Linux sandbox tests in a privileged container, migration-from-Milestone-2 tests, Svelte diagnostics, frontend unit tests, production builds, Playwright desktop/mobile tests, Tauri configuration validation, SDK documentation tests, and diff hygiene.

## Failure Rules

- Unknown manifest or protocol fields fail closed.
- A staged package never executes.
- Installation never implies enablement or capability grants.
- An enabled version without a current exact grant cannot invoke.
- A missing or unavailable runtime denies invocation.
- Artifact, manifest, settings, or grant hash mismatch prevents execution.
- A plugin cannot approve itself, grant itself authority, resolve arbitrary secrets, or write authoritative audit history.
- Audit persistence failure before an administrative or child side effect prevents that effect.
- Uncertain post-dispatch results remain `unknown` and are not retried automatically.
