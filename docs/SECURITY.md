# Security Model

Lumen assumes that useful agents routinely process hostile content and occasionally produce incorrect or unsafe actions. Safety therefore comes from runtime-enforced authority boundaries, not from asking a model or plugin to behave safely.

## Security Goals

- Accept requests only from authenticated and allowed identities and channels.
- Grant least authority by workspace, actor, agent, plugin, tool, and resource.
- Require meaningful approval for risky actions.
- Prevent models and extensions from bypassing policy enforcement.
- Keep local data local unless an explicit egress policy permits disclosure.
- Limit the impact of compromised or malicious extensions.
- Produce an attributable and tamper-evident history of meaningful activity.
- Fail closed when identity, policy, approval, sandbox, or audit prerequisites are unavailable.

## Threat Model

### In scope

Lumen is designed to resist or contain:

- Prompt injection in websites, files, messages, email, and retrieved context
- Malicious or malformed model output
- A model attempting to exceed the user's request
- Malicious, compromised, or vulnerable third-party plugins and skills
- Unauthorized inbound users, channels, or service identities
- Authenticated users attempting actions outside their workspace authority
- Cross-workspace data disclosure through runtime APIs or stored state
- Plugin supply-chain substitution or unreviewed upgrades
- Secret disclosure through prompts, logs, tool results, URLs, or process environments
- Network access outside an action's declared destination scope
- Filesystem access outside declared workspace paths
- Approval replay, mutation after approval, and time-of-check/time-of-use mistakes
- Runaway tools, process trees, output floods, and resource exhaustion within configured limits

### Out of scope

Lumen does not protect against:

- A compromised operating-system kernel
- A malicious or compromised operating-system administrator
- An attacker with unrestricted access as the operating-system account running Lumen
- Physical attacks on an unlocked machine
- Hardware, firmware, hypervisor, or CPU compromise
- Denial of service against dependencies outside Lumen's control

Lumen still avoids unnecessary privilege and protects stored secrets at rest where the platform permits, but it does not claim a security boundary against the host that owns the process.

## Trust Assumptions

Trusted components are limited to:

- The Lumen runtime core and its compiled-in policy enforcement
- The active policy and boot configuration selected by an authorized administrator
- The configured local secret-store implementation
- The operating system under the out-of-scope assumptions above

Models, provider endpoints, plugins, skills, external content, channel payloads, browser content, and tool results are untrusted.

## Identity And Workspaces

Every request has a structured identity containing provider, stable subject ID, channel identity where applicable, and authenticated attributes. Display names are never authorization identifiers.

Authorization is workspace-scoped:

- Unknown identities and channels are denied by default.
- Membership and role do not automatically grant tool capabilities.
- Channel adapters must authenticate before constructing a core request.
- Forwarded identity assertions require a configured trusted proxy.
- Local desktop access does not imply administrator authority.
- Service identities used by scheduled jobs have explicit grants and owners.

The initial release supports a local identity and one or more workspaces, but not hostile multi-tenant isolation between operating-system accounts.

## Capability Model

Permissions are structured capabilities, not free-form strings interpreted by plugins. A capability contains:

- Namespace and operation, such as `fs.read`, `process.spawn`, or `net.connect`
- Resource scope, such as a canonical path, executable digest, or destination origin
- Principal scope, such as user, workspace, agent, plugin, or job
- Constraints, such as read-only access, argument patterns, byte limits, or expiry
- Provenance identifying who granted it and under which policy version

The effective capability set is the intersection of actor, workspace, agent, plugin, tool, and run constraints. A plugin's manifest declaration is a request for authority, not a grant.

Initial capability namespaces are:

- `fs.read`, `fs.write`, and `fs.delete`
- `process.spawn`
- `net.connect`
- `secret.use`
- `message.send`
- `schedule.create` and `schedule.modify`
- `plugin.install`, `plugin.update`, and `plugin.enable`
- `policy.modify`

Capabilities are deny-by-default and must be checked again immediately before execution.

## Approval Model

Approvals supplement policy; they do not replace it. The approval screen must show the actual effect rather than a vague risk label.

An approval binds:

- The canonical action type and normalized arguments
- Resource identifiers, paths, command, working directory, and destination as applicable
- Relevant environment names, excluding secret values
- Hashes of referenced scripts or files when their contents determine the action
- Plugin ID, version, executable hash, and effective configuration hash
- Requesting identity, workspace, run, and policy version
- Creation time, expiry, and allowed use count

The runtime recomputes this fingerprint immediately before execution. Any material change invalidates the approval. Approval is one-shot by default. Reusable grants require an explicit narrow scope and expiration.

Approval is mandatory by default for writes outside a disposable workspace, process execution, external messages, plugin changes, permission changes, recurring jobs, destructive operations, and remote-system mutations.

## Prompt Injection And Confused Deputies

Lumen assumes that content can instruct the model to misuse legitimate capabilities. Content-origin labels are retained when context is assembled, but labels and prompt warnings are advisory rather than enforcement.

Defenses are structural:

- Retrieved content cannot grant capabilities.
- A model cannot approve its own action.
- Tool results cannot alter policy or approval state.
- The runtime evaluates the authenticated principal and intended resource, not only the model's proposed tool name.
- Sensitive actions require an exact action preview and, where policy requires, human confirmation.
- Secrets are resolved after policy evaluation so they need not enter model context.
- Results are bounded and treated as untrusted on re-entry into the agent loop.

## Isolation And Resource Control

Built-in process actions run through a supervised subprocess boundary. The sandbox backend reports its effective guarantees through the authenticated runtime API and CLI. Boot configuration requires a minimum strength, and process execution is denied if the active backend cannot meet it.

On Linux, Lumen uses bubblewrap only from fixed system paths and requires the complete Milestone 2 profile to start. That profile creates user, mount, PID, IPC, UTS, cgroup, and network namespaces; drops Linux capabilities; clears the environment; exposes the executable and workspace read-only; creates private process, device, and temporary mounts; starts a new session; and requests parent-death cleanup. Network access remains unavailable inside the isolated network namespace.

On macOS, Lumen uses the system `sandbox-exec` backend and reports its smaller filesystem, workspace-read-only, network, executable, and environment guarantee set. Other platforms currently report the sandbox as unavailable. Lumen does not claim seccomp or Landlock enforcement in the current implementation.

Third-party extensions run outside the runtime process. WASM components are instantiated without WASI imports and are bounded by component validation, fuel, memory limits, deadlines, cancellation, and response-size checks. Supervised subprocess plugins run through the plugin sandbox profile with a minimal environment, digest recheck, one framed request/response exchange, nonce and request correlation, output bounds, deadlines, cancellation, and no ambient workspace, home, network, package-directory, or secret authority.

Each action receives explicit limits for:

- Wall-clock deadline
- CPU and memory where supported
- Output bytes
- Filesystem roots and access modes
- Network destinations
- Child-process creation
- Environment variables
- Cancellation and process-tree termination

The process monitor enforces wall-clock and captured-output bounds on every supported Unix backend. It also applies CPU, file-size, open-file, and process-count rlimits; Linux additionally applies an address-space limit. Cancellation, timeout, output exhaustion, failure, and unknown outcomes remain distinct in persisted state and audit events.

## Network Egress

Network access is a capability. It is disabled for sandboxed actions unless granted for explicit destination origins. Policy evaluates normalized scheme, host, port, and resolved-address constraints and defends against redirects and DNS rebinding at connection time.

Remote model requests are network egress and follow [Model Routing](MODEL_ROUTING.md). Loopback is not automatically trusted: local services still require an explicit endpoint configuration.

## Secrets

The first implementation uses the operating-system keychain through a `SecretStore` interface. SQL and configuration contain opaque secret references only. Environment variables are permitted only to bootstrap the secret store or for explicitly configured development use.

Executors request a secret by reference after policy and approval checks and verify its workspace, executable, and destination environment name. Values are scoped to one action, omitted from normalized actions and approval responses, and redacted from model input, captured output, SSE events, SQL state, and audit payloads. Approval responses expose only an opaque reference ID, operator label, and destination environment name. Redaction is defense in depth, not permission to expose secrets broadly.

## Policy Administration

Policy changes are authenticated, authorized, approved when they expand authority, versioned, and audited. Runs retain the policy version and decision record used for every action. Revocation prevents new actions immediately; running actions are cancelled when the revoked capability is material to their execution.

## Failure Behavior

Lumen fails closed when it cannot authenticate a request, load policy, verify an approval, satisfy a required sandbox profile, access required audit persistence, or resolve a scoped secret. A crash after dispatch but before outcome recording is represented as an `unknown` outcome and is never automatically retried unless the action is declared idempotent.

## Security Validation

Security-sensitive code requires tests for deny-by-default behavior, scope intersection, approval mutation and replay, path canonicalization, secret redaction, audit continuity, crash recovery, and resource-limit enforcement. The current suite includes end-to-end tests from model output through authenticated HTTP approval and executor dispatch, extension staging and installation substitution tests, schema and protocol fuzz cases, WASM and subprocess host conformance tests, plugin artifact tamper quarantine, grant revocation cancellation, rolling health quarantine, side-by-side upgrades, Linux and macOS sandbox contract tests where available, process-tree cancellation and timeout tests, exact resource-limit tests on Linux-capable targets, and desktop configuration contract tests.

The remaining Milestone 3 completion gate is privileged Linux plugin-sandbox verification in a Linux container or equivalent CI Linux target. The local macOS run proves the macOS sandbox path and platform-independent Linux profile construction tests, but it does not replace that Linux execution gate.
