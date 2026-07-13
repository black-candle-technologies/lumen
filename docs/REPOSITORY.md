# Repository Map

The repository is a Rust workspace with one shared SvelteKit control surface and a least-privilege Tauri package. Milestones 1 and 2 use these existing boundaries; no extra service or privileged helper is required.

## Current Layout

```text
apps/
  web/                    SvelteKit chat, approval, and audit control surface
  desktop/                Command-free Tauri package for the shared web application
crates/
  lumen-core/             Runtime domain types, policy, approvals, orchestration, and budgets
  lumen-db/               SQLite migrations, repositories, audit chain, and recovery
  lumen-integrations/     Local model, filesystem, process, sandbox, and secret-store adapters
  lumen-server/           Authenticated Axum HTTP and SSE transport
  lumen-cli/              Runtime composition and local operator commands
docs/                     Architecture, security, data, and milestone decisions
```

## Ownership

### `crates/lumen-core`

Owns authoritative runtime behavior:

- Structured identities, workspaces, runs, and immutable action envelopes
- Capability intersection and default-deny policy evaluation
- One-shot approval fingerprints and dispatch authorization
- Model and executor ports
- Run orchestration, cancellation outcomes, deadlines, and cumulative budgets
- Audit event construction

It does not depend on Axum, Tauri, SQLx, or a concrete model client.

### `crates/lumen-db`

Owns SQLite implementation details:

- Append-only schema migrations
- Workspace, run, action, approval, execution-attempt, and secret-reference repositories
- Atomic approval consumption and execution reservation
- Tamper-evident audit append and verification
- Conservative crash recovery from incomplete execution to `unknown`

It persists core types but does not grant authority or make policy decisions. SQLite is the only supported database today.

### `crates/lumen-integrations`

Owns adapters with external side effects:

- Loopback OpenAI-compatible model client
- Capability-based workspace reads and approval-bound atomic text replacement
- Process normalization and execution
- Linux bubblewrap and macOS `sandbox-exec` backends
- Process monitoring, output bounds, cancellation, timeouts, and Unix resource limits
- OS keychain and in-memory test secret stores

Adapters receive authorized actions through core contracts. There is no alternate direct-dispatch API. WASM, MCP, and third-party subprocess extension hosts are Milestone 3 work and are not present yet.

### `crates/lumen-server`

Owns the local transport surface:

- Bearer authentication and workspace allowlisting
- Run creation and cancellation
- Pending approval listing and decisions
- Audit listing and sandbox capability reporting
- SSE run-event replay and streaming

Handlers call the composed runtime service. They do not independently authorize or execute tools.

### `crates/lumen-cli`

Owns process composition and operator commands:

- Strict `lumen.toml` loading and fail-closed startup validation
- Database migration and server startup
- Audit-chain verification
- Sandbox capability reporting
- Secret-reference create, list, and delete commands
- Wiring of the model, policy, persistence, approval, executor, secret, and event ports

### `apps/web`

Owns the browser control surface. It provides local chat with cancellation, exact action approvals, audit inspection, and runtime connection settings. File approvals show trusted before/after content, byte counts, hashes, and the canonical fingerprint. Secret-bearing process approvals show reference metadata but never resolve values.

### `apps/desktop`

Packages the shared static web application. The Tauri shell registers no native commands or plugins, disables the global Tauri object, uses an explicit CSP, and grants the fixed `main` window an empty permission set. It is not a second runtime or tool path.

## Dependency Direction

```text
apps/web -> lumen-server HTTP/SSE API
apps/desktop -> bundled apps/web assets
lumen-cli -> lumen-server + lumen-db + lumen-integrations + lumen-core
lumen-server -> lumen-core
lumen-db -> lumen-core
lumen-integrations -> lumen-core
lumen-core -> domain-focused dependencies only
```

Cross-cutting abstractions should be extracted only after an implemented boundary needs independent ownership. The next planned boundary is the Milestone 3 extension protocol, not another path around the runtime kernel.

## Verification Areas

- Core state-machine, policy, approval, quota, and outcome tests live under `crates/lumen-core/tests`.
- SQLite migration, transaction, audit-chain, and recovery tests live under `crates/lumen-db/tests`.
- Filesystem, sandbox, process, model-client, and secret-store tests live under `crates/lumen-integrations/tests` and the sandbox module tests.
- Model-to-HTTP-to-executor security tests live with runtime composition in `crates/lumen-cli/src/runtime/security_tests.rs`.
- Authenticated route contracts live under `crates/lumen-server/tests`.
- Svelte component and Playwright desktop/mobile tests live under `apps/web`.
- Tauri authority-surface tests live under `apps/desktop/src-tauri/tests`.
