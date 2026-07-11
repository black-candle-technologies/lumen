# Repository Map

The repository is a scaffold. Existing boundaries are useful and should be filled in without adding services prematurely.

## Current Layout

```text
apps/
  web/                    SvelteKit control surface
  desktop/                Tauri desktop package
crates/
  lumen-core/             Empty runtime-core library
  lumen-db/               Empty persistence library
  lumen-integrations/     Empty integration-boundary library
  lumen-server/           Empty HTTP/SSE library
  lumen-cli/              CLI scaffold
docs/                     Product and architecture decisions
```

## Target Ownership

### `crates/lumen-core`

Owns domain types and authoritative runtime behavior:

- Request context and identity types
- Runs, action envelopes, and state machines
- Capability and policy evaluation interfaces
- Approval validation
- Orchestration and budgets
- Executor and model-provider traits
- Audit event construction

It must not depend on Axum, Tauri, SQLx, Wasmtime, or a specific model client.

### `crates/lumen-db`

Owns SQLite implementation details:

- Migrations
- Connection setup
- Repository implementations
- Transactional approval consumption and dispatch reservation
- Audit append and chain verification

It depends on core domain types and implements persistence traits defined at an appropriate boundary. It does not authorize actions.

### `crates/lumen-integrations`

Owns adapters with external side effects:

- OpenAI-compatible local model client
- Built-in filesystem and process executors
- Sandbox backend abstraction and platform implementations
- WASM component host
- Subprocess and MCP protocol supervision
- Future channel adapters

It depends on core contracts. No adapter may bypass the runtime dispatch path.

### `crates/lumen-server`

Owns the transport surface:

- Axum routes and middleware
- Local authentication transport
- Request/response DTOs
- SSE event serialization
- Health and readiness endpoints

Handlers call core application services. They do not query authorization tables to make independent policy decisions.

### `crates/lumen-cli`

Owns process startup and operator commands:

- Configuration loading
- Database migration command
- Server startup
- Audit verification
- Local administration and diagnostics

### `apps/web`

Owns the browser control surface for chat, approvals, audit inspection, and settings. It communicates through `lumen-server` APIs.

### `apps/desktop`

Packages the web control surface and starts or connects to the same runtime. Tauri commands remain narrow and cannot become a second tool-execution path. The current unrestricted opener plugin and absent CSP must be reviewed before desktop distribution.

## Dependency Direction

```text
apps/web -> lumen-server API
apps/desktop -> lumen-server / lumen-cli startup boundary
lumen-cli -> lumen-server + lumen-db + lumen-integrations + lumen-core
lumen-server -> lumen-core
lumen-db -> lumen-core domain contracts
lumen-integrations -> lumen-core domain contracts
lumen-core -> standard/domain-focused dependencies only
```

No new crate is needed for the first vertical slice. A separate policy, protocol, or sandbox crate should be extracted only when its implementation and independent tests make the boundary concrete.
