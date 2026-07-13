# Lumen

Lumen is a local-first AI agent runtime for user-owned infrastructure. It is meant to run close to the user's data, models, tools, projects, and automation logic instead of becoming a large hosted SaaS dashboard.

The core idea is simple: users own the infrastructure, Lumen coordinates it.

## What Lumen Is

Lumen is the local operating layer for personal and small-team AI automation. It connects local models, MCP servers, self-hosted services, plugins, scheduled jobs, audit logs, settings, and reusable agent skills into one inspectable runtime.

It is designed for people who want an AI agent that can do real work without giving up control of their tools, data, or execution environment.

## Principles

- **Local-first:** Default to local models, local services, local storage, and user-owned infrastructure.
- **Safe by default:** Only approved users and channels can interact with the agent. Risky actions should require explicit approval.
- **Auditable:** Every meaningful action should leave a trace: who requested it, what ran, which plugin or tool was involved, and what systems were touched.
- **Extensible:** Plugins are a first-class part of the system, not an afterthought.
- **Verifiable:** Plugin code and configuration should be cryptographically hashed so actions can be tied to the exact capability that performed them.
- **Small web surface:** The web UI exists for control and visibility, not as a sprawling admin product.
- **Skill-building:** Completed workflows can become reusable agent skills, allowing Lumen to improve at repeated work over time.

## Web Surface

The web UI/API should stay intentionally narrow:

- Chat
- Approvals
- Audit log

Lumen can expose web functionality, but the product should not depend on becoming a cloud-hosted automation platform.

## Architecture Direction

The expected MVP direction is:

- Rust backend with Axum
- Svelte or SvelteKit frontend
- SQLite for early runtime state
- Local model runner integration, initially through llama.cpp-compatible server or bindings
- OpenAI-compatible API surface where useful
- SSE streaming for chat responses
- Backend abstraction for model providers
- Plugin system for tools, model routers, providers, chat platforms, and workflows

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for more detail.

## Runtime State

Lumen separates host boot configuration from mutable runtime state.

Host-level boot config belongs in one `lumen.toml`. Environment variables are reserved for bootstrap secrets such as the local bearer token.

Runtime product state belongs in SQL:

- Installed plugins
- Enabled or disabled plugin state
- Plugin hashes
- Plugin permissions
- Plugin settings
- Model provider configs
- Scheduled jobs
- Chat settings
- Audit log
- User allowlist
- Agent skill metadata

The reason is practical: runtime state needs to be queryable, auditable, mutable through UI/API, and shareable across processes or devices.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Plugin System](docs/PLUGIN_SYSTEM.md)
- [Security Model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## Repository Status

Milestone 1, the local runtime kernel, is implemented. It includes strict local configuration, SQLite state and audit chaining, a loopback OpenAI-compatible model client, capability and approval enforcement, constrained file/process execution, authenticated HTTP/SSE APIs, and the chat/approval/audit control surface. Later roadmap milestones remain intentionally unavailable.

## License

No license has been added yet.
