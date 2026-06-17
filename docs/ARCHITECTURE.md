# Architecture

Lumen is a local-first AI agent runtime. The web UI is a control surface; the product center is the runtime that coordinates models, tools, plugins, jobs, permissions, and auditability.

## System Shape

The intended system has four main layers:

1. **Runtime core**
   - Orchestrates agent execution.
   - Applies permissions and approval gates.
   - Dispatches plugin and tool calls.
   - Writes audit events.
   - Loads reusable skills.

2. **Model layer**
   - Routes prompts and tool-capable agent loops to available models.
   - Starts with local model runners where practical.
   - Allows pluggable providers over time.
   - Can expose or consume OpenAI-compatible APIs where useful.

3. **Plugin layer**
   - Adds model providers, external chat platforms, local tools, workflow integrations, and custom capabilities.
   - Tracks plugin hashes, permissions, settings, and enabled state in SQL.
   - Makes plugin activity traceable through the audit log.

4. **Web/API layer**
   - Provides chat, scheduled jobs, audit log, and settings.
   - Avoids becoming a broad cloud-style admin dashboard.
   - Talks to the local runtime instead of replacing it.

## Suggested MVP Stack

- **Backend:** Rust with Axum
- **Frontend:** Svelte or SvelteKit
- **Database:** SQLite first
- **Streaming:** Server-sent events for chat output
- **Local model integration:** llama.cpp-compatible server or bindings first
- **Provider abstraction:** trait-based model backend interface

SQLite is the likely first database because it fits the local-first model and keeps setup simple. The schema should avoid SQLite-only assumptions where practical so Postgres compatibility remains possible later.

## Configuration Boundaries

Lumen should use files for host-level boot configuration:

- `lumen.toml`
- `config.yml`
- `.env`

Examples:

- Bind address and port
- Database path or URL
- Log level
- Local model runner path
- Bootstrap admin identity

Lumen should use SQL for runtime product state:

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

The rule of thumb: if the UI/API can mutate it, if it must be audited, or if it may be queried across processes, it belongs in SQL.

## Core Data Areas

Expected early tables or equivalent storage areas:

- `users`
- `allowed_identities`
- `conversations`
- `messages`
- `scheduled_jobs`
- `audit_events`
- `plugins`
- `plugin_versions`
- `plugin_permissions`
- `plugin_settings`
- `model_providers`
- `agent_skills`
- `approval_requests`

Names may change during implementation, but these are the product concepts the schema should cover.

## Agent Skills

Lumen should support reusable skills created from completed workflows. A skill is a repeatable procedure or capability that helps the agent avoid solving the same class of task from scratch each time.

Skill metadata belongs in SQL. Skill source or larger structured content may live on disk if that makes editing and versioning simpler, but the runtime should still index and audit it.

## Open Questions

- What is the exact plugin runtime boundary?
- Which sandboxing mechanism should plugins use?
- What is the first permission model for tools and plugins?
- What is the initial skill file format?
- Should the first database target be SQLite-only or SQLite with Postgres-compatible schema discipline?
- Which model runner integration should be implemented first?
