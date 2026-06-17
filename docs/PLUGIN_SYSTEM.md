# Plugin System

Plugins are central to Lumen. They are how the runtime grows without turning the core into a bundle of one-off integrations.

## What Plugins Can Add

Plugins may provide:

- Model routers
- Model providers
- External chat platform adapters
- Local tools
- Workflow integrations
- Custom agent capabilities
- Scheduled job handlers
- Approval-aware actions

## Requirements

Every plugin should be:

- **Explicitly installed:** The runtime should know what plugin is present and where it came from.
- **Enableable and disableable:** Installed does not always mean active.
- **Permissioned:** Plugins should only access the capabilities they have been granted.
- **Audited:** Meaningful plugin actions should appear in the audit log.
- **Hashed:** Lumen should record cryptographic hashes for plugin code/config involved in an action.
- **Configurable by scope:** Settings may vary globally, by user, by workspace, or by agent.

## Plugin Identity

A plugin should have a stable identity independent of its local directory name. At minimum, plugin metadata should include:

- Plugin ID
- Human-readable name
- Version
- Description
- Entrypoint or runtime type
- Declared permissions
- Hash or hash set

The exact manifest format is still open.

## Scoped Settings

Plugin settings should support scoped configuration. A likely table shape:

```sql
CREATE TABLE plugin_settings (
  plugin_id TEXT NOT NULL,
  scope_type TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  config TEXT NOT NULL,
  config_version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT NOT NULL,
  UNIQUE (plugin_id, scope_type, scope_id)
);
```

Expected `scope_type` values:

- `global`
- `user`
- `workspace`
- `agent`

This allows one plugin to behave differently for different users, workspaces, agents, or default system settings.

## Audit Events

Plugin-related audit events should capture:

- Plugin ID
- Plugin version
- Plugin hash
- Requesting user or channel
- Agent or job that invoked the plugin
- Permission checked
- Action attempted
- Result
- Systems touched
- Approval request ID, when relevant

The audit trail should make it possible to answer: "What code or configuration caused this action?"

## Runtime Boundary

The plugin execution boundary is still undefined. Options include:

- In-process Rust plugins for maximum performance and tight integration
- Subprocess plugins for a clearer fault and security boundary
- WASM plugins for portable sandboxing
- MCP servers as plugin-backed external tools

The early implementation should choose the smallest boundary that supports safe local automation without making future sandboxing impossible.
