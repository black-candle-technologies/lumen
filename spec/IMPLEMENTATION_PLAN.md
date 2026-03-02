# Lumen — Implementation Plan

**Version:** 1.0
**Date:** 2026-03-02
**Status:** Draft
**Tracks:** [spec/PRD.md](PRD.md)

---

## Overview

This document translates the Lumen PRD into a phase-by-phase engineering plan. Each phase maps directly to a PRD milestone (§9) and references the PRD feature sections it implements. Within each phase, work is broken into discrete work packages with clear inputs, outputs, and acceptance criteria.

### Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| Language | TypeScript (Node.js ≥ 22) | Maximizes contributor accessibility; fast iteration; wide ecosystem for messaging SDKs and LLM client libraries |
| Runtime | Node.js with ESM modules | Native async I/O for WebSocket + HTTP; single binary via `pkg` or `sea` for distribution |
| Database | SQLite via `better-sqlite3` | Zero-dependency embedded DB; single-file storage; sufficient for single-instance agent workloads; no external service to manage |
| Embedding | `onnxruntime-node` with MiniLM-L6 | Local embedding for memory retrieval with zero API cost |
| Token counting | `tiktoken` (js port) | Accurate token estimation for budget accounting |
| Package manager | pnpm | Fast installs; strict dependency resolution |
| Test framework | Vitest | Fast; native ESM and TypeScript support |
| Linting | Biome | Single tool for format + lint; fast; zero-config defaults |
| Process management | systemd (Linux) / launchd (macOS) | Native OS daemon management; auto-restart; logging integration |
| Browser automation | Playwright | Managed Chromium lifecycle; CDP access; accessibility tree snapshots |

### Repository Structure (Target)

```
lumen/
├── spec/                        # PRD, implementation plan, ADRs
├── src/
│   ├── gateway/                 # Daemon lifecycle, HTTP/WS server, health
│   ├── agent/                   # Agent runtime loop, turn execution
│   ├── context/                 # Context engine, token budgeting, compaction
│   ├── memory/                  # Persistent memory store, retrieval, lifecycle
│   ├── providers/               # LLM provider adapters
│   │   ├── anthropic.ts
│   │   ├── openai.ts
│   │   ├── google.ts
│   │   ├── ollama.ts
│   │   ├── chitin.ts
│   │   └── base.ts             # Provider interface + fallback chain
│   ├── channels/                # Messaging platform adapters
│   │   ├── telegram.ts
│   │   ├── slack.ts
│   │   ├── discord.ts
│   │   └── base.ts             # Channel interface + message normalization
│   ├── tools/                   # Tool executor, sandbox, built-in tools
│   │   ├── filesystem.ts
│   │   ├── shell.ts
│   │   ├── browser.ts
│   │   ├── http.ts
│   │   ├── cron.ts
│   │   ├── vision.ts
│   │   └── executor.ts         # Approval gates, output budgeting, audit log
│   ├── skills/                  # Skill loader, registry, signing, injection
│   ├── security/                # Auth, secrets, origin validation, audit log
│   ├── config/                  # Configuration loading, validation, defaults
│   ├── storage/                 # SQLite schema, migrations, queries
│   ├── cli/                     # CLI entry point, subcommands
│   └── index.ts                 # Main entry point
├── skills/                      # Built-in skills (shipped with Lumen)
├── migrations/                  # SQLite migration files
├── test/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── docker/
│   ├── Dockerfile
│   └── docker-compose.yml
├── scripts/                     # Install wizards, service file generators
├── package.json
├── tsconfig.json
├── biome.json
└── vitest.config.ts
```

---

## Phase 0: V0.1 — Foundation (Q2 2026)

**PRD milestone:** V0.1 — Gateway daemon, context engine, provider layer (Anthropic + Ollama), CLI, SQLite storage, encrypted secrets

**Goal:** A running gateway daemon that can receive a message via CLI, route it to an LLM provider, execute a simple agent turn, and return a response. No channels, no tools, no skills — just the core loop.

---

### 0.1 Project Scaffold

**PRD ref:** §7 Technical Architecture

**Work:**
- Initialize pnpm workspace with TypeScript, ESM, Vitest, Biome
- Set up `src/` directory structure per repository layout above
- Configure CI (GitHub Actions): lint, typecheck, test on every PR
- Create `scripts/dev.ts` for local development with watch mode

**Acceptance criteria:**
- `pnpm lint`, `pnpm typecheck`, `pnpm test` all pass on an empty project
- CI runs on push to `main` and on PRs

---

### 0.2 SQLite Storage Layer

**PRD ref:** §4.1 (persistent state), §7 (SQLite in architecture diagram)

**Work:**
- Set up `better-sqlite3` with a `storage/` module
- Implement migration runner (sequential numbered SQL files in `migrations/`)
- Create initial schema:

```sql
-- Configuration
CREATE TABLE config (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

-- Sessions
CREATE TABLE sessions (
  session_id    TEXT PRIMARY KEY,
  channel_type  TEXT NOT NULL DEFAULT 'cli',
  channel_id    TEXT NOT NULL DEFAULT 'local',
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Session messages (full conversation history)
CREATE TABLE messages (
  message_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id    TEXT NOT NULL REFERENCES sessions(session_id),
  role          TEXT NOT NULL CHECK (role IN ('system', 'user', 'assistant', 'tool')),
  content       TEXT NOT NULL,
  token_count   INTEGER,
  pinned        INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Token usage ledger
CREATE TABLE token_events (
  event_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id    TEXT NOT NULL REFERENCES sessions(session_id),
  request_id    TEXT NOT NULL,
  provider      TEXT NOT NULL,
  model         TEXT NOT NULL,
  input_tokens  INTEGER NOT NULL DEFAULT 0,
  output_tokens INTEGER NOT NULL DEFAULT 0,
  cost_usd      REAL NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Audit log
CREATE TABLE audit_log (
  log_id        INTEGER PRIMARY KEY AUTOINCREMENT,
  event_type    TEXT NOT NULL,
  actor         TEXT NOT NULL DEFAULT 'system',
  detail        TEXT,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Encrypted secrets
CREATE TABLE secrets (
  key           TEXT PRIMARY KEY,
  value_enc     BLOB NOT NULL,
  nonce         BLOB NOT NULL,
  created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
```

- Implement typed query helpers: `db.getSession()`, `db.appendMessage()`, `db.logTokenEvent()`, etc.

**Acceptance criteria:**
- Migrations run idempotently on fresh and existing databases
- Unit tests for all query helpers
- Database file created at `~/.lumen/lumen.db` by default (configurable)

---

### 0.3 Configuration System

**PRD ref:** §4.5 (provider config), §4.9 (secure defaults)

**Work:**
- Implement config loading: `~/.lumen/lumen.json` with environment variable overrides
- Define config schema with TypeScript types and runtime validation (Zod)
- Ship sensible defaults:
  - `gateway.host`: `127.0.0.1`
  - `gateway.port`: `18800`
  - `providers`: empty (must be configured by user)
  - `context.softThresholdFraction`: `0.80`
  - `context.hardThresholdFraction`: `0.90`
  - `context.toolOutputMaxTokens`: `32768`
  - `context.memoryBudgetTokens`: `4096`
  - `budgets.perDayTokens`: `null` (unlimited by default; user sets)
  - `budgets.perSessionTokens`: `null`
- Implement `lumen config show` and `lumen config set <key> <value>` CLI commands

**Acceptance criteria:**
- Invalid config rejected with clear error message listing the issue
- Config file created with defaults on first run if absent
- Environment variables override file values (`LUMEN_GATEWAY_PORT=9000`)

---

### 0.4 Encrypted Secrets Store

**PRD ref:** §4.9 Security Architecture (encrypted secret storage)

**Work:**
- Implement AES-256-GCM encryption using Node.js `crypto` module
- Key derivation from user passphrase via `scrypt` (or system keychain via `keytar` when available)
- CLI commands: `lumen secrets set <name>`, `lumen secrets list`, `lumen secrets delete <name>`
- Provider API keys stored as secrets, never in plaintext config
- First-run wizard prompts for passphrase or keychain setup

**Acceptance criteria:**
- Secrets stored in `secrets` table as encrypted blobs
- `lumen secrets list` shows names but never values
- Passphrase change re-encrypts all stored secrets
- Unit tests verify round-trip encrypt/decrypt

---

### 0.5 Provider Layer — Base + Anthropic + Ollama

**PRD ref:** §4.5 Model-Agnostic Provider System

**Work:**
- Define `Provider` interface:

```typescript
interface Provider {
  id: string;
  models(): Promise<ModelInfo[]>;
  chat(request: ChatRequest): AsyncIterable<ChatChunk>;
  countTokens(messages: Message[]): Promise<number>;
}

interface ModelInfo {
  id: string;
  contextWindow: number;
  supportsToolUse: boolean;
  inputPricePerMTok: number;
  outputPricePerMTok: number;
}
```

- Implement `AnthropicProvider` using `@anthropic-ai/sdk`:
  - Streaming chat completions
  - Tool use support
  - Token counting via API
  - Model listing with context window discovery
- Implement `OllamaProvider` using HTTP API:
  - Streaming chat completions
  - Model listing with context window from `/api/show`
  - Token estimation via `tiktoken` (Ollama doesn't expose token counts)
- Implement fallback chain logic in `providers/base.ts`:
  - Ordered list of providers per config
  - On error: classify as retryable (429, 5xx) vs. fatal (401, 403) vs. billing (402)
  - Retryable: jittered exponential backoff (1s, 2s, 4s) then failover to next provider
  - Surface accurate error type to caller
- Auth profile rotation: if a provider has multiple API keys configured, rotate round-robin on each request

**Acceptance criteria:**
- Integration test: Anthropic provider sends a message and streams a response (requires API key; skipped in CI without key)
- Integration test: Ollama provider sends a message to a local model
- Unit test: fallback chain correctly fails over on 429, retries with backoff
- Unit test: 402 surfaced as billing error, not rate limit

---

### 0.6 Token Accounting

**PRD ref:** §4.2 (token budget system), §4.5 (cost tracking, spend caps)

**Work:**
- Implement `TokenAccountant` class:
  - Counts tokens for each message using provider's tokenizer (or `tiktoken` fallback)
  - Logs every LLM call to `token_events` table with input/output counts, model, provider, cost
  - Tracks cumulative session and daily totals in memory (backed by DB queries)
- Implement budget enforcement:
  - Before each LLM call, check session and daily budgets
  - If `warn` threshold crossed: log warning, add to session metadata
  - If `block` threshold crossed: reject the call, surface error to user
- Cost calculation: maintain pricing table per provider/model (loaded from config, updatable)
- Implement `lumen usage` CLI command: show token usage and cost by session, day, model

**Acceptance criteria:**
- Every LLM call produces a `token_events` row
- Token counts within 5% of provider-reported counts
- Budget `block` prevents the LLM call and returns a clear error
- `lumen usage` shows accurate daily/session breakdown

---

### 0.7 Context Engine

**PRD ref:** §4.2 Adaptive Context Engine

**Work:**
- Implement `ContextEngine` class:
  - On each turn, assemble the full prompt: system prompt + memory injection slot + conversation history + tool schemas
  - **Token budget allocation:**
    ```
    contextWindow         = provider.models()[selectedModel].contextWindow
    reserveForReply       = config.context.reserveForReply (default: 4096)
    systemPromptBudget    = measured (system prompt tokens)
    memoryBudget          = config.context.memoryBudgetTokens (default: 4096)
    toolSchemaBudget      = measured (active tool schemas)
    historyBudget         = contextWindow - reserveForReply - systemPromptBudget - memoryBudget - toolSchemaBudget
    ```
  - **Preflight check**: before every LLM call, measure assembled prompt tokens. If > `softThreshold`, trigger compaction before sending
  - **Tool output guardrails**: when a tool result exceeds `toolOutputMaxTokens`, truncate with `[...truncated, N tokens omitted]` marker. (Auto-summarization deferred to Phase 2 when memory system is available.)
  - **Context usage reporting**: emit current usage as a percentage after each turn (`{ usedTokens, budgetTokens, percentage }`)
- Implement graduated compaction:
  1. **Persist full session**: write all messages to `messages` table before compacting (compaction safety)
  2. **Drop redundant messages**: remove exact-duplicate messages, collapse consecutive identical tool calls
  3. **Oldest-first summarization**: call a lightweight model (Haiku or cheapest available) to summarize the oldest N messages into a single summary message; preserve pinned messages and the last K verbatim messages (default K=10)
  4. Replace the compacted messages in the session's in-memory history
- Support context windows from 16K to 1M+: all thresholds are fractions, never absolute values

**Acceptance criteria:**
- Unit test: assembled prompt stays within budget for various context window sizes (16K, 128K, 200K, 1M)
- Unit test: preflight check triggers compaction when threshold crossed
- Unit test: tool output exceeding cap is truncated
- Unit test: compaction preserves pinned messages and last K messages
- Unit test: full session persisted to DB before compaction runs
- Context percentage is monotonically increasing between compaction events (no erratic jumps)

---

### 0.8 Agent Runtime

**PRD ref:** §4.1 (agent runtime within gateway), §7 (Agent Runtime in architecture diagram)

**Work:**
- Implement `AgentRuntime` class — the core agent loop:
  1. Receive user message (from CLI or channel adapter)
  2. Resolve session (create or load from DB)
  3. Call `ContextEngine.assemble()` to build the prompt
  4. Call `Provider.chat()` to get the model response (streaming)
  5. If response contains tool calls: execute via `ToolExecutor` (Phase 2), append results, loop back to step 3
  6. If response is a text reply: append to session, return to caller
  7. Log token usage via `TokenAccountant`
- Implement session management:
  - Sessions keyed by `(channel_type, channel_id)` — e.g., `('cli', 'local')`, `('telegram', 'chat_12345')`
  - Session history loaded from DB on first access, kept in memory for the session's lifetime
  - Session persisted to DB on every message append
- Tool call loop has a configurable max iterations (default: 25) to prevent runaway loops

**Acceptance criteria:**
- End-to-end test: CLI sends a message, agent returns a response from Anthropic
- Agent loop terminates after max iterations with a clear message
- Session history persisted and reloadable across gateway restarts

---

### 0.9 Gateway Daemon

**PRD ref:** §4.1 Gateway — Persistent Agent Runtime

**Work:**
- Implement HTTP server (`fastify` or `node:http`) listening on `gateway.host:gateway.port`:
  - `GET /health` — returns `{ status: "ok", uptime, version }`
  - `GET /api/sessions` — list active sessions
  - `GET /api/sessions/:id` — session detail with message count, token usage
  - `POST /api/sessions/:id/messages` — send a message to a session (used by channel adapters and CLI)
  - `GET /api/usage` — token usage summary
  - `GET /api/config` — current config (secrets redacted)
- Implement WebSocket server on the same port:
  - Origin validation: reject connections from origins not in `gateway.allowedOrigins` (default: none; local connections exempt)
  - Used by companion apps and Web UI (future phases)
- Daemon lifecycle:
  - Graceful shutdown: drain in-flight requests (30s timeout), persist all sessions, close DB
  - Startup: run migrations, load config, validate secrets, start HTTP/WS server
  - Health monitoring: log heartbeat every 60s; expose uptime in `/health`
- Generate systemd unit file and launchd plist via `lumen install-service`

**Acceptance criteria:**
- Gateway starts and listens on configured port
- `/health` returns 200 with uptime
- Graceful shutdown completes without data loss
- `lumen install-service` generates correct systemd/launchd config
- WebSocket connection from non-allowlisted origin rejected with 403
- Gateway starts on headless Linux server with no GUI dependencies

---

### 0.10 CLI

**PRD ref:** §4.1 (CLI access), §4.10 (CLI as companion)

**Work:**
- Implement CLI entry point using `commander` or `citty`:
  - `lumen start` — start gateway daemon (foreground or daemonized)
  - `lumen stop` — stop running gateway
  - `lumen status` — show gateway health, uptime, active sessions
  - `lumen chat [--session <id>]` — interactive chat session (sends to gateway API)
  - `lumen send <message> [--session <id>]` — send a single message, print response
  - `lumen config show` / `lumen config set <key> <value>`
  - `lumen secrets set <name>` / `lumen secrets list` / `lumen secrets delete <name>`
  - `lumen usage [--day|--session <id>]`
  - `lumen install-service` — generate and install system service
  - `lumen setup` — first-run wizard (provider config, secrets, service install)
- Lazy-load modules: `lumen chat` only loads the chat module, not the full gateway stack. Keeps CLI responsive on low-power hardware.

**Acceptance criteria:**
- `lumen setup` takes a new user from zero to a working agent in < 5 minutes
- `lumen chat` provides an interactive REPL with streaming response display
- CLI starts in < 2 seconds on Raspberry Pi 4
- `lumen --help` documents all commands

---

### 0.11 Docker Support

**PRD ref:** §6.5 (Docker setup fails out of the box)

**Work:**
- Multi-stage Dockerfile: build stage (TypeScript compile) → production stage (Node.js slim)
- `docker-compose.yml` with:
  - Lumen gateway service
  - Volume mount for `~/.lumen` (config, DB, secrets)
  - Health check using `/health` endpoint
- First-run detection: if config file is missing, print setup instructions and exit cleanly (not crash)
- CI job: build Docker image and run smoke test (`lumen status`) on every merge to `main`

**Acceptance criteria:**
- `docker compose up` starts the gateway on a fresh machine with no pre-existing config
- Container logs are clean (no crash loops, no missing dependency errors)
- Data persists across container restarts via volume

---

## Phase 1: V0.2 — Channels (Q3 2026)

**PRD milestone:** V0.2 — Telegram, Slack, Discord adapters; session isolation; message normalization

**Goal:** Users can message their Lumen agent through Telegram, Slack, or Discord and receive responses in the same channel.

---

### 1.1 Channel Adapter Interface

**PRD ref:** §4.4 Multi-Channel Messaging

**Work:**
- Define `ChannelAdapter` interface:

```typescript
interface ChannelAdapter {
  id: string;                                          // e.g., 'telegram', 'slack'
  start(): Promise<void>;                              // connect to platform
  stop(): Promise<void>;                               // disconnect gracefully
  onMessage(handler: (msg: InboundMessage) => void): void;
  send(channelId: string, message: OutboundMessage): Promise<DeliveryResult>;
}

interface InboundMessage {
  channelType: string;
  channelId: string;
  senderId: string;
  content: NormalizedContent;                           // text, images, files
  raw: unknown;                                        // platform-specific payload
  timestamp: Date;
}

interface OutboundMessage {
  content: NormalizedContent;
  replyTo?: string;                                    // platform message ID
}

interface DeliveryResult {
  success: boolean;
  platformMessageId?: string;
  error?: string;
}

interface NormalizedContent {
  text?: string;
  images?: { url: string; mimeType: string }[];
  files?: { url: string; name: string; mimeType: string }[];
}
```

- Implement message normalization: convert platform-specific formats (Slack blocks, Discord embeds, Telegram HTML) to `NormalizedContent` and back
- Implement session routing: map `(channelType, channelId)` to a session; create new session on first message
- Implement secure DM mode: when enabled, session key becomes `(channelType, channelId, senderId)` so different senders in the same channel get isolated sessions
- **Delivery status tracking**: `send()` returns `DeliveryResult`; failed sends are logged and surfaced to the agent as a system message

**Acceptance criteria:**
- Unit test: normalization round-trip for text, images, and files
- Unit test: session routing creates isolated sessions per channel
- Unit test: secure DM mode isolates per sender
- Failed sends produce a user-visible error, not silent drop

---

### 1.2 Telegram Adapter

**PRD ref:** §4.4 (Telegram)

**Work:**
- Implement using `grammY` library
- Support: text messages, photos, documents, inline replies
- Map Telegram chat ID to Lumen channel ID
- Handle bot commands: `/start`, `/new` (new session), `/compact` (trigger compaction)
- Long-polling by default; webhook mode configurable for VPS deployments

**Acceptance criteria:**
- Send a message to the Telegram bot; receive agent response in same chat
- Photos sent to bot are passed to agent as images
- `/new` starts a fresh session

---

### 1.3 Slack Adapter

**PRD ref:** §4.4 (Slack)

**Work:**
- Implement using `@slack/bolt`
- Support: text messages, file uploads, threaded replies
- Map Slack channel + thread to Lumen session
- Handle Slack threading: responses to a thread stay in that thread
- App mention (`@Lumen`) triggers the agent; DMs are always active
- Handle workspace events gracefully (channel archive, member removal)

**Acceptance criteria:**
- DM the Slack app; receive agent response
- Mention `@Lumen` in a channel; response appears in thread
- File upload in DM is passed to agent as file attachment
- Reply failure (e.g., channel archived) surfaces a clear error in logs

---

### 1.4 Discord Adapter

**PRD ref:** §4.4 (Discord)

**Work:**
- Implement using `discord.js`
- Support: text messages, attachments, thread replies
- Map Discord channel ID to Lumen session; threads get separate sessions
- Bot responds to DMs and mentions
- Handle Discord-specific limits (2000 char message limit: split long responses)

**Acceptance criteria:**
- DM the Discord bot; receive agent response
- Mention in a channel starts a thread with the response
- Long responses are split across multiple messages

---

### 1.5 Channel Lifecycle Management

**PRD ref:** §4.4 (channel adapters are plugins)

**Work:**
- Gateway loads enabled channel adapters from config on startup
- Adapters are started/stopped independently; one adapter crashing does not take down others
- `GET /api/channels` — list connected channels with status (connected, disconnected, error)
- `POST /api/channels/:id/restart` — restart a specific adapter
- Config hot-reload: adding a new channel to config triggers adapter start without gateway restart

**Acceptance criteria:**
- Gateway starts with Telegram + Slack; Discord adapter failure does not affect others
- `/api/channels` shows per-adapter connection status
- Adding a Discord config and calling restart connects the new adapter

---

## Phase 2: V0.3 — Memory & Tools (Q3 2026)

**PRD milestone:** V0.3 — Persistent memory system, file/shell/browser tools, tool sandboxing, spend caps

**Goal:** The agent can remember things across sessions and use tools to interact with the local system.

---

### 2.1 Persistent Memory Store

**PRD ref:** §4.3 Structured Memory System

**Work:**
- Extend SQLite schema:

```sql
-- Memory entries
CREATE TABLE memories (
  memory_id     INTEGER PRIMARY KEY AUTOINCREMENT,
  content       TEXT NOT NULL,
  embedding     BLOB,                                  -- float32 vector, serialized
  memory_type   TEXT NOT NULL DEFAULT 'fact',           -- 'fact', 'preference', 'procedure', 'context'
  source        TEXT NOT NULL DEFAULT 'agent',          -- 'agent', 'user', 'compaction'
  access_count  INTEGER NOT NULL DEFAULT 0,
  expires_at    TEXT,                                   -- optional expiry
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Relational edges between memories
CREATE TABLE memory_relations (
  from_id       INTEGER NOT NULL REFERENCES memories(memory_id),
  to_id         INTEGER NOT NULL REFERENCES memories(memory_id),
  relation_type TEXT NOT NULL,                          -- 'related_to', 'contradicts', 'supersedes', 'part_of'
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  PRIMARY KEY (from_id, to_id, relation_type)
);
```

- Implement `MemoryManager` class:
  - `store(content, type, relations?)` — compute embedding, write to DB
  - `retrieve(query, topK, maxTokens)` — compute query embedding, find top-K by cosine similarity, cap total tokens
  - `forget(memoryId)` — soft delete
  - `decay()` — periodic job to reduce ranking score of stale, unaccessed memories
- Embedding via `onnxruntime-node` with MiniLM-L6 model (bundled, ~22MB)
- Cosine similarity computed in-process over the `memories` table (SQLite is fast enough for thousands of memories; index not needed until > 100K entries)

**Acceptance criteria:**
- Store a memory; retrieve it by semantic query
- Top-K retrieval respects `maxTokens` budget
- Memories persist across gateway restarts
- Access count increments on each retrieval
- Expired memories excluded from retrieval
- Relational edges queryable (e.g., "all memories related to memory X")

---

### 2.2 Memory-Context Integration

**PRD ref:** §4.3 (memory injection), §4.2 (memory flush on compaction)

**Work:**
- On each agent turn, `ContextEngine` calls `MemoryManager.retrieve()` with the current user message as query
- Retrieved memories injected into prompt in a `## Relevant Memory` block between system prompt and conversation history
- Memory budget enforced: total injected memory tokens ≤ `config.context.memoryBudgetTokens`
- **Memory flush on compaction**: before context compaction runs, insert a system-level turn asking the agent to extract key facts, then call `MemoryManager.store()` with each extracted fact
- User-initiated memory: agent recognizes explicit "remember this" requests and stores them
- CLI commands: `lumen memory list`, `lumen memory search <query>`, `lumen memory forget <id>`

**Acceptance criteria:**
- Agent uses relevant memories in its responses (verified in integration test)
- Compaction triggers memory extraction before discarding old messages
- `lumen memory search "user's favorite language"` returns relevant memories
- Memory injection does not exceed budget even with 1000+ stored memories

---

### 2.3 Tool Executor Framework

**PRD ref:** §4.7 Tool System

**Work:**
- Define `Tool` interface:

```typescript
interface Tool {
  name: string;
  description: string;
  parameters: JSONSchema;                              // for LLM tool use
  approvalRequired: boolean;                           // default per tool; overridable in config
  execute(args: Record<string, unknown>, context: ToolContext): Promise<ToolResult>;
}

interface ToolContext {
  sessionId: string;
  workspaceRoot: string;                               // scoped filesystem root
  approvalCallback?: (description: string) => Promise<boolean>;
}

interface ToolResult {
  success: boolean;
  output: string;
  truncated?: boolean;                                 // if output was capped
}
```

- Implement `ToolExecutor`:
  - Receives tool call from agent runtime
  - **Approval gate**: if tool requires approval, call `approvalCallback` (channel-specific: Telegram inline button, Slack button, CLI y/n prompt). Canonical argument parsing — arguments are parsed and re-serialized before allowlist check to prevent encoding bypass.
  - Execute tool in sandbox context
  - **Output budgeting**: if result > `config.context.toolOutputMaxTokens`, truncate with marker. If memory system is available, store full result in memory and reference it.
  - Log execution to `audit_log` table (tool name, args, output summary, success/failure, duration)

**Acceptance criteria:**
- Tool call with `approvalRequired: true` blocks until user approves
- Denied tool call returns a clear refusal message to the agent
- Output exceeding budget is truncated with marker
- All executions logged to audit table

---

### 2.4 Built-in Tools — Filesystem

**PRD ref:** §4.7 (file read/write)

**Work:**
- `read_file` — read a file within `workspaceRoot`; truncate if > token cap
- `write_file` — write/overwrite a file within `workspaceRoot`
- `list_directory` — list files in a directory within `workspaceRoot`
- All paths validated: must resolve within `workspaceRoot` after symlink resolution (prevent directory traversal)
- `approvalRequired`: `false` for reads, `true` for writes by default

**Acceptance criteria:**
- Read a file; output truncated if large
- Write a file; file appears on disk
- Path traversal attempt (`../../etc/passwd`) rejected with error
- Symlink outside workspace rejected

---

### 2.5 Built-in Tools — Shell

**PRD ref:** §4.7 (shell execution)

**Work:**
- `exec_command` — run a shell command in `workspaceRoot`
- `approvalRequired`: `true` always (unless command matches a configured allowlist)
- Execution via `child_process.spawn` with:
  - Timeout (configurable, default 30s)
  - Working directory set to `workspaceRoot`
  - Environment variables stripped to a safe set
- stdout + stderr captured; truncated per token cap
- Allowlist: config defines patterns for auto-approved commands (e.g., `["git status", "npm test"]`)
- Allowlist validation uses parsed argv, not raw string matching (prevents bypass via `git status; rm -rf /`)

**Acceptance criteria:**
- `exec_command("ls")` returns directory listing
- Command exceeding timeout is killed and returns timeout error
- Command not in allowlist triggers approval prompt
- `git status; rm -rf /` is parsed as a single command with literal arg, not two commands

---

### 2.6 Built-in Tools — Browser

**PRD ref:** §4.7 (browser automation with CDP)

**Work:**
- Managed Playwright Chromium instance:
  - Launched on first `browser_*` tool call; reused across calls in a session
  - Health check: if Chromium crashes, relaunch on next call (not a gateway-level failure)
  - Chromium process killed on session end or gateway shutdown
- Tools:
  - `browser_navigate(url)` — navigate to URL
  - `browser_snapshot()` — return accessibility tree with numbered interactive elements
  - `browser_click(elementRef)` — click element by reference number
  - `browser_type(elementRef, text)` — type text into element
  - `browser_screenshot()` — take screenshot, return as base64 image
- Cookie/session persistence within a Lumen session
- `approvalRequired`: `true` for all browser tools by default

**Acceptance criteria:**
- Navigate to a URL; snapshot returns accessible elements
- Click and type interact with page elements
- Browser crash mid-session recovers on next call
- Browser process cleaned up on gateway shutdown

---

### 2.7 Built-in Tools — HTTP, Cron, Vision

**PRD ref:** §4.7 (HTTP requests, cron scheduling, vision/image analysis)

**Work:**
- `http_request(method, url, headers?, body?)` — make HTTP requests; `approvalRequired: true`
- `schedule_task(cron, description, message)` — register a cron job that sends `message` to the session's agent at the cron schedule. Cron tasks get a minimal context (system prompt + task-specific memory) to avoid cost explosion
- `analyze_image(image_base64)` — pass image to the LLM's vision capability; `approvalRequired: false`

**Acceptance criteria:**
- HTTP request returns response body (truncated per token cap)
- Cron task fires at scheduled time; agent receives the message with minimal context
- Image analysis returns LLM description of the image

---

### 2.8 Spend Caps

**PRD ref:** §4.5 (spend caps), §6.4 (no built-in spend cap)

**Work:**
- Extend `TokenAccountant` with budget enforcement:
  - `perDayTokens` / `perDayUsd` — global daily cap
  - `perSessionTokens` / `perSessionUsd` — per-session cap
  - Configurable action on breach: `warn`, `throttle` (delay until next period), `block` (reject)
- When a budget is hit with `block` action, the agent receives a system message explaining why and suggesting the user adjust the budget
- CLI: `lumen usage --budget` shows current spend vs. caps

**Acceptance criteria:**
- Agent call rejected when session budget exceeded with `block` action
- Warning surfaced when `warn` threshold crossed
- Daily budget resets at midnight (configurable timezone)

---

## Phase 3: V0.4 — Ecosystem (Q4 2026)

**PRD milestone:** V0.4 — Skill system, signed registry, WhatsApp/Signal/Teams adapters, Web UI

**Goal:** The agent is extensible via skills, accessible from more messaging platforms, and manageable through a web interface.

---

### 3.1 Skill System

**PRD ref:** §4.8 Skills & Extensions

**Work:**
- Define skill manifest format:

```yaml
# skills/example/SKILL.yaml
name: weather-lookup
version: 1.0.0
description: Look up current weather for a city
author: lumen-community
signature: <base64 ed25519 signature>

# Injected into the agent's system prompt when this skill is active
instructions: |
  When the user asks about weather, use the http_request tool to call
  the OpenWeatherMap API at https://api.openweathermap.org/data/2.5/weather
  with the city name as a query parameter.

# Skills can declare new tools
tools:
  - name: get_weather
    description: Get current weather for a city
    parameters:
      type: object
      properties:
        city:
          type: string
          description: City name
      required: [city]

# Permissions this skill requires
permissions:
  - http   # needs http_request tool
```

- Implement skill loader:
  - Load skills from `~/.lumen/skills/` and built-in `skills/` directory
  - Validate manifest, check signature if present
  - Unsigned skills: log warning; if `config.skills.requireSigning` is true, refuse to load
- Implement selective injection:
  - Before each agent turn, score each loaded skill's relevance to the current user message (keyword match + embedding similarity against skill description)
  - Only inject top-N relevant skills (default N=3) into the system prompt
  - Track which skills are injected per turn for audit
- Skill isolation: each skill's tools run in the same sandbox as built-in tools, scoped to `workspaceRoot`; skills cannot access other skills' configuration

**Acceptance criteria:**
- Install a skill; agent uses it when relevant query is sent
- Unsigned skill triggers warning in logs
- Skill with `requireSigning: true` config is rejected if unsigned
- Only relevant skills injected (verified by audit log)

---

### 3.2 Skill Code Signing & Dependency Scanning

**PRD ref:** §4.8 (registry with code signing, dependency scanning)

**Work:**
- Implement Ed25519 signing:
  - `lumen skills sign <path>` — sign a skill manifest with the user's private key
  - `lumen skills verify <path>` — verify signature against a trusted public key set
  - Built-in skills signed with Lumen project key
- Dependency scanning:
  - If a skill declares `dependencies` (npm packages), scan them against the npm audit advisory database before installation
  - Reject skills with known critical vulnerabilities (configurable severity threshold)
- CLI: `lumen skills install <path|url>`, `lumen skills list`, `lumen skills remove <name>`

**Acceptance criteria:**
- Signed skill loads without warning; tampered skill (modified after signing) fails verification
- Skill with a dependency flagged by npm audit is rejected with clear message
- `lumen skills list` shows installed skills with signing status

---

### 3.3 Additional Channel Adapters — WhatsApp, Signal, Teams

**PRD ref:** §4.4 (WhatsApp, Signal, Microsoft Teams)

**Work:**
- **WhatsApp**: implement via Baileys library (unofficial WhatsApp Web API)
  - QR code linking flow via CLI or Web UI
  - Handle re-linking failures with clear error messages (not stuck "logging in")
  - Support text, images, documents
- **Signal**: implement via `signal-cli` or `libsignal` bridge
  - Registration via phone number
  - Support text and attachments
- **Microsoft Teams**: implement via Bot Framework SDK
  - App registration in Azure AD
  - Support text, adaptive cards for approval prompts
  - Handle threaded replies correctly

**Acceptance criteria:**
- Each adapter connects and delivers messages bidirectionally
- WhatsApp linking works and re-linking after disconnect works
- Teams replies land in the correct thread
- Signal messages with attachments are processed

---

### 3.4 Web UI

**PRD ref:** §4.10 (Web UI)

**Work:**
- Single-page app served by the gateway on a separate port (or path prefix):
  - **Dashboard**: gateway health, active sessions, connected channels, token usage charts
  - **Chat**: web-based chat interface to any active session
  - **Sessions**: list, inspect, and delete sessions; view message history
  - **Config**: edit provider config, budgets, channel settings (writes to `lumen.json`)
  - **Audit log**: searchable audit log viewer
  - **Memory**: browse, search, and delete memories
- Tech: lightweight framework (Preact or Svelte) with Vite build; bundled into the gateway binary
- Auth: local-only access requires no auth by default; if network-exposed (via tunnel), require a configurable password or token
- WebSocket connection for real-time updates (session messages, health status)

**Acceptance criteria:**
- Web UI loads at `http://localhost:18800/ui`
- Chat interface sends messages and displays streaming responses
- Config changes via UI are persisted and take effect without restart
- Audit log is searchable by event type and date range

---

### 3.5 Chitin Provider Adapter

**PRD ref:** §4.6 Chitin Integration

**Work:**
- Implement `ChitinProvider` extending the base provider:
  - Default `base_url`: `https://api.usechitin.com/v1`
  - Auth: `sk-chitin-` prefixed API keys; stored in secrets store
  - Uses OpenAI-compatible chat completions endpoint
- Parse `X-Gateway-*` response headers:
  - `X-Gateway-Tokens-Saved` → log to `token_events.tokens_saved`
  - `X-Gateway-Model` → log actual model used (may differ from requested)
  - `X-Gateway-Cost-USD` → use as authoritative cost instead of local estimate
  - `X-Gateway-Cache` → surface in session metadata
  - `X-Gateway-Compression` → surface in session metadata
- **No double-optimization**: when provider is Chitin, `ContextEngine` skips its own compression stages and model routing; Lumen still handles session management, memory injection, and tool execution
- **Session tagging**: pass `X-Gateway-Session-Id` and `X-Gateway-Tag` headers on every request
- **RAG coordination**: send `X-Lumen-Memory-Injected: true|false` header; when Chitin indicates RAG `replace` mode, Lumen skips memory injection
- **Fallback**: if Chitin returns 503, fall back to direct Anthropic/OpenAI connection (configurable)
- Budget integration: Chitin's 429 (budget exceeded) handled with backoff, not aggressive retry
- `lumen usage` surfaces Chitin-reported savings alongside Lumen's own accounting

**Acceptance criteria:**
- Integration test: send a message through Chitin; response received with `X-Gateway-*` headers parsed
- Chitin savings visible in `lumen usage` output
- Context compression skipped when Chitin is the active provider
- Fallback to direct provider works when Chitin returns 503

---

## Phase 4: V1.0 — General Availability (Q1 2027)

**PRD milestone:** V1.0 — Companion apps, full audit logging, Docker image, hardened security review

**Goal:** Production-quality release with companion apps, complete audit trail, and a security review.

---

### 4.1 Audit Logging Hardening

**PRD ref:** §4.9 (audit logging, tamper-evident)

**Work:**
- Extend `audit_log` table with hash chain:

```sql
ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;
```

- Each log entry's `entry_hash` = SHA-256 of `(prev_hash + event_type + actor + detail + created_at)`
- On startup, verify the hash chain integrity; alert if tampering detected
- Log all privileged operations:
  - Tool executions (already logged in Phase 2)
  - Skill installations, updates, removals
  - Config changes
  - Auth events (secret creation, key rotation)
  - Channel connections and disconnections
  - Budget threshold breaches
- Retention policy: configurable auto-purge of entries older than N days (default: 90), preserving hash chain continuity (tombstone entries)
- `lumen audit` CLI command: search, filter, and export audit log

**Acceptance criteria:**
- Hash chain verified on startup; intentionally corrupted entry detected
- All privileged operations produce audit log entries
- `lumen audit --type tool_exec --since 2026-12-01` returns filtered results

---

### 4.2 Security Hardening & Review

**PRD ref:** §4.9 Security Architecture, §6.3 Security Failures

**Work:**
- **Localhost-only enforcement**: verify gateway binds to 127.0.0.1 by default; attempting to bind to 0.0.0.0 requires `gateway.allowNetworkExposure: true` with a logged warning
- **WebSocket origin validation**: audit all WS endpoints; reject non-allowlisted origins
- **No tokens in URLs**: audit all API endpoints; verify no auth material in query params or logs
- **Tool sandbox audit**: verify filesystem tools cannot escape `workspaceRoot`; verify shell allowlist cannot be bypassed via encoding
- **Dependency audit**: run `pnpm audit`; resolve all critical and high findings
- **Threat model document**: document trust boundaries (user ↔ agent, agent ↔ tools, agent ↔ provider, agent ↔ channels) and mitigations
- Commission external security review (scope: gateway API, tool execution, secret storage, channel adapters)

**Acceptance criteria:**
- No critical or high vulnerabilities in dependency audit
- Threat model document covers all trust boundaries
- External review completed with all critical findings resolved

---

### 4.3 macOS Menu Bar App

**PRD ref:** §4.10 (macOS companion)

**Work:**
- Native macOS app (Swift + SwiftUI) or Electron-based menu bar app:
  - Gateway status indicator (running/stopped/error)
  - Start/stop gateway
  - Quick-access chat panel
  - Push-to-talk voice input (system audio capture → transcription via Whisper API → send to agent)
  - Notification delivery for agent-initiated messages
- Communicates with gateway via WebSocket on localhost

**Acceptance criteria:**
- Menu bar icon reflects gateway status
- Start/stop controls work
- Voice input transcribed and sent to agent; response displayed in panel

---

### 4.4 Mobile Node (iOS / Android)

**PRD ref:** §4.10 (iOS / Android)

**Work:**
- React Native or native app:
  - Pairs to gateway via WebSocket (local network or tunnel)
  - Chat interface with streaming responses
  - Voice input
  - Camera capture → send image to agent for vision analysis
  - Push notifications for agent-initiated messages
- Device pairing: gateway generates a pairing code; mobile app scans or enters it

**Acceptance criteria:**
- Mobile app pairs to gateway and sends/receives messages
- Voice input works end-to-end
- Camera capture sends image; agent responds with analysis
- Push notifications delivered for agent messages when app is backgrounded

---

### 4.5 Production Docker Image

**PRD ref:** §6.5 (Docker setup fails out of the box)

**Work:**
- Finalize multi-stage Dockerfile with:
  - Build stage: compile TypeScript, prune dev dependencies
  - Production stage: Node.js 22 slim base, non-root user, read-only filesystem (except data volume)
- Docker Compose file with health check, restart policy, and volume configuration
- CI/CD: build and push image to GitHub Container Registry on every release tag
- Smoke test in CI: `docker compose up`, wait for health check, send a test message, verify response

**Acceptance criteria:**
- `docker pull ghcr.io/black-candle-technologies/lumen:latest && docker compose up` works on a fresh machine
- Health check passes within 30 seconds
- Image size < 200MB

---

### 4.6 Documentation & Release

**Work:**
- Quickstart guide: install → configure → first message in < 5 minutes
- Configuration reference: all config keys with defaults and descriptions
- Channel setup guides: per-platform setup instructions (Telegram bot token, Slack app creation, etc.)
- Skill authoring guide: manifest format, signing, testing
- Security guide: recommended deployment patterns, tunnel setup, secret management
- API reference: all HTTP/WS endpoints
- Changelog for V1.0

**Acceptance criteria:**
- A new user can follow the quickstart and have a working agent in < 5 minutes
- All public API endpoints documented
- Channel setup guides tested on fresh accounts

---

## Appendix A: Cross-Cutting Concerns

### Testing Strategy

| Layer | Approach | Coverage Target |
|---|---|---|
| Unit tests | Vitest; mock providers and DB | All core logic: context engine, memory retrieval, token accounting, budget enforcement, tool sandbox, config validation |
| Integration tests | Vitest with real SQLite; mock LLM providers via HTTP interceptors | Agent loop end-to-end, channel adapter message flow, skill loading |
| Provider integration tests | Real API calls (skipped in CI without keys) | Anthropic, Ollama, Chitin provider adapters |
| E2E tests | Docker Compose; real gateway + CLI | Install → setup → send message → receive response |
| Security tests | Dedicated test suite | Path traversal, shell injection, WebSocket origin, token exposure, tool allowlist bypass |

### Error Handling Philosophy

- **User-facing errors**: clear, actionable message. "Your daily token budget of 500K has been reached. Increase it with `lumen config set budgets.perDayTokens 1000000` or wait until tomorrow."
- **Provider errors**: classified (rate limit / billing / server / auth) and surfaced accurately. Never "API rate limit reached" when the real issue is a billing error.
- **Channel errors**: delivery failures are visible, not silent. The agent knows when a message failed to send.
- **Internal errors**: logged with full context; never exposed to user as raw stack traces.

### Performance Targets

| Metric | Target |
|---|---|
| Gateway startup (Linux, SSD) | < 3 seconds |
| Gateway startup (Raspberry Pi 4, SD card) | < 10 seconds |
| CLI command startup | < 2 seconds (Raspberry Pi 4) |
| Memory retrieval (1000 memories) | < 100ms |
| Context assembly (200K token session) | < 500ms |
| Message processing overhead (excluding LLM call) | < 200ms |

### Dependency Policy

- Minimize dependencies; prefer Node.js built-ins where feasible
- No dependency with known critical CVE at time of release
- `pnpm audit` runs in CI on every PR; block merge on critical findings
- Major dependency updates reviewed quarterly
