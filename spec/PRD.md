# Lumen — Personal AI Agent Platform

## Product Requirements Document

**Version:** 1.0
**Date:** 2026-03-02
**Status:** Draft

---

## 1. Executive Summary

Lumen is a local-first personal AI agent platform that connects large language models to messaging platforms, local tools, and automation workflows. It runs as a persistent background service on the user's own hardware, providing a private, always-on AI assistant accessible through the chat apps people already use.

The market for open-source personal AI agents has demonstrated massive demand (200K+ GitHub stars on leading projects) but existing solutions suffer from critical architectural defects: broken context management that silently loses user work, a security posture riddled with CVEs, runaway API costs with no guardrails, and a memory system that degrades as it grows. Lumen is designed from the ground up to solve these problems.

---

## 2. Problem Statement

Existing open-source personal AI agent platforms have proven the concept but fail users in practice:

- **Context management is fundamentally broken.** Sessions hit hard token ceilings regardless of model capability, auto-compaction fails to trigger or fires prematurely, and large tool outputs cause irrecoverable failure loops. When compaction does fire, it silently destroys active work and learned facts.
- **Memory degrades over time.** The more the agent learns, the worse it performs. Memory is stored inside the context window where compaction can wipe it. Between sessions, the agent is stateless. Default configurations ship with persistent memory disabled.
- **Security is an afterthought.** Exposed instances number in the tens of thousands. Supply chain attacks have compromised 20%+ of community skill registries. Critical RCE vulnerabilities stem from fundamental architectural choices (trusting WebSocket origins, tokens in query parameters, no origin validation). Traditional SAST tools cannot catch LLM-to-tool trust boundary issues.
- **Costs are unpredictable and extreme.** Full conversation history is re-sent on every API call. System prompts consume 5K-10K tokens per turn. Heartbeat/cron features compound costs silently. No built-in spend caps exist. Users report $50+/day bills from misconfigured defaults.
- **Setup and reliability are poor.** Docker setup fails out of the box. Gateway crashes on headless servers. Channel integrations fail silently. Browser automation is unreliable. Plugin installation breaks across platforms.

---

## 3. Target Users

| Persona | Description |
|---|---|
| **Power User** | Technical individual who wants a private AI assistant for daily automation — email triage, scheduling, research, reminders — accessible from their phone via messaging apps. |
| **Developer** | Software engineer who wants an always-on agent for CI/CD monitoring, incident response, code review notifications, and development workflow automation. |
| **Small Team Lead** | Manager of a 3-10 person team who wants a shared AI assistant for Slack/Teams that can answer questions, run reports, and automate recurring tasks without sending data to third parties. |
| **Self-Hoster** | Privacy-conscious user who runs services on their own hardware and wants full control over their AI agent's data, model selection, and network exposure. |

---

## 4. Core Features

### 4.1 Gateway — Persistent Agent Runtime

A single long-lived background process (systemd/launchd) that serves as the control plane for all agent sessions, channel connections, and tool execution.

**Requirements:**
- Run as a daemon with automatic restart on failure and health monitoring
- Expose a local-only control API (HTTP + WebSocket) on a configurable port
- Support graceful shutdown with in-flight request draining
- Provide a heartbeat scheduler for proactive agent tasks (cron-like)
- Ship with secure defaults: bind to localhost only, require explicit opt-in for network exposure
- Start reliably on headless servers, containers, Raspberry Pi, and desktop environments

### 4.2 Adaptive Context Engine

A context management system that dynamically scales to the model's actual capabilities and prevents the failure modes that plague existing solutions.

**Requirements:**
- Query the model provider for actual context window size; never hardcode ceilings
- Implement a token budget system: reserve capacity for system prompt, tool schemas, memory, and reply — only the remainder is available for conversation history
- **Preflight context check** before every LLM call: if the assembled prompt would exceed the budget, trigger compaction *before* sending, not after failure
- **Tool output guardrails**: cap individual tool results at a configurable maximum (default 32K tokens); auto-summarize results that exceed the cap rather than injecting them raw
- Graduated compaction: summarize oldest conversation turns first, preserving recent context and any explicitly pinned messages
- **Compaction safety**: before compacting, persist the full uncompacted session to disk so the user can recover if compaction loses important context
- Context usage reporting: surface accurate, real-time token usage percentage to the user (no erratic jumps)
- Support context windows from 16K (local models) to 1M+ (frontier models) without architectural changes

### 4.3 Structured Memory System

A memory architecture that improves with use rather than degrading, stored outside the context window where compaction cannot destroy it.

**Requirements:**
- **Persistent memory store** backed by SQLite, separate from conversation context
- Memories are written to the store explicitly (agent-initiated or user-initiated), not implicitly via context window contents
- **Semantic retrieval**: on each turn, retrieve only the top-k most relevant memories via embedding similarity, injecting a bounded number of tokens (configurable, default 4K)
- **Memory lifecycle**: memories have creation timestamps, access counts, and optional expiry — stale memories decay in retrieval ranking
- **Relational indexing**: store typed relationships between memory entries (e.g., "User prefers X", "Project Y uses framework Z") to enable graph-style traversal, not just vector similarity
- **Cross-session continuity**: memory persists across gateway restarts, session boundaries, and compaction events
- **Memory flush on compaction**: before any context compaction, the agent is prompted to extract and persist any important facts from the context being compacted
- **Memory budget**: total injected memory tokens are capped and configurable, preventing the "lost in the middle" degradation seen with unbounded retrieval

### 4.4 Multi-Channel Messaging

Connect the agent to the messaging platforms users already live in, with proper session isolation.

**Requirements:**
- Support at minimum: WhatsApp, Telegram, Slack, Discord, Signal, Microsoft Teams, Matrix, IRC
- Each channel/conversation gets an isolated session by default (no context leakage)
- Secure DM mode: isolate sessions per sender within group channels
- Channel adapters are plugins — adding a new platform does not require modifying the core
- Normalize message formats across platforms (text, images, files, reactions) into a common internal representation
- Handle platform-specific quirks (WhatsApp linking, Slack threading, Teams card formats) gracefully with clear error messages on failure, not silent drops

### 4.5 Model-Agnostic Provider System

Support any LLM provider without lock-in, with intelligent cost management.

**Requirements:**
- First-class support for: Anthropic (Claude), OpenAI (GPT/Codex), Google (Gemini), and local models via Ollama/vLLM
- Provider configuration via a single config file with per-provider auth, model selection, and context window overrides
- **Fallback chains**: configure primary and fallback providers with automatic failover on error or rate limit
- **Rate limit handling**: detect 429 responses and back off with jittered exponential delay; never retry aggressively in a tight loop
- Correctly distinguish between rate limits (429), billing errors (402), and server errors (5xx) — surface accurate error messages to the user
- **Spend caps**: built-in per-day and per-session token budget with configurable hard stop and warning thresholds
- **Cost tracking**: log token usage per session, per channel, and per model with queryable history
- Auth profile rotation for providers that support multiple API keys

### 4.6 Tool System

A sandboxed, auditable tool execution layer.

**Requirements:**
- **Built-in tools**: file read/write, shell execution, browser automation (CDP), cron scheduling, HTTP requests, vision/image analysis
- All tool executions are logged with full input/output for audit
- **Sandboxing**: tools run in a restricted environment by default; filesystem access is scoped to a configurable workspace root; shell commands require explicit allowlisting or user approval
- **Tool output budgeting**: tool results exceeding the configured token cap are summarized before injection into context
- **Approval gates**: configurable per-tool approval requirements (auto-approve, require approval, deny) — no execution path should bypass the approval gate via argument tricks or encoding exploits
- Browser automation with managed Chromium, CDP control, accessibility-tree-based element targeting, and session/cookie persistence

### 4.7 Skills & Extensions

A safe, auditable extension system that avoids the supply chain pitfalls of existing skill registries.

**Requirements:**
- Skills are declarative packages (manifest + instructions + optional code) that extend agent capabilities
- **Skill isolation**: skills cannot access other skills' data or escalate their own permissions
- **Registry with code signing**: the official skill registry requires cryptographic signing; unsigned skills trigger a prominent warning
- **Dependency scanning**: skills that install external packages are scanned against known vulnerability databases before installation
- **Selective injection**: only skills relevant to the current turn are injected into the prompt, not the entire skill catalog
- Users can write, install, and share custom skills without modifying the core
- **Audit trail**: all skill installations, updates, and removals are logged

### 4.8 Security Architecture

Security as a foundational design constraint, not a bolt-on.

**Requirements:**
- **Local-only by default**: the gateway binds to 127.0.0.1; exposing it to the network requires explicit configuration with a mandatory warning
- **Origin validation on all WebSocket connections**: reject connections from origins that are not explicitly allowlisted
- **No tokens in URLs**: authentication tokens are never placed in query parameters, URLs, or server logs
- **Encrypted secret storage**: API keys and auth tokens are stored encrypted at rest (system keychain integration or encrypted file with user-provided passphrase)
- **Multi-user access control**: support distinct user identities with separate permissions, sessions, and memory stores
- **Principle of least privilege for tools**: tools start with no permissions; each capability (filesystem, network, shell) must be explicitly granted
- **Automatic security updates**: the gateway checks for critical security patches and notifies the user (opt-in auto-update)
- **Audit logging**: all privileged operations (tool execution, skill installation, config changes, auth events) are logged to a tamper-evident audit log

### 4.9 Companion Apps

Optional native apps that enhance the gateway experience.

**Requirements:**
- **macOS**: menu bar app for gateway health, start/stop, and push-to-talk voice input
- **iOS / Android**: mobile node that pairs to the gateway over WebSocket; provides voice input, camera capture, and notification delivery
- **Web UI**: browser-based control panel and chat interface for gateway management, session inspection, and debug tools
- All apps are optional — the gateway alone is fully functional via messaging channels and CLI

---

## 5. Non-Features (Explicitly Out of Scope)

The following are intentionally excluded from Lumen's scope to maintain focus, security, and architectural clarity:

| Non-Feature | Rationale |
|---|---|
| **IDE / code editor integration** | Lumen is a personal assistant platform, not a coding agent. Purpose-built coding tools (e.g., AI-powered IDE extensions) serve this use case better. |
| **Direct internet exposure mode** | The gateway will never ship with a "public server" mode. Users who want remote access must use SSH tunnels, VPNs, or Tailscale. This eliminates an entire class of security vulnerabilities. |
| **Built-in LLM inference** | Lumen orchestrates models; it does not run them. Local inference is delegated to Ollama, vLLM, or similar runtimes. This keeps the install lightweight and avoids GPU dependency management. |
| **Autonomous multi-agent orchestration** | V1 supports a single agent per session. Multi-agent coordinator/specialist patterns introduce compounding token costs and trust boundary complexity. This may be revisited in V2 after the single-agent experience is solid. |
| **Marketplace with auto-install** | Skills can be shared and installed, but the agent will never autonomously discover and install skills from a remote registry without explicit user initiation. This prevents supply chain attacks via prompt injection. |
| **Social / community features** | No user profiles, leaderboards, skill ratings, or social graphs. Lumen is a tool, not a platform. |
| **Real-time collaboration** | Lumen serves one operator (or one small team) per instance. It is not a shared SaaS workspace. |

---

## 6. Known Industry Defects Addressed

This section catalogs specific, documented defects in existing personal AI agent platforms that Lumen's architecture is designed to prevent.

### 6.1 Context Scaling Failures

| Defect | Lumen Mitigation |
|---|---|
| Hardcoded 200K context ceiling ignoring model capabilities | Context engine queries provider for actual limit; no hardcoded ceilings |
| Custom providers default to 4096 tokens, below minimum viable | Minimum context floor of 16K enforced; sensible defaults per known provider |
| Auto-compaction fails to trigger, session grows until hard crash | Preflight budget check before every LLM call; compaction is proactive, not reactive |
| False-positive context overflow detection due to incorrect token counting | Token estimation validated against provider tokenizer; fallback to conservative estimate on mismatch |
| Large tool output causes irrecoverable context overflow | Tool output cap with auto-summarization; no raw injection of unbounded output |
| Context percentage reporting jumps erratically (30% -> 13% -> 27%) | Single-source token accounting with monotonic tracking between compaction events |

### 6.2 Memory Failures

| Defect | Lumen Mitigation |
|---|---|
| Memory stored inside context window; compaction destroys it | Memory is a separate persistent store; context compaction cannot affect it |
| Memory flush disabled by default; no persistent fallback | Memory persistence enabled by default with sensible defaults |
| Memory flush threshold is an absolute value, doesn't scale with context window | Flush threshold is a percentage of context window, not an absolute token count |
| Agent gets worse as memory grows (attention dilution) | Bounded retrieval (top-k, token-capped) with relevance decay |
| Stateless between sessions; every restart starts from zero | Persistent SQLite-backed memory survives restarts, crashes, and upgrades |
| Messaging history bloat (28K tokens of channel history per call) | Channel adapters inject only the current conversation turn, not full history |

### 6.3 Security Failures

| Defect | Lumen Mitigation |
|---|---|
| WebSocket hijacking via missing origin validation (CVSS 8.8 RCE) | Mandatory origin validation on all WebSocket connections |
| Auth tokens in URL query parameters (harvestable from logs/history) | Tokens transmitted only in headers; never in URLs |
| Tool execution bypass via argument encoding tricks | Allowlist validation uses canonical argument parsing; no raw string matching |
| 20%+ of community skill registry compromised with malware | Signed skills required; no auto-install from registry; dependency scanning |
| 21K-42K instances exposed to internet with auth bypass | Local-only binding by default; network exposure requires explicit opt-in with warning |
| No encrypted API key storage | Encrypted at-rest storage via system keychain or passphrase-protected file |
| No multi-user access control | User identity and permission system built into core |

### 6.4 Cost & Performance Failures

| Defect | Lumen Mitigation |
|---|---|
| Full conversation history re-sent on every API call | Context engine manages a rolling window; only the budgeted history is sent |
| No built-in spend cap; users report $50+/day from misconfigured defaults | Per-day and per-session spend caps with hard stop |
| Heartbeat/cron sends full session context on every tick | Cron tasks get a minimal context (system prompt + task-specific memory); not full session |
| Gateway restart triggers 4x full-context retry (cost explosion) | Retry on restart sends only a recovery prompt, not the full prior context |
| Rate limit handling causes aggressive retry loops | Jittered exponential backoff with per-provider retry budgets |
| 402 billing errors misidentified as rate limits (and vice versa) | HTTP status code handling distinguishes 402, 429, and 5xx with accurate user messaging |
| Thinking/reasoning mode explodes costs 10-50x with no warning | Token usage projection shown before enabling reasoning mode; budget applies to thinking tokens |

### 6.5 Reliability Failures

| Defect | Lumen Mitigation |
|---|---|
| Docker setup fails out of the box | Official Docker image with CI-tested compose file; first-run wizard validates config |
| Gateway won't start on headless servers | Headless mode is a first-class configuration; no implicit GUI dependencies |
| Channel replies fail silently (Slack, Teams, Mattermost) | Channel adapters report delivery status; failed sends surface as user-visible errors with retry option |
| Browser automation is unreliable | Managed Chromium lifecycle with health checks; graceful fallback to non-browser tools on failure |
| Plugin/skill install fails across platforms | Platform-specific install paths tested in CI for Linux, macOS, and Windows |
| CLI extremely slow on low-power hardware (Raspberry Pi) | Lazy-load architecture; CLI only loads modules needed for the current command |

---

## 7. Technical Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Companion Apps                        │
│  ┌──────────┐  ┌───────────┐  ┌──────────┐  ┌───────┐  │
│  │ macOS    │  │ iOS/Android│  │ Web UI   │  │  CLI  │  │
│  │ Menu Bar │  │ Mobile Node│  │ Control  │  │       │  │
│  └────┬─────┘  └─────┬─────┘  └────┬─────┘  └───┬───┘  │
│       └───────────────┼─────────────┼────────────┘      │
│                       │ WebSocket (local only)           │
└───────────────────────┼─────────────────────────────────┘
                        │
┌───────────────────────┼─────────────────────────────────┐
│                   Gateway (Daemon)                       │
│  ┌────────────────────┴────────────────────────────┐    │
│  │              Control Plane API                   │    │
│  │    (Health, Config, Sessions, Audit Log)         │    │
│  └──────────────────────┬──────────────────────────┘    │
│                         │                                │
│  ┌──────────┐  ┌────────┴────────┐  ┌────────────────┐  │
│  │ Channel  │  │  Agent Runtime  │  │   Tool         │  │
│  │ Adapters │──│                 │──│   Executor     │  │
│  │          │  │  - Context Eng. │  │   (Sandboxed)  │  │
│  │ WhatsApp │  │  - Memory Mgr  │  │                │  │
│  │ Telegram │  │  - Token Acctg │  │  - Filesystem  │  │
│  │ Slack    │  │  - Compaction   │  │  - Shell       │  │
│  │ Discord  │  │  - Skill Inject│  │  - Browser     │  │
│  │ Signal   │  │                 │  │  - HTTP        │  │
│  │ Teams    │  │                 │  │  - Cron        │  │
│  │ Matrix   │  │                 │  │  - Vision      │  │
│  │ IRC      │  └────────┬───────┘  └────────────────┘  │
│  │ ...      │           │                                │
│  └──────────┘  ┌────────┴───────┐                       │
│                │  Provider Layer │                       │
│                │                 │                       │
│                │  Anthropic      │                       │
│                │  OpenAI         │                       │
│                │  Google         │                       │
│                │  Ollama/vLLM    │                       │
│                │  Custom         │                       │
│                └─────────────────┘                       │
│                                                          │
│  ┌──────────────────────────────────────────────────┐   │
│  │            Persistent Storage (SQLite)            │   │
│  │  Sessions │ Memory │ Audit Log │ Config │ Skills  │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
```

---

## 8. Success Metrics

| Metric | Target |
|---|---|
| Gateway uptime (self-hosted) | 99.9% (< 8.7 hours downtime/year) |
| Time from install to first working message | < 5 minutes |
| Context compaction data loss incidents | 0 (recoverable from persisted full session) |
| Security vulnerabilities (critical/high) | 0 unpatched for > 7 days |
| Median API cost per active user per day | < $2 (with default config) |
| Memory retrieval relevance (top-5 precision) | > 80% |
| Channel message delivery success rate | > 99.5% |
| Startup time on Raspberry Pi 4 | < 10 seconds |

---

## 9. Milestones

| Phase | Scope | Target |
|---|---|---|
| **V0.1 — Foundation** | Gateway daemon, context engine, provider layer (Anthropic + Ollama), CLI, SQLite storage, encrypted secrets | Q2 2026 |
| **V0.2 — Channels** | Telegram, Slack, Discord adapters; session isolation; message normalization | Q3 2026 |
| **V0.3 — Memory & Tools** | Persistent memory system, file/shell/browser tools, tool sandboxing, spend caps | Q3 2026 |
| **V0.4 — Ecosystem** | Skill system, signed registry, WhatsApp/Signal/Teams adapters, Web UI | Q4 2026 |
| **V1.0 — General Availability** | Companion apps, full audit logging, Docker image, hardened security review | Q1 2027 |

---

## 10. Open Questions

1. **Skill language**: Should skills be limited to declarative manifests + natural language, or should they support arbitrary code execution? Declarative is safer; code is more powerful.
2. **Multi-tenant**: Should a single gateway support multiple distinct users (household use case), or should each user run their own instance?
3. **Voice**: Should voice input/output be a core feature or a companion app concern?
4. **Offline mode**: Should the agent provide any functionality when the LLM provider is unreachable (cached responses, local model fallback)?
