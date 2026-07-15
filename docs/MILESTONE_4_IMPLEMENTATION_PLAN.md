# Controlled Egress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete Roadmap Milestone 4 with explicit remote provider enablement, workspace/data-class egress policy, destination-scoped network capabilities, external channel identity mapping, and audited fail-closed egress.

**Architecture:** Keep local inference as the default. Add validated egress policy types in `lumen-core`, persistent provider/policy/channel state in `lumen-db`, endpoint and HTTP adapter enforcement in `lumen-integrations`, runtime composition in `lumen-cli`, authenticated API surfaces in `lumen-server`, and compact operator controls in the Svelte app. Remote adapters remain thin and cannot approve, audit, or grant themselves.

**Tech Stack:** Rust 2024, Tokio, Axum, SQLite/SQLx, reqwest with redirect denial, OS-keychain secret references, serde/TOML, SvelteKit, Vitest, Playwright, Tauri 2

---

## File Structure

```text
crates/lumen-core/src/
  egress.rs                 # data classes, provider/destination scopes, routing decisions
  capability.rs             # network.egress and channel.send capability names
  model.rs                  # model input data class and provider-selection metadata
crates/lumen-db/migrations/
  0004_controlled_egress.sql # providers, routing policies, destinations, channels
crates/lumen-db/src/
  egress.rs                 # transactional egress repositories
crates/lumen-integrations/src/
  openai_compatible.rs      # explicit remote policy, auth header injection, no redirects
  network.rs                # runtime-owned HTTP egress adapter
  channels.rs               # channel adapter identity contracts
crates/lumen-cli/src/
  config.rs                 # explicit bootstrap remote provider and egress policy parsing
  runtime.rs                # routing and network/channel actions through normal lifecycle
crates/lumen-server/src/
  routes/mod.rs             # authenticated egress policy/provider/channel routes
apps/web/src/
  routes/settings/+page.svelte or routes/egress/+page.svelte
  lib/components/           # provider, data-class, destination, channel controls
docs/
  MILESTONE_4_DESIGN.md
  MILESTONE_4_IMPLEMENTATION_PLAN.md
```

## Task 1: Config And Endpoint Policy

**Files:** `crates/lumen-cli/src/config.rs`, `crates/lumen-cli/tests/config.rs`, `crates/lumen-integrations/src/openai_compatible.rs`, `crates/lumen-integrations/tests/openai_compatible.rs`, `docs/{MODEL_ROUTING,SECURITY}.md`

- [ ] Add failing config tests proving remote endpoints remain denied by default, `allow_remote = true` alone is insufficient, and a remote endpoint is accepted only with explicit provider ID plus allowed data classes.
- [ ] Add failing config tests proving `secret` is rejected as an allowed remote data class and unknown data classes fail strict parsing.
- [ ] Add failing OpenAI-compatible tests proving remote endpoint construction requires explicit `EndpointPolicy::AllowRemote`, redirects remain disabled, and provider identity reports `Remote`.
- [ ] Confirm the focused tests fail before implementation.
- [ ] Implement bounded data-class parsing and explicit remote-provider bootstrap config.
- [ ] Keep loopback endpoints valid without remote egress policy.
- [ ] Run `cargo test -p lumen-cli --test config` and `cargo test -p lumen-integrations --test openai_compatible`.
- [ ] Commit as `feat(egress): require explicit remote model policy`.

## Task 2: Core Egress Policy Types

**Files:** `crates/lumen-core/src/{lib,egress,capability,model}.rs`, `crates/lumen-core/tests/core_security.rs`

- [ ] Add failing tests for data-class ordering, canonical provider IDs, canonical destination scopes, and rejection of secret egress.
- [ ] Add failing tests proving `network.egress` and `channel.send` action scopes are exact and fingerprinted.
- [ ] Add failing tests for routing decisions: local preferred, remote denied by default, workspace exception required for `workspace` and `sensitive`, no silent fallback.
- [ ] Confirm the focused tests fail before implementation.
- [ ] Implement `DataClass`, `ProviderEgressPolicy`, `DestinationScope`, and routing decision helpers.
- [ ] Run focused core tests, formatting, and strict Clippy.
- [ ] Commit as `feat(core): define controlled egress policy`.

## Task 3: SQL Provider And Policy State

**Files:** `crates/lumen-db/migrations/0004_controlled_egress.sql`, `crates/lumen-db/src/{lib,egress}.rs`, `crates/lumen-db/tests/{database,egress}.rs`, `docs/DATA_MODEL.md`

- [ ] Add failing migration tests for provider records, workspace routing rules, destination grants, channel mappings, and foreign keys.
- [ ] Add failing repository tests for provider enablement, allowed data-class updates, workspace policy versions, secret-reference-only credentials, and immutable audit-relevant revisions.
- [ ] Confirm the focused tests fail before implementation.
- [ ] Implement append-only migration and transactional repositories.
- [ ] Run database and egress repository tests.
- [ ] Commit as `feat(db): persist controlled egress policy`.

## Task 4: Runtime Model Routing

**Files:** `crates/lumen-cli/src/{runtime,config}.rs`, `crates/lumen-cli/src/runtime/security_tests.rs`, `crates/lumen-integrations/src/openai_compatible.rs`

- [ ] Add failing end-to-end tests proving public remote requests work only when policy permits the provider.
- [ ] Add failing tests proving workspace and sensitive data stay local unless a workspace exception exists.
- [ ] Add failing tests proving remote provider failures do not silently fallback to another unconfigured remote provider.
- [ ] Confirm the focused tests fail before implementation.
- [ ] Compose provider selection through the existing run lifecycle and audit model-turn metadata.
- [ ] Run focused runtime security tests.
- [ ] Commit as `feat(runtime): route models through egress policy`.

## Task 5: Network Egress Actions

**Files:** `crates/lumen-core/src/{action,capability,egress}.rs`, `crates/lumen-integrations/src/network.rs`, `crates/lumen-cli/src/runtime.rs`, focused tests under owning crates`

- [ ] Add failing tests for canonical destination scopes, no redirects to unapproved origins, request/response byte limits, secret header redaction, and approval-bound dispatch.
- [ ] Confirm the focused tests fail before implementation.
- [ ] Implement a runtime-owned HTTP egress action adapter using reqwest with redirects disabled and exact destination checks.
- [ ] Route plugin-returned network proposals through normal capability, approval, execution, and audit paths.
- [ ] Run focused network and runtime tests.
- [ ] Commit as `feat(runtime): add destination-scoped network egress`.

## Task 6: External Channel Identity And API

**Files:** `crates/lumen-core/src/identity.rs`, `crates/lumen-db/src/egress.rs`, `crates/lumen-integrations/src/channels.rs`, `crates/lumen-server/src/routes/mod.rs`, `crates/lumen-server/tests/routes.rs`

- [ ] Add failing tests for unknown inbound channel denial, stable external-to-Lumen identity mapping, workspace allowlisting, and service identity ownership.
- [ ] Add failing tests for outbound `channel.send` requiring exact channel destination scope and approval when authority expands.
- [ ] Confirm the focused tests fail before implementation.
- [ ] Implement channel records, identity mapping helpers, and authenticated API routes for channel review.
- [ ] Run focused server and integration tests.
- [ ] Commit as `feat(channels): add allowlisted external identities`.

## Task 7: Operator Control Surface

**Files:** `apps/web/src/lib/api.ts`, `apps/web/src/lib/components/*`, `apps/web/src/routes/*`, `apps/web/tests/control-surface.spec.ts`

- [ ] Add failing API/component tests for provider enablement, data-class policy, destination scopes, channel allowlisting, secret redaction, and conflict states.
- [ ] Confirm frontend tests fail before implementation.
- [ ] Add compact settings/egress controls with provider, workspace, data-class, destination, and channel views.
- [ ] Route sensitive policy expansion to existing approval workflows.
- [ ] Run Svelte diagnostics, unit tests, production build, and Playwright.
- [ ] Commit as `feat(web): add egress controls`.

## Task 8: Milestone 4 Verification

**Files:** security tests under owning crates, `README.md`, `docs/{ARCHITECTURE,DATA_MODEL,MODEL_ROUTING,PLUGIN_SYSTEM,ROADMAP,RUNTIME_EXECUTION,SECURITY}.md`, this plan

- [ ] Add adversarial tests for prompt-injected URLs, plugin-proposed ungranted destinations, redirect attempts, secret leakage, unknown channels, provider disablement, workspace policy revocation, and audit failure.
- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets -- -D warnings`.
- [ ] Run `CARGO_INCREMENTAL=0 cargo test --workspace`.
- [ ] Run frontend checks, unit tests, production build, and Playwright.
- [ ] Update Roadmap Milestone 4 only for behavior proven by the suite.
- [ ] Run `git diff --check`.
- [ ] Commit and push the completed milestone branch.
