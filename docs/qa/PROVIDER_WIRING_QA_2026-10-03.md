# Lumen Provider Wiring QA Report

**Date:** 2026-10-03
**Branch:** `fix/apiint` (`8de265f`, 2 commits on `161a7033`)
**Scope:** Remote provider API-key wiring (lumen#87) plus regression pass over terminal surfaces
**Result:** PASS on provider wiring. 2 findings, 1 pre-existing bug. Full QA still in progress.

## Environment

- Host: lane-vps (Ubuntu), headless, no desktop secret service
- Build: `cargo build --workspace`, clean
- QA dir: `/home/ubuntu/lumen-qa`, config `lumen.toml`
- Workspace: `3292a55c-5d79-44f3-884d-00a2fa0b2897`
- Server: `127.0.0.1:3210`, bearer auth via `.token`
- Keyring: `gnome-keyring-daemon` + D-Bus session (see Finding 2)

## 1. Health check — PASS

`lumen health`: 8/8 checks ok.

- config: loaded and validated
- database: connected, 32 migrations applied (includes `0032_provider_configuration`)
- workspace: bootstrapped
- audit-chain: hash chain verified over 17 events
- sandbox: `linux-bubblewrap`, `KernelEnforced`
- plugin-admissions: store readable, 0 records
- data-directory: writable
- model-provider: configured, credential reference ready, network not tested

## 2. Provider credential lifecycle — PASS

`lumen provider credential create --metadata <json> --stdin`:

- Value enters via stdin only. Never in argv, env, config, or history. Max 16 KiB printable ASCII.
- Lifecycle is audited: `pending` on commit, `ready` after keyring write. A failed first attempt left a pending reference; the next create auto-cleaned it (revoked `b2c93ded-55cd-464d-a399-00b3a9c4b5e8`).
- No command reads a key back out. `provider credential list` shows metadata only.
- Key material lands in the OS keyring under service `dev.lumen.runtime`, account `provider:<workspace>:<reference>`.

## 3. Provider registration — PASS

`lumen provider register --file <json>` for both vendors:

| Provider | Protocol | Profile | Model | Revisions |
|---|---|---|---|---|
| openai-primary | openai | openai-text | gpt-4o-mini | 1/1/1/1 |
| anthropic-primary | anthropic | anthropic-text | claude-sonnet-5-5 | 2/2/2/2 |

- Optimistic concurrency on all four heads (provider, profile, egress, workspace_policy). Re-registration with stale heads is a clean conflict, not a silent overwrite.
- `provider list` / `provider show` report revisions, `credential_status: ready`, `network_status: not_tested`, `configuration_status: configured`.
- Model swap (haiku to Sonnet) was a new revision pointing at the same credential reference. No value mutation behind a pinned reference.

## 4. Live authentication — PASS

Real requests against both vendors through the registry profile path:

- OpenAI (`gpt-4o-mini`): `model_egress` authorized then completed. No 401.
- Anthropic (`claude-sonnet-5-5`): `model_egress` authorized then completed. No 401.
- Keys resolve per request from the keyring. Audit records authorized/completed/failed phases with profile and revision pins. No fallback to another provider on failure.

## 5. Audit log — PASS

- `lumen audit list`: 17 events, full payloads, tells the whole session story (early local-endpoint failure, pending credential, revocation, both keys ready, both registrations, every egress attempt including the failed Anthropic call).
- `lumen audit verify`: chain verified.

## 6. Secrets — PASS

- `secret create --label --program --environment` with stdin value. `--program` must be an existing executable path (canonicalized); a bare name fails with `No such file or directory`, which is correct scoping behavior with a confusing message.
- `secret list`: IDs and metadata only. No value exposure.
- `secret delete --id`: full lifecycle verified on a dummy secret.
- Provider credentials and regular secrets are separate scopes by design and do not leak into each other.

## 7. Plugin admission pipeline — PASS

Ran a minimal subprocess test plugin (`dev.qa.echo 0.1.0`) through the full lifecycle:

1. `plugin submit`: digest-pinned, stage `5be963bc`, status `submitted`
2. `plugin inspect`: package, manifest, artifact, and per-file digests all reported
3. `plugin test`: 4/4 pass (digest-reverification, source-lock, static-manifest, capability-policy)
4. `plugin approve --reason ... --yes`: status `approved`
5. `plugin install`: requested approval `6bc2dce8` (fingerprint, exact digest arguments, scoped capability, expiry all shown)
6. Approval granted via `POST .../approvals/{id}/decision` `{"decision":"grant"}`; install executed server-side; plugin lands `not_enabled` as designed

Approval flow notes:

- The web approvals UI is not built yet (CLI points at `docs/WEB_UI_FOLLOWUP.md`).
- A CLI-created run that requests approval is orphaned when the CLI exits; the install only completed when re-driven through the `plugins/actions` API.
- `plugins/actions` requires canonical `arguments` (409 without them).

## Findings

### Finding 1: Headless servers have no OS credential store (deployment gap)

The `keyring` v4 backend needs a D-Bus secret service. Stock headless Ubuntu has none, so the first credential create failed with `provider credential storage failed` and left a pending reference. Fix for QA was installing `gnome-keyring` + `dbus-x11`, starting a session bus and daemon, and exporting `DBUS_SESSION_BUS_ADDRESS` (saved to `~/.lumen-keyring-env`; helper at `~/bin/lumen-keyring-start.sh`). The daemon must be running for every `serve`, since keys resolve per request. `docs/REMOTE_PROVIDERS.md` should document this or the backend needs a server-suitable store.

### Finding 2: Planner prompt/schema mismatch (pre-existing, on master)

`POST .../orchestrations` 409s on every call: `planner: unknown field 'tasks', expected 'nodes'`. `JsonModelPlanner` (`lumen-control-plane/src/lib.rs`) prompts the model with "Return ONLY TaskGraphProposal JSON... <=256 tasks" but `TaskGraphProposal` deserializes with `deny_unknown_fields` expecting `nodes`. The model returns `{"tasks": [...]}`, parsing fails. The prompt is identical on `161a7033`, so this predates the branch. It blocks orchestration-based model behavior and tool-call QA until fixed.

### Non-finding: Anthropic 409 was a stale model ID

The first Anthropic attempt failed with `provider request failed`. Adapter request construction is correct (`x-api-key`, `anthropic-version: 2023-06-01`, `/v1/messages`). The cause was the guessed model ID `claude-3-5-haiku-latest`; `claude-sonnet-5-5` works. Not a code bug.

## Not yet covered

Leases, sessions, sandbox behavior beyond the health probe, web UI, tool calls through workers (blocked on Finding 2), failure handling.
