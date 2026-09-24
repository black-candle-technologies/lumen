# Courier transport decision

**Decision:** the Courier adapter shells out to the `courier` CLI as a
supervised subprocess over its documented JSON-lines agent bridge
(`courier stdio`). No in-process Rust client is used.

## Why not a Rust client

`black-candle-technologies/courier` is Go-only. Verified 2026-09-23:

- crates.io API search for `courier`: no Black Candle client crate exists.
- GitHub code search over `black-candle-technologies/courier`: one repository, language Go, no Rust client module.

Writing a from-scratch Rust reimplementation of the Courier protocol
(Ed25519/X25519 identity, relay wire protocol, E2E session crypto) inside
the Lumen host would duplicate a security-critical codebase and risk
divergence. Shelling out keeps one canonical implementation of the crypto.

## The `courier stdio` contract

Grounded in `cmd/courier/main.go` (`courier stdio` bridge), reviewed release
line. JSON-lines on stdin/stdout:

- Request: `{"id":N,"cmd":"send","to":addr,"body":text,"reply_to":M?}`
- Request: `{"id":N,"cmd":"inbox","after":cursor?,"limit":N?}`
- Request: `{"id":N,"cmd":"address"}` / `{"id":N,"cmd":"health"}`
- Response: `{"id":N,"ok":bool,"error"?,"address"?,"message_id"?,"messages"?}`
- Message: `{id, from, body, sent_at, received_at, flags?, request?, reply_to?, reply_quote?, bridged?}` — timestamps are Unix **seconds** (grounded: `time.Now().Unix()` in the Go client); the adapter converts to millis.

CLI surface used (from `courier --help` output, same source):
`courier send <address|contact|@handle> <msg>` (`-` reads stdin,
`--attach`, `--reply-to`, `--ttl`), `courier inbox [--follow]`,
`courier wake -- <command>` (new-message JSON on stdin),
`courier receipts`, `courier version`, `courier address`.

## Supervision and credential brokering

- The adapter spawns `courier stdio` once at `bind`, multiplexes requests by
  `id` over oneshot channels, and enforces a per-request timeout (default 30s).
- Reader/writer tasks detect child death; a dead child surfaces as
  `ConnectionState::AuthLost` and blocks outbound effects.
- **Key material never enters the Pi process.** The kernel materializes the
  ephemeral per-session identity into a kernel-owned directory; the child
  runs with `HOME` pointed there so the CLI reads
  `<identity_dir>/.courier/config.json`. The adapter receives the directory
  path only — never key bytes. (Phase-4 owns identity materialization;
  see `TODO(PHASE4)`.)
- The environment is otherwise inherited so proxy variables honored by the
  courier client (`HTTPS_PROXY`, etc.) keep working.
- Bind pins the reviewed binary: `courier version` must satisfy
  `min_version`, and an optional expected SHA-256 (`expected_binary_sha256`)
  fails closed on mismatch.

## Signature verification layering

Courier verifies Ed25519 message signatures on receipt (relay and
recipients verify). The adapter treats only CLI-delivered output as
authenticated, then applies Lumen's own layers: version-pinned supervised
bridge, dedupe before Pi-session entry, explicit principal mapping
(fail closed), and attachment quarantine.

## VHL and handoffs

- **VHL requests** travel natively: `VhlCourierCarriage`
  `{approval_id, action_digest, nonce, expires_at_millis}` is serialized into
  the message body as `{"lumen_vhl":{...},"text":"..."}`. The adapter
  carries the kernel-minted digest + nonce; it never mints them, and
  verification against the kernel approval store is a phase-4 seam.
- **Signed handoffs**: `HandoffArtifact` binds `{artifact_id,
  from_session, to_session, payload_digest}` with carried countersignatures
  (hex Ed25519 over the canonical bytes). Payload digests are re-verified on
  decode; signature verification against session keys is a phase-4 seam.

## Delivery/receipt correlation

`send` returns the provider message id, correlated to the idempotency key in
the persisted `DeliveryReceipt`. Read/delivery status polling via
`courier receipts` is a host follow-up (the stdio bridge has no receipts
command); the correlation key is already in place.

## Limits of this transport

- The stdio bridge exposes `send` but not edit/react/delete or attachments;
  the adapter declares `outbound_verbs = ["send"]` and fails closed on other
  verbs. Attachment upload would need `courier send --attach` with
  quarantine-resolved bytes — a host wiring follow-up.
- Group/channel sends are not yet mapped (DM-focused baseline); the ingest
  path already tolerates `group_id`/`channel_id` context fields.
