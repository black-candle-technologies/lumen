# Lumen Messaging Adapters (Phase 5)

Host-side adapters translate provider events into the provider-neutral
`MessageEnvelope` and route every outbound effect through the kernel's lease
checks, metering, and audit. Adapters do **not** run inside Pi, never expose
provider credentials to the model, and never treat an incoming message as
authorization to act.

**Uniform authority rule:** no messaging provider can extend a lease, approve
its own request, or bypass VHL. A message can ask; only the kernel can
authorize.

## Crate layout (`crates/lumen-messaging`)

| Module | Contents |
|---|---|
| `envelope` | `MessageEnvelope`: provider, connection, conversation, sender + verified mapping, message id + dedupe key, content + attachment refs, reply context, `received_at`, provenance (adapter version + raw-event digest), transport trust |
| `dedupe` | `DedupeStore` trait + in-memory impl; checked **before** an event may enter a Pi session |
| `principals` | Explicit external-identity → principal mapping registry; fail closed on unknown/ambiguous |
| `attachments` | Quarantine: size/type policy, SHA-256 digest, pluggable sandbox scanner; fail closed on inconclusive scans |
| `outbound` | Typed verbs (`send`/`edit`/`react`/`delete`/`moderate`/`upload`), per-verb lease scope checks, idempotency keys, receipt persistence, fail-closed audit gating |
| `adapters::courier` | Native baseline: supervised `courier stdio` subprocess, session-identity binding, VHL carriage, signed handoffs, receipt correlation |
| `adapters::discord` | Beta scaffolding (feature `discord` + runtime flag): Ed25519 interaction verification, allowlists, typed resources, REST call descriptors |
| `adapters::signal` | Disabled by eligibility decision |

## Pipeline order (inbound)

1. Verify provider signature / authenticated session.
2. Deduplicate (`DedupeStore::check_and_insert`): first sighting proceeds,
   known redelivery is skipped (`Ok(None)` from `ingest`), a store outage
   fails closed (`IngestError::DuplicateUncertain`).
3. Map the sender explicitly (`PrincipalMappingRegistry::resolve`); unknown or ambiguous fails closed.
4. Quarantine attachments (`attachments::quarantine`).
5. Normalize into `MessageEnvelope` with provenance.

## Pipeline order (outbound, `OutboundPipeline::execute`)

1. Validate the request (verb-specific required fields).
2. Declared-capability check against the adapter descriptor.
3. Idempotency: a replayed key returns the stored `DeliveryReceipt`; the provider is never called twice.
4. Kernel lease check over an `ActionEnvelope` (`message.send`, `message.edit`, …) scoped to the exact target resource.
5. Pre-send audit record — **if audit persistence is unavailable, the send is blocked**.
6. Adapter executes the provider call with the kernel-brokered credential.
7. Receipt persisted; post-send audit recorded (a post-send audit failure surfaces the receipt for reconciliation instead of retrying).

## Enablement flags

| Adapter | Cargo feature | Runtime flag | Default |
|---|---|---|---|
| Courier | — | `LUMEN_MESSAGING_COURIER` | enabled |
| Discord | `discord` | `LUMEN_MESSAGING_DISCORD` | disabled (beta) |
| Signal | — | `LUMEN_MESSAGING_SIGNAL` (ignored) | disabled (not eligible) |

`MessagingConfig::from_env()` reads the `LUMEN_MESSAGING_*` variables.

## Phase-4 integration seams

Marked `TODO(PHASE4)` in code:

- **Session identity**: phase-4 issues the ephemeral per-session Courier keypair and materializes it into a kernel-owned directory. The adapter binds it (`CourierAdapter::bind_session`) and spawns the CLI with `HOME` pointed there; it never mints identities or holds key material.
- **VHL verification**: the adapter *carries* the kernel-minted approval digest + nonce in Courier message bodies (`VhlCourierCarriage`); verification against the kernel approval store lands with phase-4.
- **Handoff signatures**: `HandoffArtifact` carries countersignatures; verification against session keys lands with phase-4.
- **Per-verb capabilities**: all verbs currently carry `message.send`; finer-grained capability names when the kernel defines them.

## Failure posture

Lost provider auth, identity ambiguity, duplicate uncertainty, or audit
failure **blocks outbound effects**. Reasoning may continue; sending may not.

## Rollback

Each adapter is independently removable:

- `AdapterRegistry::disable(name)` revokes the adapter and invalidates its credential handle without touching the kernel or other channels.
- Removing `crates/lumen-messaging` from the workspace members and deleting the crate directory removes all messaging support; no other crate depends on it.
- Discord: unset `LUMEN_MESSAGING_DISCORD` (or build without the `discord` feature) to return to Courier-only.
