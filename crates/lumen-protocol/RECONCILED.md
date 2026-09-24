# `lumen-protocol`: reconciliation record (integration restack, 2026-09-24)

## Decision

**This crate is a thin re-export facade over `lumen_core::pi_boundary`; the
superseded snapshot (`5498b7b`) was not retained.**

The Phase-0 frozen authority is `crates/lumen-core/src/pi_boundary.rs`,
pinned by the seven ADRs in `docs/adr/` and the checked-in fixtures
(`fixtures/*.v1.json`, copied from the frozen set). The snapshot duplicated
those contracts with materially different shapes and would have forked the
protocol. There is exactly one definition of each wire type; `lumen-core`
does not depend on `lumen-protocol` (the reverse), so there is no cycle.

## Per-type reconciliation

| Contract | Snapshot (`5498b7b`) | Frozen (kept) | Notes |
|---|---|---|---|
| `ActionEnvelope` | `protocol_version`, `action_id: String`, `arguments: Value` (floats allowed), `input_hashes: Vec<String>`, string path/host/secret lists, `Vec<EffectClass>`, string lease ids, RFC3339 `expires_at` | `version`, `action_id: Uuid`, `arguments: BTreeMap<String, Value>` integer-only, `inputs: Vec<InputRef>`, typed `PathResource`/`NetworkResource`/`SecretRef`, boolean `EffectClasses`, `LeaseId(Uuid)`, `expires_at_ms: i64` | Kernel-internal `EffectClass` (lease scopes) derived from frozen `EffectClasses` in `lumen_core::lease::CanonicalAction::from_envelope`; per-resource declared rights (`PathRights`) used for path authorization. Snapshot fixture digest `b3ea…` does not match frozen digest `ef12…` — the fixtures here are the frozen set. |
| `PolicyDecision` | `action_digest`, `decided_at` (RFC3339), free-form `reason`, allow `lease_id`, `bind()` helper | `version`, `DecisionOutcome` tagged by `"decision"`, typed `Obligation`, typed `DenyReason`, `PendingApproval { approval_id, reason }` | Action binding moved to the wire layer (`KernelWireResponse.action_digest`); the covering lease id stays available to audit callers via the `validate_chain` path (recorded in event `detail`). `bind()` removed. |
| `AuditEvent` | snapshot shape + `AuditLink` on the wire | `version`, `event_id: Uuid`, `sequence`, `timestamp_ms`, typed `AuditActor`, typed `AuditEventKind`, `action_digest`, optional `decision`, `detail`, `prev_hash`/`hash` | `AuditLink` is a kernel-internal runtime record in `lumen_core::kernel_audit`, not a wire contract. |
| Pi bridge | `PiEvent` / `PiCommand` / `PiToolRequest` (raw JSONL process model) | `BridgeToolRequest`, `BridgeCancellation`, `BridgeEvent` | The raw-JSONL process model is Phase-3 runtime implementation, not a frozen contract. |
| `SandboxDriver` | v0: `Stateful` profile, `ResourceLimits`, `NetworkPolicy`, `SandboxRunSpec`, `SandboxResult`, `wait()` | v1: `SandboxProfile::Strict` only, `SandboxQuotas`, typed egress allowlist, `SandboxHandle`, `prepare`/`start`/`stream`/`cancel`/`export`/`destroy` | sandboxd keeps wide runtime types (`DaemonRunSpec`, `DaemonLimits`, `DaemonNetworkPolicy`) internally with explicit conversion to/from frozen wire types. |

## Superseded-snapshot defects (not carried forward)

- `cargo clippy -p lumen-protocol --all-targets` on the snapshot reported 3
  warnings, all in `src/audit.rs`: unused imports `sha2::{Digest, Sha256}`
  (line 11) and an unneeded `mut` on `event` in `append` (line 94).
- The snapshot's own `tests/fixtures.rs` did not compile: unresolved imports
  `lumen_protocol::ACTION_ENVELOPE_VERSION` and `lumen_protocol::SandboxProfile`.

## Verification

- `cargo test -p lumen-protocol` — 6 fixture tests parse every frozen
  fixture through the re-exported types, including the envelope digest check
  and the audit chain-link recomputation.
