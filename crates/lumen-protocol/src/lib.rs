//! Lumen protocol: the frozen Phase-0 wire contracts, re-exported.
//!
//! ADR-0011 proposes strict ActionEnvelope v2, PolicyDecision v3 and kernel
//! transport v2. Superseded action/decision/transport fixtures remain raw
//! historical evidence and are rejected by live decoders. The legacy
//! authority-bearing PiBridge tool request is retired; the host owns the
//! intent-only PiBridge v2. The table below records the historical restack,
//! not permission to admit the old authority versions.
//!
//! # Why this crate is a re-export facade
//!
//! The authoritative wire contracts are frozen in
//! [`lumen_core::pi_boundary`] (Phase 0: `crates/lumen-core/src/pi_boundary.rs`,
//! pinned by the seven ADRs in `docs/adr/` and the checked-in JSON fixtures
//! under `fixtures/`). An earlier Phase-1 snapshot of this crate
//! (`lumen-protocol` at `5498b7b`) duplicated those contracts with materially
//! different shapes (stringly-typed fields, `Vec<EffectClass>`,
//! RFC3339 timestamps, `protocol_version`, `AuditLink` on the wire, …) and
//! could not be retained as-is: two competing definitions of the same wire
//! types would fork the protocol.
//!
//! Reconciliation decision (integration restack, 2026-09-24): this crate is a
//! thin facade. Every contract type is re-exported from `pi_boundary`; there
//! is exactly one definition. `lumen-core` does **not** depend on this crate
//! (the reverse), so there is no dependency cycle.
//!
//! # What changed per contract type
//!
//! | Contract | Superseded snapshot (`5498b7b`) | Frozen authority (`pi_boundary`) |
//! |---|---|---|
//! | Action envelope | `protocol_version`, `action_id: String`, `arguments: Value`, `input_hashes: Vec<String>`, string path/host/secret lists, `Vec<EffectClass>`, string lease ids, RFC3339 `expires_at`, floats allowed | `version`, `action_id: Uuid`, `arguments: BTreeMap<String, Value>` (integer-only), typed `inputs: Vec<InputRef>`, typed `PathResource` / `NetworkResource` / `SecretRef`, boolean `EffectClasses`, `LeaseId(Uuid)`, integer `expires_at_ms` |
//! | Policy decision | carried `action_digest`, `decided_at` timestamp, free-form `reason`, allow `lease_id` | `version`, `DecisionOutcome` tagged by `"decision"`, typed `Obligation`, typed `DenyReason`, `PendingApproval { approval_id, reason }`; binding to the action happens at the wire layer (`KernelWireResponse.action_digest`) |
//! | Audit event | incompatible shape (`AuditLink`, own hash scheme) | `version`, `event_id: Uuid`, `sequence`, `timestamp_ms`, typed `AuditActor`, typed `AuditEventKind`, `action_digest`, optional `decision`, `detail`, `prev_hash`/`hash` chain |
//! | Pi bridge | `PiEvent` / `PiCommand` / `PiToolRequest` (raw JSONL process model) | `BridgeToolRequest`, `BridgeCancellation`, `BridgeEvent`; JSONL parsing helpers are runtime implementation, not wire contracts |
//! | Sandbox driver | `SandboxDriver` v0 with `Stateful` profile, detailed `ResourceLimits`, `NetworkPolicy`, `SandboxRunSpec`, `SandboxResult`, `wait` method | `SandboxDriver` v1 with only `SandboxProfile::Strict`, `SandboxQuotas`, typed egress allowlist, `SandboxHandle`, `stream`/`export`/`destroy`; Firecracker's detailed resource config stays sandboxd-internal |
//!
//! # Snapshot-only items (not frozen contracts)
//!
//! - `AuditLink` (checkpoint link records) moved to kernel-internal types in
//!   `lumen_core::kernel_audit`; checkpoints are runtime records, not wire.
//! - The snapshot's raw `PiEvent`/`PiCommand` JSONL parsing model has no
//!   frozen counterpart; the host/Pi implementation (Phase 3) owns it as
//!   runtime code.
//! - The snapshot's wide `ResourceLimits` / `NetworkPolicy` / `SandboxResult`
//!   shapes survive as sandboxd-internal runtime types with explicit
//!   conversion to/from the frozen wire types; they are not re-declared here.

// ---------------------------------------------------------------------------
// Action envelope contract
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{
    ACTION_ENVELOPE_VERSION, ActionEnvelope, EffectClasses, InputRef, LeaseId, NetworkResource,
    PathResource, PathRights, ResourceSet, SecretRef, ToolRef,
};

// ---------------------------------------------------------------------------
// Canonicalization (part of the envelope contract)
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{canonical_digest, canonical_json};

// ---------------------------------------------------------------------------
// Policy decision contract
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{
    DecisionOutcome, DenyReason, Obligation, POLICY_DECISION_VERSION, PolicyDecision,
};

// ---------------------------------------------------------------------------
// Pi bridge contract
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{
    BridgeCancellation, BridgeEvent, BridgeToolRequest, PIBRIDGE_VERSION,
};

// ---------------------------------------------------------------------------
// Audit event contract
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{
    AUDIT_EVENT_VERSION, AuditActor, AuditEvent, AuditEventKind, AuditLog,
};

// ---------------------------------------------------------------------------
// Sandbox driver contract
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{
    ExportedFile, NullSandboxDriver, OutputChunk, OutputSink, SANDBOX_DRIVER_VERSION,
    SandboxDriver, SandboxHandle, SandboxOutcome, SandboxProfile, SandboxQuotas, SandboxSpec,
    StreamStats,
};

// ---------------------------------------------------------------------------
// Kernel wire protocol contract
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{
    KERNEL_MAX_RECORD_BYTES, KERNEL_WIRE_PROTOCOL, KernelWireRequest, KernelWireResponse, WireError,
};

// ---------------------------------------------------------------------------
// Contract errors
// ---------------------------------------------------------------------------
pub use lumen_core::pi_boundary::{BoundaryError, KernelError, SandboxError};
