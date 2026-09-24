# ADR-0004: Canonical encoding and protocol versioning

- Status: Accepted (phase-0 spike)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Design doc §"Protocol", implementation plan phase 0

## Context

Action digests, audit chain hashes, and lease narrowing proofs are only
meaningful if every party serializes the same bytes. JSON's freedoms
(key order, number formatting, unicode escapes, duplicate keys) make naive
`serde_json::to_string` hashing non-deterministic across implementations
(Rust kernel, TypeScript extension, future Go/Python clients).

## Decision

- **Canonical JSON**: recursively sorted object keys, integers only (no
  floats), no insignificant whitespace, UTF-8, no duplicate keys. Implemented
  once in `lumen_core::pi_boundary::canonical_json`; all digests
  (`ActionEnvelope::digest`, `AuditEvent::compute_hash`) hash the canonical
  form with SHA-256.
- **Explicit version fields** on every contract (`ActionEnvelope v1`,
  `PolicyDecision v1`, `PiBridge v1`, `AuditEvent v1`, `SandboxDriver v1`,
  wire `lumen-kernel/1`). Deserialization rejects unknown versions; there
  is no default-allow path for unversioned or newer-than-known messages.
- **Frozen fixtures**: checked-in JSON fixtures under
  `crates/lumen-core/tests/fixtures/` pin the v1 bytes, digests, and chain
  links. Any serialization change breaks the fixture tests loudly.

## Rationale

- Digests must verify across languages (the TS extension computes the same
  action digest the Rust kernel audits). Canonical form is the only sane
  basis.
- Version rejection is a security property: a v2 envelope must never be
  evaluated by v1 policy logic that doesn't understand its fields.
- Fixtures make the "frozen" claim testable rather than aspirational.

## Consequences

- All future protocol changes go through a new version + new fixtures; v1
  parsing code is never "extended in place".
- Numbers on the wire are integers only; millisecond timestamps, byte
  counts, and quotas fit comfortably. If fractional values are ever needed,
  they arrive as a new version with an explicit decimal encoding.
- The TS extension and any future client must implement the same canonical
  form; the fixtures are the conformance reference.

## Alternatives considered

- CBOR / protobuf: better canonicalization stories, worse debuggability and
  worse interop with Pi's JSONL-native RPC. Revisit if JSON canonicalization
  proves error-prone in a second client implementation.
- Hashing `serde_json::to_string` output: rejected — key order is
  insertion order, not deterministic across producers.
