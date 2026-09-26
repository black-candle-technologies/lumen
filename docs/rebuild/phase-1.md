# Phase 1 authority reset

Status: **in progress; gate not passed**. Branch:
`lumen-rebuild/phase-1-authority-reset`, stacked on the Phase 0 draft at `98afe01`.
Phase 0 production Pi admission remains disabled. Historical phase claims are
reference material; no merge, deployment or gate acceptance follows this draft.

## First verified gaps and changes

Actual probes against the reference core found unequal filesystem views with the
same scope digest, distinct Linux paths collapsed by lossy symlink resolution,
unknown scope fields accepted by decoding, and invalid tool names accepted by
Serde although the constructor rejected them. The reference account encoding also
concatenated provider and account identifiers with an allowed delimiter.

[ADR-0010](../adr/0010-canonical-scope-v2.md) defines the proposed scope-digest v2
and LeaseDocument v3 transition. Scope hashes now contain a version/domain and
structured resource dimensions. Set ordering and identical duplicate grants are
canonicalized; filesystem-view flags and account dimensions remain explicit.
Canonical path encodings are separate from display paths. Non-UTF-8 resolved path
components are rejected without replacement. Host parsing cannot reinterpret
userinfo, a port, or a path as a DNS name; CIDRs normalize network bits.

Signed resource decoding rejects unknown nested fields, invalid/noncanonical
identifiers, malformed paths, invalid port ranges and method scopes. It validates
without repairing signed data. Scope validation also applies to direct Rust
callers before issuance, signing and subset checks. Budget maps reject duplicate
or unknown dimensions, while retaining explicit signed zero entries. Setting an
existing cap to zero now removes the prior grant. The host
lease version follows the kernel's v3 constant instead of a separate v1 value.

Migration 0029 appends contract metadata and a version guard for new lease rows.
Old signed rows, digests, budget balances, audit events and checkpoints are not
rewritten. The new decoder refuses old authority. A real migration test verifies
byte preservation, signed audit verification after reopen, transactional rollback
on a late DDL failure, and old-migrator rejection of the new schema. New fixture
signatures/digests were generated independently with Python/Ed25519 using a public
test-vector seed; Rust verifies both the legacy signature and the v3 signature,
then rejects v2 authority independently of signature validity. Original action and
audit fixtures remain unchanged.

`scripts/rebuild/verify_authority_fixtures.py` verifies the scope digest and both
lease signatures without loading Lumen. CI runs it with Python/cryptography.
The historical fixture includes an explicit zero budget; migration preserves it
in signed bytes and typed ledger restoration instead of silently dropping it.

[ADR-0011](../adr/0011-action-envelope-v2.md) adds the next proposed transition:
ActionEnvelope v2, PolicyDecision v3 and `lumen-kernel/2`. Unknown nested authority
fields, old/future versions, recursively duplicated argument keys and non-integer
numbers are rejected before digest review. Input content hashes and exact tool
versions are validated. A kernel response must contain a complete decision with
digest/audit binding, or an error; contradictory or incomplete responses fail.
The old authority-bearing PiBridge request decoder is retired. The legacy host
action channel now has its own `lumen-host-action/2` identifier and remains
unavailable to production Pi. Malformed requests produce static, redacted audit
events; audit failure or timeout produces an error without sandbox dispatch.

Migration 0030 appends these contract versions without changing prior approval,
lease, budget or audit records. Tests verify transactional failure rollback,
restart preservation and older-binary refusal. The old action version changes
the digest: a cryptographically valid v1 approval cannot mint a lease for a v2
action. Prior approvals are never translated or re-signed; new requests need new
human review. Historical v1 fixture digests and audit references remain verified
as raw evidence, while new fixtures cover live decoding and transport binding.
The host fixture freezes both representations and their distinct digests; the
conversion rejects stale/future policy versions. The independent Python verifier
checks these digests as well as the core/protocol fixture copies.

The next persistence probe found a distinct audit failure: stored version
`4294967297` narrowed to v1 before hashing, so an unchanged v1 checkpoint could
verify the different stored version. Audit reads, checkpoint sequences, query
bounds/limits and sequence advancement now use checked integer conversions.
Append validates the existing tip's exact version and hash and refuses corrupt
or exhausted tips. This is not a full-history verification on each append.

Migration 0031 adds an exact-v1 guard for new audit rows and records the existing
audit contract version. It does not change the AuditEvent v1 encoding or hashes,
nor transform invalid historical bytes. The numeric regression tests retain a
valid signature while varying the stored version, exercise migration failure
rollback and restart preservation, reject overflowing query bounds, and fault
inject corruption/exhaustion without allowing a new append. Audit JSON decoding,
complete startup chain validation and signature-role distinctions still require
review; these checks do not finish the audit gate.

## Contract and operator review

Review code, fixtures, migrations, tests and ADR-0010/0011 together. Required owners:
kernel producer and host/persistence consumers. Their sign-offs are pending.

Before any authorized deployment, stop admission and drain actions on the old
kernel, reconcile every reservation, destroy sessions and revoke all old roots
and descendants. Verify the complete audit chain and record a restore point.
Unreconciled/unknown usage blocks migration admission. Do not reset balances or
re-sign old documents. New grants require new reviewed issuance; approval inputs
and signatures must never be translated silently.

The new binary refuses legacy live documents or malformed persisted authority.
Historical rows remain available as raw evidence, not executable authority. Older
binaries refuse newer schemas (0029/0030/0031); rollback needs the reviewed backup with
admission stopped, or a forward fix. Never downgrade a migrated database or
restore unconfined Pi. The migration tests exercise scratch databases; an operator
staging restore rehearsal remains outstanding.

An invalid historical audit version is evidence of an integrity failure. Stop
admission and preserve the original database for independent inspection; never
rewrite the version, hash, event, or checkpoint to make verification pass. Use a
reviewed verified restore point or a separately reviewed forward recovery plan.

## Verification and remaining gate work

Run on unprivileged Linux (lane-vps scratch or CI):

```sh
cargo test -p lumen-core -p lumen-db -p lumen-protocol -p lumen-server --lib --tests
cargo test -p lumen-acceptance --test pi_bypass_inventory
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

`canonical_contract` tests cover the demonstrated failures, generated scope
ordering/uniqueness, invalid issuance without nonce/budget mutation, frozen new
fixtures, migration failures and restart behavior. The actual non-UTF-8 filesystem
test is Linux-only: macOS rejects those filenames before the kernel resolver runs.
Other property/concurrency/restart suites still run; passing them does not by
itself establish all Phase 1 invariants.

[Recorded checks](evidence/phase1-contracts.json) tie the implementation at
`876218890d6262da285631d926e5abedd08a98d8` to matching hashes for all 434 tracked
source files in the Linux scratch checkout: 577 core/database/host tests in 31
suites passed, with no ignored tests. The 14 focused contract/migration tests,
independent fixture verifier and workspace Clippy also passed. Cargo emitted one
package-selection warning because the excluded desktop package does not exist;
there were no Rust/Clippy diagnostics. Logs and fixture/migration hashes are
recorded in that evidence. [Draft PR #85](https://github.com/black-candle-technologies/lumen/pull/85)
is stacked on Phase 0; owner review and phase acceptance remain pending.

[Action contract checks](evidence/phase1-action-contracts.json) tie `7d01adf` to
454 hash-matched files on lane-vps: 600 tests in 35 suites and the 14 bounded
transport acceptance tests passed without ignores or warnings. Workspace Clippy
and the independent fixture verifier passed. This evidence predates the audit
numeric correction and is not its validation evidence.

[Audit numeric checks](evidence/phase1-audit-numeric.json) tie `546c123` to 458
hash-matched files on lane-vps: 605 tests in 36 suites, workspace Clippy and the
independent fixture verifier passed without ignores or warnings. The
[pre-correction probe](evidence/phase1-audit-version-probe.json) records the
stored-version alias and successful checkpoint verification before correction.

The [restart characterization](evidence/phase1-session-restart-gap.json) records
an unresolved violation in the inherited implementation and tests. Reopening the
kernel leaves the ephemeral identity vault empty, but hydrates public session
records as live authority; retained root/child leases verify, and a retained
one-shot envelope completes through the test pipeline. These passing reference
tests express the wrong requirement. Startup must invalidate old sessions and
revoke descendants before admission, preserve audit/nonces/budget history, and
require fresh session authority. Boot failures, concurrent authority owners and
unknown execution usage must also fail closed. The pipeline test uses a mock
sandbox; this evidence does not claim a production external effect.

The historical decoder gap is reproduced in the
[ActionEnvelope v1 probe](evidence/phase1-action-v1-probe.json). Adding an unknown
authority field at the envelope, tool, input, resource-set, path-resource or
effect-class level is accepted and leaves the decoded action digest unchanged.
This is a decoder observation at the recorded commit, not proof of an external
effect. ADR-0011's proposed revision rejects these fields and preserves v1 bytes
as historical evidence. Producer/consumer acceptance is still pending.

Remaining work includes other authority decoders and complete host/kernel
representation reconciliation,
mount/inode identity and resolution-to-execution races, complete lease-chain and
nonce revalidation, budget reservation/spend/reconciliation under process faults,
measured transitive revocation latency, deterministic redaction and independent
audit verification tied to the final phase artifacts. Production authority
admission, owner acceptance and operator staging drills remain open. Phase 2 must
prove per-action Firecracker isolation and writeback; these resource tests do not
substitute for that boundary.
