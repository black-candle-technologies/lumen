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

## Contract and operator review

Review code, fixtures, migration, tests and ADR-0010 together. Required owners:
kernel producer and host/persistence consumers. Their sign-offs are pending.

Before any authorized deployment, stop admission and drain actions on the old
kernel, reconcile every reservation, destroy sessions and revoke all old roots
and descendants. Verify the complete audit chain and record a restore point.
Unreconciled/unknown usage blocks migration admission. Do not reset balances or
re-sign old documents. New grants require new reviewed issuance; approval inputs
and signatures must never be translated silently.

The new binary refuses legacy live documents or malformed persisted authority.
Historical rows remain available as raw evidence, not executable authority. Older
binaries refuse schema 0029; rollback needs the reviewed pre-migration backup with
admission stopped, or a forward fix. Never downgrade a migrated database or
restore unconfined Pi. The migration tests exercise scratch databases; an operator
staging restore rehearsal remains outstanding.

## Verification and remaining gate work

Run on unprivileged Linux (lane-vps scratch or CI):

```sh
cargo test -p lumen-core -p lumen-db -p lumen-server --lib --tests
cargo clippy -p lumen-core -p lumen-db -p lumen-server --all-targets -- -D warnings
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

The next decoder gap is reproduced in the
[ActionEnvelope v1 probe](evidence/phase1-action-v1-probe.json). Adding an unknown
authority field at the envelope, tool, input, resource-set, path-resource or
effect-class level is accepted and leaves the decoded action digest unchanged.
This is a decoder observation, not proof of an external effect. The next contract
revision must reject these fields and preserve v1 bytes only as historical
evidence, with producer/consumer review and migration fixtures.

Remaining work includes the other frozen authority decoders (ActionEnvelope and
nested resources currently need a separate versioned strict-decoding transition),
mount/inode identity and resolution-to-execution races, complete lease-chain and
nonce revalidation, budget reservation/spend/reconciliation under process faults,
measured transitive revocation latency, deterministic redaction and independent
audit verification tied to the final phase artifacts. Production authority
admission, owner acceptance and operator staging drills remain open. Phase 2 must
prove per-action Firecracker isolation and writeback; these resource tests do not
substitute for that boundary.
