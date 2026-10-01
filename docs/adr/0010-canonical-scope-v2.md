# ADR-0010: strict canonical resources and typed scope digests

Status: proposed Phase 1 contract change. Kernel producer and host/persistence
consumer owner sign-off are pending. Phase 0 admission stays disabled.

The reference implementation admits unknown scope fields and bypasses identifier
validation during Serde decoding. Its scope digest concatenates resource strings;
path-view suffixes and account delimiters can collide. Real Linux symlink targets
containing non-UTF-8 bytes also collapse through `to_string_lossy`. These violate
the authority contract even without assuming a downstream exploit.

## Decision and threat review

Use validated typed resource values at decode, issuance, signing and persistence
boundaries. Reject unknown nested fields, malformed components, noncanonical
ports/hosts, invalid identifiers and invalid method tokens. Budget maps reject
duplicate/unknown dimensions. Explicit zero entries survive signed-data decoding
unchanged; setting a previous cap to zero removes the earlier grant. Do not normalize an
already signed document into a different meaning. User-input parsers may produce
normalized values; signed-resource decoding requires those values already be
canonical. Non-UTF-8 resolved filesystem components fail closed; no replacement
characters may be introduced. Resolution still does not pin an inode or mount:
execution/writeback must separately prove freedom from path races in Phase 2.

Scope digest v2 hashes a domain-separated, versioned canonical JSON object with
explicit dimensions and structured values. Set-valued grants are sorted and
exact duplicates removed. The encoder never concatenates authority dimensions
with punctuation. Filesystem-view flags remain explicit. Display paths are not
scope encodings. Existing ActionEnvelope v1 and audit payload encodings remain
unchanged; their historical fixtures must continue to pass.

LeaseDocument becomes v3. Its version is signed and v1/v2 authority is rejected.
The wire field names remain unchanged; v3 commits to strict typed scope semantics
and scope digest v2. Validation must precede nonce claims and budget reservations,
including for Rust callers constructing public scope fields directly. This uses
the existing kernel implementation and dependencies; it adds no privileged
service, credential path, execution mechanism or production admission route.

## Migration and rollback

Migration 0029 is forward-only and transactional. It records the contract versions
and rejects new lease rows with unsupported versions. Existing signed lease rows,
recorded scope digests, audit payloads and checkpoints are never rewritten.
Historical rows remain raw evidence; they are not upgraded or re-signed in place.
Before a deployment (separate authorization), stop admission, drain actions,
reconcile budgets, terminate sessions and revoke old roots/descendants using the
old kernel. Verify the audit chain and take a restore point. The new kernel must
refuse legacy live authority; grants and approvals require fresh issuance through
reviewed workflows. Unknown or unreconciled usage is never reset to zero.

An older binary must refuse the newer migration. Rollback means restoring the
reviewed pre-migration backup while admission remains stopped, or shipping a
forward fix; never downgrade a migrated database or re-enable unconfined Pi.
Restart, migration atomicity, old/new version rejection, signature/digest fixtures,
negative decoding and generated uniqueness/subset tests accompany this change.
These tests do not replace operator staging drills or independent owner review.
