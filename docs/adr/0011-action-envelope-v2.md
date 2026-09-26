# ADR-0011: reject lossy authority decoding

Status: proposed Phase 1 change. Kernel producer and host/protocol consumer
sign-off pending. Production Pi admission remains disabled.

The recorded ActionEnvelope v1 probe at `8762188` adds unknown authority fields
at six levels. Serde accepts them, discards them and produces the same action
digest. JSON object maps also ordinarily overwrite duplicate keys. Neither
behavior is acceptable before authority evaluation or human digest review.

## Decision

ActionEnvelope v2 retains typed field names, uses a signed/digested version of 2,
and rejects unknown fields throughout tools, inputs, resources and effects. The
live decoder rejects every other version. Typed arguments recursively reject
duplicate object keys and non-integer numbers before conversion to JSON values.
Structural validation applies during decode and again before kernel evaluation;
there is no repair of an already approved envelope. Input hashes and pinned tool
versions must be valid. Filesystem resolution still belongs to the kernel;
lexical path normalization is not evidence of symlink or mount confinement.

The host's current envelope representation also moves to version 2 and uses the
same strict JSON argument decoder. Its conversion to the kernel representation
remains explicit; host transport and kernel action digests are distinct and must
not be substituted for one another. Consolidating these representations and
proving the complete execution path remain required host integration work.

The legacy host action channel is named `lumen-host-action/2`; it must no longer
share a protocol identifier with the different kernel wire schema. It remains
unavailable to production Pi while admission is disabled. Its v1 ChannelDecision
is an outcome rendering, not PolicyDecision or reusable authority. Rejected raw
requests are audited with fixed reasons and no caller-controlled identity or
parser text; an audit failure/timeout produces an error and no sandbox dispatch.

PolicyDecision v3 rejects unknown fields and versions, including nested reasons
and obligations. The host representation uses the same version and strict
decision/obligation decoding. Kernel JSONL transport becomes `lumen-kernel/2`,
with strict request/response field and protocol decoding. A response must contain
either a decision with its action digest and audit sequence, or an error; missing
and contradictory authority fail closed. The new request contains ActionEnvelope v2. The
old authority-bearing PiBridge tool-request decoder is retired: the proposed
intent-only PiBridge v2 in the host is the replacement, not a new way for Pi to
supply an envelope or lease. Legacy non-authority event/cancellation fixtures are
unchanged. Sandbox contracts still require review; this change does not claim to
have validated every remaining authority decoder.

No privileged service, credential path, execution mechanism or production
admission route is added. Kernel, host and protocol owners review the code,
fixtures, migration and operator instructions together before acceptance.

## Migration and evidence

Migration 0030 only appends action-envelope, policy-decision, kernel-wire and
host-action-channel version metadata.
It never edits historical action, approval, lease or audit bytes. v1 fixtures
remain in the repository and their digests/chain references are still verified
as raw historical evidence; they must not decode into live authority. Separate
v2 fixtures cover positive round trips and request/response digest binding.

Before a separately authorized deployment, stop admission, drain actions,
reconcile all usage, terminate sessions and revoke their authority. Record the
complete audit chain and a restore point. Pending v1 approvals must be left as
history or explicitly cancelled using the old kernel; never change their digest,
nonce, inputs or signatures into a v2 approval. A new request requires a new
human decision. The v2 version changes the action digest, so a valid v1 approval
cannot authorize a v2 action.

Older binaries refuse schema 0030. Rollback requires the reviewed pre-migration
backup with admission stopped, or a forward fix. Scratch migration/restart tests
do not replace the operator staging restore rehearsal. Negative tests must cover
unknown nested fields, duplicate argument keys, old/future versions, malformed
hashes and tool pins, raw transport rejection, and old-approval digest binding.
