# Lumen rebuild: security program

This is the current delivery baseline. The implementations merged through PRs
#72–#79 (and the Phase-0 follow-ups) are reference material, not accepted phase
evidence. Older milestone documents describe that reference implementation.

Pi is an untrusted, long-lived JSONL RPC subprocess. Pi, extensions, model output,
and repositories are outside the trusted computing base. The only effect route is
Pi → host → kernel decision → disposable Firecracker microVM → controlled commit
→ signed audit. There is no direct Pi filesystem, shell, network, or provider path.
There is no desktop client in v1; clients are the web app and a thin CLI.

The kernel owns authority, policy, leases, budgets, VHL digest binding, ephemeral
session keys, and audit. The host owns supervision, the model gateway, authd
integration, adapters, and APIs. sandboxd owns the minimal privileged mechanism.
Provider credentials stay in the trusted host; they never enter Pi or guests.
authd's stable account identity is distinct from session authority. Jev only
recommends; every choice is rechecked against kernel policy and budget.

## Contract ownership

| Contract | Owner | Required authority-bearing contents |
|---|---|---|
| ActionEnvelope | Kernel | Action, canonical resources, exact inputs/effects, lease chain |
| PolicyDecision | Kernel | Explicit allow/deny/pending, typed reason and obligations |
| PiBridge | Host | Session events, typed tool intent, cancellation |
| AuditEvent | Kernel | Actor, action digest, decision, chain link |
| SandboxDriver | Sandbox | Prepare, start, stream, cancel, export, destroy |
| LeaseDocument | Kernel | Signed root/child documents; mechanical typed subsets |
| ApprovalRequest | Kernel | Immutable action digest, session, nonce, expiry |
| SandboxRunSpec / Result | Sandbox | Exact image/policy digests, known usage, export manifest |
| MessageEnvelope | Adapters | Provider, principal, conversation, message, retained provenance |

Unknown authority fields/versions fail closed. A breaking change needs a new
version, migration plan, new fixtures, and producer/consumer owner sign-off.
The existing conflicting host and kernel schema names must not be treated as
interchangeable. New codec work remains proposed until both owners sign off.

## Phase gates

Each phase has its own branch and draft PR, stacked after its prerequisite. Green
CI and subsystem-owner review precede merge. Merge, release, tag, and deploy are
separate authorizations. No phase is accepted on historical test results alone.

| Phase | Required gate | Current acceptance |
|---|---|---|
| 0 — Mediation | Pinned real Pi requests a real tool; kernel verdict + audit; hostile direct paths fail observably | **Not passed**; [current work and bypass inventory](phase-0.md) |
| 1 — Authority | Signed narrowing leases; transitive revocation/replay; atomic reserved budgets; property/concurrency tests; independently verified audit | Reference only; revalidation required |
| 2 — Sandbox | Signed reproducible guest; jailer/seccomp/cgroup v2; default-deny egress; atomic validated writeback; quota/restart/fault evidence with zero orphans | Reference only; real KVM evidence required |
| 3 — Host | Bounded lifecycle/streams; strict tools; host credential gateway; real kernel + real sandbox slice; fault reconciliation | Reference only; fake-child/mock-sandbox tests are not the slice |
| 4 — Human authority | Ephemeral Ed25519 identity; exact-digest one-use approval through Courier; mutation/replay/expiry/shutdown fail closed | Reference only |
| 5 — Messaging | Courier first; independently gated official Discord bot beta; dedupe, provenance, quarantine, receipts, outage/audit tests | Reference only; Signal disabled, contract only |
| 6 — Control plane | Web/CLI controls map to kernel operations; immutable plugin admission; auth tests; stale-state labels; scanned support exports | Reference only; no desktop |
| Pilot | Independent security review and current release-digest evidence for every gate; emergency-stop/revocation/restore/rollback/adapter-disable drills | **No-go** |

Leases are signed and single-use when appropriate, with nonce replay protection.
Child scope, reserved budget, and expiry cannot exceed the parent; revocation is
transitive. Session shutdown destroys the ephemeral private key and revokes all
descendant leases. Approval authorizes exactly one digest/inputs/session/nonce/
expiry, and never creates a standing lease. The approval UI must expose action,
resource, destination, effect class, budget, and expiry before deciding.

SQLite holds sessions, leases, usage, approvals, and audit. Migrations are forward
only and transactional; startup rejects a database newer than the binary. Prior
audit payloads are immutable; append corrections instead of rewriting history.
Kernel/audit failure, unknown usage, and expired or stale leases fail closed.
Fan-out budget reservation, idempotent debit, crash reconciliation, deterministic
secret redaction, and signed hash-chain checkpoints are kernel obligations.

Plugin admission requires a locked source and digest, inspection, tests, review,
an immutable approved manifest, and scoped enablement. No runtime discovery,
floating tags/branches, or automatic updates. Features default off: effectful Pi
tools, strict execution, standing leases, VHL minting, every adapter, plugin
activation, and stateful sandbox profiles. A signed message proves provenance,
never action authority. Sending is blocked if audit is unavailable.

Every item includes contract, tests, migration impact, and operator documentation
reviewed together. CI must cover positive, negative, concurrency, restart, and
timeout behavior; audit must prove outcomes; rollback must be rehearsed in staging.
Enlarging the trusted base, weakening per-action isolation, introducing ambient
credentials, or unpinning extensions requires a new architecture decision and
threat-model review before implementation. Missing audit, ambiguous authority,
unsigned artifacts, orphans, unreconciled budget, and unverified credential paths
are pilot no-go conditions.
