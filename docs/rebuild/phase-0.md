# Phase 0 boundary reset

Status: **in progress; gate not passed; production Pi admission disabled**.
Branch: `lumen-rebuild/phase-0-boundary-reset`, based on `c2ed463`.

## Why the reference spike is insufficient

The prior BCT extension requested an allow decision and then called Node
`realpath` and `readFile` inside Pi. A replaced extension could skip the decision,
and the check/read sequence did not eliminate path races. Both supervisor launch
paths started an ordinary subprocess with inherited host environment. The frozen
transcript in ADR-0007 explicitly excluded hostile-extension confinement and its
generating harness was removed. Those facts invalidate the new Phase-0 gate.

## Changes in this draft

Both public launch APIs reject before child creation. Session admission rejects
before identity creation, lease issuance, or persistence. There is no flag,
environment setting, public unchecked constructor, or production build feature to
override this. Fake-child lifecycle tests use private `cfg(test)` helpers; they
exercise protocol mechanics and are not confinement evidence. Integration tests
link the ordinary library and prove that even pinned executables cannot launch.

The BCT extension now expresses only `bct.read_file` intent through Pi's documented
RPC `extension_ui_request` / `extension_ui_response` channel. The reserved title
`lumen.pi-bridge/2` identifies a machine request. It must **not** be presented as a
human approval dialog. No socket credential, session identity, lease, envelope,
resource, effect, filesystem operation, subprocess, or provider request is handled
by the extension. All non-completed outcomes fail once without retry or fallback.

The proposed host codec strictly decodes intent and derives the envelope from
host-owned session and lease state. Duplicate call IDs are claimed before an
await and retained, including on failure; the per-generation set is bounded.
Completion requires execution result, usage, action digest, and durable audit
reference. An allow-only decision cannot be used as an execution result.

The codec is tested against the real SQLite authority kernel and an explicitly
identified sandbox double. **It is not yet wired into a confined real-Pi session.**
It does not establish KVM isolation, credential absence, cancellation safety for
effectful execution, or restart reconciliation. No feature is enabled by this PR.

## Proposed contract transition

PiBridge v1 and `lumen-kernel/1` fixtures remain unchanged as historical contracts.
The new tool-intent component is **PiBridge v2, proposed**. Its fixture is
`crates/lumen-protocol/fixtures/pibridge_read_request.v2.json`; host types are in
`crates/lumen-server/src/pi_tool_bridge.rs`, consumer decoding in
`lumen-integrations/bct-pi-extension/src/host-client.ts`.

Request: version 2, tool call ID, exact catalog tool, typed path and maximum byte
count. Authority fields and unknown fields/versions are rejected. Reply: version,
matching call ID, action digest, and explicit outcome. Completed outcomes require
bounded output, zero exit status, known nonnegative usage, and an audit reference.
Non-completed outcomes never authorize an operation in Pi.

Migration: stop existing sessions and revoke their descendants before replacing
the reviewed extension manifest and host together. Do not accept both the old
allow-then-local-read path and v2. Do not transparently translate approval digests
or replay old requests. Host startup stays disabled until the complete confinement
and mediation gate is accepted. No DB schema changes are needed for this draft;
no migration or historical audit payload is modified.

Required reviews (pending): host owner as producer, Pi integration owner as
consumer, kernel owner for authority projection, sandbox owner for launch
admission. This document does not supply their sign-off.

## Bypass inventory

| Route | Reference gap | Current control / remaining proof |
|---|---|---|
| Built-in read/write/edit/find/grep/ls | Flags only | All launch admission denied; confined hostile run pending |
| Raw bash/powershell/export RPC | Supervisor allowlist only | All launch admission denied; no production raw sender |
| Replaced extension Node fs APIs | Host OS access | Local read removed; OS enforcement acceptance pending |
| Symlink/path race | Extension check then read | No Pi read; kernel canonicalization + guest snapshot/writeback need new gate evidence |
| Node child_process / shell | Host OS access | Launch disabled; actual syscall denial still must be demonstrated |
| Network/provider/metadata/DNS | Host network access | Launch disabled; default-deny confinement evidence still required |
| Environment / home / credentials | Parent environment inherited | Environment cleared in fixture mechanics; real confined credential test pending |
| Repository extension discovery | Inconsistent flags | Launch disabled; immutable runtime allowlist and startup discovery proof pending |
| Forged authority fields | Pi built an envelope and held channel credential | v2 accepts only typed intent; authority comes from host |
| Duplicate / concurrent tool request | New envelope on each attempt | Bounded atomic per-generation ID claim; kernel nonce/lease enforcement remains mandatory |
| Pending/deny/unknown response | Could fall into local execution | Only audited completed output returned; all other outcomes throw, no retry |
| Missing audit/usage, oversized result | Extension read independently | Strict completion decoder fails closed; pipeline audit-failure tests retained |
| Restart / alternate launcher | Two independent subprocess entry points | Both public launch paths disabled; fake-child tests explicitly separated |

Denial before launch is containment, **not proof of an instrumented confined Pi**.
The historical fixture tests only check historical data. Do not count either as
the full Phase-0 gate.

## Remaining acceptance work

1. Review the Pi runtime confinement architecture and threat model. The runtime
   image must contain only pinned runtime inputs; exclude host workspace, home,
   sockets, credentials, network, and process-spawn authority. No fallback profile.
2. Independently reproduce and verify the pinned Pi source/build, extension, and
   runtime dependency digests. The old `PINNED_PI.md` hashes are candidates only.
3. Wire bounded stdio v2 requests into a host generation whose identity/leases are
   kernel-owned; wire cancellation and termination to that generation. Explicitly
   reject unknown dialog requests. Never render machine requests as VHL prompts.
4. Commit a repeatable harness using real pinned Pi and a deterministic model.
   A kernel-denied real read satisfies the first mediation proof without creating
   a pre-Firecracker host-read exception. A real allow path requires the actual
   per-action sandbox and signed audit path, not a mock or local read.
5. Run malicious extensions attempting direct fs, shell, sockets, providers,
   discovery, malformed/flooded RPC, and credential access. Capture actual denial
   observations and compare attempts against the append-only audit.
6. Tie evidence to exact artifacts; obtain owner review. Only then proceed to
   later phase acceptance. No automatic deployment follows acceptance.

## Operator checks and rollback

Run `cargo test -p lumen-server --lib --tests` on Linux, and `npm ci
--ignore-scripts && npm run typecheck && npm test` in the extension directory.
The Pi admission integration tests must run against the non-test library. The
real-kernel bridge tests deliberately use a sandbox double; label them accordingly.

On a deployed reference build, apply emergency-stop/session-revocation procedures
under a separate deployment authorization before replacing binaries. This source
change does not stop an already-running old service. Rolling back the draft's
code must not re-enable unconfined Pi; retain the admission denial until a reviewed
replacement exists. Staging rollback and real-Pi evidence are still pending.
