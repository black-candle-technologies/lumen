# Phase 0 boundary reset

Status: **in progress; gate not passed; production Pi admission disabled**.
Branch: `lumen-rebuild/phase-0-boundary-reset`, based on `c2ed463`.

The v1 development evidence remains immutable: [lane-vps results](evidence/phase0-confinement.json),
[exact unsigned runtime candidate](evidence/phase0-runtime.candidate.json),
[audited denial](evidence/phase0-denial.audit.json), and
[separately captured checkpoint anchor](evidence/phase0-denial.anchor.json).
The [earlier preparation record](evidence/phase0-preparation.json) is preserved
unchanged and describes its earlier commit, before real Pi was exercised.
The v2 liveness follow-up is specified in [ADR-0009](../adr/0009-pi-host-liveness.md).
Its [new evidence record](evidence/phase0-liveness.json) captures 25 passing Linux
tests, three host-SIGKILL teardown measurements (21–35 ms), monitor failure,
preparation recovery and a repeated real Pi denial. The
[v2 runtime candidate](evidence/phase0-runtime-liveness.candidate.json) pins 3,921
files; the [new public audit](evidence/phase0-liveness-denial.audit.json) and
[checkpoint anchor](evidence/phase0-liveness-denial.anchor.json) are separate
artifacts. No prior evidence is overwritten.

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

The codec has unit coverage against the real SQLite authority kernel and an
explicit sandbox double. The new [confinement experiment](../../scripts/rebuild/README.md)
also drives the **real pinned Pi CLI**, a deterministic model, the actual BCT
read-request function, and the real SQLite kernel through an unapproved one-shot
denial (missing exact-action binding, before path-scope evaluation).
The deny probe has no executor. Direct filesystem/shell/native-network attempts
fail inside that Pi session; a separate Python verifier validates the durable
audit chain, signatures, captured head and exact denial digest. Native tests also
cover worker inheritance, environment stripping, quotas and managed timeouts.
The v2 experiment adds an external pinned liveness monitor, systemd-owned runtime
directories and ownership-locked recovery. Real SIGKILL tests cover an active
non-cooperative guest and interrupted preparation; monitor death and corrupt
liveness input terminate the entire unit. Recovery preserves live owners and
rejects symlinks, unsafe permissions and unavailable service-manager state.
These are process-crash observations, not machine-reboot, Firecracker, or kernel
authority-reconciliation evidence. Signed artifact admission and owner acceptance
remain pending. No product feature is enabled by this PR.

## Proposed contract transition

PiBridge v1 and `lumen-kernel/1` fixtures remain unchanged as historical contracts.
The new tool-intent component is **PiBridge v2, proposed**. Its fixture is
`crates/lumen-protocol/fixtures/pibridge_read_request.v2.json`; host types are in
`crates/lumen-server/src/pi_tool_bridge.rs`, consumer decoding in
`lumen-integrations/bct-pi-extension/src/host-client.ts`.

Request: version 2, tool call ID, exact catalog tool, typed path and maximum byte
count. Authority fields and unknown fields/versions are rejected. Reply: version,
matching call ID, **kernel AuditEvent action digest**, and explicit outcome. The
reference host compatibility envelope has a different digest; returning that
value would sever reply-to-audit correlation. The v2 proposal now uses the kernel
contract's canonical encoding, with a persisted-denial regression test. Completed outcomes require
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

The runtime candidate manifest separately advances from v1 to v2, requiring
`profile: bwrap-stdio-liveness-v2` and the native monitor's hash. Missing monitor,
unknown profiles/versions and v1 manifests fail closed. Drain v1 test units before
switching; never reinterpret old manifests. No DB or historical audit migration
is needed. Runtime ownership locks carry no authority. See the
[operator procedure](../../scripts/rebuild/README.md) for recovery and rollback.

## Bypass inventory

| Route | Reference gap | Current control / remaining proof |
|---|---|---|
| Built-in read/write/edit/find/grep/ls | Flags only | Real Pi fixture exposes only bct.read_file; syscalls/mounts separately constrain hostile code |
| Raw bash/powershell/export RPC | Supervisor allowlist only | All launch admission denied; no production raw sender |
| Replaced extension Node fs APIs | Host OS access | Real Pi host-sentinel read fails; no host repository/home mounted; acceptance pending |
| Symlink/path race | Extension check then read | No Pi read; kernel canonicalization + guest snapshot/writeback need new gate evidence |
| Node child_process / shell | Host OS access | Real Pi Node spawn and native exec/fork/process-clone probes return denial |
| Network/provider/metadata/DNS | Host network access | Real Pi IPv4/IPv6/Unix socket creation denied; no network mount; Firecracker egress gate separate |
| Environment / home / credentials | Parent environment inherited | Parent canary/NODE_OPTIONS stripped; exact runtime environment observed; no host home/proc mounts |
| Repository extension discovery | Inconsistent flags | Exact hashed runtime inventory and explicit fixture extension; discovery disabled; production admission pending |
| Forged authority fields | Pi built an envelope and held channel credential | v2 accepts only typed intent; authority comes from host |
| Duplicate / concurrent tool request | New envelope on each attempt | Bounded atomic per-generation ID claim; kernel nonce/lease enforcement remains mandatory |
| Pending/deny/unknown response | Could fall into local execution | Only audited completed output returned; all other outcomes throw, no retry |
| Missing audit/usage, oversized result | Extension read independently | Strict completion decoder fails closed; pipeline audit-failure tests retained |
| Restart / alternate launcher | Two independent subprocess entry points | Both public launch paths disabled; fake-child tests explicitly separated |
| Abrupt prototype host/monitor death | systemd parent outlived launcher | v2 FIFO monitor + managed runtime directories; real SIGKILL/partial-startup recovery tests; kernel lease reconciliation remains separate |

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
4. Independently reproduce/review the committed real-Pi deterministic denial
   harness and malicious native probes. A real allow path requires the actual
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
replacement exists. Real Pi denial evidence is available above; staging rollback,
signed admission and owner acceptance remain pending.
