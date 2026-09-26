# ADR-0007: Phase-0 spike end-to-end evidence (real Pi, real kernel wire)

> Current acceptance: historical evidence only. This transcript does not meet the
> rebuilt Phase-0 gate because Pi performed the read and hostile extensions were
> unconfined. See [Phase-0 boundary reset](../rebuild/phase-0.md). The historical
> transcript and audit fixture are preserved without modification.

- Status: Accepted (phase-0 spike)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Implementation plan phase 0, completion gate BOUNDARY PROVEN

## Context

The spike's completion gate requires proof, not just unit tests, that one
real mediated tool can be allowed or denied through the real Pi → kernel
path, and that every bypass attempt fails observably. Kernel-wire tests
(`pi_bypass_inventory`, 14 cases) prove policy for callers that use the
kernel. This ADR records the end-to-end run that proves the full loop:
a real Pi session, loading the real BCT extension, driving the real
`bct.read_file` tool through the real kernel socket.

## Pinned inputs

| Input | Value |
|---|---|
| Lumen base | `4b7a4a10` (tip of `origin/feat/issue-62-mixed-trust-gate`) |
| Pi source | `b45597504eeaba1f11a9920a1d1048c361ed4b8e` (2026-09-23) |
| Pi version | `0.87.1` |
| Pi build | `npm ci --no-audit --no-fund && npm run build` (npm workspaces; pnpm omits workspace deps) |
| `package-lock.json` SHA-256 | `95dbf4d7aa54eebf235edccd6926efac42fbf4e1c6a92c625c9ac706a8b367f7` |
| Artifact `packages/coding-agent/dist/bundle/cli.js` SHA-256 | `e79626f2dd6f94aa45d30f3fa63cd84319a6eefcd150b353cfaf274366926774` |
| Pi flags | `--mode rpc --no-session --no-builtin-tools` |

## Harness (scaffolding, not committed)

The run used throwaway scaffolding that is not part of the deliverable:

- **Example kernel** (`spike_kernel`, since removed): `LocalKernel` behind a
  Unix socket with `SO_PEERCRED` + per-session nonce, exactly the
  `pi_boundary` wire contract. Root lease narrowed to a scratch `work/`
  directory; child lease identical (proves chain evaluation uses the leaf).
  An `approvable/` sibling sits outside the lease under an approvable root.
- **Scripted model** (`spike-echo`, since removed): a deterministic Pi
  model extension, typechecked against the pinned Pi's real declarations.
  On a marked prompt it emits exactly one `bct.read_file` tool call with
  the case's path, then answers with text so the agent settles instead of
  looping. Three markers: `SPIKE_ALLOW`, `SPIKE_DENY`, `SPIKE_PENDING`.
- **Driver** (node, since removed): spawned the kernel, read its config
  from stdout, launched Pi with the lockdown flags plus the BCT extension
  and the scripted model, sent the three prompts sequentially waiting for
  `agent_settled` each time, and froze the transcript plus the kernel's
  hash-chained audit log.

The scripted model is a stand-in for a real model, not for the boundary:
everything between the tool call and the verdict — extension, socket,
nonce, lease evaluation, audit — is the real code path.

## Observed results (2026-09-24)

| Prompt | Tool event | Verdict |
|---|---|---|
| `SPIKE_ALLOW` (leased `work/allowed.txt`) | `tool_execution_end`, `isError: false` | Content `LUMEN-SPIKE-EXPECTED-CONTENT` returned; `details` carries `action_digest` and `audit_sequence` |
| `SPIKE_DENY` (`/etc/hostname`) | `tool_execution_end`, `isError: true` | `Denied by Lumen kernel [scope_exceeded]: path '/etc/hostname' is outside the leaf lease scope`; no content leaked |
| `SPIKE_PENDING` (`approvable/needs-approval.txt`) | `tool_execution_end`, `isError: true` | `Action requires human approval (apr-…): …`; file not read, nothing executed |

Each prompt ended with `agent_settled`; Pi exited 0. The kernel audit log
shows six hash-chained events in order:

`action_proposed → policy_allowed → action_proposed → policy_denied →
action_proposed → approval_requested`

The frozen transcript and audit log are checked in as
`crates/lumen-core/tests/fixtures/spike-e2e-evidence.json`, and
`crates/lumen-acceptance/tests/spike_e2e_evidence.rs` re-verifies the three
verdicts, the audit pairing and hash-chain links, and the Pi provenance on
every test run.

## Bugs the run caught

1. **Pending fell through to allow.** The BCT extension compared
   `decision.decision === "pending"` but the wire value is
   `"pending_approval"` (serde `rename_all = "snake_case"` on
   `DecisionOutcome::PendingApproval`). A pending verdict would have
   executed the read. Fixed in `lumen-integrations/bct-pi-extension`.
2. **Scripted-model infinite loop.** The model re-emitted the tool call
   after every tool result because it keyed "already called" on the whole
   session transcript instead of the latest prompt. Scaffolding-only, but
   the same shape would bite any stateful model adapter.
3. **Pi `toolcall_start` contract.** The first scripted event sequence
   crashed the model because `toolcall_start` requires
   `partial.content[contentIndex]` to already hold the tool-call block.
   Real Pi declarations caught two more gaps (`Usage.totalTokens`,
   `Usage.cost.total`, `AssistantMessage.timestamp`).

## Decision

The frozen evidence plus its regression test constitute the spike's
end-to-end proof for the mediated path. The scaffolding is intentionally
not committed: it was a means to the evidence, and its paths fall outside
phase-0 ownership.

## What this does NOT prove

- **Replaced-extension confinement (B14).** The run proves the mediated
  tool path: a cooperating extension's tool calls are allowed, denied, or
  held for approval, observably. A *replaced* extension still runs with
  the Pi process's OS authority and could use Node `fs`/network APIs
  directly; it cannot mint kernel authority (no lease, no socket nonce),
  but OS-level access is unconfined until phase-2 process confinement
  (ADR-0002).
- **Durable audit.** The chained log in the evidence is the in-memory
  spike log; phase 1 persists it.
- **Approval UX.** `pending_approval` returns an approval id; no human
  approval loop exists yet.

## Consequences

- The E2E evidence is a regression test: if the wire contract, verdict
  strings, or audit pairing change, `spike_e2e_evidence` fails.
- Any future model adapter must be one-tool-call-per-prompt by
  construction (lesson from bug 2).
- The `pending_approval` wire string is now covered by both the fixture
  suite and the E2E evidence; the extension matches it exactly.
