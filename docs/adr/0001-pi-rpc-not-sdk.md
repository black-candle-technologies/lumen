# ADR-0001: Pi integration via RPC subprocess, not in-process SDK

- Status: Accepted (phase-0 spike)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Design doc §"Pi harness", implementation plan phase 0

## Context

The rebuild embeds Pi as the agent loop inside a Lumen host that owns the
kernel (leases, policy, sandbox, audit). Pi can be integrated two ways:

1. **In-process SDK** (`@earendil-works/pi-coding-agent` imported into the
   host process, driving `AgentSession` directly).
2. **RPC subprocess** (`pi --mode rpc` as a child process, strict JSONL over
   stdin/stdout).

## Decision

Use the RPC subprocess for v1.

## Rationale

- **Crash and misbehavior isolation.** A subprocess can be killed, restarted
  under a bounded policy, and have its stdout framed, capped, and discarded.
  An in-process SDK shares the host's memory, event loop, and fate: a hang
  or panic in Pi is a hang or panic in the kernel host.
- **Least privilege by construction.** The RPC channel exposes only what Pi's
  RPC mode exposes. The supervisor allowlists three commands
  (`prompt`, `get_state`, `abort`); effectful commands (`bash`,
  `export_html`, provider/model/tool mutation) are unrepresentable in the
  supervisor's type surface. An in-process SDK exposes the full extension
  context, session control, and provider registry to any code in the process.
- **Future sandboxing.** Phase 2 confines the Pi process (user namespaces /
  Landlock / dedicated UID, then Firecracker for tool execution). You cannot
  `unshare()` half a process; the RPC boundary is the unit that gets
  confined.
- **Versioning and replacement.** The RPC wire is a versioned protocol
  (`lumen-kernel/1`, PiBridge v1). The agent loop can be swapped (a different
  harness, a newer Pi) without recompiling the host.

## Consequences

- The supervisor must implement strict JSONL framing, flood caps, malformed
  record handling, and bounded restart — done in
  `crates/lumen-server/src/pi_supervisor.rs`, all covered by tests.
- Slight latency overhead vs in-process calls; irrelevant for an agent loop.
- Pi's stdout is untrusted input and is treated as such (size caps, no
  Unicode line splitting, malformed-line budgets).

## Alternatives considered

In-process SDK: rejected — it collapses the process boundary the whole
design depends on, and makes phase-2 confinement impossible.
