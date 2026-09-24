# ADR-0005: Writeback file classes, size limits, conflict behavior

- Status: Accepted (phase-0 spike; enforcement in phases 1–2)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Design doc §"Execution", implementation plan phases 1–2

## Context

Allowed actions produce outputs that must land on host files (edited
source, generated reports, downloaded artifacts). The guest VM must never
write directly (ADR-0002); instead the kernel applies writeback. Without
explicit rules, writeback is a confused-deputy channel: oversized writes,
writes outside the lease, and lost-update races.

## Decision

Writeback is governed by three explicit dimensions, all decided
kernel-side before anything touches the filesystem:

1. **File classes.** Every writable path belongs to a class declared in the
   lease or policy:
   - `scratch`: freely writable, VM-local semantics, never synced anywhere.
   - `workspace`: the agent's working tree; writes allowed only within the
     lease's path prefixes.
   - `artifact`: content-addressed outputs (reports, builds); written once,
     immutable afterwards, referenced by digest.
   - `config`/`secret`: never writable by tool actions, period. Only
     explicit human approval (phase 4 VHL) can mint a one-shot write lease,
     and secrets are never readable by tools (redaction obligation).
2. **Size limits.** Per-action output caps (`Obligation::TruncateOutput`,
   default 64 KiB in the spike) and per-class quotas. Anything over the cap
   is truncated or denied before writeback — never partially applied.
3. **Conflict behavior.** Writeback is atomic (write temp + rename). If the
   target changed since the action's input snapshot, the write is rejected
   as a conflict; the agent must re-read and re-propose. Last-writer-wins
   is never silent: overwrites of unexpected content require a fresh
   evaluation against the current snapshot.

## Rationale

- The kernel, not the tool, decides what lands on disk. The tool proposes
  bytes; the kernel checks class, scope, size, and freshness, then applies.
- Atomicity plus conflict rejection gives the agent a coherent view of the
  filesystem without distributed locking.
- Immutable artifacts by digest make audit meaningful: the audit log can
  name exactly which bytes were produced by which action.

## Consequences

- Phase 1 extends `EffectClasses`/`Obligation` with write classes and quotas;
  the v1 contract shape is frozen, the taxonomy grows in v2.
- Tools must declare their intended write class up front in the envelope;
  undeclared writes are denied.
- Human-in-the-loop flows (phase 4) can approve `config` writes, but the
  approval names the exact path, class, and content digest — never a blank
  cheque.

## Alternatives considered

- Direct guest bind mounts: rejected — gives the guest ambient write
  authority the kernel cannot inspect or revoke mid-action.
- Silent last-writer-wins: rejected — destroys auditability and lets a
  racing action clobber human edits without notice.
