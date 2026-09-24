# ADR-0006: Remote audit checkpoints for the pilot

- Status: Proposed (decision deferred to pilot readiness review)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Design doc §"Audit", implementation plan phase 5

## Context

The audit log is the trust anchor: hash-chained, append-only, every action
proposal and verdict recorded. If the machine hosting the kernel is
compromised, a local-only log can be rewritten from genesis. Remote
checkpoints (periodically anchoring the chain head to independent storage)
close that gap — at the cost of new infrastructure, new failure modes, and
a network dependency on the audit path.

## Decision (deferred)

The pilot does **not** require remote audit checkpoints to start. The
requirement is revisited at the pilot readiness review with fresh threat
information. This ADR records the decision procedure, not the outcome.

## Rationale for deferring

- The pilot runs on a single operator-controlled host (lane-vps) where the
  primary threats are tool misbehavior and agent confusion, not host
  compromise by a sophisticated adversary. Local hash-chaining already
  detects tampering by anything that doesn't own the whole machine.
- Checkpointing adds a network round-trip to the trust story: if the
  checkpoint service is down, do we fail closed (halt the agent) or open
  (run unaudited)? That policy question deserves its own design, not a
  rushed default.
- Phase 0–1 must prove the local chain first: canonical hashing, no gaps,
  no rewrites, verification tooling. A checkpoint on a broken local chain
  is theater.

## What "revisit" means concretely

At pilot readiness, answer:

1. What is the checkpoint target (independent host, transparency-log style
   service, operator's own hardware)?
2. Checkpoint cadence and failure policy (fail closed vs. degraded mode with
   loud alerting).
3. What the checkpoint covers: chain head hash + sequence + timestamp, signed
   by the kernel's identity key.
4. Recovery procedure: how a verifier detects a fork between local chain and
   checkpoints, and what the operator does then.

If any of 1–4 has no good answer, the pilot still ships without remote
checkpoints, and this ADR stays Proposed.

## Consequences

- Phase 1 builds the local audit log as if checkpoints will exist: chain
  head export is a pure function, signing keys are kernel-held, verification
  is offline-capable.
- No network code on the audit path until the readiness review says so.

## Alternatives considered

- Require checkpoints from day one: rejected — premature infrastructure with
  unanswered failure-policy questions.
- Never checkpoint (local log only, forever): rejected — a single-host log
  cannot survive host compromise; the question is *when*, not *whether*.
