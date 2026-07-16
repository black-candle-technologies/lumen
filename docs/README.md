# Lumen Documentation

These documents are the authoritative design baseline for Lumen. When a roadmap item conflicts with an architectural invariant or the security model, the invariant and security model take precedence.

## Foundations

- [Architecture](ARCHITECTURE.md): system boundaries, invariants, deployment model, and dependency direction
- [Security Model](SECURITY.md): threat model, capabilities, approvals, isolation, egress, secrets, and failure behavior
- [Runtime Execution](RUNTIME_EXECUTION.md): action envelopes, state machines, dispatch, recovery, and cancellation

## Subsystems

- [Plugin System](PLUGIN_SYSTEM.md): extension types, manifests, installation, capability requests, and process boundaries
- [Model Routing](MODEL_ROUTING.md): local-first selection, data classes, and remote-provider rules
- [Data Model](DATA_MODEL.md): SQLite storage areas and transactional invariants
- [Audit Log](AUDIT_LOG.md): authoritative event structure, hash chaining, redaction, and verification

## Delivery

- [Repository Map](REPOSITORY.md): current crate ownership, dependency direction, and verification areas
- [Roadmap](ROADMAP.md): security-complete product milestones
- [Implementation Plan](IMPLEMENTATION_PLAN.md): ordered work for the first local runtime kernel
- [Milestone 4 Design](MILESTONE_4_DESIGN.md): controlled egress scope, policy, provider, network, and channel boundaries
- [Milestone 4 Implementation Plan](MILESTONE_4_IMPLEMENTATION_PLAN.md): ordered work for remote providers, network egress, channels, and verification
- [Milestone 5 Design](MILESTONE_5_DESIGN.md): durable scheduled jobs, service identities, reviewed skills, and workflow capture
- [Milestone 5 Implementation Plan](MILESTONE_5_IMPLEMENTATION_PLAN.md): ordered work for automation persistence, scheduling, skills, capture, UI, and verification

## Decision Priority

Implementation decisions follow this order:

1. Security goals and explicit out-of-scope assumptions
2. Architectural invariants and trust boundaries
3. Runtime and subsystem contracts
4. Milestone scope
5. Implementation details

Changing an item higher in the list requires reviewing every dependent document and recording the reason in the commit or future decision record.
