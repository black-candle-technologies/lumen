# ADR-0002: Strict per-action Firecracker microVMs by default

- Status: Accepted (phase-0 spike; implementation in phase 2)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Design doc §"Sandboxing", implementation plan phases 0–2

## Context

Every tool action the kernel allows must execute somewhere. Options range
from in-process execution to per-action microVMs. The spike must prove the
authority boundary; phases 1–2 must make the execution boundary real.

## Decision

The default execution profile is a **strict per-action Firecracker
microVM**: one microVM per allowed action, no writable bind mount into the
guest, no ambient secrets, default-deny egress, inspected atomic writeback.

## Rationale

- **Blast radius of one action.** A compromised or malicious tool sees only
  the inputs the kernel placed in its VM and can affect only what the lease
  permits. There is no cross-action state to poison.
- **Writeback integrity.** The guest never writes directly to host paths.
  Outputs come back through an inspected channel and are applied atomically
  by the host, which enforces file classes, size limits, and conflict
  behavior (ADR-0005).
- **Hardware isolation.** Firecracker gives KVM-backed isolation with
  ~125ms boot times, viable per-action on the v1 target (lane-vps has
  `/dev/kvm`; verified 2026-09-23).
- **Least privilege for the privileged piece.** Only sandboxd touches KVM,
  the jailer, and the (deny-by-default) network. The kernel holds intent;
  sandboxd holds mechanism (ADR-0003).

## Consequences

- Phase 2 builds the Firecracker driver behind the frozen `SandboxDriver`
  v1 trait (`crates/lumen-core/src/pi_boundary.rs`).
- Per-action VM boot cost must be amortized (snapshot/restore, warm pools);
  the spike does not solve this, phase 2 must.
- The spike is honest about its residual risk: until phase-2 confinement
  lands, a *replaced* Pi extension runs with the Pi process's OS permissions
  and could use Node APIs directly. It still cannot mint kernel authority,
  but OS-level reads are not stopped. This is documented in the bypass
  inventory (B14) and is a phase-gate item, not a hand-wave.

## Alternatives considered

- Process-only sandboxing (namespaces/seccomp) as the default: weaker
  isolation, shared kernel attack surface; kept as a fallback profile for
  platforms without KVM, not the default.
- Container per action: larger trusted computing base (container runtime,
  shared host kernel) than microVMs for the same isolation goal.
