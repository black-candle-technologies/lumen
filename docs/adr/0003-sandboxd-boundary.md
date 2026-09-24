# ADR-0003: sandboxd privilege and process boundary

- Status: Accepted (phase-0 spike; implementation in phase 2)
- Date: 2026-09-24
- Deciders: Lumen rebuild team
- Context: Design doc §"Sandboxing", implementation plan phase 2

## Context

Something must hold the privileges that create isolation: KVM access, the
Firecracker jailer, network namespace setup, and (deny-by-default) egress
wiring. That something must not also hold agent intent, lease authority, or
user data.

## Decision

`sandboxd` is a small, dedicated, privileged daemon. It owns **mechanism
only**:

- Create/destroy Firecracker microVMs via the jailer.
- Apply resource quotas (memory, vCPU, wall time, output bytes).
- Wire the default-deny network (explicit egress allowlist per action).
- Return inspected execution results to the kernel.

It never sees: lease contents, policy decisions, user prompts, secrets, or
audit plaintext beyond what the kernel explicitly hands it per action. The
kernel (intent, leases, policy, audit) and sandboxd (mechanism) communicate
over the frozen `SandboxDriver` v1 trait; in production they are separate
OS processes (separate UIDs), and the kernel never runs as root.

## Rationale

- **Privilege separation.** The code that parses untrusted agent output and
  the code that configures KVM are different code in different processes.
  A bug in intent handling cannot become host compromise.
- **Minimal trusted computing base.** sandboxd's job is deliberately boring:
  spawn VM, enforce quotas, return bytes. Small enough to audit; no policy
  language, no network clients, no secret handling.
- **No ambient authority.** The guest gets no writable bind mount, no host
  credentials, no network by default. Writeback is inspected and applied
  atomically by the kernel side (ADR-0005).

## Consequences

- Phase 2 must implement sandboxd without touching the phase-1 lease/policy
  core; the trait boundary is frozen in phase 0 to make that possible.
- The spike's `NullSandboxDriver` fails closed, so any code path that
  forgets to install a real driver denies rather than executing anywhere.
- Operational cost: one more daemon to supervise, with its own minimal
  config and logging. No remote API: it only serves the local kernel.

## Alternatives considered

- Kernel holds KVM directly: rejected — puts host-compromise-capable
  syscalls in the same process as the policy engine.
- One VM per session instead of per action: rejected — cross-action state
  inside the VM becomes a confused-deputy channel (ADR-0002).
