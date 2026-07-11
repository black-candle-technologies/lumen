# Roadmap

Lumen will grow through security-complete vertical slices. A milestone is complete only when its actions use the same identity, policy, approval, execution, and audit path intended for later plugins.

## Milestone 0: Architecture Baseline

- Define trust boundaries and out-of-scope host threats.
- Fix crate ownership and dependency direction.
- Select SQLite, local-first routing, WASM plus subprocess extensions, and OS-keychain secrets.
- Define action, approval, capability, and audit invariants.

## Milestone 1: Local Runtime Kernel

- Load one `lumen.toml` configuration.
- Create and migrate SQLite runtime state.
- Support local identity and workspace allowlisting.
- Implement action envelopes, capability evaluation, approvals, and audit chaining.
- Connect one loopback OpenAI-compatible local model endpoint.
- Implement workspace-scoped file reads and sandboxed command execution.
- Expose chat, approval, and audit APIs with SSE run events.
- Add integration tests proving that API, model, and executor paths cannot bypass policy.

This milestone intentionally excludes remote providers, third-party plugin loading, external chat channels, scheduled jobs, browser automation, and learned skills.

## Milestone 2: Hardened Local Tools

- Add file writes with exact previews and approval binding.
- Complete Linux sandbox enforcement and platform capability reporting.
- Add OS-keychain secret references and scoped injection.
- Add cancellation, unknown-outcome recovery, quotas, and resource-limit tests.
- Complete desktop security configuration and approval UX.

## Milestone 3: Extension Runtime

- Enable signed or locally reviewed plugin installation.
- Ship the WASM component host and supervised subprocess protocol.
- Add capability-grant and plugin-settings interfaces.
- Add quarantine, side-by-side updates, provenance, and artifact verification.
- Publish a small extension SDK only after the runtime contracts stabilize.

## Milestone 4: Controlled Egress

- Add explicitly enabled remote model providers.
- Enforce data classification and provider/workspace egress policy.
- Add destination-scoped network capabilities.
- Add external channel adapters with stable identity mapping and allowlisting.

## Milestone 5: Durable Automation

- Add scheduled jobs with service identities, owners, leases, and idempotency.
- Add reviewed, versioned skills without inherited authority.
- Add workflow capture only after approval and audit semantics are stable.

## Deferred

- PostgreSQL support
- Distributed workers
- Hostile operating-system-user multi-tenancy
- Public plugin marketplace
- Automatic plugin updates
- Silent remote model fallback
- Protection from a compromised host or administrator
