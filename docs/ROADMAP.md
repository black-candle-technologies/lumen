# Roadmap

Lumen will grow through security-complete vertical slices. A milestone is complete only when its actions use the same identity, policy, approval, execution, and audit path intended for later plugins.

## Milestone 0: Architecture Baseline

- [x] Define trust boundaries and out-of-scope host threats.
- [x] Fix crate ownership and dependency direction.
- [x] Select SQLite, local-first routing, WASM plus subprocess extensions, and OS-keychain secrets.
- [x] Define action, approval, capability, and audit invariants.

## Milestone 1: Local Runtime Kernel

- [x] Load one `lumen.toml` configuration.
- [x] Create and migrate SQLite runtime state.
- [x] Support local identity and workspace allowlisting.
- [x] Implement action envelopes, capability evaluation, approvals, and audit chaining.
- [x] Connect one loopback OpenAI-compatible local model endpoint.
- [x] Implement workspace-scoped file reads and sandboxed command execution.
- [x] Expose chat, approval, and audit APIs with SSE run events.
- [x] Add integration tests proving that API, model, and executor paths cannot bypass policy.

This milestone intentionally excludes remote providers, third-party plugin loading, external chat channels, scheduled jobs, browser automation, and learned skills.

## Milestone 2: Hardened Local Tools

- [x] Add file writes with exact previews and approval binding.
- [x] Complete Linux sandbox enforcement and platform capability reporting.
- [x] Add OS-keychain secret references and scoped injection.
- [x] Add cancellation, unknown-outcome recovery, quotas, and resource-limit tests.
- [x] Complete desktop security configuration and approval UX.

Linux process execution requires the complete bubblewrap profile and fails closed when it cannot start. macOS reports its narrower `sandbox-exec` guarantees explicitly. Lumen does not claim seccomp, Landlock, or protection from the host operating-system account in this milestone.

## Milestone 3: Extension Runtime

- [x] Enable locally reviewed plugin staging, approval-bound installation, and immutable version records.
- [x] Ship the WASM component host and supervised subprocess protocol.
- [x] Add capability-grant and plugin-settings interfaces in SQL, API, and the web control surface.
- [x] Add quarantine, side-by-side updates, provenance, and artifact verification.
- [x] Publish the first extension SDK and shared host conformance fixtures.
- [x] Run the mandatory privileged Linux plugin-sandbox verification gate before declaring the milestone complete.

The implemented slice supports reviewed local packages, exact package/manifest/artifact hashes, global and workspace grants, deterministic scoped settings, WASM-component execution, supervised subprocess execution, child action proposals through the normal approval lifecycle, authenticated plugin APIs, plugin review controls, and privileged Linux plugin-sandbox verification in GitHub Actions run `29381403861`.

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
