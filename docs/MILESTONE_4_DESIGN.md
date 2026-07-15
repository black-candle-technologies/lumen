# Milestone 4: Controlled Egress

## Status

Accepted for implementation. The project owner delegated roadmap decisions, and Milestone 4 starts after Milestone 3's local extension runtime and privileged Linux sandbox gate passed.

## Goal

Milestone 4 allows Lumen to talk to explicitly configured remote systems without weakening the local-first default. Remote model providers, outbound network destinations, and external chat channels are treated as data egress. They must be visible, scoped, policy-checked, approval-aware, and audited.

The milestone is complete only when remote data flow can be enabled per provider, workspace, data class, destination, and channel while unknown or unapproved egress fails closed.

## Scope

Milestone 4 includes:

- Explicitly enabled remote OpenAI-compatible model providers.
- Workspace routing policy for `public`, `workspace`, `sensitive`, and `secret` data classes.
- Provider records that distinguish local and remote endpoints, credentials, health, priority, and allowed data classes.
- Destination-scoped `network.egress` capabilities for runtime-owned HTTP actions and plugin-returned proposals.
- External channel adapter records with stable identity mapping, workspace allowlisting, and inbound audit provenance.
- Audit events that show when egress occurred, where data went, which policy allowed it, and what data class was involved.

Milestone 4 does not include a public plugin marketplace, automatic plugin updates, browser automation, scheduled jobs, distributed workers, or silent fallback to remote providers. A remote provider error may fail the run or ask the operator to choose another configured provider, but it must never cause an unconfigured fallback.

## Chosen Approach

Lumen will add a runtime-owned egress policy layer and keep adapters thin.

Alternatives considered:

1. **Policy-first controlled egress (chosen).** Remote providers and channels are normal configured resources, but every use is gated by workspace/data-class policy and audited as egress.
2. **Provider allowlist only.** This is simpler but too broad: enabling one remote provider would implicitly expose all workspaces and data classes.
3. **Per-request approvals only.** This is visible but noisy and still lacks durable workspace routing rules, destination scopes, and channel identity records.

The implementation proceeds in vertical slices: configuration and provider policy, persistence, model routing, network capabilities, external channels, UI controls, and adversarial verification.

## Data Classes

The initial data classes are:

- `public`: may leave the local runtime when a workspace policy permits the provider or destination.
- `workspace`: local by default; remote egress requires a workspace-level rule naming the provider or destination.
- `sensitive`: local by default; remote egress requires an explicit workspace exception and approval for policy expansion.
- `secret`: never enters model context or channel payloads.

Context inherits the most restrictive included source. Redaction can remove sensitive fields, but it does not automatically downgrade a request's data class.

## Remote Model Providers

Remote providers are configured records, not arbitrary URLs in prompts or plugin settings. A provider has:

- Stable provider ID.
- Endpoint class: `local` or `remote`.
- OpenAI-compatible endpoint origin and base path.
- Configured model name and optional advertised model metadata.
- Enabled state.
- Secret reference for credentials, if needed.
- Allowed data classes.
- Workspace scope.
- Priority and health state.

Configuration can bootstrap a single provider, but mutable provider state belongs in SQL. Remote endpoints are rejected unless `allow_remote = true` and an explicit egress policy names the provider and allowed data class. Local loopback endpoints remain the default.

## Routing

Routing evaluates:

1. Workspace local-only setting.
2. Request data class.
3. Explicit user or conversation model selection.
4. Provider enabled state and workspace scope.
5. Provider allowed data classes.
6. Provider health and priority.
7. Required model features.

If no eligible local provider exists, Lumen pauses with an actionable error. It does not try a remote provider unless the selected workspace policy permits the request's data class for that provider.

Every model turn records provider ID, endpoint class, configured and resolved model identity, data class, whether egress occurred, policy version, selection reason, request/response sizes, usage metadata, outcome, latency, and cancellation state.

## Network Capabilities

Milestone 4 introduces runtime-owned destination scopes for network egress:

```text
network.egress:https://api.example.com
network.egress:https://api.example.com/v1/
network.egress:channel:slack:workspace-id
```

Scopes are canonicalized before comparison. Redirects are disabled unless the redirected destination is separately allowed. Credentials are secret references and are resolved only for the specific approved request. Plugins and skills cannot create authority namespaces; they may only return proposals for runtime-owned network actions.

## External Channels

External channel adapters map provider-specific inbound identities to stable Lumen identities:

- Channel provider, workspace/team ID, channel ID, and message ID.
- External user stable ID and display metadata.
- Mapped Lumen identity and workspace.
- Allowlisted channel state.
- Service identity used for outbound replies.

Unknown channels and users are denied by default. Inbound messages create audited request contexts before reaching the model. Outbound messages are `channel.send` actions and require destination-scoped authority plus approval when the recipient or channel is not already allowed by policy.

## Secrets

Remote provider API keys and channel tokens are secret references. They are never stored in provider config JSON, plugin settings, prompts, model messages, channel payload audit summaries, or UI responses. Secret resolution occurs after policy approval and immediately before the outbound request.

## Audit And Failure Behavior

Every egress attempt records:

- Workspace, actor or channel identity, run, and action IDs.
- Provider or destination ID.
- Endpoint class and canonical destination.
- Data class and policy version.
- Approval ID, when required.
- Whether egress occurred.
- Request and response byte counts.
- Outcome and failure class.

If policy cannot be loaded, a provider cannot be resolved, a secret reference is unavailable, a destination cannot be canonicalized, or audit persistence fails, the action fails closed before sending data.

## Completion Gates

Milestone 4 is complete only after:

- Remote provider config and SQL state enforce explicit enablement and workspace/data-class policy.
- Model routing tests prove local-first behavior, no silent fallback, and remote denial by default.
- Network capability tests prove destination scopes, redirect denial, secret redaction, and audit provenance.
- Channel adapter tests prove identity mapping, allowlisting, inbound denial by default, and approval-bound outbound sends.
- API and UI tests prove operators can inspect and manage egress policy without exposing secrets.
- Full workspace tests, focused security tests, frontend checks, and diff hygiene pass.
