# Model Routing

Local inference is Lumen's default execution mode. Remote inference is an explicit data-egress decision, not an automatic reliability fallback.

## Provider Contract

Model providers implement a runtime-owned interface for:

- Capability discovery
- Chat or response generation
- Structured tool-call proposals
- Streaming events
- Cancellation
- Usage reporting
- Stable provider and model identity

The first integration is an OpenAI-compatible HTTP client configured for a loopback llama.cpp-compatible server. Lumen does not manage model downloads or GPU runtimes in the first milestone.

## Routing Policy

Selection evaluates:

- Workspace local-only setting
- Conversation and attached-data sensitivity
- Required model features, such as tool calling or vision
- Explicit user model selection
- Provider health and configured priority
- Context-window requirements
- Cost and token budgets

The default policy selects an eligible local provider. If none is available, the run pauses with an actionable error. It does not send data to a remote provider unless policy and the user-visible configuration permit that provider for the request's data class.

## Data Classes

Initial data classes are:

- `public`: may be sent to an explicitly enabled remote provider.
- `workspace`: remains local unless the workspace grants remote egress.
- `sensitive`: local-only by default and requires an explicit per-workspace exception.
- `secret`: never enters model context.

Context inherits the most restrictive class of its included sources. Redaction may remove data but does not automatically downgrade the classification.

## Provider Records

Each model turn records:

- Provider configuration ID and endpoint class (`local` or `remote`)
- Advertised and resolved model identity
- Routing policy version and selection reason
- Data class and whether egress occurred
- Request and response size and usage metadata
- Sampling and tool-schema configuration needed for reproduction
- Outcome, latency, and cancellation state

Prompts and responses follow workspace retention policy and may be omitted or encrypted independently of the metadata record.

## Local Provider Safety

Loopback endpoints are authenticated when the runner supports it and constrained to configured origins. A local model remains untrusted: malformed tool calls are rejected, output is bounded, and all proposed actions pass through the same policy and approval path as remote-model proposals.

## Remote Providers

Remote providers must be enabled explicitly. Configuration shows what endpoint receives data, and provider credentials are secret references. Enabling a provider does not grant it access to every workspace. Remote-provider errors never trigger an unconfigured fallback.

## Model Capability Variance

The runtime does not rely on prompt compliance for security. Provider capability discovery affects usability only. Models with weak structured-output support may be restricted to text or low-risk tools, but they cannot obtain a weaker enforcement path.
