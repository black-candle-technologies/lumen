# Remote provider configuration

Provider administration is an offline, local operator workflow. Stop the service before
these commands; every command that may migrate the database holds the runtime owner
lock. Use the same config, workspace and OS user as the service. Commands do not start
runtime recovery, read provider keys for inspection, or make test model calls.

## Choose a protocol

| `kind` | Request path relative to the base | Authentication |
| --- | --- | --- |
| `openai` | `responses` | Bearer |
| `anthropic` | `messages` | `x-api-key`, `anthropic-version: 2023-06-01` |
| `openai_compatible` | `chat/completions` | Bearer |

Choose the vendor's supported protocol explicitly. The hostname does not select a
protocol and Lumen does not retry using a different protocol. Set the base URL to
include the API prefix, such as `https://api.openai.com/v1/` or
`https://api.anthropic.com/v1/`. Compatible gateways may use a different prefix.
HTTPS and certificate verification are required for remote providers. Userinfo,
query strings, fragments and loopback remote endpoints are rejected. Paths are
joined relatively, preserving the prefix. Redirects and environment proxies are disabled.

## Create a credential reference

Create a metadata-only `credential.json`:

```json
{
  "provider_id": "primary-remote",
  "kind": "openai_compatible",
  "endpoint": "https://provider.example/v1/",
  "label": "Primary remote account"
}
```

Choose a fresh provider ID. Historical IDs without a workspace owner cannot be
claimed implicitly. Do not put the key in this JSON, a URL, argv, environment
variables, config files, or shell history. Unknown descriptor fields are rejected.

Pipe the credential directly from a password manager or an interactive no-echo
prompt into:

```sh
lumen --config lumen.toml provider credential create --metadata credential.json --stdin
```

The command accepts at most 16 KiB of nonempty printable ASCII authentication
material, with an optional single trailing LF or CRLF. It does not trim whitespace.
Output contains a reference UUID and scoped metadata; keep the returned UUID for
registration. Key material goes into the OS credential store under service
`dev.lumen.runtime`, account `provider:<workspace UUID>:<reference UUID>`.
Provider references are separate from executable/environment-scoped process
references and confer no `SecretUse` capability.

Creation commits audited `pending` metadata, stores the key, then commits audited
`ready` metadata. A failed or interrupted operation never yields usable pending
metadata. A subsequent create cleans up pending accounts in the workspace under
the owner lock and revokes their references. Cleanup failure stops creation with a
safe error; explicitly retry revocation if needed.

## Register a provider, profile and policies

Put the returned UUID in `provider.json`. The initial four heads are independently
zero; every successful registration advances each head by one.

```json
{
  "provider_id": "primary-remote",
  "kind": "openai_compatible",
  "endpoint": "https://provider.example/v1/",
  "credential_secret_ref": "REPLACE-WITH-RETURNED-UUID",
  "enabled": true,
  "expected": { "provider": 0, "profile": 0, "egress": 0, "workspace_policy": 0 },
  "allowed_data_classes": ["public"],
  "workspace_allowed_data_classes": ["public"],
  "profile": {
    "id": "primary-text",
    "model": "YOUR-VENDOR-MODEL-ID",
    "enabled": true,
    "capabilities": ["text", "tool_calling"],
    "context_window_tokens": 32768,
    "concurrency_limit": 1,
    "priority": 0
  }
}
```

Advertise only capabilities the selected model supports. Add `workspace` or
`sensitive` classes only when you intend to permit that disclosure, in both
policies. `secret` is forbidden. The profile initially uses `remote_untrusted`.
A credential authenticates a request; it grants no egress permission.

```sh
lumen --config lumen.toml provider register --file provider.json
lumen --config lumen.toml provider list
lumen --config lumen.toml provider show primary-remote
lumen --config lumen.toml provider credential list
```

Registration validates ownership and the ready reference's exact workspace,
provider ID, protocol and canonical endpoint. One transaction compares all four
expected heads and writes provider config, profile, egress mirror, workspace policy
and audit event. A stale head is an explicit conflict; failure rolls back all writes.
Profile IDs cannot be reassigned to another provider. Provider and profile revision
numbers can differ, for example when adding another profile to an existing provider.

List/show report enabled state, separate heads, profile revisions, credential
metadata state and `network_status: not_tested`. These commands do not resolve the
key or test connectivity. A ready reference does not prove the OS account still
contains a usable key, or that the vendor accepts it.

## Select the profile and start

Replace the legacy model selection with the profile ID and returned revision:

```toml
[model]
allow_remote = true
streaming = false
timeout_seconds = 120
max_response_bytes = 4194304

[model.registry_profile]
id = "primary-text"
revision = 1
```

Retain the rest of your host configuration. Remove legacy `endpoint`, `model`,
`remote_provider` and non-off GPU settings. Registry configuration parses offline;
startup validates the explicit pin and current metadata without a keyring read or
remote call. Registered adapters currently require `streaming=false`. Legacy local
loopback OpenAI-compatible/Ollama configuration and streaming retain their existing
behavior. Legacy remote configuration still parses for offline administration,
but startup explains how to migrate it instead of constructing an unbound client.

```sh
lumen --config lumen.toml health
lumen --config lumen.toml serve
```

Remote readiness is metadata only: `remote_not_probed` when available, otherwise
`unavailable`. Health distinguishes configured metadata, a ready credential
reference and untested network access. No billable probe or keyring prompt occurs.

Ordinary runs, planner requests and scheduled runs load the selected snapshot,
authorize that exact route and then resolve its key for each request. They do not
fall back to another permitted provider or the legacy endpoint. Workers keep their
assignment's exact provider/profile and existing projection/data-policy gates;
the shared lazy resolver rechecks remote egress before key use. Worker generation
settings and usage recording are forwarded. A registry profile alone does not
create worker routing metadata, capacity, health observations or data policies;
those remain part of the existing orchestration setup and default-deny admission.

## Rotation, disablement and revocation

Stop the service. Create a new reference with the same provider scope (or the new
protocol/endpoint if changing those). Inspect all four heads, register a new bundle
using those heads and the new reference, update the selected profile revision,
then restart. Do not mutate the value behind an existing pinned reference.
An older selection becomes unavailable when the provider/profile head advances.
Disabling a provider or changing its egress mirror also stops subsequent requests.

Revoke explicitly after deciding whether the old reference is needed for rollback:

```sh
lumen --config lumen.toml provider credential revoke --id RETURNED-UUID
```

Revocation commits audited `revoked` metadata before deleting the OS account.
Failed deletion leaves the reference unusable and reports a safe cleanup error;
retrying revoke is supported, including an already absent account. Keep historical
metadata and audit events. Rollback is a new revision pointing to an explicitly
valid credential/configuration, never a revision decrement.

Checks authorize one request snapshot. Changes block subsequent admissions; they
cannot unsend an already admitted HTTP request or guarantee live cancellation.
Stronger live revocation would require a dispatch barrier and cancellation protocol.

## Diagnostics and verification

Key buffers use zeroizing ownership and sensitive headers. Provider/backend errors
use safe categories rather than response bodies or keyring error text. Known keys
are registered with the host's shared diagnostic/support redactor; reflected keys
in final text, model names, tool names/IDs or arguments are rejected before return
and persistence. The redactor retains in-memory copies for later scrubbing; HTTP
header allocations and external OS stores do not have a complete zeroization guarantee.
The guard does not promise detection of arbitrary encoded/transformed secrets.

Migration `0032_provider_configuration.sql` rebuilds the provider parent table and
adds ownership and provider-purpose reference metadata. The migration connection
disables foreign keys before SQLx's transaction, restores them afterward and checks
all foreign keys before returning a database handle. Existing parent/child history
is preserved; failed migration returns no serving handle.

Tests use counting fake stores and verified local HTTPS fixtures with a test CA.
No live provider key or paid request is used in CI. For an optional real-provider
smoke test, explicitly authorize a benign public prompt and its cost, configure
the real vendor endpoint/model through the workflow above, start the service, and
use the existing authenticated `POST /api/v1/workspaces/<workspace UUID>/runs`
route. Observe its completion through the existing run/event API. Record protocol,
model, result and time without keys or authorization headers. Do not treat passive
readiness as a successful authentication test; there is no `lumen run start` command.
