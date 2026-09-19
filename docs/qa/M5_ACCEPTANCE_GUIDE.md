# M5 local readiness acceptance guide

This guide describes the current CLI and API after QA issue #22. It does not revise the historical September 12 observations. Use a disposable local bearer token; do not paste a production token into a shell command, URL, log, or QA report.

## Host diagnostics before configuration

From the repository root, `cargo run -p lumen-cli -- --config missing.toml sandbox report` prints the detected sandbox backend, strength, guarantees, and diagnostic detail without loading a config, opening a keyring, or creating runtime files. The same command works in PowerShell and WSL Bash. A missing or malformed config still fails for commands that need it, for example `cargo run -p lumen-cli -- --config missing.toml migrate`.

On Windows, a report of unavailable kernel enforcement is a host diagnostic, not permission to downgrade execution. `serve` remains fail-closed when the configured required sandbox strength is unavailable. For a live acceptance run, use a supported Linux/WSL host with its required sandbox backend available.

## Start and check each layer

Start with your local `lumen.toml` and `LUMEN_BEARER_TOKEN` set to a disposable token: `cargo run -p lumen-cli -- --config lumen.toml serve`. For repeated QA operations, build once and run the exact binary as described in the [Cargo cache guide](M5_CARGO_CACHE_GUIDE.md). `event=server_starting` reports the intended bind address, config path, workspace ID, sandbox backend and strength, and owned process PID before database/runtime initialization; it is **not** a listening claim. `event=server_started` reports the same fields only after the socket has bound and initialization completed. A bind conflict prints `event=server_bind_failed` and exits nonzero; it does not claim readiness. Ctrl+C prints `event=server_stopping` followed by `event=server_stopped result=ok` after bounded shutdown.

Replace the bind address and workspace ID below with those from your own startup line. In PowerShell:

```powershell
$uri = 'http://127.0.0.1:3000/api/v1/workspaces/YOUR-WORKSPACE-UUID/runtime/capabilities'
$headers = @{ Authorization = "Bearer $env:LUMEN_BEARER_TOKEN" }
Invoke-RestMethod -Uri $uri -Headers $headers
Invoke-RestMethod -Uri "${uri}?probe_model=true" -Headers $headers
```

In WSL Bash, for a disposable local token only:

```bash
uri='http://127.0.0.1:3000/api/v1/workspaces/YOUR-WORKSPACE-UUID/runtime/capabilities'
curl --fail-with-body -H "Authorization: Bearer ${LUMEN_BEARER_TOKEN}" "$uri"
curl --fail-with-body -H "Authorization: Bearer ${LUMEN_BEARER_TOKEN}" "${uri}?probe_model=true"
```

The first authenticated GET is cheap: `server: "listening"` and `workspace: "ready"` mean the server accepted the request for this configured workspace; `sandbox` reports its backend and guarantees; `model: "not_checked"` means no model request was made. A bad token returns 401 and a different workspace returns 403. There is no unauthenticated `/health` route.

The opt-in `probe_model=true` GET checks only the configured **loopback** OpenAI-compatible `/v1/models` catalog, with a three-second timeout and bounded response. `model: "listed"` means the configured model ID appears in that catalog, **not** that an inference worker/GPU is loaded or generation will succeed. `"not_listed"` means the catalog is reachable but lacks that ID; `"unavailable"` means it could not be read. A configured remote model returns `"remote_not_probed"`: this diagnostic does not authorize remote egress or bypass model policy. If the model is down, the server and workspace can still report ready while the opt-in model field reports unavailable.

Automated evidence for the owned-process startup, auth, port conflict, model-down, and shutdown path is `cargo test -p lumen-cli --test readiness` in WSL. Route and local catalog cases are covered by `cargo test -p lumen-server --test routes` and `cargo test -p lumen-integrations --test openai_compatible`. Those tests are not a substitute for recording a separate manual live acceptance result.
