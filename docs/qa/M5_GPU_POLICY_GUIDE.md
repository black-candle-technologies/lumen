# M5 scoped GPU residency policy — issue #28

Implementation tested: `3ccdbc8c7ad9bf6d2657dbf272591dff93a25ec7` on `qa-m5-28-gpu-verification`, stacked on `qa-m5-25-js-deps` (`5eba8bb166665b4dea522fbcbed0820485f1349f`). Evidence date: 2026-09-16, America/Chicago. Issue #28 remains open for review.

## Scope and operator setting

The default `[model] gpu_policy = "off"` makes no GPU claim and preserves generic OpenAI-compatible providers. Opt in with `gpu_policy = "require_full"` for a model that must be fully resident in GPU memory, or `gpu_policy = "allow_mixed"` to permit partial GPU/CPU offload. The policy accepts only an HTTP loopback Ollama `/v1` or `/v1/` endpoint. It does not govern unrelated executables, another machine, the Windows Ollama instance, or remote providers. No new network egress or privilege is granted.

For an opted-in request, Lumen reads bounded same-origin `GET /api/ps` telemetry. If the configured model is absent, it first asks Ollama to load it via `POST /api/generate` with an empty prompt, then probes again. Lumen sends user content to `/v1/chat/completions` only after the pre-check passes. A post-check must also pass before Lumen releases model output. A cancelled, failed, or unverified request has no CPU fallback in Lumen. This guard is shared by the CLI-launched `serve` process and its authenticated run API; this CLI has no separate direct-inference command.

| `/api/ps` observation | Classification | `require_full` | `allow_mixed` |
| --- | --- | --- | --- |
| `size_vram == size > 0` | Full GPU residency | Allow | Allow |
| `0 < size_vram < size` | Mixed offload | Reject | Allow |
| `size_vram == 0`, `size > 0` | CPU-only | Reject | Reject |
| HTTP/transport/timeout failure, or still absent after preload | Unavailable | Reject | Reject |
| Missing/malformed/invalid size metrics | Unknown | Reject | Reject |

These are model-level memory snapshots, **not request-correlated hardware attestation**. Concurrent inference, a reload between probes, or a dishonest local endpoint can defeat attribution. Even a full-residency observation does not prove every operation executed on the GPU. Operators needing that guarantee must obtain request-correlated backend telemetry from their trusted runtime. We intentionally did not add a misleading `GPU=true` capability field or duplicate orchestration work in issues #4/#5. Ollama describes `/api/ps` model residency and `ollama ps` processor meanings in its [API reference](https://docs.ollama.com/api/ps) and [FAQ](https://docs.ollama.com/faq).

## Environment and inventory

The tested managed endpoint was WSL systemd Ollama 0.34.0 at `127.0.0.1:11434`, executable `/usr/local/bin/ollama`, service `ollama.service`, with local `qwen3:4b`. The host GPU was NVIDIA GeForce RTX 4070 Ti SUPER (16,376 MiB reported). The existing service drop-in `gpu-required.conf` invokes `/usr/local/bin/require-nvidia-gpu` before startup and `/usr/local/bin/require-ollama-cuda` after startup; `/usr/local/bin/verify-ollama-gpu` is a separate operator probe. These existing host files were inspected, not changed. Their startup checks do not enforce a per-model or per-Lumen-request policy. A separate Windows Ollama 0.34.1 installation was inventoried but not used as this Linux managed endpoint.

Commands run from the isolated Windows worktree (the disposable config and database are ignored under `.worktrees/m5-28-live/`; bearer value redacted):

```powershell
wsl.exe -- /usr/local/bin/ollama --version
wsl.exe -- /usr/lib/wsl/lib/nvidia-smi
wsl.exe -- curl -fsS http://127.0.0.1:11434/api/version
wsl.exe -- systemctl cat ollama
wsl.exe -- /usr/local/bin/verify-ollama-gpu qwen3:4b
wsl.exe -- curl -fsS http://127.0.0.1:11434/api/ps
& "$env:LOCALAPPDATA\Programs\Ollama\ollama.exe" --version
cargo fmt --all -- --check
cargo clippy -p lumen-integrations -p lumen-cli --all-targets -- -D warnings
cargo test --workspace --quiet
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin CARGO_TARGET_DIR=/home/laneb/.cache/lumen-m5-cargo-target /home/laneb/.cargo/bin/cargo test -p lumen-integrations --test openai_compatible
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin CARGO_TARGET_DIR=/home/laneb/.cache/lumen-m5-cargo-target /home/laneb/.cargo/bin/cargo test -p lumen-cli --quiet
```

The disposable config used `endpoint = "http://127.0.0.1:11434/v1/"`, `model = "qwen3:4b"`, `gpu_policy = "require_full"`, `streaming = false`, a loopback server bind `127.0.0.1:38281`, and an owned workspace/database. Exact live command forms follow; substitute only the redacted owned fixture token. In terminal A, Lumen served in the foreground (run a second time after stopping the first owned process):

```powershell
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin CARGO_TARGET_DIR=/home/laneb/.cache/lumen-m5-cargo-target /home/laneb/.cargo/bin/cargo build -p lumen-cli
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LUMEN_BEARER_TOKEN=<redacted-owned-fixture-token> /home/laneb/.cache/lumen-m5-cargo-target/debug/lumen --config .worktrees/m5-28-live/lumen.toml serve
```

In terminal B, the authenticated API and journal checks were:

```powershell
$headers = @{Authorization='Bearer <redacted-owned-fixture-token>'}
$root = 'http://127.0.0.1:38281/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31'
Invoke-RestMethod -Uri "$root/runtime/capabilities" -Headers $headers
Invoke-RestMethod -Method Post -Uri "$root/runs" -Headers $headers -ContentType 'application/json' -Body '{"prompt":"Reply with exactly: GPU_READY"}'
Invoke-RestMethod -Uri "$root/runs/e7a7272b-33dc-49e3-a625-d35963a78656/status" -Headers $headers
wsl.exe -- curl -sS -N --max-time 5 -H 'Authorization: Bearer <redacted-owned-fixture-token>' http://127.0.0.1:38281/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/runs/e7a7272b-33dc-49e3-a625-d35963a78656/events
wsl.exe -- curl -fsS http://127.0.0.1:11434/api/ps
wsl.exe -- journalctl -u ollama --since '2026-09-16 20:05:00' --no-pager -o cat
# After restarting only the owned Lumen process in terminal A:
Invoke-RestMethod -Method Post -Uri "$root/runs" -Headers $headers -ContentType 'application/json' -Body '{"prompt":"Reply with exactly: RESTART_READY"}'
Invoke-RestMethod -Uri "$root/runs/0ce71311-2a20-4910-88a5-0ff0686c9f1d/status" -Headers $headers
wsl.exe -- curl -sS -N --max-time 3 -H 'Authorization: Bearer <redacted-owned-fixture-token>' http://127.0.0.1:38281/api/v1/workspaces/26db5a31-94f0-4e92-a9c9-4cdf19d71c31/runs/0ce71311-2a20-4910-88a5-0ff0686c9f1d/events
```

The SSE `curl --max-time` invocations returned the completed event, then exited with timeout code 28 because the event stream remains open. The Ollama service itself was not restarted, avoiding disruption to other local users.

## Expected versus actual

| Check | Expected | Actual |
| --- | --- | --- |
| Local fitting model, direct operator probe | GPU available, full residency | `verify-ollama-gpu qwen3:4b` exited 0; `ollama ps` showed 3.2 GB, 100% GPU, context 4096. |
| Managed API under `require_full` | Authenticated run completes only when pre/post residency passes | Run `e7a7272b-33dc-49e3-a625-d35963a78656` completed, SSE `GPU_READY`. `/api/ps` reported `size = size_vram = 3178149969` for `qwen3:4b`. |
| Request-window backend evidence | CUDA runner appears for the corresponding Ollama call | At 20:05:17–20:05:22 CDT the WSL journal showed pre/post `/api/ps`, one `/v1/chat/completions` HTTP 200, and `runner.inference="[{ID:0 Library:CUDA}]"`, `runner.size=runner.vram="3.0 GiB"` for `qwen3:4b`. Ollama logs no Lumen run ID, so the correlation is temporal, not cryptographic. |
| Fresh shell / owned Lumen restart | Same persisted config still guards the run | New Lumen PID started; run `0ce71311-2a20-4910-88a5-0ff0686c9f1d` completed, SSE `RESTART_READY`. At 20:06:27–20:06:28 CDT the journal again showed pre/post probes, one chat POST, and a CUDA runner. |
| GPU unavailable, CPU-only, mixed, unknown, preload backend failure, post-call downgrade | No silent successful output under `require_full` | Deterministic wiremock tests rejected each disallowed state, including `/api/ps` HTTP 503 and `/api/generate` HTTP 503; the authenticated runtime test reached `failed` with CPU-only telemetry and issued no chat POST. `allow_mixed` accepted only mixed/full. The post-call downgrade test withheld an otherwise valid answer. |
| Regression / invariants | Existing functionality remains green | Windows `cargo test --workspace --quiet` passed; Linux provider test 21/21 and CLI package (including new guarded authenticated run) passed; format, strict clippy, and `git diff --check` passed. |

Unrun live cases: a larger model that partially offloads or does not fit, physical GPU removal/backend failure, restart of the shared Ollama systemd service, and a managed run against the separate Windows Ollama installation. Synthetic mixed, CPU-only, telemetry-unavailable/unknown, preload-failure, and downgrade fixtures cover fail-closed behavior without changing drivers or shared service state. `gpu_policy = "off"` remains the explicit user override and carries no GPU assurance; `allow_mixed` is the explicit offload allowance.
