# M5 WSL memory pressure: measured triage and safe shutdown (QA #26)

Evidence date: 2026-09-16, America/Chicago. Measured source tree: `qa-m5-26-wsl-memory` at parent commit `9b0763c60311a7319603e1b078c42c4a5f283eca`. Historical F21 was a user report of high `VmmemWSL` use, **not** a measured Lumen leak. This guide is an operational follow-up; no host settings, drivers, Ollama service, or application code were changed.

## What to measure before changing a limit

Run these from PowerShell at baseline, during the workload, immediately after it, and after idle. Run the WSL commands from a second terminal while a build/inference is active. They show process names, not command-line arguments or environment values, to avoid collecting unrelated secrets.

```powershell
Get-Date -Format o
Get-CimInstance Win32_ComputerSystem | Select-Object Name,TotalPhysicalMemory
Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize
Get-Process -Name vmmemWSL -ErrorAction SilentlyContinue | Select-Object ProcessName,Id,WorkingSet64,PrivateMemorySize64
wsl.exe --version
wsl.exe --list --verbose
wsl.exe --list --running
$wslConfigPath = Join-Path $env:USERPROFILE '.wslconfig'
Test-Path -LiteralPath $wslConfigPath
if (Test-Path -LiteralPath $wslConfigPath) { Get-Content -LiteralPath $wslConfigPath }
wsl.exe --distribution Ubuntu -- cat /etc/wsl.conf
wsl.exe --distribution Ubuntu -- free -m
wsl.exe --distribution Ubuntu -- ps -eo pid,ppid,comm,rss,vsz --sort=-rss
wsl.exe --distribution Ubuntu -- curl -fsS http://127.0.0.1:11434/api/ps
wsl.exe --distribution Ubuntu -- ss -ltnp
```

This session's default and only running distro was Ubuntu; `docker-desktop` was stopped. Replace `Ubuntu` with the exact distro under test, and repeat guest/process checks for every other running distro before attributing VM-wide `vmmemWSL` or `.wslconfig` behavior to one workload. The loopback Ollama endpoint may be shared across distros, so confirm which process owns it. `WorkingSet64` is host-resident memory for the VM process; `PrivateMemorySize64` is not the same as resident RAM. Linux `free` separates used memory from `buff/cache`; individual `ps` RSS values are not additive because pages may be shared. Ollama's `size_vram` is GPU residency and does not mean zero system-RAM use. One snapshot cannot establish a leak: compare the same process, workload, VM boot, and idle period over time. If the VM/distro restarts between samples, start a new series.

## This host's samples

Windows reported 33,515,126,784 bytes physical RAM (about 31.2 GiB), WSL 2.6.1.0, Windows build 26200.9457. No `%UserProfile%\.wslconfig` existed; `/etc/wsl.conf` enabled systemd and set the default user only. Ubuntu was WSL 2; `docker-desktop` was stopped when checked. The guest reported 15,594 MiB RAM and 4,096 MiB swap. These are observed values, not a recommendation to copy the VM size or swap setting.

| Phase | `vmmemWSL` working set | Linux `free -m` used / buff-cache | Main observed process RSS | Result |
| --- | ---: | ---: | ---: | --- |
| Fresh idle baseline | 1.85 GiB | 646 / 988 MiB | Ollama service ~38 MiB | No model loaded; swap used 0. |
| Bounded warm Rust build | 2.61–2.83 GiB | 966–1,004 / 1,483–1,650 MiB | Cargo ~169 MiB; two `rustc` processes up to ~221 and ~118 MiB in one sample | Build activity and cache both rose. |
| Just after build exit | 2.84 GiB | 658 / 1,703 MiB | Cargo/`rustc` absent | Process RSS fell; cache remained. |
| `qwen3:4b` model loaded/inferred | 5.24 GiB | 1,015 / 4,265 MiB | `llama-server` ~735 MiB; Ollama service ~52 MiB | Operator probe passed; `ollama ps` showed 3.2 GB at 100% GPU. |
| Owned Lumen server idle | 4.77 GiB | 683 / 3,797 MiB | Lumen ~37 MiB; model runner absent | Port 38281 listening under owned PID 1525. |
| Owned Lumen server stopped | 4.63 GiB | 677 / 3,797 MiB | Lumen PID absent | SIGINT exit 0, `server_stopped result=ok`, port 38281 gone. |
| Later idle observation, 20:23 CDT | 0.90 GiB | 666 / 994 MiB | No build or model runner | Unexplained reduction; this was not a controlled reclaim test. |

The measurements establish contributors in this session: transient compiler RSS, a model runner, and several GiB of Linux cache/VM working-set change. They do **not** reproduce the September 12 pressure at its original scale or attribute it to Lumen. Host free physical memory also changed (about 18.7 GiB at initial inventory, 13.0 GiB near inference, 15.6 GiB after the owned server stopped), but other Windows workloads were not held constant. Swap stayed at 0 MiB used in every sampled `free -m` result. No OOM or sustained process-RSS growth was observed. The later idle decline is not proof of automatic reclaim: neither model unload nor a controlled cache-reclaim experiment was run, and the VM/distro lifecycle across that gap was not pinned down.

The build command was intentionally limited to two compiler jobs:

```powershell
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/home/laneb/.cache/lumen-m5-cargo-target /home/laneb/.cargo/bin/cargo test --workspace --quiet
wsl.exe -- /usr/local/bin/verify-ollama-gpu qwen3:4b
```

The full Linux workspace test stopped at `glib-sys` because `pkg-config`/GLib desktop prerequisites were unavailable; it did **not** pass and did not fail for memory. The model probe exited 0. This was a warm, bounded build sample, not a cold-build peak or stress test. GPU VRAM (reported 4,706/16,376 MiB in the probe) is separate from the host/guest RAM figures.

An owned Lumen process was launched with the ignored `.worktrees/m5-28-live/lumen.toml` fixture. The first cached executable reported migration 6 modified. Read-only inspection showed the fixture database checksum matched the current SQL file's SHA-384; rebuilding the CLI then started the same database successfully. This is consistent with a stale build artifact, but its exact cause was not isolated. The database was retained, not reset, and this is not evidence of a memory leak. The verified process was then stopped normally. The following is the **historical record, not a reusable PID recipe** (fixture token redacted; default distro was Ubuntu):

```powershell
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/home/laneb/.cache/lumen-m5-cargo-target /home/laneb/.cargo/bin/cargo build -p lumen-cli
wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- env PATH=/home/laneb/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LUMEN_BEARER_TOKEN=<redacted-owned-fixture-token> /home/laneb/.cache/lumen-m5-cargo-target/debug/lumen --config .worktrees/m5-28-live/lumen.toml serve
wsl.exe -- ps -p 1525 -o pid=,comm=,args=  # verify the owned fixture command before signaling
wsl.exe -- kill -INT 1525
wsl.exe -- ps -p 1525 -o pid=,comm=        # no process remained
wsl.exe -- ss -ltnp                       # 127.0.0.1:38281 absent
```

For a new run, use `wsl.exe --distribution <distro> -- ps` to identify and verify the fresh owned process and its command, then signal that PID in the **same** distro. Never reuse historical PID 1525: it may now identify an unrelated process. Confirm both process exit and port release in that distro.

## Resource policy, only if repeated measurements warrant it

Keep the existing configuration unless a repeatable workload actually causes host pressure. Before setting a cap, record peak guest `used + buff/cache`, process RSS, swap use, host free RAM, and any Docker/other WSL distro use. Choose headroom for the measured build and model load plus unrelated WSL workloads; do not derive a cap from GPU VRAM. A lower `memory` value can turn a host-pressure symptom into guest OOM or slower builds; swap can prevent OOM at disk-I/O cost. Zero swap is not a safe default recommendation. Current Microsoft documentation says `%UserProfile%\.wslconfig` is VM-wide across WSL 2 distros, `memory` and `swap` are configurable there, and `autoMemoryReclaim` can be `disabled`, `gradual`, or `dropCache` ([advanced WSL settings](https://learn.microsoft.com/en-us/windows/wsl/wsl-config)). Check the installed WSL version and current Settings UI as well as the file before changing anything.

If the owner elects a change: copy the existing `.wslconfig` (or record that none existed), record the chosen values and measurement basis, close/preserve all active WSL and Docker work, apply one setting at a time, then restart the VM only during an agreed maintenance window. Re-run the same build/model/idle matrix and watch for OOM, swap thrash, and effects on other distros. Roll back by restoring the copied file (or removing only the newly created file), then restart at an agreed time. No cap, swap, reclaim, or restart change was made for this issue; a capped regression and retained-config restart are therefore **not run**.

## Stop the smallest thing first

1. Stop an owned Lumen `serve` or dev-server process with its normal interrupt/shutdown path; wait for a completed exit and check PID and listening port. `^C` alone is not an exit receipt.
2. An Ollama model unload (`ollama stop <model>`) releases model residency but may interrupt other clients of that model; check active users first. Stopping `ollama.service` affects all Ollama clients and is not the same as stopping Lumen. Neither was done here.
3. `wsl --terminate <distro>` stops that entire distro's processes. `wsl --shutdown` immediately stops **all** running WSL distros and the VM, including unrelated Docker-backed work; use only after preserving evidence and confirming no active work. Microsoft documents this scope in its [basic WSL commands](https://learn.microsoft.com/en-us/windows/wsl/basic-commands). Neither command was run here.

If a future run shows Lumen RSS increasing across repeated identical runs after model/build/cache effects are excluded, retain a process-level profile and open a focused leak investigation. F21 alone does not justify one.
