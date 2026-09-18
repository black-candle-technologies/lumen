# M5 cross-platform verification matrix — QA #27

Evidence captured 2026-09-16–17 (America/Chicago). Verified implementation commit: `f45c286` on `qa-m5-27-platform-matrix`, based on `qa-m5-21-qa-launcher` at `c36d7f31dc3d212cabab2263d24f4a56e05a8894`. The final PR head adds this report only. Issue #27 remains open with `needs-validation`. A green local suite is not live M5 acceptance.

## Historical claims versus retained evidence

The September 12 report and [issue #27](https://github.com/black-candle-technologies/lumen/issues/27) report 264 Windows workspace passes near `c4b5bc7a5c59f0cd2fccb6030749d885fa6f555f`, then 259 at `7c3080ad1530fc7026b777fc211e2a68767e9e94`. They do **not** retain the commands, target/features, raw named lists, or first failed run. Thus no name-by-name 264-to-259 reconciliation is possible. Source diff `c4b5bc7..7c3080a` adds four DB automation tests (`concurrent_revision_appends_have_one_winner`, `exhausted_revision_sequence_fails_closed`, `concurrent_occurrence_claims_have_one_winner`, `occurrence_claim_waits_for_concurrent_eligibility_changes`) and removes no test declaration in the changed files; that does not explain the five-count drop or prove equal coverage. The reported WSL 76 CLI + 11 automation + 9 integration-lib + 30 local-executor = 126 was an explicitly partial set, not a Linux workspace total. The historical unnamed two-second failure that passed on rerun cannot be identified retroactively.

## Independently observed local matrix

| Environment / exact command | Named inventory | Result | Classification |
| --- | ---: | --- | --- |
| Windows 11, Rust `1.97.1` (`x86_64-pc-windows-msvc`): `cargo test --workspace --locked -- --list`; `cargo test --workspace --locked` | 339 | 339 pass, 0 fail/ignored | PASS, native workspace including desktop |
| WSL2 Linux, Rust `1.97.0` (`x86_64-unknown-linux-gnu`), bubblewrap `0.9.0`: `cargo test --workspace --exclude lumen-desktop --locked -- --list`; `cargo test --workspace --exclude lumen-desktop --locked` | 357 | 357 pass, 0 fail/ignored | PASS, server/CLI/integrations only |
| WSL2: the four Cargo commands in `scripts/verify-linux-plugin-sandbox.sh` invoked directly | 5 sandbox unit, 8 extension-process, 3 filtered local-executor tests; example builds | All pass, including namespace isolation and process-group cleanup | PASS, Linux sandbox gate |
| Windows Node `24.19.0`, pnpm `12.4.2`: `corepack pnpm --dir apps/web check`; `corepack pnpm --dir apps/web exec vitest run --reporter=verbose`; `corepack pnpm --dir apps/web build` | 21 unit tests | Check 0 errors/warnings; 21/21; build pass | PASS, web static/unit |
| Windows: `corepack pnpm --dir apps/web exec playwright test --list`; `corepack pnpm --dir apps/web exec playwright test --workers=1` | 40 desktop/mobile cases | 40/40 pass | PASS, automated browser; not manual review |
| WSL2: `cargo test -p lumen-desktop --locked -- --list` | No list produced | Build stopped at `libdbus-sys`: `pkg-config`/native development packages unavailable | BLOCKED locally, not a desktop pass |
| GitHub Actions `m5-platform-matrix.yml` (Windows, Linux server/sandbox, Linux desktop-native, web) | Uploads named lists and raw logs per head SHA | Not yet observed at this report commit | NOT RUN; inspect PR checks/artifacts |
| Live Ollama, GPU, manual desktop/browser acceptance for this issue | — | Not run as part of #27 | NOT RUN; #8 is the acceptance umbrella |

No feature override was passed to either workspace command: Cargo defaults apply, with only `lumen-desktop` excluded from WSL. The new CI jobs record the checked-out PR head SHA, Rust/Node and OS versions, command lines, named inventories, raw run logs, and exit codes; artifacts upload even if a test step fails. The Linux server/sandbox job uses the existing privileged `rust:slim` Docker envelope needed for namespace tests, then runs the full non-desktop suite and sandbox gate. That container path was syntax-checked but could not be executed locally because Docker Desktop is unavailable. The Linux desktop job installs `pkg-config`, `libdbus-1-dev`, GTK 3, WebKitGTK 4.1, and the other native Tauri build prerequisites in CI only. No host packages were installed on this WSL machine.

The final named-inventory diff is 19 Unix/Linux-gated names present only in WSL and one desktop-target name present only in Windows. Specifically:

```text
WSL only (Unix/Linux cfg):
runtime::security_tests::symlink_escape_fails_through_the_model_to_executor_path
occupied_port_reports_bind_failure_without_claiming_readiness
ready_server_reports_layers_with_model_down_and_stops_boundedly
sandbox::tests::linux_plugin_profile_has_no_workspace_home_or_inherited_environment
sandbox::tests::linux_profile_isolates_namespaces_and_exposes_one_executable
sandbox::tests::linux_report_names_each_enforced_guarantee_without_claiming_seccomp
rejects_symlinks_and_hard_links
sdk_fixture_has_no_ambient_files_environment_network_or_process_execution
system_host_executes_the_sdk_subprocess_fixture
system_host_terminates_deadline_cancellation_and_cpu_exhaustion
system_plugin_profile_denies_workspace_reads_writes_and_environment
file_write_preparation_rejects_symlink_targets
process_monitor_applies_cpu_memory_file_descriptor_and_process_limits
process_monitor_enforces_output_limit
process_monitor_honors_cancellation
process_monitor_timeout_terminates_the_process_group
system_sandbox_denies_reads_outside_the_workspace
system_sandbox_denies_workspace_writes
workspace_reader_rejects_symlink_escape

Windows only (desktop target excluded from WSL command):
desktop_shell_has_one_local_least_privilege_authority_surface
```

These are current-tree names, **not** reconstructed names for the historical 264/259 claims. Linux native desktop is a separate CI job, not inferred from the 356 server/CLI passes.

## First failures, repairs, and remaining uncertainty

- First full WSL non-desktop run failed four `extension_process` tests: bubblewrap reported `Creating new namespace failed: Resource temporarily unavailable`. The test fixture set `RLIMIT_NPROC=4`, which counts other processes of the host UID. Its limit is now 512 for tests of sandbox isolation. The separate `process_monitor_applies_cpu_memory_file_descriptor_and_process_limits` test still enforces a strict process limit; no sandbox permission was relaxed. Targeted extension-process and full WSL suites pass after the fixture correction.
- Parallel WSL runs exposed a real approval race: the approval row became visible before the original runtime task parked its `StoredRun`; a grant spawned an advance that saw no in-memory run and returned, leaving a granted action stuck in `awaiting_approval`. A new deterministic test forced that interleaving, failed before the repair, and passes after a shared run-availability wakeup lets the advance wait for parking or terminal cancellation. Authorization, fingerprints, expiry, reservation, and audit paths are unchanged.
- In a 32-thread pass, the 1.1-second timer sleep ended while the observed wall clock was still 463 ms before the persisted approval expiry (`expiry=1789613940178`, `now=1789613939715`). Approval tests now wait for the database's actual creation/expiry timestamp with a bounded guard. The one-second TTL and fail-closed stale/expired decisions are unchanged.
- The same WSL clock rollback exposed a product defect in health quarantine. Three counted plugin faults had timestamps `1789614762128`, `1789614762156`, then `1789614761564`; the old SQL upper bound `occurred_at <= current fault` excluded the first two already-recorded faults, leaving the plugin enabled. A descending-timestamp DB test failed before the query correction and passes on Windows and WSL afterward. Review found that simply dropping the upper bound could also let a distant future-dated fault cause premature quarantine. A second red/green test proves the bounded-window rule: a future outlier does not count with two ordinary faults or pin the window against a later genuine three-fault cluster. The ten-minute window and three-fault threshold remain; a nearby previously persisted fault is still causal if the clock steps backward.
- Earlier stress attempts also produced `approval_stale` 409s and one local `crashed_administrative_reservation_recovers_unknown_without_retry` two-second `executor entered` timeout. They are preserved, not recast as passes. The current approval test helper waits for persisted creation time before grant and reports the server conflict body if it recurs. After the initial DB correction, 40 consecutive full 32-thread CLI runs passed; after that test-helper change, another 20/20 passed. Those stress runs predate the final bounded-window review adjustment; the full Windows and WSL suites passed again at `f45c286`. This does not prove which historical unnamed test failed or rule out every future WSL clock jump. The reservation test retains its original two-second bound with state diagnostics on failure.
- Strict WSL `cargo clippy --workspace --exclude lumen-desktop --all-targets --locked -- -D warnings` failed on three existing `readiness.rs` lints under Rust 1.97.0 (`needless_borrows_for_generic_args` twice, `manual_flatten` once). That file was not changed for #27. Targeted strict Clippy for the affected libraries passed on WSL; full strict workspace Clippy passed on Windows. The WSL lint failure remains an explicit non-test gate gap.

## Retained raw evidence

Local Windows logs are under `%LOCALAPPDATA%\Temp\lumen-m5-matrix-20260916-c36d7f3\`; WSL logs are under `$HOME/.local/share/lumen-m5-qa/matrix-20260916-c36d7f3/`. The final primary filenames and SHA-256 are:

| File | SHA-256 |
| --- | --- |
| `windows-workspace-list-review.txt` | `30d6cf9a7853e114c4cc249c606ed315be3f9ab31c22cf05bd4a6fcdc3ecb3cd` |
| `windows-workspace-run-review.txt` | `933e1ba344f85389351e1949c72d016029cde718bd381553906c8f6096c6f3b4` |
| `wsl-server-list-review.txt` | `9b6618e95e534777526c68a88ffb68eb7b789581a3a4d8e8944d7048e89700ac` |
| `wsl-server-run-review.txt` | `006509be07926723cb6a941d92147eaf99994f0a8f7121706514278cd5667959` |
| `windows-web-check-review.txt` | `1d53033f84a0f86feddb00fb04f0cc2755ce6bfb4499f09be4eacdc1eab0354e` |
| `windows-web-unit-review.txt` | `d5e0dee8093510989658523d966aaa6f54cbf47d5122d4c50c88fe51e0428ebf` |
| `windows-web-build-review.txt` | `3c31c8c1032fdd4528dc5c281d612ec38e4e05bacd7674014067f5b0267287b1` |
| `windows-web-browser-list-review.txt` | `a5ff2396edb6473c607413c43ff059b7fdf4fe4a402b3a894a6a321872ce8626` |
| `windows-web-browser-run-review.txt` | `a7e7dadb59b305d96494a2d3fc30d18edd8f666ca9ab9bf1031f0d14db7586d7` |

The same directories retain the first-failure runs, WSL desktop compiler error, targeted sandbox logs, Clippy output, and parallel stress files (`wsl-cli-stress-*`). These are local evidence, not remote CI artifacts. The workflow's future `m5-windows-workspace-<SHA>`, `m5-linux-server-<SHA>`, `m5-linux-desktop-<SHA>`, and `m5-web-<SHA>` artifacts are the shareable raw-result channel once GitHub runners execute. If CI is unavailable, report it as unavailable rather than silently promoting local evidence to CI evidence.

## Disposition

The supported local automated matrix is green at the implementation commit, with the above first failures and repairs disclosed. Historical name reconciliation, native Linux desktop execution, and a green shareable CI run remain unverified. Keep #27 open with `needs-validation`, and do not declare final M5 acceptance from this matrix; #8 must evaluate live/manual behavior separately.
