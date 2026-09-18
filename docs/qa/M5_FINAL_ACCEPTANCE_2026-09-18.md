# M5 final acceptance evidence — QA #8

Recorded 2026-09-18 (America/Chicago). **Disposition: NOT ACCEPTED.** This is an evidence report for the last branch of the unmerged M5 QA stack, not a release sign-off. The [machine-readable matrix](M5_FINAL_ACCEPTANCE_2026-09-18.json) enumerates **47 named cases: 34 PASS, 1 FAIL, 6 PARTIAL, 4 NOT RUN, 2 BLOCKED**. Every row has an expected result, observed result, source/environment reference, and evidence reference or an explicit reason for missing evidence. `PARTIAL` is not a pass.

The live Lumen source was `bcceae4cabdb9af165f3df8e5744b4416347e1e2` on parent branch `qa-m5-27-platform-matrix` (PR #51). The owned WSL binary SHA-256 was `9a140f82a7154ec0edd59abbe751c55dd2b094718ed67374d07e46dcb3e36074`. The real model was Ollama 0.34.0, `qwen3:4b`, digest `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7`. The 2.5-second delay test used a **deterministic WSL-local stub**, not Ollama. All browser interaction here was **agent-operated Edge**, not human manual validation.

## Live runtime and authorization

| Case | Status | Expected → observed |
| --- | --- | --- |
| API final answer | PASS | `run.completed` carries exact text → `LUMEN_M5_LIVE_OK` in run `65145937-52ec-4a1f-902a-3822912690ae`. |
| Real model tool read | PASS | Model-to-tool-to-answer loop → succeeded `filesystem.read` of `probe.txt`, source SHA-256 `71696db3830b80ea33318bb8c9d0d3ee1eb5791566d8cfd64cfdb6b99d12c605`, final marker `LUMEN_M5_READ_MARKER_73B1`. |
| Approval-gated real write | PASS | File absent until exact grant → consumed approval and file SHA-256 `a3b017d986bcd07144b4d5e42c1cf400e79604f5eb04959c6126774b20270f90`. |
| Rejected write | **FAIL** | No write and consistent terminal states → no file and run failed, but persisted action remained `normalized`, not terminal. No side effect occurred; state reconciliation still fails the full criterion. |
| Zero-grant denial | PASS | Service cannot read without a grant → failed scheduled run/occurrence, `policy_denied`, no `execution_started`. |
| Zero-grant tool catalog | PARTIAL | Unavailable tools should not be advertised → model still proposed `filesystem.read`; dispatch denied it. This is not an authorization bypass. |
| Approval expiry | PASS | Grant after deadline cannot dispatch → HTTP 409 `approval_expired`, no file. The run remained `awaiting_approval` for possible renewal, so this does not prove all lifecycle questions around expiry. |
| Approval replay | PASS | Repeated grant cannot redispatch → HTTP 409 `approval_consumed`, unchanged file hash. |
| Scheduled success | PASS | One-shot authorized service read → succeeded occurrence, linked completed run `9b7dedc4-f6f9-441a-af1a-a91dd0a76c74`, exact file marker. |
| Scheduled failure | PASS | Denied service action terminalizes → failed occurrence and linked failed run `76c15a01-2885-48fe-831a-fb2723325556`. |
| Occurrence/run/service identity | PASS | Linked states and actors agree → both observed occurrences matched their runs and service identities. |
| Duplicate prevention after restart | PASS | Completed one-shot does not redispatch → one occurrence retained; UI later showed no next occurrence after pause/resume. This is only the observed one-shot path. |
| Same-DB restart | PASS | Jobs, approvals, skills, audit and occurrences persist → same uncorrupted DB restarted with `quick_check=ok`, prior states intact. |
| Crash at durable handoff | NOT RUN | No crash was injected between occurrence persistence and dispatch. |
| Unknown-outcome reconciliation | NOT RUN | No ambiguous executor-outcome fault was injected; earlier review concerns remain. |
| Active cancellation | PASS | Running model request can terminate without action → run `7cb81520-cda3-419d-97b3-7f1645b41260` emitted `run.cancelled`, zero actions. |
| Provider unavailable | PASS | Closed model port fails consistently → run `9b42dc05-75ed-485a-8d07-400c1ffb5495` failed with request error and no actions. |
| Delayed provider | PASS | Bounded delayed response completes → WSL-local SSE stub delayed 2.5 s; parent run `8472c634-6e6a-4fad-8c4e-4e681044113d` completed in 2.542 s, then the checked-in fixture drove run `86f8a49d-4126-470d-bf59-0f022140ffb1` to completion in 2.584 s at source `cb75f52d4eb738f0586f1229fe241e698ca4aaac`; both returned `LUMEN_M5_DELAY_OK`. An initial request before the first stub was listening failed; it is not recast as the delayed pass. |
| Provider timeout | NOT RUN | An over-deadline response was not injected. |
| Live outbound tool wire correlation | PARTIAL | Retained wire request should prove advertised schemas, call ID and correlated result → run/action/audit/model digest are retained, but the complete outbound live wire payload and tool-call ID were not. The automated protocol tests are separate evidence. |

## Skills, audit, browser and shutdown

| Case | Status | Expected → observed |
| --- | --- | --- |
| Workflow capture | PASS | Tool-bearing source yields reviewable draft → captured completed read with source run, action kind/argument digest, audit sequence and review warnings. |
| Skill publish | PASS | Exact approval gates publication → `skill.publish` approval consumed for skill `7ab9d210-133c-43db-b4b1-589d62afdbf9` version `1.0.0`. |
| Skill load | PASS | Intact reviewed version loads → status `loaded`, digest `sha256:dc20738d6256b9408b0cb787a5881378deea6d2facb903e21f606395b7ba3e2b`. |
| Skill tamper exclusion | PASS | Changed bytes are excluded → `digest_mismatch`; exact original bytes restored and load resumed. |
| Changed-input reviewed reuse | PARTIAL | Captured procedure should guide a new changed-input run → draft is generic; no such guided run was demonstrated. Publication is not proof of reusable learning. |
| Audit verify | PASS | Healthy chain verifies → CLI `AuditVerified` before mutation and after exact snapshot restore. |
| Audit tamper fail-closed | PASS | Changed audited payload prevents startup → event 1 hash mismatch with SQLite `quick_check=ok`; launcher refused startup and kept port free; snapshot restore recovered. |
| Chat answer | PASS | Final model answer visible in UI → Edge displayed `LUMEN_M5_UI_OK` as Lumen's message; [retained screenshot](M5_FINAL_ACCEPTANCE_2026-09-18.json) is indexed as `browser_chat_image`. |
| Valid browser connection | PASS | Verified runtime enables Chat and controls → `Local runtime` and two jobs/two service identities visible. |
| Unreachable browser runtime | PASS | Outage is not a zero-data success → approvals showed “Pending count unavailable” and a retryable load error. |
| Invalid bearer token | PASS | Bad credential loses verified connection → “Authentication failed”; Chat disabled. |
| Disallowed workspace | PASS | Wrong workspace loses verified connection → “Workspace denied”; Chat disabled. |
| Late response from old connection | PARTIAL | Old generation cannot overwrite new verified state → automated browser coverage exists, but no live delayed old-connection response was captured. |
| Pause pending + grant | PASS | No optimistic pause; grant commits → persisted enabled revision 1 while pending, paused revision 2 after UI grant. |
| Pause rejection | PASS | Reject leaves state/revision unchanged → enabled revision 3 before and after UI reject. |
| Resume pending + grant | PASS | No optimistic resume; grant commits → paused revision 2 while pending, enabled revision 3 after UI grant. |
| Resume rejection | PASS | Reject leaves state/revision unchanged → paused revision 4 before and after UI reject. |
| Browser error versus empty | PASS | Failure and true zero render differently → outage showed alert/unavailable; restart + Retry showed “0 pending” and “No actions are waiting for approval.” |
| Idle bounded shutdown | PASS | Owned process and port stop promptly → one observed shutdown ~506 ms with port free; subsequent stops freed the port. |
| Full active shutdown | PARTIAL | Active HTTP/SSE/model/executor children finish within shared deadline → automated coverage exists; no combined live active-stream/native-child shutdown was retained here. |
| GPU verification | PARTIAL | Attribute the actual request to GPU policy → `ollama ps` reported `qwen3:4b` 100% GPU residency during a scheduled run. Residency is **not** per-request attribution or proof that every invocation is GPU-only. |

## Automated platform matrix and prerequisites

The [#27 platform matrix](M5_PLATFORM_MATRIX_2026-09-17.md) is the retained automated tier, at full test-tree SHA `f45c286733b3ebd6abe21aad20303792d310a36e`. Later #27 commits changed CI/report metadata, not the production test tree. Its named inventory, commands, raw-log SHA-256 values, first failures and non-green gates are not replaced by this acceptance report. On this #8 branch, `wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- python3 -m unittest discover -s scripts/qa -p 'test_*.py' -v` ran 41 QA-helper tests: 39 passed, 2 explicitly skipped because the optional owned-live-server test binary variable was not set. `python -m unittest discover -s scripts/qa -p test_m5_delay_provider.py -v` separately passed all 4 fixture tests on Windows. The live fixture checks above are separate from those skipped test methods.

| Case | Status | Actual result |
| --- | --- | --- |
| Native Windows workspace | PASS | `cargo test --workspace --locked`: 339/339; strict Clippy pass. |
| WSL non-desktop/sandbox | PASS | `cargo test --workspace --exclude lumen-desktop --locked`: 357/357; Linux sandbox gate pass. Full strict WSL workspace Clippy retained three existing unrelated lints. |
| Web automated | PASS | `corepack pnpm --dir apps/web check`, Vitest 21/21, build pass, automated Playwright 40/40. |
| Native Linux desktop | BLOCKED | Local GTK/DBus development dependencies unavailable; no desktop native test list or pass. |
| Shareable CI matrix | BLOCKED | [PR #51 run 35297498359](https://github.com/black-candle-technologies/lumen/actions/runs/35297498359) did not start any job step because of the account payment/spending-limit annotation; no artifacts. |
| Human manual acceptance | NOT RUN | Edge walkthrough above was agent-operated; no maintainer sign-off or native Linux desktop walkthrough. |

## Reproduction and retained evidence

The [QA launcher guide](M5_QA_LAUNCHER_GUIDE.md) gives the full fixture lifecycle. The command sequence for the owned live tier was `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/qa/m5_launcher.ps1 -Distro Ubuntu init --name m5-acceptance-20260917`, then the same prefix with `build`, `start`, `status`, `snapshot --label pre-audit-tamper`, `stop`, a synthetic one-row audit mutation on the **stopped owned DB**, a refused `start`, `restore --label pre-audit-tamper --confirm 3bb8e247-6102-4bbc-ae8b-c059e9a6fa55`, `start`, `snapshot --label post-browser-acceptance`, and `stop`. API requests used `POST /api/v1/workspaces/{workspace_id}/runs`, `GET /runs/{run_id}/events`, approval decisions, job/service/occurrence status, and `GET /skills`. The helper's case JSON records retain the run/job/approval IDs and operation summaries; they are not a complete shell transcript. Token-bearing commands and raw request bodies are intentionally not committed. No bearer token is stored in this report.

The in-budget delay was originally observed against a transient WSL-local SSE stub. It was repeated end-to-end against the checked-in fixture with `wsl.exe --cd /mnt/c/Users/laneb/lumen-m5-windows -- python3 -u scripts/qa/m5_delay_provider.py --port 11436 --delay-ms 2500`, then `m5_launcher.ps1 -Distro Ubuntu init --name m5-acceptance-delay-checked --endpoint http://127.0.0.1:11436/v1/ --model qa-delay`, `build`, `start`, authenticated `POST /runs`, `GET /runs/{id}/events`, and `stop`. The fixture binds loopback only, caps request size and delay, and returns `LUMEN_M5_DELAY_OK` SSE frames. Its wire and timing contract is tested on Windows and WSL. This does not relabel the stub as a real model or an over-deadline timeout test.

Sanitized records, browser captures and snapshots are retained in the launcher evidence stores keyed by fixture IDs: live `3bb8e247-6102-4bbc-ae8b-c059e9a6fa55`, model-down `09f74d38-2fe2-4af1-adde-c98b15a97c50`, original delay `c3c7b87c-5688-4c29-9029-97ff3501373d`, checked-in delay `36e5afa4-d1fc-4721-9f80-0b0754d017aa`. Their filenames and SHA-256 hashes are indexed in the JSON matrix. The final live SQLite snapshot is `snapshots/post-browser-acceptance.sqlite3`, SHA-256 `b0999693cf553c3f6437d9259966b9d0c0b9621b52b2a386a796ad9a432825c0`. Synthetic audit tamper was restored from a hash-checked snapshot; the final snapshot is of the healthy post-browser state.

One generated browser connection-form snapshot exposed the **disposable fixture bearer token** in local automation output. I removed that saved snapshot, scanned the retained browser files for the token, stopped the runtime, and retired the owned live fixture (including its token file) through launcher cleanup. Its evidence directory and final DB snapshot remain; the fixture itself cannot be restarted. This is a test-only local credential, not a production secret, but raw connection-form snapshots must not be shared. The model-down and both delay fixtures were stopped, not deleted.

## Decision boundary

The observed rejected-write action-state inconsistency is a concrete failure, and the partial/not-run/blocked rows are material. Earlier [issue #8 review crosswalk](https://github.com/black-candle-technologies/lumen/issues/8#issuecomment-5691927364) also identifies upstream lifecycle, approval timing, publication recovery, and workflow provenance gaps; the narrow #8 evidence PR does not rewrite those upstream branches. Keep #8 and the relevant canonical issues open for maintainer disposition and targeted follow-up. No PR in the stack should be treated as merge-ready from green test totals alone.
