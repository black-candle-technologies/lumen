# Lumen M5 QA — Published issue index

**QA session:** September 12, 2026
**Repository:** black-candle-technologies/lumen
**Authoring account:** LaneBucher
**Reviewed head:** `7c3080ad1530fc7026b777fc211e2a68767e9e94`
**PR:** #6, `fix/m5-windows` → `feat/milestone-5-durable-automation`
**Disposition:** Hold final acceptance for targeted repair and missing evidence. No merge performed.

The report is `M5_QA_2026-09-12.md`. Its 24 report observations map to the 22 GitHub QA findings below through the report's explicit crosswalk. The 72 chronological test records distinguish operator observations, agent-reported suites, code-confirmed implementation facts, and risks that still need reproduction.

All **22** findings were published under **LaneBucher**. Each returned issue record confirmed the indicated existing repository label(s). Priorities are explicit title/body triage fields, not custom labels or CVSS scores. No assignees or milestones were imposed. No code, branch, pull-request state, or merge was changed.

| GitHub QA finding | Priority | GitHub issue | Labels |
|---|---|---|---|
| [F01](M5_QA_2026-09-12.md#f01) | P1 | [#7 — Complete the real-model tool-calling request and result round trip](https://github.com/black-candle-technologies/lumen/issues/7) | bug |
| [F02](M5_QA_2026-09-12.md#f22) | P1 | [#8 — Close the live acceptance gaps and require evidence-based pass criteria](https://github.com/black-candle-technologies/lumen/issues/8) | documentation, enhancement |
| [F03](M5_QA_2026-09-12.md#f02) | P1 | [#9 — Preserve aggregate runtime quotas for scheduled runs](https://github.com/black-candle-technologies/lumen/issues/9) | bug |
| [F04](M5_QA_2026-09-12.md#f03) | P1 | [#10 — Persist the scheduled occurrence-to-run handoff before dispatch](https://github.com/black-candle-technologies/lumen/issues/10) | bug |
| [F05](M5_QA_2026-09-12.md#f04) | P1 | [#11 — Finalize failed scheduled occurrences and surface persistence/scheduler errors](https://github.com/black-candle-technologies/lumen/issues/11) | bug |
| [F06](M5_QA_2026-09-12.md#f06) | P2 | [#12 — Record actual audit event times with an injectable clock](https://github.com/black-candle-technologies/lumen/issues/12) | bug |
| [F07](M5_QA_2026-09-12.md#f07) | P2 | [#13 — Expire approval state correctly and preserve conflict reasons in the UI](https://github.com/black-candle-technologies/lumen/issues/13) | bug |
| [F08](M5_QA_2026-09-12.md#f08) | P2 | [#14 — Verify runtime connectivity and invalidate stale workspace UI state](https://github.com/black-candle-technologies/lumen/issues/14) | bug |
| [F09](M5_QA_2026-09-12.md#f09) | P2 | [#15 — Do not display empty success states when resource loading fails](https://github.com/black-candle-technologies/lumen/issues/15) | bug |
| [F10](M5_QA_2026-09-12.md#f10) | P2 | [#16 — Show meaningful automation approval previews and readable job state](https://github.com/black-candle-technologies/lumen/issues/16) | enhancement |
| [F11](M5_QA_2026-09-12.md#f11) | P2 | [#17 — Make rejected or missing reviewed skills visible in audit and run status](https://github.com/black-candle-technologies/lumen/issues/17) | enhancement |
| [F12](M5_QA_2026-09-12.md#f12) | P1 | [#18 — Enforce skill source size limits before allocating the full file](https://github.com/black-candle-technologies/lumen/issues/18) | bug |
| [F13](M5_QA_2026-09-12.md#f13) | P2 | [#19 — Validate meaningful workflow capture and reviewed reuse with a tool-bearing run](https://github.com/black-candle-technologies/lumen/issues/19) | documentation, enhancement |
| [F14](M5_QA_2026-09-12.md#f14) | P1 | [#20 — Bound shutdown with active runs and SSE subscriptions](https://github.com/black-candle-technologies/lumen/issues/20) | bug |
| [F15](M5_QA_2026-09-12.md#f15) | P2 | [#21 — Add a safe reproducible functional-test launcher and evidence lifecycle](https://github.com/black-candle-technologies/lumen/issues/21) | documentation, enhancement |
| [F16](M5_QA_2026-09-12.md#f16) | P2 | [#22 — Improve CLI sandbox diagnostics and authenticated readiness feedback](https://github.com/black-candle-technologies/lumen/issues/22) | documentation, enhancement |
| [F17](M5_QA_2026-09-12.md#f17) | P2 | [#23 — Document audit pagination and preserve API errors in test clients](https://github.com/black-candle-technologies/lumen/issues/23) | documentation, enhancement |
| [F18](M5_QA_2026-09-12.md#f18) | P2 | [#24 — Stabilize WSL build artifacts and diagnose repeated Cargo rebuilds](https://github.com/black-candle-technologies/lumen/issues/24) | documentation, enhancement |
| [F19](M5_QA_2026-09-12.md#f18) | P2 | [#25 — Prevent Windows/WSL native JavaScript dependency mismatches](https://github.com/black-candle-technologies/lumen/issues/25) | documentation, enhancement |
| [F20](M5_QA_2026-09-12.md#f20) | P2 | [#28 — Verify scoped GPU-required inference policy and request-level evidence](https://github.com/black-candle-technologies/lumen/issues/28) | documentation, enhancement |
| [F21](M5_QA_2026-09-12.md#f21) | P2 | [#26 — Measure WSL memory pressure and document safe resource limits and shutdown](https://github.com/black-candle-technologies/lumen/issues/26) | documentation, enhancement |
| [F22](M5_QA_2026-09-12.md#f23) | P1 | [#27 — Reconcile test inventories and finish the cross-platform verification matrix](https://github.com/black-candle-technologies/lumen/issues/27) | documentation, enhancement |

Publication note: #7 through #28 are the 22 open canonical QA issues. Issue #29 duplicated #7 and is closed as a duplicate. The authoritative mapping is the table above, not issue-number arithmetic.

## Suggested work sequence

**First: core correctness and evidence.** Complete the live tool protocol (#7); repair quota inheritance (#9), durable handoff (#10), and error finalization (#11); bound skill reads (#18); establish shutdown behavior (#20). Timestamp correctness (#12) and approval lifecycle handling (#13) are small related correctness work. Reconcile the test inventory (#27) and close the named acceptance gaps (#8) before a blanket acceptance decision.

**Second: reliable control surface.** Connection verification (#14), error-versus-empty states (#15), actionable previews (#16), and rejected-skill diagnostics (#17) should preserve the pause/resume behavior that already passed. Meaningful reviewed workflow reuse is #19.

**Third: repeatable operations.** Launcher/evidence lifecycle (#21), diagnostics (#22), pagination helpers (#23), build isolation (#24), native dependency setup (#25), WSL resource measurement (#26), and scoped GPU enforcement verification (#28) address the setup and operational friction without conflating it with proven Lumen defects.

P1 means a proposed acceptance gate or high-priority correctness/verification work, not that every P1 is a reproduced exploitable vulnerability. P2 means a scoped follow-up. Maintainers should explicitly dispose of any deferred item rather than silently marking it passed.

## Unchanged boundaries

No `base/ui` changes, no Riley checkout changes, no automatic approval bypass, no blanket Windows test skipping, no historical audit rehashing, no unapproved cloud fallback, and no host driver surgery are part of these issue requests. No issue is permission to merge a PR automatically.
