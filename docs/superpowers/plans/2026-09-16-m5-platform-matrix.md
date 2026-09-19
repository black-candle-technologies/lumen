# M5 platform matrix plan

Issue: #27. Parent: `qa-m5-21-qa-launcher` / PR #50. This is verification infrastructure and evidence, not a runtime policy change.

1. Reconcile historical claims against the source revisions and retained reports. Do not infer named pass/fail outcomes from totals when raw inventories are absent; keep the unrecorded two-second failure visible.
2. Add separate Windows, Linux CLI/server, Linux desktop-native and web CI jobs. Record commit, target/toolchain, exact command, named list, raw result and exit status, and upload logs even on failure. Keep Linux sandbox coverage explicit; desktop dependencies must be installed only in CI, not on the user’s WSL host.
3. Run the supported local Windows/WSL/web suites on the current branch, preserve raw logs and named inventories, identify cfg-gated differences, and stress the identifiable two-second tests without extending deadlines. Mark anything unavailable as BLOCKED or NOT RUN.
4. Publish a matrix distinguishing historical agent reports, independently observed local/CI runs and live/manual acceptance. Cite exact source revisions and artifact paths; rerun changed behavior after any repair.
5. Review the scoped diff, verify workflow syntax and test results, commit/push `qa-m5-27-platform-matrix`, open a normal PR on `qa-m5-21-qa-launcher`, comment #27, then continue to #8.
