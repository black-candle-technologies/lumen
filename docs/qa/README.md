# Lumen QA Records

This directory preserves durable QA history tied to source revisions: acceptance evidence, regression findings, test methodology, known limitations, and mappings from findings to GitHub issues.

The current M5 operator commands and status meanings are in [M5 local readiness acceptance guide](M5_ACCEPTANCE_GUIDE.md).
The current audit cursor and full-run QA procedure is in [M5 audit pagination acceptance guide](M5_AUDIT_ACCEPTANCE_GUIDE.md).
The current Windows/WSL build-cache procedure and measurements are in [M5 Cargo cache guide](M5_CARGO_CACHE_GUIDE.md).
The current Windows/WSL pnpm dependency procedure is in [M5 JavaScript dependencies guide](M5_JS_DEPENDENCIES_GUIDE.md).
The scoped Ollama GPU residency policy and issue #28 evidence are in [M5 GPU policy guide](M5_GPU_POLICY_GUIDE.md).
The measured WSL memory triage and shutdown procedure for issue #26 are in [M5 WSL memory guide](M5_WSL_MEMORY_GUIDE.md).
The reproducible disposable fixture and evidence lifecycle for issue #21 are in [M5 QA launcher guide](M5_QA_LAUNCHER_GUIDE.md).
The named Windows/WSL/web inventories, first failures, and native desktop CI status for issue #27 are in [M5 platform matrix](M5_PLATFORM_MATRIX_2026-09-17.md).

## Repository policy

Commit:

- Markdown QA reports, acceptance matrices, and issue crosswalks
- Exact tested commit and branch metadata
- Sanitized reproduction instructions and known limitations

Do not normally commit raw databases, large ZIP archives, giant logs, browser traces or videos, model binaries, build artifacts, or sensitive credentials.

Raw evidence may live in CI artifacts, releases, or dedicated evidence storage. Reports should record its filename and SHA-256 when available. Automated tests and manual or live acceptance are separate evidence classes and must be reported separately.

## Naming

- `M<milestone>_QA_<YYYY-MM-DD>.md`
- `M<milestone>_QA_ISSUE_INDEX_<YYYY-MM-DD>.md`

Historical QA records must not be silently rewritten to claim later tests passed. Create a new report or append a clearly dated follow-up when disposition changes.

Never commit API keys, bearer tokens, passwords, private keys, customer data, production secrets, or machine-specific personal paths that add no QA value.
