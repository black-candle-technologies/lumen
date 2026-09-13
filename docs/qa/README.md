# Lumen QA Records

This directory preserves durable QA history tied to source revisions: acceptance evidence, regression findings, test methodology, known limitations, and mappings from findings to GitHub issues.

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
