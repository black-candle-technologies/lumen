# M5 audit pagination acceptance guide

This is the current QA procedure for issue #23, not a rewrite of the September 12 record. The historical `limit=250` request was invalid; its resulting `.events[]` null-iteration error was not evidence of missing audit events.

## Endpoint contract

Use `GET /api/v1/workspaces/{workspace_id}/audit?after=0&limit=100` on the numeric loopback bind address printed by `lumen serve`. A valid local bearer token is required. A wrong token returns 401 `unauthorized`; an authenticated but unallowlisted workspace returns 403 `workspace_forbidden`. No audit events are returned before those checks.

`after` defaults to 0 and is a nonnegative, **exclusive sequence cursor**: the next page uses the last returned event's `sequence`, not a page number or an offset. Events are returned in ascending sequence order for that workspace; gaps can occur because sequence IDs are global. `limit` defaults to 100 and accepts 1–200. `limit=0`, `limit=201`, `limit=250`, or `after=-1` return HTTP 400 JSON `{"error":{"code":"bad_request","message":"invalid audit page bounds"}}`. Malformed numeric query values also return HTTP 400, but Axum's query extractor currently sends non-JSON diagnostic text rather than that route error envelope. Neither failure has an `events` array. A successful empty `{"events":[]}` page is different from an error response.

There is no `next_cursor` field: carry the last sequence yourself. A page shorter than the requested limit is exhausted at that read; a full page requires one more request, which may be empty. Do not repeatedly fetch `after=0`, pipe a status-blind response into `.events[]`, use `curl -s` alone, or replace a missing array with `[]` to manufacture success.

## Complete run lookup

The repository's stdlib-only helper reads every ordered page and matches the exact `payload.run_id`; it does not issue raw SQL or bypass workspace authorization. Set `LUMEN_BEARER_TOKEN` in the environment to a **disposable local** token before starting Lumen and the helper. The token is never a CLI argument or URL parameter. Replace the bind address, workspace UUID, and run UUID with your owned fixture values. From the repository root, in PowerShell:

```powershell
python .\scripts\qa\audit_inspect.py --base-url http://127.0.0.1:3210 --workspace-id YOUR-WORKSPACE-UUID --run-id YOUR-RUN-UUID --limit 100
$LASTEXITCODE
```

In WSL Bash:

```bash
python3 scripts/qa/audit_inspect.py --base-url http://127.0.0.1:3210 --workspace-id YOUR-WORKSPACE-UUID --run-id YOUR-RUN-UUID --limit 100
echo $?
```

Use the server's numeric loopback address; hostnames, remote origins, URL credentials, proxies, and redirects are not accepted. The helper has a five-second socket inactivity timeout, a default 1,000-page safety ceiling (`--max-pages` can be set explicitly for a larger owned history), and a 16 MiB matching-output ceiling. It prints matching event JSON only after a complete search. Its outcomes are distinct:

| Exit | Output category | Meaning |
| ---: | --- | --- |
| 0 | `matching_events` | Matching run events found, final page reached. |
| 1 | `no_matching_events` | Final page reached, no exact `payload.run_id` match. An empty audit is this case. |
| 2 | `transport_error` | No reliable HTTP response, e.g. connection refused. |
| 3 | `api_error` | HTTP non-200, with status and sanitized JSON code/message or bounded plain-text body. Includes 400, 401, 403, and redirects. |
| 4 | `invalid_response` | HTTP 200 without a valid events array, sequence advance, workspace ID, or payload shape. |
| 5 | `incomplete_pagination` | Page or matching-output ceiling reached before completion; even a previously seen match is not reported as complete. |

The web Audit screen currently labels its first-page view as such; use the helper, not that first page, for a complete run provenance claim. Record the exact command, tested commit/branch, Windows or WSL environment, expected and actual status/output, and any failed/blocked page. Automated checks are `cargo test -p lumen-server --test routes -- audit`, `python -m unittest discover -s scripts/qa -p test_audit_inspect.py -v` (use `python3` in WSL), and `corepack pnpm --dir apps/web exec vitest run src/lib/api.test.ts`. Keep manual live acceptance separate from these fixture tests.
