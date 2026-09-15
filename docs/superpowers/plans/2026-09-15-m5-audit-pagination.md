# M5 Audit Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make M5 audit QA inspection report real HTTP failures and search a run through every ordered page without changing the legitimate server page cap.

**Architecture:** Characterize the existing authenticated audit route instead of adding a duplicate run-filter endpoint. A stdlib Python CLI uses direct loopback HTTP (no proxy or redirect), reads sequence pages, checks status and JSON shape before inspecting events, and terminates only on an exhausted page; the web API rejects malformed successful audit bodies instead of treating them as an empty list. A current guide replaces invalid examples while the September 12 report remains unchanged.

**Tech Stack:** Rust/Axum route tests; Python 3 standard library (`argparse`, `http.client`, `ipaddress`, `json`, `unittest`); Svelte/TypeScript/Vitest; Markdown.

**Spec:** [Canonical QA issue #23](https://github.com/black-candle-technologies/lumen/issues/23), with historical evidence in [F17](../../qa/M5_QA_2026-09-12.md#f17).

## Global Constraints

- Work only in `C:\Users\laneb\lumen-m5-windows` on `qa-m5-23-audit-pagination`, based on pushed `qa-m5-22-cli-readiness`; do not edit `base/ui` or Riley's checkout.
- Preserve audit authorization, workspace scoping, integrity, and `limit` 1–200; `after` is a nonnegative exclusive sequence cursor, not an offset.
- Do not rewrite historical QA observations or claim the invalid `limit=250` query proved lost audit events.
- Use one normal open stacked PR against #22, do not merge/auto-merge, keep issue #23 open, and disclose unrun/blocked checks.
- Original user instruction is to continue without per-issue approval waits; execute this plan inline, with red/green checks before implementation and a review gate before pushing.

---

### Task 1: Characterize audit HTTP bounds and errors

**Files:** Modify `crates/lumen-server/tests/routes.rs` near `audit_listing_is_workspace_scoped_and_bounded`. No production route change is planned unless a regression test proves a contract mismatch.

**Interfaces:** Consumes `GET /api/v1/workspaces/{workspace_id}/audit?after={i64}&limit={u16}`. Produces a test-backed contract for Task 3: defaults `after=0, limit=100`; valid `limit=1,200`; invalid `0,201,after=-1` return JSON `bad_request`; malformed numeric values return HTTP 400 without an `events` array; wrong token returns 401 and other workspace 403 before service dispatch.

- [x] **Step 1: Add route characterization tests.** Use the existing `test_app`, `request`, `json_body`, and `audit_queries` fixture. Request the default path and valid `limit=1,200`, assert recorded `AuditQuery` values. Request `limit=0`, `limit=201`, and `after=-1`, assert HTTP 400 plus `body["error"]["code"] == "bad_request"`. Request `limit=oops` and `after=oops`, assert HTTP 400 and no successful `events` envelope. Request a bad bearer token and a different workspace, assert 401/403 and that `audit_queries.len()` did not increase. The core invalid-bound assertion is:

```rust
let response = app.clone().oneshot(request(
    "GET", format!("/api/v1/workspaces/{workspace_id}/audit?limit=201"), Body::empty()
)).await.expect("invalid bound response");
assert_eq!(response.status(), StatusCode::BAD_REQUEST);
assert_eq!(json_body(response).await["error"]["code"], "bad_request");
```

- [x] **Step 2: Run the route suite and read exact status/body output.** Run `cargo test -p lumen-server --test routes -- audit`. If a malformed-query response is plain text from Axum extraction, document that precise result; do not fabricate a JSON error envelope or weaken the cap.

- [x] **Step 3: Keep the route unchanged if tests confirm the contract.** A test-only characterization is the smallest source change for a valid 1–200 server bound. Run `cargo test -p lumen-server --test routes` after the test edits.

### Task 2: Add a status-safe complete run inspector

**Files:** Create `scripts/qa/audit_inspect.py` and `scripts/qa/test_audit_inspect.py`; modify `.gitignore` to exclude generated Python bytecode.

**Interfaces:** CLI arguments are `--base-url` (numeric HTTP loopback origin only, no credentials/path/query/fragment), `--workspace-id`, `--run-id`, `--limit` (default 100, validate 1–200), and `--max-pages` (default 1000, validate positive). Bearer token comes only from `LUMEN_BEARER_TOKEN`. Each GET uses `after=<last sequence>`, validates `events` as an array of strictly increasing integer sequences and matching workspace IDs, and matches only `payload.run_id == --run-id`. Exit 0 means matching events after complete pagination; 1 means complete search/no match; 2 transport failure; 3 HTTP/API failure; 4 malformed success body or nonincreasing sequence; 5 early page cap. Never print the token or report success on an incomplete search.

- [x] **Step 1: Write stdlib unit tests before the CLI.** Patch `http.client.HTTPConnection` with an owned sequential fake connection/response and assert each request cursor. Return 200 events for sequences 1–200, then 201–250 with the run ID at 225; assert the requests use `after=0`, `after=200`, and exit 0 only after that final short page. Add empty 200 success, 400 JSON `bad_request`, 401/403, a `ConnectionRefusedError`, a 200 body missing `events`, a nonincreasing sequence, `--max-pages=1`, and non-loopback/redirect cases. Assert no token appears in captured diagnostics. Use this fake-response shape:

```python
from unittest.mock import Mock, patch
fake_connection = Mock()
fake_connection.getresponse.return_value.status = 200
fake_connection.getresponse.return_value.read.return_value = b'{"events":[]}'
valid_args = ["--base-url", "http://127.0.0.1:3210",
              "--workspace-id", "26db5a31-94f0-4e92-a9c9-4cdf19d71c31",
              "--run-id", "f46038e8-4740-41de-af78-b965a732b1c3"]
with patch("http.client.HTTPConnection", return_value=fake_connection):
    self.assertEqual(audit_inspect.main(valid_args), 1)
```

- [x] **Step 2: Run tests red.** Run `python -m unittest discover -s scripts/qa -p test_audit_inspect.py -v` on Windows (or `python3` in WSL). Expected red result is a missing `audit_inspect` module or missing inspector entry point, not a passing mock.

- [x] **Step 3: Implement the minimal CLI.** Parse and validate `--base-url` as an HTTP loopback origin, construct only `/api/v1/workspaces/{uuid}/audit?after=<last>&limit=<valid>` with `urllib.parse.urlencode`, and send `Authorization: Bearer <env token>` through `http.client.HTTPConnection(host, port, timeout=5)`. Read at most 32 MiB + 1 for success or 4 KiB for errors; treat every non-200 status (including 3xx) as `api_error` without redirect-following. On success validate body shape and sequence progress before inspecting `payload.run_id`. Continue when a page has exactly `limit` entries, so a next empty page proves completion; any max-page or 16 MiB matching-output cutoff is `incomplete_pagination` rather than success. Redact matching events before serialization and emit a short category/status/sequence/pages summary. The cursor loop below is schematic; implemented code also validates each response and enforces the output ceiling:

```python
import json
import sys
def inspect_pages(args, token):
    after = 0
    matches = []
    for page in range(1, args.max_pages + 1):
        events = read_page(args, after, token)
        for event in events:
            if event["sequence"] <= after:
                raise InvalidResponse("audit sequence did not advance")
            after = event["sequence"]
            if event["payload"].get("run_id") == args.run_id:
                matches.append(event)
        if len(events) < args.limit:
            category = "matching_events" if matches else "no_matching_events"
            print(json.dumps({"category": category, "pages": page,
                              "last_sequence": after, "events": matches}))
            return 0 if matches else 1
    print(f"incomplete_pagination pages={args.max_pages} after={after}", file=sys.stderr)
    return 5
```

- [x] **Step 4: Run tests green.** Run `python -m unittest discover -s scripts/qa -p test_audit_inspect.py -v` and verify each status/transport/no-match/incomplete assertion. Tests patch the direct stdlib connection and do not call a user or production audit endpoint with a fixture token.

### Task 3: Document current usage and reject malformed web audit shapes

**Files:** Create `docs/qa/M5_AUDIT_ACCEPTANCE_GUIDE.md`; modify `docs/qa/README.md`, `apps/web/src/lib/api.ts`, `apps/web/src/lib/api.test.ts`, and `apps/web/src/routes/audit/+page.svelte` (label the first page honestly).

**Interfaces:** `ApiClient.listAudit(after=0,limit=100)` still returns `Promise<AuditEvent[]>`, but a successful body without an `events` array throws `ApiError(0, 'invalid_response', 'Audit response is missing an events array')`. Existing non-2xx `ApiError.status/code/message` remains unchanged. The guide uses the Python helper for a full run lookup and gives PowerShell `python` and WSL `python3` commands with valid limits; it names default/exclusive cursor/ascending order/401/403/400/plain malformed-query fallback and category-specific exit codes.

- [x] **Step 1: Write web tests red.** Mock a 200 `{"error":{"code":"bad_request"}}` body and assert `listAudit()` rejects with `code: 'invalid_response'`; mock a 400 JSON error and assert `status: 400, code: 'bad_request'` rather than a null-array result. Run `corepack pnpm --dir apps/web exec vitest run src/lib/api.test.ts`; the malformed 200 assertion must fail against the current unchecked cast. The assertion shape is:

```typescript
await expect(client.listAudit()).rejects.toMatchObject({ code: 'invalid_response' });
```

- [x] **Step 2: Add the smallest shape guard.** Read `this.request<unknown>(...)`; after the successful request, check the following condition and return the array as `AuditEvent[]`. Do not change shared non-2xx parsing or add speculative web run-search UI.

```typescript
if (!response || typeof response !== 'object' || !('events' in response) || !Array.isArray(response.events)) {
    throw new ApiError(0, 'invalid_response', 'Audit response is missing an events array');
}
return response.events as AuditEvent[];
```

- [x] **Step 3: Add the current guide and link it.** Explain `limit=0,201` is a real API error and `limit=250` was an invalid historic test command. Include exact helper commands with `limit=100` and `--run-id`, and make empty search, transport failure, API failure, and incomplete pagination visibly different. Leave `docs/qa/M5_QA_2026-09-12.md` untouched.

- [x] **Step 4: Verify and review.** Run `cargo fmt --all -- --check`, `cargo test --workspace -q`, strict workspace clippy, `corepack pnpm --dir apps/web check`, targeted Vitest, Python unittest on Windows/WSL, and affected WSL route tests. Run `git diff --check`; independently review the diff and disclose the known WSL bubblewrap process-limit/CI-billing gates if they recur.

- [ ] **Step 5: Commit, push, and open the stacked PR.** Stage only #23 files, commit with a conventional message, push `qa-m5-23-audit-pagination` normally, create a non-draft open PR whose base is `qa-m5-22-cli-readiness`, comment on issue #23 with exact commit/commands/status, and leave the issue open.

## Self-review

The three tasks cover bounds/auth/error contract, full ordered run search and incomplete detection, malformed success shape, current valid examples, and exact QA evidence. No server cap increase or raw-SQL client filter is planned; the existing run ID field in each event payload is sufficient for the helper. No user/production endpoint or historical QA report is mutated.
