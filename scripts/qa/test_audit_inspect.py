"""Owned, dependency-free checks for the M5 audit QA inspector."""

import io
import json
import os
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import audit_inspect


WORKSPACE = "26db5a31-94f0-4e92-a9c9-4cdf19d71c31"
RUN = "f46038e8-4740-41de-af78-b965a732b1c3"
TOKEN = "disposable-audit-test-token"
ARGS = [
    "--base-url", "http://127.0.0.1:3210",
    "--workspace-id", WORKSPACE,
    "--run-id", RUN,
]


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self.body = io.BytesIO(body)

    def read(self, size):
        return self.body.read(size)


class FakeConnection:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests = []

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return FakeResponse(*outcome)

    def close(self):
        pass


def events(start, count, matching_sequence=None):
    return [
        {
            "sequence": sequence,
            "workspace_id": WORKSPACE,
            "payload": {"run_id": RUN if sequence == matching_sequence else "other-run"},
        }
        for sequence in range(start, start + count)
    ]


def page(entries):
    return 200, json.dumps({"events": entries}).encode()


class AuditInspectTests(unittest.TestCase):
    def run_inspector(self, outcomes, args=ARGS, token=TOKEN):
        connection = FakeConnection(outcomes)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {"LUMEN_BEARER_TOKEN": token}), \
             patch("http.client.HTTPConnection", return_value=connection), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = audit_inspect.main(args)
        self.assertNotIn(token, stdout.getvalue() + stderr.getvalue())
        return code, stdout.getvalue(), stderr.getvalue(), connection

    def test_run_after_first_200_is_found_only_after_complete_sequence_search(self):
        code, stdout, stderr, connection = self.run_inspector(
            [page(events(1, 200)), page(events(201, 50, matching_sequence=225))],
            ARGS + ["--limit", "200"],
        )
        self.assertEqual(code, 0, stderr)
        self.assertIn("matching_events", stdout)
        self.assertIn("225", stdout)
        self.assertEqual(
            [parse_qs(urlsplit(path).query)["after"][0] for _, path, _ in connection.requests],
            ["0", "200"],
        )
        self.assertTrue(all(method == "GET" for method, _, _ in connection.requests))
        self.assertTrue(all(headers["Authorization"] == f"Bearer {TOKEN}"
                            for _, _, headers in connection.requests))

    def test_empty_success_is_no_match_not_failure(self):
        code, stdout, stderr, _ = self.run_inspector([page([])])
        self.assertEqual(code, 1, stderr)
        self.assertIn("no_matching_events", stdout)
        self.assertNotIn("api_error", stdout)

    def test_matching_payload_redacts_json_escaped_token_before_serializing(self):
        for token in [r"escaped\fixture-token", 'quoted"fixture-token']:
            with self.subTest(token=token):
                event = events(1, 1, matching_sequence=1)[0]
                event["payload"]["secret"] = token
                event["payload"][f"key-{token}"] = "fixture"
                code, stdout, stderr, _ = self.run_inspector([page([event])], token=token)
                self.assertEqual(code, 0, stderr)
                result = json.loads(stdout)["events"][0]["payload"]
                self.assertEqual(result["secret"], "[redacted]")
                self.assertIn("key-[redacted]", result)

    def test_matching_output_budget_is_not_reported_as_complete(self):
        event = events(1, 1, matching_sequence=1)[0]
        with patch.object(audit_inspect, "MATCH_BYTES", 1):
            code, stdout, stderr, _ = self.run_inspector([page([event])])
        self.assertEqual(code, 5, stdout)
        self.assertIn("incomplete_pagination", stderr)
        self.assertNotIn("matching_events", stdout)

        second = events(2, 1, matching_sequence=2)[0]
        one_match_size = len(json.dumps(event, ensure_ascii=False).encode()) + 1
        with patch.object(audit_inspect, "MATCH_BYTES", one_match_size):
            code, stdout, stderr, connection = self.run_inspector(
                [page([event]), page([second])], ARGS + ["--limit", "1"]
            )
        self.assertEqual(code, 5, stdout)
        self.assertIn("output_limit", stderr)
        self.assertEqual(len(connection.requests), 2)

    def test_json_api_errors_keep_status_and_code(self):
        for status, expected_code in [
            (400, "bad_request"),
            (401, "unauthorized"),
            (403, "workspace_forbidden"),
        ]:
            with self.subTest(status=status):
                body = json.dumps({"error": {"code": expected_code, "message": "audit denied"}}).encode()
                code, stdout, stderr, _ = self.run_inspector([(status, body)])
                self.assertEqual(code, 3, stdout)
                self.assertIn(f"status={status}", stderr)
                self.assertIn(expected_code, stderr)
                self.assertNotIn("no_matching_events", stdout)

    def test_plain_api_error_keeps_bounded_diagnostic(self):
        code, _, stderr, _ = self.run_inspector([(400, b"invalid digit found in string")])
        self.assertEqual(code, 3)
        self.assertIn("api_error", stderr)
        self.assertIn("invalid digit", stderr)

        code, _, stderr, _ = self.run_inspector([(502, b'{"message":"backend unavailable"}')])
        self.assertEqual(code, 3)
        self.assertIn("backend unavailable", stderr)

    def test_transport_failure_is_not_an_empty_success(self):
        code, stdout, stderr, _ = self.run_inspector([ConnectionRefusedError("Connection refused")])
        self.assertEqual(code, 2, stdout)
        self.assertIn("transport_error", stderr)
        self.assertIn("Connection refused", stderr)
        self.assertNotIn("no_matching_events", stdout)

    def test_malformed_success_and_sequence_regression_are_not_matches(self):
        for outcome in [
            (200, b'{"error":{"code":"bad_request"}}'),
            page(events(1, 1) + events(1, 1)),
            page([{"sequence": 1, "workspace_id": "wrong-workspace", "payload": {"run_id": RUN}}]),
        ]:
            with self.subTest(outcome=outcome):
                code, stdout, stderr, _ = self.run_inspector([outcome])
                self.assertEqual(code, 4, stdout)
                self.assertIn("invalid_response", stderr)
                self.assertNotIn("matching_events", stdout)

    def test_page_cap_never_claims_success_even_if_a_match_was_seen(self):
        code, stdout, stderr, connection = self.run_inspector(
            [page(events(1, 200, matching_sequence=50))],
            ARGS + ["--limit", "200", "--max-pages", "1"],
        )
        self.assertEqual(code, 5, stdout)
        self.assertIn("incomplete_pagination", stderr)
        self.assertNotIn("matching_events", stdout)
        self.assertEqual(len(connection.requests), 1)

    def test_mid_search_api_or_transport_failure_never_claims_a_seen_match(self):
        first = page(events(1, 200, matching_sequence=50))
        for second, expected_exit in [
            ((403, b'{"error":{"code":"workspace_forbidden"}}'), 3),
            (ConnectionRefusedError("Connection refused"), 2),
        ]:
            with self.subTest(second=second):
                code, stdout, stderr, connection = self.run_inspector(
                    [first, second], ARGS + ["--limit", "200"]
                )
                self.assertEqual(code, expected_exit, stdout)
                self.assertNotIn("matching_events", stdout)
                self.assertEqual(len(connection.requests), 2)
                self.assertTrue("api_error" in stderr or "transport_error" in stderr)

    def test_malformed_origin_and_control_token_fail_before_connecting(self):
        for base, token in [
            ("http://[::1", TOKEN),
            ("http://127.0.0.1:0", TOKEN),
            ("http://127.0.0.1:", TOKEN),
            ("http://127.0.0.1:3210", "unsafe\tfixture-token"),
        ]:
            with self.subTest(base=base, token=token), \
                 patch.dict(os.environ, {"LUMEN_BEARER_TOKEN": token}), \
                 patch("http.client.HTTPConnection") as opener, \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    audit_inspect.main(["--base-url", base] + ARGS[2:])
                opener.assert_not_called()

    def test_redirect_and_remote_origin_do_not_forward_the_token(self):
        code, _, stderr, connection = self.run_inspector([(302, b"redirect blocked")])
        self.assertEqual(code, 3)
        self.assertIn("status=302", stderr)
        self.assertEqual(len(connection.requests), 1)
        for base in ["http://example.com", "http://localhost:3210"]:
            with self.subTest(base=base), \
                 patch.dict(os.environ, {"LUMEN_BEARER_TOKEN": TOKEN}), \
                 patch("http.client.HTTPConnection") as opener, \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    audit_inspect.main(["--base-url", base] + ARGS[2:])
                opener.assert_not_called()

    def test_invalid_limits_are_rejected_before_any_connection(self):
        for limit in ["0", "201", "not-a-number"]:
            with self.subTest(limit=limit), \
                 patch.dict(os.environ, {"LUMEN_BEARER_TOKEN": TOKEN}), \
                 patch("http.client.HTTPConnection") as opener, \
                 redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    audit_inspect.main(ARGS + ["--limit", limit])
                opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
