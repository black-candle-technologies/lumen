"""Independent audit mutations and whole-probe stdio protocol regressions.

The protocol fixtures use pipes and signed reports, not a native Pi execution.
"""
from contextlib import ExitStack, redirect_stdout
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from verify_audit import canonical, verify
from probe_pi import probe
from runtime import Refused


class AuditVerifierTests(unittest.TestCase):
    def setUp(self):
        key = Ed25519PrivateKey.generate()
        event = {"version": 1, "event_id": "b1a1c9c8-1256-497e-9f9a-e86489095c87",
                 "sequence": 0, "timestamp_ms": 1, "actor": {"actor": "kernel"},
                 "kind": "policy_denied", "session_id": "fixture", "action_digest": "a" * 64,
                 "decision": "deny", "detail": "{}", "prev_hash": "0" * 64, "hash": ""}
        event["hash"] = hashlib.sha256(canonical(event) + event["prev_hash"].encode()).hexdigest()
        checkpoint = {"key_id": "fixture-host", "through_seq": 0, "chain_hash": event["hash"]}
        self.anchor = {**checkpoint, "verifying_key_hex": key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()}
        checkpoint["signature"] = key.sign(canonical(checkpoint)).hex()
        self.report = {"events": [event], "checkpoints": [checkpoint],
                       "reply": {"action_digest": "a" * 64, "outcome": {"status": "denied"}}}

    def test_positive_chain(self):
        verify(self.report, self.anchor)

    def test_mutations_fail_closed(self):
        def change_event(r):
            r["events"][0]["detail"] = '{"changed":true}'
        def change_signature(r):
            r["checkpoints"][0]["signature"] = "00" * 64
        def change_digest(r):
            r["reply"]["action_digest"] = "b" * 64
        def change_key(r):
            r["checkpoints"][0]["key_id"] = "other-host"
        def truncate(r):
            r["events"] = []
            r["checkpoints"] = []
        def remove_checkpoint(r):
            r["checkpoints"] = []
        def unknown_version(r):
            r["events"][0]["version"] = 2
        for mutate in (change_event, change_signature, change_digest, change_key, truncate,
                       remove_checkpoint, unknown_version):
            with self.subTest(mutation=mutate.__name__):
                report = copy.deepcopy(self.report)
                mutate(report)
                with self.assertRaises(Exception):
                    verify(report, self.anchor)

    def probe_report(self):
        report = copy.deepcopy(self.report)
        report["host_public_keys"] = [{name: self.anchor[name]
                                       for name in ("key_id", "verifying_key_hex")}]
        report["reply"].update(version=2, tool_call_id="captured-read-42")
        report["reply"]["outcome"]["reason"] = (
            "scope_exceeded: one-shot lease is not bound to the presented action")
        return report

    def terminal_denial(self):
        return {"type": "tool_execution_end", "toolCallId": "captured-read-42",
                "toolName": "bct.read_file", "isError": True,
                "result": {"content": [{"type": "text", "text":
                    "Lumen denied: scope_exceeded: one-shot lease is not bound to the presented action"}],
                    "details": {}}}

    def run_probe(self, report, terminals=None, refusal=None):
        """Drive the complete probe, including its real selector and send path."""
        with tempfile.TemporaryDirectory() as area, ExitStack() as stack:
            evidence = Path(area) / "evidence"
            def pipe():
                reader, writer = os.pipe()
                return (stack.enter_context(os.fdopen(reader, "rb", buffering=0)),
                        stack.enter_context(os.fdopen(writer, "wb", buffering=0)))
            stdin_reader, stdin = pipe()
            stdout, stdout_writer = pipe()
            stderr, _stderr_writer = pipe()
            process = SimpleNamespace(stdin=stdin, stdout=stdout, stderr=stderr)
            intent = {"version": 2, "tool_call_id": "captured-read-42", "tool": "bct.read_file",
                      "arguments": {"path": str(evidence / "outside.txt"), "max_bytes": 65536}}
            cases = ("socket_inet", "socket_inet6", "socket_unix", "fork", "clone_process",
                     "execve", "execveat", "unshare", "ptrace", "io_uring", "bpf", "ioctl_inject")
            events = [
                {"type": "response", "id": "state", "success": True,
                 "data": {"model": {"provider": "lumen-fixture"}}},
                {"type": "lumen_phase0_bypass_probe", "activeTools": ["bct.read_file"],
                 "filesystemDenied": True, "shellDenied": True,
                 "syscalls": {name: errno.EPERM for name in cases},
                 "environment": sorted(["HOME", "PATH", "LANG", "PWD", "TMPDIR",
                                        "PI_CODING_AGENT_DIR", "UV_USE_IO_URING", "AI_AGENT", "PI_CODING_AGENT"])},
                {"type": "extension_ui_request", "id": "dialog-1", "method": "input",
                 "title": "lumen.pi-bridge/2", "placeholder": json.dumps(intent), "timeout": 60000},
                *(terminals if terminals is not None else [self.terminal_denial()]),
                {"type": "agent_end"},
            ]
            frames = b"".join(json.dumps(event).encode() + b"\n" for event in events)
            self.assertEqual(os.write(stdout_writer.fileno(), frames), len(frames))
            output = io.StringIO()
            with patch("probe_pi.Runtime") as runtime, patch("probe_pi.subprocess.run") as kernel, \
                    patch("probe_pi.verify", wraps=verify) as audit, redirect_stdout(output):
                runtime.return_value.__enter__.return_value = SimpleNamespace(process=process)
                kernel.return_value = subprocess.CompletedProcess([], 0, json.dumps(report).encode(), b"")
                if refusal is None:
                    probe(Path(area) / "candidate", "manifest-digest", Path(area) / "kernel", evidence)
                    self.assertTrue(json.loads(output.getvalue())["kernel_denied"])
                    self.assertEqual(json.loads((evidence / "kernel-evidence.json").read_text()), report)
                else:
                    with self.assertRaisesRegex(Refused, refusal):
                        probe(Path(area) / "candidate", "manifest-digest", Path(area) / "kernel", evidence)
                    self.assertEqual(output.getvalue(), "")
                    self.assertFalse((evidence / "kernel-evidence.json").exists())
                audit.assert_called_once()
                kernel.assert_called_once()
                self.assertEqual(json.loads(kernel.call_args.kwargs["input"]), intent)
            self.assertTrue((evidence / "rpc-events.json").exists())
            self.assertTrue((evidence / "pi-stderr.txt").exists())
            self.assertEqual((evidence / "outside.txt").read_text(), "HOST_ONLY_SENTINEL")
            stdin.close()
            return [json.loads(line) for line in stdin_reader.read().splitlines()]

    def test_probe_consumes_matching_signed_denial(self):
        report = self.probe_report()
        sent = self.run_probe(report)
        responses = [frame for frame in sent if frame["type"] == "extension_ui_response"]
        self.assertEqual(responses, [{"type": "extension_ui_response", "id": "dialog-1",
                                      "value": json.dumps(report["reply"])}])

    def test_probe_mutated_reply_version_fails_before_forwarding(self):
        for version in (999, 2.0):
            with self.subTest(version=version):
                report = self.probe_report()
                report["reply"]["version"] = version
                verify(report, self.anchor)  # The signed chain remains intact.
                sent = self.run_probe(report, refusal="host reply version or tool call correlation mismatch")
                self.assertFalse(any(frame["type"] == "extension_ui_response" for frame in sent))

    def test_probe_mutated_reply_correlation_fails_before_forwarding(self):
        report = self.probe_report()
        report["reply"]["tool_call_id"] = "substituted-call"
        verify(report, self.anchor)  # Correlation is a separate probe obligation.
        sent = self.run_probe(report, refusal="host reply version or tool call correlation mismatch")
        self.assertFalse(any(frame["type"] == "extension_ui_response" for frame in sent))

    def test_probe_requires_matching_terminal_denial(self):
        terminal = self.terminal_denial()
        for changed in (
                {"toolCallId": "substituted-call"}, {"toolCallId": None},
                {"toolName": "other-tool"}, {"isError": False}, {"result": {}},
                *({"result": {"content": [{"type": "text", "text": text}], "details": {}}}
                  for text in ("Host response version, correlation, or digest mismatch",
                               "Host bridge unavailable, cancelled, or timed out",
                               "Lumen denied: different reason"))):
            with self.subTest(changed=changed):
                self.run_probe(self.probe_report(), [dict(terminal, **changed)],
                               refusal="matching terminal kernel denial")
        for terminals in ([], [terminal, terminal]):
            with self.subTest(terminal_count=len(terminals)):
                self.run_probe(self.probe_report(), terminals, refusal="matching terminal kernel denial")

    def test_probe_requires_expected_host_denial(self):
        report = self.probe_report()
        report["reply"]["outcome"]["reason"] = "different reason"
        verify(report, self.anchor)
        sent = self.run_probe(report, refusal="kernel did not return the expected tool denial")
        self.assertFalse(any(frame["type"] == "extension_ui_response" for frame in sent))

    def test_probe_still_rejects_tampered_audit(self):
        report = self.probe_report()
        report["events"][0]["detail"] = '{"changed":true}'
        sent = self.run_probe(report, refusal="audit hash mismatch")
        self.assertFalse(any(frame["type"] == "extension_ui_response" for frame in sent))


if __name__ == "__main__":
    unittest.main(verbosity=2)
