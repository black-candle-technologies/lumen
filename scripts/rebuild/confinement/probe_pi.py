"""Bounded stdio smoke test: real Pi -> real kernel denial -> signed audit.

Development fixture only. The kernel probe has no effect executor. Runtime
admission for production supervisors remains unavailable.
"""
import json
import errno
import os
from pathlib import Path
import selectors
import subprocess
import sys
import time

from runtime import Refused, Runtime, unique_object
from verify_audit import verify


def probe(candidate, expected_digest, kernel_probe, evidence):
    evidence.mkdir(exist_ok=False)
    (evidence / "leased").mkdir()
    target = evidence / "outside.txt"
    target.write_text("HOST_ONLY_SENTINEL")
    manifest = candidate / "manifest.json"
    events, authority = [], None
    with Runtime(candidate / "root", manifest, expected_digest) as runtime:
        process = runtime.process
        selector = selectors.DefaultSelector()
        pending, stderr = bytearray(), bytearray()
        total = 0
        deadline = time.monotonic() + 40
        def send(value):
            raw = json.dumps(value, separators=(",", ":")).encode() + b"\n"
            if len(raw) > 4096:
                raise Refused("oversized host request")
            # Each request is below PIPE_BUF; the selector bounds a stalled Pi.
            ready = selectors.DefaultSelector()
            try:
                ready.register(process.stdin, selectors.EVENT_WRITE)
                if not ready.select(max(0, min(2, deadline - time.monotonic()))):
                    raise Refused("Pi stdin stalled")
                if os.write(process.stdin.fileno(), raw) != len(raw):
                    raise Refused("partial Pi stdin write")
            finally:
                ready.close()
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(process.stdin.fileno(), False)
        send({"id": "state", "type": "get_state"})
        try:
            done = False
            while not done:
                if time.monotonic() >= deadline:
                    raise TimeoutError("real Pi mediation probe timed out")
                for key, _ in selector.select(0.25):
                    chunk = os.read(key.fd, 8192)
                    if not chunk:
                        raise Refused("Pi exited before mediation completed: " + stderr.decode(errors="replace")[:2000])
                    total += len(chunk)
                    if total > 256 * 1024:
                        raise Refused("Pi stream limit exceeded")
                    if key.data == "stderr":
                        stderr.extend(chunk)
                        continue
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, tail = pending.partition(b"\n")
                        pending[:] = tail
                        if len(line) > 65536 or len(events) >= 256:
                            raise Refused("Pi frame limit exceeded")
                        event = json.loads(line, object_pairs_hook=unique_object)
                        events.append(event)
                        if event.get("type") == "response" and event.get("id") == "state":
                            if event.get("success") is not True or event["data"]["model"]["provider"] != "lumen-fixture":
                                raise Refused("pinned probe provider unavailable")
                            send({"id": "retry", "type": "set_auto_retry", "enabled": False})
                            send({"id": "compact", "type": "set_auto_compaction", "enabled": False})
                            send({"id": "prompt", "type": "prompt", "message": json.dumps({"path": str(target)})})
                        elif event.get("type") == "extension_ui_request":
                            if (set(event) != {"type", "id", "method", "title", "placeholder", "timeout"}
                                    or event["method"] != "input" or event["title"] != "lumen.pi-bridge/2"
                                    or not isinstance(event["id"], str) or len(event["id"]) > 128
                                    or type(event["timeout"]) is not int or event["timeout"] != 60000
                                    or not isinstance(event["placeholder"], str) or authority is not None):
                                raise Refused("unknown or repeated bridge dialog")
                            request = event["placeholder"].encode()
                            if len(request) > 16384:
                                raise Refused("oversized bridge intent")
                            result = subprocess.run([str(kernel_probe), str(evidence / "audit.sqlite3"),
                                                     str(evidence / "leased")], input=request,
                                                    capture_output=True, timeout=15, check=False,
                                                    env={"PATH": "/usr/bin:/bin"}, close_fds=True)
                            if result.returncode != 0 or len(result.stdout) > 65536 or result.stderr:
                                raise Refused("kernel probe failed: " + result.stderr[:2048].decode(errors="replace"))
                            authority = json.loads(result.stdout, object_pairs_hook=unique_object)
                            head = authority["checkpoints"][-1]
                            public_key = next(key for key in authority["host_public_keys"] if key["key_id"] == head["key_id"])
                            anchor = {**public_key, "through_seq": head["through_seq"], "chain_hash": head["chain_hash"]}
                            verify(authority, anchor)
                            (evidence / "audit-anchor.json").write_text(json.dumps(anchor, indent=2) + "\n")
                            reply = authority["reply"]
                            if reply["outcome"]["status"] != "denied":
                                raise Refused("kernel did not deny the real tool request")
                            send({"type": "extension_ui_response", "id": event["id"], "value": json.dumps(reply)})
                        elif event.get("type") == "agent_end":
                            done = True
                    if len(pending) > 65536:
                        raise Refused("unterminated Pi frame")
            if authority is None:
                raise Refused("real Pi did not request the mediated tool")
            attempts = [e for e in events if e.get("type") == "lumen_phase0_bypass_probe"]
            cases = {"socket_inet", "socket_inet6", "socket_unix", "fork", "clone_process",
                     "execve", "execveat", "unshare", "ptrace", "io_uring", "bpf", "ioctl_inject"}
            if (len(attempts) != 1 or attempts[0]["activeTools"] != ["bct.read_file"]
                    or attempts[0]["filesystemDenied"] is not True or attempts[0]["shellDenied"] is not True
                    or attempts[0]["syscalls"] != {name: errno.EPERM for name in cases}
                    or attempts[0]["environment"] != sorted(["HOME", "PATH", "LANG", "PWD", "TMPDIR",
                                                             "PI_CODING_AGENT_DIR", "UV_USE_IO_URING",
                                                             "AI_AGENT", "PI_CODING_AGENT"])):
                raise Refused("real Pi bypass observations do not match the confined profile")
            errors = [e for e in events if e.get("type") == "tool_execution_end"]
            if len(errors) != 1 or errors[0].get("isError") is not True:
                raise Refused("Pi did not render exactly one terminal tool denial")
            if target.read_text() != "HOST_ONLY_SENTINEL":
                raise Refused("host sentinel changed")
            (evidence / "rpc-events.json").write_text(json.dumps(events, indent=2) + "\n")
            (evidence / "kernel-evidence.json").write_text(json.dumps(authority, indent=2) + "\n")
            (evidence / "pi-stderr.txt").write_bytes(stderr)
        finally:
            # Failed runs retain bounded, fixture-only observations too.
            (evidence / "rpc-events.json").write_text(json.dumps(events, indent=2) + "\n")
            (evidence / "pi-stderr.txt").write_bytes(stderr)
            selector.close()
    print(json.dumps({"real_pi": True, "kernel_denied": True, "session_destroyed": True,
                      "audit_verified": True, "runtime_manifest": expected_digest,
                      "events": len(events), "evidence": str(evidence)}))


if __name__ == "__main__":
    probe(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve(), Path(sys.argv[4]).resolve())
