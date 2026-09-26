"""Test-only real host process, deliberately killed by test_liveness.py."""
import json
import os
from pathlib import Path
import select
import signal
import sys

import runtime


def report(instance):
    print(json.dumps({"unit": instance.unit, "directory": instance.temp.name,
                      "relay_pid": instance.process.pid if instance.process else None}), flush=True)


if __name__ == "__main__":
    root, manifest, expected, stage = sys.argv[1:]
    instance = runtime.Runtime(Path(root), Path(manifest), expected)
    if stage == "preparation":
        def interrupted_snapshot(*_):
            # Stop at a real ownership boundary, before a service exists. No
            # mock process or cleanup implementation is used by the test.
            report(instance)
            os.kill(os.getpid(), signal.SIGSTOP)
            raise AssertionError("fault host unexpectedly resumed")
        runtime.snapshot = interrupted_snapshot
    elif stage != "active":
        raise ValueError("unknown fault stage")
    with instance:
        ready, _, _ = select.select([instance.process.stdout], [], [], 15)
        if not ready or instance.process.stdout.readline(256) != b"READY\n":
            raise AssertionError("fault guest did not become ready")
        report(instance)
        while True:
            signal.pause()
