"""Linux fault injection: real host SIGKILL, service death and startup recovery.

Observations precede fallback cleanup, so cleanup cannot make a failed liveness
assertion pass. Only processes/directories created by this suite are targeted.
"""
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time
import uuid
from unittest.mock import patch

from recovery import OwnedDirectory, recover, runtime_root, stop_unit, unit_state
from runtime import Refused, Runtime, check_host_tools, control_env, load_manifest
from test_runtime import ConfinementFixture


READY = "require('node:fs').writeSync(1,'READY\\n');"
UNCOOPERATIVE = READY + "process.on('SIGTERM',()=>{});while(true){}"
MAX_TEARDOWN_SECONDS = 5


class LivenessTests(ConfinementFixture):
    @contextlib.contextmanager
    def fault_host(self, manifest, expected, stage):
        # Isolated Python ignores ambient site modules, PYTHONPATH and env.
        here = str(Path(__file__).resolve().parent)
        code = "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); runpy.run_module('fault_host',run_name='__main__')"
        process = subprocess.Popen([sys.executable, "-I", "-S", "-c", code, here,
                                    str(self.root), str(manifest), expected, stage],
                                   cwd="/", env=control_env(), close_fds=True,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        info = None
        try:
            ready, _, _ = select.select([process.stdout], [], [], 20)
            self.assertTrue(ready, "fault host readiness timed out")
            line = process.stdout.readline(4096)
            self.assertTrue(line, "fault host exited before readiness")
            info = json.loads(line)
            self.assertEqual(set(info), {"unit", "directory", "relay_pid"})
            yield process, info
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()
            if info is not None:
                # Only after assertions; never counted as passive recovery.
                stop_unit(info["unit"])
                recover()

    def await_empty(self, unit, directory, cgroup, began=None):
        if began is None:
            began = time.monotonic()
        while time.monotonic() - began < MAX_TEARDOWN_SECONDS:
            state = unit_state(unit)
            group_gone = cgroup is None or not cgroup.exists()
            if (state["ActiveState"] in ("inactive", "failed") and not state["ControlGroup"]
                    and not Path(directory).exists() and group_gone):
                return time.monotonic() - began
            time.sleep(0.025)
        self.fail(f"runtime survived fault: unit={unit}, state={state}, snapshot={Path(directory).exists()}")

    def cgroup(self, unit):
        value = unit_state(unit)["ControlGroup"]
        self.assertTrue(value.startswith("/user.slice/"), value)
        path = Path("/sys/fs/cgroup") / value.lstrip("/")
        self.assertTrue(path.is_dir())
        return path

    def started(self, instance):
        ready, _, _ = select.select([instance.process.stdout], [], [], 15)
        self.assertTrue(ready, "runtime did not start")
        self.assertEqual(instance.process.stdout.readline(256), b"READY\n")

    def test_01_sigkill_host_reaps_noncooperative_guest_without_recovery(self):
        manifest, expected = self.candidate(UNCOOPERATIVE)
        latencies = []
        for _ in range(3):
            with self.fault_host(manifest, expected, "active") as (host, info):
                group = self.cgroup(info["unit"])
                # Observe the exact relay process, immune to numeric PID reuse.
                relay = os.pidfd_open(info["relay_pid"])
                try:
                    began = time.monotonic()
                    host.kill()
                    self.assertEqual(host.wait(timeout=5), -signal.SIGKILL)
                    latencies.append(self.await_empty(info["unit"], info["directory"], group, began))
                    self.assertTrue(select.select([relay], [], [], 5)[0], "relay survived host death")
                finally:
                    os.close(relay)
        print(json.dumps({"fault": "host_sigkill", "teardown_seconds": latencies}), flush=True)

    def test_02_preparation_crash_recovery_preserves_a_live_owner(self):
        manifest, expected = self.candidate(READY + "setInterval(()=>{},1000)")
        with Runtime(self.root, manifest, expected) as live:
            self.started(live)
            with self.fault_host(manifest, expected, "preparation") as (host, info):
                self.assertTrue(Path(info["directory"]).is_dir())
                self.assertEqual(unit_state(info["unit"])["LoadState"], "not-found")
                host.kill()
                host.wait(timeout=5)
                check_host_tools(load_manifest(manifest, expected))
                self.assertIn(info["unit"], recover())
                self.assertFalse(Path(info["directory"]).exists())
                self.assertEqual(unit_state(live.unit)["ActiveState"], "active")
                self.assertTrue(Path(live.temp.name).is_dir())
                # Restart creates a new generation after recovery.
                with Runtime(self.root, manifest, expected) as fresh:
                    self.started(fresh)
                    self.assertNotIn(fresh.unit, (live.unit, info["unit"]))

    def test_03_monitor_death_reaps_its_whole_cgroup(self):
        manifest, expected = self.candidate(UNCOOPERATIVE)
        with Runtime(self.root, manifest, expected) as instance:
            self.started(instance)
            group = self.cgroup(instance.unit)
            began = time.monotonic()
            subprocess.run(["/usr/bin/systemctl", "--user", "kill", "--kill-whom=main",
                            "--signal=KILL", instance.unit], env=control_env(), check=True,
                           capture_output=True, timeout=10)
            latency = self.await_empty(instance.unit, instance.temp.name, group, began)
            print(json.dumps({"fault": "monitor_sigkill", "teardown_seconds": latency}), flush=True)

    def test_04_liveness_corruption_terminates_generation(self):
        manifest, expected = self.candidate(UNCOOPERATIVE)
        with Runtime(self.root, manifest, expected) as instance:
            self.started(instance)
            group = self.cgroup(instance.unit)
            os.write(instance.temp.writer, b"unexpected")
            self.await_empty(instance.unit, instance.temp.name, group)

    def test_05_dead_writer_before_monitor_start_cannot_launch(self):
        # --help would print if the monitor ever execs bwrap. These are real
        # FIFO semantics and the actual native monitor, with no child stub.
        unit = "lumen-phase0-" + uuid.uuid4().hex + ".service"
        owned = OwnedDirectory(unit)
        try:
            owned.close_liveness()
            result = subprocess.run([str(self.root / "guard/liveness"),
                                     owned.name + "/liveness", "--", "/usr/bin/bwrap", "--help"],
                                    env=control_env(), capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 126)
            self.assertEqual(result.stdout, b"")
            self.assertEqual(result.stderr, b"")
        finally:
            owned.cleanup()

    def test_06_missing_tampered_or_invalid_monitor_never_reaches_entrypoint(self):
        monitor = self.root / "guard/liveness"
        original = monitor.read_bytes()
        try:
            for mutation in ("missing", "tampered"):
                manifest, expected = self.candidate("console.log('ENTRYPOINT_EXECUTED')")
                if mutation == "missing":
                    monitor.unlink()
                else:
                    monitor.write_bytes(b"not the pinned monitor")
                with self.assertRaises(Refused):
                    with Runtime(self.root, manifest, expected):
                        self.fail("unverified monitor launched")
                monitor.write_bytes(original)
                monitor.chmod(0o755)
            # Even a reviewed-but-invalid executable cannot activate a weaker
            # profile. Native exec fails, and no application code is reached.
            monitor.write_bytes(b"invalid ELF")
            code, out, _ = self.run_script("console.log('ENTRYPOINT_EXECUTED')")
            self.assertNotEqual(code, 0)
            self.assertNotIn(b"ENTRYPOINT_EXECUTED", out)
        finally:
            monitor.write_bytes(original)
            monitor.chmod(0o755)

    def test_07_recovery_rejects_symlink_and_unsafe_targets(self):
        target = self.base / "outside-recovery"
        target.mkdir()
        marker = target / "keep"
        marker.write_text("do not delete")
        bad = runtime_root() / ("lumen-pi-runtime-" + uuid.uuid4().hex)
        try:
            bad.symlink_to(target, target_is_directory=True)
            with self.assertRaises(Refused):
                recover()
            self.assertEqual(marker.read_text(), "do not delete")
            bad.unlink()
            bad.mkdir(mode=0o755)
            bad.chmod(0o755)
            with self.assertRaises(Refused):
                recover()
            self.assertTrue(bad.is_dir())
        finally:
            if bad.is_symlink():
                bad.unlink()
            elif bad.exists():
                bad.rmdir()

    def test_08_runtime_generation_cannot_be_reused(self):
        manifest, expected = self.candidate("console.log('ONCE')")
        instance = Runtime(self.root, manifest, expected)
        with instance:
            self.assertEqual(instance.collect()[0], 0)
        with self.assertRaises(Refused):
            with instance:
                self.fail("stale runtime restarted")

    def test_09_unavailable_manager_preserves_unverified_state(self):
        unit = "lumen-phase0-" + uuid.uuid4().hex + ".service"
        owned = OwnedDirectory(unit)
        owned.close()
        try:
            # Exercise the real systemctl against a nonexistent manager socket;
            # no fabricated command result can accidentally count as evidence.
            unavailable = {**control_env(), "XDG_RUNTIME_DIR": str(self.base / "no-manager")}
            with patch("recovery.control_env", return_value=unavailable):
                with self.assertRaisesRegex(Refused, "service manager state unavailable"):
                    recover()
            self.assertTrue(Path(owned.name).is_dir())
            self.assertIn(unit, recover())
            self.assertFalse(Path(owned.name).exists())
        finally:
            owned.cleanup()

    def test_10_recovery_rejects_indirect_owner_lock_and_recovers_partial_creation(self):
        unit = "lumen-phase0-" + uuid.uuid4().hex + ".service"
        owned = OwnedDirectory(unit)
        owned.close()
        owner = Path(owned.name) / "owner.lock"
        outside = self.base / "outside-lock"
        outside.write_text("unchanged")
        try:
            owner.unlink()
            owner.symlink_to(outside)
            with self.assertRaises((OSError, Refused)):
                recover()
            self.assertEqual(outside.read_text(), "unchanged")
            self.assertTrue(Path(owned.name).is_dir())
            owner.unlink()
            # A crash between mkdir and owner-lock creation is stale while
            # the registry lock is held, and must not strand a partial run.
            self.assertIn(unit, recover())
            self.assertFalse(Path(owned.name).exists())
        finally:
            owned.cleanup()
