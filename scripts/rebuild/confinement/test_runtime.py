"""Actual Linux namespace/seccomp tests. No fake child or policy stub.

Requires an unprivileged user with a working systemd user manager, cgroup v2,
bubblewrap, GCC, system Node >=22, and Node N-API headers. Missing prerequisites
are failures on the Linux runner, not skipped tests or weaker fallback profiles.
"""
import errno
import json
import os
import select
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from prepare import compile_guard, manifest_for, system_runtime
from runtime import Refused, Runtime, control_env, load_manifest, sha256


class ConfinementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.area = tempfile.TemporaryDirectory(prefix="lumen-confinement-tests-")
        cls.base = Path(cls.area.name)
        cls.root = cls.base / "root"
        cls.root.mkdir()
        system_runtime(cls.root)
        compile_guard(cls.root)
        probe = cls.root / "guard/probe.node"
        subprocess.run(["/usr/bin/gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                        "-fPIC", "-shared", "-I/usr/include/node", "-o", str(probe),
                        str(Path(__file__).with_name("probe.c"))], check=True, timeout=30)
        (cls.root / "app").mkdir()

    @classmethod
    def tearDownClass(cls):
        cls.area.cleanup()

    def candidate(self, source):
        (self.root / "app/main.cjs").write_text(source)
        manifest = self.base / "manifest.json"
        expected = manifest_for(self.root, manifest, "/app/main.cjs")
        return manifest, expected

    def run_script(self, source, **kwargs):
        manifest, expected = self.candidate(source)
        with Runtime(self.root, manifest, expected) as runtime:
            return runtime.collect(**kwargs)

    def test_01_runtime_reaches_node_after_native_seal(self):
        code, out, err = self.run_script("console.log(JSON.stringify({ready:true}));")
        self.assertEqual(code, 0, err.decode())
        self.assertEqual(json.loads(out), {"ready": True})

    def test_02_native_shell_network_and_escape_syscalls_are_denied(self):
        cases = ["socket_inet", "socket_inet6", "socket_unix", "fork", "clone_process",
                 "execve", "execveat", "unshare", "ptrace", "io_uring", "bpf", "ioctl_inject"]
        script = "const {probe}=require('/guard/probe.node'); console.log(JSON.stringify(" + \
                 "Object.fromEntries(" + json.dumps(cases) + ".map(name=>[name,probe(name)]))));"
        code, out, err = self.run_script(script)
        self.assertEqual(code, 0, err.decode())
        self.assertEqual(json.loads(out), {case: errno.EPERM for case in cases})

    def test_03_host_files_credentials_proc_and_shell_are_unavailable(self):
        canary = self.base / "host-canary"
        canary.write_text("PRIVATE_HOST_BYTES")
        script = """
const fs=require('node:fs'), cp=require('node:child_process');
const paths=HOST_PATHS;
const denied=paths.map(path=>{try{fs.readFileSync(path);return false}catch{return true}});
let writeDenied; try{fs.writeFileSync(HOST_FILE,'corrupted');writeDenied=false}catch{writeDenied=true}
const spawned=cp.spawnSync('/usr/bin/node',['-e',"console.log('ESCAPED')"]);
console.log(JSON.stringify({denied,writeDenied,spawnDenied:!!spawned.error,
  environment:Object.keys(process.env).sort(),pwd:process.env.PWD}));
""".replace("HOST_PATHS", json.dumps([str(canary), "/etc/passwd", "/proc/self/environ",
                                     "/proc/1/root/etc/passwd", "/state/../../etc/passwd"])) \
    .replace("HOST_FILE", json.dumps(str(canary)))
        with patch.dict(os.environ, {"PROVIDER_TEST_SECRET": "PRIVATE_ENV_CANARY",
                                     "NODE_OPTIONS": "--require /host/forbidden.cjs"}):
            code, out, err = self.run_script(script)
        self.assertEqual(code, 0, err.decode())
        value = json.loads(out)
        self.assertTrue(all(value["denied"]))
        self.assertTrue(value["writeDenied"])
        self.assertTrue(value["spawnDenied"])
        self.assertEqual(value["environment"], sorted(["HOME", "PATH", "LANG", "PWD", "TMPDIR", "PI_CODING_AGENT_DIR", "UV_USE_IO_URING"]))
        self.assertEqual(value["pwd"], "/state")
        self.assertNotIn(b"PRIVATE_ENV_CANARY", out + err)
        self.assertEqual(canary.read_text(), "PRIVATE_HOST_BYTES")

    def test_04_worker_threads_inherit_the_filter(self):
        script = """
const {Worker}=require('node:worker_threads');
const worker=new Worker(`const {parentPort}=require('node:worker_threads');
const {probe}=require('/guard/probe.node');
parentPort.postMessage({socket:probe('socket_inet'),exec:probe('execve')});`,{eval:true});
worker.on('message',value=>console.log(JSON.stringify(value)));
worker.on('error',err=>{console.error(err);process.exitCode=1});
"""
        code, out, err = self.run_script(script)
        self.assertEqual(code, 0, err.decode())
        self.assertEqual(json.loads(out), {"socket": errno.EPERM, "exec": errno.EPERM})

    def test_05_failed_addon_prevents_entrypoint(self):
        guard = self.root / "guard/guard.node"
        saved = guard.read_bytes()
        try:
            guard.write_bytes(b"not an ELF file")
            code, out, err = self.run_script("console.log('ENTRYPOINT_EXECUTED');")
            self.assertNotEqual(code, 0)
            self.assertNotIn(b"ENTRYPOINT_EXECUTED", out)
            self.assertIn(b"guard.node", err)
        finally:
            guard.write_bytes(saved)

    def test_06_unpinned_tampered_and_symlink_files_refuse_launch(self):
        manifest, expected = self.candidate("console.log('OK')")
        source = self.root / "app/main.cjs"
        source.write_text("console.log('TAMPERED')")
        with self.assertRaises(Refused):
            with Runtime(self.root, manifest, expected):
                self.fail("tampered runtime launched")
        extra = self.root / "app/extra"
        try:
            extra.write_text("extra")
            with self.assertRaises(Refused):
                with Runtime(self.root, manifest, expected):
                    self.fail("unlisted file admitted")
            extra.unlink()
            extra.symlink_to("/etc/passwd")
            with self.assertRaises(Refused):
                with Runtime(self.root, manifest, expected):
                    self.fail("symlink admitted")
        finally:
            extra.unlink(missing_ok=True)

    def test_07_running_process_uses_copied_bytes(self):
        manifest, expected = self.candidate("console.log('PINNED_BYTES')")
        with Runtime(self.root, manifest, expected) as runtime:
            (self.root / "app/main.cjs").write_text("console.log('REPLACED_BYTES')")
            code, out, err = runtime.collect()
        self.assertEqual(code, 0, err.decode())
        self.assertEqual(out.strip(), b"PINNED_BYTES")

    def test_08_unknown_manifest_fields_versions_and_traversal_are_rejected(self):
        manifest, expected = self.candidate("console.log('OK')")
        original = json.loads(manifest.read_bytes())
        for change in ({"version": 2}, {"network": True}, {"entrypoint": "/app/../app/main.cjs"}):
            manifest.write_text(json.dumps({**original, **change}))
            with self.assertRaises(Refused):
                load_manifest(manifest, sha256(manifest))
        with self.assertRaises(Refused):
            load_manifest(manifest, expected)

    def test_09_timeout_and_output_flood_remove_transient_units(self):
        for source, error, options in [
            ("setInterval(()=>{},1000)", TimeoutError, {"timeout": 1}),
            ("process.stdout.write('x'.repeat(1000000));", Refused, {"max_bytes": 1024}),
        ]:
            manifest, expected = self.candidate(source)
            runtime = Runtime(self.root, manifest, expected)
            with self.assertRaises(error):
                with runtime:
                    runtime.collect(**options)
            self.assertIsNotNone(runtime.process.poll())
            self.assertFalse(Path(runtime.temp.name).exists())
            state = subprocess.run(["/usr/bin/systemctl", "--user", "show", runtime.unit,
                                    "--property=ActiveState", "--value"], env=control_env(),
                                   capture_output=True, timeout=10)
            self.assertIn(state.stdout.strip(), (b"", b"inactive", b"failed"))

    def test_10_alternate_syscall_architectures_are_fatal(self):
        for arch in ("x32", "i386"):
            code, out, _ = self.run_script(f"console.log('SEALED');require('/guard/probe.node').probe('{arch}'); console.log('ESCAPED')")
            self.assertNotEqual(code, 0)
            self.assertEqual(out.strip(), b"SEALED")

    def test_11_cgroup_limits_are_effective(self):
        manifest, expected = self.candidate("console.log('READY');setInterval(()=>{},1000)")
        with Runtime(self.root, manifest, expected) as runtime:
            ready, _, _ = select.select([runtime.process.stdout], [], [], 10)
            self.assertTrue(ready, "runtime did not start")
            self.assertEqual(runtime.process.stdout.readline(256), b"READY\n")
            group = subprocess.check_output(["/usr/bin/systemctl", "--user", "show", runtime.unit,
                       "--property=ControlGroup", "--value"], env=control_env(), timeout=10).decode().strip()
            self.assertTrue(group.startswith("/user.slice/"))
            cgroup = Path("/sys/fs/cgroup") / group.lstrip("/")
            self.assertEqual((cgroup / "memory.max").read_text().strip(), str(768 * 1024 * 1024))
            self.assertEqual((cgroup / "memory.swap.max").read_text().strip(), "0")
            self.assertEqual((cgroup / "pids.max").read_text().strip(), "64")
            quota, period = (cgroup / "cpu.max").read_text().split()
            self.assertEqual(int(quota), int(period))

    def test_12_concurrent_and_restarted_runtimes_do_not_share_state(self):
        manifest, expected = self.candidate("""
const fs=require('node:fs');
const value=fs.readFileSync(0,'utf8');
const existed=fs.existsSync('/state/private-marker');
fs.writeFileSync('/state/private-marker',value);
setTimeout(()=>console.log(JSON.stringify({existed,value:fs.readFileSync('/state/private-marker','utf8')})),200);
""")
        def run(value):
            with Runtime(self.root, manifest, expected) as runtime:
                code, out, err = runtime.collect(value.encode())
                self.assertEqual(code, 0, err.decode())
                return runtime.unit, json.loads(out)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, ["session-a", "session-b"]))
        results.append(run("restarted-session"))
        self.assertEqual(len({unit for unit, _ in results}), 3)
        self.assertEqual([value for _, value in results], [
            {"existed": False, "value": value} for value in ["session-a", "session-b", "restarted-session"]])

    def test_13_arguments_cannot_expand_the_service_manager_environment(self):
        manifest, _ = self.candidate("console.log(JSON.stringify(process.argv.slice(2)))")
        expected = manifest_for(self.root, manifest, "/app/main.cjs", ["$HOME", "${PATH}"])
        with Runtime(self.root, manifest, expected) as runtime:
            code, out, err = runtime.collect()
        self.assertEqual(code, 0, err.decode())
        self.assertEqual(json.loads(out), ["$HOME", "${PATH}"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
