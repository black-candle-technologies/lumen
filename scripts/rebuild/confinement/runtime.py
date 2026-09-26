"""Experimental, fail-closed Linux Pi runtime launcher (ADR-0008).

This is test infrastructure, not an admission path for the product supervisors.
No live repository, home, credential, host socket, or network is mounted.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import selectors
import signal
import stat
import subprocess
import tempfile
import time
import uuid

TOOLS = {"bwrap": "/usr/bin/bwrap", "systemd_run": "/usr/bin/systemd-run",
         "systemctl": "/usr/bin/systemctl"}
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_FILES = 8192


class Refused(RuntimeError):
    pass


def sha256(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise Refused("duplicate manifest field")
        obj[key] = value
    return obj


def exact(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise Refused("unknown or missing manifest fields")


def path_parts(path):
    if not isinstance(path, str) or not path.startswith("/") or "\0" in path or len(path) > 4096:
        raise Refused("invalid runtime path")
    parts = PurePosixPath(path).parts[1:]
    if not parts or len(parts) > 64 or any(p in (".", "..") for p in parts) or "/" + "/".join(parts) != path:
        raise Refused("noncanonical runtime path")
    return parts


def digest(value):
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise Refused("invalid sha256")


def inventory(directory: int, prefix="", budget=None) -> set[str]:
    """Walk directory descriptors, never following a source-tree symlink."""
    if budget is None:
        budget = [MAX_FILES * 2]
    with os.scandir(directory) as entries:
        return inventory_entries(directory, entries, prefix, budget)


def inventory_entries(directory, entries, prefix, budget):
    found = set()
    for entry in entries:
        name = entry.name
        budget[0] -= 1
        if budget[0] < 0:
            raise Refused("runtime entry limit exceeded")
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
        path = prefix + "/" + name
        path_parts(path)
        if stat.S_ISREG(info.st_mode):
            found.add(path)
        elif stat.S_ISDIR(info.st_mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            try:
                found.update(inventory(child, path, budget))
            finally:
                os.close(child)
        else:
            raise Refused("symlink or special file in runtime")
        if len(found) > MAX_FILES:
            raise Refused("runtime file limit exceeded")
    return found


@contextlib.contextmanager
def open_beneath(directory: int, path: str):
    parts = path_parts(path)
    parent = os.dup(directory)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise Refused("runtime input is not a regular file")
            yield source
    finally:
        os.close(parent)


def load_manifest(path: Path, expected_digest: str):
    digest(expected_digest)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise Refused("manifest is not a regular file")
        raw = source.read(2 * 1024 * 1024 + 1)
    if len(raw) > 2 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected_digest:
        raise Refused("runtime manifest digest mismatch")
    obj = json.loads(raw, object_pairs_hook=unique_object)
    exact(obj, ("version", "platform", "files", "host_tools", "entrypoint", "arguments"))
    if type(obj["version"]) is not int or obj["version"] != 1 or obj["platform"] != "linux-x86_64":
        raise Refused("unsupported runtime manifest")
    files = obj["files"]
    if not isinstance(files, dict) or not 3 <= len(files) <= MAX_FILES:
        raise Refused("invalid runtime inventory")
    for name, expected in files.items():
        path_parts(name)
        digest(expected)
    for required in ("/usr/bin/node", "/guard/guard.node", "/guard/bootstrap.cjs"):
        if required not in files:
            raise Refused("required runtime component missing")
    exact(obj["host_tools"], TOOLS)
    for expected in obj["host_tools"].values():
        digest(expected)
    path_parts(obj["entrypoint"])
    if obj["entrypoint"] not in files:
        raise Refused("entrypoint is not pinned")
    args = obj["arguments"]
    if not isinstance(args, list) or len(args) > 64 or any(
        not isinstance(a, str) or len(a) > 4096 or "\0" in a for a in args
    ):
        raise Refused("invalid fixed entrypoint arguments")
    return obj


def snapshot(source_root: Path, destination: Path, manifest):
    """Verify the bytes we copy, then execute only this private snapshot.

    No original runtime path is bind-mounted. Concurrent modifications produce
    either the exact admitted bytes or a refusal, never an unchecked exec.
    """
    root = os.open(source_root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    total = 0
    try:
        if inventory(root) != set(manifest["files"]):
            raise Refused("runtime inventory mismatch")
        for name, expected in sorted(manifest["files"].items()):
            target = destination.joinpath(*path_parts(name))
            target.parent.mkdir(parents=True, exist_ok=True)
            copied = 0
            actual = hashlib.sha256()
            with open_beneath(root, name) as source, target.open("xb") as out:
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    total += len(chunk)
                    if copied > MAX_FILE_BYTES or total > MAX_TREE_BYTES:
                        raise Refused("runtime byte limit exceeded")
                    actual.update(chunk)
                    out.write(chunk)
            if actual.hexdigest() != expected:
                raise Refused("runtime file digest mismatch")
            target.chmod(0o555 if name == "/usr/bin/node" or target.name.startswith("ld-linux-") else 0o444)
        for name in ("state", "dev"):
            (destination / name).mkdir(exist_ok=True)
    finally:
        os.close(root)


def control_env():
    # These values are for trusted systemd/bubblewrap only. No parent environment
    # is copied. Bubblewrap separately sets the smaller guest environment below.
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}"}


class Runtime:
    """One transient cgroup + disposable mount/PID/network namespace per run."""
    def __init__(self, source_root: Path, manifest_path: Path, expected_digest: str):
        if platform.system() != "Linux" or platform.machine() != "x86_64" or os.geteuid() == 0:
            raise Refused("requires unprivileged Linux x86-64; no fallback")
        self.manifest = load_manifest(manifest_path, expected_digest)
        self.source_root = source_root
        self.process = None
        self.temp = None
        self.unit = "lumen-phase0-" + uuid.uuid4().hex + ".service"

    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lumen-pi-runtime-")
        try:
            base = Path(self.temp.name)
            snapshot(self.source_root, base / "root", self.manifest)
            # Preserve the distro's path-bound AppArmor profile for bubblewrap.
            # Host executables must be root-owned, immutable to this unprivileged
            # account, and hash-pinned. A root compromise is outside this profile.
            for tool, original in TOOLS.items():
                candidate = Path(original)
                for component in (candidate, *candidate.parents):
                    info = component.lstat()
                    if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or os.access(component, os.W_OK):
                        raise Refused("host tool path is mutable or indirect")
                if sha256(Path(original)) != self.manifest["host_tools"][tool]:
                    raise Refused("host tool digest mismatch")
            argv = [TOOLS["bwrap"], "--unshare-all", "--unshare-user", "--unshare-cgroup",
                    "--disable-userns", "--die-with-parent", "--new-session",
                    "--uid", "65534", "--gid", "65534", "--cap-drop", "ALL",
                    "--ro-bind", str(base / "root"), "/", "--dev", "/dev",
                    "--tmpfs", "/state", "--dir", "/state/agent", "--dir", "/state/tmp",
                    "--chdir", "/state", "--clearenv"]
            for name, value in {"HOME": "/state", "PATH": "/nonexistent", "LANG": "C.UTF-8",
                                "PWD": "/state",
                                "TMPDIR": "/state/tmp", "PI_CODING_AGENT_DIR": "/state/agent",
                                "UV_USE_IO_URING": "0"}.items():
                argv += ["--setenv", name, value]
            argv += ["--", "/usr/bin/node", "--max-old-space-size=256", "--require",
                     "/guard/bootstrap.cjs", "--", self.manifest["entrypoint"],
                     *self.manifest["arguments"]]
            # The user manager creates a transient service, never modifies a
            # deployed Lumen service, and enforces bounds outside the guest.
            command = [TOOLS["systemd_run"], "--user", "--quiet", "--wait", "--pipe", "--collect",
                       "--unit=" + self.unit, "-p", "MemoryMax=768M", "-p", "MemorySwapMax=0",
                       "-p", "TasksMax=64", "-p", "CPUQuota=100%", "-p", "RuntimeMaxSec=90",
                       "-p", "KillMode=control-group", "-p", "TimeoutStopSec=2", "-p", "LimitCORE=0",
                       # libuv may initialize io_uring before --require runs.
                       # Deny setup before exec; the final TSYNC filter also
                       # denies all three calls. Never permit an existing ring.
                       "-p", "SystemCallFilter=~io_uring_setup io_uring_enter io_uring_register",
                       "-p", "SystemCallErrorNumber=ENOSYS",
                       "--", *argv]
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, env=control_env(), close_fds=True,
                                            start_new_session=True)
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *_):
        if self.process is not None:
            try:
                # Stop the complete cgroup even if the stdio relay exited.
                subprocess.run([TOOLS["systemctl"], "--user", "stop", self.unit],
                               env=control_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=10, check=False)
            finally:
                if self.process.poll() is None:
                    os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=10)
                for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                    stream.close()
            state = subprocess.run([TOOLS["systemctl"], "--user", "show", self.unit,
                                    "--property=ActiveState", "--value"], env=control_env(),
                                   capture_output=True, timeout=10, check=False)
            if state.returncode == 0 and state.stdout.strip() not in (b"inactive", b"failed"):
                raise Refused("transient runtime unit remains active")
        if self.temp is not None:
            self.temp.cleanup()

    def collect(self, input_bytes=b"", timeout=20, max_bytes=256 * 1024):
        """Bound both streams and stdin, including a child that never reads."""
        if len(input_bytes) > 64 * 1024 or self.process is None:
            raise Refused("invalid bounded run")
        process = self.process
        selector = selectors.DefaultSelector()
        output = {"stdout": bytearray(), "stderr": bytearray()}
        remaining = memoryview(input_bytes)
        deadline = time.monotonic() + timeout
        try:
            for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            os.set_blocking(process.stdin.fileno(), False)
            if remaining:
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while selector.get_map():
                budget = deadline - time.monotonic()
                if budget <= 0:
                    raise TimeoutError("confined runtime timed out")
                for key, _ in selector.select(min(budget, 0.25)):
                    if key.data == "stdin":
                        try:
                            n = os.write(key.fd, remaining[:4096])
                            remaining = remaining[n:]
                        except BrokenPipeError:
                            remaining = remaining[:0]
                        if not remaining:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        data = os.read(key.fd, 8192)
                        if not data:
                            selector.unregister(key.fileobj)
                        else:
                            output[key.data].extend(data)
                            if sum(map(len, output.values())) > max_bytes:
                                raise Refused("confined output exceeded byte limit")
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
            return code, bytes(output["stdout"]), bytes(output["stderr"])
        finally:
            selector.close()
