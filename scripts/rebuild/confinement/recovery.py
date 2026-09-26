"""Private runtime ownership/recovery. No lease or identity authority lives here."""
import contextlib
import fcntl
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import time

from runtime import Refused, TOOLS, control_env

PREFIX = "lumen-pi-runtime-"
NAME = re.compile(r"lumen-pi-runtime-([a-f0-9]{32})\Z")
MAX_ENTRIES = 4096
MAX_RUNTIMES = 128


def runtime_root():
    root = Path(f"/run/user/{os.getuid()}")
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused("unsafe user runtime directory")
    if not shutil.rmtree.avoids_symlink_attacks:
        raise Refused("fd-based cleanup is required")
    return root


def checked_lock(directory, name, create=False):
    flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(name, flags | (os.O_CREAT if create else 0), 0o600, dir_fd=directory)
    info = os.fstat(descriptor)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(descriptor)
        raise Refused("unsafe runtime lock")
    return descriptor


@contextlib.contextmanager
def registry():
    directory = os.open(runtime_root(), os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW)
    lock = None
    try:
        lock = checked_lock(directory, ".lumen-pi-runtime.registry.lock", create=True)
        deadline = time.monotonic() + 5
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise Refused("runtime registry lock timed out")
                time.sleep(0.01)
        yield directory
    finally:
        if lock is not None:
            os.close(lock)
        os.close(directory)


def unit_for(name):
    match = NAME.fullmatch(name)
    if not match:
        raise Refused("invalid owned runtime name")
    return "lumen-phase0-" + match[1] + ".service"


def unit_state(unit):
    if not re.fullmatch(r"lumen-phase0-[a-f0-9]{32}\.service", unit):
        raise Refused("invalid runtime unit")
    status = subprocess.run([TOOLS["systemctl"], "--user", "show", unit,
                             "--property=LoadState", "--property=ActiveState", "--property=ControlGroup"],
                            env=control_env(), capture_output=True, timeout=10, check=False)
    if status.returncode != 0 or len(status.stdout) > 4096:
        raise Refused("service manager state unavailable")
    fields = dict(line.split("=", 1) for line in status.stdout.decode().splitlines())
    if set(fields) != {"LoadState", "ActiveState", "ControlGroup"}:
        raise Refused("unknown service manager state")
    return fields


def stop_unit(unit):
    subprocess.run([TOOLS["systemctl"], "--user", "stop", unit], env=control_env(),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10, check=False)
    state = unit_state(unit)
    if (state["LoadState"] not in ("loaded", "not-found")
            or state["ActiveState"] not in ("inactive", "failed") or state["ControlGroup"]):
        raise Refused("runtime unit has not been reaped")


def remove_directory(directory, name):
    try:
        info = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise Refused("unsafe cleanup target")
    try:
        shutil.rmtree(name, dir_fd=directory)
    except FileNotFoundError:
        # The manager also owns teardown; accept only an absent top-level
        # directory, not an incomplete deletion with surviving contents.
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise


def recover_locked(directory):
    recovered = []
    count = 0
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries):
            if index >= MAX_ENTRIES:
                raise Refused("runtime registry inventory limit")
            if not NAME.fullmatch(entry.name):
                continue
            count += 1
            if count > MAX_RUNTIMES:
                raise Refused("runtime count limit")
            try:
                info = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                raise Refused("unsafe recovery target")
            # systemd may concurrently remove a stopped runtime directory.
            try:
                child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                continue
            owner = None
            try:
                try:
                    owner = checked_lock(child, "owner.lock")
                    fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    continue  # live/concurrent host; never delete its snapshot
                except FileNotFoundError:
                    pass  # interrupted creation; registry lock excludes a creator
                unit = unit_for(entry.name)
                stop_unit(unit)
                remove_directory(directory, entry.name)
                recovered.append(unit)
            finally:
                if owner is not None:
                    os.close(owner)
                os.close(child)
    return recovered


def recover():
    with registry() as directory:
        return recover_locked(directory)


class OwnedDirectory:
    def __init__(self, unit):
        if not re.fullmatch(r"lumen-phase0-[a-f0-9]{32}\.service", unit):
            raise Refused("invalid runtime unit")
        self.basename = PREFIX + unit[len("lumen-phase0-"):-len(".service")]
        self.name = str(runtime_root() / self.basename)
        self.owner = None
        self.writer = None
        with registry() as directory:
            recover_locked(directory)
            os.mkdir(self.basename, 0o700, dir_fd=directory)
            child = os.open(self.basename, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory)
            try:
                self.owner = checked_lock(child, "owner.lock", create=True)
                fcntl.flock(self.owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.mkfifo("liveness", 0o600, dir_fd=child)
                reader = os.open("liveness", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=child)
                try:
                    self.writer = os.open("liveness", os.O_WRONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=child)
                    if os.write(self.writer, b"L") != 1:
                        raise Refused("liveness startup marker failed")
                finally:
                    os.close(reader)
            except BaseException:
                self.close()
                remove_directory(directory, self.basename)
                raise
            finally:
                os.close(child)

    def close_liveness(self):
        if self.writer is not None:
            os.close(self.writer)
            self.writer = None

    def close(self):
        self.close_liveness()
        if self.owner is not None:
            os.close(self.owner)
            self.owner = None

    def cleanup(self):
        try:
            with registry() as directory:
                remove_directory(directory, self.basename)
        finally:
            self.close()
