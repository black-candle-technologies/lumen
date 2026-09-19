#!/usr/bin/env python3
"""Owned, WSL-only M5 manual QA fixture and evidence helper."""

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import time
import tomllib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


BASE = Path.home() / ".local/share/lumen-m5-qa"
TARGET = Path.home() / ".cache/lumen-m5-cargo-target"
CARGO = shutil.which("cargo") or str(Path.home() / ".cargo/bin/cargo")
REPO = Path(__file__).resolve().parents[2]
NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,39}\Z")
CASE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
OUTCOMES = {"pass", "fail", "expected_refusal", "inconclusive", "not_run"}


class QaError(Exception):
    pass


def fail_unless(condition, message):
    if not condition:
        raise QaError(message)


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    fail_unless(not path.is_symlink(), f"refusing symlink: {path}")
    temporary = path.with_name(path.name + f".tmp-{uuid.uuid4().hex}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(value, output, indent=2, sort_keys=True)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json(path):
    fail_unless(path.is_file() and not path.is_symlink(), f"missing regular file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        fail_unless(isinstance(value, dict), f"expected JSON object in {path}")
        return value
    except (ValueError, OSError) as error:
        raise QaError(f"invalid JSON in {path}: {error}") from error


def slug(value, label="name"):
    fail_unless(bool(NAME.fullmatch(value)), f"invalid {label}: use lowercase letters, digits and hyphens")
    return value


def safe_layout():
    for path in (BASE, BASE / "fixtures", BASE / "evidence"):
        fail_unless(not path.is_symlink(), f"refusing symlinked QA directory: {path}")


def fixture_root(name):
    return BASE / "fixtures" / slug(name)


def evidence_root(fixture_id):
    return BASE / "evidence" / str(uuid.UUID(fixture_id))


def validate_loopback(endpoint):
    parts = urlsplit(endpoint)
    try:
        valid = parts.scheme == "http" and ipaddress.ip_address(parts.hostname or "").is_loopback
        port = parts.port
    except ValueError:
        valid, port = False, None
    fail_unless(valid and port and not parts.username and not parts.password and
                parts.path == "/v1/" and not parts.query and not parts.fragment,
                "model endpoint must be a numeric loopback HTTP /v1/ URL")


def available_port(port):
    fail_unless(isinstance(port, int) and 0 <= port <= 65535, "invalid port")
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError as error:
            raise QaError(f"port {port} is occupied: {error}") from error
        return listener.getsockname()[1]


def select_fixture(name):
    safe_layout()
    load_fixture(name)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_json(BASE / "selected.json", {"name": name})


def selected_name():
    selected = read_json(BASE / "selected.json")
    return slug(selected.get("name", ""))


def ensure_evidence(manifest):
    evidence = evidence_root(manifest["fixture_id"])
    fail_unless(not evidence.is_symlink(), "evidence root is symlinked")
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = evidence / "environment.json"
    if not record.exists():
        write_json(record, {key: value for key, value in manifest.items()
                            if key not in ("pid", "pid_start")})


def clear_interrupted_stages(name):
    parent = BASE / "fixtures"
    if not parent.exists():
        return
    for stage in parent.glob(f".{name}.init-*"):
        fail_unless(bool(re.fullmatch(rf"\.{re.escape(name)}\.init-[0-9a-f]{{32}}", stage.name)) and
                    stage.is_dir() and not stage.is_symlink() and
                    stage.resolve() == parent.resolve() / stage.name,
                    f"unrecognized interrupted fixture stage: {stage}")
        children = {path.name for path in stage.iterdir()}
        temporary = {child for child in children if re.fullmatch(r"(owner|manifest)\.json\.tmp-[0-9a-f]{32}", child)}
        fail_unless(children <= {"workspace", "owner.json", "manifest.json", "token", "lumen.toml"} | temporary and
                    (not (stage / "workspace").exists() or not any((stage / "workspace").iterdir())) and
                    not any(path.is_symlink() for path in stage.rglob("*")),
                    f"interrupted fixture stage contains foreign content: {stage}")
        marker = stage / "owner.json"
        if marker.exists():
            owner = read_json(marker)
            try:
                valid_id = str(uuid.UUID(owner.get("fixture_id", ""))) == owner["fixture_id"]
            except (ValueError, TypeError, KeyError):
                valid_id = False
            fail_unless(owner.get("name") == name and valid_id,
                        f"interrupted fixture stage owner mismatch: {stage}")
            if (stage / "manifest.json").exists():
                manifest = read_json(stage / "manifest.json")
                fail_unless(manifest.get("name") == name and
                            manifest.get("fixture_id") == owner["fixture_id"],
                            f"interrupted fixture stage manifest mismatch: {stage}")
        else:
            fail_unless(children <= {"workspace"} | temporary,
                        f"unmarked interrupted fixture stage contains data: {stage}")
        shutil.rmtree(stage)


def init_fixture(name, source_sha, dirty, model, endpoint, port):
    safe_layout()
    slug(name)
    BASE.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = BASE / "init.lock"
    fail_unless(not lock.is_symlink(), "fixture init lock is symlinked")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+b") as handle:
        # ponytail: one short global init lock; split per fixture only if concurrent setup becomes useful.
        fcntl.flock(handle, fcntl.LOCK_EX)
        return _init_fixture(name, source_sha, dirty, model, endpoint, port)


def _init_fixture(name, source_sha, dirty, model, endpoint, port):
    safe_layout()
    slug(name)
    fail_unless(bool(SHA.fullmatch(source_sha)), "source SHA must be a full lowercase Git SHA")
    fail_unless(isinstance(dirty, bool), "dirty flag must be boolean")
    fail_unless(isinstance(model, str) and 0 < len(model) <= 128 and not any(c.isspace() for c in model),
                "model name is invalid")
    validate_loopback(endpoint)
    root = fixture_root(name)
    clear_interrupted_stages(name)
    if root.exists() or root.is_symlink():
        manifest = load_fixture(name)
        fail_unless(manifest["source_sha"] == source_sha and manifest["source_dirty"] == dirty and
                    manifest["model"] == model and manifest["model_endpoint"] == endpoint,
                    "existing fixture metadata differs; use a new fixture name")
        ensure_evidence(manifest)
        select_fixture(name)
        return manifest
    bind_port = available_port(port)
    root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    stage = root.parent / f".{name}.init-{uuid.uuid4().hex}"
    stage.mkdir(mode=0o700)
    fixture_id, workspace_id = str(uuid.uuid4()), str(uuid.uuid4())
    database = root / "lumen.sqlite3"
    config = root / "lumen.toml"
    manifest = {
        "fixture_id": fixture_id, "name": name, "workspace_id": workspace_id,
        "source_sha": source_sha, "source_dirty": dirty,
        "model": model, "model_endpoint": endpoint, "port": bind_port,
        "database_path": str(database), "config_path": str(config),
        "binary_path": None, "binary_sha256": None, "pid": None, "pid_start": None,
        "launch_id": None,
        "created_at": now(),
    }
    try:
        (stage / "workspace").mkdir(mode=0o700)
        write_json(stage / "owner.json", {"fixture_id": fixture_id, "name": name})
        write_json(stage / "manifest.json", manifest)
        token_path = stage / "token"
        fd = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(secrets.token_urlsafe(48) + "\n")
        staged_config = stage / "lumen.toml"
        staged_config.write_text(
            f'[server]\nbind = "127.0.0.1:{bind_port}"\n'
            f'[database]\npath = {json.dumps(str(database))}\n'
            f'[model]\nendpoint = {json.dumps(endpoint)}\nmodel = {json.dumps(model)}\n'
            f'[workspace]\nid = "{workspace_id}"\nname = "M5 disposable QA"\n'
            f'path = {json.dumps(str(root / "workspace"))}\n'
            f'[runtime]\ndata_directory = {json.dumps(str(root / "data"))}\n'
            '[bootstrap_admin]\nprovider = "local"\nsubject = "operator"\n', encoding="utf-8")
        staged_config.chmod(0o600)
        os.replace(stage, root)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    ensure_evidence(manifest)
    select_fixture(name)
    return manifest


def load_fixture(name=None):
    safe_layout()
    name = slug(name or selected_name())
    root = fixture_root(name)
    fail_unless(root.is_dir() and not root.is_symlink() and root.resolve() ==
                (BASE / "fixtures").resolve() / name, "unowned or symlinked fixture root")
    manifest = read_json(root / "manifest.json")
    marker = read_json(root / "owner.json")
    fail_unless(manifest.get("name") == name and marker.get("fixture_id") == manifest.get("fixture_id"),
                "fixture owner marker mismatch")
    try:
        uuid.UUID(manifest["fixture_id"])
        uuid.UUID(manifest["workspace_id"])
    except (ValueError, KeyError, TypeError) as error:
        raise QaError("invalid fixture or workspace ID") from error
    fail_unless(manifest.get("database_path") == str(root / "lumen.sqlite3") and
                manifest.get("config_path") == str(root / "lumen.toml"), "fixture paths changed")
    token, config = root / "token", root / "lumen.toml"
    fail_unless(token.is_file() and not token.is_symlink() and config.is_file() and
                not config.is_symlink(), "fixture token or config missing/symlinked")
    with config.open("rb") as source:
        data = tomllib.load(source)
    fail_unless(data.get("workspace", {}).get("id") == manifest["workspace_id"] and
                data.get("workspace", {}).get("path") == str(root / "workspace") and
                data.get("database", {}).get("path") == manifest["database_path"] and
                data.get("runtime", {}).get("data_directory") == str(root / "data") and
                data.get("server", {}).get("bind") == f'127.0.0.1:{manifest["port"]}' and
                data.get("model", {}).get("model") == manifest["model"] and
                data.get("model", {}).get("endpoint") == manifest["model_endpoint"],
                "fixture config and manifest disagree")
    for writable in (root / "workspace", root / "data", root / "lumen.sqlite3"):
        fail_unless(not writable.is_symlink() and writable.resolve().is_relative_to(root.resolve()),
                    f"fixture writable path escapes root: {writable}")
    return manifest


def save_manifest(name, manifest):
    load_fixture(name)
    write_json(fixture_root(name) / "manifest.json", manifest)


def token_for(name):
    load_fixture(name)
    return (fixture_root(name) / "token").read_text(encoding="utf-8").strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def source_state():
    repo = str(REPO)
    probe = subprocess.run(["git", "-C", repo, "rev-parse", "HEAD"],
                           capture_output=True, text=True, check=False)
    git = "git"
    if probe.returncode != 0:
        windows = subprocess.run(["wslpath", "-w", repo], capture_output=True,
                                 text=True, check=False)
        fail_unless(windows.returncode == 0 and windows.stdout.strip(),
                    "cannot resolve source tree for Git")
        repo, git = windows.stdout.strip(), "git.exe"
        probe = subprocess.run([git, "-C", repo, "rev-parse", "HEAD"],
                               capture_output=True, text=True, check=False)
    sha = probe.stdout.strip()
    fail_unless(probe.returncode == 0 and bool(SHA.fullmatch(sha)),
                "cannot read a full Git source SHA")
    status = subprocess.run([git, "-C", repo, "status", "--porcelain"],
                            capture_output=True, text=True, check=False)
    fail_unless(status.returncode == 0, "cannot inspect source worktree status")
    return sha, bool(status.stdout.strip())


def build_fixture(name):
    manifest = recover_pending(load_fixture(name))
    fail_unless(not manifest["source_dirty"], "build requires a clean source revision for reusable identity")
    fail_unless(source_state() == (manifest["source_sha"], False),
                "source revision or worktree changed since fixture selection")
    fail_unless(not owned_process_running(manifest), "stop the owned server before rebuilding")
    binary = TARGET / "debug/lumen"
    if (manifest.get("binary_path") == str(binary) and binary.is_file() and
            manifest.get("binary_sha256") == sha256(binary)):
        return {"reused": True, "binary": str(binary), "sha256": manifest["binary_sha256"]}
    fail_unless(not TARGET.is_symlink() and not binary.is_symlink(), "Cargo target or binary is symlinked")
    TARGET.mkdir(parents=True, exist_ok=True)
    command = [CARGO, "build", "--locked", "-p", "lumen-cli", "--bin", "lumen", "-j", "2"]
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    evidence = evidence_root(manifest["fixture_id"])
    log = evidence / f"build-{uuid.uuid4().hex}.log"
    with log.open("x", encoding="utf-8") as output:
        output.write(f"source_sha={manifest['source_sha']}\ncommand={' '.join(command)}\n")
        output.flush()
        try:
            result = subprocess.run(command, cwd=REPO, env=environment,
                                    stdout=output, stderr=subprocess.STDOUT, timeout=900, check=False)
        except subprocess.TimeoutExpired as error:
            raise QaError(f"build exceeded 900 seconds; see {log}") from error
    fail_unless(result.returncode == 0 and binary.is_file(), f"build failed; see {log}")
    manifest["binary_path"] = str(binary)
    manifest["binary_sha256"] = sha256(binary)
    save_manifest(name, manifest)
    return {"reused": False, "binary": str(binary), "sha256": manifest["binary_sha256"],
            "log": str(log)}


def existing_db(manifest):
    db = Path(manifest["database_path"])
    fail_unless(db.is_file() and not db.is_symlink(), "database missing or symlinked; no empty DB created")
    return db


def check_sqlite(path):
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=3) as connection:
        fail_unless(connection.execute("PRAGMA quick_check").fetchone() == ("ok",),
                    "SQLite quick_check failed")


def snapshot_fixture(name, label):
    slug(label, "snapshot label")
    manifest = load_fixture(name)
    db = existing_db(manifest)
    evidence = evidence_root(manifest["fixture_id"])
    fail_unless(evidence.is_dir() and not evidence.is_symlink(), "evidence root missing/symlinked")
    snapshots = evidence / "snapshots"
    fail_unless(not snapshots.is_symlink(), "snapshot directory is symlinked")
    snapshots.mkdir(exist_ok=True, mode=0o700)
    target = snapshots / f"{label}.sqlite3"
    fail_unless(not target.exists() and not target.is_symlink(), "snapshot label already exists")
    temporary = snapshots / f"{label}.sqlite3.tmp"
    fail_unless(not temporary.exists() and not temporary.is_symlink(), "snapshot temporary file exists")
    try:
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=3) as source:
            with sqlite3.connect(temporary, timeout=3) as destination:
                source.backup(destination, pages=1000, sleep=0.05)
        temporary.chmod(0o600)
        check_sqlite(temporary)
        os.replace(temporary, target)
        write_json(snapshots / f"{label}.json", {
            "fixture_id": manifest["fixture_id"], "workspace_id": manifest["workspace_id"],
            "sha256": sha256(target), "created_at": now(), "source_sha": manifest["source_sha"],
        })
    finally:
        temporary.unlink(missing_ok=True)
    return target


def restore_fixture(name, label):
    slug(label, "snapshot label")
    fail_unless(name == selected_name(), "restore is limited to the selected fixture")
    manifest = load_fixture(name)
    ensure_stopped(manifest)
    db = existing_db(manifest)
    snapshots = evidence_root(manifest["fixture_id"]) / "snapshots"
    fail_unless(not snapshots.is_symlink(), "snapshot directory is symlinked")
    snap = snapshots / f"{label}.sqlite3"
    meta = read_json(snapshots / f"{label}.json")
    fail_unless(snap.is_file() and not snap.is_symlink() and
                meta.get("fixture_id") == manifest["fixture_id"] and
                meta.get("workspace_id") == manifest["workspace_id"] and
                meta.get("sha256") == sha256(snap), "snapshot ownership or hash mismatch")
    check_sqlite(snap)
    with sqlite3.connect(snap.as_uri() + "?mode=ro", uri=True, timeout=3) as source:
        with sqlite3.connect(db, timeout=3) as destination:
            source.backup(destination, pages=1000, sleep=0.05)
    check_sqlite(db)
    return db


def scrub(value, token):
    if isinstance(value, str):
        value = value.replace(token, "[redacted]")
        return re.sub(r"(?i)Bearer\s+[^\s\"']+", "Bearer [redacted]", value)
    if isinstance(value, list):
        return [scrub(item, token) for item in value]
    if isinstance(value, dict):
        return {key: "[redacted]" if any(word in key.lower() for word in
                                    ("token", "secret", "password", "private_key", "authorization"))
                else scrub(item, token) for key, item in value.items()}
    return value


def record_result(name, case_id, outcome, commands, details):
    fail_unless(bool(CASE.fullmatch(case_id)), "invalid case ID")
    fail_unless(outcome in OUTCOMES, "invalid outcome")
    manifest = load_fixture(name)
    evidence = evidence_root(manifest["fixture_id"])
    fail_unless(evidence.is_dir() and not evidence.is_symlink(), "evidence root missing/symlinked")
    report = evidence / f"{case_id}.json"
    fail_unless(not report.exists() and not report.is_symlink(), "case report already exists")
    result = {"case_id": case_id, "source_sha": manifest["source_sha"],
              "source_dirty": manifest["source_dirty"], "workspace_id": manifest["workspace_id"],
              "fixture_id": manifest["fixture_id"], "binary_sha256": manifest["binary_sha256"],
              "timestamp": now(), "outcome": outcome, "commands": commands, "details": details}
    write_json(report, scrub(result, token_for(name)))
    return report


def attach_evidence(name, label, source):
    slug(label, "evidence label")
    manifest = load_fixture(name)
    source = Path(source)
    fail_unless(source.is_file() and not source.is_symlink() and source.stat().st_size <= 32 * 1024 * 1024,
                "source evidence must be a regular file of at most 32 MiB")
    fail_unless(not source.resolve().is_relative_to(fixture_root(name).resolve()),
                "copy a sanitized artifact outside the fixture; raw fixture files are refused")
    with source.open("rb") as input_file:
        content = input_file.read(32 * 1024 * 1024 + 1)
    fail_unless(len(content) <= 32 * 1024 * 1024, "source evidence exceeded 32 MiB")
    fail_unless(token_for(name).encode() not in content and
                not re.search(rb"(?i)Authorization\s*:|Bearer\s+\S+|-----BEGIN [A-Z ]*PRIVATE KEY-----", content),
                "credential-looking content cannot be retained as evidence")
    evidence = evidence_root(manifest["fixture_id"])
    fail_unless(evidence.is_dir() and not evidence.is_symlink(), "evidence root missing/symlinked")
    target = evidence / f"{label}{source.suffix}"
    fail_unless(not target.exists() and not target.is_symlink(), "evidence label already exists")
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(content)
    return target


def process_stat(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[0], fields[19]
    except (OSError, IndexError):
        return None


def process_start(pid):
    details = process_stat(pid)
    return details[1] if details else None


def owned_process_running(manifest):
    pid, started, binary = manifest.get("pid"), manifest.get("pid_start"), manifest.get("binary_path")
    if not isinstance(pid, int) or not started or not binary:
        return False
    details = process_stat(pid)
    if not details or details[0] == "Z" or details[1] != started:
        return False
    try:
        executable = (Path(f"/proc/{pid}/exe").resolve(strict=True))
        command = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        arguments = [part.decode("utf-8") for part in command if part]
        position = arguments.index("--config")
    except (OSError, UnicodeDecodeError, ValueError):
        return False
    return (executable == Path(binary).resolve(strict=True) and
            position + 1 < len(arguments) and arguments[position + 1] == manifest["config_path"] and
            arguments[-1] == "serve")


def recover_pending(manifest):
    """Adopt only our exact spawned process if interrupted before saving its PID."""
    if manifest.get("pid") is not None or not manifest.get("launch_id"):
        return manifest
    expected = {f'LUMEN_QA_LAUNCH_ID={manifest["launch_id"]}'.encode(),
                f'LUMEN_BEARER_TOKEN={token_for(manifest["name"])}'.encode()}
    matches = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            environment = set((entry / "environ").read_bytes().split(b"\0"))
        except OSError:
            continue
        if expected.issubset(environment):
            candidate = {**manifest, "pid": int(entry.name), "pid_start": process_start(int(entry.name))}
            if owned_process_running(candidate):
                matches.append(candidate)
    fail_unless(len(matches) <= 1, "multiple processes match this fixture launch identity")
    if matches:
        manifest = matches[0]
        write_json(fixture_root(manifest["name"]) / "manifest.json", manifest)
    return manifest


def stop_fixture(name):
    manifest = recover_pending(load_fixture(name))
    pid = manifest.get("pid")
    if pid is None:
        return {"running": False, "port_free": port_free(manifest["port"])}
    details = process_stat(pid)
    if details and details[0] != "Z" and not owned_process_running(manifest):
        raise QaError("recorded PID exists but no longer matches the owned process; refusing signal")
    if owned_process_running(manifest):
        os.kill(pid, signal.SIGINT)
        deadline = time.monotonic() + 10
        while owned_process_running(manifest) and time.monotonic() < deadline:
            time.sleep(0.1)
        fail_unless(not owned_process_running(manifest), "owned process did not exit within 10 seconds")
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass  # a later shell is not the process's parent
    manifest["pid"] = None
    manifest["pid_start"] = None
    save_manifest(name, manifest)
    return {"running": False, "port_free": port_free(manifest["port"])}


def port_free(port):
    with socket.socket() as connection:
        connection.settimeout(0.5)
        return connection.connect_ex(("127.0.0.1", port)) != 0


def readiness(manifest, token):
    url = (f'http://127.0.0.1:{manifest["port"]}/api/v1/workspaces/'
           f'{manifest["workspace_id"]}/runtime/capabilities')
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urlopen(request, timeout=2) as response:
            fail_unless(response.status == 200, f"readiness HTTP {response.status}")
            raw = response.read(65537)
    except HTTPError as error:
        error.close()
        raise QaError(f"readiness HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise QaError(f"readiness unavailable: {type(error).__name__}") from error
    fail_unless(len(raw) <= 65536, "readiness response exceeded 64 KiB")
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError) as error:
        raise QaError("readiness response is not JSON") from error
    fail_unless(isinstance(body, dict) and body.get("server") == "listening" and
                body.get("workspace") == "ready", "readiness response is not ready")
    return scrub(body, token)


def inspect_approval(manifest, token, run_id, kind):
    try:
        run_id = str(uuid.UUID(run_id))
    except (ValueError, AttributeError) as error:
        raise QaError("run ID must be a UUID") from error
    fail_unless(isinstance(kind, str) and bool(re.fullmatch(r"[a-z0-9._-]{1,128}", kind)),
                "expected action kind is invalid")
    url = f'http://127.0.0.1:{manifest["port"]}/api/v1/workspaces/{manifest["workspace_id"]}/approvals'
    request = Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    try:
        with urlopen(request, timeout=3) as response:
            raw = response.read(1024 * 1024 + 1)
    except HTTPError as error:
        error.close()
        raise QaError(f"approvals HTTP {error.code}") from error
    except (URLError, TimeoutError, OSError) as error:
        raise QaError(f"approvals unavailable: {type(error).__name__}") from error
    fail_unless(len(raw) <= 1024 * 1024, "approvals response exceeded 1 MiB")
    try:
        body = json.loads(raw)
        server_time = body["server_time"]
        approvals = body["approvals"]
    except (ValueError, KeyError, TypeError) as error:
        raise QaError("invalid approvals response") from error
    fail_unless(isinstance(server_time, int) and isinstance(approvals, list),
                "invalid approvals response")
    matches = [item for item in approvals if isinstance(item, dict) and
               item.get("run_id") == run_id and item.get("kind") == kind]
    fail_unless(len(matches) == 1, "expected exactly one approval for the known run/action")
    approval = matches[0]
    fail_unless(isinstance(approval.get("expires_at"), int) and
                approval["expires_at"] > server_time, "selected approval has expired")
    fail_unless(isinstance(approval.get("fingerprint"), str) and "arguments" in approval and
                isinstance(approval.get("capabilities"), list), "selected approval preview is incomplete")
    return scrub({key: approval[key] for key in
                  ("approval_id", "run_id", "kind", "expires_at", "fingerprint", "arguments", "capabilities")}, token)


def ensure_stopped(manifest):
    manifest = recover_pending(manifest)
    pid = manifest.get("pid")
    if pid is not None:
        details = process_stat(pid)
        fail_unless(not details or details[0] == "Z", "recorded PID is live; stop or investigate before mutation")
    fail_unless(port_free(manifest["port"]), "selected port is occupied; refusing destructive fixture mutation")


def start_fixture(name):
    manifest = recover_pending(load_fixture(name))
    fail_unless(not manifest["source_dirty"], "start requires a clean source revision")
    fail_unless(source_state() == (manifest["source_sha"], False),
                "source revision or worktree changed since fixture selection")
    fail_unless(not owned_process_running(manifest), "owned server is already running")
    if manifest.get("pid") is not None:
        ensure_stopped(manifest)
    binary = Path(manifest.get("binary_path") or "")
    fail_unless(binary.is_file() and not binary.is_symlink() and
                manifest.get("binary_sha256") == sha256(binary), "built binary missing or changed; rebuild")
    fail_unless(port_free(manifest["port"]), "selected port is occupied; refusing to target another service")
    token = token_for(name)
    evidence = evidence_root(manifest["fixture_id"])
    log = evidence / "server.log"
    environment = os.environ.copy()
    environment["LUMEN_BEARER_TOKEN"] = token
    manifest["launch_id"] = str(uuid.uuid4())
    environment["LUMEN_QA_LAUNCH_ID"] = manifest["launch_id"]
    save_manifest(name, manifest)
    command = [str(binary), "--config", manifest["config_path"], "serve"]
    with log.open("a", encoding="utf-8") as output:
        pid = os.posix_spawn(str(binary), command, environment, setsid=True,
                             file_actions=[(os.POSIX_SPAWN_DUP2, output.fileno(), 1),
                                           (os.POSIX_SPAWN_DUP2, output.fileno(), 2)])
    manifest["pid"] = pid
    manifest["pid_start"] = process_start(pid)
    fail_unless(manifest["pid_start"] is not None, "server exited before PID identity was recorded")
    save_manifest(name, manifest)
    deadline = time.monotonic() + 30
    print(f"phase=starting deadline_seconds=30 pid={pid}", flush=True)
    last_error = "not ready"
    while time.monotonic() < deadline:
        if not owned_process_running(manifest):
            raise QaError(f"owned server exited before readiness; see {log}")
        try:
            ready = readiness(manifest, token)
            record_result(name, f"start-{uuid.uuid4().hex}", "pass", command,
                          {"http_status": 200, "readiness": ready, "pid": pid})
            return ready
        except QaError as error:
            last_error = str(error)
            if last_error.startswith("readiness HTTP"):
                break
        time.sleep(min(0.25, max(0, deadline - time.monotonic())))
    if owned_process_running(manifest):
        stop_fixture(name)
    raise QaError(f"readiness failed within 30 seconds: {last_error}; see {log}")


def status_fixture(name):
    manifest = recover_pending(load_fixture(name))
    running = owned_process_running(manifest)
    result = {"name": name, "fixture_id": manifest["fixture_id"],
              "workspace_id": manifest["workspace_id"], "port": manifest["port"],
              "model": manifest["model"], "source_sha": manifest["source_sha"],
              "binary_sha256": manifest["binary_sha256"], "pid": manifest["pid"],
              "running": running, "evidence_path": str(evidence_root(manifest["fixture_id"]))}
    if running:
        try:
            result["readiness"] = readiness(manifest, token_for(name))
        except QaError as error:
            result["readiness_error"] = str(error)
    else:
        result["port_free"] = port_free(manifest["port"])
    return result


def job_phase(name, job_id, revision, scheduled_for_ms):
    try:
        job_id = str(uuid.UUID(job_id))
    except (ValueError, AttributeError) as error:
        raise QaError("job ID must be a UUID") from error
    fail_unless(isinstance(scheduled_for_ms, int) and scheduled_for_ms >= 0,
                "scheduled-for must be a nonnegative epoch millisecond")
    fail_unless(isinstance(revision, int) and revision > 0, "revision must be positive")
    manifest = load_fixture(name)
    db = existing_db(manifest)
    try:
        with sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=3) as connection:
            due = connection.execute(
                "SELECT r.next_due_at, "
                "(SELECT MAX(latest.revision) FROM scheduled_job_revisions latest WHERE latest.job_id = j.job_id) "
                "FROM scheduled_jobs j "
                "JOIN scheduled_job_revisions r ON r.job_id = j.job_id "
                "WHERE j.job_id = ? AND j.workspace_id = ? AND r.revision = ?",
                (job_id, manifest["workspace_id"], revision)).fetchone()
            fail_unless(due is not None, "job revision is absent from the selected workspace")
            occurrence = connection.execute(
                "SELECT state, run_id FROM scheduled_job_runs "
                "WHERE occurrence_key = ? AND job_id = ? AND revision = ? AND scheduled_for = ?",
                (f"{job_id}:{revision}:{scheduled_for_ms}", job_id, revision, scheduled_for_ms)).fetchone()
            if occurrence:
                state, run_id = occurrence
                if state == "succeeded":
                    run = connection.execute(
                        "SELECT state FROM agent_runs WHERE id = ? AND workspace_id = ?",
                        (run_id, manifest["workspace_id"])).fetchone() if run_id else None
                    phase = "completed" if run == ("completed",) else "inconsistent"
                else:
                    phase = state if state in ("claimed", "running", "failed", "cancelled", "unknown") else "inconsistent"
                return {"phase": phase, "job_id": job_id, "revision": revision,
                        "scheduled_for_ms": scheduled_for_ms,
                        "run_id": run_id}
            phase = ("not_scheduled" if revision != due[1] or due[0] != scheduled_for_ms
                     else "due" if scheduled_for_ms <= int(time.time() * 1000) else "scheduled")
            return {"phase": phase, "job_id": job_id, "revision": revision,
                    "scheduled_for_ms": scheduled_for_ms,
                    "run_id": None}
    except sqlite3.Error as error:
        raise QaError(f"job state query failed: {error}") from error


def poll_job(name, job_id, revision, scheduled_for_ms, seconds):
    fail_unless(isinstance(seconds, int) and 0 <= seconds <= 600, "poll deadline must be 0–600 seconds")
    deadline = time.monotonic() + seconds
    observations = []
    last = None
    while True:
        state = job_phase(name, job_id, revision, scheduled_for_ms)
        if state["phase"] != last:
            print(f'phase={state["phase"]} deadline_seconds_remaining={max(0, int(deadline - time.monotonic()))}',
                  flush=True)
            observations.append({"at": now(), **state})
            last = state["phase"]
        if state["phase"] in ("completed", "failed", "cancelled", "unknown", "inconsistent", "not_scheduled"):
            outcome = "pass" if state["phase"] == "completed" else "fail"
            report = record_result(name, f"poll-{uuid.uuid4().hex}", outcome,
                                   [f"poll-job {job_id} {revision} {scheduled_for_ms} {seconds}"],
                                   {"observations": observations})
            fail_unless(outcome == "pass", f'job entered {state["phase"]}; see {report}')
            return state
        if time.monotonic() >= deadline:
            report = record_result(name, f"poll-{uuid.uuid4().hex}", "inconclusive",
                                   [f"poll-job {job_id} {revision} {scheduled_for_ms} {seconds}"],
                                   {"observations": observations, "limit": "deadline expired"})
            raise QaError(f"poll deadline expired without completion; see {report}")
        time.sleep(min(0.5, deadline - time.monotonic()))


def cleanup_fixture(name):
    fail_unless(name == selected_name(), "cleanup is limited to the selected fixture")
    manifest = load_fixture(name)
    ensure_stopped(manifest)
    root = fixture_root(name)
    fail_unless(not any(path.is_symlink() for path in root.rglob("*")), "fixture contains a symlink")
    shutil.rmtree(root)
    selected = BASE / "selected.json"
    if selected.exists() and selected_name() == name:
        selected.unlink()
    return evidence_root(manifest["fixture_id"])


def arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    initialize = commands.add_parser("init", help="create or reselect a disposable WSL fixture")
    initialize.add_argument("--name", required=True)
    initialize.add_argument("--source-sha", required=True)
    initialize.add_argument("--source-dirty", action="store_true")
    initialize.add_argument("--model", default="qwen3:4b")
    initialize.add_argument("--endpoint", default="http://127.0.0.1:11434/v1/")
    initialize.add_argument("--port", type=int, default=0)
    chosen = commands.add_parser("select", help="select an existing named fixture")
    chosen.add_argument("name")
    for command in ("build", "start", "status", "stop", "connection", "snapshot", "restore",
                    "poll-job", "approval-check", "record", "attach", "cleanup"):
        sub = commands.add_parser(command)
        sub.add_argument("--name", help="default: selected fixture")
        if command in ("snapshot", "restore"):
            sub.add_argument("--label", required=True)
        if command in ("restore", "cleanup"):
            sub.add_argument("--confirm", required=True, help="exact selected fixture ID")
        if command == "poll-job":
            sub.add_argument("--job-id", required=True)
            sub.add_argument("--revision", type=int, required=True)
            sub.add_argument("--scheduled-for-ms", type=int, required=True)
            sub.add_argument("--seconds", type=int, default=120)
        if command == "approval-check":
            sub.add_argument("--run-id", required=True)
            sub.add_argument("--kind", required=True)
        if command == "record":
            sub.add_argument("--case", required=True)
            sub.add_argument("--outcome", required=True, choices=sorted(OUTCOMES))
            sub.add_argument("--command", dest="record_commands", action="append", default=[])
            sub.add_argument("--details", default="{}", help="JSON with no raw credentials")
        if command == "attach":
            sub.add_argument("--label", required=True)
            sub.add_argument("--file", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    try:
        fail_unless(sys.platform == "linux" and
                    ("microsoft" in Path("/proc/version").read_text().lower() or
                     bool(os.environ.get("WSL_INTEROP"))), "run this helper in WSL Linux")
        fail_unless(not str(Path.home().resolve()).startswith("/mnt/"),
                    "WSL home must be on the Linux filesystem, not a Windows mount")
        if args.command == "init":
            result = init_fixture(args.name, args.source_sha, args.source_dirty,
                                  args.model, args.endpoint, args.port)
        elif args.command == "select":
            select_fixture(args.name)
            result = status_fixture(args.name)
        else:
            name = args.name or selected_name()
            if args.command == "build":
                result = build_fixture(name)
            elif args.command == "start":
                result = start_fixture(name)
            elif args.command == "status":
                result = status_fixture(name)
            elif args.command == "stop":
                result = stop_fixture(name)
            elif args.command == "connection":
                manifest = load_fixture(name)
                result = {"workspace_id": manifest["workspace_id"],
                          "url": f'http://127.0.0.1:{manifest["port"]}',
                          "token_path": str(fixture_root(name) / "token"),
                          "note": "Read token locally only for the browser; never put it in a URL or report."}
            elif args.command == "snapshot":
                result = {"snapshot": str(snapshot_fixture(name, args.label))}
            elif args.command == "restore":
                manifest = load_fixture(name)
                fail_unless(args.confirm == manifest["fixture_id"], "confirmation fixture ID mismatch")
                result = {"restored": str(restore_fixture(name, args.label))}
            elif args.command == "poll-job":
                result = poll_job(name, args.job_id, args.revision, args.scheduled_for_ms, args.seconds)
            elif args.command == "approval-check":
                result = inspect_approval(load_fixture(name), token_for(name), args.run_id, args.kind)
            elif args.command == "record":
                try:
                    details = json.loads(args.details)
                except ValueError as error:
                    raise QaError("--details must be JSON") from error
                result = {"report": str(record_result(name, args.case, args.outcome,
                                                       args.record_commands, details))}
            elif args.command == "attach":
                result = {"evidence": str(attach_evidence(name, args.label, args.file))}
            else:
                manifest = load_fixture(name)
                fail_unless(args.confirm == manifest["fixture_id"], "confirmation fixture ID mismatch")
                result = {"evidence_retained": str(cleanup_fixture(name))}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if not (args.command == "status" and result.get("readiness_error")) else 1
    except (QaError, OSError, sqlite3.Error) as error:
        print(f"qa launcher error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
