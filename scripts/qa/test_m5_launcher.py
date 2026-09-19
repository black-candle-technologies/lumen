"""Behavior checks for the owned M5 QA fixture, evidence, and recovery paths."""

import json
import io
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
import uuid
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch

import m5_launcher as qa


SHA = "a" * 40


def is_wsl():
    if sys.platform != "linux":
        return False
    try:
        version = Path("/proc/version").read_text().lower()
    except OSError:
        return False
    return "microsoft" in version or bool(os.environ.get("WSL_INTEROP"))


def symlink_tests_supported():
    # Windows runners commonly lack the Developer Mode/privilege required to
    # create symlinks.  The non-symlink helper contract remains portable.
    return sys.platform != "win32" or bool(os.environ.get("LUMEN_M5_WINDOWS_SYMLINK_TESTS"))


class LauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name) / "qa"
        self.base_patch = patch.object(qa, "BASE", self.base)
        self.base_patch.start()
        self.addCleanup(self.base_patch.stop)

    def init(self, name="sample"):
        return qa.init_fixture(name, SHA, False, "qwen3:4b", "http://127.0.0.1:11434/v1/", 0)

    def test_selected_fixture_reuses_identity_and_keeps_token_out_of_manifest(self):
        first = self.init()
        again = self.init()
        self.assertEqual(first["fixture_id"], again["fixture_id"])
        self.assertEqual(first["workspace_id"], again["workspace_id"])
        self.assertEqual(qa.selected_name(), "sample")
        token = (self.base / "fixtures" / "sample" / "token").read_text().strip()
        self.assertTrue(token)
        self.assertEqual((self.base / "fixtures" / "sample" / "token").stat().st_mode & 0o777, 0o600)
        self.assertNotIn(token, json.dumps(first))
        self.assertNotIn(token, (self.base / "fixtures" / "sample" / "lumen.toml").read_text())
        self.assertTrue((self.base / "evidence" / first["fixture_id"]).is_dir())

    def test_interrupted_initialization_can_retry_without_partial_named_fixture(self):
        original_write = qa.write_json

        def interrupted_write(path, value):
            if path.name == "manifest.json":
                raise qa.QaError("injected init interruption")
            return original_write(path, value)

        with patch.object(qa, "write_json", side_effect=interrupted_write):
            with self.assertRaises(qa.QaError):
                self.init()
        self.assertFalse((self.base / "fixtures" / "sample").exists())
        self.assertEqual(self.init()["name"], "sample")

    @unittest.skipUnless(symlink_tests_supported(), "Windows symlink privilege is unavailable")
    def test_retry_reclaims_only_a_marked_interrupted_stage_with_token(self):
        fixture = self.init()
        stage = self.base / "fixtures" / f".sample.init-{uuid.uuid4().hex}"
        stage.mkdir()
        qa.write_json(stage / "owner.json", {"name": "sample", "fixture_id": fixture["fixture_id"]})
        qa.write_json(stage / "manifest.json", fixture)
        (stage / "token").write_text("orphan-test-token")
        qa.init_fixture("sample", SHA, False, "qwen3:4b", "http://127.0.0.1:11434/v1/", 0)
        self.assertFalse(stage.exists())
        foreign = self.base / "fixtures" / f".sample.init-{uuid.uuid4().hex}"
        foreign.symlink_to(self.base / "evidence", target_is_directory=True)
        with self.assertRaises(qa.QaError):
            qa.init_fixture("sample", SHA, False, "qwen3:4b", "http://127.0.0.1:11434/v1/", 0)
        self.assertTrue(foreign.is_symlink())

    @unittest.skipUnless(symlink_tests_supported(), "Windows symlink privilege is unavailable")
    def test_invalid_name_and_symlinked_fixture_are_refused_without_cleanup(self):
        with self.assertRaises(qa.QaError):
            self.init("../outside")
        foreign = Path(self.temporary.name) / "foreign"
        foreign.mkdir()
        (foreign / "keep").write_text("safe")
        (self.base / "fixtures").mkdir(parents=True)
        (self.base / "fixtures" / "linked").symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(qa.QaError):
            qa.cleanup_fixture("linked")
        self.assertEqual((foreign / "keep").read_text(), "safe")

    @unittest.skipUnless(symlink_tests_supported(), "Windows symlink privilege is unavailable")
    def test_symlinked_fixture_parent_is_refused_without_writing_outside_base(self):
        foreign = Path(self.temporary.name) / "foreign-parent"
        foreign.mkdir()
        self.base.mkdir()
        (self.base / "fixtures").symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(qa.QaError):
            self.init("outside")
        self.assertFalse((foreign / "outside").exists())

    def test_cleanup_retains_evidence_and_refuses_bad_marker(self):
        fixture = self.init()
        root = self.base / "fixtures" / "sample"
        marker = root / "owner.json"
        marker.write_text('{"fixture_id":"not-mine"}')
        with self.assertRaises(qa.QaError):
            qa.cleanup_fixture("sample")
        self.assertTrue(root.exists())
        marker.write_text(json.dumps({"fixture_id": fixture["fixture_id"]}))
        qa.cleanup_fixture("sample")
        self.assertFalse(root.exists())
        self.assertTrue((self.base / "evidence" / fixture["fixture_id"]).exists())

    def test_restore_and_cleanup_refuse_an_occupied_selected_port_without_pid(self):
        fixture = self.init()
        db = Path(fixture["database_path"])
        with sqlite3.connect(db) as connection:
            connection.execute("CREATE TABLE proof (value TEXT)")
        qa.snapshot_fixture("sample", "healthy")
        with socket.socket() as foreign:
            foreign.bind(("127.0.0.1", fixture["port"]))
            foreign.listen()
            with self.assertRaises(qa.QaError):
                qa.restore_fixture("sample", "healthy")
            with self.assertRaises(qa.QaError):
                qa.cleanup_fixture("sample")
        self.assertTrue(db.exists())

    def test_destructive_commands_refuse_a_named_but_unselected_fixture(self):
        first = self.init("first")
        self.init("second")
        with self.assertRaises(qa.QaError):
            qa.cleanup_fixture("first")
        self.assertTrue((self.base / "fixtures" / "first").exists())
        qa.select_fixture("first")
        qa.cleanup_fixture("first")
        self.assertTrue((self.base / "evidence" / first["fixture_id"]).exists())

    def test_live_wal_snapshot_restores_committed_rows_without_main_file_copy(self):
        fixture = self.init()
        db = Path(fixture["database_path"])
        writer = sqlite3.connect(db)
        self.addCleanup(writer.close)
        writer.execute("PRAGMA journal_mode=WAL")
        writer.execute("CREATE TABLE proof (value TEXT)")
        writer.execute("INSERT INTO proof VALUES ('healthy')")
        writer.commit()
        self.assertTrue(Path(str(db) + "-wal").exists())
        snap = qa.snapshot_fixture("sample", "healthy")
        with sqlite3.connect(snap) as saved:
            self.assertEqual(saved.execute("SELECT value FROM proof").fetchall(), [("healthy",)])
        writer.close()
        with sqlite3.connect(db) as changed:
            changed.execute("DELETE FROM proof")
            changed.commit()
        qa.restore_fixture("sample", "healthy")
        with sqlite3.connect(db) as restored:
            self.assertEqual(restored.execute("SELECT value FROM proof").fetchall(), [("healthy",)])

    def test_missing_database_does_not_create_empty_snapshot_source(self):
        fixture = self.init()
        db = Path(fixture["database_path"])
        with self.assertRaises(qa.QaError):
            qa.snapshot_fixture("sample", "healthy")
        self.assertFalse(db.exists())

    @unittest.skipUnless(symlink_tests_supported(), "Windows symlink privilege is unavailable")
    def test_snapshot_refuses_symlinked_snapshot_directory(self):
        fixture = self.init()
        with sqlite3.connect(fixture["database_path"]) as connection:
            connection.execute("CREATE TABLE proof (value TEXT)")
        outside = Path(self.temporary.name) / "outside-snapshots"
        outside.mkdir()
        evidence = self.base / "evidence" / fixture["fixture_id"]
        (evidence / "snapshots").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(qa.QaError):
            qa.snapshot_fixture("sample", "healthy")
        self.assertEqual(list(outside.iterdir()), [])

    def test_record_redacts_secret_and_rejects_unsafe_evidence_path(self):
        fixture = self.init()
        token = (self.base / "fixtures" / "sample" / "token").read_text().strip()
        report = qa.record_result("sample", "G02", "pass", ["curl Authorization: Bearer " + token], {"body": token})
        self.assertNotIn(token, report.read_text())
        self.assertIn("[redacted]", report.read_text())
        self.assertEqual(json.loads(report.read_text())["source_sha"], SHA)
        first_bytes = report.read_bytes()
        with self.assertRaises(qa.QaError):
            qa.record_result("sample", "G02", "fail", ["second"], {})
        self.assertEqual(report.read_bytes(), first_bytes)
        with self.assertRaises(qa.QaError):
            qa.attach_evidence("sample", "../outside", Path(__file__))

    def test_attach_refuses_own_token_and_bearer_material(self):
        fixture = self.init()
        root = self.base / "fixtures" / "sample"
        token = root / "token"
        evidence = self.base / "evidence" / fixture["fixture_id"]
        with self.assertRaises(qa.QaError):
            qa.attach_evidence("sample", "copied-token", token)
        other = Path(self.temporary.name) / "response.txt"
        other.write_text("Authorization: Bearer another-secret")
        with self.assertRaises(qa.QaError):
            qa.attach_evidence("sample", "copied-response", other)
        self.assertFalse((evidence / "copied-token").exists())
        self.assertFalse((evidence / "copied-response.txt").exists())
        other.write_text("synthetic response without credentials")
        self.assertEqual(qa.attach_evidence("sample", "clean-response", other).read_text(),
                         "synthetic response without credentials")

    def test_malformed_manifest_fails_visibly(self):
        self.init()
        (self.base / "fixtures" / "sample" / "manifest.json").write_text("[]")
        with self.assertRaises(qa.QaError):
            qa.load_fixture("sample")

    @unittest.skipUnless(symlink_tests_supported(), "Windows symlink privilege is unavailable")
    def test_changed_runtime_path_and_symlinked_workspace_are_refused_before_start(self):
        fixture = self.init()
        root = self.base / "fixtures" / "sample"
        config = root / "lumen.toml"
        original = config.read_text()
        config.write_text(original.replace(str(root / "data"), str(Path(self.temporary.name) / "foreign")))
        with self.assertRaises(qa.QaError):
            qa.load_fixture("sample")
        config.write_text(original)
        (root / "workspace").rmdir()
        foreign = Path(self.temporary.name) / "foreign"
        foreign.mkdir()
        (root / "workspace").symlink_to(foreign, target_is_directory=True)
        with self.assertRaises(qa.QaError):
            qa.load_fixture("sample")

    def test_stop_signals_only_a_fresh_matching_owned_process(self):
        fixture = self.init()
        config = fixture["config_path"]
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)",
                                  "--config", config, "serve"])
        self.addCleanup(lambda: child.poll() is None and child.kill())
        fixture.update(binary_path=sys.executable, pid=child.pid, pid_start=qa.process_start(child.pid))
        qa.save_manifest("sample", fixture)
        self.assertTrue(qa.owned_process_running(fixture))
        fixture["pid_start"] = "wrong-start-time"
        qa.save_manifest("sample", fixture)
        with self.assertRaises(qa.QaError):
            qa.stop_fixture("sample")
        self.assertIsNone(child.poll())
        fixture["pid_start"] = qa.process_start(child.pid)
        qa.save_manifest("sample", fixture)
        qa.stop_fixture("sample")
        child.wait(timeout=5)
        self.assertIsNotNone(child.returncode)

    def test_build_uses_stable_target_once_and_records_binary_hash(self):
        self.init()
        target = Path(self.temporary.name) / "cargo-target"
        fake = Path(self.temporary.name) / "fake-cargo"
        count = Path(self.temporary.name) / "build-count"
        fake.write_text("#!/bin/sh\nmkdir -p \"$CARGO_TARGET_DIR/debug\"\n"
                        f"printf x >> '{count}'\n"
                        "printf 'owned binary' > \"$CARGO_TARGET_DIR/debug/lumen\"\n")
        fake.chmod(0o700)
        with patch.object(qa, "TARGET", target), patch.object(qa, "CARGO", str(fake)), \
             patch.object(qa, "source_state", return_value=(SHA, False)):
            first = qa.build_fixture("sample")
            second = qa.build_fixture("sample")
        self.assertFalse(first["reused"])
        self.assertTrue(second["reused"])
        self.assertEqual(count.read_text(), "x")
        self.assertEqual(len(qa.load_fixture("sample")["binary_sha256"]), 64)

    def test_build_refuses_source_changed_since_fixture_selection(self):
        self.init()
        with patch.object(qa, "source_state", return_value=("b" * 40, False)):
            with self.assertRaises(qa.QaError):
                qa.build_fixture("sample")

    def test_readiness_requires_auth_and_exact_workspace_without_echoing_token(self):
        fixture = self.init()
        token = qa.token_for("sample")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                authorized = self.headers.get("Authorization") == f"Bearer {token}"
                correct_path = self.path == (f"/api/v1/workspaces/{fixture['workspace_id']}"
                                             "/runtime/capabilities")
                self.send_response(200 if authorized and correct_path else 403)
                self.end_headers()
                self.wfile.write(b'{"server":"listening","workspace":"ready","model":"not_checked"}')

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        fixture["port"] = server.server_port
        self.assertEqual(qa.readiness(fixture, token)["workspace"], "ready")
        with self.assertRaises(qa.QaError) as error:
            qa.readiness(fixture, "wrong")
        self.assertNotIn(token, str(error.exception))

    @unittest.skipUnless(os.environ.get("LUMEN_M5_QA_TEST_BINARY"), "set LUMEN_M5_QA_TEST_BINARY for owned live server test")
    def test_real_owned_server_starts_resumes_and_stops_without_token_in_evidence(self):
        fixture = self.init()
        binary = Path(os.environ["LUMEN_M5_QA_TEST_BINARY"])
        fixture.update(binary_path=str(binary), binary_sha256=qa.sha256(binary))
        qa.save_manifest("sample", fixture)
        try:
            with patch.object(qa, "source_state", return_value=(SHA, False)):
                started = qa.start_fixture("sample")
                self.assertEqual(started["workspace"], "ready")
                self.assertTrue(qa.status_fixture("sample")["running"])
        finally:
            qa.stop_fixture("sample")
        self.assertFalse(qa.status_fixture("sample")["running"])
        log = self.base / "evidence" / fixture["fixture_id"] / "server.log"
        self.assertNotIn(qa.token_for("sample"), log.read_text())

    @unittest.skipUnless(os.environ.get("LUMEN_M5_QA_TEST_BINARY"), "set LUMEN_M5_QA_TEST_BINARY for owned live server test")
    def test_interrupted_spawn_is_recovered_only_with_matching_launch_identity(self):
        fixture = self.init()
        binary = Path(os.environ["LUMEN_M5_QA_TEST_BINARY"])
        fixture.update(binary_path=str(binary), binary_sha256=qa.sha256(binary),
                       launch_id=str(uuid.uuid4()))
        qa.save_manifest("sample", fixture)
        environment = os.environ.copy()
        environment["LUMEN_BEARER_TOKEN"] = qa.token_for("sample")
        environment["LUMEN_QA_LAUNCH_ID"] = fixture["launch_id"]
        process = subprocess.Popen([str(binary), "--config", fixture["config_path"], "serve"],
                                   env=environment, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)
        try:
            with patch.object(qa, "port_free", return_value=True):
                with self.assertRaisesRegex(qa.QaError, "recorded PID is live"):
                    qa.cleanup_fixture("sample")
            self.assertTrue(qa.status_fixture("sample")["running"])
            self.assertEqual(qa.load_fixture("sample")["pid"], process.pid)
            qa.stop_fixture("sample")
            process.wait(timeout=10)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

    def test_poll_job_distinguishes_due_claimed_running_and_terminal_state(self):
        fixture = self.init()
        job_id = "c4c4c4c4-1111-4111-8111-111111111111"
        run_id = "d5d5d5d5-2222-4222-8222-222222222222"
        db = Path(fixture["database_path"])
        with sqlite3.connect(db) as connection:
            connection.execute("CREATE TABLE scheduled_jobs (job_id TEXT, workspace_id TEXT)")
            connection.execute("CREATE TABLE scheduled_job_revisions (job_id TEXT, revision INTEGER, next_due_at INTEGER)")
            connection.execute("CREATE TABLE scheduled_job_runs (occurrence_key TEXT, job_id TEXT, revision INTEGER, scheduled_for INTEGER, state TEXT, run_id TEXT)")
            connection.execute("CREATE TABLE agent_runs (id TEXT, workspace_id TEXT, state TEXT)")
            connection.execute("INSERT INTO scheduled_jobs VALUES (?, ?)", (job_id, fixture["workspace_id"]))
            connection.execute("INSERT INTO scheduled_job_revisions VALUES (?, 1, 1)", (job_id,))
        self.assertEqual(qa.job_phase("sample", job_id, 1, 1)["phase"], "due")
        with self.assertRaisesRegex(qa.QaError, "deadline expired"):
            qa.poll_job("sample", job_id, 1, 1, 0)
        reports = list((self.base / "evidence" / fixture["fixture_id"]).glob("poll-*.json"))
        self.assertEqual(len(reports), 1)
        self.assertEqual(json.loads(reports[0].read_text())["outcome"], "inconclusive")
        with sqlite3.connect(db) as connection:
            connection.execute("INSERT INTO scheduled_job_runs VALUES (?, ?, 1, 1, 'claimed', NULL)",
                               (f"{job_id}:1:1", job_id))
        self.assertEqual(qa.job_phase("sample", job_id, 1, 1)["phase"], "claimed")
        with sqlite3.connect(db) as connection:
            connection.execute("UPDATE scheduled_job_runs SET state='running', run_id=?", (run_id,))
            connection.execute("INSERT INTO agent_runs VALUES (?, ?, 'running')", (run_id, fixture["workspace_id"]))
        self.assertEqual(qa.job_phase("sample", job_id, 1, 1)["phase"], "running")
        with sqlite3.connect(db) as connection:
            connection.execute("UPDATE scheduled_job_runs SET state='succeeded'")
        self.assertEqual(qa.job_phase("sample", job_id, 1, 1)["phase"], "inconsistent")
        with sqlite3.connect(db) as connection:
            connection.execute("UPDATE agent_runs SET state='completed'")
        self.assertEqual(qa.job_phase("sample", job_id, 1, 1)["phase"], "completed")
        with sqlite3.connect(db) as connection:
            connection.execute("INSERT INTO scheduled_job_revisions VALUES (?, 2, 1)", (job_id,))
        self.assertEqual(qa.job_phase("sample", job_id, 2, 1)["phase"], "due")
        with sqlite3.connect(db) as connection:
            connection.execute("UPDATE scheduled_job_revisions SET next_due_at=2")
        self.assertEqual(qa.job_phase("sample", job_id, 1, 2)["phase"], "not_scheduled")
        with sqlite3.connect(db) as connection:
            connection.execute("UPDATE scheduled_job_runs SET state='failed'")
            connection.execute("UPDATE agent_runs SET state='failed'")
        self.assertEqual(qa.job_phase("sample", job_id, 1, 1)["phase"], "failed")
        with self.assertRaises(qa.QaError):
            qa.job_phase("sample", "", 1, 1)

    def test_approval_inspection_selects_one_live_exact_run_and_kind(self):
        fixture = self.init()
        run_id = "e6e6e6e6-3333-4333-8333-333333333333"
        other = "f7f7f7f7-4444-4444-8444-444444444444"
        token = qa.token_for("sample")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path != f"/api/v1/workspaces/{fixture['workspace_id']}/approvals":
                    self.send_response(404)
                    self.end_headers()
                    return
                if self.headers.get("Authorization") != f"Bearer {token}":
                    self.send_response(401)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({"server_time": 1000, "approvals": [
                    {"approval_id": other, "run_id": other, "kind": "schedule.job.create", "expires_at": 5000,
                     "created_at": 500, "fingerprint": "other", "arguments": {}, "capabilities": [], "secret_references": []},
                    {"approval_id": run_id, "run_id": run_id, "kind": "schedule.job.create", "expires_at": 5000,
                     "created_at": 500, "fingerprint": "expected-fingerprint",
                     "arguments": {"job_id": other, "prompt": "synthetic"},
                     "capabilities": [{"name": "schedule.create"}], "secret_references": []},
                ]}).encode())

            def log_message(self, *_args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        self.addCleanup(server.server_close)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        fixture["port"] = server.server_port
        inspected = qa.inspect_approval(fixture, token, run_id, "schedule.job.create")
        self.assertEqual(inspected["approval_id"], run_id)
        self.assertEqual(inspected["fingerprint"], "expected-fingerprint")
        self.assertEqual(inspected["arguments"]["prompt"], "synthetic")
        self.assertEqual(inspected["capabilities"], [{"name": "schedule.create"}])
        with self.assertRaises(qa.QaError):
            qa.inspect_approval(fixture, token, run_id, "skill.publish")

    @unittest.skipUnless(is_wsl(), "M5 launcher CLI contract is WSL-specific; portable helpers still run")
    def test_cli_fresh_shell_selection_and_destructive_confirmation(self):
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(qa.main(["init", "--name", "sample", "--source-sha", SHA]), 0)
            self.assertEqual(qa.main(["status"]), 0)
        fixture = qa.load_fixture("sample")
        self.assertIn(fixture["workspace_id"], output.getvalue())
        self.assertNotIn(qa.token_for("sample"), output.getvalue() + errors.getvalue())
        with redirect_stdout(output), redirect_stderr(errors):
            self.assertEqual(qa.main(["record", "--case", "G02", "--outcome", "pass",
                                      "--command", "echo synthetic"]), 0)
        with redirect_stderr(errors):
            self.assertNotEqual(qa.main(["cleanup", "--confirm", str(uuid.uuid4())]), 0)
        self.assertTrue((self.base / "fixtures" / "sample").exists())
        with redirect_stdout(output):
            self.assertEqual(qa.main(["cleanup", "--confirm", fixture["fixture_id"]]), 0)
        self.assertTrue((self.base / "evidence" / fixture["fixture_id"]).exists())


if __name__ == "__main__":
    unittest.main()
