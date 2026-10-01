"""Exercise the source guards with real Git and stubbed build commands.

Run with: python3 scripts/rebuild/test_build_pinned_pi.py
"""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("build-pinned-pi.sh")

# BASH_ENV intercepts only external build work and the remote fetch. Git source
# verification still executes normally. No network, npm or user service runs.
BUILD_STUBS = r"""
id() { if [[ "$1" = -u ]]; then echo 1000; else command id "$@"; fi; }
systemctl() { :; }
env() {
    local arg
    for arg in "$@"; do
        case "$arg" in
            /usr/bin/python3)
                echo hydrate >> "$TEST_TRACE"
                mkdir -p "$TEST_OUTPUT/repo/packages/ai/src/providers/data"
                echo '{}' > "$TEST_OUTPUT/repo/packages/ai/src/providers/data/.manifest.json"
                return ;;
            /usr/bin/systemd-run)
                if [[ " $* " = *" /usr/bin/npm ci "* ]]; then
                    echo deps >> "$TEST_TRACE"
                    mkdir -p "$TEST_OUTPUT/repo/node_modules"
                    echo dependency > "$TEST_OUTPUT/repo/node_modules/fixture.js"
                else
                    echo build >> "$TEST_TRACE"
                    mkdir -p "$TEST_OUTPUT/repo/packages/coding-agent/dist/bundle"
                    echo bundle > "$TEST_OUTPUT/repo/packages/coding-agent/dist/bundle/cli.js"
                    if [[ -n "$TEST_BUILD_EDIT" ]]; then
                        echo modified >> "$TEST_OUTPUT/repo/source.js"
                        if [[ "$TEST_BUILD_EDIT" = index ]]; then
                            git -C "$TEST_OUTPUT/repo" add source.js
                        fi
                    fi
                fi
                return ;;
        esac
    done
    local -a args=()
    for arg in "$@"; do
        if [[ "$arg" = https://github.com/earendil-works/pi.git ]]; then
            arg="$TEST_UPSTREAM"
        fi
        args+=("$arg")
    done
    command env "${args[@]}"
}
"""


class BuildPinnedPiTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.upstream = self.root / "upstream"
        self.upstream.mkdir()
        self.git(self.upstream, "init", "-q")
        (self.upstream / "source.js").write_text("original\n")
        (self.upstream / ".gitattributes").write_text(
            "* text=auto eol=lf\n*.bat text eol=crlf\n")
        (self.upstream / "pi-test.bat").write_bytes(b"@echo off\necho fixture\n")
        lock = b'{"lockfileVersion": 3}\n'
        (self.upstream / "package-lock.json").write_bytes(lock)
        self.git(self.upstream, "add", "source.js", "package-lock.json",
                 ".gitattributes", "pi-test.bat")
        self.git(self.upstream, "-c", "user.name=Fixture", "-c",
                 "user.email=fixture@example.invalid", "commit", "-qm", "fixture")
        self.commit = self.git(self.upstream, "rev-parse", "HEAD").strip()
        # Substitute only the fixture's commit and lock digest, leaving all
        # verification and build control flow from the production script intact.
        script = re.sub(r"^pi_commit=.*$", f"pi_commit={self.commit}",
                        SCRIPT.read_text(), count=1, flags=re.MULTILINE)
        script = re.sub(r"^pi_lock=.*$", f"pi_lock={hashlib.sha256(lock).hexdigest()}",
                        script, count=1, flags=re.MULTILINE)
        self.script = self.root / "build-pinned-pi.sh"
        self.script.write_text(script)
        self.stubs = self.root / "stubs.sh"
        self.stubs.write_text(BUILD_STUBS)
        self.output = self.root / "output"
        self.repo = self.output / "repo"
        self.trace = self.root / "execution.log"

    def git(self, repo, *args):
        return subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
            check=True, capture_output=True, text=True,
        ).stdout

    def prepare_resume(self):
        shutil.copytree(self.upstream, self.repo)

    def run_build(self, resume=True, build_edit=""):
        args = ["bash", str(self.script), str(self.output)]
        if resume:
            args.append("--resume-build")
        return subprocess.run(args, capture_output=True, text=True, timeout=15,
                              env={**os.environ, "BASH_ENV": str(self.stubs),
                                   "TEST_TRACE": str(self.trace),
                                   "TEST_OUTPUT": str(self.output),
                                   "TEST_UPSTREAM": str(self.upstream),
                                   "TEST_BUILD_EDIT": build_edit})

    def executions(self):
        return self.trace.read_text().splitlines() if self.trace.exists() else []

    def test_resume_rejects_staged_source_before_build_work(self):
        self.prepare_resume()
        (self.repo / "source.js").write_text("modified\n")
        self.git(self.repo, "add", "source.js")
        self.assertEqual(self.git(self.repo, "rev-parse", "HEAD").strip(), self.commit)
        self.git(self.repo, "diff", "--exit-code", "--quiet")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.executions(), [], result.stderr)
        self.assertIn("index is dirty", result.stderr)

    def test_resume_rejects_unstaged_source_before_build_work(self):
        self.prepare_resume()
        (self.repo / "source.js").write_text("modified\n")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.executions(), [], result.stderr)
        self.assertIn("working tree is dirty", result.stderr)

    def assert_hidden_source_edit_rejected(self, flag):
        self.prepare_resume()
        self.git(self.repo, "update-index", flag, "source.js")
        (self.repo / "source.js").write_text("modified\n")
        # Both existing diff guards miss the edit when this index flag is set.
        self.git(self.repo, "diff", "--exit-code", "--quiet")
        self.git(self.repo, "diff", "--cached", "--exit-code", "--quiet",
                 self.commit, "--")
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.executions(), [], result.stderr)
        self.assertIn("source.js", result.stderr)
        self.assertIn("content hash", result.stderr)

    def test_resume_rejects_assume_unchanged_source_before_build_work(self):
        self.assert_hidden_source_edit_rejected("--assume-unchanged")

    def test_resume_rejects_skip_worktree_source_before_build_work(self):
        self.assert_hidden_source_edit_rejected("--skip-worktree")

    def test_final_checks_reject_source_edits_hidden_by_index_flags(self):
        self.prepare_resume()
        for flag in ("--assume-unchanged", "--skip-worktree"):
            with self.subTest(flag=flag):
                (self.repo / "source.js").write_text("original\n")
                self.git(self.repo, "update-index", "--no-assume-unchanged",
                         "--no-skip-worktree", "source.js")
                self.git(self.repo, "update-index", flag, "source.js")
                self.trace.unlink(missing_ok=True)
                result = self.run_build(build_edit="working-tree")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.executions(), ["hydrate", "deps", "build"])
                self.assertIn("source.js", result.stderr)
                self.assertIn("content hash", result.stderr)
                self.assertNotIn("Candidate build complete", result.stdout)

    def test_final_checks_reject_build_source_edits(self):
        self.prepare_resume()
        for edit, message in (("index", "index is dirty"),
                              ("working-tree", "working tree is dirty")):
            with self.subTest(edit=edit):
                self.git(self.repo, "reset", "--hard", self.commit)
                self.trace.unlink(missing_ok=True)
                result = self.run_build(build_edit=edit)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertEqual(self.executions(), ["hydrate", "deps", "build"])
                self.assertIn(message, result.stderr)
                self.assertNotIn("Candidate build complete", result.stdout)

    def test_clean_resume_accepts_generated_untracked_inputs(self):
        self.prepare_resume()
        # A previous build's generated input remains untracked on resume.
        (self.repo / "node_modules").mkdir()
        (self.repo / "node_modules/fixture.js").write_text("dependency\n")
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.executions(), ["hydrate", "deps", "build"])
        self.assertIn("Candidate build complete", result.stdout)

    def test_clean_fresh_build(self):
        result = self.run_build(resume=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.executions(), ["hydrate", "deps", "build"])
        self.assertEqual(self.git(self.repo, "rev-parse", "HEAD").strip(), self.commit)
        self.assertIn("Candidate build complete", result.stdout)

    def test_clean_fresh_build_accepts_crlf_checkout(self):
        result = self.run_build(resume=False)
        contents = (self.repo / "pi-test.bat").read_bytes()
        self.assertEqual(contents, b"@echo off\r\necho fixture\r\n")
        blob = subprocess.check_output(
            ["git", "-C", str(self.repo), "show", f"{self.commit}:pi-test.bat"])
        self.assertEqual(blob, b"@echo off\necho fixture\n")
        expected = self.git(self.repo, "rev-parse", f"{self.commit}:pi-test.bat").strip()
        raw_hash = hashlib.sha1(
            b"blob " + str(len(contents)).encode() + b"\0" + contents).hexdigest()
        self.assertNotEqual(raw_hash, expected)
        self.assertEqual(self.git(self.repo, "hash-object", "pi-test.bat").strip(), expected)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.executions(), ["hydrate", "deps", "build"])
        self.assertIn("Candidate build complete", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
