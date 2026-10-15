"""Workspace evidence uses real local Git and ordinary child processes."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from veacode.workspace import processes_alive, run_checks, snapshot


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "репозиторий с пробелами"
        self.root.mkdir()
        self.git("init", "--quiet")
        (self.root / "tracked.txt").write_text("original\n", encoding="utf-8")
        self.git("add", "--", "tracked.txt")
        self.commit()

    def git(self, *argv):
        result = subprocess.run(
            ["git", "-C", str(self.root), *argv],
            capture_output=True,
            check=True,
            timeout=20,
        )
        return result.stdout

    def commit(self):
        self.git(
            "-c",
            "user.name=Veacode Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )

    def test_snapshot_detects_tracked_untracked_and_deleted_files(self):
        before = snapshot(self.root)
        self.assertTrue(before["is_git"])
        self.assertTrue(before["fingerprint_complete"])
        self.assertEqual(before["status"], [])
        (self.root / "tracked.txt").write_text("changed\n", encoding="utf-8")
        path = self.root / "новый файл.txt"
        path.write_text("first", encoding="utf-8")
        changed = snapshot(self.root)
        self.assertNotEqual(before["fingerprint"], changed["fingerprint"])
        self.assertIn("+changed", changed["diff"])
        self.assertIn("новый файл.txt", [entry["path"] for entry in changed["status"]])
        path.write_text("other", encoding="utf-8")
        modified_untracked = snapshot(self.root)
        self.assertNotEqual(changed["fingerprint"], modified_untracked["fingerprint"])
        (self.root / "tracked.txt").unlink()
        deleted = snapshot(self.root)
        self.assertTrue(any(entry["status"] == " D" for entry in deleted["status"]))

    def test_runtime_state_does_not_change_evidence(self):
        before = snapshot(self.root)
        state = self.root / ".veacode" / "tasks"
        state.mkdir(parents=True)
        (state / "events.jsonl").write_text("event one", encoding="utf-8")
        self.assertEqual(before["fingerprint"], snapshot(self.root)["fingerprint"])
        (state / "events.jsonl").write_text("event two", encoding="utf-8")
        self.assertEqual(before["fingerprint"], snapshot(self.root)["fingerprint"])

    def test_secret_paths_are_not_read_or_included_in_diff(self):
        for name in (".env", "private.key", "service_credentials.json", "api_key.txt"):
            (self.root / name).write_text("TOP_SECRET_ORIGINAL", encoding="utf-8")
        self.git("add", ".")
        self.commit()
        for name in (".env", "private.key", "service_credentials.json", "api_key.txt"):
            (self.root / name).write_text("TOP_SECRET_CHANGED", encoding="utf-8")
        untracked = self.root / "untracked_secret.txt"
        untracked.write_text("TOP_SECRET_UNTRACKED", encoding="utf-8")
        with patch.object(Path, "open", side_effect=AssertionError("must not read secrets")):
            evidence = snapshot(self.root)
        self.assertNotIn("TOP_SECRET", evidence["diff"])
        self.assertNotIn("TOP_SECRET", evidence["diff_stat"])
        self.assertFalse(evidence["fingerprint_complete"])
        self.assertTrue(any("metadata only" in note for note in evidence["limitations"]))

    def test_rename_preserves_paths_with_spaces_and_unicode(self):
        self.git("mv", "tracked.txt", "новое имя.txt")
        evidence = snapshot(self.root)
        self.assertEqual(
            evidence["status"],
            [
                {
                    "status": "R ",
                    "path": "новое имя.txt",
                    "original_path": "tracked.txt",
                }
            ],
        )

    def test_binary_change_updates_fingerprint(self):
        path = self.root / "image.bin"
        path.write_bytes(b"\x00original")
        self.git("add", "image.bin")
        self.commit()
        path.write_bytes(b"\x00changed1")
        first = snapshot(self.root)
        path.write_bytes(b"\x00changed2")
        self.assertNotEqual(first["fingerprint"], snapshot(self.root)["fingerprint"])

    def test_untracked_hash_limit_is_reported(self):
        (self.root / "huge.bin").write_bytes(b"x" * 1_048_577)
        evidence = snapshot(self.root)
        self.assertFalse(evidence["fingerprint_complete"])
        self.assertTrue(any("hashing limit" in note for note in evidence["limitations"]))

    def test_non_git_workspace_has_clear_result(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        evidence = snapshot(outside)
        self.assertFalse(evidence["is_git"])
        self.assertIsNone(evidence["fingerprint"])
        self.assertTrue(evidence["error"])

    def test_unborn_repository_is_reported_without_crashing(self):
        unborn = Path(self.temp.name) / "unborn"
        unborn.mkdir()
        subprocess.run(["git", "init", "--quiet", str(unborn)], check=True, timeout=20)
        (unborn / "new.txt").write_text("new", encoding="utf-8")
        result = snapshot(unborn)
        self.assertTrue(result["is_git"])
        self.assertIsNone(result["head"])
        self.assertFalse(result["fingerprint_complete"])


class CheckTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_python_placeholder_exit_status_cwd_and_no_shell(self):
        script = "import os,sys; print(os.getcwd()); print(sys.argv[1]); sys.exit(3)"
        result = run_checks(self.root, [["{python}", "-c", script, "literal;echo unsafe"]])[0]
        self.assertEqual(result["argv"][0], sys.executable)
        self.assertEqual(result["exit_code"], 3)
        self.assertFalse(result["passed"])
        self.assertIn(str(self.root), result["stdout"])
        self.assertIn("literal;echo unsafe", result["stdout"])
        self.assertFalse(result["timed_out"])

    def test_check_output_is_bounded_and_redacted(self):
        code = (
            "import sys; print('api_key=super-private-value'); "
            "print('Bearer hidden-bearer'); print('x' * 100000); "
            "print('password=also-private', file=sys.stderr)"
        )
        result = run_checks(self.root, [["{python}", "-c", code]])[0]
        self.assertTrue(result["passed"])
        self.assertLess(len(result["stdout"]), 25_000)
        self.assertTrue(result["stdout_truncated"])
        self.assertNotIn("super-private-value", result["stdout"])
        self.assertNotIn("hidden-bearer", result["stdout"])
        self.assertNotIn("also-private", result["stderr"])

    def test_missing_executable_is_failed_result(self):
        result = run_checks(self.root, [["veacode-nonexistent-executable-123456"]])[0]
        self.assertFalse(result["passed"])
        self.assertIsNone(result["exit_code"])
        self.assertTrue(result["stderr"])

    def test_timeout_kills_owned_process_tree(self):
        marker = self.root / "child-survived.txt"
        child = (
            "import time; from pathlib import Path; time.sleep(1.2); "
            f"Path({str(marker)!r}).write_text('survived')"
        )
        parent = (
            "import subprocess,sys,time; "
            f"child=subprocess.Popen([sys.executable, '-c', {child!r}]); "
            "print(child.pid, flush=True); time.sleep(60)"
        )
        result = run_checks(self.root, [["{python}", "-c", parent]], timeout_seconds=0.4)[0]
        self.assertFalse(result["passed"])
        self.assertTrue(result["timed_out"])
        time.sleep(1.3)
        self.assertFalse(marker.exists(), "child must die with its timed-out parent")

    def test_invalid_check_configuration(self):
        for checks in ([[]], ["echo hi"], [[1]]):
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                run_checks(self.root, checks)
        with self.assertRaises(ValueError):
            run_checks(self.root, [["{python}"]], timeout_seconds=0)

    def test_interrupt_terminates_owned_check_before_propagating(self):
        original_wait = subprocess.Popen.wait
        interrupted = []

        def interrupt_once(process, *args, **kwargs):
            if not interrupted:
                interrupted.append(process.pid)
                raise KeyboardInterrupt
            return original_wait(process, *args, **kwargs)

        with (
            patch.object(subprocess.Popen, "wait", interrupt_once),
            self.assertRaises(KeyboardInterrupt),
        ):
            run_checks(self.root, [["{python}", "-c", "import time; time.sleep(60)"]])
        self.assertEqual(processes_alive(interrupted), [])

    def test_process_probe_never_terminates_process(self):
        self.assertEqual(processes_alive([os.getpid(), os.getpid(), -1, 0]), [os.getpid()])
        self.assertEqual(processes_alive([2_147_483_647]), [])
        self.assertEqual(processes_alive([2**64 + os.getpid()]), [])

    def test_checks_do_not_inherit_provider_credentials(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "private-provider-value"}):
            results = run_checks(
                self.root,
                [["{python}", "-c", "import os; assert 'DEEPSEEK_API_KEY' not in os.environ"]],
            )
        self.assertTrue(results[0]["passed"], results)


if __name__ == "__main__":
    unittest.main()
