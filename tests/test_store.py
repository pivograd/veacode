"""Persistence, transaction failures and real process concurrency."""

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from veacode.store import LockBusy, Store, WorkspaceLock


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        self.state = self.workspace / "state"
        self.store = Store(self.state)
        self.addCleanup(self.store.close)

    def task(self):
        return self.store.create_task({"goal": "Проверить сохранение"}, self.workspace)

    def test_task_and_events_survive_reopen_in_insertion_order(self):
        task = self.task()
        self.assertEqual(task["status"], "pending")
        self.assertEqual(task["phase"], "plan")
        self.assertEqual(task["data"], {})
        self.assertEqual(Path(task["workspace"]), self.workspace.resolve())
        updated = self.store.update_task(
            task["id"], status="running", phase="execute", data={"accepted_plan": "Есть план"}
        )
        self.store.record_event(task["id"], {"type": "start", "value": 2})
        self.store.record_event(task["id"], {"type": "finish", "value": 1})
        with Store(self.state) as other:
            self.assertEqual(other.get_task(task["id"]), updated)
            self.assertEqual(other.list_tasks(), [updated])
            self.assertEqual(
                other.events(task["id"]),
                [{"type": "start", "value": 2}, {"type": "finish", "value": 1}],
            )
            with closing(sqlite3.connect(other.path)) as db:
                self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_active_attempt_survives_reopen_with_pid_and_masks_environment(self):
        task = self.task()
        route = {"name": "test", "env": {"DEEPSEEK_API_KEY": "never-persist-this-value"}}
        attempt_id = self.store.begin_attempt(task["id"], "execute", route)
        self.store.set_attempt_pid(attempt_id, 12345)
        with Store(self.state) as other:
            attempts = other.active_attempts(task["id"])
            self.assertEqual(len(attempts), 1)
            self.assertEqual(attempts[0]["id"], attempt_id)
            self.assertEqual(attempts[0]["pid"], 12345)
            self.assertEqual(attempts[0]["route"]["env"], {"DEEPSEEK_API_KEY": "<configured>"})
            self.assertIsNone(attempts[0]["result"])
            other.mark_attempt_interrupted(
                attempt_id, "Controller stopped before collecting result"
            )
        self.assertEqual(self.store.active_attempts(task["id"]), [])
        finished = self.store.attempts(task["id"])[0]
        self.assertIsNotNone(finished["finished_at"])
        self.assertTrue(finished["result"]["interrupted"])
        self.assertEqual(route["env"]["DEEPSEEK_API_KEY"], "never-persist-this-value")
        for file in self.state.glob("state.sqlite3*"):
            self.assertNotIn(b"never-persist-this-value", file.read_bytes())

    def test_finished_attempt_cannot_be_overwritten(self):
        task = self.task()
        attempt_id = self.store.begin_attempt(task["id"], "plan", {"name": "test"})
        self.store.finish_attempt(attempt_id, {"success": True, "text": "accepted"})
        with self.assertRaises(ValueError):
            self.store.finish_attempt(attempt_id, {"success": False})
        with self.assertRaises(ValueError):
            self.store.set_attempt_pid(attempt_id, 42)
        self.assertEqual(self.store.attempts(task["id"])[0]["result"]["text"], "accepted")

    def test_bad_update_is_atomic_and_next_write_works(self):
        task = self.task()
        with self.assertRaises(ValueError):
            self.store.update_task(task["id"], status="running", data={"bad": float("nan")})
        self.assertEqual(self.store.get_task(task["id"]), task)
        with self.assertRaises(ValueError):
            self.store.update_task(task["id"], workspace="somewhere-else")
        self.assertEqual(self.store.update_task(task["id"], status="running")["status"], "running")

    def test_database_error_rolls_back_and_leaves_connection_usable(self):
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute(
                """CREATE TRIGGER reject_task AFTER INSERT ON tasks BEGIN
                   SELECT RAISE(ABORT, 'injected database failure'); END"""
            )
            db.commit()
        with self.assertRaises(sqlite3.IntegrityError):
            self.task()
        self.assertEqual(self.store.list_tasks(), [])
        with closing(sqlite3.connect(self.store.path)) as db:
            db.execute("DROP TRIGGER reject_task")
            db.commit()
        self.assertEqual(self.task()["status"], "pending")

    def test_safe_ids_missing_records_and_invalid_pid(self):
        for bad_id in ("../outside", "x' OR 1=1", "A" * 32, "", None):
            with self.subTest(bad_id=bad_id), self.assertRaises(ValueError):
                self.store.get_task(bad_id)
        with self.assertRaises(KeyError):
            self.store.record_event("0" * 32, {"type": "missing"})
        with self.assertRaises(KeyError):
            self.store.begin_attempt("0" * 32, "plan", {})
        with self.assertRaises(KeyError):
            self.store.finish_attempt("0" * 32, {})
        task = self.task()
        attempt_id = self.store.begin_attempt(task["id"], "plan", {})
        for pid in (-1, 0, True, 1.5):
            with self.subTest(pid=pid), self.assertRaises(ValueError):
                self.store.set_attempt_pid(attempt_id, pid)

    def test_concurrent_process_writers_do_not_lose_events(self):
        task = self.task()
        source = """
import sys
from pathlib import Path
from veacode.store import Store
with Store(Path(sys.argv[1])) as store:
    for index in range(25):
        store.record_event(sys.argv[2], {"writer": sys.argv[3], "index": index})
"""
        processes = [
            subprocess.Popen(
                [sys.executable, "-c", source, str(self.state), task["id"], str(index)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            for index in range(2)
        ]
        try:
            for process in processes:
                _, error = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, error)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        events = self.store.events(task["id"])
        self.assertEqual(len(events), 50)
        for writer in ("0", "1"):
            self.assertEqual(
                [event["index"] for event in events if event["writer"] == writer],
                list(range(25)),
            )


class WorkspaceLockTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)

    def child(self, source):
        return subprocess.run(
            [sys.executable, "-c", source, str(self.workspace)],
            capture_output=True,
            text=True,
            timeout=15,
        )

    def test_same_workspace_blocks_another_process_and_keeps_metadata(self):
        source = """
import sys
from pathlib import Path
from veacode.store import LockBusy, WorkspaceLock
try:
    with WorkspaceLock(Path(sys.argv[1])):
        pass
except LockBusy:
    sys.exit(23)
"""
        lock = WorkspaceLock(self.workspace)
        with lock:
            with self.assertRaises(LockBusy):
                WorkspaceLock(self.workspace).acquire()
            metadata = lock.path.read_bytes()
            self.assertEqual(json.loads(metadata)["pid"], os.getpid())
            self.assertEqual(self.child(source).returncode, 23)
            self.assertEqual(lock.path.read_bytes(), metadata)
        self.assertTrue(lock.path.exists())
        child = self.child(source)
        self.assertEqual(child.returncode, 0, child.stderr)
        lock.release()

    def test_abrupt_owner_exit_releases_lock_without_removing_file(self):
        source = """
import os, sys
from pathlib import Path
from veacode.store import WorkspaceLock
lock = WorkspaceLock(Path(sys.argv[1])).acquire()
os._exit(0)
"""
        child = self.child(source)
        self.assertEqual(child.returncode, 0, child.stderr)
        lock = WorkspaceLock(self.workspace)
        self.assertTrue(lock.path.exists())
        with lock:
            self.assertEqual(json.loads(lock.path.read_text())["pid"], os.getpid())

    def test_exception_releases_lock_and_workspace_must_exist(self):
        with self.assertRaisesRegex(RuntimeError, "work failed"), WorkspaceLock(self.workspace):
            raise RuntimeError("work failed")
        with WorkspaceLock(self.workspace):
            pass
        with self.assertRaises(FileNotFoundError):
            WorkspaceLock(self.workspace / "missing").acquire()


if __name__ == "__main__":
    unittest.main()
