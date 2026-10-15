"""Durable task records and a workspace lock shared by all controller instances."""

from __future__ import annotations

import errno
import json
import os
import re
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

_ID = re.compile(r"[0-9a-f]{32}\Z")
_SCHEMA_VERSION = 1
# Windows byte locks also prevent reads. Reserve a byte beyond the metadata so
# operators can inspect the JSON file while the controller still owns the lock.
_LOCK_OFFSET = 1024 * 1024


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _check_id(value: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("Expected a 32-character lowercase hexadecimal ID")
    return value


def _json_object(value: dict[str, Any]) -> str:
    if not isinstance(value, dict):
        raise TypeError("Expected a JSON object")
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))


def _public_route(value: dict[str, Any]) -> dict[str, Any]:
    """Do not persist environment values, even if a caller forgets Route.public()."""
    if not isinstance(value, dict):
        raise TypeError("Expected a route object")

    def redact(item: Any) -> Any:
        if isinstance(item, dict):
            result = {}
            for key, child in item.items():
                if isinstance(key, str) and key.lower() in {"env", "environment"}:
                    if isinstance(child, dict):
                        result[key] = {str(name): "<configured>" for name in child}
                    else:
                        result[key] = None if child is None else "<configured>"
                else:
                    result[key] = redact(child)
            return result
        if isinstance(item, (list, tuple)):
            return [redact(child) for child in item]
        return item

    return redact(value)


class Store:
    """SQLite-backed records; each mutation commits or rolls back as one transaction.

    Independent Store instances and processes may share a state directory. The
    workspace lock, rather than this database, owns controller exclusivity.
    """

    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir).expanduser().resolve()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.state_dir / "state.sqlite3"
        self._mutex = threading.RLock()
        self._db = sqlite3.connect(self.path, timeout=10, check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        try:
            self._db.execute("PRAGMA busy_timeout = 10000")
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
            self._initialize()
        except BaseException:
            self._db.close()
            raise

    def _initialize(self) -> None:
        with self._transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version > _SCHEMA_VERSION:
                raise RuntimeError(f"Unsupported state schema version: {version}")
            db.execute(
                """CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY, status TEXT NOT NULL, phase TEXT NOT NULL,
                    workspace TEXT NOT NULL, spec_json TEXT NOT NULL, data_json TEXT NOT NULL,
                    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                )"""
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL REFERENCES tasks(id),
                    event_json TEXT NOT NULL, created_at TEXT NOT NULL
                )"""
            )
            db.execute(
                """CREATE TABLE IF NOT EXISTS attempts (
                    id TEXT PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
                    phase TEXT NOT NULL, route_json TEXT NOT NULL, pid INTEGER,
                    started_at TEXT NOT NULL, finished_at TEXT, result_json TEXT
                )"""
            )
            db.execute("CREATE INDEX IF NOT EXISTS events_task ON events(task_id, sequence)")
            db.execute(
                "CREATE INDEX IF NOT EXISTS attempts_task ON attempts(task_id, started_at, id)"
            )
            db.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._mutex:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def close(self) -> None:
        with self._mutex:
            self._db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    @staticmethod
    def _task(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "status": row["status"],
            "phase": row["phase"],
            "workspace": row["workspace"],
            "spec": json.loads(row["spec_json"]),
            "data": json.loads(row["data_json"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _attempt(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "task_id": row["task_id"],
            "phase": row["phase"],
            "route": json.loads(row["route_json"]),
            "pid": row["pid"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "result": json.loads(row["result_json"]) if row["result_json"] else None,
        }

    @staticmethod
    def _require_task(db: sqlite3.Connection, task_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM tasks WHERE id = ?", (_check_id(task_id),)).fetchone()
        if row is None:
            raise KeyError(task_id)
        return row

    @staticmethod
    def _require_attempt(db: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM attempts WHERE id = ?", (_check_id(attempt_id),)).fetchone()
        if row is None:
            raise KeyError(attempt_id)
        return row

    def create_task(self, spec: dict[str, Any], workspace: Path) -> dict[str, Any]:
        spec_json = _json_object(spec)
        task_id, timestamp = uuid.uuid4().hex, _now()
        with self._transaction() as db:
            db.execute(
                """INSERT INTO tasks
                   (id, status, phase, workspace, spec_json, data_json, created_at, updated_at)
                   VALUES (?, 'pending', 'plan', ?, ?, '{}', ?, ?)""",
                (
                    task_id,
                    str(Path(workspace).expanduser().resolve()),
                    spec_json,
                    timestamp,
                    timestamp,
                ),
            )
            return self._task(self._require_task(db, task_id))

    def get_task(self, task_id: str) -> dict[str, Any]:
        with self._mutex:
            return self._task(self._require_task(self._db, task_id))

    def list_tasks(self) -> list[dict[str, Any]]:
        with self._mutex:
            rows = self._db.execute("SELECT * FROM tasks ORDER BY created_at, id").fetchall()
            return [self._task(row) for row in rows]

    def update_task(self, task_id: str, **changes: Any) -> dict[str, Any]:
        _check_id(task_id)
        unknown = changes.keys() - {"status", "phase", "data"}
        if unknown:
            raise ValueError(f"Unsupported task fields: {', '.join(sorted(unknown))}")
        fields: dict[str, str] = {}
        for key, value in changes.items():
            if key == "data":
                fields["data_json"] = _json_object(value)
            else:
                if not isinstance(value, str) or not value:
                    raise ValueError(f"{key} must be a nonempty string")
                fields[key] = value
        with self._transaction() as db:
            self._require_task(db, task_id)
            if fields:
                fields["updated_at"] = _now()
                assignments = ", ".join(f"{key} = ?" for key in fields)
                db.execute(
                    f"UPDATE tasks SET {assignments} WHERE id = ?",
                    (*fields.values(), task_id),
                )
            return self._task(self._require_task(db, task_id))

    def record_event(self, task_id: str, event: dict[str, Any]) -> None:
        event_json = _json_object(event)
        with self._transaction() as db:
            self._require_task(db, task_id)
            db.execute(
                "INSERT INTO events (task_id, event_json, created_at) VALUES (?, ?, ?)",
                (task_id, event_json, _now()),
            )

    def events(self, task_id: str) -> list[dict[str, Any]]:
        with self._mutex:
            self._require_task(self._db, task_id)
            rows = self._db.execute(
                "SELECT event_json FROM events WHERE task_id = ? ORDER BY sequence", (task_id,)
            ).fetchall()
            return [json.loads(row["event_json"]) for row in rows]

    def begin_attempt(self, task_id: str, phase: str, route: dict[str, Any]) -> str:
        if not isinstance(phase, str) or not phase:
            raise ValueError("phase must be a nonempty string")
        route_json = _json_object(_public_route(route))
        attempt_id = uuid.uuid4().hex
        with self._transaction() as db:
            self._require_task(db, task_id)
            db.execute(
                """INSERT INTO attempts (id, task_id, phase, route_json, started_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (attempt_id, task_id, phase, route_json, _now()),
            )
        return attempt_id

    def set_attempt_pid(self, attempt_id: str, pid: int) -> None:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("pid must be a positive integer")
        with self._transaction() as db:
            row = self._require_attempt(db, attempt_id)
            if row["finished_at"] is not None:
                raise ValueError("Attempt already finished")
            db.execute("UPDATE attempts SET pid = ? WHERE id = ?", (pid, attempt_id))

    def finish_attempt(self, attempt_id: str, result: dict[str, Any]) -> None:
        result_json = _json_object(result)
        with self._transaction() as db:
            row = self._require_attempt(db, attempt_id)
            if row["finished_at"] is not None:
                raise ValueError("Attempt already finished")
            db.execute(
                "UPDATE attempts SET finished_at = ?, result_json = ? WHERE id = ?",
                (_now(), result_json, attempt_id),
            )

    def attempts(self, task_id: str) -> list[dict[str, Any]]:
        with self._mutex:
            self._require_task(self._db, task_id)
            rows = self._db.execute(
                "SELECT * FROM attempts WHERE task_id = ? ORDER BY started_at, id", (task_id,)
            ).fetchall()
            return [self._attempt(row) for row in rows]

    def active_attempts(self, task_id: str) -> list[dict[str, Any]]:
        with self._mutex:
            self._require_task(self._db, task_id)
            rows = self._db.execute(
                """SELECT * FROM attempts WHERE task_id = ? AND finished_at IS NULL
                   ORDER BY started_at, id""",
                (task_id,),
            ).fetchall()
            return [self._attempt(row) for row in rows]

    def mark_attempt_interrupted(self, attempt_id: str, message: str) -> None:
        self.finish_attempt(
            attempt_id,
            {"success": False, "failure": "cancelled", "message": message, "interrupted": True},
        )


class LockBusy(RuntimeError):
    """Another process already owns this workspace."""


class WorkspaceLock:
    """OS advisory lock independent of the controller's selected state directory.

    The metadata file is intentionally retained. Unlinking it would let another
    process lock a different inode while an existing owner still holds its lock.
    A process exit releases the lock even when its metadata file remains.
    """

    def __init__(self, workspace: Path):
        self.workspace = Path(workspace).expanduser().resolve()
        self.path = self.workspace / ".veacode" / "controller.lock"
        self._file: BinaryIO | None = None

    def acquire(self) -> WorkspaceLock:
        if self._file is not None:
            raise LockBusy(f"Workspace lock is already held: {self.workspace}")
        if not self.workspace.exists():
            raise FileNotFoundError(self.workspace)
        if not self.workspace.is_dir():
            raise NotADirectoryError(self.workspace)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        stream = os.fdopen(fd, "r+b", buffering=0)
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(_LOCK_OFFSET)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            stream.close()
            if exc.errno in {errno.EACCES, errno.EAGAIN, errno.EDEADLK} or getattr(
                exc, "winerror", None
            ) in {33, 36}:
                raise LockBusy(f"Another controller owns workspace: {self.workspace}") from exc
            raise
        self._file = stream
        try:
            metadata = _json_object(
                {"pid": os.getpid(), "created_at": _now(), "workspace": str(self.workspace)}
            ).encode("utf-8")
            stream.seek(0)
            stream.write(metadata)
            stream.truncate()
            os.fsync(stream.fileno())
        except BaseException:
            self.release()
            raise
        return self

    def release(self) -> None:
        stream, self._file = self._file, None
        if stream is None:
            return
        try:
            if os.name == "nt":
                import msvcrt

                stream.seek(_LOCK_OFFSET)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()

    def __enter__(self) -> WorkspaceLock:
        return self.acquire()

    def __exit__(self, *_: Any) -> None:
        self.release()
