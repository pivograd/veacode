"""Git evidence and checks from trusted local configuration.

Evidence covers Git-visible files. Ignored files and secret-looking paths are never
read for a fingerprint; oversized untracked files use metadata instead, which is
reported explicitly. Runtime state under ``.veacode`` is excluded throughout.
"""

from __future__ import annotations

import ctypes
import fnmatch
import hashlib
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

_OUTPUT_LIMIT = 24_000
_GIT_TIMEOUT = 20
_UNTRACKED_FILE_LIMIT = 1_048_576
_UNTRACKED_TOTAL_LIMIT = 8_388_608
_SECRET_PATTERNS = (
    ".env*",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "*.keystore",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*secret*",
    "*credential*",
    "*token*",
    "key",
    "keys",
    "key.*",
    "keys.*",
    "*_key.*",
    "*-key.*",
    "auth.json",
    ".ssh",
    ".aws",
)


def _redact(text: str) -> str:
    # Keep local checks independent of provider credentials or authentication files.
    import re

    text = re.sub(r"(?i)(\bBearer\s+)[^\s\"']+", r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)(\b(?:[\w-]*(?:api[_-]?key|token|password|passwd|secret|credential)"
        r"[\w-]*)\b[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]+)",
        r"\1[REDACTED]",
        text,
    )
    return re.sub(r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,})", "[REDACTED]", text)


class _WindowsJob:
    """Own a Windows child tree even when taskkill is blocked by a sandbox."""

    def __init__(self) -> None:
        from ctypes import wintypes

        class BasicLimit(ctypes.Structure):
            _fields_ = [
                ("process_time", ctypes.c_longlong),
                ("job_time", ctypes.c_longlong),
                ("flags", wintypes.DWORD),
                ("min_working_set", ctypes.c_size_t),
                ("max_working_set", ctypes.c_size_t),
                ("active_processes", wintypes.DWORD),
                ("affinity", ctypes.c_size_t),
                ("priority", wintypes.DWORD),
                ("scheduling", wintypes.DWORD),
            ]

        class IoCounters(ctypes.Structure):
            _fields_ = [(f"counter_{index}", ctypes.c_ulonglong) for index in range(6)]

        class ExtendedLimit(ctypes.Structure):
            _fields_ = [
                ("basic", BasicLimit),
                ("io", IoCounters),
                ("process_memory", ctypes.c_size_t),
                ("job_memory", ctypes.c_size_t),
                ("peak_process_memory", ctypes.c_size_t),
                ("peak_job_memory", ctypes.c_size_t),
            ]

        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self.kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self.kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self.kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self.kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.kernel32.TerminateJobObject.restype = wintypes.BOOL
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.handle = self.kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = ExtendedLimit()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if not self.kernel32.SetInformationJobObject(
            self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def attach(self, process: subprocess.Popen[bytes]) -> None:
        if not self.kernel32.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def terminate(self) -> None:
        if not self.kernel32.TerminateJobObject(self.handle, 1):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self) -> None:
        if self.handle:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def _terminate_tree(
    process: subprocess.Popen[bytes], windows_job: _WindowsJob | None = None
) -> None:
    """Kill an owned check and its descendants, never unrelated recorded PIDs."""
    if windows_job is not None:
        windows_job.terminate()
    elif os.name == "nt":
        if process.poll() is None:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait(timeout=10)


def _read_output(stream: Any) -> tuple[str, str, bool]:
    stream.seek(0)
    digest = hashlib.sha256()
    preview = bytearray()
    total = 0
    while chunk := stream.read(65_536):
        digest.update(chunk)
        if len(preview) < _OUTPUT_LIMIT:
            preview.extend(chunk[: _OUTPUT_LIMIT - len(preview)])
        total += len(chunk)
    truncated = total > _OUTPUT_LIMIT
    text = preview.decode("utf-8", errors="replace")
    if truncated:
        text += "\n[output truncated]"
    return text, digest.hexdigest(), truncated


def _execute(
    argv: list[str],
    cwd: Path,
    timeout: float,
    env_overrides: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Capture to temporary files, so a noisy child cannot block or fill RAM."""
    options: dict[str, Any] = {}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        options["start_new_session"] = True
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        job = None
        process = None
        try:
            if os.name == "nt":
                job = _WindowsJob()
            process = subprocess.Popen(
                argv,
                cwd=cwd,
                env={
                    **{
                        key: value
                        for key, value in os.environ.items()
                        if not re.search(
                            r"(API_KEY|TOKEN|PASSWORD|SECRET|AUTHORIZATION)", key, re.I
                        )
                        and not key.upper().startswith(
                            (
                                "ANTHROPIC_",
                                "OPENAI_",
                                "CODEX_",
                                "DEEPSEEK_",
                                "OPENROUTER_",
                            )
                        )
                    },
                    **(env_overrides or {}),
                },
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                **options,
            )
            if job is not None:
                job.attach(process)
        except BaseException as exc:
            if process is not None:
                process.kill()
                process.wait(timeout=10)
            if job is not None:
                job.close()
            if not isinstance(exc, OSError):
                raise
            return {
                "exit_code": None,
                "stdout": "",
                "stderr": str(exc),
                "timed_out": False,
                "stdout_sha256": hashlib.sha256(b"").hexdigest(),
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
        timed_out = False
        try:
            try:
                process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_tree(process, job)
            except BaseException:
                _terminate_tree(process, job)
                raise
        finally:
            if job is not None:
                job.close()
            elif os.name != "nt":
                # A successful parent must not leave background descendants behind.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        out, out_hash, out_truncated = _read_output(stdout)
        err, _, err_truncated = _read_output(stderr)
        return {
            "exit_code": process.returncode,
            "stdout": out,
            "stderr": err,
            "timed_out": timed_out,
            "stdout_sha256": out_hash,
            "stdout_truncated": out_truncated,
            "stderr_truncated": err_truncated,
        }


def _git(root: Path, *args: str) -> dict[str, Any]:
    return _execute(
        ["git", "-c", "core.quotepath=false", "-C", str(root), *args], root, _GIT_TIMEOUT
    )


def _runtime_path(path: str) -> bool:
    return ".veacode" in PurePosixPath(path).parts


def _secret_path(path: str) -> bool:
    return any(
        fnmatch.fnmatchcase(part.lower(), pattern)
        for part in PurePosixPath(path).parts
        for pattern in _SECRET_PATTERNS
    )


def _parse_status(output: str) -> list[dict[str, str]]:
    records = iter(output.split("\0"))
    result = []
    for record in records:
        if not record:
            continue
        status, path = record[:2], record[3:]
        entry = {"status": status, "path": path}
        if "R" in status or "C" in status:
            entry["original_path"] = next(records, "")
        if not _runtime_path(path):
            result.append(entry)
    return result


def _safe_pathspec() -> list[str]:
    # Git glob magic's **/ also matches files in the repository root.
    result = [".", ":(exclude,glob)**/.veacode/**"]
    for pattern in _SECRET_PATTERNS:
        result.extend(
            [
                f":(exclude,glob,icase)**/{pattern}",
                f":(exclude,glob,icase)**/{pattern}/**",
            ]
        )
    return result


def _file_evidence(root: Path, entry: dict[str, str], remaining: int) -> tuple[dict, int]:
    path = root / entry["path"]
    evidence: dict[str, Any] = {"path": entry["path"]}
    try:
        stat = path.lstat()
        evidence.update(size=stat.st_size, mtime_ns=stat.st_mtime_ns)
        if _secret_path(entry["path"]):
            evidence["omitted"] = "secret-looking path; metadata only"
        elif path.is_symlink():
            evidence["symlink"] = os.readlink(path)
        elif not path.is_file():
            evidence["omitted"] = "not a regular file"
        elif not path.resolve().is_relative_to(root):
            evidence["omitted"] = "path resolves outside repository"
        elif stat.st_size > _UNTRACKED_FILE_LIMIT or stat.st_size > remaining:
            evidence["omitted"] = "untracked content hashing limit; metadata only"
        elif entry["status"] == "??":
            digest = hashlib.sha256()
            with path.open("rb") as source:
                # Bound reads even if the file grows after the initial stat.
                data = source.read(min(_UNTRACKED_FILE_LIMIT, remaining) + 1)
            if len(data) > min(_UNTRACKED_FILE_LIMIT, remaining):
                evidence["omitted"] = "file grew beyond content hashing limit"
            else:
                digest.update(data)
                evidence["sha256"] = digest.hexdigest()
                remaining -= len(data)
    except OSError as exc:
        evidence["omitted"] = f"file unavailable: {exc.__class__.__name__}"
    return evidence, remaining


def snapshot(workspace: Path) -> dict[str, Any]:
    """Return bounded Git evidence and a recovery fingerprint, without secrets.

    Full safe tracked diffs are hashed, including binary patches. Safe untracked
    contents are hashed up to 1 MiB per file and 8 MiB in total. Secret-looking
    paths contribute status/metadata only. ``fingerprint_complete`` signals any
    omission; ignored files are always outside the contract.
    """
    workspace = Path(workspace).resolve()
    found = _git(workspace, "rev-parse", "--show-toplevel")
    if found["exit_code"] != 0:
        return {
            "is_git": False,
            "root": str(workspace),
            "head": None,
            "status": [],
            "fingerprint": None,
            "fingerprint_complete": False,
            "error": _redact(found["stderr"] or "Workspace is not a Git repository"),
        }
    root = Path(found["stdout"].strip()).resolve()
    head = _git(root, "rev-parse", "--verify", "HEAD")
    status_result = _git(
        root,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--",
        ".",
        ":(exclude,glob)**/.veacode/**",
    )
    # Never treat a truncated status as a complete file inventory.
    status = _parse_status(status_result["stdout"])
    diff_args = ["diff", "--no-ext-diff", "--no-textconv", "--binary", "--full-index"]
    if head["exit_code"] == 0:
        diff_args.append("HEAD")
    else:
        # With no HEAD, the index is the only source of tracked new files.
        diff_args.append("--cached")
    diff = _git(root, *diff_args, "--", *_safe_pathspec())
    stat_args = ["diff", "--no-ext-diff", "--no-textconv", "--stat"]
    stat_args.append("HEAD" if head["exit_code"] == 0 else "--cached")
    diff_stat = _git(root, *stat_args, "--", *_safe_pathspec())
    limitations = ["Ignored files are outside the recovery fingerprint."]
    complete = True
    if status_result["stdout_truncated"]:
        limitations.append("Git status exceeded the output limit; inventory is incomplete.")
        complete = False
    for label, result in (("status", status_result), ("diff", diff), ("diff stat", diff_stat)):
        if result["exit_code"] != 0:
            limitations.append(f"Git {label} failed: {_redact(result['stderr'])}")
            complete = False
    if head["exit_code"] != 0:
        limitations.append("Repository has no HEAD; unstaged tracked contents use metadata only.")
        complete = False
    file_evidence = []
    remaining = _UNTRACKED_TOTAL_LIMIT
    for entry in status:
        if entry["status"] == "??" or _secret_path(entry["path"]) or head["exit_code"] != 0:
            evidence, remaining = _file_evidence(root, entry, remaining)
            file_evidence.append(evidence)
            if "omitted" in evidence:
                complete = False
                limitations.append(f"{entry['path']}: {evidence['omitted']}")
    head_value = head["stdout"].strip() if head["exit_code"] == 0 else None
    payload = {
        "head": head_value,
        "status": status,
        "status_sha256": status_result["stdout_sha256"],
        "diff_sha256": diff["stdout_sha256"],
        "files": file_evidence,
    }
    fingerprint = hashlib.sha256(
        json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    return {
        "is_git": True,
        "root": str(root),
        "head": head_value,
        "status": status,
        "diff_stat": _redact(diff_stat["stdout"]),
        "diff": _redact(diff["stdout"]),
        "diff_sha256": diff["stdout_sha256"],
        "diff_truncated": diff["stdout_truncated"],
        "fingerprint": fingerprint,
        "fingerprint_complete": complete,
        "limitations": limitations,
    }


def run_checks(
    workspace: Path, checks: list[list[str]], timeout_seconds: float = 120
) -> list[dict[str, Any]]:
    """Run argv arrays from trusted user configuration, never model output.

    ``{python}`` as an entire argv item resolves to the current interpreter.
    Every check runs directly with no shell, and its output is bounded/redacted.
    """
    if timeout_seconds <= 0:
        raise ValueError("Check timeout must be positive")
    if any(
        not isinstance(argv, list) or not argv or any(not isinstance(v, str) for v in argv)
        for argv in checks
    ):
        raise ValueError("Checks must be non-empty argument lists")
    results = []
    for check in checks:
        argv = [sys.executable if item == "{python}" else item for item in check]
        # Python's timestamp/size bytecode cache can survive a same-size source edit
        # within one second. Verification must execute the current source instead.
        with tempfile.TemporaryDirectory(prefix="veacode-check-cache-") as pycache:
            executed = _execute(
                argv,
                Path(workspace).resolve(),
                timeout_seconds,
                {"PYTHONPYCACHEPREFIX": pycache, "PYTHONDONTWRITEBYTECODE": "1"},
            )
        results.append(
            {
                "argv": [_redact(item) for item in argv],
                "exit_code": executed["exit_code"],
                "passed": executed["exit_code"] == 0 and not executed["timed_out"],
                "stdout": _redact(executed["stdout"]),
                "stderr": _redact(executed["stderr"]),
                "timed_out": executed["timed_out"],
                "stdout_truncated": executed["stdout_truncated"],
                "stderr_truncated": executed["stderr_truncated"],
            }
        )
    return results


def processes_alive(pids: list[int]) -> list[int]:
    """Inspect recorded PIDs without signalling or terminating any process."""
    alive = []
    for pid in dict.fromkeys(pids):
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            continue
        if os.name == "nt":
            if pid > 0xFFFFFFFF:
                continue
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
            kernel32.GetExitCodeProcess.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                try:
                    code = wintypes.DWORD()
                    queried = kernel32.GetExitCodeProcess(handle, ctypes.byref(code))
                    if not queried or code.value == 259:
                        alive.append(pid)
                finally:
                    kernel32.CloseHandle(handle)
            elif ctypes.get_last_error() == 5:
                # Access denied is not evidence the process has exited.
                alive.append(pid)
        else:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                continue
            except PermissionError:
                pass
            except (OverflowError, OSError):
                continue
            alive.append(pid)
    return alive
