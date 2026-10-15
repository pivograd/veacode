"""Bounded, shell-free adapters for the three supported agent CLIs.

The controller owns routing and paid-access consent. These adapters enforce the
configured billing channel and confine the agent's tool surface. Credentials are
inherited only for the selected provider and never included in our event log.
"""

from __future__ import annotations

import json
import math
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from .models import Adapter, AdapterResult, FailureKind, Route, RunRequest
from .workspace import _WindowsJob

MAX_LINE_BYTES = 256 * 1024
MAX_TEXT_CHARS = 256 * 1024
MAX_LOG_BYTES = 4 * 1024 * 1024
MAX_STREAM_BYTES = 32 * 1024 * 1024
_SECRET_NAME = re.compile(r"(?:KEY|TOKEN|PASSWORD|SECRET|AUTH)", re.I)
_PROVIDER_PREFIXES = (
    "ANTHROPIC_",
    "OPENAI_",
    "CODEX_",
    "CLAUDE_",
    "DEEPSEEK_",
    "OPENROUTER_",
    "GEMINI_",
    "GOOGLE_API",
    "AWS_",
    "AZURE_OPENAI_",
    "OPENCODE_",
    "LITELLM_",
    "TOGETHER_",
    "GROQ_",
    "MISTRAL_",
)
_REDACTED = "[REDACTED]"


def redact(text: str, secrets: Iterable[str] = ()) -> str:
    """Redact known environment credentials and common credential syntax."""
    for secret in sorted({x for x in secrets if len(x) >= 8}, key=len, reverse=True):
        text = text.replace(secret, _REDACTED)
        text = text.replace(json.dumps(secret)[1:-1], _REDACTED)
    text = re.sub(r"\b(?:sk-(?:ant-)?|gh[pousr]_|github_pat_)[A-Za-z0-9_-]{12,}", _REDACTED, text)
    text = re.sub(r"(?i)(\bbearer\s+)[^\s\"'<>]+", r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)((?:api[_-]?key|access[_-]?token|auth[_-]?token|password|client[_-]?secret)"
        r"[\"']?\s*[:=]\s*[\"']?)([^\s\"',;}]+)",
        lambda match: (
            match.group(0)
            if match.group(2).lower() in {"true", "false", "null", "none", "0", "1"}
            else match.group(1) + _REDACTED
        ),
        text,
    )
    return text


def _scrub(value: Any, secrets: list[str], depth: int = 0) -> Any:
    if depth > 12:
        return "<nested data omitted>"
    if isinstance(value, str):
        return redact(value, secrets)[:MAX_TEXT_CHARS]
    if isinstance(value, dict):
        return {
            str(key): (
                _REDACTED
                if re.search(
                    r"(?i)^(?:api[_-]?key|authorization|access[_-]?token|refresh[_-]?token|password|secret)$",
                    str(key),
                )
                else _scrub(item, secrets, depth + 1)
            )
            for key, item in list(value.items())[:1000]
        }
    if isinstance(value, list):
        return [_scrub(x, secrets, depth + 1) for x in value[:1000]]
    return value


def classify_failure(error: Any) -> FailureKind:
    """Prefer provider codes/HTTP statuses over ambiguous prose."""
    codes: list[str] = []
    messages: list[str] = []

    def walk(value: Any, depth: int = 0) -> None:
        if depth > 8:
            return
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {
                    "code",
                    "error_code",
                    "type",
                    "name",
                    "status",
                    "statusCode",
                    "status_code",
                    "http_status",
                }:
                    if isinstance(item, (str, int)):
                        codes.append(str(item).lower())
                if key in {"message", "error", "errors", "detail", "data", "cause"}:
                    walk(item, depth + 1)
        elif isinstance(value, list):
            for item in value[:100]:
                walk(item, depth + 1)
        elif isinstance(value, str):
            messages.append(value.lower())

    walk(error)
    groups = (
        (
            FailureKind.QUOTA,
            {
                "usage_limit_reached",
                "quota_exceeded",
                "insufficient_quota",
                "quota_error",
                "subscription_limit_reached",
            },
        ),
        (
            FailureKind.BALANCE,
            {
                "402",
                "insufficient_balance",
                "insufficient_credits",
                "billing_hard_limit_reached",
                "credit_balance_too_low",
            },
        ),
        (
            FailureKind.AUTH,
            {
                "401",
                "authentication_error",
                "invalid_api_key",
                "unauthorized",
                "apikeymissingerror",
                "providerautherror",
            },
        ),
        (FailureKind.PERMISSION, {"403", "permission_error", "permission_denied", "forbidden"}),
        (
            FailureKind.RATE_LIMIT,
            {"429", "rate_limit_error", "rate_limit_exceeded", "rate_limit", "too_many_requests"},
        ),
        (
            FailureKind.NETWORK,
            {
                "500",
                "502",
                "503",
                "504",
                "529",
                "overloaded_error",
                "api_connection_error",
                "econnreset",
                "enotfound",
            },
        ),
        (FailureKind.TIMEOUT, {"408", "504", "request_timeout", "timeout_error"}),
    )
    for kind, known in groups:
        if any(code in known for code in codes):
            return kind
    message = " ".join(messages)
    patterns = (
        (
            FailureKind.BALANCE,
            r"insufficient (?:balance|credits)|credit balance|billing.+limit|payment required",
        ),
        (
            FailureKind.QUOTA,
            r"usage limit|quota|weekly limit|daily limit|out of.+(?:usage|tokens)|"
            r"hit your limit|limit resets|you.ve reached your.+limit",
        ),
        (
            FailureKind.AUTH,
            r"unauthenticated|unauthorized|authentication|not logged in|log in|login required|"
            r"invalid.+(?:key|token)|api key.+(?:missing|required)|oauth.+expired",
        ),
        (
            FailureKind.PERMISSION,
            r"permission denied|access denied|not permitted|forbidden|permission prompts",
        ),
        (FailureKind.RATE_LIMIT, r"rate.limit|too many requests|retry.after"),
        (FailureKind.TIMEOUT, r"timed out|timeout"),
        (
            FailureKind.NETWORK,
            r"network|connection|dns|unreachable|overloaded|fetch failed|tls|certificate|"
            r"service unavailable",
        ),
        (
            FailureKind.UNAVAILABLE,
            r"unknown option|unknown argument|unrecognized argument|unknown model|"
            r"model.+not found|not supported|unsupported",
        ),
    )
    for kind, pattern in patterns:
        if re.search(pattern, message):
            return kind
    return FailureKind.PROCESS


def _resolve_executable(harness: str, override: str | None = None) -> list[str]:
    """Never execute a Windows .cmd/.bat through cmd.exe with agent input."""
    candidate = override or harness
    found = shutil.which(candidate)
    if not found and Path(candidate).is_file():
        found = str(Path(candidate).resolve())
    if not found:
        raise FileNotFoundError(f"{harness} executable not found")
    path = Path(found)
    if path.suffix.lower() in {".cmd", ".bat", ".ps1"}:
        packages = {
            "codex": Path("node_modules/@openai/codex/bin/codex.js"),
            "claude": Path("node_modules/@anthropic-ai/claude-code/cli.js"),
            "opencode": Path("node_modules/opencode-ai/bin/opencode"),
        }
        relative = packages[harness]
        bases = [path.parent / "node_modules"]
        if path.parent.name == ".bin":
            bases.insert(0, path.parent.parent)
        node = shutil.which("node")
        for base in bases:
            script = base / relative.relative_to("node_modules")
            if harness == "opencode" and script.with_suffix(".exe").is_file():
                return [str(script.with_suffix(".exe"))]
            if node and script.is_file():
                return [node, str(script)]
        raise FileNotFoundError(
            f"{harness} npm launcher needs node and its standard package entry point"
        )
    if path.suffix.lower() == ".py":
        return [sys.executable, str(path)]
    return [str(path)]


def _environment(route: Route) -> tuple[dict[str, str], list[str]]:
    merged = dict(os.environ)
    merged.update(route.env)
    secrets = [value for key, value in merged.items() if _SECRET_NAME.search(key)]
    env = {
        key: value
        for key, value in merged.items()
        if not key.upper().startswith(_PROVIDER_PREFIXES) and not _SECRET_NAME.search(key)
    }
    env.update({"NO_COLOR": "1", "TERM": "dumb", "PYTHONIOENCODING": "utf-8"})
    if route.harness == "codex":
        env["CODEX_HOME"] = str(
            Path(
                route.env.get("CODEX_HOME")
                or os.environ.get("CODEX_HOME")
                or Path.home() / ".codex"
            )
            .expanduser()
            .resolve()
        )
    elif route.harness == "claude":
        env["CLAUDE_CODE_SAFE_MODE"] = "1"
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
    elif route.harness == "opencode" and merged.get("DEEPSEEK_API_KEY"):
        env["DEEPSEEK_API_KEY"] = merged["DEEPSEEK_API_KEY"]
    return env, secrets


def _safe_profile_effort(route: Route, env: dict[str, str]) -> str | None:
    """Reuse only effort from the old delegate profile, never its integrations."""
    if not route.profile:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", route.profile):
        raise ValueError("Codex profile must be a simple name")
    home = Path(env["CODEX_HOME"])
    candidates = [home / f"{route.profile}.config.toml", home / "config.toml"]
    for path in candidates:
        try:
            if path.stat().st_size > 1024 * 1024:
                continue
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            profile = (
                data.get("profiles", {}).get(route.profile, {})
                if path.name == "config.toml"
                else data
            )
            effort = profile.get("model_reasoning_effort")
            if isinstance(effort, str) and effort in {
                "minimal",
                "low",
                "medium",
                "high",
                "xhigh",
                "max",
                "ultra",
            }:
                return effort
        except (OSError, ValueError):
            continue
    return None


def _check_opencode_project(workspace: Path) -> None:
    """Do not merge project plugins/providers/agent permissions into this run."""
    current = workspace.resolve()
    while True:
        if any(
            (current / name).exists() for name in ("opencode.json", "opencode.jsonc", ".opencode")
        ):
            raise ValueError(
                "OpenCode project configuration detected; the isolated adapter requires a "
                "workspace without opencode.json, opencode.jsonc or .opencode customizations"
            )
        if (current / ".git").exists() or current.parent == current:
            break
        current = current.parent


def _check_codex_project(workspace: Path) -> None:
    """--ignore-user-config excludes the user file, not project config layers."""
    current = workspace.resolve()
    while True:
        if (current / ".codex" / "config.toml").exists():
            raise ValueError(
                "Codex project configuration detected; the isolated adapter currently "
                "requires a workspace without .codex/config.toml"
            )
        if (current / ".git").exists() or current.parent == current:
            break
        current = current.parent


def _build_command(
    route: Route, request: RunRequest, env: dict[str, str]
) -> tuple[list[str], bytes | None]:
    executable = _resolve_executable(route.harness, route.executable)
    if route.harness == "codex":
        if (route.provider, route.billing) != ("openai", "chatgpt_subscription"):
            raise ValueError("Codex supports only OpenAI ChatGPT subscription routes")
        if (Path(env["CODEX_HOME"]) / ".env").exists():
            raise ValueError(
                "CODEX_HOME/.env detected; Codex loads it before CLI configuration, "
                "so this adapter cannot guarantee subscription/provider isolation"
            )
        _check_codex_project(request.workspace)
        args = [
            "exec",
            "--ignore-user-config",
            "--ephemeral",
            "--json",
            "--color",
            "never",
            "--cd",
            str(request.workspace),
            "--sandbox",
            "read-only" if request.read_only else "workspace-write",
            "--model",
            route.model,
            "-c",
            'forced_login_method="chatgpt"',
            "-c",
            'model_provider="openai"',
            "-c",
            'approval_policy="never"',
            "-c",
            "mcp_servers={}",
            "-c",
            "features.multi_agent=false",
            "-c",
            "features.multi_agent_v2=false",
            "-c",
            "agents.enabled=false",
            "-c",
            "features.apps=false",
            "-c",
            "features.plugins=false",
            "-c",
            "features.hooks=false",
            "-c",
            'web_search="disabled"',
            "-c",
            "sandbox_workspace_write.network_access=false",
        ]
        effort = route.effort or _safe_profile_effort(route, env)
        if effort:
            args.extend(["-c", f"model_reasoning_effort={json.dumps(effort)}"])
        return executable + args + ["-"], request.prompt.encode("utf-8")
    if route.harness == "claude":
        if (route.provider, route.billing) != ("anthropic", "claude_subscription"):
            raise ValueError("Claude supports only Anthropic subscription routes")
        tools = "Read,Glob,Grep" + ("" if request.read_only else ",Edit,Write")
        settings = {
            "permissions": {
                "allow": tools.split(","),
                "deny": ["Bash", "Agent", "Task", "WebFetch", "WebSearch", "mcp__*"],
            }
        }
        args = [
            "--print",
            "--safe-mode",
            "--restricted",
            "--permission-prompts",
            "none",
            "--output-format",
            "stream-json",
            "--verbose",
            "--model",
            route.model,
            "--tools",
            tools,
            "--allowedTools",
            tools,
            "--strict-mcp-config",
            "--mcp-config",
            '{"mcpServers":{}}',
            "--settings",
            json.dumps(settings, separators=(",", ":")),
            "--permission-mode",
            "dontAsk" if request.read_only else "acceptEdits",
        ]
        if route.effort:
            args.extend(["--effort", route.effort])
        return executable + args, request.prompt.encode("utf-8")
    if route.harness == "opencode":
        if (route.provider, route.billing) != ("deepseek", "deepseek_api"):
            raise ValueError("OpenCode supports only DeepSeek API routes in this version")
        if not env.get("DEEPSEEK_API_KEY"):
            raise PermissionError("DEEPSEEK_API_KEY is not configured")
        _check_opencode_project(request.workspace)
        isolated = request.run_dir / "opencode"
        for kind in ("config", "data", "state", "cache"):
            location = isolated / kind
            location.mkdir(parents=True, exist_ok=True)
            env[f"XDG_{kind.upper()}_HOME"] = str(location.resolve())
        env["OPENCODE_CONFIG_DIR"] = str((isolated / "config").resolve())
        protected_paths = {
            "*.env": "deny",
            "*.env.*": "deny",
            "*.key": "deny",
            "*.pem": "deny",
            "*.p12": "deny",
            "*.pfx": "deny",
            "*auth.json": "deny",
            "*credentials.json": "deny",
            "*.npmrc": "deny",
            "*.pypirc": "deny",
            "*.netrc": "deny",
        }
        for directory in (".veacode", ".git", ".ssh", ".aws", ".codex", ".claude"):
            for separator in ("/", "\\"):
                for prefix in ("", f"*{separator}"):
                    protected_paths[f"{prefix}{directory}"] = "deny"
                    protected_paths[f"{prefix}{directory}{separator}*"] = "deny"
        read_rules = {"*": "allow", **protected_paths}
        edit_rules = {"*": "deny" if request.read_only else "allow", **protected_paths}
        permission = {
            "*": "deny",
            "read": read_rules,
            "glob": "allow",
            "grep": "allow",
            "edit": edit_rules,
            "external_directory": "deny",
            "bash": "deny",
            "task": "deny",
            "skill": "deny",
            "webfetch": "deny",
            "websearch": "deny",
            "question": "deny",
        }
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]*", route.model):
            raise ValueError("OpenCode model must be a bare DeepSeek model ID")
        model = f"deepseek/{route.model}"
        config = {
            "$schema": "https://opencode.ai/config.json",
            "model": model,
            "small_model": model,
            "enabled_providers": ["deepseek"],
            "share": "disabled",
            "autoupdate": False,
            "permission": permission,
            "mcp": {},
            "plugin": [],
            "formatter": False,
            "lsp": False,
            "provider": {
                "deepseek": {
                    "options": {
                        "apiKey": "{env:DEEPSEEK_API_KEY}",
                        "baseURL": "https://api.deepseek.com",
                    }
                }
            },
            "agent": {
                "veacode": {
                    "description": "Isolated veacode task executor",
                    "mode": "primary",
                    "model": model,
                    "permission": permission,
                }
            },
        }
        env.update(
            {
                "OPENCODE_CONFIG_CONTENT": json.dumps(config, separators=(",", ":")),
                "OPENCODE_PERMISSION": json.dumps(permission, separators=(",", ":")),
                "OPENCODE_DISABLE_AUTOUPDATE": "true",
                "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
                "OPENCODE_DISABLE_CLAUDE_CODE": "true",
                "OPENCODE_DISABLE_LSP_DOWNLOAD": "true",
                "OPENCODE_AUTO_SHARE": "false",
            }
        )
        args = ["run", "--pure", "--format", "json", "--model", model, "--agent", "veacode"]
        if route.effort:
            args.extend(["--variant", route.effort])
        # OpenCode documents a positional prompt; no shell ever interprets it.
        return executable + args + ["--", request.prompt], None
    raise ValueError(f"Unsupported harness: {route.harness}")


def _kill_tree(process: subprocess.Popen[bytes], job: _WindowsJob | None = None) -> None:
    if job is not None:
        job.terminate()
    elif os.name == "nt":
        try:
            subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=8,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        if process.poll() is None:
            process.kill()
    else:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()


class _Transcript:
    def __init__(self, harness: str):
        self.harness = harness
        self.text = ""
        self.session_id: str | None = None
        self.observed_model: str | None = None
        self.usage: dict[str, Any] = {}
        self.failure: FailureKind | None = None
        self.message = ""
        self.completed = False

    def ingest(self, event: dict[str, Any]) -> None:
        kind = event.get("type", "")
        if not isinstance(kind, str):
            return
        session = event.get("session_id") or event.get("sessionID") or event.get("thread_id")
        if isinstance(session, str):
            self.session_id = session
        if isinstance(event.get("model"), str):
            self.observed_model = event["model"]
        if self.harness == "codex":
            item = event.get("item", {})
            if (
                kind == "item.completed"
                and isinstance(item, dict)
                and item.get("type") == "agent_message"
            ):
                text = item.get("text")
                self.text = text[:MAX_TEXT_CHARS] if isinstance(text, str) else ""
            if kind == "turn.completed":
                self.completed = True
                usage = event.get("usage", {})
                self.usage = usage if isinstance(usage, dict) else {}
            if kind in {"turn.failed", "error"}:
                self.failure = classify_failure(event.get("error", event))
                self.message = str(
                    event.get("error", event.get("message", "Codex reported failure"))
                )[:4096]
        elif self.harness == "claude":
            message = event.get("message", {})
            if kind == "assistant" and isinstance(message, dict):
                if isinstance(message.get("model"), str):
                    self.observed_model = message["model"]
                blocks = message.get("content", [])
                if isinstance(blocks, list):
                    text = "".join(
                        str(b.get("text", ""))
                        for b in blocks
                        if isinstance(b, dict) and b.get("type") == "text"
                    )
                    if text:
                        self.text = text[:MAX_TEXT_CHARS]
            if kind == "result":
                self.completed = (
                    not event.get("is_error", False)
                    and event.get("subtype", "success") == "success"
                )
                text = event.get("result", self.text)
                self.text = text[:MAX_TEXT_CHARS] if isinstance(text, str) else ""
                usage = event.get("usage", {})
                self.usage = usage if isinstance(usage, dict) else {}
                if "total_cost_usd" in event:
                    self.usage = dict(self.usage, total_cost_usd=event["total_cost_usd"])
                model_usage = event.get("modelUsage", {})
                if isinstance(model_usage, dict) and model_usage:
                    self.observed_model = next(iter(model_usage))
                if not self.completed:
                    self.failure = classify_failure(event)
                    self.message = str(
                        event.get("errors") or event.get("result") or event.get("subtype")
                    )[:4096]
                if event.get("permission_denials"):
                    self.failure = FailureKind.PERMISSION
                    self.message = "Claude reported denied tool permissions"
            if kind == "error":
                self.failure = classify_failure(event)
                self.message = str(
                    event.get("error", event.get("message", "Claude reported failure"))
                )[:4096]
        else:
            part = event.get("part", {})
            if not isinstance(part, dict):
                part = {}
            if kind == "text":
                text = part.get("text", event.get("text", ""))
                if isinstance(text, str):
                    self.text = (self.text + text)[:MAX_TEXT_CHARS]
            if kind == "step_finish":
                self.completed = part.get("reason") in {"stop", "end_turn"}
                tokens = part.get("tokens", {})
                if isinstance(tokens, dict):
                    for key, value in tokens.items():
                        if isinstance(value, (int, float)):
                            self.usage[key] = self.usage.get(key, 0) + value
                if isinstance(part.get("cost"), (int, float)):
                    self.usage["cost_usd"] = self.usage.get("cost_usd", 0) + part["cost"]
                    self.usage["cost_kind"] = "estimate"
                    self.usage["cost_source"] = "opencode_catalog"
            if isinstance(part.get("modelID"), str):
                self.observed_model = part["modelID"]
            if kind == "error":
                self.failure = classify_failure(event.get("error", event))
                self.message = str(
                    event.get("error", event.get("message", "OpenCode reported failure"))
                )[:4096]


class CLIAdapter:
    def __init__(self, harness: str):
        self.harness = harness

    def run(self, route: Route, request: RunRequest, on_event, on_started) -> AdapterResult:
        if route.harness != self.harness:
            return AdapterResult(
                False, failure=FailureKind.UNAVAILABLE, message="Adapter and route harness differ"
            )
        if not math.isfinite(route.timeout_seconds) or route.timeout_seconds <= 0:
            return AdapterResult(
                False, failure=FailureKind.PROTOCOL, message="Timeout must be positive and finite"
            )
        request.run_dir.mkdir(parents=True, exist_ok=True)
        env, secrets = _environment(route)
        try:
            command, prompt = _build_command(route, request, env)
        except FileNotFoundError as exc:
            return AdapterResult(
                False, failure=FailureKind.UNAVAILABLE, message=redact(str(exc), secrets)
            )
        except PermissionError as exc:
            return AdapterResult(False, failure=FailureKind.AUTH, message=redact(str(exc), secrets))
        except (ValueError, OSError) as exc:
            return AdapterResult(
                False, failure=FailureKind.PERMISSION, message=redact(str(exc), secrets)
            )
        job = None
        try:
            if os.name == "nt":
                job = _WindowsJob()
            process = subprocess.Popen(
                command,
                cwd=request.workspace,
                env=env,
                stdin=subprocess.PIPE if prompt is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=os.name != "nt",
                creationflags=(
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                if os.name == "nt"
                else 0,
            )
            if job is not None:
                try:
                    job.attach(process)
                except OSError:
                    process.kill()
                    process.wait(timeout=5)
                    raise
        except OSError as exc:
            if job is not None:
                job.close()
            return AdapterResult(
                False, failure=FailureKind.UNAVAILABLE, message=redact(str(exc), secrets)
            )
        chunks: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=32)
        stop = threading.Event()

        def put(tag: str, data: bytes | None) -> None:
            while not stop.is_set():
                try:
                    chunks.put((tag, data), timeout=0.1)
                    return
                except queue.Full:
                    pass

        def read_pipe(tag: str, pipe) -> None:
            try:
                while not stop.is_set():
                    data = pipe.read1(8192)
                    if not data:
                        break
                    put(tag, data)
            except (OSError, ValueError):
                pass
            finally:
                put(tag, None)

        def write_prompt() -> None:
            try:
                if process.stdin:
                    process.stdin.write(prompt or b"")
                    process.stdin.close()
            except (OSError, ValueError):
                pass

        transcript = _Transcript(self.harness)
        tail = ""
        buffers = {"stdout": b"", "stderr": b""}
        streams_done: set[str] = set()
        total = 0
        log_size = 0
        forced: FailureKind | None = None
        deadline = time.monotonic() + route.timeout_seconds
        threads: list[threading.Thread] = []
        try:
            on_started(process.pid)
            for tag, pipe in (("stdout", process.stdout), ("stderr", process.stderr)):
                thread = threading.Thread(target=read_pipe, args=(tag, pipe), daemon=True)
                thread.start()
                threads.append(thread)
            if prompt is not None:
                thread = threading.Thread(target=write_prompt, daemon=True)
                thread.start()
                threads.append(thread)
            with (request.run_dir / "process.jsonl").open("w", encoding="utf-8") as log:

                def emit(tag: str, raw: bytes) -> None:
                    nonlocal tail, log_size
                    line = redact(raw.decode("utf-8", errors="replace"), secrets)
                    if not line.strip():
                        return
                    try:
                        value = json.loads(line) if tag == "stdout" else None
                    except (ValueError, RecursionError):
                        value = None
                    if isinstance(value, dict):
                        clean = _scrub(value, secrets)
                        transcript.ingest(clean)
                        event = {"stream": tag, "event": clean}
                    else:
                        tail = (tail + "\n" + line)[-16384:]
                        event = {"stream": tag, "text": line[:16384]}
                    encoded = json.dumps(event, ensure_ascii=False)
                    if len(encoded.encode("utf-8")) > MAX_LINE_BYTES:
                        event = {
                            "stream": tag,
                            "type": "oversized_event",
                            "message": "CLI event omitted due to size",
                        }
                        encoded = json.dumps(event)
                    if log_size + len(encoded.encode("utf-8")) + 1 <= MAX_LOG_BYTES:
                        log.write(encoded + "\n")
                        log.flush()
                        log_size += len(encoded.encode("utf-8")) + 1
                        on_event(event)

                while len(streams_done) < 2:
                    if time.monotonic() >= deadline:
                        forced = FailureKind.TIMEOUT
                        break
                    try:
                        tag, data = chunks.get(
                            timeout=min(0.1, max(0.001, deadline - time.monotonic()))
                        )
                    except queue.Empty:
                        continue
                    if data is None:
                        if buffers[tag]:
                            emit(tag, buffers[tag])
                            buffers[tag] = b""
                        streams_done.add(tag)
                        continue
                    total += len(data)
                    if total > MAX_STREAM_BYTES:
                        forced = FailureKind.PROTOCOL
                        break
                    buffers[tag] += data
                    while b"\n" in buffers[tag]:
                        line, buffers[tag] = buffers[tag].split(b"\n", 1)
                        if len(line) > MAX_LINE_BYTES:
                            forced = FailureKind.PROTOCOL
                            break
                        emit(tag, line)
                    if forced or len(buffers[tag]) > MAX_LINE_BYTES:
                        forced = FailureKind.PROTOCOL
                        break
            if forced:
                _kill_tree(process, job)
            else:
                try:
                    process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    forced = FailureKind.TIMEOUT
                    _kill_tree(process, job)
        except BaseException:
            _kill_tree(process, job)
            raise
        finally:
            stop.set()
            if job is not None:
                job.close()
            elif os.name != "nt":
                # A successful parent can leave children with closed output pipes.
                # This group belongs to our start_new_session=True invocation.
                _kill_tree(process)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe:
                    try:
                        pipe.close()
                    except OSError:
                        pass
            for thread in threads:
                thread.join(timeout=0.5)
        failure = forced or transcript.failure
        message = transcript.message
        if forced:
            message = (
                "Agent process timed out"
                if forced == FailureKind.TIMEOUT
                else "Agent output exceeded the bounded protocol limit"
            )
        if failure is None and process.returncode != 0:
            failure = classify_failure(tail)
            message = tail.strip()[-4096:] or f"Agent exited with code {process.returncode}"
        if failure is None and (not transcript.completed or not transcript.text.strip()):
            failure = FailureKind.PROTOCOL
            message = "CLI exited without a successful completion event and final text"
        return AdapterResult(
            success=failure is None,
            text=redact(transcript.text, secrets),
            failure=failure,
            message=redact(message, secrets),
            session_id=transcript.session_id,
            usage=transcript.usage,
            observed_model=transcript.observed_model,
            exit_code=process.returncode,
        )


def make_adapter(harness: str) -> Adapter:
    if harness not in {"codex", "claude", "opencode"}:
        raise ValueError(f"Unsupported harness: {harness}")
    return CLIAdapter(harness)


class AdapterRegistry:
    def __init__(self, adapters: dict[str, Adapter] | None = None):
        self.adapters = adapters or {}

    def get(self, harness: str) -> Adapter:
        return self.adapters.get(harness) or make_adapter(harness)


def availability(route: Route) -> dict[str, Any]:
    """Read-only executable/key presence probe; never invokes a model."""
    try:
        command = _resolve_executable(route.harness, route.executable)
        result: dict[str, Any] = {"available": True, "executable": command[0]}
    except (FileNotFoundError, KeyError) as exc:
        result = {"available": False, "message": str(exc)}
    if route.harness == "opencode":
        result["api_key_configured"] = bool(
            route.env.get("DEEPSEEK_API_KEY") or os.environ.get("DEEPSEEK_API_KEY")
        )
        result["ready"] = result["available"] and result["api_key_configured"]
    else:
        result["ready"] = result["available"]
    return result
