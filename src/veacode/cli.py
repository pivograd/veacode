"""Human and script friendly command-line entry point."""

import argparse
import json
import os
import shutil
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

from . import __version__
from .config import load_config
from .controller import Controller, validate_state_directory
from .security import redact
from .spec import load_spec
from .store import LockBusy, Store


def _print(value: object) -> None:
    print(json.dumps(redact(value), ensure_ascii=False, indent=2, default=str))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="veacode", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Write a configuration template, without credentials")
    init.add_argument("--output", type=Path, default=Path("veacode.toml"))
    for name in ("doctor", "routes", "run", "submit", "resume", "status", "events", "list"):
        command = commands.add_parser(name)
        command.add_argument("--state-dir", type=Path, default=Path(".veacode"))
        if name in {"doctor", "routes", "run", "resume"}:
            command.add_argument("--config", type=Path, default=Path("veacode.toml"))
        if name in {"run", "submit"}:
            command.add_argument("--spec", type=Path, required=True)
            command.add_argument("--workspace", type=Path, required=True)
        if name in {"resume", "status", "events"}:
            command.add_argument("task_id")
        if name == "resume":
            command.add_argument(
                "--reconcile",
                action="store_true",
                help="After inspecting files/processes, accept uncertain local state",
            )
    return parser


def _doctor(config_path: Path) -> dict:
    config = load_config(config_path)
    routes = []
    for route in config.routes.values():
        name = route.executable or (
            "codex.cmd" if os.name == "nt" and route.harness == "codex" else route.harness
        )
        binary = shutil.which(name)
        item = {
            **route.public(),
            "installed": binary is not None,
            "permitted": config.permitted(route),
            "executable_path": binary,
        }
        if route.billing == "deepseek_api":
            item["key_configured"] = bool(os.environ.get("DEEPSEEK_API_KEY"))
        elif binary:
            env = dict(os.environ)
            env["CODEX_HOME"] = route.env.get("CODEX_HOME", str(Path.home() / ".codex"))
            args = (
                [binary, "login", "status"]
                if route.harness == "codex"
                else [binary, "auth", "status"]
            )
            try:
                result = subprocess.run(
                    args,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=env,
                    timeout=15,
                    check=False,
                )
                if route.harness == "claude":
                    auth = json.loads(result.stdout)
                    item["subscription_login"] = (
                        bool(auth.get("loggedIn")) and auth.get("authMethod") == "claude.ai"
                    )
                else:
                    output = result.stdout + result.stderr
                    item["subscription_login"] = result.returncode == 0 and "ChatGPT" in output
            except (OSError, subprocess.TimeoutExpired, ValueError):
                item["subscription_login"] = "unknown"
        routes.append(item)
    return {
        "python": sys.version.split()[0],
        "git": shutil.which("git"),
        "routes": routes,
        "note": "No model requests made; remaining quotas are unknown.",
    }


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "init":
            template = files("veacode").joinpath("default.toml").read_text(encoding="utf-8")
            with args.output.open("x", encoding="utf-8") as handle:
                handle.write(template)
            _print({"config": str(args.output.resolve()), "deepseek_enabled": False})
            return 0
        if args.command == "doctor":
            _print(_doctor(args.config))
            return 0
        if args.command == "routes":
            config = load_config(args.config)
            _print(
                {
                    "routes": [
                        {**route.public(), "permitted": config.permitted(route)}
                        for route in config.routes.values()
                    ],
                    "routing": config.routing,
                }
            )
            return 0
        with Store(args.state_dir) as store:
            if args.command == "list":
                _print(store.list_tasks())
            elif args.command == "status":
                _print(
                    {"task": store.get_task(args.task_id), "attempts": store.attempts(args.task_id)}
                )
            elif args.command == "events":
                _print(store.events(args.task_id))
            elif args.command == "submit":
                # Submission needs no installed harness, model credentials, or runtime policy.
                from .workspace import snapshot

                workspace = args.workspace.resolve(strict=True)
                evidence = snapshot(workspace)
                if not evidence.get("is_git"):
                    raise ValueError("Task workspace must be a Git repository")
                workspace = Path(evidence["root"]).resolve()
                validate_state_directory(store.state_dir, workspace)
                task = store.create_task(redact(load_spec(args.spec)), workspace)
                _print(task)
            else:
                controller = Controller(load_config(args.config), store)
                if args.command == "run":
                    task = controller.submit(load_spec(args.spec), args.workspace)
                    task_id = task["id"]
                    # Print ID before starting so an interrupted run remains discoverable.
                    print(f"task_id: {task_id}", file=sys.stderr, flush=True)
                else:
                    task_id = args.task_id
                task = controller.run(task_id, reconcile=getattr(args, "reconcile", False))
                _print(task)
                return 0 if task["status"] == "completed" else 2
        return 0
    except LockBusy as exc:
        _print({"error": "workspace_busy", "message": str(exc)})
        return 3
    except (OSError, ValueError, KeyError, RuntimeError) as exc:
        _print({"error": type(exc).__name__, "message": str(exc)})
        return 1
    except KeyboardInterrupt:
        _print(
            {"error": "interrupted", "message": "State preserved; inspect status before resume."}
        )
        return 130
