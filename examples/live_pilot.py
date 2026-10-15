"""Run a real reserve against an isolated task with the primary deliberately unavailable."""

import argparse
import hashlib
import json
import os
import subprocess
import uuid
from dataclasses import replace
from pathlib import Path

from veacode.config import Config, load_config
from veacode.controller import Controller
from veacode.store import Store


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("examples/veacode.toml"))
    parser.add_argument("--route", default="codex")
    parser.add_argument("--directory", type=Path)
    parser.add_argument(
        "--deepseek-key-file",
        type=Path,
        help="Read a local secret into this process only; never save it in task state",
    )
    parser.add_argument(
        "--prepare-only", action="store_true", help="Create fixture without model calls"
    )
    args = parser.parse_args()
    configured = load_config(args.config)
    if args.route not in configured.routes:
        parser.error("Unknown configured route")
    reserve = configured.routes[args.route]
    if args.deepseek_key_file:
        if reserve.billing != "deepseek_api":
            parser.error("A DeepSeek key file is only valid for a DeepSeek route")
        key = args.deepseek_key_file.read_text(encoding="utf-8-sig").strip()
        if not key or any(char.isspace() for char in key):
            parser.error("Key file must contain one nonempty API key")
        os.environ["DEEPSEEK_API_KEY"] = key
    if not configured.permitted(reserve):
        parser.error("Route disabled by policy; authorize DeepSeek in your configuration first")
    workspace = (
        args.directory or Path("_scratch") / f"live-pilot-{uuid.uuid4().hex[:8]}"
    ).resolve()
    if workspace.exists():
        parser.error("Pilot directory already exists; choose a fresh directory")
    workspace.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    (workspace / ".gitignore").write_text(".veacode/\n__pycache__/\n", encoding="utf-8")
    (workspace / "maths.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    tests = (
        "import unittest\nfrom maths import add\n"
        "class AdditionTests(unittest.TestCase):\n"
        "    def test_positive(self): self.assertEqual(add(2, 3), 5)\n"
        "    def test_negative(self): self.assertEqual(add(-2, -3), -5)\n"
        "    def test_zero(self): self.assertEqual(add(0, 7), 7)\n"
    )
    (workspace / "test_maths.py").write_text(tests, encoding="utf-8")
    # Hash the bytes actually written; Windows may translate LF into CRLF.
    digest = hashlib.sha256((workspace / "test_maths.py").read_bytes()).hexdigest()
    integrity_check = (
        "import hashlib; from pathlib import Path; "
        f"assert hashlib.sha256(Path('test_maths.py').read_bytes()).hexdigest() == {digest!r}"
    )
    unavailable = replace(
        reserve, name="unavailable_primary", executable=str(workspace / "absent-primary.exe")
    )
    config = Config(
        routes={unavailable.name: unavailable, reserve.name: reserve},
        routing={
            "plan": [unavailable.name, reserve.name],
            "execute": [reserve.name],
            "review": [reserve.name],
        },
        allow_deepseek=configured.allow_deepseek,
        max_repairs=configured.max_repairs,
        check_timeout_seconds=configured.check_timeout_seconds,
    )
    with Store(workspace / ".veacode") as store:
        controller = Controller(config, store)
        task = controller.submit(
            {
                "goal": "Fix addition in maths.py. Do not modify test_maths.py or .gitignore. "
                "The controller will check test integrity and run all three tests.",
                "constraints": ["Modify maths.py only", "No external actions or nested agents"],
                "checks": [
                    ["{python}", "-c", integrity_check],
                    ["{python}", "-m", "unittest", "discover", "-v"],
                ],
            },
            workspace,
        )
        print(
            json.dumps(
                {
                    "task_id": task["id"],
                    "workspace": str(workspace),
                    "state_dir": str(store.state_dir),
                    "reserve": reserve.public(),
                    "primary_intentionally_unavailable": True,
                    "prepare_only": args.prepare_only,
                },
                indent=2,
            ),
            flush=True,
        )
        if args.prepare_only:
            return 0
        result = controller.run(task["id"])
        print(
            json.dumps(
                {
                    "task_id": task["id"],
                    "status": result["status"],
                    "data": result["data"],
                    "attempts": store.attempts(task["id"]),
                },
                indent=2,
            )
        )
        return 0 if result["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
