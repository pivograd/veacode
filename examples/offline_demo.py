"""Reproducible controller demonstration; no external model requests or credentials."""

import json
import subprocess
import sys
from pathlib import Path

from veacode.config import config_from_dict
from veacode.controller import Controller
from veacode.models import AdapterResult, FailureKind
from veacode.store import Store


class LocalSimulation:
    def run(self, route, request, on_event, on_started):
        on_event({"simulation": True, "phase": request.phase, "route": route.name})
        if route.name == "unavailable_max":
            return AdapterResult(
                False,
                failure=FailureKind.QUOTA,
                message="Simulated exhausted Max; no provider contacted",
            )
        if request.phase == "plan":
            return AdapterResult(True, text="Fix addition in maths.py; run the trusted unit tests.")
        if request.phase == "execute":
            (request.workspace / "maths.py").write_text(
                "def add(a, b):\n    return a + b\n",
                encoding="utf-8",
            )
            return AdapterResult(True, text="Fixed addition. This result comes from a simulation.")
        return AdapterResult(
            True,
            text=json.dumps(
                {
                    "accepted": True,
                    "summary": "Local simulation accepted the tested addition fix",
                }
            ),
        )


def main():
    workspace = Path(sys.argv[1] if len(sys.argv) > 1 else "_scratch/offline-demo").resolve()
    if workspace.exists():
        raise SystemExit("Choose a new demo directory; existing files are never overwritten.")
    workspace.mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    (workspace / ".gitignore").write_text(".veacode/\n__pycache__/\n", encoding="utf-8")
    (workspace / "maths.py").write_text("def add(a, b):\n    return a - b\n", encoding="utf-8")
    (workspace / "test_maths.py").write_text(
        "import unittest\nfrom maths import add\n"
        "class AdditionTests(unittest.TestCase):\n"
        "    def test_positive(self): self.assertEqual(add(2, 3), 5)\n"
        "    def test_negative(self): self.assertEqual(add(-2, -3), -5)\n"
        "    def test_zero(self): self.assertEqual(add(5, 0), 5)\n",
        encoding="utf-8",
    )
    config = config_from_dict(
        {
            "routes": {
                "unavailable_max": {
                    "harness": "claude",
                    "model": "SIMULATED",
                    "provider": "anthropic",
                    "billing": "claude_subscription",
                },
                "local_reserve": {
                    "harness": "codex",
                    "model": "SIMULATED",
                    "provider": "openai",
                    "billing": "chatgpt_subscription",
                },
            },
            "routing": {
                phase: ["unavailable_max", "local_reserve"]
                for phase in ("plan", "execute", "review")
            },
        }
    )
    with Store(workspace / ".veacode") as store:
        controller = Controller(config, store, lambda _: LocalSimulation())
        task = controller.submit(
            {
                "goal": "Correct addition; preserve test files",
                "checks": [["{python}", "-m", "unittest", "discover", "-v"]],
            },
            workspace,
        )
        result = controller.run(task["id"])
        print(
            json.dumps(
                {
                    "simulation": True,
                    "task_id": task["id"],
                    "status": result["status"],
                    "workspace": str(workspace),
                    "attempts": len(store.attempts(task["id"])),
                    "checks": result["data"].get("checks"),
                },
                indent=2,
            )
        )
        return 0 if result["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
