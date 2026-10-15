"""Failure boundaries must never turn missing evidence into accepted work."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from veacode.config import config_from_dict
from veacode.controller import Controller
from veacode.models import AdapterResult
from veacode.store import Store


class FixtureAdapter:
    def __init__(self, action=None):
        self.action = action
        self.calls = []

    def run(self, route, request, on_event, on_started):
        self.calls.append(request.phase)
        if self.action:
            self.action(request)
        text = (
            '{"accepted": true, "summary": "Fixture result accepted"}'
            if request.phase == "review"
            else "Fixture stage completed"
        )
        return AdapterResult(True, text=text)


class ControllerGuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.workspace = self.root / "repo"
        self.workspace.mkdir()
        self.git("init", "-q")
        (self.workspace / "example.txt").write_text("original\n", encoding="utf-8")
        self.git("add", "example.txt")
        self.git(
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "initial",
        )
        self.config = config_from_dict(
            {
                "routes": {
                    "fixture": {
                        "harness": "codex",
                        "model": "FAKE",
                        "provider": "openai",
                        "billing": "chatgpt_subscription",
                    }
                },
                "routing": {phase: ["fixture"] for phase in ("plan", "execute", "review")},
            }
        )
        self.store = Store(self.root / "state")
        self.addCleanup(self.store.close)

    def git(self, *argv):
        return subprocess.run(
            ["git", "-C", str(self.workspace), *argv],
            check=True,
            capture_output=True,
            timeout=20,
        )

    def submit(self, controller, checks=None):
        return controller.submit(
            {
                "goal": "Complete a fixture task",
                "checks": checks or [["{python}", "-c", "print('verified')"]],
            },
            self.workspace,
        )

    def hide_git(self):
        source = (self.workspace / ".git").resolve()
        target = (self.workspace / ".git-hidden").resolve()
        self.assertTrue(source.is_relative_to(self.workspace))
        self.assertTrue(target.is_relative_to(self.workspace))
        source.rename(target)

    def test_git_loss_during_execution_blocks_checks_and_review(self):
        marker = self.root / "checks-ran.txt"

        def remove_git_during_execute(request):
            if request.phase == "execute":
                self.hide_git()

        adapter = FixtureAdapter(remove_git_during_execute)
        controller = Controller(self.config, self.store, lambda _: adapter)
        check = [
            "{python}",
            "-c",
            f"from pathlib import Path; Path({str(marker)!r}).write_text('ran')",
        ]
        task = self.submit(controller, [check])
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual(adapter.calls, ["plan", "execute"])
        self.assertFalse(marker.exists())

    def test_git_loss_during_verification_blocks_review(self):
        adapter = FixtureAdapter()
        controller = Controller(self.config, self.store, lambda _: adapter)
        # This is an explicitly trusted fixture command, operating only inside temp repo.
        check = [
            "{python}",
            "-c",
            "from pathlib import Path; root=Path.cwd().resolve(); "
            "source=(root/'.git').resolve(); target=(root/'.git-hidden').resolve(); "
            "assert source.is_relative_to(root) and target.is_relative_to(root); "
            "source.rename(target)",
        ]
        task = self.submit(controller, [check])
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertNotIn("review", adapter.calls)
        self.assertTrue(result["data"]["checks"][0]["passed"])

    def test_custom_runtime_directory_cannot_become_workspace_evidence(self):
        with Store(self.workspace / "runtime-state") as internal_store:
            controller = Controller(self.config, internal_store, lambda _: FixtureAdapter())
            with self.assertRaises(ValueError):
                self.submit(controller)

    def test_crash_after_recorded_readonly_violation_still_requires_reconciliation(self):
        def change_file_during_plan(request):
            if request.phase == "plan":
                (self.workspace / "example.txt").write_text("unexpected edit\n", encoding="utf-8")

        adapter = FixtureAdapter(change_file_during_plan)
        controller = Controller(self.config, self.store, lambda _: adapter)
        task = self.submit(controller)
        original_finish = self.store.finish_attempt

        def crash_after_finished_attempt(attempt_id, result):
            original_finish(attempt_id, result)
            raise SystemExit("Simulated crash before pause/checkpoint could be saved")

        with patch.object(self.store, "finish_attempt", side_effect=crash_after_finished_attempt):
            with self.assertRaises(SystemExit):
                controller.run(task["id"])
        self.assertEqual(adapter.calls, ["plan"])
        restarted = Controller(self.config, self.store, lambda _: adapter)
        result = restarted.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual(adapter.calls, ["plan"], "Do not conceal violation with another model")


if __name__ == "__main__":
    unittest.main()
