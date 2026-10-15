import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from veacode.config import config_from_dict
from veacode.controller import Controller
from veacode.models import AdapterResult, FailureKind
from veacode.store import Store


def config(max_repairs=1):
    return config_from_dict(
        {
            "policy": {"max_repairs": max_repairs},
            "routes": {
                "primary": {
                    "harness": "claude",
                    "model": "test-supervisor",
                    "provider": "anthropic",
                    "billing": "claude_subscription",
                },
                "reserve": {
                    "harness": "codex",
                    "model": "test-worker",
                    "provider": "openai",
                    "billing": "chatgpt_subscription",
                },
            },
            "routing": {
                "plan": ["primary", "reserve"],
                "execute": ["reserve", "primary"],
                "simple": ["primary", "reserve"],
                "review": ["primary", "reserve"],
            },
        }
    )


class ScriptedAdapter:
    def __init__(self, handler):
        self.calls = []
        self.handler = handler

    def run(self, route, request, on_event, on_started):
        self.calls.append((route.name, request.phase))
        on_event({"type": "fixture", "source": "local simulation"})
        result = self.handler(route, request)
        return result


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name) / "repo"
        self.workspace.mkdir()
        subprocess.run(["git", "init", "-q", str(self.workspace)], check=True)
        (self.workspace / ".gitignore").write_text(".veacode/\n__pycache__/\n", encoding="utf-8")
        self.store = Store(Path(self.temp.name) / "state")
        self.addCleanup(self.store.close)
        self.spec = {
            "goal": "Create answer.txt containing exactly 42",
            "checks": [
                [
                    "{python}",
                    "-c",
                    "from pathlib import Path; assert Path('answer.txt').read_text() == '42'",
                ]
            ],
        }

    def standard(self, route, request):
        if request.phase == "execute":
            (request.workspace / "answer.txt").write_text("42", encoding="utf-8")
            return AdapterResult(True, text="Created answer.txt")
        if request.phase == "review":
            return AdapterResult(True, text=json.dumps({"accepted": True, "summary": "Verified"}))
        return AdapterResult(True, text="Inspect files and implement the goal")

    def controller(self, handler=None, settings=None):
        adapter = ScriptedAdapter(handler or self.standard)
        return Controller(settings or config(), self.store, lambda _: adapter), adapter

    def test_full_pipeline_runs_real_check_and_records_routes(self):
        controller, adapter = self.controller()
        task = controller.submit(self.spec, self.workspace)
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            adapter.calls, [("primary", "plan"), ("reserve", "execute"), ("primary", "review")]
        )
        self.assertTrue(result["data"]["checks"][0]["passed"])
        self.assertTrue((self.store.state_dir / "tasks" / task["id"] / "handoff.json").is_file())
        self.assertEqual(len(self.store.attempts(task["id"])), 3)
        self.assertEqual(controller.run(task["id"])["status"], "completed")
        self.assertEqual(len(adapter.calls), 3)

    def test_zero_max_starts_reserve_supervisor_without_primary_summary(self):
        def handler(route, request):
            if route.name == "primary":
                return AdapterResult(False, failure=FailureKind.QUOTA, message="Max unavailable")
            if request.phase == "execute":
                self.assertIn("Inspect files and implement the goal", request.prompt)
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            adapter.calls,
            [
                ("primary", "plan"),
                ("reserve", "plan"),
                ("reserve", "execute"),
                ("reserve", "review"),
            ],
        )

    def test_partial_work_survives_quota_failure_and_reaches_acceptance(self):
        def handler(route, request):
            if request.phase == "execute" and route.name == "reserve":
                (request.workspace / "partial.txt").write_text("keep this", encoding="utf-8")
                return AdapterResult(False, failure=FailureKind.QUOTA, message="Quota ran out")
            if request.phase == "execute":
                self.assertIn("partial.txt", request.prompt)
                self.assertEqual((request.workspace / "partial.txt").read_text(), "keep this")
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        self.assertEqual(controller.run(task["id"])["status"], "completed")
        self.assertIn(("primary", "execute"), adapter.calls)
        self.assertEqual((self.workspace / "partial.txt").read_text(), "keep this")

    def test_uncertain_executor_timeout_pauses_without_replay(self):
        def handler(route, request):
            if request.phase == "execute":
                (request.workspace / "partial.txt").write_text("part", encoding="utf-8")
                return AdapterResult(False, failure=FailureKind.TIMEOUT, message="Timed out")
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        calls = list(adapter.calls)
        self.assertEqual(controller.run(task["id"])["status"], "needs_reconciliation")
        self.assertEqual(adapter.calls, calls)

    def test_failed_checks_escalate_and_are_rechecked(self):
        def handler(route, request):
            if request.phase == "execute" and route.name == "reserve":
                (request.workspace / "answer.txt").write_text("wrong", encoding="utf-8")
                return AdapterResult(True, text="Claimed completion")
            if request.phase == "execute":
                self.assertIn("Local verification failed", request.prompt)
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["data"]["repair_round"], 1)
        self.assertIn(("primary", "execute"), adapter.calls)

    def test_failed_checks_cannot_be_overruled_by_accepting_reviewer(self):
        def handler(route, request):
            if request.phase == "execute":
                return AdapterResult(True, text="Nothing changed")
            return self.standard(route, request)

        controller, adapter = self.controller(handler, config(max_repairs=0))
        task = controller.submit(self.spec, self.workspace)
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "paused")
        self.assertNotIn("review", [phase for _, phase in adapter.calls])

    def test_rejected_review_requests_bounded_repair(self):
        rejected = False

        def handler(route, request):
            nonlocal rejected
            if request.phase == "review" and not rejected:
                rejected = True
                return AdapterResult(True, text='{"accepted":false,"summary":"Improve docs"}')
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        result = controller.run(task["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(sum(phase == "execute" for _, phase in adapter.calls), 2)

    def test_invalid_review_json_uses_fallback_instead_of_accepting_prose(self):
        def handler(route, request):
            if request.phase == "review" and route.name == "primary":
                return AdapterResult(True, text="Everything looks good")
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        self.assertEqual(controller.run(task["id"])["status"], "completed")
        self.assertEqual(adapter.calls[-1], ("reserve", "review"))

    def test_read_only_mutation_stops_all_fallbacks(self):
        def handler(route, request):
            if request.phase == "plan":
                (request.workspace / "unexpected.txt").write_text("changed", encoding="utf-8")
            return self.standard(route, request)

        controller, adapter = self.controller(handler)
        task = controller.submit(self.spec, self.workspace)
        self.assertEqual(controller.run(task["id"])["status"], "needs_reconciliation")
        self.assertEqual(len(adapter.calls), 1)

    def test_read_only_analysis_can_complete_without_commands(self):
        spec = {"goal": "Explain this repository", "read_only": True, "kind": "research"}

        def handler(route, request):
            self.assertTrue(request.read_only)
            if request.phase == "review":
                return AdapterResult(True, text='{"accepted":true,"summary":"Useful analysis"}')
            return AdapterResult(True, text="Repository analysis")

        controller, _ = self.controller(handler)
        task = controller.submit(spec, self.workspace)
        self.assertEqual(controller.run(task["id"])["status"], "completed")

    def test_check_that_changes_source_invalidates_validation(self):
        spec = {
            **self.spec,
            "checks": [
                [
                    "{python}",
                    "-c",
                    "from pathlib import Path; Path('answer.txt').write_text('wrong')",
                ]
            ],
        }
        controller, adapter = self.controller()
        task = controller.submit(spec, self.workspace)
        self.assertEqual(controller.run(task["id"])["status"], "needs_reconciliation")
        self.assertNotIn("review", [phase for _, phase in adapter.calls])

    def test_external_edit_after_checks_prevents_review_of_stale_validation(self):
        controller, adapter = self.controller()
        checkpoint = controller._checkpoint

        def change_after_checkpoint(task, workspace, next_phase):
            checkpoint(task, workspace, next_phase)
            if next_phase == "review":
                (workspace / "answer.txt").write_text("wrong", encoding="utf-8")

        controller._checkpoint = change_after_checkpoint
        task = controller.submit(self.spec, self.workspace)
        self.assertEqual(controller.run(task["id"])["status"], "needs_reconciliation")
        self.assertNotIn("review", [phase for _, phase in adapter.calls])


if __name__ == "__main__":
    unittest.main()
