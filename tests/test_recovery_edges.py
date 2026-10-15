"""Recovery and route authorization against real temporary Git repositories."""

import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from veacode.config import ConfigError, config_from_dict
from veacode.controller import Controller
from veacode.models import AdapterResult, FailureKind
from veacode.store import LockBusy, Store, WorkspaceLock
from veacode.workspace import snapshot


def make_config(*, paid=False, allow=False):
    if paid:
        route = {
            "harness": "opencode",
            "provider": "deepseek",
            "billing": "deepseek_api",
            "model": "deepseek-chat",
        }
    else:
        route = {
            "harness": "codex",
            "provider": "openai",
            "billing": "chatgpt_subscription",
            "model": "test-model",
        }
    return config_from_dict(
        {
            "routes": {"primary": route, "reserve": dict(route)},
            "routing": {phase: ["primary", "reserve"] for phase in ("plan", "execute", "review")},
            "policy": {"allow_deepseek": allow},
        }
    )


class FakeAdapter:
    def __init__(self):
        self.calls = []
        self.fail = False

    def run(self, route, request, on_event, on_started):
        self.calls.append((route.name, request.phase))
        if self.fail:
            return AdapterResult(False, failure=FailureKind.QUOTA, message="Quota unavailable")
        text = '{"accepted": true, "summary": "Verified actual work"}'
        return AdapterResult(True, text=text if request.phase == "review" else "Work is ready")


class RecoveryEdgesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.workspace = root / "repo"
        self.workspace.mkdir()
        self.git("init", "-q")
        (self.workspace / "example.txt").write_text("initial\n", encoding="utf-8")
        self.git("add", "example.txt")
        self.git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "initial",
        )
        self.store = Store(root / "state")
        self.addCleanup(self.store.close)
        self.adapter = FakeAdapter()
        self.controller = Controller(make_config(), self.store, lambda _: self.adapter)

    def git(self, *argv):
        return subprocess.run(
            ["git", *argv],
            cwd=self.workspace,
            check=True,
            capture_output=True,
            text=True,
        )

    def submit(self):
        return self.controller.submit(
            {
                "goal": "Check a temporary fixture",
                "checks": [["{python}", "-c", "print('verified')"]],
            },
            self.workspace,
        )

    def test_all_routes_unavailable_pauses_and_a_later_run_can_retry(self):
        task = self.submit()
        self.adapter.fail = True
        paused = self.controller.run(task["id"])
        self.assertEqual(paused["status"], "paused")
        self.assertEqual(paused["phase"], "plan")
        self.assertEqual(self.store.active_attempts(task["id"]), [])
        self.assertEqual(self.adapter.calls, [("primary", "plan"), ("reserve", "plan")])
        self.adapter.fail = False
        self.assertEqual(self.controller.run(task["id"])["status"], "completed")

    def test_paid_routes_are_skipped_until_policy_allows_them(self):
        self.controller.config = make_config(paid=True)
        task = self.submit()
        self.assertEqual(self.controller.run(task["id"])["status"], "paused")
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.store.attempts(task["id"]), [])
        self.controller.config = replace(self.controller.config, allow_deepseek=True)
        self.assertEqual(self.controller.run(task["id"])["status"], "completed")
        self.assertEqual([phase for _, phase in self.adapter.calls], ["plan", "execute", "review"])

    def test_live_recorded_child_blocks_even_explicit_reconciliation(self):
        task = self.submit()
        attempt_id = self.store.begin_attempt(task["id"], "execute", {"name": "prior"})
        self.store.set_attempt_pid(attempt_id, os.getpid())
        result = self.controller.run(task["id"], reconcile=True)
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual(self.adapter.calls, [])
        self.assertEqual(self.store.active_attempts(task["id"])[0]["id"], attempt_id)

    def test_attempt_without_pid_requires_reconciliation_then_is_retained(self):
        task = self.submit()
        attempt_id = self.store.begin_attempt(task["id"], "execute", {"name": "prior"})
        result = self.controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual(self.adapter.calls, [])
        result = self.controller.run(task["id"], reconcile=True)
        self.assertEqual(result["status"], "completed")
        old = next(item for item in self.store.attempts(task["id"]) if item["id"] == attempt_id)
        self.assertTrue(old["result"]["interrupted"])
        self.assertEqual(self.store.active_attempts(task["id"]), [])

    def test_external_change_blocks_models_until_reconciliation(self):
        task = self.submit()
        self.store.update_task(
            task["id"],
            phase="review",
            data={
                "checkpoint_fingerprint": snapshot(self.workspace)["fingerprint"],
                "checks": [{"passed": True, "stdout": "old verification"}],
            },
        )
        (self.workspace / "example.txt").write_text("external edit\n", encoding="utf-8")
        result = self.controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual(self.adapter.calls, [])
        result = self.controller.run(task["id"], reconcile=True)
        self.assertEqual(result["status"], "completed")
        self.assertNotEqual(result["data"]["checks"][0].get("stdout"), "old verification")
        self.assertEqual([phase for _, phase in self.adapter.calls], ["plan", "execute", "review"])

    def test_task_is_reloaded_after_workspace_lock_acquisition(self):
        task = self.submit()
        store = self.store

        class AnotherControllerFinished(WorkspaceLock):
            def __enter__(self):
                super().__enter__()
                store.update_task(task["id"], status="completed", phase="done")
                return self

        with patch("veacode.controller.WorkspaceLock", AnotherControllerFinished):
            result = self.controller.run(task["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.adapter.calls, [], "A completed task must never be executed twice")

    def test_subdirectory_cannot_bypass_repository_workspace_lock(self):
        nested = self.workspace / "package"
        nested.mkdir()
        with WorkspaceLock(self.workspace):
            with self.assertRaises((LockBusy, ValueError)):
                task = self.controller.submit(
                    {"goal": "Inspect a package", "read_only": True},
                    nested,
                )
                self.controller.run(task["id"])
        self.assertEqual(self.adapter.calls, [])

    def test_paid_deepseek_label_cannot_authorize_another_provider_model(self):
        with self.assertRaises(ConfigError):
            config_from_dict(
                {
                    "routes": {
                        "wrong": {
                            "harness": "opencode",
                            "provider": "deepseek",
                            "billing": "deepseek_api",
                            "model": "openai/gpt-4.1",
                        }
                    },
                    "routing": {phase: ["wrong"] for phase in ("plan", "execute", "review")},
                    "policy": {"allow_deepseek": True},
                }
            )

    def test_finished_attempts_recover_without_repeating_any_model_phase(self):
        class SimulatedCrash(RuntimeError):
            pass

        for crash_phase in ("plan", "execute", "review"):
            with self.subTest(crash_phase=crash_phase):
                self.adapter.calls.clear()
                task = self.submit()
                original_finish = self.store.finish_attempt

                def finish_then_crash(
                    attempt_id,
                    result,
                    *,
                    finish=original_finish,
                    task_id=task["id"],
                    phase=crash_phase,
                ):
                    finish(attempt_id, result)
                    attempt = next(
                        item for item in self.store.attempts(task_id) if item["id"] == attempt_id
                    )
                    if attempt["phase"] == phase:
                        raise SimulatedCrash("Finished result committed; stage checkpoint absent")

                with patch.object(self.store, "finish_attempt", finish_then_crash):
                    with self.assertRaises(SimulatedCrash):
                        self.controller.run(task["id"])
                self.assertEqual(self.store.get_task(task["id"])["phase"], crash_phase)
                self.assertEqual(self.store.active_attempts(task["id"]), [])
                with Store(self.store.state_dir) as reopened:
                    restarted = Controller(make_config(), reopened, lambda _: self.adapter)
                    result = restarted.run(task["id"])
                self.assertEqual(result["status"], "completed")
                self.assertEqual(
                    [phase for _, phase in self.adapter.calls], ["plan", "execute", "review"]
                )
                recovered = [
                    event
                    for event in self.store.events(task["id"])
                    if event["type"] == "saved_result_recovered"
                ]
                self.assertEqual(len(recovered), 1)

    def test_done_checkpoint_recovers_completion_without_another_model_call(self):
        task = self.submit()
        original_update = self.store.update_task

        def fail_completion(task_id, **changes):
            if changes.get("status") == "completed":
                raise RuntimeError("Crash after done checkpoint before completion")
            return original_update(task_id, **changes)

        with patch.object(self.store, "update_task", fail_completion):
            with self.assertRaisesRegex(RuntimeError, "Crash after done"):
                self.controller.run(task["id"])
        self.assertEqual(self.store.get_task(task["id"])["phase"], "done")
        self.assertEqual(len(self.adapter.calls), 3)
        with Store(self.store.state_dir) as reopened:
            restarted = Controller(make_config(), reopened, lambda _: self.adapter)
            result = restarted.run(task["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(self.adapter.calls), 3)

    def test_external_edit_after_saved_first_plan_requires_reconciliation(self):
        for explicit_reconcile in (False, True):
            with self.subTest(explicit_reconcile=explicit_reconcile):
                self.adapter.calls.clear()
                task = self.submit()
                attempt_id = self.store.begin_attempt(task["id"], "plan", {"name": "primary"})
                self.store.finish_attempt(
                    attempt_id,
                    {
                        "success": True,
                        "text": "An old plan based on original contents",
                        "workspace_fingerprint": snapshot(self.workspace)["fingerprint"],
                    },
                )
                # A committed result exists before its first stage checkpoint.
                self.store.update_task(task["id"], status="running")
                (self.workspace / "example.txt").write_text(
                    f"edited after saved plan {task['id']}\n", encoding="utf-8"
                )
                result = self.controller.run(task["id"], reconcile=explicit_reconcile)
                if explicit_reconcile:
                    self.assertEqual(result["status"], "completed")
                    self.assertEqual(
                        [phase for _, phase in self.adapter.calls], ["plan", "execute", "review"]
                    )
                else:
                    self.assertEqual(result["status"], "needs_reconciliation")
                    self.assertEqual(self.adapter.calls, [])

    def test_saved_failed_executor_does_not_lose_uncertain_outcome_after_crash(self):
        task = self.submit()
        original_run = self.adapter.run
        original_finish = self.store.finish_attempt

        def timeout_execute(route, request, on_event, on_started):
            if request.phase == "execute":
                self.adapter.calls.append((route.name, request.phase))
                return AdapterResult(
                    False, failure=FailureKind.TIMEOUT, message="Executor timed out"
                )
            return original_run(route, request, on_event, on_started)

        def finish_then_crash(attempt_id, result):
            original_finish(attempt_id, result)
            if result.get("failure") == FailureKind.TIMEOUT:
                raise RuntimeError("Crash after failed attempt before pause")

        with patch.object(self.adapter, "run", timeout_execute):
            with patch.object(self.store, "finish_attempt", finish_then_crash):
                with self.assertRaisesRegex(RuntimeError, "Crash after failed"):
                    self.controller.run(task["id"])
        self.assertEqual(self.store.active_attempts(task["id"]), [])
        result = self.controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual([phase for _, phase in self.adapter.calls], ["plan", "execute"])

    def test_failed_executor_checkpoint_before_pause_still_requires_reconciliation(self):
        task = self.submit()
        original_run = self.adapter.run
        original_update = self.store.update_task

        def timeout_execute(route, request, on_event, on_started):
            if request.phase == "execute":
                self.adapter.calls.append((route.name, request.phase))
                return AdapterResult(
                    False, failure=FailureKind.TIMEOUT, message="Executor timed out"
                )
            return original_run(route, request, on_event, on_started)

        def save_then_crash(task_id, **changes):
            result = original_update(task_id, **changes)
            last_attempt = changes.get("data", {}).get("last_attempt")
            if last_attempt:
                latest = self.store.attempts(task_id)[-1]
                if latest["phase"] == "execute" and latest["result"]["failure"] == "timeout":
                    raise RuntimeError("Crash after failed checkpoint before pause")
            return result

        with patch.object(self.adapter, "run", timeout_execute):
            with patch.object(self.store, "update_task", save_then_crash):
                with self.assertRaisesRegex(RuntimeError, "Crash after failed checkpoint"):
                    self.controller.run(task["id"])
        self.assertEqual(self.store.active_attempts(task["id"]), [])
        result = self.controller.run(task["id"])
        self.assertEqual(result["status"], "needs_reconciliation")
        self.assertEqual([phase for _, phase in self.adapter.calls], ["plan", "execute"])


if __name__ == "__main__":
    unittest.main()
