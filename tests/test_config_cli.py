import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from veacode.cli import main
from veacode.config import ConfigError, config_from_dict, load_config
from veacode.security import redact
from veacode.spec import validate_spec


class ConfigCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = self.root / "config.toml"
        self.capture(["init", "--output", str(self.config)])

    def capture(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(argv)
        return code, json.loads(output.getvalue())

    def test_installed_default_has_three_harnesses_and_paid_disabled(self):
        config = load_config(self.config)
        self.assertEqual(
            {r.harness for r in config.routes.values()}, {"claude", "codex", "opencode"}
        )
        self.assertFalse(config.allow_deepseek)
        self.assertFalse(config.permitted(config.routes["deepseek"]))
        code, result = self.capture(["init", "--output", str(self.config)])
        self.assertEqual(code, 1)
        self.assertEqual(result["error"], "FileExistsError")

    def test_invalid_config_cannot_smuggle_api_keys_or_other_billing(self):
        base = {
            "routes": {
                "bad": {
                    "harness": "codex",
                    "model": "test",
                    "provider": "openai",
                    "billing": "openai_api",
                }
            },
            "routing": {k: ["bad"] for k in ("plan", "execute", "review")},
        }
        with self.assertRaises(ConfigError):
            config_from_dict(base)
        base["routes"]["bad"]["billing"] = "chatgpt_subscription"
        base["routes"]["bad"]["env"] = {"OPENAI_API_KEY": "should-not-be-stored"}
        with self.assertRaises(ConfigError):
            config_from_dict(base)
        base["routes"]["bad"].pop("env")
        base["routes"]["bad"]["timeout_seconds"] = float("nan")
        with self.assertRaises(ConfigError):
            config_from_dict(base)

    def test_changing_tasks_require_trusted_argument_array_checks(self):
        for spec in (
            {"goal": "edit"},
            {"goal": "edit", "checks": ["python test.py"]},
            {"goal": "edit", "checks": [["python", ""]]},
            {"goal": "edit", "read_only": "yes"},
        ):
            with self.subTest(spec=spec), self.assertRaises(ValueError):
                validate_spec(spec)

    def test_submit_and_status_work_without_clients_or_config(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        spec = self.root / "task.toml"
        spec.write_text('goal="Inspect repository"\nread_only=true\n', encoding="utf-8")
        state = str(self.root / "state")
        code, task = self.capture(
            ["submit", "--spec", str(spec), "--workspace", str(repo), "--state-dir", state]
        )
        self.assertEqual(code, 0)
        code, result = self.capture(["status", task["id"], "--state-dir", state])
        self.assertEqual(result["task"]["status"], "pending")
        self.assertEqual(result["attempts"], [])
        code, tasks = self.capture(["list", "--state-dir", state])
        self.assertEqual(len(tasks), 1)

    def test_runtime_redaction_handles_structured_values_and_environment(self):
        secret = "opaque-secret-123456789"
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": secret}):
            result = redact({"message": f"error with {secret}", "authorization": secret})
        self.assertNotIn(secret, json.dumps(result))

    def test_usage_counters_are_preserved_while_credentials_are_redacted(self):
        result = redact({"input_tokens": 120, "output_tokens": 9, "access_token": "private"})
        self.assertEqual(result["input_tokens"], 120)
        self.assertEqual(result["output_tokens"], 9)
        self.assertNotEqual(result["access_token"], "private")


if __name__ == "__main__":
    unittest.main()
