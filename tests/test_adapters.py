"""Exercise actual subprocesses without invoking any model or using credentials."""

import json
import os
import tempfile
import time
import unittest
from dataclasses import replace
from fnmatch import fnmatchcase
from pathlib import Path
from unittest.mock import patch

from veacode.adapters import (
    AdapterRegistry,
    _build_command,
    _environment,
    _resolve_executable,
    availability,
    classify_failure,
    make_adapter,
    redact,
)
from veacode.models import FailureKind, Route, RunRequest


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.workspace = Path(self.temp.name)
        (self.workspace / ".git").mkdir()
        self.fake = self.workspace / "fake_agent.py"
        self.request = RunRequest(
            "task-test", "execute", "Do a small task", self.workspace, self.workspace / "run"
        )
        self.route = Route(
            "codex-test",
            "codex",
            "test-model",
            "openai",
            "chatgpt_subscription",
            executable=str(self.fake),
            timeout_seconds=10,
        )
        self.events = []
        self.pids = []

    def write_script(self, source):
        self.fake.write_text("import json, os, sys, time\n" + source, encoding="utf-8")

    def run_adapter(self, route=None, request=None):
        route = route or self.route
        return make_adapter(route.harness).run(
            route, request or self.request, self.events.append, self.pids.append
        )

    def codex_success(self, result="done"):
        self.write_script(
            'json.loads("null")\n'
            'print(json.dumps({"type":"thread.started","thread_id":"thread-123"}), flush=True)\n'
            'print(json.dumps({"type":"item.completed",'
            f'"item":{{"type":"agent_message","text":{result!r}}}}}), flush=True)\n'
            'print(json.dumps({"type":"turn.completed",'
            '"usage":{"input_tokens":12,"output_tokens":3}}), flush=True)\n'
        )

    def test_codex_success_stores_session_usage_and_sanitized_log(self):
        self.codex_success()
        result = self.run_adapter()
        self.assertTrue(result.success, result)
        self.assertEqual(result.text, "done")
        self.assertEqual(result.session_id, "thread-123")
        self.assertEqual(result.usage["input_tokens"], 12)
        self.assertEqual(len(self.pids), 1)
        self.assertTrue((self.request.run_dir / "process.jsonl").is_file())

    def test_prompt_is_stdin_and_not_a_shell_command(self):
        prompt = 'quote " ; & $(never-run) `bad`\nПривет'
        self.write_script(
            "prompt = sys.stdin.read()\n"
            'print(json.dumps({"type":"item.completed","item":{"type":"agent_message","text":prompt}}))\n'
            'print(json.dumps({"type":"turn.completed"}))\n'
        )
        result = self.run_adapter(request=replace(self.request, prompt=prompt))
        self.assertTrue(result.success, result)
        self.assertEqual(result.text, prompt)
        self.assertNotIn(prompt, self.events[0].get("command", ""))

    def test_subscription_child_does_not_inherit_provider_keys_or_endpoints(self):
        credentials = {
            "OPENAI_API_KEY": "fake-openai-secret-value",
            "CODEX_API_KEY": "fake-codex-secret-value",
            "OPENAI_BASE_URL": "https://unapproved.invalid",
            "ANTHROPIC_AUTH_TOKEN": "fake-anthropic-secret-value",
            "DEEPSEEK_API_KEY": "fake-deepseek-secret-value",
            "GITHUB_TOKEN": "fake-github-secret-value",
        }
        self.write_script(
            f"names = {list(credentials)!r}\n"
            "result = {name: name in os.environ for name in names}\n"
            'result["home_configured"] = bool(os.environ.get("CODEX_HOME"))\n'
            'print(json.dumps({"type":"item.completed","item":{"type":"agent_message","text":json.dumps(result)}}))\n'
            'print(json.dumps({"type":"turn.completed"}))\n'
        )
        with patch.dict(os.environ, credentials):
            result = self.run_adapter()
        child = json.loads(result.text)
        self.assertTrue(child.pop("home_configured"))
        self.assertFalse(any(child.values()), child)

    def test_secrets_redacted_from_events_text_errors_and_logs(self):
        secret = "fixture-super-private-secret-123"
        self.codex_success(f"{secret} api_key=another-private-value Bearer opaque-private-value")
        with patch.dict(os.environ, {"MY_SECRET": secret}):
            result = self.run_adapter()
        combined = (
            result.text
            + json.dumps(self.events)
            + (self.request.run_dir / "process.jsonl").read_text(encoding="utf-8")
        )
        for forbidden in (secret, "another-private-value", "opaque-private-value"):
            self.assertNotIn(forbidden, combined)
        self.assertIn("REDACTED", combined)

    def test_codex_flags_enforce_subscription_and_bounded_permissions(self):
        self.codex_success()
        env, _ = _environment(self.route)
        command, prompt = _build_command(self.route, self.request, env)
        self.assertIn("--ignore-user-config", command)
        self.assertIn("--ephemeral", command)
        self.assertIn('forced_login_method="chatgpt"', command)
        self.assertIn('model_provider="openai"', command)
        self.assertIn("features.multi_agent=false", command)
        self.assertIn("workspace-write", command)
        self.assertNotIn("--dangerously-bypass-approvals-and-sandbox", command)
        self.assertEqual(prompt, self.request.prompt.encode())
        readonly, _ = _build_command(self.route, replace(self.request, read_only=True), env)
        self.assertIn("read-only", readonly)

    def test_codex_delegate_profile_is_optional_and_only_effort_is_reused(self):
        self.codex_success()
        profile_home = self.workspace / "codex-home"
        profile_home.mkdir()
        (profile_home / "config.toml").write_text(
            '[profiles.delegate]\nmodel_reasoning_effort="high"\nmodel_provider="unexpected"\n',
            encoding="utf-8",
        )
        route = replace(self.route, profile="delegate", env={"CODEX_HOME": str(profile_home)})
        env, _ = _environment(route)
        command, _ = _build_command(route, self.request, env)
        self.assertIn('model_reasoning_effort="high"', command)
        self.assertNotIn("unexpected", " ".join(command))
        route = replace(route, profile="missing")
        command, _ = _build_command(route, self.request, env)
        self.assertNotIn("--profile", command)

    def test_codex_refuses_project_config_before_launch(self):
        self.codex_success()
        (self.workspace / ".codex").mkdir()
        (self.workspace / ".codex" / "config.toml").write_text(
            '[mcp_servers.unapproved]\ncommand="unapproved-command"\n', encoding="utf-8"
        )
        result = self.run_adapter()
        self.assertEqual(result.failure, FailureKind.PERMISSION)
        self.assertEqual(self.pids, [])

    def test_codex_refuses_home_dotenv_without_reading_it(self):
        self.codex_success()
        codex_home = self.workspace / "codex-home"
        codex_home.mkdir()
        (codex_home / ".env").write_text("OPENAI_BASE_URL=https://unexpected.invalid")
        route = replace(self.route, env={"CODEX_HOME": str(codex_home)})
        with patch.object(Path, "read_text", side_effect=AssertionError("Must not read dotenv")):
            result = self.run_adapter(route)
        self.assertEqual(result.failure, FailureKind.PERMISSION)
        self.assertIn("CODEX_HOME/.env", result.message)
        self.assertEqual(self.pids, [])

    def test_codex_project_config_guard_checks_ancestors(self):
        self.codex_success()
        (self.workspace / ".codex").mkdir()
        (self.workspace / ".codex" / "config.toml").write_text("", encoding="utf-8")
        nested = self.workspace / "nested"
        nested.mkdir()
        result = self.run_adapter(request=replace(self.request, workspace=nested))
        self.assertEqual(result.failure, FailureKind.PERMISSION)
        self.assertEqual(self.pids, [])

    def test_claude_stream_success_and_restricted_file_tools(self):
        self.write_script(
            'print(json.dumps({"type":"assistant","session_id":"claude-session","message":{"model":"claude-observed","content":[{"type":"text","text":"intermediate"}]}}))\n'
            'print(json.dumps({"type":"result","subtype":"success","result":"finished","usage":{"output_tokens":8},"modelUsage":{"claude-observed":{}},"total_cost_usd":0.01}))\n'
        )
        route = replace(
            self.route,
            harness="claude",
            provider="anthropic",
            billing="claude_subscription",
            model="opus",
        )
        result = self.run_adapter(route)
        self.assertTrue(result.success, result)
        self.assertEqual(result.observed_model, "claude-observed")
        self.assertEqual(result.session_id, "claude-session")
        env, _ = _environment(route)
        command, prompt = _build_command(route, self.request, env)
        self.assertIn("--restricted", command)
        self.assertIn("--safe-mode", command)
        self.assertIn("none", command)
        self.assertEqual(command[command.index("--tools") + 1], "Read,Glob,Grep,Edit,Write")
        self.assertNotIn("--dangerously-skip-permissions", command)
        self.assertEqual(prompt, self.request.prompt.encode())

    def test_claude_denied_tools_are_not_reported_as_success(self):
        self.write_script(
            'print(json.dumps({"type":"result","subtype":"success","result":"cannot edit",'
            '"permission_denials":[{"tool_name":"Edit"}]}))\n'
        )
        route = replace(
            self.route, harness="claude", provider="anthropic", billing="claude_subscription"
        )
        result = self.run_adapter(route)
        self.assertFalse(result.success)
        self.assertEqual(result.failure, FailureKind.PERMISSION)

    def test_opencode_isolates_deepseek_and_preserves_argument_prompt(self):
        prompt = 'literal " & $() ` value'
        self.write_script(
            'config = json.loads(os.environ["OPENCODE_CONFIG_CONTENT"])\n'
            'value = {"prompt": sys.argv[-1], "config": config, '
            '"other_key": "OPENAI_API_KEY" in os.environ}\n'
            'print(json.dumps({"type":"text","sessionID":"opencode-session","part":{"text":json.dumps(value),"modelID":"deepseek-test"}}))\n'
            'print(json.dumps({"type":"step_finish","part":{"reason":"stop","tokens":{"input":5,"output":4},"cost":0.001}}))\n'
        )
        route = replace(
            self.route,
            harness="opencode",
            provider="deepseek",
            billing="deepseek_api",
            model="deepseek-test",
        )
        with patch.dict(
            os.environ,
            {
                "DEEPSEEK_API_KEY": "fake-deepseek-api-value",
                "OPENAI_API_KEY": "fake-other-provider-value",
            },
        ):
            result = self.run_adapter(route, replace(self.request, prompt=prompt))
        self.assertTrue(result.success, result)
        value = json.loads(result.text)
        self.assertEqual(value["prompt"], prompt)
        self.assertEqual(value["config"]["enabled_providers"], ["deepseek"])
        self.assertEqual(value["config"]["small_model"], "deepseek/deepseek-test")
        self.assertEqual(value["config"]["permission"]["bash"], "deny")
        self.assertEqual(value["config"]["permission"]["external_directory"], "deny")
        self.assertFalse(value["other_key"])
        self.assertEqual(result.usage["cost_usd"], 0.001)
        self.assertEqual(result.usage["cost_kind"], "estimate")
        self.assertEqual(result.usage["cost_source"], "opencode_catalog")
        self.assertEqual(result.observed_model, "deepseek-test")

    def test_opencode_file_permissions_protect_state_git_and_credentials(self):
        self.codex_success()
        route = replace(self.route, harness="opencode", provider="deepseek", billing="deepseek_api")
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fake-deepseek-api-value"}):
            env, _ = _environment(route)
            _build_command(route, self.request, env)
        config = json.loads(env["OPENCODE_CONFIG_CONTENT"])
        permission = config["permission"]

        def evaluate(rules, path):
            # OpenCode documents last-match wins with '*' matching any characters.
            result = "ask"
            for pattern, action in rules.items():
                if fnmatchcase(path, pattern):
                    result = action
            return result

        for path in (
            ".veacode/state.db",
            ".git",
            ".git/config",
            "C:/repo/.git/config",
            r"C:\repo\.veacode\state.db",
            "src/.env",
            "src/.env.production",
            "certs/private.pem",
            "secrets/deepseek.key",
            "C:/repo/.ssh/id_ed25519",
            "/repo/.aws/credentials",
            "/repo/auth.json",
            "/repo/.npmrc",
        ):
            for tool in ("read", "edit"):
                with self.subTest(path=path, tool=tool):
                    self.assertEqual(evaluate(permission[tool], path), "deny")
        for path in ("maths.py", "src/main.py", "/repo/.gitignore"):
            for tool in ("read", "edit"):
                with self.subTest(path=path, tool=tool):
                    self.assertEqual(evaluate(permission[tool], path), "allow")
        self.assertEqual(config["agent"]["veacode"]["permission"], permission)
        self.assertEqual(json.loads(env["OPENCODE_PERMISSION"]), permission)

    def test_opencode_read_only_keeps_edits_denied_with_path_rules(self):
        self.codex_success()
        route = replace(self.route, harness="opencode", provider="deepseek", billing="deepseek_api")
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fake-deepseek-api-value"}):
            env, _ = _environment(route)
            _build_command(route, replace(self.request, read_only=True), env)
        edits = json.loads(env["OPENCODE_CONFIG_CONTENT"])["permission"]["edit"]
        self.assertTrue(edits)
        self.assertEqual(set(edits.values()), {"deny"})

    def test_opencode_key_absent_returns_auth_without_launch(self):
        self.codex_success()
        route = replace(self.route, harness="opencode", provider="deepseek", billing="deepseek_api")
        with patch.dict(os.environ, {}, clear=True):
            result = self.run_adapter(route)
        self.assertEqual(result.failure, FailureKind.AUTH)
        self.assertEqual(self.pids, [])

    def test_opencode_refuses_merged_project_integrations(self):
        self.codex_success()
        (self.workspace / "opencode.json").write_text('{"mcp":{"unapproved":{}}}', encoding="utf-8")
        route = replace(self.route, harness="opencode", provider="deepseek", billing="deepseek_api")
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fake-deepseek-api-value"}):
            result = self.run_adapter(route)
        self.assertEqual(result.failure, FailureKind.PERMISSION)
        self.assertEqual(self.pids, [])

    def test_opencode_rejects_model_with_alternate_provider_prefix(self):
        self.codex_success()
        route = replace(
            self.route,
            harness="opencode",
            provider="deepseek",
            billing="deepseek_api",
            model="openai/paid-model",
        )
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fake-deepseek-api-value"}):
            result = self.run_adapter(route)
        self.assertEqual(result.failure, FailureKind.PERMISSION)
        self.assertEqual(self.pids, [])

    def test_nonapproved_billing_route_never_launches(self):
        self.codex_success()
        result = self.run_adapter(replace(self.route, billing="openai_api"))
        self.assertFalse(result.success)
        self.assertEqual(self.pids, [])

    def test_structured_quota_is_failure_even_with_zero_exit(self):
        self.write_script(
            'print(json.dumps({"type":"turn.failed",'
            '"error":{"code":"usage_limit_reached","message":"try later"}}))\n'
        )
        result = self.run_adapter()
        self.assertEqual(result.failure, FailureKind.QUOTA)
        self.assertEqual(result.exit_code, 0)

    def test_structured_codes_take_precedence_over_messages(self):
        cases = [
            ({"code": "rate_limit_error", "message": "a quota mention"}, FailureKind.RATE_LIMIT),
            ({"statusCode": 401, "message": "try again later"}, FailureKind.AUTH),
            ({"error": {"data": {"statusCode": 402}}}, FailureKind.BALANCE),
            ({"code": "insufficient_quota", "message": "rate limit"}, FailureKind.QUOTA),
            ({"code": "permission_denied"}, FailureKind.PERMISSION),
            ({"status_code": 503}, FailureKind.NETWORK),
        ]
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(classify_failure(value), expected)

    def test_missing_cli_returns_unavailable(self):
        result = self.run_adapter(
            replace(self.route, executable=str(self.workspace / "missing_agent"))
        )
        self.assertEqual(result.failure, FailureKind.UNAVAILABLE)
        self.assertEqual(self.pids, [])

    def test_bad_json_and_zero_exit_cannot_claim_success(self):
        self.write_script('print("{broken json")\n')
        result = self.run_adapter()
        self.assertEqual(result.failure, FailureKind.PROTOCOL)

    def test_malformed_machine_fields_do_not_crash_or_claim_empty_success(self):
        self.write_script(
            'print(json.dumps({"type":[]}))\n'
            'print(json.dumps({"type":"item.completed",'
            '"item":{"type":"agent_message","text":None}}))\n'
            'print(json.dumps({"type":"turn.completed","usage":[]}))\n'
        )
        result = self.run_adapter()
        self.assertFalse(result.success)
        self.assertEqual(result.failure, FailureKind.PROTOCOL)

    def test_stderr_auth_error_classified_when_process_fails(self):
        self.write_script('print("Not logged in. Please log in.", file=sys.stderr)\nsys.exit(1)\n')
        result = self.run_adapter()
        self.assertEqual(result.failure, FailureKind.AUTH)

    def test_timeout_stops_process_tree(self):
        child_marker = self.workspace / "orphan-finished.txt"
        child = (
            "import time; from pathlib import Path; time.sleep(1.5); "
            f"Path({str(child_marker)!r}).write_text('orphan')"
        )
        self.write_script(
            "import subprocess\n"
            f'subprocess.Popen([sys.executable, "-c", {child!r}])\ntime.sleep(20)\n'
        )
        started = time.monotonic()
        result = self.run_adapter(replace(self.route, timeout_seconds=0.35))
        self.assertEqual(result.failure, FailureKind.TIMEOUT)
        self.assertLess(time.monotonic() - started, 5)
        time.sleep(1.6)
        self.assertFalse(child_marker.exists(), "agent descendant survived timeout")

    @unittest.skipIf(os.name == "nt", "POSIX process-group cleanup")
    def test_success_stops_background_descendants_with_closed_pipes(self):
        child_marker = self.workspace / "background-finished.txt"
        child = (
            "import time; from pathlib import Path; time.sleep(0.8); "
            f"Path({str(child_marker)!r}).write_text('orphan')"
        )
        self.write_script(
            "import subprocess\n"
            f'subprocess.Popen([sys.executable, "-c", {child!r}], '
            "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            'print(json.dumps({"type":"item.completed",'
            '"item":{"type":"agent_message","text":"done"}}))\n'
            'print(json.dumps({"type":"turn.completed"}))\n'
        )
        result = self.run_adapter()
        self.assertTrue(result.success, result)
        time.sleep(1)
        self.assertFalse(child_marker.exists(), "agent descendant survived successful completion")

    def test_oversized_output_is_bounded_protocol_failure(self):
        self.write_script('sys.stdout.write("x" * 300000)\nsys.stdout.flush()\ntime.sleep(10)\n')
        result = self.run_adapter()
        self.assertEqual(result.failure, FailureKind.PROTOCOL)
        self.assertLess((self.request.run_dir / "process.jsonl").stat().st_size, 1024)

    def test_log_cap_does_not_prevent_parsing_final_result(self):
        self.write_script(
            'for i in range(30): print(json.dumps({"type":"progress","message":"x"*100}))\n'
            'print(json.dumps({"type":"item.completed",'
            '"item":{"type":"agent_message","text":"completed after lots of progress"}}))\n'
            'print(json.dumps({"type":"turn.completed"}))\n'
        )
        with patch("veacode.adapters.MAX_LOG_BYTES", 700):
            result = self.run_adapter()
        self.assertTrue(result.success, result)
        self.assertLessEqual((self.request.run_dir / "process.jsonl").stat().st_size, 700)

    def test_callback_exception_stops_agent(self):
        self.write_script("time.sleep(20)\n")

        def refuse_started(pid):
            raise RuntimeError("callback failed")

        with self.assertRaisesRegex(RuntimeError, "callback failed"):
            make_adapter("codex").run(self.route, self.request, self.events.append, refuse_started)

    def test_npm_launcher_cannot_fall_back_to_shell(self):
        launcher = self.workspace / "codex.cmd"
        launcher.write_text("@echo unsafe", encoding="utf-8")
        with self.assertRaises(FileNotFoundError):
            _resolve_executable("codex", str(launcher))

    def test_registry_and_doctor_do_not_invoke_model_or_expose_key(self):
        self.codex_success()
        registry = AdapterRegistry({"codex": "fake"})
        self.assertEqual(registry.get("codex"), "fake")
        self.assertIsNotNone(registry.get("claude"))
        with self.assertRaises(ValueError):
            make_adapter("unapproved")
        route = replace(self.route, harness="opencode", provider="deepseek", billing="deepseek_api")
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "secret-do-not-print-this"}):
            result = availability(route)
        self.assertTrue(result["api_key_configured"])
        self.assertNotIn("secret-do-not-print-this", json.dumps(result))
        self.assertEqual(self.pids, [])

    def test_generic_redaction_handles_bearer_and_api_key(self):
        result = redact('Bearer opaque-token-123 api_key="opaque-api-key-123" sk-abcdefghijklmnop')
        for credential in ("opaque-token-123", "opaque-api-key-123", "sk-abcdefghijklmnop"):
            self.assertNotIn(credential, result)


if __name__ == "__main__":
    unittest.main()
