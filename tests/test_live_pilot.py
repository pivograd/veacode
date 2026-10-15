"""The live fixture can be prepared and its integrity checked without any model calls."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from veacode.store import Store
from veacode.workspace import run_checks


class LivePilotTests(unittest.TestCase):
    def test_prepared_fixture_integrity_matches_actual_platform_bytes(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "pilot"
            result = subprocess.run(
                [
                    sys.executable,
                    str(root / "examples/live_pilot.py"),
                    "--config",
                    str(root / "examples/veacode.toml"),
                    "--directory",
                    str(workspace),
                    "--prepare-only",
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            metadata = json.loads(result.stdout)
            self.assertTrue(metadata["prepare_only"])
            with Store(workspace / ".veacode") as store:
                task = store.get_task(metadata["task_id"])
                self.assertEqual(store.attempts(task["id"]), [])
            checks = run_checks(workspace, task["spec"]["checks"])
            self.assertTrue(checks[0]["passed"], checks[0])
            self.assertFalse(checks[1]["passed"], "Initial addition defect must be detected")
            (workspace / "maths.py").write_text(
                "def add(a, b):\n    return a + b\n", encoding="utf-8"
            )
            self.assertTrue(
                all(check["passed"] for check in run_checks(workspace, task["spec"]["checks"]))
            )


if __name__ == "__main__":
    unittest.main()
