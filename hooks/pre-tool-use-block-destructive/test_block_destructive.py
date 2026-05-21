import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from block_destructive import find_block_reason
from install import command_for


class DetectionTests(unittest.TestCase):
    def test_allows_normal_bash_commands(self):
        self.assertIsNone(find_block_reason("npm test"))
        self.assertIsNone(find_block_reason("git push origin feature-branch"))
        self.assertIsNone(find_block_reason("DELETE FROM users WHERE id = 1"))

    def test_blocks_rm_rf_variants(self):
        self.assertIn("rm -rf", find_block_reason("rm -rf /tmp/build"))
        self.assertIn("rm -rf", find_block_reason("rm -fr node_modules"))

    def test_blocks_sql_destructive_patterns(self):
        self.assertIn("DROP TABLE", find_block_reason("psql -c 'DROP TABLE users'"))
        self.assertIn("TRUNCATE", find_block_reason("TRUNCATE audit_log"))
        self.assertIn("DELETE FROM", find_block_reason("DELETE FROM users"))

    def test_blocks_force_push(self):
        self.assertIn("git push --force", find_block_reason("git push --force origin main"))
        self.assertIn("git push --force", find_block_reason("git push -f origin main"))


class HookIntegrationTests(unittest.TestCase):
    def run_hook(self, payload, home):
        script = Path(__file__).with_name("block_destructive.py")
        result = subprocess.run(
            [sys.executable, str(script)],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            check=True,
            env={"HOME": str(home), "USERPROFILE": str(home)},
        )
        return json.loads(result.stdout)

    def test_safe_command_continues(self):
        with tempfile.TemporaryDirectory() as temp_home:
            output = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "npm test"},
                    "cwd": "/work/project",
                },
                Path(temp_home),
            )
        self.assertTrue(output["continue"])

    def test_blocked_command_denies_and_logs(self):
        with tempfile.TemporaryDirectory() as temp_home:
            home = Path(temp_home)
            output = self.run_hook(
                {
                    "hook_event_name": "PreToolUse",
                    "tool_name": "Bash",
                    "tool_input": {"command": "rm -rf /important"},
                    "cwd": "/work/project",
                },
                home,
            )
            log_path = home / ".claude" / "hooks" / "blocked.log"
            log_entry = json.loads(log_path.read_text(encoding="utf-8").splitlines()[0])

        hook_output = output["hookSpecificOutput"]
        self.assertEqual(hook_output["hookEventName"], "PreToolUse")
        self.assertEqual(hook_output["permissionDecision"], "deny")
        self.assertIn("rm -rf", hook_output["permissionDecisionReason"])
        self.assertEqual(log_entry["command"], "rm -rf /important")
        self.assertEqual(log_entry["project_path"], "/work/project")


class InstallerTests(unittest.TestCase):
    def test_command_quotes_python_and_hook_paths(self):
        command = command_for(Path("/tmp/claude hooks/block_destructive.py"))
        self.assertIn("block_destructive.py", command)
        self.assertTrue(command.startswith('"'))


if __name__ == "__main__":
    unittest.main()
