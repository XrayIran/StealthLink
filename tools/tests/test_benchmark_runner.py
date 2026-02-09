from __future__ import annotations

import pathlib
import sys
import unittest

TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import benchmark_runner  # noqa: E402


class BenchmarkRunnerTests(unittest.TestCase):
    def test_run_captures_command_output(self) -> None:
        result = benchmark_runner.run(["python3", "-c", "print('ok')"])
        self.assertEqual(result["rc"], 0)
        self.assertIn("ok", result["stdout"])
        self.assertEqual(result["stderr"], "")


if __name__ == "__main__":
    unittest.main()
