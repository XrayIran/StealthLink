from __future__ import annotations

import pathlib
import sys
import unittest

TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import gfw_simulator  # noqa: E402


class GFWSimulatorTests(unittest.TestCase):
    def test_evaluate_detects_blocked_sample(self) -> None:
        result = gfw_simulator.evaluate("connect youtube.com via vpn tunnel")
        self.assertTrue(result["blocked"])
        self.assertIn("sni_block", result["rules"])
        self.assertIn("keyword_block", result["rules"])

    def test_evaluate_allows_benign_sample(self) -> None:
        result = gfw_simulator.evaluate("weather api status endpoint")
        self.assertFalse(result["blocked"])
        self.assertEqual(result["rules"], [])


if __name__ == "__main__":
    unittest.main()
