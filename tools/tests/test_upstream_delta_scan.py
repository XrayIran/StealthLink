from __future__ import annotations

import pathlib
import sys
import unittest

TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import upstream_delta_scan  # noqa: E402


class UpstreamDeltaScanTests(unittest.TestCase):
    def test_scan_produces_rows(self) -> None:
        root = pathlib.Path(__file__).resolve().parents[2]
        rules = upstream_delta_scan.load_rules(root / "tools/upstream_delta_rules.yaml")
        report = upstream_delta_scan.scan(root, rules)
        self.assertGreaterEqual(len(report["rows"]), 25)

        by_name = {r["upstream"]: r for r in report["rows"]}
        self.assertIn("TrustTunnel", by_name)
        self.assertIn("EasyTier", by_name)
        self.assertIn("Tunnel", by_name)
        self.assertIn(by_name["EasyTier"]["status"], {"integrated", "out_of_scope_l3", "needs_patch"})


if __name__ == "__main__":
    unittest.main()
