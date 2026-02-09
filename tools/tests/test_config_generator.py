from __future__ import annotations

import pathlib
import sys
import unittest

TOOLS_DIR = pathlib.Path(__file__).resolve().parents[1]
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

import config_generator  # noqa: E402


class ConfigGeneratorTests(unittest.TestCase):
    def test_merge_updates_nested_keys(self) -> None:
        dst = {"transport": {"uqsp": {"carrier": {"type": "xhttp"}, "obfuscation": {"profile": "adaptive"}}}}
        src = {"transport": {"uqsp": {"carrier": {"type": "rawtcp"}}}, "role": "agent"}

        out = config_generator.merge(dst, src)

        self.assertEqual(out["transport"]["uqsp"]["carrier"]["type"], "rawtcp")
        self.assertEqual(out["transport"]["uqsp"]["obfuscation"]["profile"], "adaptive")
        self.assertEqual(out["role"], "agent")


if __name__ == "__main__":
    unittest.main()
