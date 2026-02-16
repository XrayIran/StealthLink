from __future__ import annotations

import pathlib
import sys
import tempfile
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

    def test_collect_metrics_extracts_iperf_values(self) -> None:
        sample = {
            "iperf3_tcp": {
                "rc": 0,
                "stdout": '{"end":{"sum_received":{"bits_per_second":800000000}}}',
            },
            "iperf3_udp": {
                "rc": 0,
                "stdout": '{"end":{"sum":{"bits_per_second":600000000,"jitter_ms":4.2}}}',
            },
        }
        metrics = benchmark_runner.collect_metrics(sample)
        self.assertAlmostEqual(metrics["tcp_mbps"], 800.0)
        self.assertAlmostEqual(metrics["udp_mbps"], 600.0)
        self.assertAlmostEqual(metrics["latency_ms"], 4.2)

    def test_evaluate_acceptance_passes_balanced_thresholds(self) -> None:
        metrics = {"tcp_mbps": 800.0, "udp_mbps": 600.0, "latency_ms": 10.0, "reconnect_seconds": 4.0}
        baseline = {"tcp_mbps": 900.0, "udp_mbps": 700.0, "latency_ms": 2.0}
        result = benchmark_runner.evaluate_acceptance(metrics, baseline)
        self.assertTrue(result["pass"])

    def test_evaluate_acceptance_fails_low_throughput(self) -> None:
        metrics = {"tcp_mbps": 100.0, "latency_ms": 20.0}
        baseline = {"tcp_mbps": 300.0, "latency_ms": 1.0}
        result = benchmark_runner.evaluate_acceptance(metrics, baseline)
        self.assertFalse(result["pass"])
        names = {c["name"] for c in result["checks"] if not c["pass"]}
        self.assertIn("tcp_mbps_ratio", names)

    def test_evaluate_acceptance_fails_missing_required_metric(self) -> None:
        metrics = {"tcp_mbps": 500.0}
        baseline = {"tcp_mbps": 500.0, "udp_mbps": 500.0}
        result = benchmark_runner.evaluate_acceptance(metrics, baseline)
        self.assertFalse(result["pass"])
        names = {c["name"] for c in result["checks"] if not c["pass"]}
        self.assertIn("udp_mbps_present", names)

    def test_evaluate_acceptance_fails_without_any_checks(self) -> None:
        result = benchmark_runner.evaluate_acceptance({}, {})
        self.assertFalse(result["pass"])
        self.assertEqual(len(result["checks"]), 0)


    def test_ci_selftest_passes_with_default_baseline(self) -> None:
        self.assertTrue(benchmark_runner.run_ci_selftest())

    def test_ci_selftest_passes_with_baseline_file(self) -> None:
        baseline = {"tcp_mbps": 500.0, "udp_mbps": 400.0, "latency_ms": 2.0}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json
            json.dump(baseline, f)
            f.flush()
            self.assertTrue(benchmark_runner.run_ci_selftest(f.name))

    def test_load_baseline_metrics_from_structured_schema(self) -> None:
        structured = {
            "metadata": {"version": "baseline-v1"},
            "network_performance": {
                "tcp_mbps": 111.0,
                "udp_mbps": 222.0,
                "latency_p50_ms": 3.5,
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json
            json.dump(structured, f)
            f.flush()
            loaded = benchmark_runner.load_baseline_metrics(f.name)
        self.assertEqual(loaded["tcp_mbps"], 111.0)
        self.assertEqual(loaded["udp_mbps"], 222.0)
        self.assertEqual(loaded["latency_ms"], 3.5)

    def test_load_baseline_metrics_from_profiles_schema_v2(self) -> None:
        structured = {
            "profiles": {
                "HTTP+": {
                    "off": {"tcp_mbps": 100.0, "udp_mbps": 200.0, "latency_ms": 3.0},
                    "on": {"tcp_mbps": 90.0, "udp_mbps": 180.0, "latency_ms": 6.0},
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            import json
            json.dump(structured, f)
            f.flush()
            loaded_off = benchmark_runner.load_baseline_metrics(f.name, mode_profile="HTTP+", warp="off")
            loaded_on = benchmark_runner.load_baseline_metrics(f.name, mode_profile="HTTP+", warp="on")
        self.assertEqual(loaded_off["tcp_mbps"], 100.0)
        self.assertEqual(loaded_off["udp_mbps"], 200.0)
        self.assertEqual(loaded_off["latency_ms"], 3.0)
        self.assertEqual(loaded_on["tcp_mbps"], 90.0)
        self.assertEqual(loaded_on["udp_mbps"], 180.0)
        self.assertEqual(loaded_on["latency_ms"], 6.0)

    def test_run_reconnect_probe(self) -> None:
        probe = benchmark_runner.run_reconnect_probe("python3 -c pass", attempts=2)
        self.assertEqual(probe["failures"], 0)
        self.assertEqual(len(probe["samples"]), 2)
        self.assertIsInstance(probe["avg_seconds"], float)

    def test_loopback_metrics_returns_required_keys(self) -> None:
        m = benchmark_runner.loopback_metrics(1)
        self.assertIn("tcp_mbps", m)
        self.assertIn("udp_mbps", m)
        self.assertIn("latency_ms", m)
        self.assertGreater(m["tcp_mbps"], 0.0)
        self.assertGreater(m["udp_mbps"], 0.0)


if __name__ == "__main__":
    unittest.main()
