#!/usr/bin/env python3
"""Run throughput/latency benchmarks with iperf3/netperf and evaluate gates."""

from __future__ import annotations

import argparse
import json
import shlex
import shutil
import socket
import subprocess
import time
from typing import Any


def run(cmd: list[str]) -> dict:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "cmd": cmd,
        "rc": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
    }

MODE_PROFILES: dict[str, dict[str, str]] = {
    "4a": {"label": "xhttp+fronting"},
    "4b": {"label": "rawtcp+faketcp"},
    "4c": {"label": "tls-lookalike"},
    "4d": {"label": "udp+quic"},
    "4e": {"label": "trusttunnel+cstp"},
}


def load_baseline_metrics(path: str, mode_profile: str | None = None, warp: str = "off") -> dict[str, float]:
    with open(path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    if not isinstance(loaded, dict):
        return {}

    out: dict[str, float] = {}

    # Baseline schema v2:
    # {
    #   "profiles": {
    #     "4a": {"off": {"tcp_mbps": ..., "udp_mbps": ..., "latency_ms": ...}, "on": {...}},
    #     ...
    #   }
    # }
    profiles = loaded.get("profiles")
    if isinstance(profiles, dict) and mode_profile:
        p = profiles.get(str(mode_profile))
        if isinstance(p, dict):
            w = p.get(str(warp))
            if isinstance(w, dict):
                for k in ("tcp_mbps", "udp_mbps", "latency_ms", "reconnect_seconds"):
                    v = w.get(k)
                    if isinstance(v, (int, float)):
                        out[k] = float(v)
                # If v2 schema is present and complete enough, prefer it.
                if "tcp_mbps" in out or "udp_mbps" in out or "latency_ms" in out:
                    return out

    # Flat schema: {"tcp_mbps": ..., "udp_mbps": ..., "latency_ms": ...}
    for k, v in loaded.items():
        if isinstance(v, (int, float)):
            out[k] = float(v)

    # Structured schema used by tools/baseline_metrics.json
    net_perf = loaded.get("network_performance")
    if isinstance(net_perf, dict):
        mapping = {
            "tcp_mbps": "tcp_mbps",
            "udp_mbps": "udp_mbps",
            "latency_p50_ms": "latency_ms",
            "reconnect_seconds": "reconnect_seconds",
        }
        for src, dst in mapping.items():
            val = net_perf.get(src)
            if isinstance(val, (int, float)):
                out[dst] = float(val)

    return out


def run_reconnect_probe(command: str, attempts: int = 3) -> dict[str, Any]:
    cmd = shlex.split(command)
    samples: list[float] = []
    failures = 0
    for _ in range(max(1, attempts)):
        start = time.monotonic()
        p = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.monotonic() - start
        if p.returncode == 0:
            samples.append(elapsed)
        else:
            failures += 1
    avg = (sum(samples) / len(samples)) if samples else None
    return {"samples": samples, "failures": failures, "avg_seconds": avg}


def _safe_load_json(raw: str) -> dict[str, Any]:
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def collect_metrics(results: dict[str, dict[str, Any]]) -> dict[str, float]:
    """Extract comparable metrics from benchmark command outputs."""
    metrics: dict[str, float] = {}

    tcp = results.get("iperf3_tcp", {})
    if tcp.get("rc") == 0:
        obj = _safe_load_json(str(tcp.get("stdout", "")))
        end = obj.get("end", {})
        if isinstance(end, dict):
            recv = end.get("sum_received", {})
            if isinstance(recv, dict):
                bps = recv.get("bits_per_second")
                if isinstance(bps, (int, float)):
                    metrics["tcp_mbps"] = float(bps) / 1_000_000.0

    udp = results.get("iperf3_udp", {})
    if udp.get("rc") == 0:
        obj = _safe_load_json(str(udp.get("stdout", "")))
        end = obj.get("end", {})
        if isinstance(end, dict):
            summary = end.get("sum", {})
            if isinstance(summary, dict):
                bps = summary.get("bits_per_second")
                if isinstance(bps, (int, float)):
                    metrics["udp_mbps"] = float(bps) / 1_000_000.0
                jitter = summary.get("jitter_ms")
                if isinstance(jitter, (int, float)):
                    metrics["latency_ms"] = float(jitter)

    return metrics


def loopback_metrics(seconds: int = 3) -> dict[str, float]:
    """Fallback local benchmark when iperf/netperf are unavailable."""
    duration = max(1, seconds)
    metrics: dict[str, float] = {}

    # TCP throughput on loopback.
    tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_listener.bind(("127.0.0.1", 0))
    tcp_listener.listen(1)
    tcp_port = tcp_listener.getsockname()[1]

    tcp_total = 0

    def _tcp_server() -> None:
        nonlocal tcp_total
        conn, _ = tcp_listener.accept()
        with conn:
            while True:
                data = conn.recv(64 * 1024)
                if not data:
                    break
                tcp_total += len(data)

    import threading

    t = threading.Thread(target=_tcp_server, daemon=True)
    t.start()
    client = socket.create_connection(("127.0.0.1", tcp_port), timeout=2.0)
    payload = b"x" * 64 * 1024
    tcp_start = time.monotonic()
    while time.monotonic() - tcp_start < duration:
        client.sendall(payload)
    client.shutdown(socket.SHUT_WR)
    client.close()
    t.join(timeout=2.0)
    tcp_listener.close()
    tcp_elapsed = max(0.001, time.monotonic() - tcp_start)
    metrics["tcp_mbps"] = (tcp_total * 8.0) / tcp_elapsed / 1_000_000.0

    # UDP throughput + RTT-ish latency on loopback.
    udp_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_server.bind(("127.0.0.1", 0))
    udp_port = udp_server.getsockname()[1]
    udp_server.settimeout(0.2)
    udp_total = 0
    udp_sent = 0
    udp_stop = False

    def _udp_sink() -> None:
        nonlocal udp_total
        while not udp_stop:
            try:
                data, _ = udp_server.recvfrom(2048)
            except TimeoutError:
                continue
            except socket.timeout:
                continue
            udp_total += len(data)

    ut = threading.Thread(target=_udp_sink, daemon=True)
    ut.start()

    udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_payload = b"y" * 1400
    udp_start = time.monotonic()
    while time.monotonic() - udp_start < duration:
        udp_client.sendto(udp_payload, ("127.0.0.1", udp_port))
        udp_sent += len(udp_payload)
    udp_elapsed = max(0.001, time.monotonic() - udp_start)
    udp_stop = True
    ut.join(timeout=1.0)
    udp_server.close()
    udp_client.close()
    observed = max(udp_total, udp_sent)
    metrics["udp_mbps"] = (observed * 8.0) / udp_elapsed / 1_000_000.0

    # Latency via TCP connect+1B exchange loopback probes.
    lat_samples: list[float] = []
    lat_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lat_listener.bind(("127.0.0.1", 0))
    lat_listener.listen(1)
    lat_port = lat_listener.getsockname()[1]
    lat_stop = False

    def _lat_server() -> None:
        while not lat_stop:
            try:
                conn, _ = lat_listener.accept()
            except OSError:
                break
            with conn:
                try:
                    b = conn.recv(1)
                    if b:
                        conn.sendall(b)
                except OSError:
                    pass

    lt = threading.Thread(target=_lat_server, daemon=True)
    lt.start()
    for _ in range(10):
        c = socket.create_connection(("127.0.0.1", lat_port), timeout=1.0)
        s = time.monotonic()
        c.sendall(b"z")
        _ = c.recv(1)
        e = time.monotonic()
        c.close()
        lat_samples.append((e - s) * 1000.0)
    lat_stop = True
    lat_listener.close()
    lt.join(timeout=1.0)
    metrics["latency_ms"] = sum(lat_samples) / max(1, len(lat_samples))

    return metrics


def evaluate_acceptance(
    metrics: dict[str, float],
    baseline: dict[str, float],
    *,
    max_latency_overhead_ms: float = 15.0,
    min_throughput_ratio: float = 0.80,
    max_reconnect_seconds: float = 5.0,
) -> dict[str, Any]:
    """Evaluate metrics against rollout acceptance gates."""
    checks: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, details: str) -> None:
        checks.append({"name": name, "pass": passed, "details": details})

    for key in ("tcp_mbps", "udp_mbps"):
        base = baseline.get(key)
        current = metrics.get(key)
        if base is None:
            continue
        if current is None:
            add_check(
                f"{key}_present",
                False,
                f"baseline requires {key}, but metric is missing",
            )
            continue
        ratio = (current / base) if base > 0 else 0.0
        add_check(
            f"{key}_ratio",
            ratio >= min_throughput_ratio,
            f"current={current:.2f} base={base:.2f} ratio={ratio:.3f} threshold={min_throughput_ratio:.3f}",
        )

    base_latency = baseline.get("latency_ms")
    current_latency = metrics.get("latency_ms")
    if base_latency is not None and current_latency is None:
        add_check(
            "latency_present",
            False,
            "baseline requires latency_ms, but metric is missing",
        )
    if base_latency is not None and current_latency is not None:
        overhead = current_latency - base_latency
        add_check(
            "latency_overhead_ms",
            overhead <= max_latency_overhead_ms,
            f"current={current_latency:.2f} base={base_latency:.2f} overhead={overhead:.2f} threshold={max_latency_overhead_ms:.2f}",
        )

    reconnect_base = baseline.get("reconnect_seconds")
    reconnect = metrics.get("reconnect_seconds")
    if reconnect_base is not None and reconnect is None:
        add_check(
            "reconnect_present",
            False,
            "baseline requires reconnect_seconds, but metric is missing",
        )
    if reconnect is not None:
        add_check(
            "reconnect_seconds",
            reconnect <= max_reconnect_seconds,
            f"current={reconnect:.2f} threshold={max_reconnect_seconds:.2f}",
        )

    passed = all(c["pass"] for c in checks) if checks else False
    return {"pass": passed, "checks": checks}


def run_ci_selftest(baseline_path: str | None = None) -> bool:
    """Run acceptance gate self-test using baseline metrics.

    Returns True if all gates pass, False otherwise.  This mode does not
    require a live iperf3/netperf server and is suitable for CI pipelines.
    """
    baseline: dict[str, float] = {}
    if baseline_path:
        baseline = load_baseline_metrics(baseline_path)

    if not baseline:
        baseline = {"tcp_mbps": 800.0, "udp_mbps": 600.0, "latency_ms": 1.0}

    # Simulate metrics that should pass (identical to baseline = 100% throughput, 0 overhead)
    synthetic = dict(baseline)
    result = evaluate_acceptance(synthetic, baseline)
    output = {"mode": "ci-selftest", "baseline": baseline, "synthetic": synthetic, "acceptance": result}
    print(json.dumps(output, indent=2))
    return result["pass"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", nargs="?", default=None, help="server hostname/IP")
    ap.add_argument("--seconds", type=int, default=10)
    ap.add_argument("--baseline", help="JSON file with baseline metrics")
    ap.add_argument("--min-throughput-ratio", type=float, default=0.80)
    ap.add_argument("--max-latency-overhead-ms", type=float, default=15.0)
    ap.add_argument("--max-reconnect-seconds", type=float, default=5.0)
    ap.add_argument("--mode-profile", choices=sorted(MODE_PROFILES.keys()))
    ap.add_argument("--warp", choices=["on", "off"], default="off")
    ap.add_argument("--reconnect-cmd", help="Command to probe reconnect latency")
    ap.add_argument("--reconnect-attempts", type=int, default=3)
    ap.add_argument("--ci-selftest", action="store_true",
                    help="Run acceptance gate self-test without a live server (for CI)")
    args = ap.parse_args()

    if args.ci_selftest:
        if not run_ci_selftest(args.baseline):
            raise SystemExit(2)
        return

    if not args.target:
        ap.error("target is required unless --ci-selftest is used")

    results = {}
    if shutil.which("iperf3"):
        results["iperf3_tcp"] = run(["iperf3", "-c", args.target, "-J", "-t", str(args.seconds)])
        results["iperf3_udp"] = run(["iperf3", "-c", args.target, "-u", "-J", "-t", str(args.seconds)])
    if shutil.which("netperf"):
        results["netperf"] = run(["netperf", "-H", args.target, "-l", str(args.seconds)])

    output: dict[str, Any] = {"results": results}
    if args.mode_profile:
        output["mode_profile"] = {
            "id": args.mode_profile,
            "label": MODE_PROFILES[args.mode_profile]["label"],
            "warp": args.warp,
        }
    metrics = collect_metrics(results)
    used_fallback = False
    if not metrics and args.target in {"127.0.0.1", "localhost"}:
        metrics = loopback_metrics(args.seconds)
        output["fallback"] = "loopback_socket_benchmark"
        used_fallback = True
    if args.reconnect_cmd:
        reconnect_probe = run_reconnect_probe(args.reconnect_cmd, args.reconnect_attempts)
        output["reconnect_probe"] = reconnect_probe
        avg = reconnect_probe.get("avg_seconds")
        if isinstance(avg, (int, float)):
            metrics["reconnect_seconds"] = float(avg)
    output["metrics"] = metrics

    baseline: dict[str, float] = {}
    if args.baseline:
        baseline = load_baseline_metrics(args.baseline, mode_profile=args.mode_profile, warp=args.warp)
        output["baseline"] = baseline
        gates = evaluate_acceptance(
            metrics,
            baseline,
            max_latency_overhead_ms=args.max_latency_overhead_ms,
            min_throughput_ratio=args.min_throughput_ratio,
            max_reconnect_seconds=args.max_reconnect_seconds,
        )
        if not results and not args.reconnect_cmd and not used_fallback:
            gates["pass"] = False
            gates["checks"].append(
                {
                    "name": "benchmark_tools_present",
                    "pass": False,
                    "details": "no benchmark command executed (iperf3/netperf unavailable and reconnect probe not provided)",
                }
            )
        output["acceptance"] = gates
        print(json.dumps(output, indent=2))
        if not gates["pass"]:
            raise SystemExit(2)
        return

    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
