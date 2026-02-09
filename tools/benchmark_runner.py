#!/usr/bin/env python3
"""Run throughput/latency benchmarks with iperf3/netperf."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess


def run(cmd: list[str]) -> dict:
    p = subprocess.run(cmd, capture_output=True, text=True)
    return {
        "cmd": cmd,
        "rc": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="server hostname/IP")
    ap.add_argument("--seconds", type=int, default=10)
    args = ap.parse_args()

    results = {}
    if shutil.which("iperf3"):
        results["iperf3_tcp"] = run(["iperf3", "-c", args.target, "-J", "-t", str(args.seconds)])
        results["iperf3_udp"] = run(["iperf3", "-c", args.target, "-u", "-J", "-t", str(args.seconds)])
    if shutil.which("netperf"):
        results["netperf"] = run(["netperf", "-H", args.target, "-l", str(args.seconds)])

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
