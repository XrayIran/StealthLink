#!/usr/bin/env python3
"""Live validation orchestration for stress/soak/profile and mode-matrix checks."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "dist" / "live-validation"


def run(cmd: list[str], timeout: int | None = None) -> dict[str, Any]:
    p = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
    )
    return {
        "cmd": cmd,
        "rc": p.returncode,
        "stdout": p.stdout,
        "stderr": p.stderr,
    }


def ts() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def save_report(name: str, payload: dict[str, Any]) -> pathlib.Path:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    out = REPORT_DIR / f"{name}.json"
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return out


def parse_json(stdout: str) -> dict[str, Any]:
    try:
        obj = json.loads(stdout)
    except json.JSONDecodeError:
        return {}
    return obj if isinstance(obj, dict) else {}


def file_nonempty(path: pathlib.Path) -> bool:
    return path.exists() and path.is_file() and path.stat().st_size > 0


def run_mode_matrix(target: str, include_warp: bool) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    matrix_ok = True
    for mode in ("HTTP+", "TCP+", "TLS+", "UDP+", "TLS"):
        cmd = [
            "python3",
            "tools/benchmark_runner.py",
            target,
            "--baseline",
            "tools/baseline_metrics.json",
            "--mode-profile",
            mode,
        ]
        if include_warp:
            cmd += ["--warp", "on"]
        r = run(cmd)
        parsed = parse_json(r["stdout"])
        acceptance = parsed.get("acceptance", {})
        checks = acceptance.get("checks", []) if isinstance(acceptance, dict) else []
        metrics = parsed.get("metrics", {})
        row_ok = (
            r["rc"] == 0
            and isinstance(acceptance, dict)
            and acceptance.get("pass") is True
            and isinstance(checks, list)
            and len(checks) > 0
            and isinstance(metrics, dict)
            and len(metrics) > 0
        )
        if not row_ok:
            matrix_ok = False
        rows.append({"mode": mode, "warp": include_warp, "result": r, "parsed": parsed, "pass": row_ok})
    return {"generated_at": ts(), "target": target, "rows": rows, "pass": matrix_ok}


def run_stress() -> dict[str, Any]:
    tests = [
        run(["go", "test", "./test/integration", "-run", "TestXMuxConnectionChurn_NoLeaks", "-count=1"]),
        run(["go", "test", "./internal/transport/batch", "-run", "TestIntegration_HighPPS", "-count=1"]),
        run(
            [
                "go",
                "test",
                "-tags",
                "integration",
                "./internal/transport/reverse",
                "-run",
                "TestConcurrentStreams",
                "-count=1",
            ]
        ),
    ]
    passed = True
    for t in tests:
        if t["rc"] != 0 or "[no test files]" in t.get("stdout", ""):
            passed = False
    return {"generated_at": ts(), "tests": tests, "pass": passed}


def run_soak(duration_seconds: int, check_interval: int) -> dict[str, Any]:
    started = time.time()
    checks: list[dict[str, Any]] = []
    pass_all = True
    while time.time() - started < duration_seconds:
        r = run(["go", "test", "./test/integration", "-run", "TestUQSPVariantsEndToEnd", "-count=1"])
        if r["rc"] != 0:
            pass_all = False
        checks.append({"at": ts(), "go_test_integration": r})
        time.sleep(check_interval)
    return {"generated_at": ts(), "duration_seconds": duration_seconds, "checks": checks, "pass": pass_all}


def collect_pprof(base_url: str, output_prefix: str, cpu_seconds: int) -> dict[str, Any]:
    out_cpu = REPORT_DIR / f"{output_prefix}-cpu.pb.gz"
    out_heap = REPORT_DIR / f"{output_prefix}-heap.pb.gz"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    cpu = run(
        [
            "curl",
            "-fsSL",
            f"{base_url.rstrip('/')}/debug/pprof/profile?seconds={cpu_seconds}",
            "-o",
            str(out_cpu),
        ],
        timeout=max(cpu_seconds + 10, 30),
    )
    heap = run(
        [
            "curl",
            "-fsSL",
            f"{base_url.rstrip('/')}/debug/pprof/heap",
            "-o",
            str(out_heap),
        ]
    )
    cpu_ok = cpu["rc"] == 0 and file_nonempty(out_cpu)
    heap_ok = heap["rc"] == 0 and file_nonempty(out_heap)
    fallback: dict[str, Any] | None = None
    if not (cpu_ok and heap_ok):
        # Fallback: produce local profiles from integration workloads.
        cpu_fb = run(
            [
                "go",
                "test",
                "./test/integration",
                "-run",
                "TestUQSPVariantsEndToEndOverLocalhost",
                "-count=1",
                f"-cpuprofile={out_cpu}",
            ],
            timeout=max(cpu_seconds + 30, 60),
        )
        heap_fb = run(
            [
                "go",
                "test",
                "./test/integration",
                "-run",
                "TestUQSPVariantsEndToEndOverLocalhost",
                "-count=1",
                f"-memprofile={out_heap}",
            ],
            timeout=max(cpu_seconds + 30, 60),
        )
        cpu_ok = cpu_fb["rc"] == 0 and file_nonempty(out_cpu)
        heap_ok = heap_fb["rc"] == 0 and file_nonempty(out_heap)
        fallback = {"cpu_profile_cmd": cpu_fb, "heap_profile_cmd": heap_fb}
    return {
        "generated_at": ts(),
        "base_url": base_url,
        "cpu_profile": str(out_cpu.relative_to(ROOT)),
        "heap_profile": str(out_heap.relative_to(ROOT)),
        "cpu_fetch": cpu,
        "heap_fetch": heap,
        "fallback": fallback,
        "pass": cpu_ok and heap_ok,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_validate = sub.add_parser("validate-live")
    p_validate.add_argument("--target", required=True)
    p_validate.add_argument("--warp", choices=["on", "off", "both"], default="both")

    sub.add_parser("stress")

    p_soak = sub.add_parser("soak")
    p_soak.add_argument("--duration-seconds", type=int, default=24 * 60 * 60)
    p_soak.add_argument("--check-interval-seconds", type=int, default=300)

    p_profile = sub.add_parser("profile")
    p_profile.add_argument("--pprof-url", default="http://127.0.0.1:9090")
    p_profile.add_argument("--cpu-seconds", type=int, default=60)
    p_profile.add_argument("--output-prefix", default="live")

    sub.add_parser("release-readiness")

    args = parser.parse_args()

    if args.cmd == "validate-live":
        payload: dict[str, Any] = {"generated_at": ts(), "target": args.target, "runs": []}
        modes = ["off", "on"] if args.warp == "both" else [args.warp]
        ok = True
        for warp in modes:
            result = run_mode_matrix(args.target, include_warp=(warp == "on"))
            payload["runs"].append(result)
            if not result.get("pass", False):
                ok = False
        payload["pass"] = ok
        out = save_report("validate-live", payload)
        print(out.relative_to(ROOT))
        return 0 if ok else 2

    if args.cmd == "stress":
        report = run_stress()
        out = save_report("stress-live", report)
        print(out.relative_to(ROOT))
        return 0 if report.get("pass", False) else 2

    if args.cmd == "soak":
        report = run_soak(args.duration_seconds, args.check_interval_seconds)
        out = save_report("soak-24h", report)
        print(out.relative_to(ROOT))
        return 0 if report.get("pass", False) else 2

    if args.cmd == "profile":
        report = collect_pprof(args.pprof_url, args.output_prefix, args.cpu_seconds)
        out = save_report(
            "profile-live",
            report,
        )
        print(out.relative_to(ROOT))
        return 0 if report.get("pass", False) else 2

    if args.cmd == "release-readiness":
        required = [
            REPORT_DIR / "validate-live.json",
            REPORT_DIR / "stress-live.json",
            REPORT_DIR / "profile-live.json",
        ]
        missing = [str(p.relative_to(ROOT)) for p in required if not p.exists()]
        payload: dict[str, Any] = {"generated_at": ts(), "required_reports": [str(p.relative_to(ROOT)) for p in required]}
        if missing:
            payload["pass"] = False
            payload["missing_reports"] = missing
            out = save_report("release-readiness", payload)
            print(out.relative_to(ROOT))
            return 2

        reports: dict[str, Any] = {}
        all_pass = True
        for p in required:
            obj = parse_json(p.read_text(encoding="utf-8"))
            key = p.name
            reports[key] = obj
            if obj.get("pass") is not True:
                all_pass = False
        payload["reports"] = reports
        payload["pass"] = all_pass
        out = save_report("release-readiness", payload)
        print(out.relative_to(ROOT))
        return 0 if all_pass else 2

    print(f"unsupported command: {args.cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
