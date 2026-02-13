#!/usr/bin/env python3
"""Coverage gate for touched packages plus drift checks for core transport packages."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import tempfile
from dataclasses import dataclass

ROOT = pathlib.Path(__file__).resolve().parents[1]
DEFAULT_BASELINE = ROOT / "tools" / "baseline_coverage.json"

CORE_PACKAGES = [
    "./internal/transport/batch",
    "./internal/transport/faketcp",
    "./internal/transport/kcpbase",
    "./internal/transport/rawtcp",
    "./internal/transport/reality",
    "./internal/transport/trusttunnel",
    "./internal/transport/uqsp",
    "./internal/transport/uqsp/behavior",
    "./internal/transport/uqsp/carrier",
    "./internal/transport/xhttp",
    "./internal/transport/xhttpmeta",
    "./internal/mux",
]


@dataclass
class CmdResult:
    rc: int
    out: str
    err: str


def run(*cmd: str) -> CmdResult:
    p = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    return CmdResult(p.returncode, p.stdout.strip(), p.stderr.strip())


def git_touched_go_files() -> list[pathlib.Path]:
    r = run("git", "status", "--porcelain")
    if r.rc != 0:
        raise RuntimeError(r.err or "git status failed")
    paths: list[pathlib.Path] = []
    for line in r.out.splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1].strip()
        if not path.endswith(".go"):
            continue
        p = ROOT / path
        if p.exists():
            paths.append(p)
    return paths


def file_to_pkg(file_path: pathlib.Path) -> str | None:
    rel_dir = file_path.parent.relative_to(ROOT)
    r = run("go", "list", f"./{rel_dir}")
    if r.rc != 0:
        return None
    return r.out


def pkg_to_rel(pkg: str) -> str:
    # stealthlink/internal/foo => ./internal/foo
    marker = "stealthlink/"
    if marker in pkg:
        return "./" + pkg.split(marker, 1)[1]
    return pkg


def package_coverage(pkg_rel: str) -> float:
    with tempfile.NamedTemporaryFile(prefix="cov-", suffix=".out", delete=True) as tmp:
        r = run("go", "test", f"-coverprofile={tmp.name}", pkg_rel)
        if r.rc != 0:
            raise RuntimeError(f"go test failed for {pkg_rel}: {r.err or r.out}")
        c = run("go", "tool", "cover", f"-func={tmp.name}")
        if c.rc != 0:
            raise RuntimeError(f"go tool cover failed for {pkg_rel}: {c.err or c.out}")
        for line in c.out.splitlines():
            if line.startswith("total:"):
                # total: (statements) 72.1%
                pct = line.split()[-1].rstrip("%")
                return float(pct)
    raise RuntimeError(f"unable to parse coverage for {pkg_rel}")


def load_baseline(path: pathlib.Path) -> dict[str, float]:
    if not path.exists():
        return {}
    obj = json.loads(path.read_text(encoding="utf-8"))
    pkgs = obj.get("packages", {})
    out: dict[str, float] = {}
    if isinstance(pkgs, dict):
        for k, v in pkgs.items():
            if isinstance(v, (int, float)):
                out[str(k)] = float(v)
    return out


def write_baseline(path: pathlib.Path, package_cov: dict[str, float]) -> None:
    payload = {"packages": package_cov}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def normalize_path(path_arg: str) -> pathlib.Path:
    p = pathlib.Path(path_arg)
    if not p.is_absolute():
        p = ROOT / p
    return p.resolve()


def load_scope_file(path: pathlib.Path) -> set[str]:
    scope: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        scope.add(line)
    return scope


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--min", type=float, default=80.0, dest="min_cov")
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE))
    parser.add_argument("--write-baseline-if-missing", action="store_true")
    parser.add_argument(
        "--scope-file",
        help="Optional newline-delimited package list to enforce threshold on (for touched packages only)",
    )
    args = parser.parse_args()

    touched_files = git_touched_go_files()
    touched_pkgs_abs = {file_to_pkg(p) for p in touched_files}
    touched_pkgs_abs.discard(None)
    touched_pkgs = sorted(pkg_to_rel(p) for p in touched_pkgs_abs)  # type: ignore[arg-type]

    if not touched_pkgs:
        print("no touched Go packages detected; coverage gate skipped")
        return 0

    scope_pkgs: set[str] = set()
    if args.scope_file:
        scope_path = normalize_path(args.scope_file)
        if not scope_path.exists():
            raise RuntimeError(f"scope file not found: {scope_path}")
        scope_pkgs = load_scope_file(scope_path)

    touched_cov: dict[str, float] = {}
    failures: list[str] = []
    gated_pkgs: list[str] = []
    for pkg in touched_pkgs:
        should_gate = not scope_pkgs or pkg in scope_pkgs
        if should_gate:
            gated_pkgs.append(pkg)
        else:
            continue
        cov = package_coverage(pkg)
        touched_cov[pkg] = cov
        if cov < args.min_cov:
            if should_gate:
                failures.append(f"{pkg}: {cov:.1f}% < {args.min_cov:.1f}%")

    baseline_path = normalize_path(args.baseline)
    baseline_cov = load_baseline(baseline_path)

    core_cov: dict[str, float] = {}
    for pkg in CORE_PACKAGES:
        if pkg in touched_pkgs:
            continue
        core_cov[pkg] = package_coverage(pkg)

    if not baseline_cov and args.write_baseline_if_missing:
        write_baseline(baseline_path, core_cov)
        try:
            rel = baseline_path.relative_to(ROOT)
            print(f"wrote baseline coverage: {rel}")
        except ValueError:
            print(f"wrote baseline coverage: {baseline_path}")
    else:
        for pkg, current in core_cov.items():
            prev = baseline_cov.get(pkg)
            if prev is None:
                continue
            if current + 1e-6 < prev:
                failures.append(f"{pkg}: drift {prev:.1f}% -> {current:.1f}%")

    print("touched package coverage:")
    for pkg, cov in sorted(touched_cov.items()):
        print(f"  {pkg}: {cov:.1f}%")
    if scope_pkgs:
        print("coverage threshold scope:")
        for pkg in sorted(gated_pkgs):
            print(f"  {pkg}")

    if failures:
        print("coverage gate failed:")
        for f in failures:
            print(f"  - {f}")
        return 2

    print("coverage gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
