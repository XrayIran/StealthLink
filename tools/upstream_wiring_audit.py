#!/usr/bin/env python3
"""
upstream_wiring_audit: prove upstream "integration" is reachable in real code paths.

This complements tools/upstream_delta_scan.py (which checks presence of source snapshots
and mapped destination paths) by answering:
  - Are the mapped destination Go packages reachable from production entrypoints
    (cmd/agent, cmd/gateway)?
  - If not reachable, is there an explicit wiring test declaring technique-only coverage?

Stdlib-only.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Any


ROOT = pathlib.Path(__file__).resolve().parents[1]
RULES = ROOT / "tools" / "upstream_delta_rules.yaml"
FEATURE_MAP = ROOT / "docs" / "upstreams" / "FEATURE_MAP.md"

OUT_DIR = ROOT / "dist" / "upstream-analysis"
OUT_JSON = OUT_DIR / "wiring_audit.json"
OUT_MD = OUT_DIR / "wiring_audit.md"


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)


def die(msg: str) -> None:
    print(f"upstream_wiring_audit: {msg}", file=sys.stderr)
    raise SystemExit(2)


# ---------------------------------------------------------------------------
# Minimal rules loader: reuse upstream_delta_scan's YAML decoding (stdlib-only).
# ---------------------------------------------------------------------------


def load_rules(path: pathlib.Path) -> dict[str, Any]:
    sys.path.insert(0, str((ROOT / "tools").resolve()))
    try:
        import upstream_delta_scan  # type: ignore
    except Exception as e:  # pragma: no cover
        die(f"failed to import tools/upstream_delta_scan.py: {e}")
    try:
        return upstream_delta_scan.load_rules(path)  # type: ignore[attr-defined]
    except Exception as e:
        die(f"failed to load rules: {e}")


# ---------------------------------------------------------------------------
# Wiring evidence via deps and explicit wiring tests
# ---------------------------------------------------------------------------


def module_name() -> str:
    p = ROOT / "go.mod"
    text = p.read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("module "):
            return line.split(None, 1)[1].strip()
    die("could not parse module name from go.mod")
    return ""


def normalize_destination(dest: str) -> str:
    # Accept file paths by mapping to their directory.
    dest = dest.strip().lstrip("./")
    if not dest:
        return ""
    if dest.endswith(".go"):
        dest = str(pathlib.Path(dest).parent)
    # Strip trailing slash.
    dest = dest.rstrip("/")
    return dest


def go_pkg_path(mod: str, dest: str) -> str | None:
    # Only Go packages are checked via go list -deps.
    if not dest:
        return None
    if dest.startswith("internal/") or dest.startswith("cmd/") or dest.startswith("agent/") or dest.startswith("gateway/"):
        return f"{mod}/{dest}"
    return None


def dep_graph(entrypoints: list[str]) -> set[str]:
    p = run(["go", "list", "-deps", *entrypoints])
    if p.returncode != 0:
        die(f"go list -deps failed:\n{p.stderr}")
    return set(line.strip() for line in p.stdout.splitlines() if line.strip())


_MARKER_RE = re.compile(r"(?m)^[ \t]*//[ \t]*UPSTREAM_WIRING:[ \t]*([A-Za-z0-9_.\\-]+)[ \t]*$")


def scan_wiring_markers() -> dict[str, list[str]]:
    """
    Find explicit wiring declarations in Go tests:
      // UPSTREAM_WIRING: <upstream-name>

    Returns upstream -> list of file paths (repo-relative).
    """
    out: dict[str, list[str]] = {}
    for path in ROOT.rglob("*_test.go"):
        # Skip dist/ and sources/ to avoid noise.
        try:
            rel = path.relative_to(ROOT)
        except ValueError:
            continue
        if rel.parts and rel.parts[0] in ("dist", "sources"):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _MARKER_RE.finditer(text):
            name = m.group(1).strip()
            out.setdefault(name, []).append(str(rel))
    return out


@dataclass
class Row:
    upstream: str
    status: str
    mode_stack: str
    destinations: list[str]
    reachable: bool
    reachable_destinations: list[str]
    explicit_wiring_tests: list[str]
    pass_: bool
    notes: list[str]


def evaluate(rules: dict[str, Any], deps: set[str], markers: dict[str, list[str]]) -> dict[str, Any]:
    mod = module_name()
    rows: list[dict[str, Any]] = []
    requested_env = os.environ.get("UPSTREAM_WIRING_REQUESTED", "").strip()
    requested = set(s.strip() for s in requested_env.split(",") if s.strip()) if requested_env else None

    for u in rules.get("upstreams", []) or []:
        name = str(u.get("name", "")).strip()
        if not name:
            continue

        status = str(u.get("status", "")).strip()
        mode_stack = str(u.get("mode_stack", "")).strip()
        dests_raw = u.get("destinations", [])
        dests = [normalize_destination(str(d)) for d in (dests_raw or [])]
        dests = [d for d in dests if d]

        reachable_dests: list[str] = []
        notes: list[str] = []
        for d in dests:
            pkg = go_pkg_path(mod, d)
            if pkg is None:
                notes.append(f"non-go-destination:{d}")
                continue
            if pkg in deps:
                reachable_dests.append(d)
                continue
            # Accept prefix matches: mapping to a directory may have subpackages in deps.
            prefix = pkg.rstrip("/") + "/"
            if any(p.startswith(prefix) for p in deps):
                reachable_dests.append(d)

        explicit = markers.get(name, [])

        # Passing rule:
        # - out_of_scope_l3 / verify_only are informational and do not fail wiring
        # - otherwise: must be reachable from deps OR have explicit wiring test markers
        reachable = len(reachable_dests) > 0
        gated = requested is None or name in requested
        pass_row = True
        if gated and status not in ("out_of_scope_l3", "verify_only"):
            pass_row = reachable or len(explicit) > 0
        if not gated:
            notes.append("not-gated")

        rows.append(
            Row(
                upstream=name,
                status=status,
                mode_stack=mode_stack,
                destinations=dests,
                reachable=reachable,
                reachable_destinations=reachable_dests,
                explicit_wiring_tests=explicit,
                pass_=pass_row,
                notes=notes,
            ).__dict__
        )

    ok = all(r["pass_"] for r in rows)
    return {
        "generated_at": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "entrypoints": ["./cmd/agent", "./cmd/gateway"],
        "gated_upstreams": sorted(requested) if requested is not None else [],
        "pass": ok,
        "rows": rows,
    }


def render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Upstream Wiring Audit",
        "",
        f"Generated: {report.get('generated_at', '')}",
        "",
        "This report checks whether each upstream's mapped destination packages are reachable from `cmd/agent` or `cmd/gateway` via `go list -deps`.",
        "If a destination is not reachable, the upstream can still pass if there is an explicit wiring test marker:",
        "",
        "```go",
        "// UPSTREAM_WIRING: <upstream-name>",
        "```",
        "",
        "| Upstream | Status | Reachable From cmd/* | Explicit Wiring Tests | Destinations (reachable subset) |",
        "|---|---:|:---:|---|---|",
    ]
    for r in report.get("rows", []):
        name = r["upstream"]
        status = r.get("status", "")
        reach = "yes" if r.get("reachable") else "no"
        tests = ", ".join(f"`{p}`" for p in (r.get("explicit_wiring_tests") or [])) or "-"
        dests = ", ".join(f"`{d}`" for d in (r.get("destinations") or [])) or "-"
        reach_d = ", ".join(f"`{d}`" for d in (r.get("reachable_destinations") or [])) or "-"
        lines.append(f"| `{name}` | `{status}` | **{reach}** | {tests} | {dests}<br/>reachable: {reach_d} |")
    lines.append("")
    lines.append(f"Overall: {'PASS' if report.get('pass') else 'FAIL'}")
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default=str(RULES.relative_to(ROOT)))
    ap.add_argument(
        "--upstreams",
        default="",
        help="Comma-separated list of upstream names to gate (others are still reported but won't fail --strict). "
        "Equivalent to setting UPSTREAM_WIRING_REQUESTED.",
    )
    ap.add_argument("--strict", action="store_true", help="Fail gated upstreams that are neither reachable nor explicitly wired by tests.")
    args = ap.parse_args()

    if args.upstreams.strip():
        os.environ["UPSTREAM_WIRING_REQUESTED"] = args.upstreams.strip()

    rules = load_rules(ROOT / args.rules)
    deps = dep_graph(["./cmd/agent", "./cmd/gateway"])
    markers = scan_wiring_markers()
    report = evaluate(rules, deps, markers)

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    OUT_MD.write_text(render_md(report), encoding="utf-8")

    print(str(OUT_JSON.relative_to(ROOT)))
    print(str(OUT_MD.relative_to(ROOT)))

    if args.strict and not report.get("pass", False):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
