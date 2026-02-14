#!/usr/bin/env python3
"""Generate upstream integration delta matrix from deterministic local rules."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys
from typing import Any

ALLOWED_STATUSES = {"integrated", "needs_patch", "out_of_scope_l3", "verify_only"}


def _unquote_scalar(raw: str) -> str:
    raw = raw.strip()
    if len(raw) >= 2 and ((raw[0] == raw[-1] == '"') or (raw[0] == raw[-1] == "'")):
        return raw[1:-1]
    return raw


def _load_rules_minimal_yaml(text: str) -> dict[str, Any]:
    """
    Minimal YAML parser for tools/upstream_delta_rules.yaml.

    We avoid a hard dependency on PyYAML so `make upstream-audit` works on
    clean hosts where only stdlib Python is available.
    """

    out: dict[str, Any] = {}
    upstreams: list[dict[str, Any]] | None = None
    current: dict[str, Any] | None = None
    current_destinations: list[str] | None = None

    for raw in text.splitlines():
        line = raw.rstrip("\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))

        # Top-level key/value (e.g. "version: 1")
        if indent == 0 and ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip()
            current = None
            current_destinations = None
            if val == "":
                if key == "upstreams":
                    upstreams = []
                    out[key] = upstreams
                else:
                    out[key] = None
            else:
                out[key] = _unquote_scalar(val)
            continue

        # New upstream entry (e.g. "  - name: tcpraw")
        if indent == 2 and stripped.startswith("- "):
            if upstreams is None:
                raise ValueError("encountered list item before 'upstreams:'")
            current = {}
            upstreams.append(current)
            current_destinations = None
            rest = stripped[2:].strip()
            if ":" in rest:
                k, v = rest.split(":", 1)
                current[k.strip()] = _unquote_scalar(v.strip())
            else:
                raise ValueError(f"unsupported list item: {stripped!r}")
            continue

        # Upstream fields (e.g. "    status: integrated")
        if indent == 4 and current is not None and ":" in stripped:
            key, val = stripped.split(":", 1)
            key = key.strip()
            val = val.strip()
            current_destinations = None
            if val == "":
                if key == "destinations":
                    current_destinations = []
                    current[key] = current_destinations
                else:
                    current[key] = None
            else:
                current[key] = _unquote_scalar(val)
            continue

        # Destinations list items (e.g. "      - internal/transport/rawtcp")
        if indent == 6 and stripped.startswith("- ") and current is not None:
            # destinations must have been initialized already
            dests = current.get("destinations")
            if not isinstance(dests, list):
                # tolerate weird ordering by initializing on first item
                dests = []
                current["destinations"] = dests
            dests.append(_unquote_scalar(stripped[2:].strip()))
            continue

        raise ValueError(f"unsupported YAML line: {raw!r}")

    return out


def load_rules(path: pathlib.Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        obj = yaml.safe_load(text)
    except ModuleNotFoundError:
        obj = _load_rules_minimal_yaml(text)
    if not isinstance(obj, dict):
        raise ValueError("rules file must decode to a mapping")
    return obj


def resolve_status(base_status: str, src_exists: bool, destinations_ok: bool) -> str:
    if base_status in {"out_of_scope_l3", "verify_only"}:
        return base_status
    if not src_exists or not destinations_ok:
        return "needs_patch"
    return base_status


def scan(root: pathlib.Path, rules: dict[str, Any]) -> dict[str, Any]:
    upstreams = rules.get("upstreams")
    if not isinstance(upstreams, list):
        raise ValueError("rules.upstreams must be a list")

    rows: list[dict[str, Any]] = []
    for entry in upstreams:
        if not isinstance(entry, dict):
            raise ValueError("each upstream entry must be a mapping")
        name = str(entry.get("name", "")).strip()
        mode_stack = str(entry.get("mode_stack", "")).strip()
        base_status = str(entry.get("status", "")).strip()
        destinations = entry.get("destinations", [])
        if not name or not mode_stack:
            raise ValueError(f"invalid upstream entry: {entry!r}")
        if base_status not in ALLOWED_STATUSES:
            raise ValueError(f"{name}: unsupported status {base_status!r}")
        if not isinstance(destinations, list) or not destinations:
            raise ValueError(f"{name}: destinations must be a non-empty list")

        source_path = root / "sources" / name
        src_exists = source_path.exists()

        resolved_destinations: list[str] = []
        missing_destinations: list[str] = []
        for raw in destinations:
            p = root / str(raw)
            resolved_destinations.append(str(raw))
            if not p.exists():
                missing_destinations.append(str(raw))

        effective = resolve_status(
            base_status=base_status,
            src_exists=src_exists,
            destinations_ok=len(missing_destinations) == 0,
        )

        rows.append(
            {
                "upstream": name,
                "mode_stack": mode_stack,
                "status": effective,
                "base_status": base_status,
                "source_exists": src_exists,
                "source_path": str(source_path.relative_to(root)),
                "destinations": resolved_destinations,
                "missing_destinations": missing_destinations,
            }
        )

    return {
        "generated_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "rule_version": rules.get("version", 1),
        "statuses": sorted(ALLOWED_STATUSES),
        "rows": rows,
    }


def render_markdown(report: dict[str, Any]) -> str:
    rows = report["rows"]
    lines = [
        "# Upstream Delta Matrix",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "| Upstream | Mode Stack | Status | Source | Destinations |",
        "|---|---|---|---|---|",
    ]
    for r in rows:
        src = "present" if r["source_exists"] else "missing"
        dest = ", ".join(f"`{d}`" for d in r["destinations"])
        if r["missing_destinations"]:
            missing = ", ".join(f"`{d}`" for d in r["missing_destinations"])
            dest = f"{dest}<br/>missing: {missing}"
        lines.append(
            f"| `{r['upstream']}` | `{r['mode_stack']}` | `{r['status']}` | {src} | {dest} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", default="tools/upstream_delta_rules.yaml")
    parser.add_argument("--json-out", default="docs/upstream-delta-matrix.json")
    parser.add_argument("--md-out", default="docs/upstream-delta-matrix.md")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    rules_path = root / args.rules
    json_out = root / args.json_out
    md_out = root / args.md_out

    rules = load_rules(rules_path)
    report = scan(root, rules)

    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    md_out.write_text(render_markdown(report), encoding="utf-8")

    if args.strict:
        bad: list[str] = []
        for r in report["rows"]:
            if not r["source_exists"]:
                bad.append(f"{r['upstream']}: source snapshot missing")
            if r["status"] == "needs_patch":
                bad.append(f"{r['upstream']}: missing mapped destination path(s)")
        if bad:
            print("upstream audit failed:", file=sys.stderr)
            for item in bad:
                print(f"  - {item}", file=sys.stderr)
            return 2

    try:
        json_label = str(json_out.relative_to(root))
    except ValueError:
        json_label = str(json_out)
    try:
        md_label = str(md_out.relative_to(root))
    except ValueError:
        md_label = str(md_out)
    print(f"wrote {json_label} and {md_label}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
