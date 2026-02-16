#!/usr/bin/env python3
"""Analyze all upstream repositories in sources/ and generate analysis artifacts.

This tool:
1. Enumerates all 47 upstream repos in sources/
2. Extracts metadata (name, git status, license, feature keywords)
3. Cross-references with upstream_delta_rules.yaml for mapping validation
4. Generates upstreams.json and UPSTREAM_ANALYSIS_v2.0.0.md

Usage:
    python3 tools/analyze_upstreams.py
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCES_DIR = ROOT / "sources"
RULES_FILE = ROOT / "tools" / "upstream_delta_rules.yaml"
OUTPUT_DIR = ROOT / "dist" / "upstream-analysis"

FEATURE_PATTERNS = [
    ("tun", r"\btun\b"),
    ("tap", r"\btap\b"),
    ("quic", r"\bquic\b"),
    ("kcp", r"\bkcp\b"),
    ("smux", r"\bsmux\b"),
    ("obfs", r"\bobfs\b"),
    ("reality", r"\breality\b"),
    ("warp", r"\bwarp\b"),
    ("wg", r"\bwireguard\b|\bwg\b"),
    ("masque", r"\bmasque\b"),
    ("dtls", r"\bdtls\b"),
    ("front", r"\bfronting\b|\bfront\b"),
]

LICENSE_PATTERNS = [
    "LICENSE",
    "LICENSE.md",
    "LICENSE.txt",
    "LICENSE.rst",
    "COPYING",
    "COPYING.md",
    "COPYING.txt",
    "COPYING.LESSER",
]


@dataclass
class UpstreamRepo:
    name: str
    path: Path
    is_git: bool = False
    head: str = ""
    license_file: str = ""
    features: list[str] = field(default_factory=list)
    mapping_status: str = "unknown"
    mapping_destinations: list[str] = field(default_factory=list)
    mapping_mode_stack: str = ""


def run_git(args: list[str], cwd: Path) -> str:
    try:
        result = subprocess.run(
            ["git"] + args,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.stdout.strip()
    except Exception:
        return ""


def detect_license(repo_path: Path) -> str:
    for pattern in LICENSE_PATTERNS:
        for f in repo_path.iterdir():
            if f.is_file() and f.name.lower() == pattern.lower():
                return f.name
    return ""


def scan_features(repo_path: Path) -> list[str]:
    features = []
    try:
        result = subprocess.run(
            ["rg", "-l", "-i", "|".join(p[1] for p in FEATURE_PATTERNS)],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return []
        matched_files = (
            set(result.stdout.strip().split("\n")) if result.stdout.strip() else set()
        )
        for name, pattern in FEATURE_PATTERNS:
            try:
                r = subprocess.run(
                    ["rg", "-l", "-i", pattern],
                    cwd=repo_path,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                if r.returncode == 0 and r.stdout.strip():
                    features.append(name)
            except Exception:
                pass
    except FileNotFoundError:
        pass
    return features


def parse_simple_yaml(content: str) -> dict[str, Any]:
    result: dict[str, Any] = {"upstreams": []}
    lines = content.split("\n")
    current_upstream: dict[str, Any] | None = None
    current_key = ""
    indent_stack: list[tuple[int, str]] = []

    for line in lines:
        stripped = line.rstrip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())
        if stripped.lstrip().startswith("- "):
            value = stripped.lstrip()[2:].strip()
            if indent == 2 and value.startswith("name:"):
                if current_upstream:
                    result["upstreams"].append(current_upstream)
                current_upstream = {"name": value.split(":", 1)[1].strip().strip('"')}
                current_key = ""
            elif current_upstream is not None:
                if ":" in value:
                    k, v = value.split(":", 1)
                    k = k.strip()
                    v = v.strip().strip('"')
                    current_upstream[k] = v
                    current_key = k
                elif current_key == "destinations" and value.startswith("-"):
                    dest_val = value.lstrip("- ").strip().strip('"')
                    if "destinations" not in current_upstream:
                        current_upstream["destinations"] = []
                    current_upstream["destinations"].append(dest_val)
        elif ":" in stripped and not stripped.startswith(" "):
            key = stripped.split(":")[0].strip()
            current_key = key
            if key == "upstreams":
                current_upstream = None

    if current_upstream:
        result["upstreams"].append(current_upstream)

    return result


def load_rules() -> dict[str, Any]:
    if not RULES_FILE.exists():
        return {"upstreams": []}
    content = RULES_FILE.read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(content) or {"upstreams": []}
    except ImportError:
        return parse_simple_yaml(content)
    content = RULES_FILE.read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(content) or {"upstreams": []}
    except ImportError:
        return {"upstreams": []}


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    rules = load_rules()
    rules_map = {}
    for entry in rules.get("upstreams", []):
        name = entry.get("name", "")
        if name:
            rules_map[name] = entry

    repos: list[UpstreamRepo] = []
    missing_mappings: list[str] = []

    if not SOURCES_DIR.exists():
        print(f"sources/ directory not found: {SOURCES_DIR}", file=sys.stderr)
        return 1

    for entry in sorted(SOURCES_DIR.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.startswith("."):
            continue

        repo = UpstreamRepo(name=entry.name, path=entry)

        git_dir = entry / ".git"
        repo.is_git = git_dir.exists()
        if repo.is_git:
            repo.head = run_git(["rev-parse", "--short", "HEAD"], entry)

        repo.license_file = detect_license(entry)
        repo.features = scan_features(entry)

        if entry.name in rules_map:
            rule = rules_map[entry.name]
            repo.mapping_status = rule.get("status", "unknown")
            repo.mapping_destinations = rule.get("destinations", [])
            repo.mapping_mode_stack = rule.get("mode_stack", "")
        else:
            missing_mappings.append(entry.name)
            repo.mapping_status = "missing_from_rules"

        repos.append(repo)

    upstreams_json = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "total_repos": len(repos),
        "repos": [
            {
                "name": r.name,
                "is_git": r.is_git,
                "head": r.head,
                "license": r.license_file,
                "features": r.features,
                "mapping_status": r.mapping_status,
                "mapping_destinations": r.mapping_destinations,
                "mapping_mode_stack": r.mapping_mode_stack,
            }
            for r in repos
        ],
        "missing_mappings": missing_mappings,
    }

    json_path = OUTPUT_DIR / "upstreams.json"
    json_path.write_text(json.dumps(upstreams_json, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {json_path}")

    md_lines = [
        "# Upstream Analysis v2.0.0",
        "",
        f"Generated: {datetime.utcnow().isoformat()}Z",
        f"",
        f"**Total upstreams:** {len(repos)}",
        f"",
    ]

    status_counts: dict[str, int] = {}
    for r in repos:
        status_counts[r.mapping_status] = status_counts.get(r.mapping_status, 0) + 1

    md_lines.append("## Mapping Status Summary")
    md_lines.append("")
    md_lines.append("| Status | Count |")
    md_lines.append("|--------|-------|")
    for status, count in sorted(status_counts.items()):
        md_lines.append(f"| {status} | {count} |")
    md_lines.append("")

    if missing_mappings:
        md_lines.append("## Missing Mappings")
        md_lines.append("")
        md_lines.append(
            "The following repos are not defined in `tools/upstream_delta_rules.yaml`:"
        )
        md_lines.append("")
        for name in missing_mappings:
            md_lines.append(f"- `{name}`")
        md_lines.append("")

    md_lines.append("## Repository Details")
    md_lines.append("")

    for r in repos:
        md_lines.append(f"### {r.name}")
        md_lines.append("")
        md_lines.append(f"- **Path:** `sources/{r.name}/`")
        md_lines.append(f"- **Git:** {'Yes' if r.is_git else 'No'}")
        if r.head:
            md_lines.append(f"- **HEAD:** `{r.head}`")
        if r.license_file:
            md_lines.append(f"- **License:** `{r.license_file}`")
        md_lines.append(f"- **Mapping Status:** `{r.mapping_status}`")
        if r.mapping_mode_stack:
            md_lines.append(f"- **Mode Stack:** `{r.mapping_mode_stack}`")
        if r.mapping_destinations:
            md_lines.append(f"- **Destinations:**")
            for d in r.mapping_destinations:
                md_lines.append(f"  - `{d}`")
        if r.features:
            md_lines.append(f"- **Detected Features:** {', '.join(r.features)}")
        md_lines.append("")

    md_path = OUTPUT_DIR / "UPSTREAM_ANALYSIS_v2.0.0.md"
    md_path.write_text("\n".join(md_lines), encoding="utf-8")
    print(f"Wrote {md_path}")

    if missing_mappings:
        print(
            f"Warning: {len(missing_mappings)} repos missing from rules",
            file=sys.stderr,
        )
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
