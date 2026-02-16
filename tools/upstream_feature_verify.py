#!/usr/bin/env python3
"""
Verify docs/upstreams/FEATURE_MAP.md covers requested upstreams and references
real in-repo destinations/tests.

Stdlib-only by design.
"""

from __future__ import annotations

import os
import re
import sys
import argparse
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
FEATURE_MAP = ROOT / "docs" / "upstreams" / "FEATURE_MAP.md"

REQUESTED = [
    "conjure",
    "daggerConnect",
    "snowflake",
    "Tunnel",
    "psiphon-tunnel-core",
    "paqet",
    "paqctl",
    "EasyTier",
    "lyrebird",
    "webtunnel",
]


@dataclass
class Section:
    name: str
    body: str


def die(msg: str) -> None:
    print(f"upstream_feature_verify: {msg}", file=sys.stderr)
    raise SystemExit(2)


def read_text(p: Path) -> str:
    try:
        return p.read_text(encoding="utf-8")
    except FileNotFoundError:
        die(f"missing file: {p}")


def split_sections(md: str) -> list[Section]:
    # Split on "## " headings only.
    parts = re.split(r"(?m)^##[ ]+", md)
    if len(parts) <= 1:
        return []
    out: list[Section] = []
    for part in parts[1:]:
        lines = part.splitlines()
        if not lines:
            continue
        name = lines[0].strip()
        body = "\n".join(lines[1:]).strip() + "\n"
        out.append(Section(name=name, body=body))
    return out


def find_subsection(body: str, title: str) -> str:
    # Extract between "### {title}" and next "### " or end.
    m = re.search(rf"(?ms)^### {re.escape(title)}\s*$\n(.*?)(?=^### |\Z)", body)
    return m.group(1) if m else ""


def parse_status(body: str) -> str:
    m = re.search(r"(?m)^Status:\s*(.+?)\s*$", body)
    if not m:
        return ""
    # Normalize: strip any parenthetical notes.
    s = m.group(1).strip()
    s = s.split("(", 1)[0].strip()
    return s.lower()


def extract_backticked_paths(text: str) -> list[str]:
    out: list[str] = []
    for m in re.finditer(r"`([^`]+)`", text):
        tok = m.group(1).strip()
        if not tok or tok.startswith("http://") or tok.startswith("https://"):
            continue
        # We only validate repo-relative paths.
        if "/" not in tok and "\\" not in tok:
            continue
        tok = tok.split(":", 1)[0]  # allow `path:TestName`
        tok = tok.split("#", 1)[0]  # allow `path#L123`
        tok = tok.strip()
        if tok:
            out.append(tok)
    # Dedupe preserving order.
    seen = set()
    uniq: list[str] = []
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq


def main() -> int:
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--strict", action="store_true", help="Reserved for compatibility; verification is always strict.")
    _ = ap.parse_args()

    md = read_text(FEATURE_MAP)
    sections = split_sections(md)
    by_name = {s.name: s for s in sections}

    missing = [u for u in REQUESTED if u not in by_name]
    if missing:
        die(f"missing upstream sections: {', '.join(missing)}")

    problems: list[str] = []

    for up in REQUESTED:
        sec = by_name[up]
        status = parse_status(sec.body)
        if not status:
            problems.append(f"{up}: missing Status: line")
            continue

        intentionally_unused = "intentionally unused" in status or "out_of_scope" in status

        where = find_subsection(sec.body, "Where implemented")
        tests = find_subsection(sec.body, "Tests that prove it")

        where_paths = extract_backticked_paths(where)
        test_paths = extract_backticked_paths(tests)

        if not intentionally_unused:
            if not where_paths:
                problems.append(f"{up}: no paths listed under 'Where implemented'")
            if not test_paths:
                problems.append(f"{up}: no paths listed under 'Tests that prove it'")

        for p in where_paths:
            full = ROOT / p
            if not full.exists():
                problems.append(f"{up}: mapped path does not exist: {p}")

        for p in test_paths:
            full = ROOT / p
            if not full.exists():
                problems.append(f"{up}: mapped test does not exist: {p}")

    if problems:
        die("verification failed:\n- " + "\n- ".join(problems))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
