#!/usr/bin/env python3
"""Maintain reproducible pins for upstream repos under sources/.

This repo vendors many upstream projects under sources/.  We want:
- A reproducible lockfile capturing current pins (commit SHA + tag/describe when available)
- An optional updater that can move each upstream to a newer "latest stable" revision

Design constraints:
- Prefer stdlib only (no PyYAML).
- Never mutate repos unless --update is provided.

Usage:
  python3 tools/upstreams_lock.py --write
  python3 tools/upstreams_lock.py --update --write
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources"
LOCK_PATH = ROOT / "tools" / "upstreams.lock.json"
RULES_PATH = ROOT / "tools" / "upstream_delta_rules.yaml"


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def run_git(repo: Path, *args: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            ["git", *args],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
        return (r.stdout or "").strip()
    except Exception:
        return ""


def is_git_repo(path: Path) -> bool:
    return (path / ".git").exists()


def minimal_rules_upstreams(path: Path) -> list[str]:
    """Extract upstream names from tools/upstream_delta_rules.yaml without PyYAML."""
    if not path.exists():
        return []
    names: list[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Matches: - name: Xray-core
        m = re.match(r"^-\s+name:\s*(.+?)\s*$", line)
        if m:
            val = m.group(1).strip().strip('"').strip("'")
            if val:
                names.append(val)
    return names


def list_upstreams() -> list[str]:
    # Prefer rules file so the lockfile aligns with audit scope.
    names = minimal_rules_upstreams(RULES_PATH)
    if names:
        return names
    if not SOURCES.exists():
        return []
    return sorted([p.name for p in SOURCES.iterdir() if p.is_dir() and not p.name.startswith(".")])


def semver_key(tag: str) -> tuple[int, ...] | None:
    """Best-effort semver-ish key. Accepts v1.2.3, 1.2.3, v1.2."""
    t = tag.strip()
    if t.startswith("refs/tags/"):
        t = t[len("refs/tags/") :]
    if t.startswith("v"):
        t = t[1:]
    if not re.match(r"^\d+(\.\d+){0,3}$", t):
        return None
    return tuple(int(x) for x in t.split("."))


def choose_latest_stable(repo: Path) -> str:
    """Return a rev to checkout. Prefer highest semver tag; else origin/HEAD."""
    tags = run_git(repo, "tag").splitlines()
    semver_tags: list[tuple[tuple[int, ...], str]] = []
    for t in tags:
        k = semver_key(t)
        if k is not None:
            semver_tags.append((k, t.strip()))
    if semver_tags:
        semver_tags.sort(key=lambda x: x[0])
        return semver_tags[-1][1]

    # Fallback: remote HEAD if remote exists
    head = run_git(repo, "symbolic-ref", "-q", "--short", "refs/remotes/origin/HEAD")
    if head.startswith("origin/"):
        return head

    # Fallback: current branch
    br = run_git(repo, "rev-parse", "--abbrev-ref", "HEAD")
    return br or "HEAD"


@dataclass
class LockEntry:
    name: str
    path: str
    is_git: bool
    head: str
    describe: str
    origin: str


def read_origin(repo: Path) -> str:
    return run_git(repo, "remote", "get-url", "origin")


def capture_lock() -> dict[str, Any]:
    entries: list[LockEntry] = []
    missing: list[str] = []

    for name in list_upstreams():
        repo = SOURCES / name
        if not repo.exists():
            missing.append(name)
            continue
        if not repo.is_dir():
            continue

        if is_git_repo(repo):
            head = run_git(repo, "rev-parse", "HEAD")
            describe = run_git(repo, "describe", "--tags", "--always", "--dirty")
            origin = read_origin(repo)
            entries.append(
                LockEntry(
                    name=name,
                    path=str(repo.relative_to(ROOT)),
                    is_git=True,
                    head=head,
                    describe=describe,
                    origin=origin,
                )
            )
        else:
            entries.append(
                LockEntry(
                    name=name,
                    path=str(repo.relative_to(ROOT)),
                    is_git=False,
                    head="",
                    describe="",
                    origin="",
                )
            )

    return {
        "generated_at": _utc_now(),
        "root": str(ROOT),
        "entries": [asdict(e) for e in entries],
        "missing": missing,
        "notes": {
            "policy": "Prefer latest semver tag when updating; else origin/HEAD; else current branch.",
            "mutations": "No repo is modified unless --update is used.",
        },
    }


def update_repos(lock: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    for e in lock.get("entries", []):
        name = str(e.get("name", ""))
        if not name:
            continue
        repo = ROOT / str(e.get("path", ""))
        if not repo.exists() or not is_git_repo(repo):
            continue

        # Best effort: fetch tags and remotes. If offline, keep going.
        _ = run_git(repo, "fetch", "--tags", "--force", "--prune", timeout=120)
        _ = run_git(repo, "fetch", "origin", "--prune", timeout=120)

        target = choose_latest_stable(repo)
        before = run_git(repo, "rev-parse", "HEAD")
        _ = run_git(repo, "checkout", "--quiet", target, timeout=120)
        after = run_git(repo, "rev-parse", "HEAD")
        if before and after and before != after:
            changed.append(name)
    return changed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="Write tools/upstreams.lock.json")
    ap.add_argument("--update", action="store_true", help="Fetch + checkout latest stable revisions")
    ap.add_argument("--lock", default=str(LOCK_PATH), help="Lockfile output path")
    args = ap.parse_args()

    lock = capture_lock()
    changed: list[str] = []
    if args.update:
        changed = update_repos(lock)
        # Re-capture after update so pins reflect current state.
        lock = capture_lock()
        lock["updated_at"] = _utc_now()
        lock["updated_repos"] = changed

    if args.write:
        out_path = Path(args.lock)
        out_path.write_text(json.dumps(lock, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {out_path.relative_to(ROOT)}")
        if changed:
            print(f"updated: {', '.join(changed)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
