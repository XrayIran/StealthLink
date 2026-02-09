#!/usr/bin/env python3
"""Basic DPI rule simulator for quick policy regression checks."""

from __future__ import annotations

import argparse
import json
import re

RULES = {
    "sni_block": re.compile(r"(google\.com|youtube\.com|facebook\.com)", re.I),
    "proto_block": re.compile(r"(wireguard|openvpn|trojan)", re.I),
    "keyword_block": re.compile(r"(vpn|proxy|tunnel)", re.I),
}


def evaluate(sample: str) -> dict:
    hits = [name for name, pat in RULES.items() if pat.search(sample)]
    return {"sample": sample, "blocked": bool(hits), "rules": hits}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("samples", nargs="+")
    args = p.parse_args()
    print(json.dumps([evaluate(s) for s in args.samples], indent=2))


if __name__ == "__main__":
    main()
