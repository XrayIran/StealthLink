#!/usr/bin/env python3
"""Generate deployment-optimized StealthLink config profiles."""

from __future__ import annotations

import argparse
import copy
import yaml

BASE = {
    "transport": {
        "type": "uqsp",
        "uqsp": {
            "carrier": {"type": "xhttp"},
            "obfuscation": {"profile": "adaptive", "padding_min": 16, "padding_max": 128},
            "behaviors": {
                "domainfront": {"enabled": True, "front_domain": "cloudflare.com"},
                "ech": {"enabled": True, "public_name": "cloudflare.com"},
                "tlsfrag": {"enabled": True, "strategy": "random"},
            },
        },
    }
}

PROFILES = {
    "iran": {"transport": {"uqsp": {"carrier": {"type": "xhttp"}}}},
    "china": {"transport": {"uqsp": {"carrier": {"type": "rawtcp"}, "obfuscation": {"profile": "adaptive"}}}},
    "russia": {"transport": {"uqsp": {"carrier": {"type": "trusttunnel"}}}},
}


def merge(dst: dict, src: dict) -> dict:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)
        else:
            dst[k] = v
    return dst


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("profile", choices=sorted(PROFILES.keys()))
    p.add_argument("--role", choices=["gateway", "agent"], default="agent")
    p.add_argument("--out", default="")
    args = p.parse_args()

    cfg = copy.deepcopy(BASE)
    cfg["role"] = args.role
    merge(cfg, PROFILES[args.profile])

    txt = yaml.safe_dump(cfg, sort_keys=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(txt)
    else:
        print(txt)


if __name__ == "__main__":
    main()
