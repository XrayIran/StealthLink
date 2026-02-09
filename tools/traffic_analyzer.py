#!/usr/bin/env python3
"""Simple DPI fingerprint analyzer for capture files and live interfaces."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

try:
    from scapy.all import rdpcap, sniff, TCP, UDP, IP  # type: ignore
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"scapy import failed: {exc}")


def summarize_packets(pkts) -> dict:
    protocols = Counter()
    dst_ports = Counter()
    ttl_values = Counter()

    for pkt in pkts:
        if IP in pkt:
            ttl_values[int(pkt[IP].ttl)] += 1
        if TCP in pkt:
            protocols["tcp"] += 1
            dst_ports[int(pkt[TCP].dport)] += 1
        elif UDP in pkt:
            protocols["udp"] += 1
            dst_ports[int(pkt[UDP].dport)] += 1
        else:
            protocols["other"] += 1

    return {
        "total_packets": len(pkts),
        "protocols": dict(protocols),
        "top_dst_ports": dst_ports.most_common(10),
        "top_ttl": ttl_values.most_common(10),
    }


def _tls_client_hello_fingerprint(payload: bytes) -> str:
    # Minimal TLS ClientHello parser for audit mode.
    # Returns empty string when packet payload is not a TLS ClientHello.
    if len(payload) < 9:
        return ""
    if payload[0] != 0x16:  # handshake record
        return ""
    rec_len = (payload[3] << 8) | payload[4]
    if rec_len + 5 > len(payload):
        return ""
    if payload[5] != 0x01:  # ClientHello
        return ""
    hs_len = (payload[6] << 16) | (payload[7] << 8) | payload[8]
    if 9 + hs_len > len(payload):
        return ""
    # TLS version in ClientHello legacy_version
    if len(payload) < 11:
        return ""
    ver = f"{payload[9]:02x}{payload[10]:02x}"
    # Keep audit lightweight: use first bytes of the body as a stable signature seed.
    seed = payload[11 : min(len(payload), 27)]
    return f"v{ver}:{seed.hex()}"


def summarize_tls_fingerprints(pkts) -> dict:
    tls_fp = Counter()
    tls_ports = Counter()
    for pkt in pkts:
        if TCP not in pkt:
            continue
        dport = int(pkt[TCP].dport)
        if dport not in (443, 8443, 2053, 2083):
            continue
        payload = bytes(pkt[TCP].payload)
        fp = _tls_client_hello_fingerprint(payload)
        if not fp:
            continue
        tls_fp[fp] += 1
        tls_ports[dport] += 1
    return {
        "tls_client_hello_total": sum(tls_fp.values()),
        "unique_tls_fingerprints": len(tls_fp),
        "top_tls_fingerprints": tls_fp.most_common(10),
        "top_tls_ports": tls_ports.most_common(10),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--pcap", help="PCAP file path")
    p.add_argument("--iface", help="live interface")
    p.add_argument("--count", type=int, default=200)
    p.add_argument("--out", default="")
    p.add_argument(
        "--audit-tls",
        action="store_true",
        help="include lightweight TLS ClientHello fingerprint audit",
    )
    args = p.parse_args()

    if args.pcap:
        packets = rdpcap(args.pcap)
    elif args.iface:
        packets = sniff(iface=args.iface, count=args.count, timeout=10)
    else:
        raise SystemExit("Provide --pcap or --iface")

    report = summarize_packets(packets)
    if args.audit_tls:
        report["tls_audit"] = summarize_tls_fingerprints(packets)
    text = json.dumps(report, indent=2)
    print(text)

    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
