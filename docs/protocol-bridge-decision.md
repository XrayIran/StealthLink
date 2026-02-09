# Protocol Bridge Decision (OpenConnect, ocserv, TrustTunnel)

Date: 2026-02-06
Status: Accepted
Scope: `sources/openconnect`, `sources/ocserv`, `sources/TrustTunnel`

## Decision

StealthLink will integrate OpenConnect/ocserv/TrustTunnel as **sidecar bridges**, not in-core stealth transports.

## Why

- These are full protocol stacks with independent auth/session/state machines.
- In-core integration would increase the attack surface and complexity of the critical data path.
- Sidecar boundaries keep stealth carrier performance paths (TCP/UDP/ICMP) isolated and easier to harden.
- Sidecars allow independent release cadence and targeted protocol compatibility work.

## Integration Shape

- Sidecar processes terminate external protocols and forward traffic into StealthLink over existing carriers.
- Preferred handoff path:
  - TCP flows: `transport.type=stealth` with `carrier.kind=tcp|kcp|awg`
  - UDP flows: `carrier.kind=raw` with `raw.mode=udp_over_tcp` (or native UDP-capable carriers where available)
  - ICMP path remains in-core via `carrier.kind=raw` + `raw.mode=icmp`
- Control-plane integration should be via explicit local sockets and authenticated service identities.

## Non-Goals

- No direct in-core protocol parser/state-machine implementation for OpenConnect/ocserv/TrustTunnel in the stealth transport package.
- No silent protocol fallback from sidecar mode to in-core experimental code.

## Exit Criteria For Reconsidering In-Core

Revisit this decision only if all are met:

- sidecar bottleneck is measured and material under production load,
- protocol behavior can be reduced to a minimal, auditable subset,
- test coverage proves no regression in stealth core reliability/security.
