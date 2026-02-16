# Protocol Integration Decision (OpenConnect, ocserv, TrustTunnel)

Date: 2026-02-10  
Status: **Completed & Canonical** (Supersedes 2026-02-06 sidecar decision)  
Scope: `sources/openconnect`, `sources/ocserv`, `sources/TrustTunnel`

## Decision

StealthLink treats mode `TLS` as **in-core canonical**.  
TrustTunnel/CSTP/DTLS behavior is implemented in-core and wired through the unified UQSP runtime.

External sidecars may still be used for interoperability experiments, but they are no longer the architecture default and must not redefine the primary runtime path.

## Implementation Status (As of 2026-02-10)

**All mode TLS components are now complete:**

- ✅ **TrustTunnel Carrier**: Full HTTP/1.1 upgrade, HTTP/2 SETTINGS frames, HTTP/3 (QUIC-based) support in `internal/transport/uqsp/carrier/trusttunnel.go`
- ✅ **TrustTunnel Race Condition Fix**: ttStream.Read now properly synchronized with readMu mutex
- ✅ **TrustTunnel Session Resumption**: TLS session ticket support in setupH2() and setupH3()
- ✅ **CSTP Behavior**: Complete CSTP framing and DPD keepalive in `internal/transport/uqsp/behavior/cstp.go`
- ✅ **H2/H3 Probes**: Real ALPN negotiation with proper timeout handling
- ✅ **Reverse Mode Integration**: HTTP-based reverse registration for CDN compatibility
- ✅ **WARP Integration**: Full Noise IK handshake with HKDF+BLAKE2s key derivation

## Why

- Project goal is full in-core consolidation across 5 customized modes (`HTTP+..TLS`).
- In-core mode `TLS` gives a single control plane for reverse mode, WARP routing, metrics, and lifecycle management.
- Operational reliability is improved when systemd/CLI/install tooling controls one runtime shape instead of mixed in-core/sidecar stacks.

## Canonical Runtime Shape

- `transport.type=uqsp` (or unified stealth runtime path)
- `variant_profile=TLS`
- carrier: `trusttunnel`
- behaviors: `cstp` (+ optional `tlsfrag`, `qpp`, `violated_tcp`)
- reverse mode and WARP are applied uniformly by variant builders

## Sidecar Policy

- Allowed only as explicitly selected compatibility adapters.
- Must be clearly labeled non-canonical in docs/config examples.
- Must not silently replace in-core `TLS` behavior.

## Test Coverage

- ✅ Unit tests: `internal/transport/trusttunnel/trusttunnel_test.go` (concurrent read race, H2/H3 probes)
- ✅ Integration tests: `test/integration/e2e_test.go` and `test/integration/uqsp_variants_test.go` include mode TLS

## Exit Criteria To Reconsider

Reconsider in-core canonical status only if all are true:

- repeatable benchmark evidence shows in-core `TLS` cannot meet throughput/latency targets,
- critical security or correctness gaps remain unresolved after hardening,
- compatibility requirements cannot be met without external protocol termination.
