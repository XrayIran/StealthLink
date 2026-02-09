# Upstream Integration Audit (StealthLink)

Date: 2026-02-06
Scope: `sources/*` listed by project owner, focused on Linux server-to-server high-performance tunneling.

## Executive Summary

StealthLink already has a strong unification direction: a single runtime transport entry (`transport.type=stealth`) with configurable carrier/camouflage/shaping/session controls. The codebase contains many modules named after upstream projects, but runtime integration quality is mixed:

- Solidly integrated: KCP/KCPTUN lineage, ShadowTLS, TLS/WSS/H2 camouflage, raw TCP adapters, noize/fragmentation shaping, transparent-proxy tooling.
- Partially integrated: REALITY (custom implementation), MASQUE/QUIC advanced behavior, ocserv/openconnect compatibility.
- Missing integration: openconnect/ocserv protocol stacks, TrustTunnel feature parity.

Main technical theme: there are multiple modules with significant code but incomplete runtime wiring or placeholder logic. Consolidation should prioritize "only production-grade code paths exposed in config" and aggressively retire or gate incomplete paths.

## Current Runtime Architecture

- Runtime transport is centralized under `transport.type=stealth`:
  - `internal/config/stealth.go`
  - `internal/transport/stealth/stealth.go`
- Gateway/agent both build transport through stealth builders:
  - `internal/gateway/gateway.go`
  - `internal/agent/agent.go`

This is the right direction for throughput and operability: one composition surface and fewer codepaths.

## Upstream Coverage Matrix

Legend:
- `Integrated`: wired into active runtime path.
- `Partial`: code exists but incomplete behavior, incomplete wiring, or fidelity gaps.
- `Missing`: no meaningful runtime support.

1. `sources/paqet` -> `Integrated (partial-fidelity)`
- Evidence: raw packet/raw TCP stack and packet guard (`internal/transport/rawtcp/*`, `internal/transport/packet_guard.go`).
- Gap: parity with paqet CLI/workflow not fully represented.

2. `sources/Tunnel` -> `Integrated (partial-fidelity)`
- Evidence: reverse/tunnel management patterns (`internal/transport/reverse/reverse.go`, `internal/robot/robot.go`).
- Gap: upstream-specific orchestration and UX not fully mirrored.

3. `sources/kcptun` -> `Integrated`
- Evidence: KCP + smux + FEC/autotune + DSCP + brutal CC controls (`internal/transport/kcpmux/kcpmux.go`, `internal/transport/kcputil/kcputil.go`, `internal/config/config.go`).

4. `sources/Xray-core` (XHTTP, REALITY) -> `Integrated (partial-fidelity)`
- XHTTP:
  - Evidence: dedicated transport module is runtime wired for `https-splithttp` profile (`internal/transport/xhttp/xhttp.go`, `internal/transport/stealth/stealth.go`).
  - Gap: this implementation maps XHTTP semantics onto hardened HTTP/2 stream transport for stability, not full byte-level parity with upstream Xray behavior.
- REALITY:
  - Evidence: module wired in stealth profile (`internal/transport/stealth/stealth.go`).
  - Gap: custom implementation with non-upstream fidelity; now hardened in this audit pass but still not feature-equivalent to Xray REALITY.

5. `sources/v2ray-core` (TLSMirror) -> `Integrated (partial-fidelity)`
- Evidence: tlsmirror dialer/cache wiring (`internal/transport/tlsmirror/tlsmirror.go`, `internal/tlsutil/mirror.go`, `internal/transport/stealth/stealth.go`).
- Gap: full v2ray-core behavioral parity not validated.

6. `sources/sing-box` (ShadowTLS) -> `Integrated (partial-fidelity)`
- Evidence: shadowtls transport is runtime wired (`internal/transport/shadowtls/*`, `internal/transport/stealth/stealth.go`).
- Gap: upstream behavioral parity scope should be validated by interoperability tests.

7. `sources/amnezia-client` (AmneziaWG 2.0) -> `Integrated (partial-fidelity)`
- Evidence: AWG carrier is wired through stealth runtime (`internal/transport/stealth/stealth.go`), with keyed-KCP-backed AWG transport (`internal/transport/awg/awg.go`) and config coverage (`internal/config/stealth.go`, `internal/config/stealth_matrix_test.go`).
- Gap: implementation remains compatibility-focused, not full protocol parity with upstream AmneziaWG 2.0 behavior.

8. `sources/v2rayA` (redirect, tproxy) -> `Integrated (partial-fidelity)`
- Evidence: transparent proxy config + tools + nft/iptables backend (`internal/config/extensions.go`, `internal/tproxy/*`, `cmd/tools/main.go`).
- Gap: advanced policy scenarios still need privileged kernel-level e2e coverage; command-path e2e coverage and Linux original-destination handling are in place (`internal/tproxy/tproxy.go`, `internal/tproxy/tproxy_e2e_linux_test.go`).

9. `sources/hysteria` -> `Partial`
- Evidence: handshake padding + salamander obfs + h3/masque ideas (`internal/transport/padding/handshake.go`, `internal/transport/obfs/salamander.go`, `internal/transport/quicmux/h3masq.go`).
- Gap: not a full hysteria protocol implementation.

10. `sources/WaterWall` -> `Partial`
- Evidence: half-duplex and multiport ideas (`internal/transport/halfduplex/halfduplex.go`, `internal/transport/multiport/listener.go`).
- Gap: no full WaterWall node-graph parity.

11. `sources/Vwarp` -> `Partial`
- Evidence: noize and SNI blend lineage (`internal/transport/noize/noize.go`, `internal/tlsutil/sniblend.go`).
- Gap: no direct Vwarp chain integration/parity.

12. `sources/shadowsocks-rust` -> `Partial`
- Evidence: FakeDNS + bloom replay ideas (`internal/dns/fakedns/fakedns.go`, `internal/security/bloom/bloom.go`).
- Gap: no shadowsocks protocol runtime.

13. `sources/qtun` -> `Partial`
- Evidence: QUIC + QPP concepts (`internal/transport/quicmux/*`, `internal/crypto/qpp/qpp.go`).
- Gap: not a qtun SIP003 plugin-compatible implementation.

14. `sources/badvpn` -> `Partial`
- Evidence: TUN/TAP and transport tuning primitives (`internal/tun/*`, `internal/transport/taptun/taptun.go`).
- Gap: no badvpn protocol/runtime integration.

15. `sources/VPS-Optimizer` -> `Integrated (partial-fidelity)`
- Evidence: host optimization tooling and sysctl snapshot/rollback (`cmd/tools/main.go`, `internal/netutil/tcp_optimize.go`, `scripts/optimize-kernel.sh`).
- Gap: kernel/profile breadth is narrower than upstream scripts.

16. `sources/udp_tun` -> `Partial`
- Evidence: UDP-over-TCP carrier support (`internal/transport/udptcp/udptcp.go`, `internal/transport/stealth/stealth.go`).
- Gap: not full upstream feature parity.

17. `sources/udp2raw` -> `Integrated (partial-fidelity)`
- Evidence: fake_tcp/icmp/raw adapter modes and config surfaces (`internal/transport/faketcp/*`, `internal/transport/icmptun/icmptun.go`, `internal/config/stealth.go`).
- Gap: mature anti-replay/crypto behavior parity should be validated.

18. `sources/gfw_resist_tls_proxy` -> `Integrated (partial-fidelity)`
- Evidence: TLS fragmentation and shaping (`internal/tlsutil/fragment.go`, `internal/tlsutil/sniblend.go`).

19. `sources/gfw_resist_HTTPS_proxy` -> `Integrated (partial-fidelity)`
- Evidence: split-http profile and HTTP camouflage options (`internal/config/stealth.go`, `internal/transport/h2mux/*`, `internal/transport/xhttp/xhttp.go`).
- Gap: profile is productionized on a stable H2-backed core with XHTTP shaping headers; full upstream parity remains out of scope.

20. `sources/gfw_resist_tcp_proxy` -> `Integrated (partial-fidelity)`
- Evidence: raw TCP flag-cycling and packet crafting (`internal/transport/rawtcp/send_handle.go`, `internal/transport/rawtcp/*`).

21. `sources/grasshopper` -> `Partial`
- Evidence: QPP implementation (`internal/crypto/qpp/qpp.go`).
- Gap: no full hop/relay protocol integration.

22. `sources/ocserv` -> `Partial/Low`
- Evidence: RADIUS auth provider support (`internal/authn/authn.go`, `internal/config/extensions.go`).
- Gap: no OpenConnect/AnyConnect protocol server implementation in-core; architectural decision is sidecar bridge integration (`docs/protocol-bridge-decision.md`).

23. `sources/openconnect` -> `Missing`
- Evidence: no in-core openconnect protocol implementation in runtime; integration direction is sidecar bridge (`docs/protocol-bridge-decision.md`).

24. `sources/TrustTunnel` -> `Missing/Low`
- Evidence: no direct in-core TrustTunnel protocol/runtime integration; integration direction is sidecar bridge (`docs/protocol-bridge-decision.md`).

## Critical Risk Findings

1. REALITY path previously had a panic risk and inconsistent framing.
- Fixed in this audit pass:
  - `internal/transport/reality/handshake.go`
  - `internal/transport/reality/reality.go`
  - Added tests in `internal/transport/reality/handshake_test.go`

2. Several feature modules are not yet production-grade despite runtime wiring.
- MASQUE/QUIC advanced behavior and protocol parity still need deeper interop and load testing before being advertised as fully integrated.

3. Test coverage is heavily config/unit oriented, with limited interop/e2e transport validation.
- Current tests do not prove cross-transport reliability under load/loss conditions.

## Consolidation Plan (Prioritized)

### Phase 1: Stabilize exposed features (immediate)

- Keep only production-grade transport profiles enabled by default.
- Gate incomplete paths under explicit experimental flags.
- Add transport interoperability tests for: `kcp`, `shadowtls`, `reality`, `raw` modes, `tlsmirror`.

### Phase 2: Unify runtime transport abstraction

- Enforce one invariant for all active transports:
  - must implement full `Dial -> Session(Open/Accept stream) -> Close` lifecycle.
- Remove dead branches / non-wired modules from primary config docs.
- Add per-transport health metrics and failure reasons.

### Phase 3: Complete requested upstream slices

- Xray XHTTP:
  - extend interop/load coverage and validate behavior against upstream edge cases.
- AmneziaWG 2.0:
  - extend interop/load coverage and validate behavior against upstream edge cases.
- v2rayA redirect/tproxy:
  - extend from command-path e2e tests to privileged kernel-level e2e scenarios for policy/routing edge cases.

### Phase 4: Optional protocol bridges

- ocserv/openconnect and TrustTunnel are major protocol stacks; treat as sidecar bridges, not direct in-core transport code, to avoid destabilizing stealth core (`docs/protocol-bridge-decision.md`).

## Acceptance Criteria for "Unified"

A feature is considered integrated only if all are true:

- Runtime wired through `transport.type=stealth` path.
- Config schema validated and documented.
- Unit tests + at least one e2e test pass.
- Metrics/health visibility present.
- Failure mode is explicit (no panic, no silent downgrade).
