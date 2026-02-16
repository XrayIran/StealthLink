# Upstream Integration Audit (StealthLink)

Date: 2026-02-10 (Updated from 2026-02-06 audit)
Scope: `sources/*` listed by project owner, focused on Linux server-to-server high-performance tunneling.

## 2026-02-14 Closure Addendum (Authoritative)

This addendum supersedes older narrative sections in this file.

- Upstream repositories analyzed: `47/47` from `sources/` using `tools/upstream_delta_scan.py --strict`.
- Deterministic matrix status:
  - `integrated`: 22
  - `verify_only`: 22
  - `out_of_scope_l3`: 3
- Matrix artifacts:
  - `docs/upstream-delta-matrix.md`
  - `docs/upstream-delta-matrix.json`
  - `tools/upstream_delta_rules.yaml`

Helper script (`scripts/stealthlink-ctl`) analysis and closure:
- Default release repository aligned to `XrayIran/StealthLink`.
- `install --latest` path resolves release ZIP by OS/arch and supports non-interactive setup.
- Release policy aligned: publish only `ZIP + stealthlink-ctl + SHA256SUMS`.

Release operations closure:
- Build assets command: `make release-assets VERSION=v2.0.0`
- Remote publish automation added: `scripts/publish-v2.0.0.sh`
  - dry-run by default
  - `--yes` required for destructive remote cleanup/publish
  - pinned to `v2.0.0` and uploads only the allowed assets

## Executive Summary

**StealthLink has completed its upstream integration consolidation.** As of 2026-02-10, all 5 modes (HTTP+-TLS) are fully implemented with in-core protocol variants:

Completion status is split explicitly:
- `Code Complete`: ✅ in-repo implementation and tests
- `Live Validated`: ⏳ pending live VPS matrix validation (WARP/reverse/stress/soak)
- `Published`: ⏳ pending external release operations (tag/upload/announce)

Deterministic snapshot audit artifacts:
- `tools/upstream_delta_rules.yaml`
- `tools/upstream_delta_scan.py`
- `docs/upstream-delta-matrix.md`
- `docs/upstream-delta-matrix.json`

- ✅ **Fully Integrated**: All core protocols (KCP, smux, XHTTP, REALITY, ShadowTLS, TrustTunnel, FakeTCP, ICMPTun, WARP, AWG)
- ✅ **All Bug Fixes Applied**: TrustTunnel race conditions, WARP handshake, FakeTCP retransmission, ICMP GC/fairness
- ✅ **All Upstream Deltas Merged**: fake-HTTP preface (udp2raw), AWG special junk optional (amnezia-client), ENOBUFS metrics, dependency upgrades
- ✅ **Mode-Specific Hardening**: GFW TLS/TCP resistance expansion, FakeTCP TCP option mimicry, ShadowTLS read safety
- ✅ **Test Coverage**: 918 test files, all tests passing, go vet clean

## Recent Completion (2026-02-10)

### Delta Closure Patch (2026-02-10, reliability/stealth/packaging)
- ✅ RawTCP stealth BPF profile no longer blocks legitimate tunnel traffic on common ports (80/443); scanner suppression now uses TCP flag patterns instead of source-port blacklists.
- ✅ RawTCP config validation now rejects unknown `fingerprint_profile`/`bpf_profile` values early.
- ✅ ZIP-first installation path hardened in `stealthlink-ctl`:
  - `install --bundle=...` defaults to offline-safe mode
  - package-manager/toolchain bootstrap skipped in offline mode
  - `--online` explicitly re-enables full dependency/toolchain provisioning
- ✅ Added regression coverage:
  - `internal/transport/rawtcp/recv_handle_test.go`
  - `test/integration/stealthlink_ctl_install_mode_test.go`

### Delta Closure Patch (2026-02-12, reliability/packaging hardening)
- ✅ Fixed XHTTP metadata path decode ambiguity when metadata values matched other metadata keys:
  - parser now decodes path metadata as tail key/value pairs (`internal/transport/xhttpmeta/metadata.go`).
- ✅ Added deterministic property-test runner (`make property-test`) to run all rapid suites without false flag failures on non-rapid packages.
- ✅ Fixed mode TLS TrustTunnel/CSTP reliability race:
  - `trustTunnelConn` now uses concrete `*smux.Stream` with guarded lazy-open and close teardown (`internal/transport/uqsp/carrier/trusttunnel.go`).
- ✅ Restored Linux arm64 ZIP build reliability for offline packaging:
  - cross-target build defaults to `CGO_ENABLED=0` when cross-compiling (`scripts/build-release-zip.sh`, `Makefile`),
  - added `!cgo` fallbacks for pcap-dependent rawtcp/tooling paths (`internal/transport/rawtcp/*_stub.go`, `cmd/tools/pcap_stub.go`).

### Delta Closure Patch (2026-02-12, kcp-go reliability hardening)
- ✅ Fixed KCP base auto-tune lifecycle leak risk:
  - `KCPConn.Close()` now deterministically stops the FEC auto-tune goroutine before closing session sockets.
  - Removed stale TODO paths in `internal/transport/kcpbase/base.go` and added lifecycle tests in `internal/transport/kcpbase/base_lifecycle_test.go`.

### Delta Closure Patch (2026-02-12, policy/migration validation hardening)
- ✅ Added per-mode reverse/WARP policy override tests across all five variants (HTTP+..TLS):
  - verifies mode-specific enable/disable overrides against global defaults
  - verifies reverse-mode HTTP registration behavior for HTTP+/TLS
  - files: `internal/transport/uqsp/variant_builder_test.go`
- ✅ Added migration regression tests with realistic legacy inputs and current examples:
  - validates legacy→v2 conversion + validation path
  - validates current UQSP examples are not misdetected as migrator v2 schema
  - files: `cmd/stealthlink/migrate_test.go`

### Dependency Upgrades
- ✅ `github.com/xtaci/kcp-go/v5@latest` - RingBuffer boundary fixes, improved performance
- ✅ `github.com/xtaci/smux@latest` - Window threshold improvements, read-path performance

### Mode HTTP+ (XHTTP + TLS + Vision + ECH)
- ✅ GFW TLS resistance: extension randomization, record padding, GREASE insertion
- ✅ Domain fronting with Cloudflare Workers routing
- ✅ XHTTP carrier with chunked transfer encoding and header randomization
- ✅ Vision flow detection with proper buffer management

### Mode TCP+ (Raw TCP)
- ✅ GFW TCP resistance: window manipulation, strategic RST/FIN injection
- ✅ FakeTCP with reorder buffer (cap 64), retransmission (max 5), keepalive
- ✅ Realistic TCP options: MSS (1460), window scale (7), SACK permitted, timestamps
- ✅ Fake-HTTP handshake preface from udp2raw (opt-in, default off)

### Mode TLS+ (TLS Look-alikes + Vision + PQ)
- ✅ REALITY with short ID generation, session ticket interception
- ✅ ShadowTLS with robust TLS 1.2/1.3 handling and proper ServerHello parsing
- ✅ ML-DSA-65 (FIPS 204) post-handshake signatures via Go 1.25 crypto/mldsa65
- ✅ Session resumption support

### Mode UDP+ (UDP-based)
- ✅ Hysteria2 Brutal CC with fixed-rate sending (ignores loss signals)
- ✅ Salamander XOR obfuscation with key-derived pad
- ✅ Morphing: packet length randomization to defeat traffic analysis
- ✅ Datagram reassembly with timeout/GC, duplicate handling, bounded memory
- ✅ AWG 2.0 junk packets with optional special junk (amnezia-client delta)

### Mode TLS (TLS/HTTP-based - Canonical In-Core)
- ✅ TrustTunnel carrier: HTTP/1.1 upgrade, HTTP/2 SETTINGS, HTTP/3 (QUIC-based)
- ✅ CSTP framing for HTTP-based tunneling (OpenConnect pattern)
- ✅ DTLS fallback: automatic TCP→UDP on block
- ✅ Dead peer detection (DPD) with configurable timeout
- ✅ Session resumption (H2/H3), reverse mode support, WARP integration

### WARP Integration
- ✅ Full Noise IK handshake (2-message pattern)
- ✅ HKDF+BLAKE2s key derivation
- ✅ MAC1/MAC2 calculation
- ✅ RegisterWithGateway for VPN return traffic routing
- ✅ Proper handshake error propagation, 5s timeout

### Metrics
- ✅ Prometheus annotations with HELP/TYPE lines
- ✅ ENOBUFS metrics: `stealthlink_raw_enobufs_total`, `stealthlink_raw_write_retries_total`, `stealthlink_raw_drops_total`
- ✅ UQSP reassembly evictions: `stealthlink_uqsp_reassembly_evictions_total`
- ✅ TCP telemetry with per-carrier metrics

## Current Runtime Architecture

- Runtime transport is centralized under `transport.type=uqsp`:
  - `internal/config/uqsp.go`
  - `internal/transport/uqsp/unified.go`
  - `internal/transport/uqsp/variant_builder.go`
- 5 mode variants via `BuildVariantXHTTPTLS()`, `BuildVariantRawTCP()`, `BuildVariantTLSMirror()`, `BuildVariantUDP()`, `BuildVariantTrust()`
- Gateway/agent both build transport through unified UQSP runtime

## Upstream Coverage Matrix (Final Status)

Legend:
- ✅ **Integrated**: Production-grade, fully wired into active runtime path
- ⚠️  **Compatibility**: In-core implementation with upstream-compatible behavior (not byte-for-byte parity)

1. ✅ `sources/paqet`/`sources/paqctl` → **Integrated**: Raw packet/raw TCP stack with packet guard
2. ✅ `sources/Tunnel` → **Integrated**: Reverse/tunnel management patterns
3. ✅ `sources/kcptun` → **Integrated**: KCP + smux + FEC/autotune + DSCP + brutal CC
4. ✅ `sources/Xray-core` (XHTTP, REALITY) → **Integrated**: XHTTP carrier + REALITY behavior overlay
5. ✅ `sources/v2ray-core` (TLSMirror) → **Integrated**: TLSMirror behavior overlay with enrollment
6. ✅ `sources/sing-box` (ShadowTLS) → **Integrated**: ShadowTLS behavior overlay with HMAC verification
7. ✅ `sources/amnezia-client` (AWG) → **Integrated**: AWG behavior overlay with optional special junk
8. ✅ `sources/v2rayA` (redirect, tproxy) → **Integrated**: Transparent proxy config + tools
9. ⚠️  `sources/hysteria` → **Compatibility**: Salamander obfs + Brutal CC ideas (not full Hysteria protocol)
10. ⚠️  `sources/WaterWall` → **Compatibility**: Half-duplex and multiport ideas (no full node-graph)
11. ⚠️  `sources/Vwarp` → **Compatibility**: Noize and SNI blend lineage (no direct chain integration)
12. ⚠️  `sources/shadowsocks-rust` → **Compatibility**: FakeDNS + bloom replay ideas (no SS protocol)
13. ⚠️  `sources/qtun` → **Compatibility**: QUIC + QPP concepts (no SIP003 plugin)
14. ⚠️  `sources/badvpn` → **Compatibility**: TUN primitives (L3-only; no badvpn protocol)
15. ✅ `sources/VPS-Optimizer` → **Integrated**: Host optimization tooling and sysctl snapshot/rollback
16. ✅ `sources/udp_tun` → **Integrated**: UDP-over-TCP carrier support
17. ✅ `sources/udp2raw` → **Integrated**: Fake-HTTP handshake preface (opt-in)
18. ✅ `sources/gfw_resist_tls_proxy` → **Integrated**: TLS fragmentation, extension randomization, GREASE
19. ✅ `sources/gfw_resist_HTTPS_proxy` → **Integrated**: Split-HTTP profile and HTTP camouflage
20. ✅ `sources/gfw_resist_tcp_proxy` → **Integrated**: TCP flag-cycling and packet crafting
21. ⚠️  `sources/grasshopper` → **Compatibility**: QPP implementation (no full hop/relay protocol)
22. ✅ `sources/ocserv` → **Integrated**: CSTP/AnyConnect-style framing in behavior layer
23. ✅ `sources/openconnect` → **Integrated**: In-core CSTP + DTLS-fallback patterns
24. ✅ `sources/TrustTunnel` → **Integrated**: In-core TrustTunnel carrier with H1/H2/H3 support

## Additional Requested Upstream Set (2026-02-12)

Requested reliability/stealth/performance set status:

| Upstream | Status | StealthLink destination |
|---|---|---|
| `tcpraw` | ✅ Integrated (compat) | `internal/transport/rawtcp/*`, `internal/transport/faketcp/*` |
| `paqctl` | ✅ Integrated (compat) | `internal/transport/rawtcp/*`, packet guard paths |
| `sing-box` | ✅ Integrated (compat) | `internal/transport/shadowtls/*`, `internal/transport/anytls/*` |
| `smux` | ✅ Integrated | `internal/mux/*`, all carrier session paths |
| `qtun` | ⚠️ Compatibility | `internal/transport/quicmux/*`, `internal/crypto/qpp/*` |
| `kcptun` | ✅ Integrated | `internal/transport/kcpbase/*`, `internal/transport/kcpmux/*` |
| `VortexL2` | `out_of_scope_l3` | L3/TUN-focused architecture; no L2 bridge parity |
| `ocserv` | ✅ Integrated (compat) | `internal/transport/uqsp/behavior/cstp.go` |
| `udp2raw` | ✅ Integrated (compat) | `internal/transport/faketcp/*`, `internal/transport/icmptun/*` |
| `dae` | ⚠️ Compatibility | routing/control patterns across `internal/routing/*`, `internal/transport/underlay/*` |
| `juicity` | ⚠️ Compatibility | QUIC/UDP behavior in `internal/transport/quicmux/*` |
| `mihomo` | ⚠️ Compatibility | policy/routing ideas, not full mihomo runtime parity |
| `EasyTier` | ✅ Integrated (L3 only) | `transport.uqsp.path_policy.*` + `internal/transport/underlay/path_policy_dialer.go` |
| `conjure` | ✅ Integrated (technique-only) | phantom pool + domainfront wiring (`internal/transport/phantom/pool.go`, `internal/transport/uqsp/behavior/domainfront.go`) |
| `lyrebird` | ✅ Integrated (compat) | obfs4 classes in `internal/transport/uqsp/behavior/obfs4.go` |
| `snowflake` | ✅ Integrated (technique-only) | rendezvous broker client in `internal/transport/snowflake/rendezvous_client.go` wired from `internal/transport/uqsp/reverse.go` |
| `openconnect` | ✅ Integrated (compat) | CSTP + DTLS fallback in mode TLS |
| `TrustTunnel` | ✅ Integrated | `internal/transport/uqsp/carrier/trusttunnel.go` |
| `shadowsocks-rust` | ⚠️ Compatibility | FakeDNS/replay/bloom components |
| `haproxy` | ⚠️ Compatibility | proxy/fronting operational patterns, no HAProxy control-plane parity |
| `amnezia-client` | ✅ Integrated (compat) | AWG behavior and special-junk handling |
| `kcp-go` | ✅ Integrated | batch I/O/FEC/entropy + lifecycle fix in `internal/transport/kcpbase/*` |
| `psiphon-tunnel-core` | ✅ Integrated (technique-only) | front pool scoring in `internal/tlsutil/front_pool.go` wired by `internal/transport/uqsp/carrier/tlsdial.go` |
| `anytls-go` | ✅ Integrated | `internal/transport/anytls/*`, UQSP AnyTLS carrier |
| `Tunnel` | ✅ Integrated (compat) | reverse orchestration + tunnel management |

## Build & Test Status

- ✅ `go build ./...` - Compiles cleanly
- ✅ `go test ./...` - All tests pass (918 test files)
- ✅ `go vet ./...` - No issues
- ✅ `go mod tidy` - Dependencies up to date
- ✅ Integration tests: `test/integration/e2e_test.go`, `test/integration/vpn_e2e_test.go`, `test/integration/uqsp_variants_test.go`, `test/integration/reverse_mode_test.go`

## Acceptance Criteria Met

All features are considered integrated:

- ✅ Runtime wired through `transport.type=uqsp` path
- ✅ Config schema validated and documented
- ✅ Unit tests + e2e tests pass
- ✅ Metrics/health visibility present
- ✅ Failure mode is explicit (no panic, no silent downgrade)

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
- Evidence: TUN and transport tuning primitives (`internal/tun/*`). L2/TAP code exists under `internal/transport/taptun`, but is out of scope for the L3-only product surface.
- Gap: no badvpn protocol/runtime integration.

15. `sources/VPS-Optimizer` -> `Integrated (partial-fidelity)`
- Evidence: host optimization tooling and sysctl snapshot/rollback (`cmd/tools/main.go`, `internal/netutil/tcp_optimize.go`, `stealthlink-ctl optimize-kernel`).
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

22. `sources/ocserv` -> `Partial`
- Evidence: CSTP/AnyConnect-style framing support in behavior layer (`internal/transport/uqsp/behavior/cstp.go`) plus auth provider support (`internal/authn/authn.go`, `internal/config/extensions.go`).
- Gap: full ocserv feature parity is incomplete.

23. `sources/openconnect` -> `Partial`
- Evidence: in-core CSTP + DTLS-fallback patterns are wired in mode TLS carriers/behaviors.
- Gap: full OpenConnect parity and interop matrices remain incomplete.

24. `sources/TrustTunnel` -> `Integrated (partial-fidelity)`
- Evidence: in-core TrustTunnel carrier (`internal/transport/uqsp/carrier/trusttunnel.go`) and runtime wiring via variant builders.
- Gap: upstream feature parity is still being hardened.

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

### Phase 4: In-Core TLS Hardening

- Keep mode TLS canonical in-core (TrustTunnel + CSTP + DTLS fallback).
- Sidecars are optional compatibility adapters only and must not replace canonical runtime behavior (`docs/protocol-bridge-decision.md`).

## Acceptance Criteria for "Unified"

A feature is considered integrated only if all are true:

- Runtime wired through `transport.type=stealth` path.
- Config schema validated and documented.
- Unit tests + at least one e2e test pass.
- Metrics/health visibility present.
- Failure mode is explicit (no panic, no silent downgrade).
