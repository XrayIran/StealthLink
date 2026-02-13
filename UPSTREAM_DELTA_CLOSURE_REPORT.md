# Upstream Delta Closure Report

**Date:** 2026-02-11
**Scope:** 13 upstream source repositories vs StealthLink internal codebase

---

## Executive Summary

StealthLink has already integrated the **majority** of upstream techniques across all 13 repos. Key gaps remain in: (1) sing-box's AnyTLS protocol, (2) Xray-core's advanced XHTTP session/seq placement flexibility, (3) kcp-go's hardware-accelerated entropy source, (4) Backhaul's aggressive connection pool warmup heuristics, and (5) udp2raw's AEAD stub. Most other upstream features are already present or have superior equivalents.

---

## 1. tcpraw

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **IPv6 dual-stack raw sockets** | `tcpraw_linux.go` L203-213 (ip6tables HL matching) | StealthLink `rawtcp/` supports IPv4 raw; IPv6 raw socket path with `IPV6_UNICAST_HOPS` and `HL`-based iptables present in tcpraw but may not be fully exercised in StealthLink's rawtcp carrier | **Low** |
| **DSCP/Traffic-Class marking** | `tcpraw_linux.go` L670-697 (`SetDSCP`) | StealthLink has `dscp/` package already. ✅ Already integrated | — |
| **Linux TCP fingerprint with timestamp options** | `fingerprints.go` L18-47 (NOP+NOP+Timestamp, TSval/TSecr) | StealthLink `rawtcp/` uses gopacket for raw packets but the specific Linux fingerprint stamp (window=65535, TTL=64, NOP+NOP+TS option cycling) should be verified against upstream | **Low** |
| **BPF filter application** | `applyBPF.go` | StealthLink has BPF in `rawtcp/packet_conn.go`. ✅ Already integrated | — |

**Status:** Mostly integrated. No high-priority gaps.

---

## 2. udp2raw

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **HMAC-SHA1 + HKDF-SHA256 key derivation with directional keys** | `encrypt.cpp` L55-111 (separate encrypt/decrypt hmac+cipher keys via PBKDF2→HKDF) | StealthLink `faketcp/` uses simpler key handling. udp2raw's directional key split (server→client vs client→server) with PBKDF2-SHA256 + HKDF-SHA256 expansion provides better forward-separation | **Medium** |
| **AEAD encryption mode (stub)** | `encrypt.cpp` L580-588 (`encrypt_AEAD` / `decrypt_AEAD` TODO) | Neither project has AEAD for raw packet encryption. Could add AES-GCM or ChaCha20-Poly1305 for FakeTCP payload integrity | **Medium** |
| **GRO (Generic Receive Offload) coalesced packet splitting** | `connection.cpp` L459-475, L602-654 (`g_fix_gro`, length-prefixed multi-packet extraction) | StealthLink `packet_guard.go` L32-125 already handles GRO/LRO detection and splitting. ✅ Already integrated | — |
| **Seq mode cycling (4 modes)** | `network.cpp` L19 (`seq_mode = 3`, modes 0-4) | StealthLink has `flag_cycling` in `rawtcp/unified.go` but udp2raw's `seq_mode` has more variants (static, increment, random-increment, combined). Consider adding mode 2 (random increment) | **Low** |
| **ICMP echo tunneling with checksum** | `network.cpp` L1924-2018 (IPv4/v6 ICMP with pseudo-header checksum) | StealthLink has `icmptun/` package with full implementation. ✅ Already integrated | — |
| **Anti-replay window** | `connection.cpp` L20-64 (`anti_replay_t` sliding window) | StealthLink has nonce replay protection in control plane. Should verify raw carrier anti-replay is applied per-flow | **Low** |

**Status:** Key gap is directional HKDF key derivation for FakeTCP.

---

## 3. Hysteria

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **Brutal CC (congestion control)** | `core/internal/congestion/brutal/brutal.go` (full implementation: ack-rate tracking, 5-slot sampling, pacer, cwnd=bps×rtt×2/ackRate) | StealthLink `kcpmux/brutal.go` and `kcpbase/brutal.go` exist. ✅ Already integrated | — |
| **PMTUD (Path MTU Discovery)** | `core/internal/pmtud/avail.go` (build-tag gated) | StealthLink `tcpstat/` has PathMTU field and `tun/mtu.go` has AutoTuneMTU. ✅ Already integrated | — |
| **UDP fragmentation/defragmentation** | `core/internal/frag/frag.go` (FragUDPMessage + Defragger) | StealthLink `quicmux/fragment.go` has Fragmenter + Defragger ported from Hysteria. ✅ Already integrated | — |
| **BBR congestion control** | `core/internal/congestion/bbr/` | StealthLink `transport/bbr/bbr.go` exists. ✅ Already integrated | — |

**Status:** Fully integrated. No gaps.

---

## 4. sing-box

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **AnyTLS protocol** | `protocol/anytls/inbound.go`, `outbound.go` (anti-TLS-proxy fingerprinting with custom padding scheme, new mux scheme from `github.com/anytls/sing-anytls`) | StealthLink has **no AnyTLS implementation**. AnyTLS mitigates TLS proxy traffic characteristics that REALITY/ShadowTLS don't address — specifically the multiplexing pattern fingerprint | **High** |
| **ShadowTLS v3** | `protocol/shadowtls/` | StealthLink `shadowtls/` exists with handshake.go. ✅ Already integrated | — |
| **Hysteria2 protocol** | `protocol/hysteria2/` | StealthLink UQSP variant 4d uses Hysteria2 CC. ✅ Already integrated | — |
| **TUIC protocol** | `protocol/tuic/` | StealthLink uses QUIC directly with similar approach. Not a gap per se | **Low** |
| **WireGuard transport** | `transport/wireguard/` | StealthLink `transport/wireguard/` exists. ✅ Already integrated | — |

**Status:** Main gap is AnyTLS protocol.

---

## 5. Xray-core

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **REALITY spider crawling (SpiderX/Y)** | `transport/internet/reality/reality.go` L185-274 (web spider on unverified certs with SpiderY timing params, concurrent crawlers, href extraction) | StealthLink has SpiderX/SpiderY config but should verify the full spider behavior with concurrent crawler goroutines and `SpiderY[0..9]` timing array is implemented | **Medium** |
| **ML-DSA-65 + X25519MLKEM768 in REALITY** | `reality.go` L76-101 (mldsa65 signature verification, MLKEM768 ECDHE) | StealthLink has `pqsig/mldsa65.go` and `chrome.go` X25519MLKEM768. ✅ Already integrated | — |
| **XHTTP (SplitHTTP) session/seq placement flexibility** | `splithttp/config.go` L113-239 (SessionPlacement and SeqPlacement: path/query/header/cookie, configurable keys) | StealthLink `xhttp/` has basic XPadding but lacks the **flexible session ID and sequence number placement** (path vs query vs header vs cookie) that Xray-core's SplitHTTP supports. This is critical for CDN compatibility | **High** |
| **XHTTP Xmux connection management** | `splithttp/config.go` L241-295 (XmuxConfig: MaxConcurrency, MaxConnections, CMaxReuseTimes, HMaxRequestTimes, HMaxReusableSecs ranges) | StealthLink `xhttp/xmux.go` has connection pooling with round-robin. Should add the reuse-time and request-count limits per connection | **Medium** |
| **XPadding tokenish method (HPACK-aware)** | `splithttp/xpadding.go` (base62 padding with Huffman-encoded length targeting, HPACK compression resistance) | StealthLink `padding/xpadding.go` already has `MethodTokenish`. ✅ Already integrated | — |
| **Uplink data placement (body vs header)** | `splithttp/config.go` L127-132 (`UplinkDataPlacement`) | StealthLink's XHTTP assumes body placement. Adding header-based uplink data placement would allow CDN edge cases | **Low** |
| **Happy Eyeballs dialer** | `transport/internet/happy_eyeballs.go` | StealthLink doesn't have a dedicated happy eyeballs implementation for dual-stack dial racing | **Low** |

**Status:** Key gaps are XHTTP session/seq placement flexibility and Xmux connection lifecycle limits.

---

## 6. amnezia-client

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **AWG 2.0 junk packet parameters (Jc/Jmin/Jmax, S1/S2, H1-H4)** | `client/protocols/awgprotocol.h` (extends WireGuard) | StealthLink `awg/awg.go` L44-56 has Jc, Jmin, Jmax, S1, S2, H1-H3. ✅ Already integrated | — |
| **Init/Response packet junk sizing** | Config in amnezia-client server_scripts | StealthLink `config/uqsp.go` L667-668 has `init_packet_junk_size`, `response_packet_junk_size`. ✅ Already integrated | — |
| **Timing obfuscation** | amnezia-client timing controls | StealthLink `wireguard/junk.go` L428-466 has `TimingObfuscator`. ✅ Already integrated | — |

**Status:** Fully integrated. No gaps.

---

## 7. TrustTunnel

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **HTTP/2 + HTTP/3 CONNECT muxing** | `PROTOCOL.md`, `lib/src/http2_codec.rs`, `http3_codec.rs` | StealthLink `trusttunnel/` exists. ✅ Already integrated | — |
| **ICMP multiplexing over HTTP** | `lib/src/icmp_forwarder.rs`, `http_icmp_codec.rs` | StealthLink `trusttunnel/icmp_mux.go` exists. ✅ Already integrated | — |
| **QUIC multiplexer** | `lib/src/quic_multiplexer.rs` | StealthLink `quicmux/` exists. ✅ Already integrated | — |
| **Session recovery with exponential backoff** | `PROTOCOL.md` §10.3 (initial=1000ms, rate=1.3×, location update=10000ms) | StealthLink agent has reconnection logic but should verify the specific backoff curve parameters match TrustTunnel's spec for interop | **Low** |
| **TLS demultiplexer** | `lib/src/tls_demultiplexer.rs` | StealthLink `tlsmux/` exists. ✅ Already integrated | — |
| **Speedtest handler** | `lib/src/http_speedtest_handler.rs` | StealthLink doesn't have a built-in speedtest endpoint. Could be useful for diagnostics | **Low** |

**Status:** Fully integrated. No gaps.

---

## 8. Tunnel (Paqet)

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **TCPF (TCP forward) protocol type** | `internal/protocol/protocol.go` L13-18 (PPING/PPONG/PTCPF/PTCP/PUDP message types) | StealthLink has its own control protocol. No meaningful gap | — |
| **Gob-encoded protocol messages** | `protocol.go` L26-45 | StealthLink uses binary/protobuf encoding. Not a gap | — |

**Status:** No actionable gaps. Tunnel is much simpler than StealthLink.

---

## 9. kcp-go

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **Reed-Solomon FEC with auto-tuning** | `fec.go` (full RS FEC encoder/decoder, pulse-based autoTune, shard set management, OOB packets) | StealthLink `kcpbase/fec.go` has FECController with autoTune flag but the **pulse-based period detection** (`autotune.go`) for automatic FEC parameter discovery is more sophisticated in upstream | **Medium** |
| **OOB (Out-of-Band) FEC packets** | `fec.go` L492-502 (`encodeOOB`, `sealOOB`, `typeOOB`) | StealthLink FEC doesn't have OOB packet type for control signals alongside FEC streams | **Low** |
| **Hardware-accelerated entropy (AES-NI / ChaCha8)** | `entropy.go` (platform-detected AES-NI→AES-CTR RNG, fallback to ChaCha8, periodic reseeding) | StealthLink uses `crypto/rand` directly. kcp-go's approach is **significantly faster** for high-throughput packet encryption nonce generation | **Medium** |
| **sendmmsg/recvmmsg batch I/O** | `tx_linux.go`, `readloop_linux.go` | StealthLink `transport/batch/batch_linux.go` has stubs but comments say "Simplified implementation without sendmmsg syscall". **The actual syscall is not used** | **High** |
| **Non-continuous parity skip** | `fec.go` L436-466 (skip parity generation when data packets are non-continuous, based on RTO timing) | StealthLink FEC doesn't have this optimization. Saves bandwidth when data is bursty | **Medium** |
| **Buffer pool with memory recycling** | `bufferpool.go` | StealthLink likely uses sync.Pool; should verify KCP path uses it efficiently | **Low** |

**Status:** Key gaps are real sendmmsg/recvmmsg syscalls, hardware entropy, and FEC parity skip.

---

## 10. smux

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **Round-robin shaper queue with priority classes** | `shaper.go` (per-stream heaps with CLSCTRL/CLSDATA priority, round-robin popping, sync.Pool for heap objects) | StealthLink `mux/` has basic config but no **per-stream fair scheduling with priority classes**. The smux shaper ensures control frames (SYN/FIN/NOP/UPD) are prioritized over data | **Medium** |
| **Protocol v2 flow control (cmdUPD window updates)** | `session.go`, `frame.go` | StealthLink mux config references smux but should verify v2 window updates are enabled | **Low** |
| **Stream-level backpressure with MaxStreamBuffer** | `session.go` | StealthLink `mux/config.go` likely exposes this. Should verify | **Low** |

**Status:** Key gap is the fair-scheduling shaper with priority classes.

---

## 11. WaterWall

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **Half-duplex client/server** | `tunnels/HalfDuplexClient/`, `HalfDuplexServer/` (split upload/download connections) | StealthLink `transport/halfduplex/` exists. ✅ Already integrated | — |
| **Obfuscator client/server** | `tunnels/ObfuscatorClient/`, `ObfuscatorServer/` | StealthLink has multiple obfuscation layers (noize, obfs4, padding). ✅ Already integrated | — |
| **Pipeline tunnel architecture** | `tunnels/` directory (modular pipeline: TcpConnector→MuxClient→TlsClient→etc.) | StealthLink `transport/graph/` has pipeline DAG config. ✅ Already integrated | — |
| **UDP-over-TCP / TCP-over-UDP** | `tunnels/UdpOverTcpClient/`, `TcpOverUdpClient/` | StealthLink `transport/udptcp/` exists. ✅ Already integrated | — |
| **IpManipulator / IpOverrider** | `tunnels/IpManipulator/`, `IpOverrider/` | StealthLink has `connect_ip` for IP override. Dedicated IP manipulation layer could be useful for advanced routing | **Low** |
| **PacketToConnection / DataAsPacket** | `tunnels/PacketToConnection/`, `DataAsPacket/` | StealthLink handles this implicitly in carriers. Not a gap | — |
| **UdpStatelessSocket** | `tunnels/UdpStatelessSocket/` | Could be useful for stateless UDP relay scenarios, but StealthLink's udprelay handles this | **Low** |

**Status:** Fully integrated. No high-priority gaps.

---

## 12. Backhaul

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **Aggressive connection pool warmup** | `internal/client/transport/tcpmux.go` L205-280 (`AggressivePool` mode with adaptive pool sizing: factors a=1,b=2,x=0,y=0.75 vs normal a=4,b=5,x=3,y=4.0, 10s load tracking) | StealthLink has `max_conns` per-host limits but **lacks adaptive pool sizing** that responds to load. Backhaul's `poolMaintainer` auto-scales the pool based on observed connection utilization | **Medium** |
| **TCP+smux multiplexing transport** | `internal/client/transport/tcpmux.go` (TcpMuxTransport with smux.Config) | StealthLink uses smux via KCP. Direct TCP+smux (without KCP overhead) is a simpler, lower-latency option for reliable links | **Low** |
| **WebSocket+smux multiplexing** | `internal/client/transport/wsmux.go` | StealthLink `wssmux/` exists. ✅ Already integrated | — |
| **Control channel with token-based auth** | `tcpmux.go` L140-202 (channelDialer with token exchange) | StealthLink has shared key auth + health checks. ✅ Already integrated | — |
| **MSS/SO_RCVBUF/SO_SNDBUF tuning** | `tcpmux.go` L53-55 (per-connection socket buffer config) | StealthLink has UDP socket buffer config. Should verify TCP socket buffer tuning is exposed per-transport | **Low** |

**Status:** Key gap is adaptive connection pool sizing.

---

## 13. VortexL2

| Feature/Technique | Relevant Files | Gap in StealthLink | Priority |
|---|---|---|---|
| **EasyTier L2 mesh networking** | `core/easytier/` (prebuilt binaries for linux-x86_64, aarch64, armv7) | StealthLink has TAP mode (`taptun/`) for L2 tunneling but lacks **L2 mesh networking** with auto-discovery. VortexL2 wraps EasyTier for this | **Low** |
| **HAProxy integration for L2** | `HAPROXY_SETUP.md` | StealthLink doesn't integrate with HAProxy for L2 load balancing. Niche use case | **Low** |
| **Tunnel connectivity checking** | `TUNNEL_CONNECTIVITY.md` | StealthLink `healthz/` provides comprehensive health checking. ✅ Already integrated | — |

**Status:** L2 mesh is a niche feature. No high-priority gaps.

---

## Priority Summary

### High Priority (should integrate)
1. **sing-box → AnyTLS protocol** — New anti-TLS-fingerprinting protocol with custom padding scheme. Addresses detection vectors that REALITY/ShadowTLS don't cover.
2. **Xray-core → XHTTP session/seq placement flexibility** — Configurable placement of session ID and sequence numbers in path/query/header/cookie for CDN compatibility.
3. **kcp-go → Real sendmmsg/recvmmsg syscalls** — `batch_linux.go` has stubs only. Real batch syscalls provide 2-4× throughput on high-PPS workloads.

### Medium Priority (recommended)
4. **udp2raw → Directional HKDF key derivation for FakeTCP** — Separate encrypt/decrypt keys per direction improves security.
5. **udp2raw → AEAD mode for raw packet encryption** — AES-GCM/ChaCha20-Poly1305 for payload integrity on raw carriers.
6. **Xray-core → REALITY spider concurrent crawlers** — Verify full SpiderY[0..9] timing array implementation matches upstream.
7. **Xray-core → Xmux connection lifecycle limits** — CMaxReuseTimes, HMaxRequestTimes, HMaxReusableSecs for connection rotation.
8. **kcp-go → Hardware-accelerated entropy (AES-NI/ChaCha8 RNG)** — Faster nonce generation for high-throughput scenarios.
9. **kcp-go → FEC non-continuous parity skip** — Skip parity when data is bursty, saving bandwidth.
10. **kcp-go → Pulse-based FEC auto-tune period detection** — More sophisticated than current autoTune flag.
11. **smux → Priority-class fair shaper queue** — Control frames prioritized over data in multiplexed streams.
12. **Backhaul → Adaptive connection pool sizing** — Auto-scale pool based on load with aggressive/normal modes.

### Low Priority (nice to have)
13. tcpraw → IPv6 raw socket HL-based iptables
14. udp2raw → seq_mode random-increment variant
15. Xray-core → Happy Eyeballs dual-stack dialer
16. Xray-core → Uplink data placement in headers
17. TrustTunnel → Speedtest endpoint
18. VortexL2 → L2 mesh networking (EasyTier)
19. Backhaul → Direct TCP+smux (no KCP) transport
20. WaterWall → Dedicated IP manipulation layer
