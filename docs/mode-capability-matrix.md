# StealthLink Mode Capability Matrix

This document provides a comprehensive comparison of capabilities across all five StealthLink modes (4a-4e).

## Mode Overview

| Mode | Name | Description | Primary Use Case |
|------|------|-------------|------------------|
| 4a | XHTTP + Domain Fronting | HTTP/2 over TLS with flexible metadata placement | CDN-friendly, domain fronting scenarios |
| 4b | FakeTCP + Anti-DPI | UDP with TCP mimicry and directional encryption | Deep packet inspection evasion |
| 4c | TLS-Like + REALITY/AnyTLS | TLS 1.3 with fingerprint resistance | TLS proxy detection evasion |
| 4d | QUIC + Brutal CC | QUIC with fixed bandwidth congestion control | High-throughput, lossy networks |
| 4e | TrustTunnel + CSTP | HTTP CONNECT with ICMP multiplexing | Corporate proxy traversal |

## Capability Matrix

| Capability | 4a | 4b | 4c | 4d | 4e | Description |
|------------|----|----|----|----|----|----|
| **StreamOriented** | ✅ | ❌ | ✅ | ✅ | ✅ | Provides reliable stream semantics vs datagram |
| **ZeroRTT** | ✅ | ❌ | ✅ | ✅ | ✅ | Supports 0-RTT connection establishment |
| **ReplayProtection** | ❌ | ✅ | ❌ | ✅ | ❌ | Built-in replay attack protection |
| **PathMigration** | ❌ | ❌ | ❌ | ✅ | ❌ | Can change network paths without reconnection |
| **Multipath** | ❌ | ❌ | ❌ | ✅ | ❌ | Supports multiple concurrent network paths |
| **ServerInitiated** | ✅ | ✅ | ✅ | ✅ | ✅ | Server can dial out (reverse-init) |
| **Fronting** | ✅ | ❌ | ❌ | ❌ | ❌ | Supports domain fronting via CDN |
| **CoverTraffic** | ❌ | ❌ | ✅ | ✅ | ❌ | Can inject cover/padding traffic |

## Transport Characteristics

| Characteristic | 4a | 4b | 4c | 4d | 4e |
|----------------|----|----|----|----|----| 
| **Protocol** | HTTP/2 | UDP | TLS 1.3 | QUIC | HTTP/2 or HTTP/3 |
| **Handshake** | TLS 1.3 | Fake TCP 3-way | REALITY/AnyTLS | QUIC 0-RTT | HTTP CONNECT + CSTP |
| **Congestion Control** | TCP Cubic | None | TCP Cubic | Brutal (fixed BW) | TCP Cubic or QUIC |
| **Reliability** | TCP | FakeTCP | TCP | QUIC | TCP or QUIC |
| **Multiplexing** | Smux | Smux | Smux | QUIC Streams | TrustTunnel ICMP |
| **Default MTU** | 1400 | 1460 | 1400 | 1450 | 1380 |

## Obfuscation Techniques

### Mode 4a (XHTTP + Domain Fronting)
- Domain fronting via CDN
- Flexible metadata placement (path/query/header/cookie)
- Xmux connection rotation
- HTTP/2 framing

### Mode 4b (FakeTCP + Anti-DPI)
- TCP fingerprint mimicry
- Fake HTTP preface
- Directional HKDF key derivation
- AEAD encryption (ChaCha20-Poly1305 or AES-GCM)
- Batch I/O for performance

### Mode 4c (TLS-Like + REALITY/AnyTLS)
- REALITY spider (concurrent web crawling)
- AnyTLS padding schemes
- TLS fingerprint variation
- Connection rotation

### Mode 4d (QUIC + Brutal CC)
- AWG junk packets
- Brutal congestion control (fixed bandwidth)
- FEC with auto-tune and parity skip
- Hardware-accelerated entropy (AES-NI/ChaCha8)
- Batch I/O for performance
- Connection migration

### Mode 4e (TrustTunnel + CSTP)
- ICMP multiplexing over HTTP
- HTTP CONNECT tunneling
- Session recovery with exponential backoff
- CSTP protocol

## Performance Characteristics

| Metric | 4a | 4b | 4c | 4d | 4e |
|--------|----|----|----|----|----| 
| **Throughput** | High | Very High | High | Very High | Medium |
| **Latency** | Low | Low | Low | Low | Medium |
| **CPU Usage** | Medium | Low | Medium | Low | Medium |
| **Detectability** | Low | Very Low | Very Low | Low | Low |
| **CDN Compatibility** | Excellent | Poor | Poor | Poor | Good |

## Use Case Recommendations

### Mode 4a (XHTTP + Domain Fronting)
**Best for:**
- Scenarios requiring CDN compatibility
- Domain fronting through major CDN providers
- HTTP/2-friendly networks
- Low-latency requirements

**Avoid when:**
- CDN is not available or desired
- UDP-based transport is preferred
- Maximum throughput is critical

### Mode 4b (FakeTCP + Anti-DPI)
**Best for:**
- Deep packet inspection evasion
- Networks that block or throttle UDP
- Maximum throughput requirements
- Scenarios requiring AEAD encryption

**Avoid when:**
- Stream-oriented semantics are required
- Network has strict TCP validation
- 0-RTT is critical

### Mode 4c (TLS-Like + REALITY/AnyTLS)
**Best for:**
- TLS proxy detection evasion
- Fingerprint resistance
- Networks with TLS inspection
- Cover traffic requirements

**Avoid when:**
- Connection establishment speed is critical (spider adds latency)
- Minimal CPU usage is required
- Padding overhead is unacceptable

### Mode 4d (QUIC + Brutal CC)
**Best for:**
- High-throughput scenarios
- Lossy networks (FEC helps)
- Path migration requirements
- Multipath scenarios

**Avoid when:**
- QUIC is blocked or throttled
- Fixed bandwidth is not suitable
- Minimal detectability is critical

### Mode 4e (TrustTunnel + CSTP)
**Best for:**
- Corporate proxy traversal
- HTTP CONNECT-based scenarios
- ICMP multiplexing requirements
- Session recovery needs

**Avoid when:**
- Maximum throughput is required
- HTTP CONNECT is blocked
- Low latency is critical

## Configuration Examples

See the following files for complete configuration examples:
- `examples/uqsp-mode-4a.yaml` - Mode 4a configuration
- `examples/uqsp-mode-4b.yaml` - Mode 4b configuration
- `examples/uqsp-mode-4c.yaml` - Mode 4c configuration
- `examples/uqsp-mode-4d.yaml` - Mode 4d configuration
- `examples/uqsp-mode-4e.yaml` - Mode 4e configuration

## Mode Selection Decision Tree

```
Start
  |
  ├─ Need CDN/Domain Fronting? ──YES──> Mode 4a
  |                              
  ├─ Need DPI Evasion? ──YES──> Mode 4b
  |
  ├─ Need TLS Fingerprint Resistance? ──YES──> Mode 4c
  |
  ├─ Need High Throughput + Path Migration? ──YES──> Mode 4d
  |
  └─ Need Corporate Proxy Traversal? ──YES──> Mode 4e
```

## Compatibility Notes

### Upstream Compatibility
StealthLink modes are **not** wire-compatible with upstream projects by default. Optional compatibility adapters are available:

- **Mode 4a**: Compatible with Xray-core SplitHTTP via adapter (≥ v1.8.0)
- **Mode 4c**: Compatible with sing-box AnyTLS via adapter (≥ v1.8.0)
- **Other modes**: StealthLink-specific, no upstream compatibility

To enable upstream compatibility, use the `compat_mode` configuration option:
```yaml
transport:
  compat_mode: "xray"  # "none" | "xray" | "singbox"
```

### Reverse-Init Support
All 5 modes support reverse-init (server dials out to client):
```yaml
transport:
  role: rendezvous  # client listens, server dials
```

### WARP Underlay Support
All 5 modes can use Cloudflare WARP as transport underlay:
```yaml
transport:
  dialer: warp
  warp:
    mode: consumer  # "consumer" | "zero-trust" | "connector"
```

## Future Enhancements

Planned enhancements for future releases:
- Mode 4a: ECH (Encrypted Client Hello) support
- Mode 4b: Additional TCP fingerprints (Windows, macOS)
- Mode 4c: Additional AnyTLS padding schemes
- Mode 4d: Multipath QUIC support
- Mode 4e: HTTP/3 CONNECT support

## References

- [Design Document](../design.md)
- [Requirements Document](../requirements.md)
- [Carrier Interface Specification](../internal/transport/carrier/)
- [Configuration Schema](../internal/config/)
