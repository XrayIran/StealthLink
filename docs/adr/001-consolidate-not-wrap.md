# ADR 001: Consolidate Upstream Techniques, Don't Wrap Protocols

## Status

Accepted

## Context

StealthLink is integrating techniques from multiple upstream projects (Xray-core, sing-box, kcp-go, udp2raw, smux, Backhaul) to improve performance, security, and anti-detection capabilities. We need to decide on the integration strategy:

**Option A: Protocol Wrapping**
- Maintain wire-format compatibility with upstream projects
- Wrap upstream protocols as-is
- Allow direct interoperability with upstream clients/servers
- Example: StealthLink client ↔ Xray-core server

**Option B: Technique Consolidation**
- Extract best-of-breed techniques from upstream
- Consolidate into five unified StealthLink modes (4a-4e)
- Define StealthLink-native wire formats as canonical
- Provide optional compatibility adapters when needed

## Decision

We choose **Option B: Technique Consolidation** with the following principles:

### 1. Five Canonical Modes (4a-4e)

StealthLink defines five protocol modes as the canonical wire formats:

- **Mode 4a (XHTTP + Domain Fronting)**: HTTP/2 over TLS with flexible metadata placement
- **Mode 4b (FakeTCP + Anti-DPI)**: UDP with TCP mimicry and directional encryption
- **Mode 4c (TLS-Like + REALITY/AnyTLS)**: TLS 1.3 with fingerprint resistance
- **Mode 4d (QUIC + Brutal CC)**: QUIC with fixed bandwidth congestion control
- **Mode 4e (TrustTunnel + CSTP)**: HTTP CONNECT with ICMP multiplexing

Each mode consolidates techniques from multiple upstream projects into a cohesive protocol.

### 2. Upstream Compatibility is Optional

- Compatibility with upstream wire formats is **not** the primary goal
- Optional compatibility adapters can be implemented when interoperability is needed
- Adapters translate between StealthLink modes and upstream protocols
- Configuration flag: `compat_mode: "none" | "xray" | "singbox"`
- Default: `compat_mode: "none"` (StealthLink-native)

### 3. Unified Carrier Interface

All five modes implement a common `Carrier` interface:

```go
type Carrier interface {
    Dial(ctx context.Context, addr string) (Session, error)
    Listen(addr string) (Listener, error)
    Capabilities() CarrierCapabilities
    Configure(config CarrierConfig) error
    Stats() CarrierStats
}
```

This provides:
- Consistent API across all modes
- Explicit capability declaration
- Mode-agnostic application code
- Easy mode switching via configuration

### 4. Capability-Based Design

Each mode declares its capabilities upfront:

```go
type CarrierCapabilities struct {
    StreamOriented   bool  // vs datagram-oriented
    ZeroRTT          bool  // 0-RTT connection establishment
    ReplayProtection bool  // built-in replay protection
    PathMigration    bool  // changing network paths
    Multipath        bool  // multiple concurrent paths
    ServerInitiated  bool  // server can dial out
    Fronting         bool  // domain fronting support
    CoverTraffic     bool  // cover traffic injection
}
```

This allows:
- Runtime capability queries
- Mode selection based on requirements
- Clear documentation of what each mode supports

### 5. Common Frame Format

All modes use a common StealthLink frame format (16-byte header + padding + payload):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Type      |            Flags              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Connection ID                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Stream ID                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Padding Length        |         Payload Length        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Padding (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Payload (variable)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Each mode wraps this frame in mode-specific obfuscation:
- Mode 4a: HTTP/2 DATA frame
- Mode 4b: FakeTCP packet with TCP header
- Mode 4c: TLS Application Data record
- Mode 4d: QUIC STREAM frame
- Mode 4e: HTTP/2 DATA frame with ICMP mux header

## Rationale

### Why Consolidation Over Wrapping?

1. **Avoid Protocol Soup**: Wrapping creates a pile of transport-specific feature branches that are hard to maintain and reason about.

2. **Unified Configuration Surface**: Five modes with clear capability matrices are easier to configure than dozens of upstream protocol combinations.

3. **Optimized Integration**: Consolidation allows us to optimize how techniques work together (e.g., batch I/O + FEC + hardware entropy in mode 4d).

4. **Reduced Complexity**: We don't need to maintain compatibility with every upstream protocol version and quirk.

5. **Clear Semantics**: Each mode has well-defined semantics, capabilities, and use cases.

6. **Future Evolution**: We can evolve StealthLink protocols independently without being constrained by upstream wire formats.

### When to Use Compatibility Adapters?

Compatibility adapters should be implemented **only when**:

1. **Interoperability Required**: Need to connect StealthLink to existing upstream deployments
2. **Migration Path**: Gradual migration from upstream to StealthLink
3. **Testing**: Validate that StealthLink techniques match upstream behavior

Adapters should **not** be the default or primary mode of operation.

## Consequences

### Positive

1. **Cleaner Architecture**: Five well-defined modes instead of protocol soup
2. **Better Performance**: Optimized integration of techniques
3. **Easier Configuration**: Clear mode selection with capability matrices
4. **Independent Evolution**: Not constrained by upstream wire formats
5. **Reduced Maintenance**: Don't need to track every upstream protocol change

### Negative

1. **No Default Interoperability**: StealthLink clients/servers can't directly connect to upstream by default
2. **Adapter Maintenance**: Need to maintain compatibility adapters when interoperability is required
3. **Migration Effort**: Existing upstream deployments need migration or adapters

### Neutral

1. **Documentation Burden**: Need clear documentation of mode capabilities and use cases
2. **Testing Complexity**: Need to test both StealthLink-native and adapter modes

## Implementation

### Phase -1: Core Wire Format & Carrier Capability Model

1. ✅ Define Carrier interface with capability flags
2. ✅ Define 5 mode profiles (4a-4e) as canonical config surface
3. ✅ Add upstream compatibility adapters as optional modules
4. ✅ Update configuration schema to use mode-based profiles
5. ⏳ Definition of Done verification

### Key Files

- `internal/transport/carrier/carrier.go` - Carrier interface
- `internal/transport/carrier/capabilities.go` - Capability flags
- `internal/transport/carrier/config.go` - Configuration structures
- `internal/transport/carrier/frame.go` - Common frame format
- `internal/config/mode_profiles.go` - Mode profile definitions
- `docs/mode-capability-matrix.md` - Capability comparison table

### Configuration Example

```yaml
transport:
  # Mode selection (canonical StealthLink modes)
  mode: "4a"  # 4a | 4b | 4c | 4d | 4e
  
  # Optional: upstream compatibility
  compat_mode: "none"  # none | xray | singbox
  
  # Mode-specific configuration
  mode_4a:
    session_placement: "header"
    xmux_enabled: true
    fronting_enabled: false
```

## References

- [Requirements Document](../../.kiro/specs/upstream-integration-completion/requirements.md)
- [Design Document](../../.kiro/specs/upstream-integration-completion/design.md)
- [Mode Capability Matrix](../mode-capability-matrix.md)
- [Mode Profiles Implementation](../mode-profiles-implementation.md)

## Related Decisions

- ADR 002: Reverse-Init and WARP Underlay (planned)
- ADR 003: Batch I/O Strategy (planned)
- ADR 004: FEC Auto-Tuning Algorithm (planned)

