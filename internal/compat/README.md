# Upstream Compatibility Adapters

## Overview

This directory contains **OPTIONAL** compatibility adapters for upstream projects. These adapters translate between StealthLink's native wire formats (modes 4a-4e) and upstream protocol specifications.

## Important: When to Use Adapters

**Use adapters ONLY when interoperability with upstream clients is required.**

StealthLink's five native modes (4a-4e) are the canonical wire formats and provide the best performance, security, and feature set. Adapters are provided solely for interoperability scenarios where you need to:

- Connect StealthLink servers to upstream clients (Xray-core, sing-box)
- Connect upstream servers to StealthLink clients
- Gradually migrate from upstream solutions to StealthLink

## Available Adapters

### Xray-core Adapter (`internal/compat/xray/`)

Provides wire format compatibility with Xray-core's protocols:

- **XHTTP (SplitHTTP)**: Compatible with Xray-core v1.8.0+
- **Metadata Placement**: Supports path/query/header/cookie placement
- **Connection Lifecycle**: Compatible with Xmux rotation policies

**Compatibility**: Xray-core v1.8.0+

### sing-box Adapter (`internal/compat/singbox/`)

Provides wire format compatibility with sing-box's protocols:

- **AnyTLS**: Compatible with sing-box v1.8.0+
- **Padding Schemes**: Preserves upstream padding_scheme line arrays
- **Multiplexing**: Translates between smux and sing-box mux protocol

**Compatibility**: sing-box v1.8.0+

## Configuration

Adapters are disabled by default. Enable them via the `compat_mode` configuration flag:

```yaml
transport:
  # Compatibility mode: "none" (default) | "xray" | "singbox"
  compat_mode: none
  
  # Xray-core adapter configuration (only used when compat_mode: xray)
  xray:
    enabled: false
    mode: xhttp  # Protocol mode: "xhttp"
  
  # sing-box adapter configuration (only used when compat_mode: singbox)
  singbox:
    enabled: false
    mode: anytls  # Protocol mode: "anytls"
```

### Example: Xray-core Compatibility

```yaml
transport:
  compat_mode: xray
  xray:
    enabled: true
    mode: xhttp
```

### Example: sing-box Compatibility

```yaml
transport:
  compat_mode: singbox
  singbox:
    enabled: true
    mode: anytls
```

## Performance Impact

Adapters add minimal overhead:

- **Frame Translation**: ~5-10 µs per frame (header translation only)
- **No Additional Encryption**: Adapters do not modify security properties
- **No Compression**: Adapters preserve payload as-is
- **Mux Translation**: sing-box adapter adds ~20-30 µs for mux frame translation

For best performance, use StealthLink's native modes without adapters.

## Architecture

Adapters work by wrapping dialers and listeners:

```
┌─────────────────────────────────────────────────────────┐
│                  StealthLink Application                 │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│              Compatibility Adapter (Optional)            │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Wire Format Translation                         │  │
│  │  - StealthLink frames ↔ Upstream wire format    │  │
│  │  - Minimal overhead (header translation only)   │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│              StealthLink Native Transport                │
│                    (Modes 4a-4e)                         │
└─────────────────────────────────────────────────────────┘
```

## Testing Compatibility

Each adapter includes compatibility tests:

### Xray-core Compatibility Tests

```bash
# Test StealthLink client → Xray-core server
go test ./internal/compat/xray -run TestXrayServerCompat

# Test Xray-core client → StealthLink server
go test ./internal/compat/xray -run TestXrayClientCompat
```

### sing-box Compatibility Tests

```bash
# Test StealthLink client → sing-box server
go test ./internal/compat/singbox -run TestSingboxServerCompat

# Test sing-box client → StealthLink server
go test ./internal/compat/singbox -run TestSingboxClientCompat

# Test mux behavior parity
go test ./internal/compat/singbox -run TestMuxParity
```

## Migration Strategy

When migrating from upstream solutions to StealthLink:

1. **Phase 1**: Enable adapter for gradual migration
   - Deploy StealthLink servers with adapter enabled
   - Keep upstream clients unchanged
   - Verify compatibility and performance

2. **Phase 2**: Migrate clients to StealthLink
   - Deploy StealthLink clients
   - Disable adapter on servers
   - Use native modes (4a-4e) for best performance

3. **Phase 3**: Remove adapter configuration
   - Remove `compat_mode` from configuration
   - Enjoy full StealthLink feature set

## Limitations

Adapters have the following limitations:

- **Feature Parity**: Some StealthLink features may not be available when using adapters
- **Performance**: Adapters add overhead compared to native modes
- **Maintenance**: Adapters track upstream protocol changes and may lag behind
- **Testing**: Compatibility is tested against specific upstream versions only

## Support Matrix

| Adapter | Upstream Version | Status | Notes |
|---------|-----------------|--------|-------|
| xray | v1.8.0+ | Stable | Full XHTTP/SplitHTTP support |
| xray | v1.7.x | Limited | Header placement only |
| xray | < v1.7 | Not Supported | - |
| singbox | v1.8.0+ | Stable | Full AnyTLS + mux support |
| singbox | v1.7.x | Limited | Basic TLS only |
| singbox | < v1.7 | Not Supported | - |

## Contributing

When adding new adapters:

1. Create package under `internal/compat/<upstream>/`
2. Implement `Adapter` interface with `WrapDialer` and `WrapListener`
3. Add comprehensive documentation in `doc.go`
4. Include compatibility tests with upstream versions
5. Update this README with support matrix entry

## References

- [Xray-core Documentation](https://xtls.github.io/)
- [sing-box Documentation](https://sing-box.sagernet.org/)
- [StealthLink Mode Profiles](../../docs/mode-profiles-implementation.md)
- [StealthLink Carrier Interface](../transport/carrier/carrier.go)
