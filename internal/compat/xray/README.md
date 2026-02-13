# Xray-core Compatibility Adapter

## ⚠️ Important: Adapter Required for Xray-core Interop, Not Default

**This adapter is OPTIONAL and disabled by default.**

### When to Use This Adapter

Use this adapter **ONLY** when you need to:

- Connect StealthLink servers to Xray-core clients
- Connect Xray-core servers to StealthLink clients
- Gradually migrate from Xray-core to StealthLink

### When NOT to Use This Adapter

**DO NOT** use this adapter for:

- StealthLink-to-StealthLink communication (use native modes 4a-4e)
- New deployments without Xray-core legacy requirements
- Maximum performance scenarios (native modes are faster)

## Default Behavior

By default, this adapter is **disabled**:

```yaml
transport:
  # compat_mode: none  # Default - adapter disabled
```

StealthLink's native modes (4a-4e) are the canonical wire formats and provide:
- Better performance (no translation overhead)
- Full feature set (no compatibility constraints)
- Simpler configuration (no adapter complexity)

## Enabling the Adapter

Enable the adapter **only when required** for Xray-core interoperability:

```yaml
transport:
  compat_mode: xray
  xray:
    enabled: true
    mode: xhttp  # SplitHTTP/XHTTP protocol
```

## Supported Protocols

### XHTTP (SplitHTTP)

Compatible with Xray-core v1.8.0+ SplitHTTP transport:

- **Metadata Placement**: Supports path/query/header/cookie placement
- **Connection Lifecycle**: Compatible with Xmux rotation policies
- **Wire Format**: Translates between StealthLink and Xray-core frames

## Compatibility Matrix

| Xray-core Version | Status | Features |
|-------------------|--------|----------|
| v1.8.0+ | ✅ Stable | Full XHTTP/SplitHTTP support |
| v1.7.x | ⚠️ Limited | Header placement only |
| < v1.7 | ❌ Not Supported | - |

## Performance Impact

The adapter adds minimal overhead:

- **Frame Translation**: ~5-10 µs per frame (header translation only)
- **No Additional Encryption**: Security properties preserved
- **No Compression**: Payload preserved as-is

For best performance, use StealthLink's native modes without the adapter.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              StealthLink Application                     │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│         Xray-core Adapter (OPTIONAL - Disabled)         │
│  ┌──────────────────────────────────────────────────┐  │
│  │  Wire Format Translation                         │  │
│  │  - StealthLink frames ↔ Xray-core wire format   │  │
│  │  - Only when compat_mode: xray                  │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│         StealthLink Native Transport (4a-4e)            │
│              (Recommended - Default)                     │
└─────────────────────────────────────────────────────────┘
```

## Testing Compatibility

Test StealthLink ↔ Xray-core interoperability:

```bash
# Test StealthLink client → Xray-core server
go test ./internal/compat/xray -run TestXrayServerCompat

# Test Xray-core client → StealthLink server
go test ./internal/compat/xray -run TestXrayClientCompat
```

## Migration Strategy

### Phase 1: Enable Adapter (Temporary)

Deploy StealthLink servers with adapter enabled:

```yaml
transport:
  compat_mode: xray
  xray:
    enabled: true
    mode: xhttp
```

Keep Xray-core clients unchanged. Verify compatibility.

### Phase 2: Migrate Clients

Deploy StealthLink clients. Test with adapter still enabled.

### Phase 3: Disable Adapter (Recommended)

Once all clients are StealthLink, disable the adapter:

```yaml
transport:
  # compat_mode: none  # Back to default - adapter disabled
```

Enjoy full StealthLink performance and features!

## Implementation Details

### Wire Format Translation

The adapter performs bidirectional translation:

- **Outbound**: StealthLink frames → Xray-core wire format
- **Inbound**: Xray-core wire format → StealthLink frames

### Components

- `Adapter`: Main adapter struct with enable/disable functionality
- `WrapDialer()`: Wraps outbound connections for translation
- `WrapListener()`: Wraps inbound connections for translation
- `xrayConn`: Connection-level translation wrapper

### Configuration Validation

The adapter validates configuration at startup:

- `compat_mode` must be "xray" to enable
- `xray.enabled` must be `true`
- `xray.mode` must be "xhttp" (only supported mode)

## Limitations

- **Feature Parity**: Some StealthLink features may not be available when using the adapter
- **Performance**: Adapter adds overhead compared to native modes
- **Maintenance**: Adapter tracks Xray-core protocol changes
- **Testing**: Compatibility tested against specific Xray-core versions only

## References

- [Xray-core Documentation](https://xtls.github.io/)
- [StealthLink Mode Profiles](../../../docs/mode-profiles-implementation.md)
- [Compatibility Adapters Overview](../README.md)
- [XHTTP Metadata Placement](../../transport/xhttp/)

## Summary

**Remember**: This adapter is **OPTIONAL** and **disabled by default**. Use it **ONLY** when you need Xray-core interoperability. For all other scenarios, use StealthLink's native modes (4a-4e) for best performance and features.
