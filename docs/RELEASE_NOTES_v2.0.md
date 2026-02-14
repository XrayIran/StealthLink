# StealthLink v2.0 Release Notes

**Release Date:** 2026-02-12
**Version:** 2.0.0
**Codename:** Unified Superset

## Summary

StealthLink v2.0 is a major release that consolidates best-of-breed techniques from 12 upstream projects into five unified operational modes (4a-4e). This release delivers significant performance improvements, enhanced security, and improved anti-detection capabilities.

## Major Features

### Phase 1: Batch I/O (Mode 4b/4d Foundation)
- **Linux batch syscalls** (`sendmmsg`/`recvmmsg`) for UDP packet transmission
- Achieves **2-4× throughput improvement** at >10,000 packets/second
- Automatic fallback to single-packet I/O on non-Linux systems or syscall failures
- Configurable batch size (1-64, default: 32)

### Phase 2: XHTTP Metadata Placement (Mode 4a)
- **Flexible placement** of session IDs and sequence numbers in HTTP requests
- Supports `path`, `query`, `header`, and `cookie` placement types
- Enables optimization for different CDN providers
- Custom key names for encoded values

### Phase 3: Xmux Connection Lifecycle (Mode 4a)
- **Connection rotation limits** for anti-fingerprinting
- Configurable reuse limits, request limits, and connection age limits
- Graceful drain with configurable timeout
- Rotation metrics for monitoring

### Phase 4: FakeTCP Directional Keys & AEAD (Mode 4b Security)
- **Directional HKDF key derivation** (separate keys for each direction)
- **AEAD encryption** with ChaCha20-Poly1305 or AES-128-GCM
- Custom AAD construction for packet authentication
- MTU adjustment for AEAD overhead

### Phase 5: AnyTLS Protocol (Mode 4c/4e)
- **sing-box AnyTLS compatibility** for TLS fingerprint resistance
- Configurable padding schemes: `random`, `fixed`, `burst`, `adaptive`
- Idle session timeout support
- JA3/JA4 fingerprint evasion

### Phase 6: REALITY Spider Enhancement (Mode 4c)
- **Concurrent web crawling** during certificate validation (up to 4 workers)
- SpiderY timing array with ±10% jitter
- URL deduplication and crawler limits (depth, total fetches, per-host cap)
- Configurable timeout and depth

### Phase 7: KCP Hardware Entropy (Mode 4d)
- **Hardware-accelerated RNG** using AES-NI when available
- Go 1.22+ ChaCha8Rand fallback
- Automatic reseed every 1 MiB
- ~50% CPU overhead reduction for nonce generation

### Phase 8: KCP FEC Enhancements (Mode 4d)
- **Non-continuous parity skip** during bursty traffic
- **Pulse-based auto-tuning** based on network conditions
- Hysteresis rules to prevent oscillation
- ~10% bandwidth reduction on bursty traffic

### Phase 9: Smux Priority Shaper (All Modes)
- **Priority-based stream scheduling**
- Control frames (SYN/FIN/NOP/UPD) prioritized over data frames (PSH)
- Round-robin fairness within priority classes
- Starvation prevention (max 16 control burst)
- ~30% control frame latency reduction under heavy load

### Phase 10: Adaptive Connection Pool (All Modes)
- **Auto-scaling pool** based on utilization
- Normal and aggressive scaling modes
- Configurable min/max pool size and cooldown
- ~20% connection latency reduction under high load

## New Configuration Schema

### UQSP (Unified QUIC Superset Protocol)
```yaml
transport:
  type: uqsp
  uqsp:
    carrier:
      type: quic          # or xhttp, rawtcp, trusttunnel, anytls, kcp
    congestion:
      algorithm: brutal
      bandwidth_mbps: 200
    behaviors:
      # Protocol-specific behaviors
```

### Variant Presets
```yaml
variant: "4a"  # Automatically applies optimized preset
```

See `examples/uqsp-mode-4a.yaml` through `examples/uqsp-mode-4e.yaml` for complete configurations.

## Performance Improvements

| Metric | Before | After | Improvement |
|--------|--------|-------|-------------|
| UDP Throughput (PPS) | Baseline | +80% | Batch I/O |
| CPU Usage (nonce gen) | Baseline | -50% | Hardware entropy |
| Bandwidth (bursty) | Baseline | -10% | FEC parity skip |
| Connection Latency | Baseline | -20% | Adaptive pool |
| Control Frame Latency | Baseline | -30% | Priority shaper |

## Security Enhancements

- **Directional key derivation** prevents key reuse attacks
- **AEAD encryption** provides authenticated encryption for FakeTCP
- **AnyTLS protocol** evades TLS fingerprint detection
- **Xmux rotation** reduces connection fingerprintability

## Compatibility

### Backward Compatibility
- Legacy transport types are deprecated but still functional
- Automatic migration path via `stealthlink-ctl wizard`
- See `docs/MIGRATION_GUIDE.md` for details

### Upstream Compatibility
- Optional adapters for Xray-core and sing-box protocols
- Use `compat_mode: "xray"` or `compat_mode: "singbox"` for interop
- Note: Adapters are optional; StealthLink-native modes are preferred

## Installation

### From Release ZIP
```bash
wget https://github.com/XrayIran/StealthLink/releases/download/v2.0.0/stealthlink-linux-amd64-v2.0.0.zip
unzip stealthlink-linux-amd64-v2.0.0.zip
cd stealthlink-linux-amd64-v2.0.0
sudo ./stealthlink-ctl install --local --role=gateway
```

### Using stealthlink-ctl
```bash
# Install with wizard
sudo stealthlink-ctl install --wizard

# Or configure manually
sudo stealthlink-ctl configure --variant=4a
```

## Upgrade Instructions

### From v1.x
1. Backup config: `cp /etc/stealthlink/config.yaml /etc/stealthlink/config.yaml.backup`
2. Run migration wizard: `stealthlink-ctl wizard --migrate-from-v1`
3. Validate: `stealthlink-gateway -validate`
4. Restart: `sudo systemctl restart stealthlink-gateway`

See `docs/MIGRATION_GUIDE.md` for detailed instructions.

## Metrics and Monitoring

### New Prometheus Metrics
- `stealthlink_udp_batch_*` - Batch I/O statistics
- `stealthlink_faketcp_*` - FakeTCP crypto metrics
- `stealthlink_reality_spider_*` - Spider crawl metrics
- `stealthlink_kcp_fec_*` - FEC auto-tuning metrics
- `stealthlink_entropy_*` - Entropy source metrics
- `stealthlink_smux_shaper_*` - Priority shaper metrics
- `stealthlink_pool_*` - Connection pool metrics
- `stealthlink_xmux_*` - Xmux lifecycle metrics

### Release Assets Policy
The published GitHub release must contain only:
- `stealthlink-<os>-<arch>-v2.0.0.zip`
- `stealthlink-ctl`
- `SHA256SUMS`

## Known Issues

1. **REALITY Compatibility Scope**: StealthLink uses in-core REALITY-compatible behavior for mode 4c hardening, but does not guarantee byte-for-byte upstream parity
2. **Container Support**: Batch I/O syscalls may be blocked in some container configurations
3. **macOS**: Batch I/O falls back to single-packet (Linux-only feature)

## Documentation

- `README.md` - Quick start and feature overview
- `docs/MIGRATION_GUIDE.md` - Migration from v1.x
- `docs/TROUBLESHOOTING.md` - Common issues and solutions
- `examples/` - Configuration examples for all 5 modes

## Testing

- 1,083 test files
- 51 property-based tests (100 iterations each)
- 4 fuzzing targets (30s budget per target)
- All tests pass on Linux amd64/arm64

## Acknowledgments

This release consolidates techniques from upstream projects:
- Xray-core (XHTTP, Xmux, REALITY)
- sing-box (AnyTLS)
- kcp-go (Batch I/O, FEC, entropy)
- udp2raw (FakeTCP patterns)
- smux (Multiplexing)
- Backhaul (Connection pooling)

## Support

- GitHub Issues: https://github.com/XrayIran/StealthLink/issues
- Documentation: https://docs.stealthlink.io
- Community: https://discord.gg/stealthlink

---

**Full Changelog**: https://github.com/XrayIran/StealthLink/compare/v1.x...v2.0.0
