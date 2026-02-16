# StealthLink v2.0 Migration Guide

This guide helps migrate from previous StealthLink versions to v2.0 with the new upstream integration features.

## Overview

StealthLink v2.0 introduces:
- 12 new upstream integration features (Phases 1-10)
- 5 unified operational modes (HTTP+-TLS)
- UQSP (Unified QUIC Superset Protocol) as the default transport
- Enhanced security with directional HKDF + AEAD
- Improved performance with batch I/O and hardware entropy

## Breaking Changes

### 1. Transport Configuration

**Old (v1.x):**
```yaml
transport:
  type: kcp
  kcp:
    key: "secret"
    fec: true
```

**New (v2.0):**
```yaml
transport:
  type: uqsp
  uqsp:
    carrier:
      type: kcp
      kcp:
        key: "secret"
        fec:
          enabled: true
          auto_tune: true   # NEW
          parity_skip: true # NEW
        entropy:
          accelerated: true # NEW
```

### 2. Variant Selection

**Old (v1.x):** Implicit based on transport type

**New (v2.0):** Explicit variant selection
```yaml
variant: "HTTP+"  # or TCP+, TLS+, UDP+, TLS
```

### 3. XHTTP Configuration

**Old (v1.x):**
```yaml
transport:
  type: xhttp
  xhttp:
    path: "/tunnel"
```

**New (v2.0):**
```yaml
transport:
  type: uqsp
  uqsp:
    carrier:
      type: xhttp
      xhttp:
        path: "/tunnel"
        # NEW: Metadata placement options
        session_placement: header
        sequence_placement: query
        # NEW: Xmux connection lifecycle
        reuse_limit: 100
        request_limit: 1000
```

## Migration Steps

### Step 1: Backup Current Configuration

```bash
cp /etc/stealthlink/config.yaml /etc/stealthlink/config.yaml.backup
```

### Step 2: Use Migration Wizard

```bash
stealthlink-ctl wizard --migrate-from-v1
```

### Step 3: Validate New Configuration

```bash
stealthlink-gateway -config /etc/stealthlink/config.yaml -validate
```

### Step 4: Test in Dry-Run Mode

```bash
stealthlink-gateway -config /etc/stealthlink/config.yaml -dry-run
```

### Step 5: Apply Migration

```bash
sudo systemctl restart stealthlink-gateway
```

## Feature Migration Matrix

| Old Feature | New Equivalent | Notes |
|-------------|----------------|-------|
| `transport.type: kcp` | `transport.type: uqsp` + `carrier.type: kcp` | UQSP wrapper required |
| `transport.type: xhttp` | `transport.type: uqsp` + `carrier.type: xhttp` | UQSP wrapper required |
| `transport.type: tls` | `transport.type: uqsp` + `carrier.type: trusttunnel` | See Mode TLS |
| `transport.kcp.fec: true` | `transport.uqsp.carrier.kcp.fec.enabled: true` | Nested under fec |
| `transport.kcp.key` | `transport.uqsp.carrier.kcp.key` | Same location |
| `host.max_conns` | `transport.xmux.reuse_limit` | Xmux controls pooling |
| N/A | `transport.batch.udp_batch_enabled` | NEW: Linux batch I/O |
| N/A | `transport.faketcp.crypto.aead` | NEW: AEAD encryption |
| N/A | `transport.connection_pool.mode` | NEW: Adaptive pool |

## Mode-Based Quick Migration

### Mode HTTP+: XHTTP + Domain Fronting

```yaml
# Add to top of config
variant: "HTTP+"

# Transport changes
transport:
  type: uqsp
  uqsp:
    carrier:
      type: xhttp
      xhttp:
        session_placement: path    # NEW
        sequence_placement: query  # NEW
        reuse_limit: 100           # NEW
        request_limit: 1000        # NEW
```

### Mode TCP+: Raw TCP + FakeTCP

```yaml
# Add to top of config
variant: "TCP+"

# Transport changes
transport:
  type: uqsp
  uqsp:
    carrier:
      type: faketcp
      faketcp:
        crypto:                    # NEW
          aead: "chacha20poly1305"
          key: "your-secret"
    pool:                          # NEW
      mode: "aggressive"
      min_size: 4
      max_size: 64
```

### Mode TLS+: REALITY/AnyTLS

```yaml
# Add to top of config
variant: "TLS+"

# Transport changes
transport:
  type: uqsp
  uqsp:
    carrier:
      type: anytls                 # or reality
      anytls:                      # NEW
        padding_scheme: random
        padding_min: 100
        padding_max: 900
```

### Mode UDP+: QUIC/KCP

```yaml
# Add to top of config
variant: "UDP+"

# Transport changes
transport:
  type: uqsp
  uqsp:
    carrier:
      type: quic                   # or kcp
      kcp:                         # If using KCP
        fec:                       # NEW
          auto_tune: true
          parity_skip: true
        entropy:                   # NEW
          accelerated: true
```

### Mode TLS: TrustTunnel

```yaml
# Add to top of config
variant: "TLS"

# Transport changes
transport:
  type: uqsp
  uqsp:
    carrier:
      type: trusttunnel
      trusttunnel:
        # Existing settings preserved
        dpd_interval: 15s
```

## Automatic Migration Script

```bash
#!/bin/bash
# migrate-config.sh

CONFIG_FILE="${1:-/etc/stealthlink/config.yaml}"

# Create backup
cp "$CONFIG_FILE" "$CONFIG_FILE.backup.$(date +%Y%m%d)"

# Detect old transport type
OLD_TYPE=$(grep "^  type:" "$CONFIG_FILE" | head -1 | awk '{print $2}')

case "$OLD_TYPE" in
  kcp|quic)
    VARIANT="UDP+"
    ;;
  xhttp|h2|wss)
    VARIANT="HTTP+"
    ;;
  rawtcp|faketcp)
    VARIANT="TCP+"
    ;;
  tls|trusttunnel)
    VARIANT="TLS"
    ;;
  reality|shadowtls|anytls)
    VARIANT="TLS+"
    ;;
  *)
    echo "Unknown transport type: $OLD_TYPE"
    exit 1
    ;;
esac

# Prepend variant
echo "variant: \"$VARIANT\"" > /tmp/new_config.yaml
echo "" >> /tmp/new_config.yaml
cat "$CONFIG_FILE" >> /tmp/new_config.yaml

# Replace transport type
sed -i "s/^transport:$/transport:\n  type: uqsp/" /tmp/new_config.yaml

echo "Migration preview created at /tmp/new_config.yaml"
echo "Review and copy to $CONFIG_FILE when ready"
```

## Rollback Procedure

If migration fails:

```bash
# Stop service
sudo systemctl stop stealthlink-gateway

# Restore backup
sudo cp /etc/stealthlink/config.yaml.backup /etc/stealthlink/config.yaml

# Restart with old version
sudo systemctl start stealthlink-gateway
```

## Validation Checklist

After migration:

- [ ] Config validates: `stealthlink-gateway -validate`
- [ ] Service starts: `systemctl start stealthlink-gateway`
- [ ] Metrics endpoint responds
- [ ] Connection establishes
- [ ] Data flows in both directions
- [ ] Rotation works (if Xmux enabled)
- [ ] New metrics appear in Prometheus

## Getting Help

- Check logs: `journalctl -u stealthlink-gateway -f`
- Validate config: `stealthlink-ctl validate`
- Debug mode: Add `logging.level: debug` to config
- Documentation: See `docs/` directory
