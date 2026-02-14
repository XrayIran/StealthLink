# stealthlink

Consolidated gateway/agent tunnel with a pluggable data plane. Default transport is UQSP with five unified variants (`4a..4e`) for anti-DPI, throughput, and reliability.

## Status
Implemented:
- Transports: `tls`, `wss`, `h2`, `xhttp`, `shadowtls`, `reality`, `dtls`, `quic`, `masque`, `kcp`, `rawtcp`, `faketcp`, `awg_obfs`, `raw_adapter`, `tlsmirror` (experimental).
- TLS fingerprint shaping with uTLS for TLS/WSS/H2.
- Per-service TLS fingerprint pinning + host overrides (SNI/Host/Origin/Path).
- Optional IP override for true domain-fronting (`connect_ip`) with Host/SNI preserved.
- Per-service WSS/H2 connection pooling limits (`host.max_conns`).
- Services: `tcp`, `udp`, `tun`.
- Reverse forwarding: gateway listens publicly, agent connects out.
- Control‑plane: shared key auth + health checks + multi‑agent load balancing.
- Control‑plane security: key rotation (`shared_keys`), per-agent tokens/policy, nonce replay protection.
- UDP shaping: socket buffers + optional rate limiting (drop/pace).
- Metrics endpoint: `/metrics` (JSON), `/metrics/prom` (Prometheus), `/healthz` with traffic bytes in/out, socket gauges, per-transport active sessions, and obfuscation counters.
- Tooling: `stealthlink-tools host-optimize` (with rollback snapshots), `stealthlink-tools tproxy ... [auto|iptables|nft]`, and `stealthlink-tools proxy-matrix`.
- Transport pipeline DAG config (`transport.pipeline`) for declarative processing graphs with cycle validation.
- Pluggable auth providers (`auth.providers`): `static`, `oidc` (HS256 JWT validation), `radius` (token bridge mode).
- Live config reload watcher (agent/gateway restart in-process on valid config changes).

## Build
```bash
cd /home/iman/StealthLink

go build ./cmd/gateway

go build ./cmd/agent
```

## Build Release ZIP (Go + TypeScript + Rust + Python)
```bash
cd /home/iman/StealthLink
./scripts/build-release-zip.sh
```
This creates `dist/stealthlink-<os>-<arch>-v<version>.zip`.

Prepare publish-ready GitHub release assets (ZIP + helper script only):
```bash
cd /home/iman/StealthLink
./scripts/build-release-assets.sh --version v2.0.0
```
This creates `dist/release-assets/{stealthlink-<os>-<arch>-v<version>.zip,stealthlink-ctl,SHA256SUMS}`.

Dry-run the GitHub publish workflow that keeps only `v2.0.0`:
```bash
cd /home/iman/StealthLink
./scripts/publish-v2.0.0.sh --repo XrayIran/StealthLink
```
Execute remote cleanup/publish (destructive on remote releases/tags):
```bash
./scripts/publish-v2.0.0.sh --repo XrayIran/StealthLink --yes
```

## Install From ZIP (Offline-Friendly)
```bash
unzip stealthlink-<os>-<arch>-v<version>.zip
cd stealthlink-<os>-<arch>-v<version>
sudo ./stealthlink-ctl install --local --role=gateway
```
Or install directly from the ZIP path:
```bash
sudo ./stealthlink-ctl install --bundle=./stealthlink-<os>-<arch>-v<version>.zip --role=agent
```

## One-line install (latest GitHub release)
```bash
curl -fsSL https://github.com/XrayIran/StealthLink/releases/latest/download/stealthlink-ctl -o /tmp/stealthlink-ctl && chmod +x /tmp/stealthlink-ctl && sudo /tmp/stealthlink-ctl install --latest --role both
```

For unattended provisioning, use non-interactive setup:
```bash
sudo ./stealthlink-ctl setup --latest --repo XrayIran/StealthLink --role both --non-interactive --variant 4d --tune-profile balanced --apply-firewall true --start-services true
```

## Run (example)
Gateway:
```bash
./gateway -config examples/gateway.yaml
```

Agent:
```bash
./agent -config examples/agent.yaml
```

Full VPS-to-VPS virtual IP tunnel examples:
- `examples/uqsp-vpn-gateway.yaml`
- `examples/uqsp-vpn-agent.yaml`

## Notes
- `tun` requires OS‑level IP assignment and routing configuration (not handled by this repo).
- TUN MTU is set via OS tools (`ip` on Linux, `ifconfig` on macOS).
- KCP requires `transport.kcp.key`.
- `tlsmirror` is experimental and requires `transport.experimental: true`.
- DTLS requires `transport.dtls.psk`.
- QUIC/MASQUE use TLS cert/key on gateway and CA / server-name validation on agent.
- `rawtcp` uses libpcap/raw sockets (root required) and may need host firewall rules to suppress TCP RSTs.
- UQSP raw-family carriers (`rawtcp`, `faketcp`, `icmptun`) apply 4b overlays in-core: `gfwresist_tcp`, optional `obfs4`, adaptive morphing padding, optional AWG junking.
- Use `stealthlink-ctl firewall apply <port>` on the host to add the required rules (remove with `remove`).
- `transport.kcp.packet_guard` enables a lightweight pre‑decrypt filter on KCP packets.
- Per‑service host overrides can set SNI/Host/Origin/Path for stealth transport shaping.

## New Config Surfaces

### Phase 1: Batch I/O (Mode 4b/4d Foundation)
Linux batch syscalls for 2-4× throughput improvement:
```yaml
transport:
  udp_batch_size: 32      # Range: 1-64, default: 32
  udp_batch_enabled: true # Auto-disabled on non-Linux or ENOSYS
```

### Phase 2: XHTTP Metadata Placement (Mode 4a)
Flexible session/sequence placement for CDN compatibility:
```yaml
transport:
  uqsp:
    carrier:
      type: xhttp
      xhttp:
        session_placement: header   # path | query | header | cookie
        session_key: "X-Session-ID"
        sequence_placement: header  # path | query | header | cookie
        sequence_key: "X-Seq"
```

### Phase 3: Xmux Connection Lifecycle (Mode 4a Rotation)
Connection rotation for anti-fingerprinting:
```yaml
transport:
  uqsp:
    carrier:
      xmux:
        enabled: true
        c_max_reuse_times: 32       # TCP connection reuse limit
        h_max_request_times: 100    # HTTP/2 stream limit
        h_max_reusable_secs: 3600   # Connection age limit
        drain_timeout: 30s          # Graceful drain timeout
```

### Phase 4: FakeTCP Directional Keys & AEAD (Mode 4b Security)
Directional HKDF + AEAD encryption:
```yaml
transport:
  uqsp:
    carrier:
      type: faketcp
      faketcp:
        crypto_key: "your-shared-secret"
        aead_mode: chacha20poly1305  # off | chacha20poly1305 | aesgcm
```

### Phase 5: AnyTLS Protocol (Mode 4c/4e)
TLS fingerprint resistance via sing-box AnyTLS:
```yaml
transport:
  uqsp:
    carrier:
      type: anytls
      anytls:
        padding_scheme: random   # random | fixed | burst | adaptive
        padding_min: 100         # bytes
        padding_max: 900         # bytes
        idle_session_timeout: 300
```

### Phase 6: REALITY Spider Enhancement (Mode 4c)
Concurrent web crawling for certificate validation:
```yaml
transport:
  uqsp:
    behaviors:
      reality:
        spider_x: "https://www.example.com"
        spider_y: [50, 100, 200, 300, 500, 800, 1000, 1500, 2000, 3000]
        spider_concurrency: 4
        spider_timeout: 10s
        max_depth: 3
        max_total_fetches: 20
        per_host_cap: 5
```

### Phase 7: KCP Hardware Entropy (Mode 4d)
Hardware-accelerated RNG for reduced CPU overhead:
```yaml
transport:
  uqsp:
    carrier:
      type: kcp
      kcp:
        entropy:
          accelerated: true  # AES-NI > ChaCha8Rand > crypto/rand
```

### Phase 8: KCP FEC Enhancements (Mode 4d)
Adaptive Forward Error Correction:
```yaml
transport:
  uqsp:
    carrier:
      type: kcp
      kcp:
        fec:
          enabled: true
          data_shards: 10     # Range: 3-20
          parity_shards: 3    # Range: 1-10
          auto_tune: true     # Adjust based on loss rate
          parity_skip: true   # Skip on bursty traffic
```

### Phase 9: Smux Priority Shaper (All Modes)
Priority-based stream scheduling:
```yaml
transport:
  smux:
    priority_shaper: true
    max_control_burst: 16    # Control frames before data allowed
    queue_size: 1024
```

### Phase 10: Adaptive Connection Pool (All Modes)
Auto-scaling connection pool:
```yaml
transport:
  connection_pool:
    mode: aggressive    # normal | aggressive
    min_size: 2
    max_size: 32
    cooldown_secs: 30
```

### Other Config Surfaces
- `transport.type`: adds `tlsmirror`, `awg_obfs`, `raw_adapter`.
- `transport.pipeline`: `enabled`, `nodes`, `edges` (DAG validated).
- `variant`: optional explicit mode selector `4a|4b|4c|4d|4e` for UQSP presets.
- `transport.uqsp.variant_profile`: optional in-transport preset selector when top-level `variant` is omitted.
- `transport.uqsp.runtime.mode`: `unified` (default) or `legacy` runtime path.
- `transparent_proxy`: `mode`, `backend`, `whitelist_cidrs`.
- `obfuscation.noize`: top-level alias for transport noize controls.
- `auth.providers`: pluggable `static|oidc|radius` providers.
- `host_opt`: `profile`, `dry_run`, `rollback_token`.

## UQSP Migration Guide

UQSP (Unified QUIC Superset Protocol) replaces the legacy per-transport configs (`transport.type: rawtcp`, `tls`, `wss`, `kcp`, …) with a single unified entry:

```yaml
transport:
  type: uqsp
  uqsp:
    carrier:
      type: quic          # or rawtcp, xhttp, webtunnel, etc.
    congestion:
      algorithm: brutal    # or bbr
      bandwidth_mbps: 200
    obfuscation:
      profile: adaptive
    capsules:
      connect_ip: true
```

### Variant Presets

Set `variant` at the top of your config to apply a curated preset:

| Variant | Name | Description |
|---------|------|-------------|
| `4a` | xhttp-tls | XHTTP + TLS + Domain Fronting + XTLS Vision + ECH — maximum stealth with CDN cover |
| `4b` | raw-tcp | RawTCP/FakeTCP + KCP/smux + obfs4 + anti-DPI — low latency, high throughput |
| `4c` | tls-mirror | REALITY/ShadowTLS + XTLS Vision + PQ signatures — TLS fingerprint resistance |
| `4d` | udp | QUIC/UDP + Hysteria2 CC + AmneziaWG — UDP-based with anti-DPI |
| `4e` | trust | TrustTunnel + HTTP/2 + HTTP/3 — HTTP-constrained environments |

### Migrating from Legacy Configs

1. Change `transport.type` from your old value to `uqsp`
2. Move carrier-specific settings under `transport.uqsp.carrier`
3. Add a `variant` field (or let StealthLink infer it from your carrier/behaviors)
4. Run `stealthlink-ctl wizard` for an interactive migration

### WARP Integration

To route StealthLink traffic through Cloudflare WARP for IP obfuscation:

```yaml
warp:
  enabled: true
  required: false            # true => fail fast if WARP cannot start
  mode: builtin              # or wgquick
  endpoint: "engage.cloudflareclient.com:2408"
  routing_mode: vpn_only     # or all
  vpn_subnet: "10.77.0.0/24"
  # license_key: "your-warp-plus-key"  # optional for WARP+
```

### VPN Quick-Start

For a full VPS-to-VPS virtual IP tunnel, use the example configs:

```bash
# Gateway
cp examples/uqsp-vpn-gateway.yaml /etc/stealthlink/config.yaml
# Edit the shared_key (generate with: stealthlink-ctl secret)
systemctl start stealthlink

# Agent
cp examples/uqsp-vpn-agent.yaml /etc/stealthlink/config.yaml
# Use the SAME shared_key as the gateway
# Set agent.gateway_addr to the gateway's public IP
systemctl start stealthlink
```
