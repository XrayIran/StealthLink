# Underlay Dialers

## Overview

StealthLink supports configurable underlay dialers that control how outbound connections are established. This allows routing StealthLink traffic through different transport layers for additional obfuscation or network path control.

## Supported Dialers

### 1. Direct Dialer (Default)

The direct dialer uses standard network dialing without any intermediate layer.

**Configuration:**
```yaml
transport:
  dialer: direct  # or omit for default
```

**Use Cases:**
- Standard deployments
- Direct server-to-server connections
- Minimal latency requirements

### 2. WARP Dialer

Routes StealthLink traffic through Cloudflare WARP, making server egress appear as Cloudflare IP addresses.

**Configuration:**
```yaml
transport:
  dialer: warp
  warp_dialer:
    mode: consumer  # "consumer" | "zero-trust" | "connector"
    device_id: ""   # Optional: pre-registered device ID

warp:
  enabled: true
  mode: builtin
  endpoint: "engage.cloudflareclient.com:2408"
  routing_mode: vpn_only
  vpn_subnet: "10.8.0.0/24"
  keepalive: 25s
```

#### WARP Routing Model

Cloudflare WARP uses a WireGuard-based tunnel to route traffic through Cloudflare's global network. The routing model varies by operational mode:

**Traffic Flow:**
```
StealthLink → WARP Tunnel (WireGuard) → Cloudflare Edge → Internet
```

**Routing Modes:**
- `vpn_only`: Only StealthLink traffic routes through WARP (split tunneling)
- `full_tunnel`: All server traffic routes through WARP
- `exclude_routes`: Specific subnets bypass WARP

**Key Characteristics:**
- Uses WireGuard protocol with Noise IK handshake
- Automatic failover to nearest Cloudflare datacenter
- IPv4 and IPv6 support
- DNS queries routed through 1.1.1.1 (configurable)
- Egress IP appears as Cloudflare-owned address space

**Reference:** [Cloudflare WARP Architecture](https://developers.cloudflare.com/warp-client/get-started/warp-architecture/)

#### Operational Models

##### 1. Consumer WARP
Server runs Cloudflare WARP client, all traffic routes through Cloudflare's consumer network.

**Characteristics:**
- Free tier available (limited bandwidth)
- Automatic device registration
- Shared egress IP pool
- Best effort routing

**Use Case:** Development, testing, low-volume production

##### 2. Zero Trust WARP
Server authenticates to Cloudflare Zero Trust, routes through organization's private network.

**Characteristics:**
- Requires Cloudflare Zero Trust account
- Device posture checks
- Access policies enforced
- Dedicated egress IPs available
- Audit logging

**Use Case:** Enterprise deployments, compliance requirements

##### 3. WARP Connector
Server acts as connector, bridging private network to WARP clients.

**Characteristics:**
- Bidirectional connectivity
- Private network access for WARP clients
- No egress IP change for server
- Requires static IP or DNS name

**Use Case:** Hybrid cloud, remote access to private services

**Reference:** [Cloudflare Zero Trust Documentation](https://developers.cloudflare.com/cloudflare-one/)

#### Use Cases

**Primary Use Cases:**
- **Egress IP Obfuscation**: Server traffic appears to originate from Cloudflare IP ranges, useful for bypassing IP-based restrictions
- **Geographic Distribution**: Leverage Cloudflare's global network for optimal routing
- **DDoS Protection**: Benefit from Cloudflare's DDoS mitigation at the network edge
- **Compliance**: Route traffic through specific jurisdictions using Zero Trust

**Example Scenarios:**
- Server in restricted region needs to access global services
- Masking server's true location from destination services
- Reducing latency via Cloudflare's Argo Smart Routing
- Protecting server IP from exposure in logs

#### Limitations

**Bandwidth Constraints:**
- Consumer WARP: ~10 Gbps aggregate, ~1 Gbps per connection
- Zero Trust: Varies by plan (typically 10-100 Gbps)
- Burst traffic may be rate-limited
- Not suitable for sustained high-throughput (>500 Mbps)

**Latency Impact:**
- Adds 20-50ms baseline latency (routing through Cloudflare edge)
- Additional 10-30ms for cross-region traffic
- Jitter increases under load (±10-20ms)
- Not recommended for latency-sensitive applications (<50ms requirement)

**Terms of Service:**
- Consumer WARP: Prohibited for commercial proxy/VPN services
- Zero Trust: Subject to Cloudflare's Acceptable Use Policy
- Bandwidth abuse may result in throttling or suspension
- Must comply with destination service ToS

**Technical Limitations:**
- Requires UDP port 2408 outbound (or TCP fallback on 443)
- IPv6 may not be available in all regions
- Some protocols may be blocked (e.g., BitTorrent on consumer tier)
- ICMP/raw sockets not supported in all modes
- MTU reduced to 1420 bytes (WireGuard overhead)

**Operational Considerations:**
- Device registration requires internet connectivity
- Cloudflare can observe encrypted traffic metadata (timing, size)
- Egress IP may change during failover events
- Not suitable for applications requiring stable source IP
- Cloudflare's data retention policies apply

**Reference:** [Cloudflare WARP Terms of Service](https://www.cloudflare.com/terms/)

### 3. SOCKS5 Dialer

Routes StealthLink traffic through a SOCKS5 proxy.

**Configuration:**
```yaml
transport:
  dialer: socks
  socks_dialer:
    address: "127.0.0.1:1080"  # SOCKS5 proxy address
    username: ""                # Optional: SOCKS5 username
    password: ""                # Optional: SOCKS5 password
```

**Use Cases:**
- Routing through existing SOCKS5 infrastructure
- Chaining with other proxy systems
- Corporate proxy environments

## Metrics

Underlay dialers expose the following metrics:

- `underlay_selected`: Current dialer type ("direct", "warp", "socks")
- `warp_health`: WARP tunnel health status ("up", "down")

Access metrics via the metrics endpoint:
```bash
curl http://localhost:9090/metrics
```

## Examples

See the `examples/` directory for complete configuration examples:
- `examples/underlay-direct.yaml` - Direct dialer (default)
- `examples/underlay-warp.yaml` - WARP dialer with Cloudflare
- `examples/underlay-socks.yaml` - SOCKS5 proxy dialer

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   StealthLink Application                    │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────────┐
│                    Underlay Dialer Layer                     │
│  ┌──────────┬──────────────────────┬──────────────────────┐ │
│  │  Direct  │        WARP          │       SOCKS5         │ │
│  │  Dialer  │       Dialer         │       Dialer         │ │
│  └────┬─────┴──────────┬───────────┴──────────┬───────────┘ │
└───────┼────────────────┼──────────────────────┼─────────────┘
        │                │                      │
        │                │                      │
        v                v                      v
   net.Dial      Cloudflare WARP         SOCKS5 Proxy
                      Tunnel
```

## Implementation Details

### Direct Dialer
- Uses standard `net.Dialer` with 30s timeout
- No additional overhead
- Default behavior

### WARP Dialer
- Creates a WARP tunnel using WireGuard protocol
- Performs Noise IK handshake with Cloudflare
- Routes traffic through Cloudflare's network
- Supports split routing (vpn_only mode)
- Automatic device registration

### SOCKS5 Dialer
- Uses `golang.org/x/net/proxy` package
- Supports username/password authentication
- Context-aware connection management

## Troubleshooting

### WARP Connection Issues

1. **Check WARP health status:**
   ```bash
   curl http://localhost:9090/metrics | grep warp_health
   ```

2. **Verify WARP configuration:**
   ```bash
   stealthlink-ctl test warp
   ```

3. **Check WARP logs:**
   ```bash
   journalctl -u stealthlink-agent -f | grep warp
   ```

### SOCKS5 Connection Issues

1. **Verify SOCKS5 proxy is running:**
   ```bash
   nc -zv 127.0.0.1 1080
   ```

2. **Test SOCKS5 connectivity:**
   ```bash
   curl --socks5 127.0.0.1:1080 http://example.com
   ```

## Security Considerations

### WARP
- Traffic is encrypted end-to-end (StealthLink + WARP)
- Cloudflare can see encrypted StealthLink traffic patterns
- Device registration requires internet connectivity
- Consider Cloudflare's data retention policies

### SOCKS5
- Ensure SOCKS5 proxy is trusted
- Use authentication when possible
- Consider encrypting SOCKS5 connection (e.g., SSH tunnel)
- Monitor proxy logs for anomalies

## Performance Impact

| Dialer | Latency Overhead | Throughput Impact | CPU Overhead |
|--------|------------------|-------------------|--------------|
| Direct | None             | None              | None         |
| WARP   | +20-50ms         | -10-20%           | Low          |
| SOCKS5 | +5-20ms          | -5-10%            | Minimal      |

*Note: Actual impact varies based on network conditions and proxy location.*
