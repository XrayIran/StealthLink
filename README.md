# stealthlink

Consolidated gateway/agent tunnel with a pluggable data plane. Default transport is stealth‑oriented (WSS/H2), with KCP as a throughput fallback.

## Status
Implemented:
- Transports: `tls`, `wss`, `h2`, `xhttp`, `shadowtls`, `reality`, `dtls`, `quic`, `masque`, `kcp`, `rawtcp`, `awg_obfs`, `raw_adapter`, `tlsmirror` (experimental).
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
cd /home/iman/stealthlink

go build ./cmd/gateway

go build ./cmd/agent
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

## Notes
- `tun` requires OS‑level IP assignment and routing configuration (not handled by this repo).
- TUN MTU is set via OS tools (`ip` on Linux, `ifconfig` on macOS).
- KCP requires `transport.kcp.key`.
- `tlsmirror` is experimental and requires `transport.experimental: true`.
- DTLS requires `transport.dtls.psk`.
- QUIC/MASQUE use TLS cert/key on gateway and CA / server-name validation on agent.
- `rawtcp` uses libpcap/raw sockets (root required) and may need host firewall rules to suppress TCP RSTs.
- Use `scripts/stealthlink-iptables.sh apply <port>` on the host to add the required rules (remove with `remove`).
- `transport.kcp.packet_guard` enables a lightweight pre‑decrypt filter on KCP packets.
- Per‑service host overrides can set SNI/Host/Origin/Path for stealth transport shaping.

## New Config Surfaces
- `transport.type`: adds `tlsmirror`, `awg_obfs`, `raw_adapter`.
- `transport.pipeline`: `enabled`, `nodes`, `edges` (DAG validated).
- `transparent_proxy`: `mode`, `backend`, `whitelist_cidrs`.
- `obfuscation.noize`: top-level alias for transport noize controls.
- `auth.providers`: pluggable `static|oidc|radius` providers.
- `host_opt`: `profile`, `dry_run`, `rollback_token`.
