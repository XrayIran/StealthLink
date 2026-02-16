# StealthLink Feature Implementation Summary (L3-Only)

StealthLink is an L3 (TUN) VPS-to-VPS tunnel that provides a virtual IP link over the UQSP runtime with five canonical mode profiles (HTTP+-TLS). L2/TAP workflows are intentionally out of scope for the supported surface.

## Supported (Shipped Surface)

- Canonical mode architecture + consolidation ADR: `docs/consolidate-not-wrap.md`
- UQSP unified runtime (HTTP+-TLS mapping, underlay wiring, reverse-init): `internal/transport/uqsp/*`
- Underlay dialers (direct/policy/socks/WARP): `internal/transport/underlay/*`
- VPN (TUN only) with datagram fast-path when available: `internal/vpn/*`, `internal/tun/*`
- TUN transport selection knob (`auto|stream|datagram`) surfaced via `services[].tun.transport` and used in:
  - `internal/agent/agent.go`
  - `internal/gateway/gateway.go`
  - `internal/config/config.go`
- Release artifact is ZIP + `stealthlink-ctl` only:
  - `scripts/build-release-zip.sh`
  - `scripts/build-release-assets.sh`
  - `scripts/publish-v2.0.0.sh`

## Out Of Scope (Not Supported)

- L2/TAP (Ethernet) tunneling and L2 mesh products (e.g., VortexL2, EasyTier L2 mesh) are `out_of_scope_l3`.
  - Any residual code under `internal/transport/taptun/*` or L2-oriented upstream snapshots under `sources/` is treated as a reference snapshot only and is not exposed by validation, examples, or the wizard.

## Post-v2.0.0 Roadmap

The following features are planned for future releases and are **not** supported in v2.0.0:

- **Mesh networking** — Multi-node topology with automatic peer discovery, distributed routing tables, and NAT traversal for direct peer-to-peer links.
- **L2/TAP mode** — Ethernet-level tunneling via TAP interfaces, bridge mode for LAN extension, and L2 mesh topologies (e.g., VortexL2, EasyTier L2 mesh integration).
- **IPv6/dual-stack** — Native IPv6 tunnel endpoints, dual-stack TUN interface support, and IPv6-only deployment profiles.
