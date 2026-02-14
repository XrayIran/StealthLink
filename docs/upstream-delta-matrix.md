# Upstream Delta Matrix

Generated: 2026-02-14T19:31:57Z

| Upstream | Mode Stack | Status | Source | Destinations |
|---|---|---|---|---|
| `6TO4-GRE-IPIP-SIT` | `underlay-tunneling` | `verify_only` | present | `internal/tun` |
| `Backhaul` | `pool-and-mux` | `integrated` | present | `internal/transport/pool` |
| `EasyTier` | `l2-mesh` | `out_of_scope_l3` | present | `internal/transport/taptun` |
| `FRP_Reverse_Loadbalance` | `reverse-orchestration` | `verify_only` | present | `internal/transport/reverse` |
| `Layer2_TapTunnel` | `l2-tap` | `out_of_scope_l3` | present | `internal/transport/taptun` |
| `TrustTunnel` | `4e-trusttunnel` | `integrated` | present | `internal/transport/trusttunnel` |
| `Tunnel` | `reverse-init` | `integrated` | present | `internal/transport/reverse`, `internal/transport/uqsp/reverse.go` |
| `VPS-Optimizer` | `ops-tuning` | `verify_only` | present | `scripts/stealthlink-ctl` |
| `VornaTunnel` | `carrier-experiments` | `verify_only` | present | `internal/transport/carrier` |
| `VortexL2` | `l2-mesh` | `out_of_scope_l3` | present | `internal/transport/taptun` |
| `Vwarp` | `warp-underlay` | `integrated` | present | `internal/transport/underlay/warp_dialer.go` |
| `WaterWall` | `transport-graph` | `integrated` | present | `internal/transport/graph` |
| `Xray-core` | `4a-4c-xhttp-reality` | `integrated` | present | `internal/compat/xray`, `internal/transport/xhttpmeta` |
| `amnezia-client` | `awg-wireguard` | `integrated` | present | `internal/transport/wireguard`, `internal/transport/uqsp/behavior/awg.go` |
| `anytls-go` | `4c-4e-anytls` | `integrated` | present | `internal/transport/anytls` |
| `conjure` | `fronting-rendezvous` | `integrated` | present | `internal/transport/conjure` |
| `dae` | `routing-policy` | `verify_only` | present | `internal/routing` |
| `daggerConnect` | `anyconnect-variants` | `verify_only` | present | `internal/transport/anyconnect` |
| `gfw_resist_HTTPS_proxy` | `gfw-resist` | `verify_only` | present | `internal/transport/stealth` |
| `gfw_resist_tcp_proxy` | `gfw-resist` | `verify_only` | present | `internal/transport/rawtcp` |
| `gfw_resist_tls_proxy` | `gfw-resist` | `verify_only` | present | `internal/tlsutil` |
| `gost` | `proxy-suite` | `verify_only` | present | `internal/transport/underlay` |
| `grasshopper` | `udp-obfs` | `verify_only` | present | `internal/transport/noize` |
| `haproxy` | `fronting-lb` | `verify_only` | present | `internal/transport/tlsmux` |
| `hysteria` | `4d-quic` | `integrated` | present | `internal/transport/quicmux` |
| `juicity` | `4d-quic` | `verify_only` | present | `internal/transport/quicmux` |
| `kcp-go` | `udp-reliability` | `integrated` | present | `internal/transport/kcpbase`, `internal/transport/batch` |
| `kcptun` | `udp-reliability` | `integrated` | present | `internal/transport/kcpmux` |
| `leaf` | `routing-policy` | `verify_only` | present | `internal/routing` |
| `lyrebird` | `obfs4-fronting` | `integrated` | present | `internal/transport/obfs`, `internal/transport/uqsp/behavior/obfs4.go` |
| `mihomo` | `routing-policy` | `verify_only` | present | `internal/routing` |
| `ocserv` | `4e-cstp` | `integrated` | present | `internal/transport/anyconnect`, `internal/transport/dtls` |
| `openconnect` | `4e-cstp` | `integrated` | present | `internal/transport/anyconnect`, `internal/transport/dtls` |
| `paqctl` | `raw-packet-control` | `integrated` | present | `internal/transport/rawtcp` |
| `paqet` | `raw-packet` | `integrated` | present | `internal/transport/rawpacket`, `internal/transport/rawtcp` |
| `psiphon-tunnel-core` | `meek-fronting` | `integrated` | present | `internal/transport/psiphon` |
| `qtun` | `4d-quic` | `verify_only` | present | `internal/transport/quicmux` |
| `rust-tun` | `tun-impl` | `verify_only` | present | `internal/tun` |
| `shadowsocks-rust` | `proxy-suite` | `verify_only` | present | `internal/dns` |
| `sing-box` | `4c-4e-tls-lookalike` | `integrated` | present | `internal/compat/singbox`, `internal/transport/shadowtls` |
| `smux` | `mux` | `integrated` | present | `internal/mux` |
| `snowflake` | `rendezvous-fronting` | `integrated` | present | `internal/transport/snowflake` |
| `tuic` | `4d-quic` | `verify_only` | present | `internal/transport/quicmux` |
| `tun2proxy` | `tun-routing` | `verify_only` | present | `internal/transport/udprelay` |
| `udp_tun` | `udp-obfs` | `verify_only` | present | `internal/transport/faketcp` |
| `v2ray-core` | `compat` | `verify_only` | present | `internal/compat/xray` |
| `webtunnel` | `4e-webtunnel` | `integrated` | present | `internal/transport/uqsp/carrier` |
