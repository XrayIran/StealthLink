# Upstream Delta Matrix

Generated: 2026-02-16T01:51:34Z

| Upstream | Mode Stack | Status | Source | Destinations |
|---|---|---|---|---|
| `6TO4-GRE-IPIP-SIT` | `underlay-tunneling` | `integrated` | present | `internal/tun` |
| `Backhaul` | `pool-and-mux` | `integrated` | present | `internal/transport/pool` |
| `EasyTier` | `l3-path-policy` | `integrated` | present | `internal/transport/underlay/path_policy_dialer.go`, `internal/transport/racing` |
| `FRP_Reverse_Loadbalance` | `reverse-orchestration` | `integrated` | present | `internal/transport/reverse` |
| `Layer2_TapTunnel` | `l2-tap` | `out_of_scope_l3` | missing | `internal/transport/taptun` |
| `TrustTunnel` | `TLS-trusttunnel` | `integrated` | present | `internal/transport/trusttunnel` |
| `Tunnel` | `reverse-init` | `integrated` | present | `internal/transport/uqsp/reverse.go` |
| `VPS-Optimizer` | `ops-tuning` | `integrated` | present | `scripts/stealthlink-ctl` |
| `VornaTunnel` | `carrier-experiments` | `integrated` | present | `internal/transport/carrier` |
| `VortexL2` | `l2-mesh` | `out_of_scope_l3` | present | `internal/transport/taptun` |
| `Vwarp` | `warp-underlay` | `integrated` | present | `internal/transport/underlay/warp_dialer.go` |
| `WaterWall` | `transport-graph` | `integrated` | present | `internal/transport/graph` |
| `Xray-core` | `HTTP+-TLS+-xhttp-reality` | `integrated` | present | `internal/compat/xray`, `internal/transport/xhttpmeta` |
| `amnezia-client` | `awg-wireguard` | `integrated` | present | `internal/transport/wireguard`, `internal/transport/uqsp/behavior/awg.go` |
| `anytls-go` | `TLS+-TLS-anytls` | `integrated` | present | `internal/transport/anytls` |
| `conjure` | `fronting-rendezvous` | `integrated` | present | `internal/transport/phantom`, `internal/transport/uqsp/behavior/domainfront.go` |
| `dae` | `routing-policy` | `integrated` | present | `internal/routing` |
| `daggerConnect` | `reverse-init-ops` | `integrated` | present | `internal/transport/uqsp/reverse.go`, `internal/transport/underlay` |
| `gfw_resist_HTTPS_proxy` | `gfw-resist` | `integrated` | present | `internal/transport/stealth` |
| `gfw_resist_tcp_proxy` | `gfw-resist` | `integrated` | present | `internal/transport/rawtcp` |
| `gfw_resist_tls_proxy` | `gfw-resist` | `integrated` | present | `internal/tlsutil` |
| `gost` | `proxy-suite` | `integrated` | present | `internal/transport/underlay` |
| `grasshopper` | `udp-obfs` | `integrated` | present | `internal/transport/noize` |
| `haproxy` | `fronting-lb` | `integrated` | present | `internal/transport/tlsmux` |
| `hysteria` | `UDP+-quic` | `integrated` | present | `internal/transport/quicmux` |
| `juicity` | `UDP+-quic` | `integrated` | present | `internal/transport/quicmux` |
| `kcp-go` | `udp-reliability` | `integrated` | present | `internal/transport/kcpbase`, `internal/transport/batch` |
| `kcptun` | `udp-reliability` | `integrated` | present | `internal/transport/kcpmux` |
| `leaf` | `routing-policy` | `integrated` | present | `internal/routing` |
| `lyrebird` | `obfs4-fronting` | `integrated` | present | `internal/transport/obfs`, `internal/transport/uqsp/behavior/obfs4.go` |
| `mihomo` | `routing-policy` | `integrated` | present | `internal/routing` |
| `ocserv` | `TLS-cstp` | `integrated` | present | `internal/transport/anyconnect`, `internal/transport/dtls` |
| `openconnect` | `TLS-cstp` | `integrated` | present | `internal/transport/anyconnect`, `internal/transport/dtls` |
| `paqctl` | `raw-packet-control` | `integrated` | present | `internal/transport/rawtcp` |
| `paqet` | `raw-packet` | `integrated` | present | `internal/transport/rawtcp` |
| `psiphon-tunnel-core` | `front-pool-scoring` | `integrated` | present | `internal/tlsutil/front_pool.go`, `internal/transport/uqsp/carrier/tlsdial.go`, `internal/transport/uqsp/behavior/domainfront.go` |
| `qtun` | `UDP+-quic` | `integrated` | present | `internal/transport/quicmux` |
| `rust-tun` | `tun-impl` | `integrated` | present | `internal/tun` |
| `shadowsocks-rust` | `proxy-suite` | `integrated` | present | `internal/dns` |
| `sing-box` | `TLS+-TLS-tls-lookalike` | `integrated` | present | `internal/compat/singbox`, `internal/transport/shadowtls` |
| `smux` | `mux` | `integrated` | present | `internal/mux` |
| `snowflake` | `rendezvous-fronting` | `integrated` | present | `internal/transport/snowflake`, `internal/transport/uqsp/reverse.go`, `internal/transport/uqsp/rendezvous` |
| `tuic` | `UDP+-quic` | `integrated` | present | `internal/transport/quicmux` |
| `tun2proxy` | `tun-routing` | `integrated` | present | `internal/transport/udprelay` |
| `udp_tun` | `udp-obfs` | `integrated` | present | `internal/transport/faketcp` |
| `v2ray-core` | `compat` | `integrated` | present | `internal/compat/xray` |
| `webtunnel` | `TLS-webtunnel` | `integrated` | present | `internal/transport/uqsp/carrier` |
