# Upstream Delta Matrix

Generated: 2026-02-13T18:57:08Z

| Upstream | Mode Stack | Status | Source | Destinations |
|---|---|---|---|---|
| `tcpraw` | `4b-raw` | `integrated` | present | `internal/transport/rawtcp`, `internal/transport/faketcp` |
| `paqctl` | `4b-raw` | `integrated` | present | `internal/transport/rawtcp`, `internal/transport/packet_guard.go` |
| `Tunnel` | `reverse-orchestration` | `integrated` | present | `internal/transport/reverse`, `internal/robot` |
| `sing-box` | `4c-4e-tls-lookalike` | `integrated` | present | `internal/transport/shadowtls`, `internal/transport/anytls` |
| `anytls-go` | `4c-4e-tls-lookalike` | `integrated` | present | `internal/transport/anytls`, `internal/transport/uqsp/carrier/anytls.go` |
| `shadowsocks-rust` | `4c-4e-tls-lookalike` | `verify_only` | present | `internal/dns/fakedns`, `internal/security/bloom` |
| `smux` | `mux-and-reliability` | `integrated` | present | `internal/mux`, `internal/transport/uqsp/carrier` |
| `kcp-go` | `udp-reliability` | `integrated` | present | `internal/transport/kcpbase`, `internal/transport/batch` |
| `kcptun` | `udp-reliability` | `integrated` | present | `internal/transport/kcpmux`, `internal/transport/kcputil` |
| `qtun` | `4d-udp-quic` | `verify_only` | present | `internal/transport/quicmux`, `internal/crypto/qpp` |
| `juicity` | `4d-udp-quic` | `verify_only` | present | `internal/transport/quicmux`, `internal/transport/uqsp` |
| `ocserv` | `4e-cstp-dtls-http` | `integrated` | present | `internal/transport/uqsp/behavior/cstp.go`, `internal/transport/anyconnect` |
| `openconnect` | `4e-cstp-dtls-http` | `integrated` | present | `internal/transport/uqsp/behavior/cstp.go`, `internal/transport/dtls` |
| `TrustTunnel` | `4e-cstp-dtls-http` | `integrated` | present | `internal/transport/trusttunnel`, `internal/transport/uqsp/carrier/trusttunnel.go` |
| `amnezia-client` | `awg-faketcp` | `integrated` | present | `internal/transport/wireguard/junk.go`, `internal/transport/uqsp/behavior/awg.go` |
| `udp2raw` | `awg-faketcp` | `integrated` | present | `internal/transport/faketcp`, `internal/transport/icmptun` |
| `lyrebird` | `fronting-obfuscation-rendezvous` | `integrated` | present | `internal/transport/uqsp/behavior/obfs4.go`, `internal/transport/psiphon/meek.go` |
| `psiphon-tunnel-core` | `fronting-obfuscation-rendezvous` | `integrated` | present | `internal/transport/psiphon` |
| `conjure` | `fronting-obfuscation-rendezvous` | `verify_only` | present | `internal/transport/uqsp/behavior/domainfront.go`, `internal/transport/uqsp/reverse.go` |
| `snowflake` | `fronting-obfuscation-rendezvous` | `verify_only` | present | `internal/transport/uqsp/reverse.go`, `internal/transport/psiphon/meek.go` |
| `haproxy` | `fronting-obfuscation-rendezvous` | `verify_only` | present | `internal/transport/uqsp/behavior/domainfront.go`, `internal/transport/tlsmux` |
| `dae` | `routing-policy` | `verify_only` | present | `internal/routing`, `internal/transport/underlay` |
| `mihomo` | `routing-policy` | `verify_only` | present | `internal/routing`, `internal/config` |
| `EasyTier` | `topology-routing` | `out_of_scope_l3` | present | `internal/tun`, `internal/routing` |
| `VortexL2` | `topology-routing` | `out_of_scope_l3` | present | `internal/tun`, `internal/routing` |
