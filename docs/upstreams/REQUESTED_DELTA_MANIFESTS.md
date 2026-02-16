# Requested Upstream Delta Manifests (2026-02-16)

Scope: L3/TUN-impacting runtime deltas only. Non-runtime docs/chore/release-only changes are deferred or dropped.
Baseline: current workspace snapshot with `sources/*` as authoritative upstream mirror.

## Tunnel (`db8c094`)
Destination mapping: `internal/transport/uqsp/reverse.go`, `internal/transport/uqsp/runtime_builder.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| runtime safety/diagnostics hardening | reliability | integrate | aligns with reverse reconnect guard rails |
| KCP block default to AEAD mode | security | integrate | consistent with stricter tunnel baseline |
| profile/default tuning updates | performance | defer | UI profile specifics kept in operator layer |
| source build mirror changes | ops | drop | non-runtime L3 impact |

## psiphon-tunnel-core (`a680f45b`)
Destination mapping: `internal/tlsutil/front_pool.go`, `internal/transport/uqsp/carrier/tlsdial.go`, `internal/transport/uqsp/behavior/domainfront.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| in-proxy performance improvements | performance | integrate | folded into front-pool scoring and ordering |
| Noise session cache fix | reliability | integrate | maps to session reuse stability paths |
| split-mode counter race fix | reliability | integrate | reflected in concurrency-safe accounting |
| DTLS AEAD nonce backport | security | defer | tracked for DTLS-specific hardening pass |

## v2ray-core (`268064bc`)
Destination mapping: `internal/compat/xray`, `internal/transport/uqsp/variant_builder.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| sticky leastping choice | reliability | integrate | mapped to deterministic front selection |
| HTTP upgrade stuck fix | reliability | integrate | reflected in TLS+/HTTP+ dial path retries |
| release/version/dependency bumps | ops | drop | no direct L3 runtime extraction |

## shadowsocks-rust (`9115c5b4`)
Destination mapping: `internal/dns/fakedns`, `internal/security/replay`, `internal/security/bloom`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| runtime dependency correctness (rand/futures) | reliability | integrate | informs replay/fakedns robustness constraints |
| misc dependency bumps | ops | defer | monitor only |
| typo/chore updates | ops | drop | non-runtime |

## sing-box (`80460604`)
Destination mapping: `internal/compat/singbox`, `internal/transport/shadowtls`, `internal/transport/quicmux`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| TUIC UDP context fix | reliability | integrate | folded into UDP+ control/session wiring |
| naive padding fix | stealth/anti-DPI | integrate | mapped to look-alike/padding behavior |
| WireGuard GSO fallback fix | reliability | defer | not primary L3 tunnel path in StealthLink |
| release/version/FFI additions | ops | drop | out of L3 scope |

## EasyTier (`fe4e779`)
Destination mapping: `internal/transport/underlay/path_policy_dialer.go`, `internal/transport/racing`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| QUIC peer URL port-0 panic fix | reliability | integrate | hardens candidate dial/race path |
| tun fd force-set reliability fix | reliability | integrate | aligns with rerace-on-failure behavior |
| faketcp feature separation | ops | defer | packaging-level, low immediate L3 impact |
| web/registration/localization changes | ops | drop | non-runtime L3 |

## paqctl (`361235d`)
Destination mapping: `scripts/stealthlink-ctl`, `internal/ctltest/firewall_script_test.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| Fedora/firewalld support | ops | integrate | extends firewall orchestration coverage |
| client-side firewall rule fixes | reliability | integrate | mapped to apply/remove parity tests |
| menu/update UX changes | ops | defer | low impact to core runtime |
| panel detection quirks | ops | drop | control-plane UX only |

## daggerConnect (`4be7470`)
Destination mapping: `internal/transport/uqsp/reverse.go`, `internal/transport/underlay`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| reverse-init orchestration pattern | reliability | integrate | already reflected in reverse-first control path |
| README/setup script edits | ops | drop | non-runtime |

## paqet (`ccadb02`)
Destination mapping: `internal/transport/rawtcp`, `internal/transport/packet_guard.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| unified socket for ping/dump | reliability | integrate | informs raw-family socket lifecycle |
| concurrent read buffer invalidation fix | reliability | integrate | mapped into raw packet reader hardening |
| nil addr handling in read path | reliability | integrate | improves defensive packet decode behavior |
| build pipeline/dependency chores | ops | defer | no immediate L3 extraction |

## haproxy (`cb63e899d`)
Destination mapping: `internal/tlsutil/front_pool.go`, `internal/transport/uqsp/carrier/tlsdial.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| LB ordering/scoring techniques | reliability | integrate | used for front candidate ranking/failover |
| deviceatlas-focused maintenance commits | ops | drop | unrelated to L3 tunnel runtime |

## tuic (`635856e`)
Destination mapping: `internal/transport/quicmux`, `internal/transport/uqsp/control.go`

| Delta | Class | Decision | Notes |
|---|---|---|---|
| BBR3 congestion support | performance | integrate | folded into UDP+ CC behavior surface |
| async DNS query performance | performance | integrate | mapped to UDP+ control path responsiveness |
| client SOCKS proxy option | ops | defer | not part of in-core tunnel runtime |
| typo/chore/release plumbing | ops | drop | non-runtime |
