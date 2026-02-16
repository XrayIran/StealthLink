# Upstream Feature Map (Technique-Only, Snapshot-Based)

This document maps requested upstream snapshots under `sources/` to StealthLink's L3-only (TUN) architecture and the five canonical UQSP mode profiles (HTTP+-TLS). This is technique extraction only; no wire-interop guarantees are made with upstream ecosystems.

Decision-log companion: `docs/upstreams/REQUESTED_DELTA_MANIFESTS.md` (integrate/defer/drop outcomes for the requested 11 upstreams).

## Requested Set Closure (Wired Evidence)

| Upstream | Status | Wired evidence (runtime reachability) | Tests that prove wiring/behavior |
|---|---|---|---|
| `conjure` | integrated (technique-only) | `internal/transport/uqsp/behavior/domainfront.go` calls `phantom.NewPool(...)` and exports `ConnectIPCandidates` into `tlsutil.FrontDialOptions` | `internal/transport/phantom/pool_test.go`, `internal/transport/uqsp/behavior/domainfront_test.go` |
| `daggerConnect` | integrated (pattern extraction) | `internal/transport/uqsp/reverse.go` implements reverse-init orchestration and is used by UQSP runtime | `internal/transport/uqsp/reverse_unit_test.go`, `internal/transport/uqsp/unified_reverse_underlay_test.go` |
| `snowflake` | integrated (technique-only) | `internal/transport/uqsp/reverse.go` constructs `snowflake.BrokerRendezvousClient` via rendezvous interface | `internal/transport/snowflake/rendezvous_client_test.go`, `internal/transport/uqsp/reverse_rendezvous_test.go` |
| `Tunnel` | integrated (pattern extraction) | Reverse-init mode is configured/validated in UQSP and shipped as examples | `test/integration/reverse_mode_test.go` (integration) |
| `psiphon-tunnel-core` | integrated (algorithm extraction) | `internal/transport/uqsp/carrier/tlsdial.go` uses `tlsutil.OrderConnectIPCandidates` and reports results via `tlsutil.ReportConnectIPResult` | `internal/tlsutil/front_pool_test.go`, `internal/transport/uqsp/carrier/tlsdial_connectip_test.go` |
| `paqet` | integrated (technique-only) | Carrier `rawtcp` is selectable and implemented via `internal/transport/rawtcp` and UQSP carrier wrappers | `internal/transport/rawtcp/packet_conn_test.go`, `internal/transport/rawtcp/recv_handle_test.go` |
| `paqctl` | integrated (ops technique-only) | `scripts/stealthlink-ctl` firewall apply/remove/rollback is the operator surface for raw-family carriers | `internal/ctltest/firewall_script_test.go` |
| `EasyTier` | integrated (L3 techniques only) | `internal/transport/uqsp/variant_builder.go` wires `underlay.PathPolicyDialer` when `transport.uqsp.path_policy.*` is enabled | `internal/transport/underlay/path_policy_dialer_test.go` |
| `lyrebird` | integrated (technique-only) | `internal/transport/uqsp/behavior/obfs4.go` is an overlay and is auto-enabled by TCP+ profile when seed/node id is provided | `internal/transport/uqsp/behavior/obfs4_test.go` |
| `webtunnel` | integrated (technique-only) | Carrier `webtunnel` is selectable via UQSP carrier registry and implemented in `internal/transport/uqsp/carrier/webtunnel.go` | `internal/transport/uqsp/carrier/webtunnel_test.go`, `internal/transport/uqsp/carrier/roundtrip_test.go` |

## conjure

Status: integrated (technique-only; no Conjure network interop claim)

### Techniques extracted
- Deterministic "phantom endpoint" pool generation from a shared secret
- Pool rotation for diversified `connect_ip` candidates
- Optional epoch seeding for operator-controlled pool reshuffles (`epoch_seed`)

### Where implemented
- `internal/transport/phantom/pool.go`
- `internal/transport/uqsp/behavior/domainfront.go`
- `internal/transport/uqsp/variant_builder.go`
- `internal/config/uqsp.go`

### Wired evidence (call sites)
- Phantom pool is created and candidates are exported to the TLS dial context: `internal/transport/uqsp/behavior/domainfront.go` (`phantom.NewPool(...)`, `PrepareContext(...)`)
- Candidate ordering and reporting is performed during dialing: `internal/transport/uqsp/carrier/tlsdial.go` (`OrderConnectIPCandidates(...)`, `ReportConnectIPResult(...)`)

### How to enable
- `transport.uqsp.behaviors.domainfront.enabled: true`
- `transport.uqsp.behaviors.domainfront.phantom.enabled: true`
- `transport.uqsp.behaviors.domainfront.phantom.shared_secret: ...`
- Optional: `transport.uqsp.behaviors.domainfront.phantom.subnet_prefix_v4`, `...subnet_prefix_v6`, `...pool_size`, `epoch_seed`
- Defaults: off (requires explicit `phantom.enabled: true`)

### Tests that prove it
- `internal/transport/phantom/pool_test.go`
- `internal/transport/uqsp/behavior/domainfront_test.go`

## daggerConnect

Status: integrated (pattern extraction)

### Techniques extracted
- Reverse-init operational patterns (server-initiated connectivity, reconnect/backoff)
- HTTP mimicry consolidation via shared TLS dial path (uTLS fingerprinting, fronting context)

### Where implemented
- `internal/transport/uqsp/reverse.go`
- `internal/transport/uqsp/variant_builder.go`
- `internal/transport/uqsp/unified.go`
- `internal/transport/uqsp/carrier/xhttp.go`
- `internal/transport/uqsp/carrier/webtunnel.go`

### Wired evidence (call sites)
- Reverse-init orchestration entrypoint is `internal/transport/uqsp/reverse.go` and is invoked by UQSP runtime initialization (`Start(...)` / dialer+listener wiring)
- Underlay routing for reverse-init dials is mediated by `internal/transport/underlay` via injected dialer in `internal/transport/uqsp/variant_builder.go`

### How to enable
- Reverse-init:
  - `transport.uqsp.reverse.enabled: true`
  - `transport.uqsp.reverse.auth_token: ...`
  - Gateway defaults to reverse dialer; agent defaults to reverse listener (`internal/config/variant.go`)
- HTTP mimicry:
  - Set carrier `xhttp` or `webtunnel` and keep `tls_fingerprint` at defaults (or set explicitly)

### Tests that prove it
- `internal/transport/uqsp/reverse_unit_test.go`
- `internal/transport/uqsp/reverse_integration_test.go` (build tag: `integration`)
- `test/integration/reverse_mode_test.go` (build tag: `integration`)

## snowflake

Status: integrated (technique-only broker rendezvous; no Snowflake WebRTC interop claim)

### Techniques extracted
- Broker rendezvous concept and polling/backoff patterns (control-plane assist)

### Where implemented
- `internal/config/uqsp.go`
- `internal/transport/snowflake/rendezvous_client.go`
- `internal/transport/uqsp/rendezvous/rendezvous.go`
- `internal/transport/uqsp/reverse.go`

### Wired evidence (call sites)
- Reverse-init rendezvous client is constructed in `internal/transport/uqsp/reverse.go` (`rendezvousClient()` -> `snowflake.NewBrokerRendezvousClient(...)`)
- Publish/poll calls flow through the `internal/transport/uqsp/rendezvous` interface into the Snowflake technique client

### How to enable
- `transport.uqsp.reverse.enabled: true`
- `transport.uqsp.reverse.rendezvous.enabled: true`
- `transport.uqsp.reverse.rendezvous.broker_url: "https://broker.example.com/rv"`
- Optional: `transport.uqsp.reverse.rendezvous.front_domain`, `...utls_fingerprint`
- Defaults: off (requires explicit `rendezvous.enabled: true`)

### Tests that prove it
- `internal/transport/uqsp/reverse_rendezvous_test.go`
- `internal/transport/snowflake/rendezvous_client_test.go`

## Tunnel

Status: integrated (pattern extraction)

### Techniques extracted
- Tunnel orchestration patterns and operational expectations around reverse connectivity

### Where implemented
- `internal/transport/uqsp/reverse.go`
- `internal/transport/uqsp/variant_profile.go`

### Wired evidence (call sites)
- Reverse-init is implemented by `internal/transport/uqsp/reverse.go` and enabled by `transport.uqsp.reverse.enabled`
- Profile defaults and examples align gateway listener vs agent dial roles: `internal/transport/uqsp/variant_profile.go`, `examples/uqsp-reverse-HTTP+.yaml`, `examples/uqsp-reverse-TLS.yaml`

### How to enable
- Use UQSP variants HTTP+-TLS and set `transport.uqsp.reverse.enabled: true` where reverse-init is desired.
- Examples:
  - `examples/uqsp-reverse-HTTP+.yaml`
  - `examples/uqsp-reverse-TLS.yaml`

### Tests that prove it
- `test/integration/reverse_mode_test.go` (build tag: `integration`)

## psiphon-tunnel-core

Status: integrated (algorithm extraction; no Psiphon client/server shipped)

### Techniques extracted
- Fronting host rotation + health scoring (failure-driven demotion)
- Retry/backoff patterns for hostile networks

### Where implemented
- `internal/tlsutil/front_pool.go`
- `internal/transport/uqsp/carrier/tlsdial.go`
- `internal/transport/uqsp/behavior/domainfront.go`

### Wired evidence (call sites)
- Front domain health scoring and cooldown is implemented in `internal/tlsutil/front_pool.go`
- Connect-IP candidate ordering/reporting is used by UQSP TLS dialer: `internal/transport/uqsp/carrier/tlsdial.go`

### How to enable
- `transport.uqsp.behaviors.domainfront.enabled: true`
- Optional: `transport.uqsp.behaviors.domainfront.failover_domains: [...]`
- Defaults: scoring is conservative; it only reorders candidates when a primary accumulates failures.

### Tests that prove it
- `internal/tlsutil/front_pool_test.go`

## paqet

Status: integrated (technique-only)

### Techniques extracted
- Raw packet transport patterns for censorship resistance
- Host firewall expectations for raw TCP camouflage

### Where implemented
- `internal/transport/rawtcp`
- `scripts/stealthlink-ctl`

### Wired evidence (call sites)
- Carrier `rawtcp` is selected via UQSP carrier registry and wraps `internal/transport/rawtcp`: `internal/transport/uqsp/carrier/rawtcp.go`, `internal/transport/uqsp/carrier/registry.go`
- Firewall expectations are enforced via operator tooling: `scripts/stealthlink-ctl`

### How to enable
- Use carrier `rawtcp` (variant TCP+ default): `transport.uqsp.carrier.type: rawtcp`
- Apply firewall hardening on both peers: `stealthlink-ctl firewall apply gateway` and `stealthlink-ctl firewall apply agent`

### Tests that prove it
- `internal/transport/rawtcp/packet_conn_test.go`
- `internal/transport/rawtcp/recv_handle_test.go`
- `internal/ctltest/firewall_script_test.go`

## paqctl

Status: integrated (ops technique-only)

### Techniques extracted
- Operator-facing firewall rule expectations for raw transports (NOTRACK, RST drop, rollback)

### Where implemented
- `scripts/stealthlink-ctl`

### Wired evidence (call sites)
- Firewall apply/remove is the supported ops surface and is invoked by operators (not in-process): `scripts/stealthlink-ctl`

### How to enable
- `stealthlink-ctl firewall apply gateway|agent` (auto-detects carrier and applies raw hardening when needed)

### Tests that prove it
- `internal/ctltest/firewall_script_test.go`

## EasyTier

Status: integrated (L3 techniques only; no L2 mesh, no relay/NAT traversal claims)

### Techniques extracted
- Intelligent path selection between underlays (direct vs WARP) with failover
- Connection racing and sticky winner selection (failure-threshold re-race)

### Where implemented
- `internal/config/uqsp.go` (public config: `transport.uqsp.path_policy.*`)
- `internal/transport/underlay/path_policy_dialer.go`
- `internal/transport/racing/racing.go`
- `internal/transport/uqsp/variant_builder.go` (wiring into runtime underlay)

### Wired evidence (call sites)
- Underlay dialer is swapped to `PathPolicyDialer` when enabled: `internal/transport/uqsp/variant_builder.go`

### How to enable
- `transport.uqsp.path_policy.mode: sticky_race` (or `race`)
- `transport.uqsp.path_policy.candidates: [{ underlay: direct }, { underlay: warp }]`

### Tests that prove it
- `internal/transport/underlay/path_policy_dialer_test.go`

## lyrebird

Status: integrated (technique-only)

### Techniques extracted
- obfs4-style obfuscation

### Where implemented
- `internal/transport/uqsp/behavior/obfs4.go`

### Wired evidence (call sites)
- Obfs4 overlay participates in UQSP overlay chain for mode TCP+: `internal/transport/uqsp/raw_overlays.go`, `internal/transport/uqsp/variant_profile.go`

### How to enable
- `transport.uqsp.behaviors.obfs4.enabled: true`
- Variant TCP+ profile will also enable obfs4 automatically when `node_id` or `seed` is present: `internal/transport/uqsp/variant_profile.go`

### Tests that prove it
- `internal/transport/uqsp/behavior/obfs4_test.go`

## webtunnel

Status: integrated (technique-only)

### Techniques extracted
- HTTP/1.1 Upgrade tunneling
- HTTP/2 CONNECT tunneling
- uTLS fingerprinting defaults suitable for browser mimicry

### Where implemented
- `internal/transport/uqsp/carrier/webtunnel.go`
- `internal/transport/uqsp/carrier/webtunnel_test.go`
- `internal/config/uqsp.go`

### Wired evidence (call sites)
- Carrier is selectable via `transport.uqsp.carrier.type: webtunnel` and constructed in `internal/transport/uqsp/carrier/registry.go`

### How to enable
- `transport.uqsp.carrier.type: webtunnel`
- `transport.uqsp.carrier.webtunnel.server: "host:port"`
- `transport.uqsp.carrier.webtunnel.path: "/tunnel"`
- `transport.uqsp.carrier.webtunnel.version: "h1"|"h2"`
- Defaults: `tls_fingerprint` defaults to `chrome_auto` via `Config.ApplyUQSPDefaults()`

### Tests that prove it
- `internal/transport/uqsp/carrier/webtunnel_test.go`
- `internal/transport/uqsp/carrier/roundtrip_test.go`
- `internal/config/uqsp_validation_test.go`
