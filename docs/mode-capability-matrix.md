# Mode Capability Matrix (HTTP+-TLS)

This matrix is keyed to StealthLink capabilities (not upstream protocol names).

| Capability | HTTP+ | TCP+ | TLS+ | UDP+ | TLS |
|---|---:|---:|---:|---:|---:|
| Streams (smux multiplexed streams) | yes | yes | yes | yes | yes |
| Native datagrams (QUIC DATAGRAM) | no | no | no | yes | no |
| Capsules (CONNECT-UDP / CONNECT-IP) | no | no | no | yes | no |
| Reverse-connect topology | yes (policy) | yes (policy) | yes (policy) | yes (policy) | yes (policy) |
| WARP underlay dialer | yes (policy) | yes (policy) | yes (policy) | yes (policy) | yes (policy) |

Notes:
- `tun.transport=auto` will use datagrams when the active UQSP session supports native datagrams; otherwise it falls back to stream-framed packets.
- Reverse-connect and WARP are policy-controlled features; enablement can be scoped globally or per-variant.

## Runtime Scope Notes

- `transport.uqsp.runtime.mode=legacy` is deprecated; `unified` is the supported runtime path for new deployments.
- `transport.uqsp.runtime.max_concurrent_dials` defaults to `16` and bounds concurrent outbound runtime dial attempts.
- Reverse auth now uses a versioned frame with timestamp + nonce replay protection (strictly validated on listener side).

