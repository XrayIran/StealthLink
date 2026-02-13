// Package singbox provides optional wire format compatibility with sing-box.
//
// # Overview
//
// This package implements an adapter layer that translates between StealthLink's
// native wire format and sing-box's protocol specifications. The adapter is
// OPTIONAL and should only be enabled when interoperability with upstream
// sing-box clients or servers is required.
//
// # Supported Protocols
//
// - AnyTLS: Compatible with sing-box v1.8.0+ AnyTLS transport
//
// # Usage
//
// Enable the adapter in configuration:
//
//	transport:
//	  compat_mode: singbox
//	  singbox:
//	    enabled: true
//	    mode: anytls
//
// # Wire Format Translation
//
// The adapter performs bidirectional translation:
//
//   - Outbound: StealthLink frames → sing-box wire format
//   - Inbound: sing-box wire format → StealthLink frames
//
// # Multiplexing Compatibility
//
// The adapter handles sing-box's multiplexing scheme differences:
//
//   - Translates between StealthLink's smux and sing-box's mux protocol
//   - Preserves stream semantics and flow control
//   - Maintains padding scheme compatibility
//
// # Performance Considerations
//
// The adapter adds minimal overhead (frame header translation only).
// Padding schemes are preserved without modification.
//
// # Compatibility Matrix
//
//   - sing-box v1.8.0+: Full AnyTLS compatibility with mux translation
//   - sing-box v1.7.x: Limited compatibility (basic TLS only)
//   - sing-box < v1.7: Not supported
//
// # Important Notes
//
//   - This adapter is NOT required for StealthLink-to-StealthLink communication
//   - StealthLink's native modes (4a-4e) are the canonical wire formats
//   - Use this adapter ONLY when upstream interoperability is needed
//   - The adapter preserves padding schemes but may adjust mux behavior
//   - Mux behavior parity is maintained (not just basic connect)
package singbox
