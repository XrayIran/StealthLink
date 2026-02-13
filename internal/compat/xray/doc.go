// Package xray provides optional wire format compatibility with Xray-core.
//
// # Overview
//
// This package implements an adapter layer that translates between StealthLink's
// native wire format and Xray-core's protocol specifications. The adapter is
// OPTIONAL and should only be enabled when interoperability with upstream
// Xray-core clients or servers is required.
//
// # Supported Protocols
//
// - XHTTP (SplitHTTP): Compatible with Xray-core v1.8.0+ SplitHTTP transport
//
// # Usage
//
// Enable the adapter in configuration:
//
//	transport:
//	  compat_mode: xray
//	  xray:
//	    enabled: true
//	    mode: xhttp
//
// # Wire Format Translation
//
// The adapter performs bidirectional translation:
//
//   - Outbound: StealthLink frames → Xray-core wire format
//   - Inbound: Xray-core wire format → StealthLink frames
//
// # Performance Considerations
//
// The adapter adds minimal overhead (frame header translation only).
// No additional encryption or compression is applied.
//
// # Compatibility Matrix
//
//   - Xray-core v1.8.0+: Full XHTTP/SplitHTTP compatibility
//   - Xray-core v1.7.x: Limited compatibility (header placement only)
//   - Xray-core < v1.7: Not supported
//
// # Important Notes
//
//   - **Adapter Required for Xray-core Interop, Not Default**: This adapter is
//     OPTIONAL and disabled by default. Enable it ONLY when you need to connect
//     StealthLink servers to Xray-core clients, or Xray-core servers to StealthLink
//     clients. For StealthLink-to-StealthLink communication, use native modes (4a-4e)
//     which provide better performance and the full feature set.
//   - This adapter is NOT required for StealthLink-to-StealthLink communication
//   - StealthLink's native modes (4a-4e) are the canonical wire formats
//   - Use this adapter ONLY when upstream interoperability is needed
//   - The adapter does not modify security properties (encryption, authentication)
//   - Default configuration: compat_mode: "none" (adapter disabled)
package xray
