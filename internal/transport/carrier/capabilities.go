package carrier

// CarrierCapabilities describes what features a carrier implementation supports.
// This allows callers to query capabilities and make decisions based on what
// the carrier can do (e.g., whether to use 0-RTT, path migration, etc.).
type CarrierCapabilities struct {
	// StreamOriented indicates if the carrier provides reliable stream semantics.
	// true: TCP-like reliable ordered byte stream (modes 4a, 4c, 4d, 4e)
	// false: Datagram-oriented (mode 4b)
	StreamOriented bool

	// ZeroRTT indicates if the carrier supports 0-RTT connection establishment.
	// This allows sending data in the first packet without waiting for handshake completion.
	// Supported by: TLS 1.3 (modes 4a, 4c), QUIC (mode 4d), HTTP/3 (mode 4e)
	ZeroRTT bool

	// ReplayProtection indicates if the carrier has built-in replay attack protection.
	// This prevents attackers from capturing and replaying packets.
	// Supported by: AEAD encryption (mode 4b), QUIC (mode 4d)
	ReplayProtection bool

	// PathMigration indicates if the carrier supports changing network paths
	// without breaking the connection (e.g., switching from WiFi to cellular).
	// Supported by: QUIC (mode 4d)
	PathMigration bool

	// Multipath indicates if the carrier supports using multiple network paths
	// simultaneously for increased throughput and reliability.
	// Supported by: QUIC with multipath extension (mode 4d)
	Multipath bool

	// ServerInitiated indicates if the carrier supports server-initiated connections
	// (reverse-init mode where server dials out to client).
	// Supported by: All modes (4a-4e) with reverse-init configuration
	ServerInitiated bool

	// Fronting indicates if the carrier supports domain fronting via CDN.
	// This allows hiding the true destination by routing through a CDN.
	// Supported by: Mode 4a (XHTTP + Domain Fronting)
	Fronting bool

	// CoverTraffic indicates if the carrier supports injecting cover/dummy traffic
	// for traffic analysis resistance.
	// Supported by: Modes with padding (4c, 4d)
	CoverTraffic bool
}
