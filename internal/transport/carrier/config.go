package carrier

import "time"

// CarrierConfig is the common configuration structure for all carriers.
// It provides mode-specific settings and cross-cutting concerns like MTU and congestion control.
type CarrierConfig struct {
	// Mode specifies which StealthLink mode to use.
	// Valid values: "HTTP+" | "TCP+" | "TLS+" | "UDP+" | "TLS"
	// Each mode has different characteristics (see mode profiles in design doc).
	Mode string

	// MTU is the base Maximum Transmission Unit in bytes.
	// The effective MTU will be reduced by mode-specific overhead.
	// Default: 1500 bytes (standard Ethernet MTU).
	MTU int

	// CongestionControl specifies the congestion control algorithm.
	// Valid values: "cubic" | "bbr" | "brutal"
	// - cubic: Standard TCP congestion control (default for TCP-based modes)
	// - bbr: Bottleneck Bandwidth and RTT (better for high-latency links)
	// - brutal: Fixed bandwidth (for QUIC mode UDP+)
	CongestionControl string

	// Reliability specifies the reliability layer.
	// Valid values: "none" | "kcp" | "quic"
	// - none: No additional reliability (use for TCP-based carriers)
	// - kcp: KCP reliable UDP protocol
	// - quic: QUIC protocol (built-in reliability)
	Reliability string

	// MuxSettings configures the multiplexing layer.
	MuxSettings MuxConfig

	// RotationPolicy configures connection rotation behavior.
	RotationPolicy RotationConfig

	// PaddingPolicy configures traffic padding for anti-fingerprinting.
	PaddingPolicy PaddingConfig
}

// MuxConfig configures the multiplexing layer (typically smux).
type MuxConfig struct {
	// Enabled indicates if multiplexing is active.
	Enabled bool

	// MaxStreams is the maximum number of concurrent streams per connection.
	// Default: 256
	MaxStreams int

	// StreamBufferSize is the per-stream buffer size in bytes.
	// Default: 65536 (64 KB)
	StreamBufferSize int

	// KeepAliveInterval is the interval for sending keepalive frames.
	// Default: 30 seconds
	KeepAliveInterval time.Duration

	// KeepAliveTimeout is the timeout for keepalive responses.
	// Default: 90 seconds
	KeepAliveTimeout time.Duration
}

// RotationConfig configures connection rotation policies.
// Rotation helps prevent fingerprinting by limiting connection reuse.
type RotationConfig struct {
	// Enabled indicates if rotation is active.
	Enabled bool

	// MaxReuseTimes is the maximum number of times a connection can be reused.
	// After this limit, the connection is rotated (closed and replaced).
	// Default: 32 (for mode HTTP+ Xmux)
	MaxReuseTimes int

	// MaxRequestTimes is the maximum number of requests per connection.
	// Applies to HTTP-based carriers (modes HTTP+, TLS).
	// Default: 100
	MaxRequestTimes int

	// MaxLifetime is the maximum connection lifetime.
	// After this duration, the connection is rotated.
	// Default: 3600 seconds (1 hour)
	MaxLifetime time.Duration

	// DrainTimeout is the maximum time to wait for graceful connection drain.
	// During drain, no new requests are accepted but in-flight requests complete.
	// Default: 30 seconds
	DrainTimeout time.Duration
}

// PaddingConfig configures traffic padding for anti-fingerprinting.
type PaddingConfig struct {
	// Enabled indicates if padding is active.
	Enabled bool

	// Scheme specifies the padding scheme.
	// Valid values: "random" | "fixed" | "burst" | "adaptive"
	// - random: Uniform random padding between Min and Max
	// - fixed: Always use Max padding
	// - burst: Bursty pattern (0, 0, 0, large)
	// - adaptive: Adjust based on traffic patterns
	Scheme string

	// Min is the minimum padding length in bytes.
	// Default: 100
	Min int

	// Max is the maximum padding length in bytes.
	// Default: 900
	Max int

	// Interval is the interval between padding injections.
	// Only applies to cover traffic (not per-packet padding).
	// Default: 1 second
	Interval time.Duration
}

// CarrierStats provides observability into carrier performance and health.
type CarrierStats struct {
	// ConnectionsActive is the current number of active connections.
	ConnectionsActive int64

	// ConnectionsTotal is the total number of connections established.
	ConnectionsTotal int64

	// ConnectionsFailed is the total number of failed connection attempts.
	ConnectionsFailed int64

	// BytesSent is the total number of bytes sent.
	BytesSent uint64

	// BytesReceived is the total number of bytes received.
	BytesReceived uint64

	// PacketsSent is the total number of packets sent (for datagram carriers).
	PacketsSent uint64

	// PacketsReceived is the total number of packets received (for datagram carriers).
	PacketsReceived uint64

	// PacketsLost is the total number of packets lost (for datagram carriers with loss detection).
	PacketsLost uint64

	// RTTMean is the mean round-trip time in milliseconds.
	RTTMean float64

	// RTTP95 is the 95th percentile round-trip time in milliseconds.
	RTTP95 float64

	// RTTP99 is the 99th percentile round-trip time in milliseconds.
	RTTP99 float64
}
