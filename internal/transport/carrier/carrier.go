// Package carrier provides the carrier abstraction for transport layer.
// Carriers are responsible for the underlying network transport (TCP, QUIC, KCP, etc.)
package carrier

import (
	"context"
	"net"
)

// Capability represents a carrier capability bitmask
type Capability uint64

const (
	// CapabilityReliable indicates ordered, reliable delivery
	CapabilityReliable Capability = 1 << iota
	// CapabilityOrdered indicates in-order delivery
	CapabilityOrdered
	// CapabilityDatagram indicates datagram (message) semantics
	CapabilityDatagram
	// CapabilityStream indicates stream semantics
	CapabilityStream
	// CapabilityCongestionControl indicates built-in congestion control
	CapabilityCongestionControl
	// CapabilityFlowControl indicates built-in flow control
	CapabilityFlowControl
	// CapabilityNATTraversal indicates NAT traversal support
	CapabilityNATTraversal
	// CapabilityObfuscation indicates built-in obfuscation
	CapabilityObfuscation
	// CapabilityMultipath indicates multipath support
	CapabilityMultipath
	// CapabilityZeroRTT indicates 0-RTT connection establishment
	CapabilityZeroRTT
	// CapabilityMobility indicates connection migration support
	CapabilityMobility
)

// String returns a human-readable capability name
func (c Capability) String() string {
	switch c {
	case CapabilityReliable:
		return "reliable"
	case CapabilityOrdered:
		return "ordered"
	case CapabilityDatagram:
		return "datagram"
	case CapabilityStream:
		return "stream"
	case CapabilityCongestionControl:
		return "congestion_control"
	case CapabilityFlowControl:
		return "flow_control"
	case CapabilityNATTraversal:
		return "nat_traversal"
	case CapabilityObfuscation:
		return "obfuscation"
	case CapabilityMultipath:
		return "multipath"
	case CapabilityZeroRTT:
		return "0rtt"
	case CapabilityMobility:
		return "mobility"
	default:
		return "unknown"
	}
}

// Has checks if a capability is set
func (c Capability) Has(other Capability) bool {
	return c&other != 0
}

// Info describes a carrier's capabilities and properties
type Info struct {
	// Name is the carrier identifier
	Name string
	// Capabilities is the OR of all supported capabilities
	Capabilities Capability
	// DefaultPort is the default port for this carrier
	DefaultPort int
	// Overhead is the protocol overhead in bytes per packet
	Overhead int
	// MTU is the maximum transmission unit
	MTU int
	// Supports indicates which features are supported
	Supports struct {
		// Multiplexing indicates if the carrier supports native multiplexing
		Multiplexing bool
		// Encryption indicates if the carrier supports native encryption
		Encryption bool
		// Authentication indicates if the carrier supports native authentication
		Authentication bool
	}
}

// Dialer creates outbound connections
type Dialer interface {
	// Dial establishes a connection to the given address
	Dial(ctx context.Context, addr string) (net.Conn, error)
	// Info returns carrier information
	Info() Info
}

// Listener accepts inbound connections
type Listener interface {
	// Accept waits for and returns the next connection
	Accept() (net.Conn, error)
	// Close closes the listener
	Close() error
	// Addr returns the listener's network address
	Addr() net.Addr
	// Info returns carrier information
	Info() Info
}

// Carrier is the base interface for all transport carriers
type Carrier interface {
	// Name returns the carrier name
	Name() string
	// Capabilities returns the carrier capabilities
	Capabilities() Capability
	// Info returns carrier information
	Info() Info
	// CreateDialer creates a dialer with the given configuration
	CreateDialer(config map[string]interface{}) (Dialer, error)
	// CreateListener creates a listener with the given configuration
	CreateListener(addr string, config map[string]interface{}) (Listener, error)
}

// BaseCarrier provides common functionality for carriers
type BaseCarrier struct {
	name         string
	capabilities Capability
	info         Info
}

// NewBaseCarrier creates a new base carrier
func NewBaseCarrier(name string, caps Capability) BaseCarrier {
	return BaseCarrier{
		name:         name,
		capabilities: caps,
		info: Info{
			Name:         name,
			Capabilities: caps,
			MTU:          1500,
		},
	}
}

// Name returns the carrier name
func (c *BaseCarrier) Name() string {
	return c.name
}

// Capabilities returns the carrier capabilities
func (c *BaseCarrier) Capabilities() Capability {
	return c.capabilities
}

// Info returns the carrier info
func (c *BaseCarrier) Info() Info {
	return c.info
}

// SetInfo updates the carrier info
func (c *BaseCarrier) SetInfo(info Info) {
	c.info = info
}

// Config is the common carrier configuration
type Config struct {
	// Address is the bind/connect address
	Address string
	// Port is the bind/connect port
	Port int
	// Timeout is the connection timeout
	Timeout int // seconds
	// Keepalive is the keepalive interval
	Keepalive int // seconds
	// MTU is the maximum transmission unit
	MTU int
	// BufferSize is the send/receive buffer size
	BufferSize int
}

// Conn wraps a network connection with carrier metadata
type Conn struct {
	net.Conn
	// Carrier is the carrier that created this connection
	Carrier string
	// LocalMTU is the MTU for this connection
	LocalMTU int
	// RemoteMTU is the peer's MTU
	RemoteMTU int
}

// WrapConn wraps a net.Conn with carrier metadata
func WrapConn(conn net.Conn, carrier string, mtu int) *Conn {
	return &Conn{
		Conn:      conn,
		Carrier:   carrier,
		LocalMTU:  mtu,
		RemoteMTU: mtu,
	}
}

// PacketConn is a packet-oriented connection
type PacketConn interface {
	net.PacketConn
	// SetReadBuffer sets the read buffer size
	SetReadBuffer(bytes int) error
	// SetWriteBuffer sets the write buffer size
	SetWriteBuffer(bytes int) error
}

// StreamConn is a stream-oriented connection with additional metadata
type StreamConn interface {
	net.Conn
	// StreamID returns the stream identifier (for multiplexed connections)
	StreamID() uint64
	// SetPriority sets the stream priority
	SetPriority(priority int) error
}

// CongestionControl represents a congestion control algorithm
type CongestionControl string

const (
	// CongestionControlCubic uses CUBIC algorithm
	CongestionControlCubic CongestionControl = "cubic"
	// CongestionControlBBR uses BBR algorithm
	CongestionControlBBR CongestionControl = "bbr"
	// CongestionControlReno uses Reno algorithm
	CongestionControlReno CongestionControl = "reno"
	// CongestionControlBrutal uses Brutal algorithm (aggressive)
	CongestionControlBrutal CongestionControl = "brutal"
)

// CongestionConfig holds congestion control configuration
type CongestionConfig struct {
	// Algorithm is the congestion control algorithm
	Algorithm CongestionControl
	// InitialWindow is the initial congestion window
	InitialWindow int
	// MinWindow is the minimum congestion window
	MinWindow int
	// MaxWindow is the maximum congestion window
	MaxWindow int
	// Pacing enables pacing
	Pacing bool
}

// DefaultCongestionConfig returns the default congestion control config
func DefaultCongestionConfig() CongestionConfig {
	return CongestionConfig{
		Algorithm:     CongestionControlBBR,
		InitialWindow: 10,
		MinWindow:     2,
		MaxWindow:     1000,
		Pacing:        true,
	}
}
