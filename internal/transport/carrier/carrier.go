package carrier

import (
	"context"
	"io"
	"net"
	"time"
)

// Carrier defines the interface for StealthLink transport modes.
// All five modes (4a-4e) implement this interface with mode-specific behavior.
type Carrier interface {
	// Dial establishes an outbound connection to the specified address.
	// The address format is carrier-specific (e.g., "host:port" for TCP-based carriers).
	// Returns a Session on success, or an error if the connection fails.
	Dial(ctx context.Context, addr string) (Session, error)

	// Listen starts listening for inbound connections on the specified address.
	// The address format is carrier-specific (e.g., ":port" for TCP-based carriers).
	// Returns a Listener on success, or an error if binding fails.
	Listen(addr string) (Listener, error)

	// Capabilities returns the capability flags for this carrier implementation.
	// This allows callers to query what features the carrier supports.
	Capabilities() CarrierCapabilities

	// Configure applies configuration to the carrier.
	// This must be called before Dial or Listen.
	// Returns an error if the configuration is invalid or incompatible with the carrier.
	Configure(config CarrierConfig) error

	// Stats returns current statistics for the carrier.
	// This provides observability into carrier performance and health.
	Stats() CarrierStats
}

// Session represents an established connection through a carrier.
// It provides bidirectional data transfer with metadata access.
type Session interface {
	io.ReadWriteCloser

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	// SetDeadline sets the read and write deadlines.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the read deadline.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the write deadline.
	SetWriteDeadline(t time.Time) error
}

// Listener accepts inbound connections from a carrier.
type Listener interface {
	// Accept waits for and returns the next connection.
	// Returns an error if the listener is closed or encounters an error.
	Accept() (Session, error)

	// Close closes the listener, refusing new connections.
	// Any blocked Accept operations will return an error.
	Close() error

	// Addr returns the listener's network address.
	Addr() net.Addr
}
