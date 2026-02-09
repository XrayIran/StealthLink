// Package carrier provides the underlying transport abstraction for UQSP.
// It allows UQSP to use different transport carriers (QUIC, TrustTunnel, RawTCP, ICMPTun)
// while maintaining a single runtime entry point.
package carrier

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// Carrier is the underlying transport for UQSP.
// Implementations provide different transport mechanisms while presenting
// a unified interface to the UQSP runtime.
type Carrier interface {
	// Network returns the network type (tcp, udp, icmp, quic)
	Network() string

	// Dial establishes a connection to the address
	Dial(ctx context.Context, addr string) (net.Conn, error)

	// Listen creates a listener for incoming connections
	Listen(addr string) (Listener, error)

	// Close closes the carrier
	Close() error

	// IsAvailable returns whether this carrier is available on the current platform
	IsAvailable() bool
}

// Listener is a carrier-specific listener
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// ConnWrapper wraps a net.Conn to provide additional metadata
type ConnWrapper struct {
	net.Conn
	NetworkType string
}

// Network returns the network type for this connection
func (c *ConnWrapper) Network() string {
	return c.NetworkType
}

// SessionConn wraps a smux session to provide net.Conn interface
type SessionConn struct {
	session    *smux.Session
	stream     net.Conn
	mu         sync.Mutex
	localAddr  net.Addr
	remoteAddr net.Addr
}

// Ensure SessionConn implements net.Conn
var _ net.Conn = (*SessionConn)(nil)

func (c *SessionConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.stream == nil {
		var err error
		c.stream, err = c.session.OpenStream()
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
	}
	c.mu.Unlock()
	return c.stream.Read(p)
}

func (c *SessionConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.stream == nil {
		var err error
		c.stream, err = c.session.OpenStream()
		if err != nil {
			c.mu.Unlock()
			return 0, err
		}
	}
	c.mu.Unlock()
	return c.stream.Write(p)
}

func (c *SessionConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		_ = c.stream.Close()
	}
	return c.session.Close()
}

func (c *SessionConn) LocalAddr() net.Addr {
	if c.stream != nil {
		return c.stream.LocalAddr()
	}
	return c.localAddr
}

func (c *SessionConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		return c.stream.RemoteAddr()
	}
	return c.remoteAddr
}

func (c *SessionConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *SessionConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *SessionConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}
