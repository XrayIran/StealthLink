package kcpbase

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/xtaci/smux"
)

// Carrier implements the UQSP carrier interface for KCP-based transports.
// It supports multiple modes: standard, brutal, AWG, and DTLS.
type Carrier struct {
	cfg    *Config
	smux   *smux.Config
	ln     *Listener
	closed bool
}

// NewCarrier creates a new KCP carrier
func NewCarrier(cfg *Config, smuxCfg *smux.Config) *Carrier {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Carrier{
		cfg:  cfg,
		smux: smuxCfg,
	}
}

// Network returns "udp" (KCP is UDP-based)
func (c *Carrier) Network() string {
	return "udp"
}

// Dial connects to a KCP server and returns a smux-ready connection
func (c *Carrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := NewDialer(c.cfg, c.smux)

	// Establish KCP connection
	kcpConn, err := dialer.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("kcp dial: %w", err)
	}

	// Create smux session over KCP
	sess, err := smux.Client(kcpConn, c.smux)
	if err != nil {
		kcpConn.Close()
		return nil, fmt.Errorf("smux client: %w", err)
	}

	// Return a connection that wraps the smux session
	return &kcpCarrierConn{
		session: sess,
		conn:    kcpConn,
	}, nil
}

// Listen starts listening for KCP connections
func (c *Carrier) Listen(addr string) (net.Listener, error) {
	ln, err := Listen(addr, c.cfg, c.smux)
	if err != nil {
		return nil, err
	}

	c.ln = ln
	return &kcpCarrierListener{
		ln:   ln,
		smux: c.smux,
	}, nil
}

// Close closes the carrier
func (c *Carrier) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.ln != nil {
		return c.ln.Close()
	}
	return nil
}

// IsAvailable returns true (KCP is always available)
func (c *Carrier) IsAvailable() bool {
	return true
}

// kcpCarrierListener wraps a KCP listener with smux support
type kcpCarrierListener struct {
	ln   *Listener
	smux *smux.Config
}

func (l *kcpCarrierListener) Accept() (net.Conn, error) {
	// Accept KCP connection
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// Create smux server session
	sess, err := smux.Server(conn, l.smux)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smux server: %w", err)
	}

	return &kcpCarrierConn{
		session: sess,
		conn:    conn,
	}, nil
}

func (l *kcpCarrierListener) Close() error {
	return l.ln.Close()
}

func (l *kcpCarrierListener) Addr() net.Addr {
	return l.ln.Addr()
}

// kcpCarrierConn wraps a smux session as a net.Conn
type kcpCarrierConn struct {
	session *smux.Session
	stream  net.Conn
	conn    net.Conn
	closed  bool
}

func (c *kcpCarrierConn) Read(p []byte) (int, error) {
	if c.stream == nil {
		var err error
		c.stream, err = c.session.AcceptStream()
		if err != nil {
			return 0, err
		}
	}
	return c.stream.Read(p)
}

func (c *kcpCarrierConn) Write(p []byte) (int, error) {
	if c.stream == nil {
		var err error
		c.stream, err = c.session.OpenStream()
		if err != nil {
			return 0, err
		}
	}
	return c.stream.Write(p)
}

func (c *kcpCarrierConn) Close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	if c.stream != nil {
		c.stream.Close()
	}
	if c.session != nil {
		c.session.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	return nil
}

func (c *kcpCarrierConn) LocalAddr() net.Addr {
	if c.stream != nil {
		return c.stream.LocalAddr()
	}
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return nil
}

func (c *kcpCarrierConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		return c.stream.RemoteAddr()
	}
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return nil
}

func (c *kcpCarrierConn) SetDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *kcpCarrierConn) SetReadDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *kcpCarrierConn) SetWriteDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

// Ensure kcpCarrierConn implements net.Conn
var _ net.Conn = (*kcpCarrierConn)(nil)
