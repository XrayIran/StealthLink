package carrier

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/icmptun"

	"github.com/xtaci/smux"
)

// ICMPCarrier uses ICMP echo request/reply as the underlying transport.
// This is an ICMP-family carrier that tunnels traffic through ICMP packets.
type ICMPCarrier struct {
	config   icmptun.Config
	smux     *smux.Config
	guard    string
	listener transport.Listener
}

// NewICMPCarrier creates a new ICMP carrier
func NewICMPCarrier(cfg config.ICMPTunCarrierConfig, smuxCfg *smux.Config, guard string) Carrier {
	return &ICMPCarrier{
		config: icmptun.Config{
			MTU:          cfg.MTU,
			EchoInterval: cfg.EchoInterval,
			Timeout:      cfg.Timeout,
			WindowSize:   cfg.WindowSize,
			Obfuscate:    cfg.Obfuscate,
			ReadBuffer:   cfg.ReadBuffer,
			WriteBuffer:  cfg.WriteBuffer,
		},
		smux:  smuxCfg,
		guard: guard,
	}
}

// Network returns "icmp"
func (c *ICMPCarrier) Network() string {
	return "icmp"
}

// Dial establishes an ICMP tunnel connection and returns a net.Conn
func (c *ICMPCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := icmptun.NewDialer(c.config, c.smux, c.guard)
	session, err := dialer.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("icmptun dial: %w", err)
	}

	// Open the first stream
	stream, err := session.OpenStream()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("icmptun open stream: %w", err)
	}

	// Return a connection that manages the session lifecycle
	return &icmpConn{
		session: session,
		stream:  stream,
	}, nil
}

// Listen creates an ICMP listener
func (c *ICMPCarrier) Listen(addr string) (Listener, error) {
	ln, err := icmptun.Listen(addr, c.config, c.smux, c.guard)
	if err != nil {
		return nil, fmt.Errorf("icmptun listen: %w", err)
	}
	c.listener = ln
	return &icmpListener{ln: ln}, nil
}

// Close closes the carrier
func (c *ICMPCarrier) Close() error {
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

// IsAvailable returns whether raw ICMP sockets are available
func (c *ICMPCarrier) IsAvailable() bool {
	return icmptun.IsAvailable()
}

// icmpListener wraps an ICMP listener
type icmpListener struct {
	ln transport.Listener
}

func (l *icmpListener) Accept() (net.Conn, error) {
	session, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// Accept the first stream
	stream, err := session.AcceptStream()
	if err != nil {
		_ = session.Close()
		return nil, err
	}

	return &icmpConn{
		session: session,
		stream:  stream,
	}, nil
}

func (l *icmpListener) Close() error {
	return l.ln.Close()
}

func (l *icmpListener) Addr() net.Addr {
	return l.ln.Addr()
}

// icmpConn wraps an ICMP session and stream as a net.Conn
type icmpConn struct {
	session transport.Session
	stream  net.Conn
	mu      sync.Mutex
}

func (c *icmpConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

func (c *icmpConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

func (c *icmpConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		_ = c.stream.Close()
	}
	if c.session != nil {
		return c.session.Close()
	}
	return nil
}

func (c *icmpConn) LocalAddr() net.Addr {
	if c.stream != nil {
		return c.stream.LocalAddr()
	}
	return nil
}

func (c *icmpConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		return c.stream.RemoteAddr()
	}
	return nil
}

func (c *icmpConn) SetDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *icmpConn) SetReadDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *icmpConn) SetWriteDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

// Ensure we implement net.Conn
var _ net.Conn = (*icmpConn)(nil)
