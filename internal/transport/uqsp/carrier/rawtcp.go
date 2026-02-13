package carrier

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/rawtcp"

	"github.com/xtaci/smux"
)

// RawTCPCarrier uses raw TCP packet crafting with KCP as the underlying transport.
// This is a UDP-family carrier that uses PCAP for raw packet injection.
type RawTCPCarrier struct {
	rawConfig config.RawTCPConfig
	kcpConfig config.KCPConfig
	authToken string
	smux      *smux.Config
	listener  *rawtcp.Listener
}

// NewRawTCPCarrier creates a new RawTCP carrier
func NewRawTCPCarrier(rawCfg config.RawTCPConfig, kcpCfg config.KCPConfig, smuxCfg *smux.Config, authToken string) Carrier {
	return &RawTCPCarrier{
		rawConfig: rawCfg,
		kcpConfig: kcpCfg,
		authToken: authToken,
		smux:      smuxCfg,
	}
}

// Network returns "udp" (KCP runs over UDP-like packet interface)
func (c *RawTCPCarrier) Network() string {
	return "udp"
}

// Dial establishes a RawTCP connection via KCP and returns a net.Conn
func (c *RawTCPCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := rawtcp.NewDialer(c.rawConfig, c.effectiveKCPConfig(), c.smux)
	session, err := dialer.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("rawtcp dial: %w", err)
	}

	// Open the first stream
	stream, err := session.OpenStream()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("rawtcp open stream: %w", err)
	}

	// Return a connection that manages the session lifecycle
	return &rawTCPConn{
		session: session,
		stream:  stream,
	}, nil
}

// Listen creates a RawTCP listener
func (c *RawTCPCarrier) Listen(addr string) (Listener, error) {
	ln, err := rawtcp.Listen(c.rawConfig, c.effectiveKCPConfig(), c.smux)
	if err != nil {
		return nil, fmt.Errorf("rawtcp listen: %w", err)
	}
	c.listener = ln
	return &rawTCPListener{ln: ln}, nil
}

// Close closes the carrier
func (c *RawTCPCarrier) Close() error {
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

// IsAvailable returns whether raw sockets are available
func (c *RawTCPCarrier) IsAvailable() bool {
	// RawTCP requires CAP_NET_RAW or root
	// The actual check happens when trying to create the packet conn
	return true
}

func (c *RawTCPCarrier) effectiveKCPConfig() config.KCPConfig {
	kcpCfg := c.kcpConfig
	if kcpCfg.Block == "" {
		kcpCfg.Block = "aes"
	}
	if kcpCfg.Key == "" {
		if c.authToken != "" {
			kcpCfg.Key = c.authToken
		} else {
			kcpCfg.Key = "stealthlink-rawtcp-default"
		}
	}
	if kcpCfg.PacketGuardMagic == "" {
		kcpCfg.PacketGuardMagic = "PQT1"
	}
	if kcpCfg.PacketGuardWindow == 0 {
		kcpCfg.PacketGuardWindow = 30
	}
	if kcpCfg.PacketGuardSkew == 0 {
		kcpCfg.PacketGuardSkew = 1
	}
	return kcpCfg
}

// rawTCPListener wraps a RawTCP listener
type rawTCPListener struct {
	ln *rawtcp.Listener
}

func (l *rawTCPListener) Accept() (net.Conn, error) {
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

	return &rawTCPConn{
		session: session,
		stream:  stream,
	}, nil
}

func (l *rawTCPListener) Close() error {
	return l.ln.Close()
}

func (l *rawTCPListener) Addr() net.Addr {
	return l.ln.Addr()
}

// rawTCPConn wraps a RawTCP session and stream as a net.Conn
type rawTCPConn struct {
	session transport.Session
	stream  net.Conn
	mu      sync.Mutex
}

func (c *rawTCPConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

func (c *rawTCPConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

func (c *rawTCPConn) Close() error {
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

func (c *rawTCPConn) LocalAddr() net.Addr {
	if c.stream != nil {
		return c.stream.LocalAddr()
	}
	return nil
}

func (c *rawTCPConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		return c.stream.RemoteAddr()
	}
	return nil
}

func (c *rawTCPConn) SetDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *rawTCPConn) SetReadDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *rawTCPConn) SetWriteDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

// Ensure we implement net.Conn
var _ net.Conn = (*rawTCPConn)(nil)
