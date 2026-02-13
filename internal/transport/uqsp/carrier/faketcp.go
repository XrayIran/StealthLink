package carrier

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/faketcp"

	"github.com/xtaci/smux"
)

// FakeTCPCarrier uses TCP-like framing/state over UDP to blend traffic.
// It consolidates tcpraw/udp2raw-style fake TCP behavior as an in-core carrier.
type FakeTCPCarrier struct {
	config   *faketcp.Config
	smux     *smux.Config
	guard    string
	listener transport.Listener
}

// NewFakeTCPCarrier creates a new FakeTCP carrier.
func NewFakeTCPCarrier(cfg config.FakeTCPCarrierConfig, smuxCfg *smux.Config, guard string) Carrier {
	fcfg := faketcp.DefaultConfig()
	if cfg.MTU > 0 {
		fcfg.MTU = cfg.MTU
	}
	if cfg.WindowSize > 0 {
		fcfg.WindowSize = cfg.WindowSize
	}
	if cfg.RTO > 0 {
		fcfg.RTO = cfg.RTO
	}
	if cfg.Keepalive > 0 {
		fcfg.Keepalive = cfg.Keepalive
	}
	if cfg.KeepaliveIdle > 0 {
		fcfg.KeepaliveIdle = cfg.KeepaliveIdle
	}
	if cfg.FingerprintProfile != "" {
		fcfg.FingerprintProfile = faketcp.LookupFingerprintProfile(cfg.FingerprintProfile)
	}
	fcfg.CryptoKey = cfg.CryptoKey
	fcfg.AEADMode = cfg.AEADMode
	if cfg.FakeHTTP.IsEnabled() {
		fcfg.FakeHTTPPreface = &faketcp.FakeHTTPPrefaceConfig{
			Enabled:   true,
			Host:      cfg.FakeHTTP.Host,
			UserAgent: cfg.FakeHTTP.UserAgent,
			Path:      cfg.FakeHTTP.Path,
		}
	}
	return &FakeTCPCarrier{
		config: fcfg,
		smux:   smuxCfg,
		guard:  guard,
	}
}

func (c *FakeTCPCarrier) Network() string {
	return "udp"
}

func (c *FakeTCPCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	dialer := faketcp.NewDialer(c.config, c.smux, c.guard)
	session, err := dialer.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("faketcp dial: %w", err)
	}
	stream, err := session.OpenStream()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("faketcp open stream: %w", err)
	}
	return &fakeTCPConn{
		session: session,
		stream:  stream,
	}, nil
}

func (c *FakeTCPCarrier) Listen(addr string) (Listener, error) {
	ln, err := faketcp.Listen(addr, c.config, c.smux, c.guard)
	if err != nil {
		return nil, fmt.Errorf("faketcp listen: %w", err)
	}
	c.listener = ln
	return &fakeTCPListener{ln: ln}, nil
}

func (c *FakeTCPCarrier) Close() error {
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

func (c *FakeTCPCarrier) IsAvailable() bool {
	return true
}

type fakeTCPListener struct {
	ln transport.Listener
}

func (l *fakeTCPListener) Accept() (net.Conn, error) {
	session, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	stream, err := session.AcceptStream()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return &fakeTCPConn{
		session: session,
		stream:  stream,
	}, nil
}

func (l *fakeTCPListener) Close() error {
	return l.ln.Close()
}

func (l *fakeTCPListener) Addr() net.Addr {
	return l.ln.Addr()
}

type fakeTCPConn struct {
	session transport.Session
	stream  net.Conn
	mu      sync.Mutex
}

func (c *fakeTCPConn) Read(p []byte) (int, error) {
	return c.stream.Read(p)
}

func (c *fakeTCPConn) Write(p []byte) (int, error) {
	return c.stream.Write(p)
}

func (c *fakeTCPConn) Close() error {
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

func (c *fakeTCPConn) LocalAddr() net.Addr {
	if c.stream != nil {
		return c.stream.LocalAddr()
	}
	return nil
}

func (c *fakeTCPConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		return c.stream.RemoteAddr()
	}
	return nil
}

func (c *fakeTCPConn) SetDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *fakeTCPConn) SetReadDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *fakeTCPConn) SetWriteDeadline(t time.Time) error {
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

var _ net.Conn = (*fakeTCPConn)(nil)
