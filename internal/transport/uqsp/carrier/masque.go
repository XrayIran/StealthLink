package carrier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/masque"

	"github.com/xtaci/smux"
)

// MASQUECarrier uses the in-core QUIC MASQUE profile to blend with HTTP/3
// CONNECT-{UDP,IP}-like traffic while still carrying StealthLink sessions.
//
// Note: This is a carrier transport profile (obfuscation/masquerade), not a full
// standalone CONNECT-UDP proxy implementation.
type MASQUECarrier struct {
	config   *masque.Config
	tlsCfg   *tls.Config
	smuxCfg  *smux.Config
	guard    string
	listener transport.Listener
}

func NewMASQUECarrier(cfg config.MASQUECarrierConfig, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) Carrier {
	mcfg := &masque.Config{
		ServerAddr: cfg.ServerAddr,
		Target:     cfg.Target,
		TunnelType: cfg.TunnelType,
		AuthToken:  cfg.AuthToken,
		Headers:    cfg.Headers,
	}
	if mcfg.AuthToken == "" {
		mcfg.AuthToken = guard
	}
	return &MASQUECarrier{
		config:  mcfg,
		tlsCfg:  tlsCfg,
		smuxCfg: smuxCfg,
		guard:   guard,
	}
}

func (c *MASQUECarrier) Network() string { return "quic" }

func (c *MASQUECarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if c.tlsCfg == nil {
		return nil, fmt.Errorf("masque dial: missing tls config")
	}
	dialer := masque.NewDialer(c.config, c.tlsCfg, c.smuxCfg, c.guard, nil)
	session, err := dialer.Dial(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("masque dial: %w", err)
	}
	stream, err := session.OpenStream()
	if err != nil {
		_ = session.Close()
		return nil, fmt.Errorf("masque open stream: %w", err)
	}
	return &masqueConn{session: session, stream: stream}, nil
}

func (c *MASQUECarrier) Listen(addr string) (Listener, error) {
	if c.tlsCfg == nil {
		return nil, fmt.Errorf("masque listen: missing tls config")
	}
	// Ensure the masquerade listen address matches the actual listener.
	cfgCopy := *c.config
	cfgCopy.ServerAddr = addr
	ln, err := masque.Listen(addr, &cfgCopy, c.tlsCfg, c.smuxCfg, c.guard, nil)
	if err != nil {
		return nil, fmt.Errorf("masque listen: %w", err)
	}
	c.listener = ln
	return &masqueListener{ln: ln}, nil
}

func (c *MASQUECarrier) Close() error {
	if c.listener != nil {
		return c.listener.Close()
	}
	return nil
}

func (c *MASQUECarrier) IsAvailable() bool { return true }

type masqueListener struct {
	ln transport.Listener
}

func (l *masqueListener) Accept() (net.Conn, error) {
	session, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	stream, err := session.AcceptStream()
	if err != nil {
		_ = session.Close()
		return nil, err
	}
	return &masqueConn{session: session, stream: stream}, nil
}

func (l *masqueListener) Close() error { return l.ln.Close() }
func (l *masqueListener) Addr() net.Addr { return l.ln.Addr() }

type masqueConn struct {
	session transport.Session
	stream  net.Conn
	mu      sync.Mutex
}

func (c *masqueConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *masqueConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

func (c *masqueConn) Close() error {
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

func (c *masqueConn) LocalAddr() net.Addr  { return c.stream.LocalAddr() }
func (c *masqueConn) RemoteAddr() net.Addr { return c.stream.RemoteAddr() }
func (c *masqueConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}
func (c *masqueConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *masqueConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

var _ net.Conn = (*masqueConn)(nil)

