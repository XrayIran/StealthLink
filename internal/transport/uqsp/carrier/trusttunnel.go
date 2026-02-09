package carrier

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/trusttunnel"

	"github.com/xtaci/smux"
)

// TrustTunnelCarrier uses TrustTunnel (HTTP/1.1, HTTP/2, HTTP/3) as the underlying transport.
// This is a TCP-family carrier that tunnels traffic through HTTP connections.
type TrustTunnelCarrier struct {
	config       *trusttunnel.Config
	smux         *smux.Config
	tunnel       *trusttunnel.TrustTunnel
	dtlsFallback bool
	dpdInterval  time.Duration
}

// NewTrustTunnelCarrier creates a new TrustTunnel carrier
func NewTrustTunnelCarrier(cfg config.TrustTunnelCarrierConfig, smuxCfg *smux.Config) Carrier {
	ttConfig := &trusttunnel.Config{
		Server:         cfg.Server,
		Version:        trusttunnel.ProtocolVersion(cfg.Version),
		MaxConcurrent:  cfg.MaxConcurrent,
		StreamTimeout:  cfg.StreamTimeout,
		PaddingMin:     cfg.PaddingMin,
		PaddingMax:     cfg.PaddingMax,
		DomainFronting: cfg.DomainFronting,
		Headers:        map[string]string{},
	}

	// Only set Token if not empty
	if cfg.Token != "" {
		ttConfig.Token = cfg.Token
	}
	if cfg.DPDInterval > 0 {
		ttConfig.Headers["X-CSTP-DPD-Interval"] = cfg.DPDInterval.String()
	}
	if cfg.MTUDiscovery {
		ttConfig.Headers["X-CSTP-MTU-Discovery"] = "1"
	}
	if len(cfg.SplitInclude) > 0 {
		ttConfig.Headers["X-CSTP-Split-Include"] = strings.Join(cfg.SplitInclude, ",")
	}
	if len(cfg.SplitExclude) > 0 {
		ttConfig.Headers["X-CSTP-Split-Exclude"] = strings.Join(cfg.SplitExclude, ",")
	}

	return &TrustTunnelCarrier{
		config:       ttConfig,
		smux:         smuxCfg,
		dtlsFallback: cfg.DTLSFallback,
		dpdInterval:  cfg.DPDInterval,
	}
}

// Network returns "tcp"
func (c *TrustTunnelCarrier) Network() string {
	return "tcp"
}

// Dial establishes a TrustTunnel connection and returns a smux session
func (c *TrustTunnelCarrier) Dial(ctx context.Context, addr string) (net.Conn, error) {
	// Create TrustTunnel connection
	tunnel, err := trusttunnel.Dial(ctx, c.config)
	if err != nil {
		if !c.dtlsFallback {
			return nil, fmt.Errorf("trusttunnel dial: %w", err)
		}
		// Fallback path: force TLS-over-TCP versions when UDP/H3 paths are blocked.
		fallbackCfg := *c.config
		if fallbackCfg.Version == trusttunnel.VersionH3 {
			fallbackCfg.Version = trusttunnel.VersionH2
		}
		tunnel, err = trusttunnel.Dial(ctx, &fallbackCfg)
		if err != nil {
			fallbackCfg.Version = trusttunnel.VersionH1
			tunnel, err = trusttunnel.Dial(ctx, &fallbackCfg)
			if err != nil {
				return nil, fmt.Errorf("trusttunnel dial fallback: %w", err)
			}
		}
	}
	c.tunnel = tunnel

	// Open the first stream which will be used for the smux session
	stream, err := tunnel.OpenStream()
	if err != nil {
		_ = tunnel.Close()
		return nil, fmt.Errorf("trusttunnel open stream: %w", err)
	}

	// Create smux session over the stream
	session, err := smux.Client(stream, c.smux)
	if err != nil {
		_ = stream.Close()
		_ = tunnel.Close()
		return nil, fmt.Errorf("smux client: %w", err)
	}

	// Return a connection that wraps the smux session
	tc := &trustTunnelConn{
		tunnel:  tunnel,
		session: session,
	}
	if c.dpdInterval > 0 {
		go tc.dpdLoop(c.dpdInterval)
	}
	return tc, nil
}

// Listen creates a TrustTunnel server listener
func (c *TrustTunnelCarrier) Listen(addr string) (Listener, error) {
	conns := make(chan net.Conn, 128)
	serverConfig := &trusttunnel.ServerConfig{
		Addr:      addr,
		Versions:  []trusttunnel.ProtocolVersion{trusttunnel.VersionH1, trusttunnel.VersionH2, trusttunnel.VersionH3},
		TLSConfig: &tls.Config{
			// TLS config should be provided via carrier config
		},
		PathPrefix:    "/tunnel",
		StreamTimeout: c.config.StreamTimeout,
		OnConnect: func(stream net.Conn) error {
			select {
			case conns <- stream:
				return nil
			default:
				_ = stream.Close()
				return fmt.Errorf("listener backlog full")
			}
		},
	}

	server, err := trusttunnel.ListenAndServe(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("trusttunnel listen: %w", err)
	}

	return &trustTunnelListener{
		server: server,
		addr:   addr,
		conns:  conns,
	}, nil
}

// Close closes the carrier
func (c *TrustTunnelCarrier) Close() error {
	if c.tunnel != nil {
		return c.tunnel.Close()
	}
	return nil
}

// IsAvailable returns true (TrustTunnel uses standard HTTP/TLS which is always available)
func (c *TrustTunnelCarrier) IsAvailable() bool {
	return true
}

// trustTunnelConn wraps a TrustTunnel smux session as a net.Conn
type trustTunnelConn struct {
	tunnel  *trusttunnel.TrustTunnel
	session *smux.Session
	stream  net.Conn
	mu      sync.Mutex
}

func (c *trustTunnelConn) dpdLoop(interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		c.mu.Lock()
		s := c.stream
		c.mu.Unlock()
		if s == nil {
			continue
		}
		_ = s.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := s.Write([]byte{}); err != nil {
			return
		}
		_ = s.SetWriteDeadline(time.Time{})
	}
}

func (c *trustTunnelConn) Read(p []byte) (int, error) {
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

func (c *trustTunnelConn) Write(p []byte) (int, error) {
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

func (c *trustTunnelConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		_ = c.stream.Close()
	}
	if c.session != nil {
		_ = c.session.Close()
	}
	if c.tunnel != nil {
		return c.tunnel.Close()
	}
	return nil
}

func (c *trustTunnelConn) LocalAddr() net.Addr {
	if c.stream != nil {
		return c.stream.LocalAddr()
	}
	return nil
}

func (c *trustTunnelConn) RemoteAddr() net.Addr {
	if c.stream != nil {
		return c.stream.RemoteAddr()
	}
	return nil
}

func (c *trustTunnelConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream.SetDeadline(t)
	}
	return nil
}

func (c *trustTunnelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream.SetReadDeadline(t)
	}
	return nil
}

func (c *trustTunnelConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stream != nil {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}

// Ensure we implement net.Conn
var _ net.Conn = (*trustTunnelConn)(nil)

// trustTunnelListener wraps a TrustTunnel server as a net.Listener
type trustTunnelListener struct {
	server *trusttunnel.Server
	addr   string
	conns  chan net.Conn
	closed bool
	mu     sync.Mutex
}

// Accept accepts incoming connections
func (l *trustTunnelListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, fmt.Errorf("listener closed")
	}
	l.mu.Unlock()

	conn, ok := <-l.conns
	if !ok {
		return nil, fmt.Errorf("listener closed")
	}
	return conn, nil
}

// Close closes the listener
func (l *trustTunnelListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.closed {
		return nil
	}

	l.closed = true
	return l.server.Close()
}

// Addr returns the listener address
func (l *trustTunnelListener) Addr() net.Addr {
	host, port, err := net.SplitHostPort(l.addr)
	if err != nil {
		return &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: 0}
	}
	return &net.TCPAddr{IP: net.ParseIP(host), Port: parsePort(port)}
}

func parsePort(v string) int {
	var out int
	_, _ = fmt.Sscanf(v, "%d", &out)
	return out
}
