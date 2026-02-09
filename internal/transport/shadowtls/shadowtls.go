// Package shadowtls implements ShadowTLS v3 transport.
// ShadowTLS performs a real TLS handshake to a decoy domain, then relays
// data through a side channel, defeating active probing.
package shadowtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

// WildcardSNIMode defines how wildcard SNI matching behaves.
type WildcardSNIMode string

const (
	WildcardSNIOff     WildcardSNIMode = "off"     // Exact match only
	WildcardSNIAuthed  WildcardSNIMode = "authed"  // Wildcards allowed for authenticated clients
	WildcardSNIAll     WildcardSNIMode = "all"     // Wildcards allowed for all
)

// HandshakeConfig configures per-SNI handshake behavior.
type HandshakeConfig struct {
	Dest          string            // Decoy destination for this SNI
	SNI           string            // SNI to use
	ALPN          []string          // ALPN protocols
	Protocols     []string          // TLS protocol versions
	CipherSuites  []uint16          // Cipher suites
	Extensions    map[uint16][]byte // Custom TLS extensions
}

// Config holds ShadowTLS configuration.
type Config struct {
	Version   int    // Currently only v3 is supported
	Password  string // PSK for inner protocol
	Handshake struct {
		Dest string // Decoy domain (e.g., www.microsoft.com)
		SNI  string // Optional SNI override
	}
	// Server-side configuration
	ServerNames      []string                    // Allowed SNI values for server
	HandshakeForSNI  map[string]*HandshakeConfig // Per-SNI handshake config
	StrictMode       bool                        // Enforce TLS 1.3 only
	WildcardSNIMode  WildcardSNIMode             // Wildcard SNI matching mode
	MinTLSVersion    uint16                      // Minimum TLS version
	MaxTLSVersion    uint16                      // Maximum TLS version
}

// Dialer implements transport.Dialer for ShadowTLS.
type Dialer struct {
	Config    *Config
	TLSConfig *tls.Config
	Smux      *smux.Config
	Guard     string
}

// Listener implements transport.Listener for ShadowTLS.
type Listener struct {
	ln      net.Listener
	config  *Config
	smux    *smux.Config
	guard   string
	tlsCfg  *tls.Config
}

// session wraps a smux session with connection tracking.
type session struct {
	conn net.Conn
	sess *smux.Session
}

// NewDialer creates a ShadowTLS dialer.
func NewDialer(cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) *Dialer {
	return &Dialer{
		Config:    cfg,
		TLSConfig: tlsCfg,
		Smux:      smuxCfg,
		Guard:     guard,
	}
}

// Listen creates a ShadowTLS listener.
func Listen(addr string, cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	// Create server TLS config that accepts any SNI (we validate later)
	serverTLS := tlsCfg.Clone()
	if serverTLS == nil {
		serverTLS = &tls.Config{}
	}
	serverTLS.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		// In ShadowTLS v3, we don't have the actual certificate for the decoy
		// The handshake is relayed to the real server
		return serverTLS, nil
	}

	return &Listener{
		ln:     ln,
		config: cfg,
		smux:   smuxCfg,
		guard:  guard,
		tlsCfg: serverTLS,
	}, nil
}

// Dial connects to a ShadowTLS server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Step 1: Connect to the server
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("shadowtls dial: %w", err)
	}

	// Step 2: Perform TLS handshake relay based on version
	var shadowConn net.Conn

	if d.Config.Version == 3 {
		// ShadowTLS v3 with Session ID authentication
		shadowConn, err = d.performClientHandshakeV3(ctx, conn, d.TLSConfig)
	} else {
		// Legacy handshake
		decoySNI := d.Config.Handshake.SNI
		if decoySNI == "" {
			decoySNI = d.Config.Handshake.Dest
		}

		tlsCfg := d.TLSConfig.Clone()
		if tlsCfg == nil {
			tlsCfg = &tls.Config{}
		}
		tlsCfg.ServerName = decoySNI
		tlsCfg.InsecureSkipVerify = true

		shadowConn, err = d.performClientHandshake(ctx, conn, tlsCfg)
	}

	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("shadowtls handshake: %w", err)
	}

	// Step 3: Send guard token
	if err := transport.SendGuard(shadowConn, d.Guard); err != nil {
		_ = shadowConn.Close()
		return nil, fmt.Errorf("shadowtls guard: %w", err)
	}

	// Step 4: Start smux client
	sess, err := smux.Client(shadowConn, d.Smux)
	if err != nil {
		_ = shadowConn.Close()
		return nil, fmt.Errorf("shadowtls smux: %w", err)
	}

	return &session{conn: shadowConn, sess: sess}, nil
}

// Accept accepts a ShadowTLS connection.
func (l *Listener) Accept() (transport.Session, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// Set initial timeout
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Perform server-side shadow handshake based on version
	var shadowConn net.Conn
	if l.config.Version == 3 {
		shadowConn, err = l.performServerHandshakeV3(conn)
	} else {
		shadowConn, err = l.performServerHandshake(conn)
	}
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("shadowtls server handshake: %w", err)
	}

	// Clear deadline
	if err := shadowConn.SetDeadline(time.Time{}); err != nil {
		_ = shadowConn.Close()
		return nil, err
	}

	// Receive guard token
	if err := transport.RecvGuard(shadowConn, l.guard); err != nil {
		_ = shadowConn.Close()
		return nil, fmt.Errorf("shadowtls guard: %w", err)
	}

	// Start smux server
	sess, err := smux.Server(shadowConn, l.smux)
	if err != nil {
		_ = shadowConn.Close()
		return nil, fmt.Errorf("shadowtls smux: %w", err)
	}

	return &session{conn: shadowConn, sess: sess}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.ln.Close()
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

// validateSNI validates the SNI against allowed patterns.
func (l *Listener) validateSNI(sni string) bool {
	// Check exact match first
	for _, name := range l.config.ServerNames {
		if name == sni {
			return true
		}
	}

	// Check wildcard patterns based on mode
	switch l.config.WildcardSNIMode {
	case WildcardSNIAll:
		return l.matchWildcard(sni)
	case WildcardSNIAuthed:
		// For authed mode, we'd check authentication here
		// For now, treat same as off
		return false
	default: // WildcardSNIOff
		return false
	}
}

// matchWildcard checks if SNI matches any wildcard pattern.
func (l *Listener) matchWildcard(sni string) bool {
	for _, name := range l.config.ServerNames {
		if strings.HasPrefix(name, "*.") {
			suffix := name[1:] // Remove the leading *
			if strings.HasSuffix(sni, suffix) {
				return true
			}
		}
	}
	return false
}

// getHandshakeConfig gets the handshake config for an SNI.
func (l *Listener) getHandshakeConfig(sni string) *HandshakeConfig {
	// Check for per-SNI config
	if cfg, ok := l.config.HandshakeForSNI[sni]; ok {
		return cfg
	}

	// Check for wildcard match
	for pattern, cfg := range l.config.HandshakeForSNI {
		if strings.HasPrefix(pattern, "*.") {
			suffix := pattern[1:]
			if strings.HasSuffix(sni, suffix) {
				return cfg
			}
		}
	}

	// Return default config
	return &HandshakeConfig{
		Dest: l.config.Handshake.Dest,
		SNI:  sni,
	}
}

// applyStrictMode applies TLS version restrictions.
func (l *Listener) applyStrictMode(cfg *tls.Config) {
	if l.config.StrictMode {
		cfg.MinVersion = tls.VersionTLS13
		cfg.MaxVersion = tls.VersionTLS13
		cfg.CipherSuites = []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
		}
	} else if l.config.MinTLSVersion > 0 {
		cfg.MinVersion = l.config.MinTLSVersion
	}

	if l.config.MaxTLSVersion > 0 {
		cfg.MaxVersion = l.config.MaxTLSVersion
	}
}

// OpenStream opens a new stream.
func (s *session) OpenStream() (net.Conn, error) {
	return s.sess.OpenStream()
}

// AcceptStream accepts an incoming stream.
func (s *session) AcceptStream() (net.Conn, error) {
	return s.sess.AcceptStream()
}

// Close closes the session.
func (s *session) Close() error {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// LocalAddr returns the local address.
func (s *session) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// RemoteAddr returns the remote address.
func (s *session) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}
