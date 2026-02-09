// Package tlsmux provides a unified TLS obfuscation layer that consolidates
// REALITY, ShadowTLS, TLSMirror, and ECH into a single configurable multiplexer.
package tlsmux

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"time"

	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

// TLSMode represents the TLS obfuscation mode
type TLSMode string

const (
	// ModeDirect uses standard TLS with optional fingerprinting
	ModeDirect TLSMode = "direct"
	// ModeReality uses XTLS fingerprint mimicry without private key
	ModeReality TLSMode = "reality"
	// ModeShadowTLS uses TLS-in-TLS relay (v1/v2/v3)
	ModeShadowTLS TLSMode = "shadowtls"
	// ModeTLSMirror uses TLS record reflection with watermarking
	ModeTLSMirror TLSMode = "tlsmirror"
	// ModeECH uses Encrypted Client Hello
	ModeECH TLSMode = "ech"
)

// UnifiedTLSConfig holds the consolidated TLS configuration
type UnifiedTLSConfig struct {
	// Base TLS configuration
	TLS *tls.Config

	// Obfuscation mode
	Mode TLSMode

	// Mode-specific configuration
	Reality   *RealityConfig
	ShadowTLS *ShadowTLSConfig
	TLSMirror *TLSMirrorConfig
	ECH       *ECHConfig

	// Common TLS shaping (applies to all modes)
	Shaping TLSShapingConfig

	// Smux configuration
	Smux *smux.Config

	// Guard token for session authentication
	Guard string
}

// RealityConfig holds REALITY-specific configuration
type RealityConfig struct {
	Dest        string   // Target server to mimic (e.g., www.microsoft.com)
	ServerNames []string // Allowed SNI values
	PrivateKey  string   // X25519 private key (base64 or hex)
	ShortIDs    []string // Short IDs for session validation
	SpiderX     string   // Crawling fallback behavior
	Show        bool     // Show debug info
}

// ShadowTLSConfig holds ShadowTLS-specific configuration
type ShadowTLSConfig struct {
	Version   int    // v1, v2, or v3
	Password  string // PSK for inner protocol
	Handshake struct {
		Dest string // Decoy domain
		SNI  string // Optional SNI override
	}
	ServerNames       []string
	HandshakeForSNI   map[string]*HandshakeConfig
	StrictMode        bool
	WildcardSNIMode   string // "off", "authed", "all"
	MinTLSVersion     uint16
	MaxTLSVersion     uint16
}

// HandshakeConfig configures per-SNI handshake behavior
type HandshakeConfig struct {
	Dest         string
	SNI          string
	ALPN         []string
	Protocols    []string
	CipherSuites []uint16
	Extensions   map[uint16][]byte
}

// TLSMirrorConfig holds TLSMirror-specific configuration
type TLSMirrorConfig struct {
	Enabled            bool
	ControlChannel     string
	EnrollmentRequired bool
	AntiLoopback       bool
}

// ECHConfig holds ECH-specific configuration
type ECHConfig struct {
	Enabled    bool
	PublicName string // Outer SNI (e.g., cloudflare-ech.com)
	InnerSNI   string // Actual destination (encrypted)
	Configs    [][]byte // ECH configs from DNS HTTPS records
	RequireECH bool
}

// TLSShapingConfig holds common TLS shaping options
type TLSShapingConfig struct {
	Fingerprint string           // uTLS fingerprint (chrome, firefox, safari, etc.)
	Fragment    TLSFragmentConfig
	SNIBlend    SNIBlendConfig
	Padding     HandshakePaddingConfig
}

// TLSFragmentConfig configures TLS ClientHello fragmentation
type TLSFragmentConfig struct {
	Enabled   bool
	Mode      string        // "fixed", "random_chunk", "sni_specific"
	Size      int           // bytes per fragment
	NumFrags  int           // total fragments
	DelayMin  int           // milliseconds
	DelayMax  int           // milliseconds
	Randomize bool
}

// SNIBlendConfig configures SNI blending techniques
type SNIBlendConfig struct {
	Enabled      bool
	FakeSNIs     []string // Decoy SNIs to interleave
	BlendRatio   float64  // Ratio of fake to real SNI
	RotateInterval int    // Seconds between rotations
}

// HandshakePaddingConfig configures handshake padding
type HandshakePaddingConfig struct {
	Enabled    bool
	MinSize    int
	MaxSize    int
	Randomize  bool
}

// UnifiedDialer implements transport.Dialer with unified TLS handling
type UnifiedDialer struct {
	config *UnifiedTLSConfig
	handler Handler
}

// UnifiedListener implements transport.Listener with unified TLS handling
type UnifiedListener struct {
	ln      net.Listener
	config  *UnifiedTLSConfig
	handler Handler
}

// Handler is the interface for mode-specific TLS handlers
type Handler interface {
	// Client-side: wrap a connection with the specific TLS mode
	WrapClient(ctx context.Context, conn net.Conn, tlsConfig *tls.Config, shaping *TLSShapingConfig) (net.Conn, error)
	// Server-side: accept and unwrap a connection
	WrapServer(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error)
	// Mode returns the handler's mode
	Mode() TLSMode
}

// NewUnifiedDialer creates a new unified TLS dialer
func NewUnifiedDialer(cfg *UnifiedTLSConfig) (*UnifiedDialer, error) {
	if cfg.TLS == nil {
		cfg.TLS = &tls.Config{}
	}

	handler, err := getHandler(cfg.Mode, cfg)
	if err != nil {
		return nil, fmt.Errorf("create handler: %w", err)
	}

	return &UnifiedDialer{
		config:  cfg,
		handler: handler,
	}, nil
}

// NewUnifiedListener creates a new unified TLS listener
func NewUnifiedListener(ln net.Listener, cfg *UnifiedTLSConfig) (*UnifiedListener, error) {
	if cfg.TLS == nil {
		cfg.TLS = &tls.Config{}
	}

	handler, err := getHandler(cfg.Mode, cfg)
	if err != nil {
		return nil, fmt.Errorf("create handler: %w", err)
	}

	return &UnifiedListener{
		ln:      ln,
		config:  cfg,
		handler: handler,
	}, nil
}

// Dial connects to a unified TLS server
func (d *UnifiedDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Establish base connection
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// Apply TLS shaping (fragmentation, etc.)
	conn = applyTLSShaping(conn, &d.config.Shaping)

	// Perform mode-specific handshake
	tlsConn, err := d.handler.WrapClient(ctx, conn, d.config.TLS, &d.config.Shaping)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Send guard token
	if err := transport.SendGuard(tlsConn, d.config.Guard); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("guard: %w", err)
	}

	// Start smux
	sess, err := smux.Client(tlsConn, d.config.Smux)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("smux: %w", err)
	}

	return &session{conn: tlsConn, sess: sess}, nil
}

// Accept accepts a unified TLS connection
func (l *UnifiedListener) Accept() (transport.Session, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// Perform mode-specific handshake
	tlsConn, err := l.handler.WrapServer(conn, l.config.TLS)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Receive guard token
	if err := transport.RecvGuard(tlsConn, l.config.Guard); err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("guard: %w", err)
	}

	// Start smux
	sess, err := smux.Server(tlsConn, l.config.Smux)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("smux: %w", err)
	}

	return &session{conn: tlsConn, sess: sess}, nil
}

// Close closes the listener
func (l *UnifiedListener) Close() error {
	return l.ln.Close()
}

// Addr returns the listener address
func (l *UnifiedListener) Addr() net.Addr {
	return l.ln.Addr()
}

// getHandler returns the appropriate handler for the given mode
func getHandler(mode TLSMode, cfg *UnifiedTLSConfig) (Handler, error) {
	switch mode {
	case ModeDirect:
		return &DirectHandler{Fingerprint: cfg.Shaping.Fingerprint}, nil
	case ModeReality:
		if cfg.Reality == nil {
			return nil, fmt.Errorf("reality config required for mode=reality")
		}
		return &RealityHandler{Config: cfg.Reality}, nil
	case ModeShadowTLS:
		if cfg.ShadowTLS == nil {
			return nil, fmt.Errorf("shadowtls config required for mode=shadowtls")
		}
		return &ShadowTLSHandler{Config: cfg.ShadowTLS}, nil
	case ModeTLSMirror:
		if cfg.TLSMirror == nil {
			cfg.TLSMirror = &TLSMirrorConfig{}
		}
		return &TLSMirrorHandler{
			Config:     cfg.TLSMirror,
			BaseConfig: cfg.TLS,
			Fingerprint: cfg.Shaping.Fingerprint,
		}, nil
	case ModeECH:
		if cfg.ECH == nil {
			return nil, fmt.Errorf("ech config required for mode=ech")
		}
		return &ECHHandler{Config: cfg.ECH}, nil
	default:
		return nil, fmt.Errorf("unsupported TLS mode: %s", mode)
	}
}

// applyTLSShaping applies TLS shaping techniques to the connection
func applyTLSShaping(conn net.Conn, shaping *TLSShapingConfig) net.Conn {
	if shaping == nil {
		return conn
	}

	// Apply fragmentation if enabled
	if shaping.Fragment.Enabled {
		conn = &fragmentedConn{
			Conn:      conn,
			config:    &shaping.Fragment,
		}
	}

	return conn
}

// fragmentedConn wraps a connection with TLS fragmentation support
type fragmentedConn struct {
	net.Conn
	config *TLSFragmentConfig
}

// Write implements io.Writer with fragmentation support
func (c *fragmentedConn) Write(p []byte) (int, error) {
	if !c.config.Enabled || len(p) == 0 {
		return c.Conn.Write(p)
	}

	// Check if this looks like a TLS Client Hello (first byte should be 0x16 for handshake)
	if len(p) < 5 || p[0] != 0x16 {
		// Not a TLS handshake, pass through
		return c.Conn.Write(p)
	}

	// Fragment the TLS Client Hello
	totalWritten := 0
	fragSize := c.config.Size
	if fragSize <= 0 {
		fragSize = 100 // Default fragment size
	}

	// For each fragment
	for offset := 0; offset < len(p); {
		// Calculate fragment size with randomization if enabled
		size := fragSize
		if c.config.Randomize && size < len(p)-offset {
			// Add some randomness to fragment size (-20% to +20%)
			variation := size / 5
			if variation > 0 {
				size = size - variation + rand.Intn(variation*2)
			}
		}

		// Ensure we don't exceed remaining data
		end := offset + size
		if end > len(p) {
			end = len(p)
		}

		// Write the fragment
		n, err := c.Conn.Write(p[offset:end])
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}

		// Apply delay between fragments if configured and not the last fragment
		if c.config.DelayMin > 0 && end < len(p) {
			delay := c.config.DelayMin
			if c.config.DelayMax > c.config.DelayMin {
				delay = c.config.DelayMin + rand.Intn(c.config.DelayMax-c.config.DelayMin)
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}

		offset = end
	}

	return totalWritten, nil
}
