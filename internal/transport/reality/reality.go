// Package reality implements REALITY-style transport that mimics a live site's TLS
// without holding the private key. This defeats active probes and SNI blocking.
package reality

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"

	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

// Config holds REALITY configuration.
type Config struct {
	Dest        string   // Target server to mimic (e.g., www.microsoft.com)
	ServerNames []string // Allowed SNI values
	PrivateKey  string   // X25519 private key (base64 or hex)
	ShortIds    []string // Short IDs for session validation
	Spider      SpiderConfig
	Show        bool // Show debug info
}

// Dialer implements transport.Dialer for REALITY.
type Dialer struct {
	Config    *Config
	TLSConfig *tls.Config
	Smux      *smux.Config
	Guard     string
}

// Listener implements transport.Listener for REALITY.
type Listener struct {
	ln     net.Listener
	config *Config
	smux   *smux.Config
	guard  string
}

// NewDialer creates a new REALITY dialer.
func NewDialer(cfg *Config, tlsCfg *tls.Config, smuxCfg *smux.Config, guard string) *Dialer {
	return &Dialer{
		Config:    cfg,
		TLSConfig: tlsCfg,
		Smux:      smuxCfg,
		Guard:     guard,
	}
}

// Listen creates a REALITY listener.
func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	// REALITY server listens on TCP
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	return &Listener{
		ln:     ln,
		config: cfg,
		smux:   smuxCfg,
		guard:  guard,
	}, nil
}

// Dial connects to a REALITY server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Parse the private key
	privateKey, err := parseKey(d.Config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// Connect to server
	dialer := &net.Dialer{}
	
	// Start spider if enabled
	if d.Config.Spider.Enabled {
		spider := NewSpider(d.Config.Spider)
		// Requirement 7.10: wait for spider or timeout
		_ = spider.Start(ctx)
	}

	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	// Perform REALITY handshake
	realityConn, err := d.performClientHandshake(conn, privateKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Send guard token
	if err := transport.SendGuard(realityConn, d.Guard); err != nil {
		_ = realityConn.Close()
		return nil, fmt.Errorf("guard: %w", err)
	}

	// Start smux
	sess, err := smux.Client(realityConn, d.Smux)
	if err != nil {
		_ = realityConn.Close()
		return nil, fmt.Errorf("smux: %w", err)
	}

	return &session{conn: realityConn, sess: sess}, nil
}

// Accept accepts a REALITY connection.
func (l *Listener) Accept() (transport.Session, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}

	// Perform server-side REALITY handshake
	realityConn, err := l.performServerHandshake(conn)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Receive guard token
	if err := transport.RecvGuard(realityConn, l.guard); err != nil {
		_ = realityConn.Close()
		return nil, fmt.Errorf("guard: %w", err)
	}

	// Start smux
	sess, err := smux.Server(realityConn, l.smux)
	if err != nil {
		_ = realityConn.Close()
		return nil, fmt.Errorf("smux: %w", err)
	}

	return &session{conn: realityConn, sess: sess}, nil
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.ln.Close()
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.ln.Addr()
}

// parseKey parses a private key from base64 or hex.
func parseKey(key string) ([]byte, error) {
	// Try base64 first
	if decoded, err := base64.StdEncoding.DecodeString(key); err == nil {
		if len(decoded) != 32 {
			return nil, fmt.Errorf("invalid key length: got %d, want 32", len(decoded))
		}
		return decoded, nil
	}

	// Try hex
	if decoded, err := hex.DecodeString(key); err == nil {
		if len(decoded) != 32 {
			return nil, fmt.Errorf("invalid key length: got %d, want 32", len(decoded))
		}
		return decoded, nil
	}

	return nil, fmt.Errorf("key must be base64 or hex encoded")
}

// session wraps a smux session.
type session struct {
	conn net.Conn
	sess *smux.Session
}

func (s *session) OpenStream() (net.Conn, error) {
	return s.sess.OpenStream()
}

func (s *session) AcceptStream() (net.Conn, error) {
	return s.sess.AcceptStream()
}

func (s *session) Close() error {
	if s.sess != nil {
		_ = s.sess.Close()
	}
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *session) LocalAddr() net.Addr  { return s.conn.LocalAddr() }
func (s *session) RemoteAddr() net.Addr { return s.conn.RemoteAddr() }

// PerformClientHandshake performs the client-side REALITY handshake on an existing connection.
// This is used by the tlsmux unified handler.
func (d *Dialer) PerformClientHandshake(conn net.Conn, privateKey []byte) (net.Conn, error) {
	return d.performClientHandshake(conn, privateKey)
}

// PerformServerHandshake performs the server-side REALITY handshake on an existing connection.
// This is used by the tlsmux unified handler.
func (l *Listener) PerformServerHandshake(conn net.Conn) (net.Conn, error) {
	return l.performServerHandshake(conn)
}
