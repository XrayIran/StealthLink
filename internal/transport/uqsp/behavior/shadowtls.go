package behavior

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"

	"stealthlink/internal/config"
	"stealthlink/internal/tlsutil"
)

// ShadowTLSOverlay ports ShadowTLS v3 behaviors as a UQSP overlay.
// ShadowTLS mimics TLS handshakes to blend in with normal TLS traffic.
type ShadowTLSOverlay struct {
	EnabledField  bool
	Version       int
	Password      string
	HandshakeDest string
	ServerNames   []string
}

// NewShadowTLSOverlay creates a new ShadowTLS overlay from config
func NewShadowTLSOverlay(cfg config.ShadowTLSBehaviorConfig) *ShadowTLSOverlay {
	return &ShadowTLSOverlay{
		EnabledField:  cfg.Enabled,
		Version:       cfg.Version,
		Password:      cfg.Password,
		HandshakeDest: cfg.HandshakeDest,
		ServerNames:   cfg.ServerNames,
	}
}

// Name returns "shadowtls"
func (o *ShadowTLSOverlay) Name() string {
	return "shadowtls"
}

// Enabled returns whether this overlay is enabled
func (o *ShadowTLSOverlay) Enabled() bool {
	return o.EnabledField
}

// Apply applies ShadowTLS behavior to the connection
func (o *ShadowTLSOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	// ShadowTLS v3 handshake wrapper
	if o.Version == 3 {
		return o.applyV3(conn)
	}

	// Default to v3
	return o.applyV3(conn)
}

// applyV3 applies ShadowTLS v3 behavior
func (o *ShadowTLSOverlay) applyV3(conn net.Conn) (net.Conn, error) {
	// ShadowTLS v3 protocol:
	// 1. Client sends TLS ClientHello to handshake destination
	// 2. Server responds with TLS ServerHello (from handshake destination)
	// 3. After handshake, switch to UQSP protocol

	// Select SNI
	sni := o.HandshakeDest
	if len(o.ServerNames) > 0 {
		sni = o.ServerNames[0]
	}

	wrapper := &shadowTLSConn{
		Conn:          conn,
		password:      o.Password,
		handshakeDest: o.HandshakeDest,
		serverName:    sni,
		version:       3,
	}

	// Perform ShadowTLS handshake
	if err := wrapper.handshake(); err != nil {
		return nil, fmt.Errorf("shadowtls handshake: %w", err)
	}

	return wrapper, nil
}

// shadowTLSConn wraps a connection with ShadowTLS behavior
type shadowTLSConn struct {
	net.Conn
	password      string
	handshakeDest string
	serverName    string
	version       int
	handshakeDone bool
	mu            sync.Mutex
	readBuf       []byte
	writeBuf      []byte
}

// handshake performs the ShadowTLS handshake
func (c *shadowTLSConn) handshake() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.handshakeDone {
		return nil
	}

	// Generate ClientHello with TLS 1.3 fingerprint
	clientHello, err := c.buildClientHello()
	if err != nil {
		return fmt.Errorf("build client hello: %w", err)
	}

	// Send ClientHello
	if _, err := c.Conn.Write(clientHello); err != nil {
		return fmt.Errorf("send client hello: %w", err)
	}

	// Read ServerHello (and rest of TLS handshake)
	serverHello, err := c.readServerHello()
	if err != nil {
		return fmt.Errorf("read server hello: %w", err)
	}

	// Verify ServerHello
	if err := c.verifyServerHello(serverHello); err != nil {
		return fmt.Errorf("verify server hello: %w", err)
	}

	// Derive session key from password and handshake context
	c.deriveSessionKey(clientHello, serverHello)

	c.handshakeDone = true
	return nil
}

// buildClientHello builds a TLS 1.3 ClientHello
func (c *shadowTLSConn) buildClientHello() ([]byte, error) {
	// Use tlsutil to build a realistic ClientHello
	return tlsutil.BuildClientHello(c.serverName)
}

// readServerHello reads the ServerHello from the connection
func (c *shadowTLSConn) readServerHello() ([]byte, error) {
	// Read TLS record header
	header := make([]byte, 5)
	if _, err := c.Conn.Read(header); err != nil {
		return nil, err
	}

	// Get record length
	length := binary.BigEndian.Uint16(header[3:5])

	// Read record body
	body := make([]byte, length)
	if _, err := c.Conn.Read(body); err != nil {
		return nil, err
	}

	return append(header, body...), nil
}

// verifyServerHello verifies the ServerHello response
func (c *shadowTLSConn) verifyServerHello(serverHello []byte) error {
	if len(serverHello) < 5 {
		return fmt.Errorf("server hello too short")
	}

	// Check content type (0x16 = handshake)
	if serverHello[0] != 0x16 {
		return fmt.Errorf("expected handshake record, got 0x%02x", serverHello[0])
	}

	// Verify TLS version (should be 0x0303 for TLS 1.2 in record layer)
	version := binary.BigEndian.Uint16(serverHello[1:3])
	if version != 0x0303 && version != 0x0301 {
		return fmt.Errorf("unexpected TLS version: 0x%04x", version)
	}

	// ServerHello is valid
	return nil
}

// deriveSessionKey derives a session key from password and handshake
func (c *shadowTLSConn) deriveSessionKey(clientHello, serverHello []byte) []byte {
	h := hmac.New(sha256.New, []byte(c.password))
	h.Write(clientHello)
	h.Write(serverHello)
	return h.Sum(nil)
}

// Read reads data from the connection
func (c *shadowTLSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.handshakeDone {
		c.mu.Unlock()
		if err := c.handshake(); err != nil {
			return 0, err
		}
	} else {
		c.mu.Unlock()
	}

	// Read from buffer first
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	return c.Conn.Read(p)
}

// Write writes data to the connection
func (c *shadowTLSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.handshakeDone {
		c.mu.Unlock()
		if err := c.handshake(); err != nil {
			return 0, err
		}
	} else {
		c.mu.Unlock()
	}

	return c.Conn.Write(p)
}

// Ensure shadowTLSConn implements net.Conn
var _ net.Conn = (*shadowTLSConn)(nil)

// ShadowTLSAcceptor handles server-side ShadowTLS acceptance
type ShadowTLSAcceptor struct {
	Password      string
	ServerNames   []string
	AllowAnySNI   bool
}

// Accept handles an incoming ShadowTLS connection
func (a *ShadowTLSAcceptor) Accept(conn net.Conn) (net.Conn, error) {
	wrapper := &shadowTLSServerConn{
		Conn:        conn,
		password:    a.Password,
		serverNames: a.ServerNames,
		allowAnySNI: a.AllowAnySNI,
	}

	if err := wrapper.acceptHandshake(); err != nil {
		return nil, fmt.Errorf("shadowtls accept: %w", err)
	}

	return wrapper, nil
}

// shadowTLSServerConn wraps a server-side ShadowTLS connection
type shadowTLSServerConn struct {
	net.Conn
	password      string
	serverNames   []string
	allowAnySNI   bool
	handshakeDone bool
	mu            sync.Mutex
}

// acceptHandshake performs server-side ShadowTLS handshake
func (c *shadowTLSServerConn) acceptHandshake() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.handshakeDone {
		return nil
	}

	// Read ClientHello
	clientHello, err := c.readClientHello()
	if err != nil {
		return fmt.Errorf("read client hello: %w", err)
	}

	// Parse and validate SNI
	sni, err := c.parseSNI(clientHello)
	if err != nil {
		return fmt.Errorf("parse sni: %w", err)
	}

	if !c.allowAnySNI && len(c.serverNames) > 0 {
		valid := false
		for _, name := range c.serverNames {
			if strings.EqualFold(name, sni) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("sni not allowed: %s", sni)
		}
	}

	// Send ServerHello (using a pre-computed valid ServerHello)
	serverHello := c.buildServerHello()
	if _, err := c.Conn.Write(serverHello); err != nil {
		return fmt.Errorf("send server hello: %w", err)
	}

	c.handshakeDone = true
	return nil
}

// readClientHello reads the ClientHello from the connection
func (c *shadowTLSServerConn) readClientHello() ([]byte, error) {
	// Read TLS record header
	header := make([]byte, 5)
	if _, err := c.Conn.Read(header); err != nil {
		return nil, err
	}

	// Get record length
	length := binary.BigEndian.Uint16(header[3:5])

	// Read record body
	body := make([]byte, length)
	if _, err := c.Conn.Read(body); err != nil {
		return nil, err
	}

	return append(header, body...), nil
}

// parseSNI extracts the SNI from a ClientHello
func (c *shadowTLSServerConn) parseSNI(clientHello []byte) (string, error) {
	return tlsutil.ParseSNI(clientHello)
}

// buildServerHello builds a TLS 1.3 ServerHello
func (c *shadowTLSServerConn) buildServerHello() []byte {
	return tlsutil.BuildServerHello()
}

// Read reads data from the connection
func (c *shadowTLSServerConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.handshakeDone {
		c.mu.Unlock()
		if err := c.acceptHandshake(); err != nil {
			return 0, err
		}
	} else {
		c.mu.Unlock()
	}
	return c.Conn.Read(p)
}

// Write writes data to the connection
func (c *shadowTLSServerConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.handshakeDone {
		c.mu.Unlock()
		if err := c.acceptHandshake(); err != nil {
			return 0, err
		}
	} else {
		c.mu.Unlock()
	}
	return c.Conn.Write(p)
}

// Ensure shadowTLSServerConn implements net.Conn
var _ net.Conn = (*shadowTLSServerConn)(nil)

// ShadowTLSClientConfig configures ShadowTLS client behavior
type ShadowTLSClientConfig struct {
	Password      string
	HandshakeDest string
	ServerName    string
	ALPN          []string
}

// ShadowTLSServerConfig configures ShadowTLS server behavior
type ShadowTLSServerConfig struct {
	Password      string
	ServerNames   []string
	HandshakeDest string
}

// Helper functions for TLS handshake

// CipherSuites returns common TLS 1.3 cipher suites
func getCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
	}
}

// SupportedGroups returns common supported groups
func getSupportedGroups() []uint16 {
	return []uint16{
		0x0017, // secp256r1
		0x0018, // secp384r1
		0x0019, // secp521r1
		0x001d, // x25519
		0x0100, //ffdhe2048
	}
}

// SignatureAlgorithms returns common signature algorithms
func getSignatureAlgorithms() []uint16 {
	return []uint16{
		0x0403, // ecdsa_secp256r1_sha256
		0x0503, // ecdsa_secp384r1_sha384
		0x0603, // ecdsa_secp521r1_sha512
		0x0807, // ed25519
		0x0808, // ed448
		0x0809, // rsa_pss_pss_sha256
		0x080a, // rsa_pss_pss_sha384
		0x080b, // rsa_pss_pss_sha512
		0x0804, // rsa_pss_rsae_sha256
		0x0805, // rsa_pss_rsae_sha384
		0x0806, // rsa_pss_rsae_sha512
		0x0401, // rsa_pkcs1_sha256
		0x0501, // rsa_pkcs1_sha384
		0x0601, // rsa_pkcs1_sha512
	}
}

// ALPNProtocols returns common ALPN protocols
func getALPNProtocols() []string {
	return []string{
		"h2",
		"http/1.1",
	}
}

// generateRandom generates cryptographically secure random bytes
func generateRandom(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
