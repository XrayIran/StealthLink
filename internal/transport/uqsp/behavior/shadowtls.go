package behavior

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
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

const (
	tlsRecordTypeHandshake  = 0x16
	tlsVersion10            = 0x0301
	tlsVersion12            = 0x0303
	tlsHandshakeClientHello = 0x01
	tlsHandshakeServerHello = 0x02
)

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
	return readTLSHandshakeMessage(c.Conn, tlsHandshakeServerHello, 16)
}

// verifyServerHello verifies the ServerHello response
func (c *shadowTLSConn) verifyServerHello(serverHello []byte) error {
	if len(serverHello) < 4 {
		return fmt.Errorf("server hello too short")
	}

	if serverHello[0] != tlsHandshakeServerHello {
		return fmt.Errorf("expected ServerHello handshake message, got type 0x%02x", serverHello[0])
	}

	msgLen := int(serverHello[1])<<16 | int(serverHello[2])<<8 | int(serverHello[3])
	if msgLen <= 0 || msgLen > len(serverHello)-4 {
		return fmt.Errorf("invalid ServerHello length: %d", msgLen)
	}
	body := serverHello[4 : 4+msgLen]
	if len(body) < 38 {
		return fmt.Errorf("ServerHello body too short: %d", len(body))
	}

	// TLS 1.2 and 1.3 both typically use legacy_version 0x0303.
	version := binary.BigEndian.Uint16(body[0:2])
	if version != tlsVersion12 && version != tlsVersion10 {
		return fmt.Errorf("unexpected ServerHello legacy version: 0x%04x", version)
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

// Read reads data from the connection with TLS record deframing.
func (c *shadowTLSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.handshakeDone {
		c.mu.Unlock()
		if err := c.handshake(); err != nil {
			return 0, err
		}
		c.mu.Lock()
	}

	// Read from buffer first
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	// Read a TLS ApplicationData record from the underlying connection
	_, _, payload, err := readTLSRecord(c.Conn)
	if err != nil {
		return 0, err
	}

	n := copy(p, payload)
	if n < len(payload) {
		c.mu.Lock()
		c.readBuf = append(c.readBuf[:0], payload[n:]...)
		c.mu.Unlock()
	}
	return n, nil
}

// Write writes data to the connection wrapped in TLS ApplicationData records.
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

	// Wrap in TLS ApplicationData record (type 0x17, TLS 1.2)
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		record := make([]byte, 5+len(chunk))
		record[0] = 0x17 // ApplicationData
		record[1] = 0x03 // TLS 1.2
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(len(chunk)))
		copy(record[5:], chunk)
		if _, err := c.Conn.Write(record); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
}

// Ensure shadowTLSConn implements net.Conn
var _ net.Conn = (*shadowTLSConn)(nil)

// ShadowTLSAcceptor handles server-side ShadowTLS acceptance
type ShadowTLSAcceptor struct {
	Password    string
	ServerNames []string
	AllowAnySNI bool
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
	return readTLSHandshakeMessage(c.Conn, tlsHandshakeClientHello, 16)
}

// parseSNI extracts the SNI from a ClientHello
func (c *shadowTLSServerConn) parseSNI(clientHello []byte) (string, error) {
	if len(clientHello) < 4 || clientHello[0] != tlsHandshakeClientHello {
		return "", fmt.Errorf("invalid ClientHello handshake message")
	}
	if len(clientHello) > 65535 {
		return "", fmt.Errorf("ClientHello too large: %d", len(clientHello))
	}
	record := make([]byte, 5+len(clientHello))
	record[0] = tlsRecordTypeHandshake
	record[1] = 0x03
	record[2] = 0x03
	binary.BigEndian.PutUint16(record[3:5], uint16(len(clientHello)))
	copy(record[5:], clientHello)
	return tlsutil.ParseSNI(record)
}

// buildServerHello builds a TLS 1.3 ServerHello
func (c *shadowTLSServerConn) buildServerHello() []byte {
	return tlsutil.BuildServerHello()
}

// Read reads data from the connection with TLS record deframing.
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

	// Read a TLS ApplicationData record from the underlying connection
	_, _, payload, err := readTLSRecord(c.Conn)
	if err != nil {
		return 0, err
	}
	n := copy(p, payload)
	return n, nil
}

// Write writes data to the connection wrapped in TLS ApplicationData records.
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

	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > 16384 {
			chunk = chunk[:16384]
		}
		record := make([]byte, 5+len(chunk))
		record[0] = 0x17 // ApplicationData
		record[1] = 0x03 // TLS 1.2
		record[2] = 0x03
		binary.BigEndian.PutUint16(record[3:5], uint16(len(chunk)))
		copy(record[5:], chunk)
		if _, err := c.Conn.Write(record); err != nil {
			return written, err
		}
		written += len(chunk)
		p = p[len(chunk):]
	}
	return written, nil
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

func readTLSHandshakeMessage(conn net.Conn, wantType byte, maxRecords int) ([]byte, error) {
	var handshakeBuf []byte

	for i := 0; i < maxRecords; i++ {
		recordType, version, payload, err := readTLSRecord(conn)
		if err != nil {
			return nil, err
		}

		// Ignore non-handshake records while waiting for expected message.
		if recordType != tlsRecordTypeHandshake {
			continue
		}
		if version != tlsVersion12 && version != tlsVersion10 {
			continue
		}

		handshakeBuf = append(handshakeBuf, payload...)

		for len(handshakeBuf) >= 4 {
			msgType := handshakeBuf[0]
			msgLen := int(handshakeBuf[1])<<16 | int(handshakeBuf[2])<<8 | int(handshakeBuf[3])
			if msgLen < 0 || msgLen > 1<<20 {
				return nil, fmt.Errorf("invalid TLS handshake message length: %d", msgLen)
			}
			if len(handshakeBuf) < 4+msgLen {
				break
			}

			msg := make([]byte, 4+msgLen)
			copy(msg, handshakeBuf[:4+msgLen])
			handshakeBuf = handshakeBuf[4+msgLen:]
			if msgType == wantType {
				return msg, nil
			}
		}
	}

	return nil, fmt.Errorf("expected TLS handshake type 0x%02x not received", wantType)
}

func readTLSRecord(conn net.Conn) (recordType byte, version uint16, payload []byte, err error) {
	header := make([]byte, 5)
	if _, err = io.ReadFull(conn, header); err != nil {
		return 0, 0, nil, err
	}

	recordType = header[0]
	version = binary.BigEndian.Uint16(header[1:3])
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length < 0 || length > 64*1024 {
		return 0, 0, nil, fmt.Errorf("invalid TLS record length %d", length)
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(conn, payload); err != nil {
		return 0, 0, nil, err
	}
	return recordType, version, payload, nil
}
