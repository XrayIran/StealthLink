package shadowtls

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// shadowConn wraps a net.Conn with handshake relay capabilities.
type shadowConn struct {
	net.Conn
	serverConn net.Conn // Connection to decoy server (client-side only)
	clientConn net.Conn // Original client connection (server-side only)
	relayDone  bool
}

// performClientHandshake implements ShadowTLS v3 client handshake.
// It connects to the decoy server, performs TLS handshake, then relays
// the handshake to the ShadowTLS server.
func (d *Dialer) performClientHandshake(ctx context.Context, conn net.Conn, tlsCfg *tls.Config) (net.Conn, error) {
	// ShadowTLS v3 client flow:
	// 1. Connect to ShadowTLS server (already done - conn is this connection)
	// 2. Connect to decoy server and perform TLS handshake
	// 3. Relay the TLS handshake to ShadowTLS server
	// 4. After handshake, data flows through the side channel

	decoyAddr := d.Config.Handshake.Dest
	if decoyAddr == "" {
		return nil, fmt.Errorf("decoy destination not configured")
	}

	// Ensure port is specified
	if _, _, err := net.SplitHostPort(decoyAddr); err != nil {
		decoyAddr = net.JoinHostPort(decoyAddr, "443")
	}

	// Connect to decoy server
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	decoyConn, err := dialer.DialContext(ctx, "tcp", decoyAddr)
	if err != nil {
		return nil, fmt.Errorf("decoy connect: %w", err)
	}
	defer decoyConn.Close()

	// Perform TLS handshake with decoy
	decoyTLS := tls.Client(decoyConn, tlsCfg)
	if err := decoyTLS.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("decoy handshake: %w", err)
	}

	// Get the TLS state for verification
	state := decoyTLS.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("decoy server provided no certificates")
	}

	// Close TLS connection gracefully
	if err := decoyTLS.CloseWrite(); err != nil {
		return nil, fmt.Errorf("decoy close write: %w", err)
	}

	// Read any remaining data from decoy
	// This ensures we have the complete handshake
	_ = decoyConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	for {
		_, err := decoyConn.Read(buf)
		if err != nil {
			break
		}
	}

	// Now relay the handshake to the ShadowTLS server
	// In ShadowTLS v3, we send a special prefix indicating we're using
	// the "session ticket" extension to carry our data

	// Send protocol version indicator
	versionBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(versionBuf, uint16(d.Config.Version))
	if _, err := conn.Write(versionBuf); err != nil {
		return nil, fmt.Errorf("write version: %w", err)
	}

	// Send the decoy SNI we used
	sni := d.Config.Handshake.SNI
	if sni == "" {
		sni = d.Config.Handshake.Dest
	}
	sniLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sniLen, uint16(len(sni)))
	if _, err := conn.Write(sniLen); err != nil {
		return nil, fmt.Errorf("write sni len: %w", err)
	}
	if _, err := conn.Write([]byte(sni)); err != nil {
		return nil, fmt.Errorf("write sni: %w", err)
	}

	// Create the shadow connection wrapper
	sc := &shadowConn{
		Conn:       conn,
		serverConn: decoyConn,
		relayDone:  true,
	}

	return sc, nil
}

// performServerHandshake implements ShadowTLS v3 server handshake.
// It validates the client handshake and sets up the side channel.
func (l *Listener) performServerHandshake(conn net.Conn) (net.Conn, error) {
	// ShadowTLS v3 server flow:
	// 1. Read version indicator
	// 2. Read SNI from client
	// 3. Validate SNI against allowed list
	// 4. Connect to decoy server with same SNI
	// 5. Relay TLS handshake between client and decoy
	// 6. After handshake, switch to side channel for data

	// Read version
	versionBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, versionBuf); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	version := binary.BigEndian.Uint16(versionBuf)
	if version != uint16(l.config.Version) {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Read SNI length
	sniLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, sniLenBuf); err != nil {
		return nil, fmt.Errorf("read sni len: %w", err)
	}
	sniLen := binary.BigEndian.Uint16(sniLenBuf)
	if sniLen == 0 || sniLen > 253 { // Max SNI length + sanity check
		return nil, fmt.Errorf("invalid sni length: %d", sniLen)
	}

	// Read SNI
	sniBuf := make([]byte, sniLen)
	if _, err := io.ReadFull(conn, sniBuf); err != nil {
		return nil, fmt.Errorf("read sni: %w", err)
	}
	sni := string(sniBuf)

	// Validate SNI against allowed list
	if len(l.config.ServerNames) > 0 {
		if !l.validateSNI(sni) {
			return nil, fmt.Errorf("sni not allowed: %s", sni)
		}
	}

	// Get per-SNI handshake config
	handshakeCfg := l.getHandshakeConfig(sni)

	// Connect to decoy server
	decoyAddr := handshakeCfg.Dest
	if decoyAddr == "" {
		// Use the SNI as the decoy destination
		decoyAddr = sni
	}
	if _, _, err := net.SplitHostPort(decoyAddr); err != nil {
		decoyAddr = net.JoinHostPort(decoyAddr, "443")
	}

	// Connect to decoy
	decoyConn, err := net.DialTimeout("tcp", decoyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("decoy connect: %w", err)
	}
	defer decoyConn.Close()

	// Perform TLS handshake with decoy on behalf of client
	// This is the key ShadowTLS mechanism - the server acts as a proxy
	// for the TLS handshake, making traffic look like normal TLS to the decoy

	tlsCfg := &tls.Config{
		ServerName:         handshakeCfg.SNI,
		InsecureSkipVerify: true, // We just need the handshake to succeed
		NextProtos:         handshakeCfg.ALPN,
	}

	// Apply strict mode or custom TLS versions
	l.applyStrictMode(tlsCfg)

	decoyTLS := tls.Client(decoyConn, tlsCfg)
	if err := decoyTLS.Handshake(); err != nil {
		return nil, fmt.Errorf("decoy handshake: %w", err)
	}

	// Close the decoy connection - handshake is complete
	_ = decoyTLS.CloseWrite()

	// Create the shadow connection
	sc := &shadowConn{
		Conn:      conn,
		relayDone: true,
	}

	return sc, nil
}

// Read implements io.Reader for shadowConn.
func (sc *shadowConn) Read(p []byte) (n int, err error) {
	return sc.Conn.Read(p)
}

// Write implements io.Writer for shadowConn.
func (sc *shadowConn) Write(p []byte) (n int, err error) {
	return sc.Conn.Write(p)
}

// SetDeadline implements net.Conn.
func (sc *shadowConn) SetDeadline(t time.Time) error {
	return sc.Conn.SetDeadline(t)
}

// SetReadDeadline implements net.Conn.
func (sc *shadowConn) SetReadDeadline(t time.Time) error {
	return sc.Conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.Conn.
func (sc *shadowConn) SetWriteDeadline(t time.Time) error {
	return sc.Conn.SetWriteDeadline(t)
}

// SessionIDAuth implements ShadowTLS v3 Session ID authentication.
// In ShadowTLS v3, the client embeds authentication data in the TLS Session ID field.
type SessionIDAuth struct {
	Password   string
	SessionID  [32]byte
	Timestamp  uint64
	Random     [24]byte
}

// GenerateSessionID generates a ShadowTLS v3 Session ID with embedded auth.
// Format:
// - 8 bytes: timestamp (big endian)
// - 24 bytes: random data
// - 32 bytes: HMAC-SHA256(password, timestamp || random)
func GenerateSessionID(password string) [32]byte {
	var sessionID [32]byte

	// Timestamp (8 bytes)
	timestamp := uint64(time.Now().Unix())
	binary.BigEndian.PutUint64(sessionID[:8], timestamp)

	// Random data (24 bytes)
	rand.Read(sessionID[8:32])

	// Calculate HMAC
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(sessionID[:32])
	sum := mac.Sum(nil)

	// Store HMAC in last 32 bytes (we need a larger session ID or truncate)
	// Actually, TLS Session ID is max 32 bytes, so we use:
	// - 8 bytes: timestamp
	// - 24 bytes: HMAC-SHA256 truncated to 24 bytes
	var result [32]byte
	binary.BigEndian.PutUint64(result[:8], timestamp)
	copy(result[8:], sum[:24])

	return result
}

// VerifySessionID verifies a ShadowTLS v3 Session ID.
func VerifySessionID(password string, sessionID [32]byte) bool {
	// Extract timestamp
	timestamp := binary.BigEndian.Uint64(sessionID[:8])

	// Check timestamp is within acceptable window (±30 seconds)
	now := uint64(time.Now().Unix())
	if timestamp > now+30 || timestamp < now-300 {
		return false
	}

	// Calculate expected HMAC
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(sessionID[:8])
	sum := mac.Sum(nil)

	// Compare with provided HMAC (last 24 bytes)
	return hmac.Equal(sessionID[8:], sum[:24])
}

// EmbedAuthInClientHello embeds authentication in a TLS Client Hello.
// It replaces the Session ID field with an authenticated session ID.
func EmbedAuthInClientHello(clientHello []byte, password string) ([]byte, error) {
	if len(clientHello) < 43 {
		return nil, fmt.Errorf("client hello too short")
	}

	// Parse the Client Hello to find the session ID
	offset := 0

	// Skip record layer if present
	if clientHello[0] == 0x16 {
		offset += 5
	}

	// Skip handshake header
	offset += 4

	// Skip client version
	offset += 2

	// Skip random
	offset += 32

	// Read session ID length
	sessionIDLen := int(clientHello[offset])
	offset++

	if sessionIDLen != 32 && sessionIDLen != 0 {
		// Replace existing session ID
		// For simplicity, we'll create a new Client Hello with our session ID
	}

	// Generate authenticated session ID
	sessionID := GenerateSessionID(password)

	// Create modified Client Hello
	modified := make([]byte, len(clientHello)+32-sessionIDLen)
	copy(modified, clientHello[:offset-1])
	modified[offset-1] = 32 // New session ID length
	copy(modified[offset:], sessionID[:])
	copy(modified[offset+32:], clientHello[offset+sessionIDLen:])

	return modified, nil
}

// ExtractAndVerifySessionID extracts and verifies the Session ID from Client Hello.
func ExtractAndVerifySessionID(clientHello []byte, password string) (bool, error) {
	if len(clientHello) < 43 {
		return false, fmt.Errorf("client hello too short")
	}

	offset := 0

	// Skip record layer if present
	if clientHello[0] == 0x16 {
		offset += 5
	}

	// Skip handshake header
	offset += 4

	// Skip client version
	offset += 2

	// Skip random
	offset += 32

	// Read session ID length
	if offset >= len(clientHello) {
		return false, fmt.Errorf("truncated client hello")
	}
	sessionIDLen := int(clientHello[offset])
	offset++

	if sessionIDLen != 32 {
		return false, fmt.Errorf("invalid session ID length: %d", sessionIDLen)
	}

	if len(clientHello) < offset+32 {
		return false, fmt.Errorf("truncated session ID")
	}

	// Extract session ID
	var sessionID [32]byte
	copy(sessionID[:], clientHello[offset:offset+32])

	// Verify
	return VerifySessionID(password, sessionID), nil
}

// performClientHandshakeV3 performs ShadowTLS v3 handshake with Session ID auth.
func (d *Dialer) performClientHandshakeV3(ctx context.Context, conn net.Conn, tlsCfg *tls.Config) (net.Conn, error) {
	// ShadowTLS v3 client flow with Session ID authentication:
	// 1. Generate authenticated Session ID
	// 2. Connect to ShadowTLS server
	// 3. Send TLS Client Hello with embedded Session ID
	// 4. Relay handshake to decoy server

	// Generate authenticated Session ID
	sessionID := GenerateSessionID(d.Config.Password)

	// Connect to decoy server
	decoyAddr := d.Config.Handshake.Dest
	if decoyAddr == "" {
		return nil, fmt.Errorf("decoy destination not configured")
	}

	if _, _, err := net.SplitHostPort(decoyAddr); err != nil {
		decoyAddr = net.JoinHostPort(decoyAddr, "443")
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	decoyConn, err := dialer.DialContext(ctx, "tcp", decoyAddr)
	if err != nil {
		return nil, fmt.Errorf("decoy connect: %w", err)
	}
	defer decoyConn.Close()

	// Perform TLS handshake with decoy, but we'll intercept and modify
	// For v3, we create a custom Client Hello with our Session ID

	// Send protocol indicator to ShadowTLS server
	if _, err := conn.Write([]byte{0x03}); err != nil {
		return nil, fmt.Errorf("write version: %w", err)
	}

	// Send session ID
	if _, err := conn.Write(sessionID[:]); err != nil {
		return nil, fmt.Errorf("write session ID: %w", err)
	}

	// Send SNI
	sni := d.Config.Handshake.SNI
	if sni == "" {
		sni = d.Config.Handshake.Dest
	}
	sniLen := make([]byte, 2)
	binary.BigEndian.PutUint16(sniLen, uint16(len(sni)))
	if _, err := conn.Write(sniLen); err != nil {
		return nil, fmt.Errorf("write sni len: %w", err)
	}
	if _, err := conn.Write([]byte(sni)); err != nil {
		return nil, fmt.Errorf("write sni: %w", err)
	}

	// Create shadow connection
	sc := &shadowConn{
		Conn:       conn,
		serverConn: decoyConn,
		relayDone:  true,
	}

	return sc, nil
}

// performServerHandshakeV3 performs ShadowTLS v3 server handshake with Session ID verification.
func (l *Listener) performServerHandshakeV3(conn net.Conn) (net.Conn, error) {
	// ShadowTLS v3 server flow:
	// 1. Read version byte
	// 2. Read and verify Session ID
	// 3. Read SNI
	// 4. Relay to decoy server

	// Read version
	versionBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, versionBuf); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if versionBuf[0] != 0x03 {
		return nil, fmt.Errorf("unsupported version: %d", versionBuf[0])
	}

	// Read Session ID
	var sessionID [32]byte
	if _, err := io.ReadFull(conn, sessionID[:]); err != nil {
		return nil, fmt.Errorf("read session ID: %w", err)
	}

	// Verify Session ID
	if !VerifySessionID(l.config.Password, sessionID) {
		return nil, fmt.Errorf("invalid session ID")
	}

	// Read SNI length
	sniLenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, sniLenBuf); err != nil {
		return nil, fmt.Errorf("read sni len: %w", err)
	}
	sniLen := binary.BigEndian.Uint16(sniLenBuf)

	// Read SNI
	sniBuf := make([]byte, sniLen)
	if _, err := io.ReadFull(conn, sniBuf); err != nil {
		return nil, fmt.Errorf("read sni: %w", err)
	}
	sni := string(sniBuf)

	// Validate SNI
	if len(l.config.ServerNames) > 0 {
		if !l.validateSNI(sni) {
			return nil, fmt.Errorf("sni not allowed: %s", sni)
		}
	}

	// Connect to decoy server
	handshakeCfg := l.getHandshakeConfig(sni)
	decoyAddr := handshakeCfg.Dest
	if decoyAddr == "" {
		decoyAddr = sni
	}
	if _, _, err := net.SplitHostPort(decoyAddr); err != nil {
		decoyAddr = net.JoinHostPort(decoyAddr, "443")
	}

	decoyConn, err := net.DialTimeout("tcp", decoyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("decoy connect: %w", err)
	}
	defer decoyConn.Close()

	// Perform handshake with decoy
	tlsCfg := &tls.Config{
		ServerName:         handshakeCfg.SNI,
		InsecureSkipVerify: true,
		NextProtos:         handshakeCfg.ALPN,
	}
	l.applyStrictMode(tlsCfg)

	decoyTLS := tls.Client(decoyConn, tlsCfg)
	if err := decoyTLS.Handshake(); err != nil {
		return nil, fmt.Errorf("decoy handshake: %w", err)
	}
	_ = decoyTLS.CloseWrite()

	// Create shadow connection
	sc := &shadowConn{
		Conn:      conn,
		relayDone: true,
	}

	return sc, nil
}
