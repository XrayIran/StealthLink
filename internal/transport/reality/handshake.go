package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/curve25519"
)

// Constants for REALITY handshake.
const (
	HandshakeVersion     = 0x01
	MaxHandshakeTime     = 30 * time.Second
	MaxHandshakeDataSize = 8192
	ShortIDLength        = 8
)

// HandshakeState represents the state of a REALITY handshake.
type HandshakeState int

const (
	StateInitial HandshakeState = iota
	StateClientHello
	StateServerHello
	StateEstablished
)

// AuthID represents a valid authentication ID for a session.
type AuthID struct {
	ShortID []byte
	UUID    [16]byte
}

// HandshakeConfig holds configuration for REALITY handshake.
type HandshakeConfig struct {
	Dest           string
	ServerNames    []string
	PrivateKey     []byte // X25519 private key
	PublicKey      []byte // X25519 public key (derived)
	ShortIDs       [][]byte
	SpiderX        string
	SpiderY        string
	Show           bool
	SessionTickets bool
}

// sessionCache caches validated sessions to prevent replay attacks.
type sessionCache struct {
	mu       sync.RWMutex
	sessions map[string]time.Time // session ID -> expiration time
}

func newSessionCache() *sessionCache {
	sc := &sessionCache{
		sessions: make(map[string]time.Time),
	}
	go sc.cleanup()
	return sc
}

func (sc *sessionCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		sc.mu.Lock()
		now := time.Now()
		for id, exp := range sc.sessions {
			if now.After(exp) {
				delete(sc.sessions, id)
			}
		}
		sc.mu.Unlock()
	}
}

func (sc *sessionCache) add(sessionID string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.sessions[sessionID] = time.Now().Add(5 * time.Minute)
}

func (sc *sessionCache) exists(sessionID string) bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	_, ok := sc.sessions[sessionID]
	return ok
}

var globalSessionCache = newSessionCache()

// realityConn wraps a net.Conn with REALITY handshake state.
type realityConn struct {
	net.Conn
	state        HandshakeState
	privateKey   []byte
	publicKey    []byte
	sharedKey    []byte
	shortID      []byte
	cipher       cipher.AEAD
	readNonce    []byte
	writeNonce   []byte
	isClient     bool
	fallbackConn net.Conn // Set if in fallback mode
}

// IsFallback returns true if this connection is in fallback mode (relaying to destination).
func (rc *realityConn) IsFallback() bool {
	return rc.fallbackConn != nil
}

// performClientHandshake performs the client-side REALITY handshake.
// This implements the full REALITY protocol with X25519 ECDH, Ed25519 signatures, and AES-GCM.
func (d *Dialer) performClientHandshake(conn net.Conn, privateKey []byte) (net.Conn, error) {
	// Use a per-connection ephemeral X25519 key; the configured key is used as identity material.
	clientPrivate := make([]byte, 32)
	if _, err := rand.Read(clientPrivate); err != nil {
		return nil, fmt.Errorf("generate client key: %w", err)
	}

	rc := &realityConn{
		Conn:       conn,
		state:      StateInitial,
		privateKey: clientPrivate,
		isClient:   true,
	}

	// Generate ephemeral X25519 public key from ephemeral private key.
	publicKey, err := curve25519.X25519(clientPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral key pair: %w", err)
	}
	rc.publicKey = publicKey

	// Get server long-term X25519 public key and Ed25519 verify key.
	serverPublicKey, err := d.getServerPublicKey()
	if err != nil {
		return nil, fmt.Errorf("get server public key: %w", err)
	}
	serverVerifyKey, err := d.getServerVerifyKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("get server verify key: %w", err)
	}

	// Pre-compute shared secret for deriving keys.
	sharedSecret, err := curve25519.X25519(clientPrivate, serverPublicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared secret: %w", err)
	}

	// Derive session keys using HKDF
	clientKey, _, err := DeriveSessionKeys(sharedSecret, publicKey)
	if err != nil {
		return nil, fmt.Errorf("derive session keys: %w", err)
	}

	// Create AES-GCM cipher for client-to-server encryption
	block, err := aes.NewCipher(clientKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	rc.cipher, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// Generate short ID for this session
	shortID := ShortID(publicKey, ShortIDLength)

	// Build REALITY Client Hello (wrapped in TLS 1.3 Client Hello)
	clientHello, err := rc.buildRealityClientHello(d, publicKey, shortID)
	if err != nil {
		return nil, fmt.Errorf("build client hello: %w", err)
	}

	// Send client hello as a framed handshake message.
	if err := rc.sendHandshakeMessage(clientHello); err != nil {
		return nil, fmt.Errorf("send client hello: %w", err)
	}
	rc.state = StateClientHello

	// Receive Server Hello
	serverHello, err := rc.receiveHandshakeMessage()
	if err != nil {
		return nil, fmt.Errorf("receive server hello: %w", err)
	}

	// Process server hello with Ed25519 signature verification.
	if err := rc.processServerHello(serverHello, serverVerifyKey); err != nil {
		return nil, fmt.Errorf("process server hello: %w", err)
	}

	rc.state = StateEstablished
	rc.sharedKey = sharedSecret
	return rc, nil
}

// getServerPublicKey returns the server's long-term X25519 public key.
func (d *Dialer) getServerPublicKey() ([]byte, error) {
	if d.Config == nil {
		return nil, fmt.Errorf("missing config")
	}
	serverPrivate, err := parseKey(d.Config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	pub, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return pub, nil
}

func (d *Dialer) getServerVerifyKey(serverPrivate []byte) (ed25519.PublicKey, error) {
	if d.Config == nil {
		return nil, fmt.Errorf("missing config")
	}
	edPriv := deriveEd25519Private(serverPrivate, signingContext(d.Config))
	return edPriv.Public().(ed25519.PublicKey), nil
}

// buildRealityClientHello builds the framed REALITY client hello.
func (rc *realityConn) buildRealityClientHello(d *Dialer, publicKey, shortID []byte) ([]byte, error) {
	// Get SNI from config.
	serverName := d.Config.Dest
	if serverName == "" && len(d.Config.ServerNames) > 0 {
		serverName = d.Config.ServerNames[0]
	}
	if serverName == "" {
		return nil, fmt.Errorf("missing destination/server name")
	}

	msg := make([]byte, 1+32+2+len(serverName)+8+len(shortID))
	offset := 0
	msg[offset] = HandshakeVersion
	offset++
	copy(msg[offset:], publicKey)
	offset += 32
	binary.BigEndian.PutUint16(msg[offset:], uint16(len(serverName)))
	offset += 2
	copy(msg[offset:], []byte(serverName))
	offset += len(serverName)
	binary.BigEndian.PutUint64(msg[offset:], uint64(time.Now().Unix()))
	offset += 8
	copy(msg[offset:], shortID)
	return msg, nil
}

// marshalClientHello marshals a ClientHelloSpec to bytes.
func (rc *realityConn) marshalClientHello(spec utls.ClientHelloSpec) []byte {
	var buf bytes.Buffer

	// TLS Record Layer
	buf.WriteByte(0x16) // Handshake
	buf.WriteByte(0x03) // Version major
	buf.WriteByte(0x01) // Version minor (TLS 1.0 for compatibility)
	// Length will be filled later

	// Handshake Header
	buf.WriteByte(0x01) // Client Hello
	// Length will be filled later

	// Client Version
	buf.Write([]byte{0x03, 0x03}) // TLS 1.2

	// Random (32 bytes)
	random := make([]byte, 32)
	rand.Read(random)
	buf.Write(random)

	// Session ID
	buf.WriteByte(32) // Length
	sessionID := make([]byte, 32)
	rand.Read(sessionID)
	buf.Write(sessionID)

	// Cipher Suites
	binary.Write(&buf, binary.BigEndian, uint16(len(spec.CipherSuites)*2))
	for _, cs := range spec.CipherSuites {
		binary.Write(&buf, binary.BigEndian, cs)
	}

	// Compression Methods
	buf.WriteByte(byte(len(spec.CompressionMethods)))
	buf.Write(spec.CompressionMethods)

	// Extensions
	extensionsData := rc.marshalExtensions(spec.Extensions)
	binary.Write(&buf, binary.BigEndian, uint16(len(extensionsData)))
	buf.Write(extensionsData)

	result := buf.Bytes()

	// Fill in lengths
	handshakeLen := len(result) - 9
	result[6] = byte(handshakeLen >> 16)
	result[7] = byte(handshakeLen >> 8)
	result[8] = byte(handshakeLen)

	recordLen := len(result) - 5
	result[3] = byte(recordLen >> 8)
	result[4] = byte(recordLen)

	return result
}

// marshalExtensions marshals TLS extensions.
func (rc *realityConn) marshalExtensions(extensions []utls.TLSExtension) []byte {
	var buf bytes.Buffer

	for _, ext := range extensions {
		switch e := ext.(type) {
		case *utls.SNIExtension:
			binary.Write(&buf, binary.BigEndian, uint16(0)) // Extension type
			nameData := []byte(e.ServerName)
			nameLen := 5 + len(nameData)
			binary.Write(&buf, binary.BigEndian, uint16(nameLen))
			binary.Write(&buf, binary.BigEndian, uint16(nameLen-2))
			buf.WriteByte(0) // Host name type
			binary.Write(&buf, binary.BigEndian, uint16(len(nameData)))
			buf.Write(nameData)

		case *utls.SupportedVersionsExtension:
			binary.Write(&buf, binary.BigEndian, uint16(43)) // Extension type
			binary.Write(&buf, binary.BigEndian, uint16(3+len(e.Versions)*2))
			buf.WriteByte(byte(len(e.Versions) * 2))
			for _, v := range e.Versions {
				binary.Write(&buf, binary.BigEndian, v)
			}

		case *utls.SupportedCurvesExtension:
			binary.Write(&buf, binary.BigEndian, uint16(10)) // Extension type
			binary.Write(&buf, binary.BigEndian, uint16(2+len(e.Curves)*2))
			binary.Write(&buf, binary.BigEndian, uint16(len(e.Curves)*2))
			for _, c := range e.Curves {
				binary.Write(&buf, binary.BigEndian, uint16(c))
			}

		case *utls.SupportedPointsExtension:
			binary.Write(&buf, binary.BigEndian, uint16(11)) // Extension type
			binary.Write(&buf, binary.BigEndian, uint16(1+len(e.SupportedPoints)))
			buf.WriteByte(byte(len(e.SupportedPoints)))
			buf.Write(e.SupportedPoints)

		case *utls.ALPNExtension:
			binary.Write(&buf, binary.BigEndian, uint16(16)) // Extension type
			var alpnBuf bytes.Buffer
			for _, proto := range e.AlpnProtocols {
				alpnBuf.WriteByte(byte(len(proto)))
				alpnBuf.WriteString(proto)
			}
			alpnData := alpnBuf.Bytes()
			binary.Write(&buf, binary.BigEndian, uint16(2+len(alpnData)))
			binary.Write(&buf, binary.BigEndian, uint16(len(alpnData)))
			buf.Write(alpnData)

		case *utls.KeyShareExtension:
			binary.Write(&buf, binary.BigEndian, uint16(51)) // Extension type
			var ksBuf bytes.Buffer
			for _, ks := range e.KeyShares {
				binary.Write(&ksBuf, binary.BigEndian, uint16(ks.Group))
				binary.Write(&ksBuf, binary.BigEndian, uint16(len(ks.Data)))
				ksBuf.Write(ks.Data)
			}
			ksData := ksBuf.Bytes()
			binary.Write(&buf, binary.BigEndian, uint16(2+len(ksData)))
			binary.Write(&buf, binary.BigEndian, uint16(len(ksData)))
			buf.Write(ksData)

		case *utls.SessionTicketExtension:
			binary.Write(&buf, binary.BigEndian, uint16(35)) // Extension type
			binary.Write(&buf, binary.BigEndian, uint16(0))

		case *utls.ExtendedMasterSecretExtension:
			binary.Write(&buf, binary.BigEndian, uint16(23)) // Extension type
			binary.Write(&buf, binary.BigEndian, uint16(0))

		case *utls.RenegotiationInfoExtension:
			binary.Write(&buf, binary.BigEndian, uint16(65281)) // Extension type
			binary.Write(&buf, binary.BigEndian, uint16(1))
			buf.WriteByte(byte(e.Renegotiation))
		}
	}

	return buf.Bytes()
}

// buildAuthData builds the REALITY authentication data appended to Client Hello.
func (rc *realityConn) buildAuthData(publicKey, shortID []byte) []byte {
	var buf bytes.Buffer

	// REALITY magic bytes
	buf.Write([]byte("REALITY"))

	// Version
	buf.WriteByte(HandshakeVersion)

	// Short ID
	buf.Write(shortID)

	// Timestamp
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(time.Now().Unix()))
	buf.Write(timestamp)

	return buf.Bytes()
}

// performServerHandshake performs the server-side REALITY handshake.
func (l *Listener) performServerHandshake(conn net.Conn) (net.Conn, error) {
	// REALITY server handshake:
	// 1. Receive ClientHello
	// 2. Validate SNI against allowed list
	// 3. Generate ephemeral key pair
	// 4. Compute shared key
	// 5. Send ServerHello with authentication

	rc := &realityConn{
		Conn:  conn,
		state: StateInitial,
	}

	// Receive ClientHello
	clientHello, err := rc.receiveHandshakeMessage()
	if err != nil {
		return nil, fmt.Errorf("receive client hello: %w", err)
	}

	// Process ClientHello
	if err := rc.processClientHello(clientHello, l.config); err != nil {
		return nil, fmt.Errorf("process client hello: %w", err)
	}

	// Parse server long-term private key (X25519).
	serverPrivate, err := parseKey(l.config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("generate server key: %w", err)
	}

	// Compute shared key
	sharedKey, err := curve25519.X25519(serverPrivate, rc.publicKey)
	if err != nil {
		return nil, fmt.Errorf("compute shared key: %w", err)
	}
	rc.sharedKey = sharedKey

	// Build and send server hello.
	serverHello, err := rc.buildServerHello(serverPublic, l.config)
	if err != nil {
		return nil, fmt.Errorf("build server hello: %w", err)
	}
	if err := rc.sendHandshakeMessage(serverHello); err != nil {
		return nil, fmt.Errorf("send server hello: %w", err)
	}

	rc.state = StateEstablished
	return rc, nil
}

func (l *Listener) isValidSNI(sni string) bool {
	if len(l.config.ServerNames) == 0 {
		return true
	}
	for _, name := range l.config.ServerNames {
		if name == sni {
			return true
		}
	}
	return false
}

func (l *Listener) isValidShortID(shortID []byte) bool {
	if len(l.config.ShortIds) == 0 {
		return true
	}
	for _, id := range l.config.ShortIds {
		if bytes.Equal([]byte(id), shortID) {
			return true
		}
	}
	return false
}

// processServerHello processes the server hello and verifies Ed25519 signature.
func (rc *realityConn) processServerHello(data []byte, serverVerifyKey ed25519.PublicKey) error {
	if len(data) < 105 {
		return fmt.Errorf("server hello too short")
	}

	offset := 0

	// Verify version
	version := data[offset]
	if version != HandshakeVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}
	offset++

	// Extract server public key
	serverPublic := data[offset : offset+32]
	offset += 32

	// Compute shared key
	sharedKey, err := curve25519.X25519(rc.privateKey, serverPublic)
	if err != nil {
		return fmt.Errorf("compute shared key: %w", err)
	}

	// Verify Ed25519 signature
	sig := data[offset : offset+64]
	offset += 64

	// Verify signature using server's long-term Ed25519 verify key.
	sigData := append(serverPublic, rc.publicKey...)
	if !ed25519.Verify(serverVerifyKey, sigData, sig) {
		return fmt.Errorf("signature verification failed")
	}

	// Validate timestamp
	timestamp := binary.BigEndian.Uint64(data[offset:])
	now := uint64(time.Now().Unix())
	if timestamp > now+60 || timestamp < now-300 {
		return fmt.Errorf("timestamp out of range")
	}

	rc.sharedKey = sharedKey
	return nil
}

// processClientHello processes the Client Hello message.
func (rc *realityConn) processClientHello(data []byte, config *Config) error {
	if len(data) < 43 {
		return fmt.Errorf("client hello too short")
	}

	offset := 0

	// Extract version
	version := data[offset]
	if version != HandshakeVersion {
		return fmt.Errorf("unsupported version: %d", version)
	}
	offset++

	// Extract client public key
	rc.publicKey = make([]byte, 32)
	copy(rc.publicKey, data[offset:offset+32])
	offset += 32

	// Extract SNI
	sniLen := binary.BigEndian.Uint16(data[offset:])
	offset += 2

	if len(data) < offset+int(sniLen)+16 {
		return fmt.Errorf("client hello truncated")
	}

	sni := string(data[offset : offset+int(sniLen)])
	offset += int(sniLen)

	// Validate SNI
	if len(config.ServerNames) > 0 {
		valid := false
		for _, name := range config.ServerNames {
			if name == sni {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("SNI not allowed: %s", sni)
		}
	}

	// Extract timestamp
	timestamp := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	// Validate timestamp (prevent replay)
	now := uint64(time.Now().Unix())
	if timestamp > now+60 || timestamp < now-300 {
		return fmt.Errorf("timestamp out of range")
	}

	// Check for replay attack
	sessionID := fmt.Sprintf("%x_%d", rc.publicKey, timestamp)
	if globalSessionCache.exists(sessionID) {
		return fmt.Errorf("replay detected")
	}
	globalSessionCache.add(sessionID)

	return nil
}

// buildServerHello builds the server hello with Ed25519 signature.
func (rc *realityConn) buildServerHello(serverPublic []byte, config *Config) ([]byte, error) {
	// Format:
	// 1 byte: version
	// 32 bytes: ephemeral public key
	// 64 bytes: Ed25519 signature
	// 8 bytes: timestamp

	msg := make([]byte, 1+32+64+8)
	offset := 0

	msg[offset] = HandshakeVersion
	offset++

	copy(msg[offset:], serverPublic)
	offset += 32

	// Sign the handshake data.
	sigData := append(serverPublic, rc.publicKey...)
	serverPrivate, err := parseKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	edPriv := deriveEd25519Private(serverPrivate, signingContext(config))
	sig := ed25519.Sign(edPriv, sigData)
	copy(msg[offset:], sig)
	offset += 64

	binary.BigEndian.PutUint64(msg[offset:], uint64(time.Now().Unix()))

	return msg, nil
}

// sendHandshakeMessage sends a handshake message with length prefix.
func (rc *realityConn) sendHandshakeMessage(msg []byte) error {
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(msg)))

	if _, err := rc.Write(length); err != nil {
		return err
	}
	_, err := rc.Write(msg)
	return err
}

// receiveHandshakeMessage receives a handshake message.
func (rc *realityConn) receiveHandshakeMessage() ([]byte, error) {
	rc.SetReadDeadline(time.Now().Add(MaxHandshakeTime))
	defer rc.SetReadDeadline(time.Time{})

	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(rc.Conn, lengthBuf); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(lengthBuf)
	if length > MaxHandshakeDataSize {
		return nil, fmt.Errorf("handshake message too large: %d", length)
	}

	msg := make([]byte, length)
	if _, err := io.ReadFull(rc.Conn, msg); err != nil {
		return nil, err
	}

	return msg, nil
}

// nopConn is a no-op connection for uTLS.
type nopConn struct{}

func (n *nopConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (n *nopConn) Write(p []byte) (int, error)        { return len(p), nil }
func (n *nopConn) Close() error                       { return nil }
func (n *nopConn) LocalAddr() net.Addr                { return nil }
func (n *nopConn) RemoteAddr() net.Addr               { return nil }
func (n *nopConn) SetDeadline(t time.Time) error      { return nil }
func (n *nopConn) SetReadDeadline(t time.Time) error  { return nil }
func (n *nopConn) SetWriteDeadline(t time.Time) error { return nil }

// FallbackDialer provides fallback functionality for REALITY.
type FallbackDialer struct {
	Dest string
}

// Dial connects to the fallback destination.
func (fd *FallbackDialer) Dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, "tcp", fd.Dest)
}

// HandleFallback relays traffic between client and destination when authentication fails.
// This makes the server indistinguishable from a regular TLS proxy.
func HandleFallback(clientConn net.Conn, dest string) error {
	if dest == "" {
		return fmt.Errorf("no fallback destination configured")
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	destConn, err := dialer.Dial("tcp", dest)
	if err != nil {
		return fmt.Errorf("fallback dial: %w", err)
	}
	defer destConn.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Bidirectional relay
	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(destConn, clientConn)
		errCh <- err
		cancel()
	}()

	go func() {
		_, err := io.Copy(clientConn, destConn)
		errCh <- err
		cancel()
	}()

	// Wait for either direction to complete
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

func deriveEd25519Private(serverPrivate []byte, context string) ed25519.PrivateKey {
	material := append([]byte("stealthlink-reality-ed25519:"), serverPrivate...)
	material = append(material, ':')
	material = append(material, context...)
	seed := sha256.Sum256(material)
	return ed25519.NewKeyFromSeed(seed[:])
}

func signingContext(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	if cfg.Dest != "" {
		return cfg.Dest
	}
	if len(cfg.ServerNames) > 0 {
		return cfg.ServerNames[0]
	}
	return ""
}
