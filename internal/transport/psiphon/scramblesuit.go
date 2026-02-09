// Package psiphon implements Psiphon protocol support
package psiphon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

// ScrambleSuitConfig configures the ScrambleSuit protocol
// ScrambleSuit is a pluggable transport that provides polymorphic protocol obfuscation
type ScrambleSuitConfig struct {
	// Password for key derivation
	Password string

	// SessionTicket for session resumption (optional)
	SessionTicket []byte

	// UniformDH key (optional, for authenticated handshake)
	UniformDHKey []byte

	// Maximum padding size
	MaxPadding int

	// IAT (Inter-Arrival Time) obfuscation mode
	// 0 = disabled, 1 = enabled
	IATMode int

	// Supported protocols for negotiation
	Protocols []string
}

// DefaultScrambleSuitConfig returns default configuration
func DefaultScrambleSuitConfig() *ScrambleSuitConfig {
	return &ScrambleSuitConfig{
		MaxPadding: 1399,
		IATMode:    0,
		Protocols:  []string{"scramblesuit", "raw"},
	}
}

// ScrambleSuitConn wraps a connection with ScrambleSuit obfuscation
type ScrambleSuitConn struct {
	net.Conn
	config *ScrambleSuitConfig

	// Handshake state
	handshakeComplete atomic.Bool
	isServer          bool

	// Crypto keys
	aesKey    []byte
	hmacKey   []byte
	encoderIV []byte
	decoderIV []byte

	// Crypto state
	encoderCipher cipher.AEAD
	decoderCipher cipher.AEAD

	// Frame handling
	readBuf  []byte
	writeBuf []byte
	readMu   sync.Mutex
	writeMu  sync.Mutex

	// Session ticket for resumption
	sessionTicket []byte

	// IAT obfuscation
	iatMode   int
	iatWg     sync.WaitGroup
	iatStopCh chan struct{}
}

// ScrambleSuitHeader represents the ScrambleSuit protocol header
type ScrambleSuitHeader struct {
	Magic         [16]byte // Random magic bytes
	ProtocolFlags uint16   // Protocol negotiation flags
	PaddingLen    uint16   // Length of padding
	TicketLen     uint16   // Length of session ticket
}

// DialScrambleSuit connects to a ScrambleSuit server
func DialScrambleSuit(conn net.Conn, config *ScrambleSuitConfig) (*ScrambleSuitConn, error) {
	if config == nil {
		config = DefaultScrambleSuitConfig()
	}

	sc := &ScrambleSuitConn{
		Conn:      conn,
		config:    config,
		isServer:  false,
		iatMode:   config.IATMode,
		iatStopCh: make(chan struct{}),
	}

	// Perform handshake
	if err := sc.clientHandshake(); err != nil {
		return nil, err
	}

	// Start IAT obfuscation if enabled
	if sc.iatMode > 0 {
		sc.iatWg.Add(1)
		go sc.iatLoop()
	}

	return sc, nil
}

// AcceptScrambleSuit accepts a ScrambleSuit connection
func AcceptScrambleSuit(conn net.Conn, config *ScrambleSuitConfig) (*ScrambleSuitConn, error) {
	if config == nil {
		return nil, fmt.Errorf("scramblesuit server requires config")
	}

	sc := &ScrambleSuitConn{
		Conn:      conn,
		config:    config,
		isServer:  true,
		iatMode:   config.IATMode,
		iatStopCh: make(chan struct{}),
	}

	// Perform server handshake
	if err := sc.serverHandshake(); err != nil {
		return nil, err
	}

	// Start IAT obfuscation if enabled
	if sc.iatMode > 0 {
		sc.iatWg.Add(1)
		go sc.iatLoop()
	}

	return sc, nil
}

// clientHandshake performs client-side handshake
func (c *ScrambleSuitConn) clientHandshake() error {
	// Generate random magic bytes
	var magic [16]byte
	rand.Read(magic[:])

	// Build header with padding
	paddingLen := c.randomPaddingLength()
	header := &ScrambleSuitHeader{
		Magic:         magic,
		ProtocolFlags: 0x0001, // ScrambleSuit protocol
		PaddingLen:    uint16(paddingLen),
	}

	if len(c.config.SessionTicket) > 0 {
		header.TicketLen = uint16(len(c.config.SessionTicket))
	}

	// Send header
	if err := c.sendHeader(header); err != nil {
		return err
	}

	// Send padding
	padding := make([]byte, paddingLen)
	rand.Read(padding)
	if _, err := c.Conn.Write(padding); err != nil {
		return err
	}

	// Send session ticket if available
	if len(c.config.SessionTicket) > 0 {
		if _, err := c.Conn.Write(c.config.SessionTicket); err != nil {
			return err
		}
	}

	// Read server response
	serverHeader, err := c.receiveHeader()
	if err != nil {
		return fmt.Errorf("failed to receive server header: %w", err)
	}

	// Derive keys from password and header data
	if err := c.deriveKeys(magic[:], serverHeader.Magic[:]); err != nil {
		return err
	}

	// Skip server padding
	serverPadding := make([]byte, serverHeader.PaddingLen)
	if _, err := io.ReadFull(c.Conn, serverPadding); err != nil {
		return err
	}

	c.handshakeComplete.Store(true)
	return nil
}

// serverHandshake performs server-side handshake
func (c *ScrambleSuitConn) serverHandshake() error {
	// Read client header
	clientHeader, err := c.receiveHeader()
	if err != nil {
		return fmt.Errorf("failed to receive client header: %w", err)
	}

	// Skip client padding
	clientPadding := make([]byte, clientHeader.PaddingLen)
	if _, err := io.ReadFull(c.Conn, clientPadding); err != nil {
		return err
	}

	// Read session ticket if present
	if clientHeader.TicketLen > 0 {
		c.sessionTicket = make([]byte, clientHeader.TicketLen)
		if _, err := io.ReadFull(c.Conn, c.sessionTicket); err != nil {
			return err
		}
	}

	// Generate server response
	var serverMagic [16]byte
	rand.Read(serverMagic[:])

	paddingLen := c.randomPaddingLength()
	serverHeader := &ScrambleSuitHeader{
		Magic:         serverMagic,
		ProtocolFlags: 0x0001,
		PaddingLen:    uint16(paddingLen),
	}

	// Send server header
	if err := c.sendHeader(serverHeader); err != nil {
		return err
	}

	// Send server padding
	padding := make([]byte, paddingLen)
	rand.Read(padding)
	if _, err := c.Conn.Write(padding); err != nil {
		return err
	}

	// Derive keys
	if err := c.deriveKeys(clientHeader.Magic[:], serverMagic[:]); err != nil {
		return err
	}

	c.handshakeComplete.Store(true)
	return nil
}

// sendHeader sends the ScrambleSuit header
func (c *ScrambleSuitConn) sendHeader(header *ScrambleSuitHeader) error {
	buf := make([]byte, 22)
	copy(buf[0:16], header.Magic[:])
	binary.BigEndian.PutUint16(buf[16:18], header.ProtocolFlags)
	binary.BigEndian.PutUint16(buf[18:20], header.PaddingLen)
	binary.BigEndian.PutUint16(buf[20:22], header.TicketLen)

	_, err := c.Conn.Write(buf)
	return err
}

// receiveHeader receives the ScrambleSuit header
func (c *ScrambleSuitConn) receiveHeader() (*ScrambleSuitHeader, error) {
	buf := make([]byte, 22)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, err
	}

	header := &ScrambleSuitHeader{}
	copy(header.Magic[:], buf[0:16])
	header.ProtocolFlags = binary.BigEndian.Uint16(buf[16:18])
	header.PaddingLen = binary.BigEndian.Uint16(buf[18:20])
	header.TicketLen = binary.BigEndian.Uint16(buf[20:22])

	return header, nil
}

// randomPaddingLength generates a random padding length
func (c *ScrambleSuitConn) randomPaddingLength() int {
	if c.config.MaxPadding <= 0 {
		c.config.MaxPadding = 1399
	}

	// Uniform distribution
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomValue := binary.BigEndian.Uint32(randomBytes)

	return int(randomValue) % c.config.MaxPadding
}

// deriveKeys derives encryption keys from password and nonces
func (c *ScrambleSuitConn) deriveKeys(clientNonce, serverNonce []byte) error {
	// Create key material
	keyMaterial := []byte(c.config.Password)
	keyMaterial = append(keyMaterial, clientNonce...)
	keyMaterial = append(keyMaterial, serverNonce...)

	// Derive keys using HKDF-like construction
	h := hmac.New(sha256.New, []byte("scramblesuit-key-derivation"))
	h.Write(keyMaterial)
	derived := h.Sum(nil)

	// Split into AES key and HMAC key
	c.aesKey = derived[:16]
	c.hmacKey = derived[16:]

	// Create AES-GCM ciphers
	block, err := aes.NewCipher(c.aesKey)
	if err != nil {
		return err
	}

	// Generate IVs
	c.encoderIV = make([]byte, 12)
	c.decoderIV = make([]byte, 12)
	rand.Read(c.encoderIV)
	rand.Read(c.decoderIV)

	if c.isServer {
		c.encoderCipher, err = cipher.NewGCM(block)
		if err != nil {
			return err
		}
		c.decoderCipher = c.encoderCipher
	} else {
		c.encoderCipher, err = cipher.NewGCM(block)
		if err != nil {
			return err
		}
		c.decoderCipher = c.encoderCipher
	}

	return nil
}

// encrypt encrypts data using AES-GCM
func (c *ScrambleSuitConn) encrypt(plaintext []byte) []byte {
	nonce := make([]byte, 12)
	copy(nonce, c.encoderIV)

	// Increment nonce counter
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])+1)

	return c.encoderCipher.Seal(nil, nonce, plaintext, nil)
}

// decrypt decrypts data using AES-GCM
func (c *ScrambleSuitConn) decrypt(ciphertext []byte) ([]byte, error) {
	nonce := make([]byte, 12)
	copy(nonce, c.decoderIV)

	// Increment nonce counter
	binary.BigEndian.PutUint64(nonce[4:], binary.BigEndian.Uint64(nonce[4:])+1)

	return c.decoderCipher.Open(nil, nonce, ciphertext, nil)
}

// Read reads data from the connection
func (c *ScrambleSuitConn) Read(p []byte) (int, error) {
	if !c.handshakeComplete.Load() {
		return 0, fmt.Errorf("handshake not complete")
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Return buffered data
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read frame length
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}

	frameLen := binary.BigEndian.Uint16(lenBuf[:])
	if frameLen == 0 || frameLen > 16384 {
		return 0, fmt.Errorf("invalid frame length")
	}

	// Read encrypted frame
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}

	// Decrypt
	plaintext, err := c.decrypt(frame)
	if err != nil {
		return 0, err
	}

	// Extract payload: [length || payload || padding]
	if len(plaintext) < 2 {
		return 0, fmt.Errorf("frame too short")
	}

	payloadLen := binary.BigEndian.Uint16(plaintext[:2])
	if int(payloadLen) > len(plaintext)-2 {
		return 0, fmt.Errorf("invalid payload length")
	}

	payload := plaintext[2 : 2+payloadLen]

	// Copy to output
	n := copy(p, payload)
	if n < len(payload) {
		c.readBuf = payload[n:]
	}

	return n, nil
}

// Write writes data to the connection
func (c *ScrambleSuitConn) Write(p []byte) (int, error) {
	if !c.handshakeComplete.Load() {
		return 0, fmt.Errorf("handshake not complete")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalWritten := 0

	// Chunk data
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > 1400 {
			chunkSize = 1400
		}

		chunk := p[:chunkSize]
		p = p[chunkSize:]

		// Add padding for uniform distribution
		paddingLen := c.calculateUniformPadding(len(chunk))
		frameLen := 2 + len(chunk) + paddingLen

		frame := make([]byte, frameLen)
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(chunk)))
		copy(frame[2:], chunk)

		if paddingLen > 0 {
			rand.Read(frame[2+len(chunk):])
		}

		// Encrypt
		ciphertext := c.encrypt(frame)

		// Send: [length || ciphertext]
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(ciphertext)))

		if _, err := c.Conn.Write(lenBuf); err != nil {
			return totalWritten, err
		}
		if _, err := c.Conn.Write(ciphertext); err != nil {
			return totalWritten, err
		}

		totalWritten += chunkSize
	}

	return totalWritten, nil
}

// calculateUniformPadding calculates padding for uniform distribution
func (c *ScrambleSuitConn) calculateUniformPadding(payloadLen int) int {
	// Target uniform distribution between min and max packet sizes
	minSize := 16
	maxSize := 1399

	if payloadLen >= maxSize {
		return 0
	}

	// Random padding to reach uniform distribution
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomValue := binary.BigEndian.Uint32(randomBytes)

	targetSize := minSize + int(randomValue)%int(maxSize-minSize)
	if targetSize < payloadLen {
		targetSize = payloadLen
	}

	return targetSize - payloadLen
}

// Close closes the connection
func (c *ScrambleSuitConn) Close() error {
	if c.iatMode > 0 {
		close(c.iatStopCh)
		c.iatWg.Wait()
	}
	return c.Conn.Close()
}

// iatLoop sends dummy traffic for IAT obfuscation
func (c *ScrambleSuitConn) iatLoop() {
	defer c.iatWg.Done()

	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()

	for {
		select {
		case <-c.iatStopCh:
			return
		case <-ticker.C:
			// Send dummy frame
			c.sendDummyFrame()
		}
	}
}

// sendDummyFrame sends a dummy frame for IAT obfuscation
func (c *ScrambleSuitConn) sendDummyFrame() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Create dummy payload
	dummy := make([]byte, 16)
	rand.Read(dummy)

	// Mark as dummy frame
	binary.BigEndian.PutUint16(dummy[0:2], 0xFFFF)

	// Encrypt and send
	ciphertext := c.encrypt(dummy)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(ciphertext)))

	if _, err := c.Conn.Write(lenBuf); err != nil {
		return err
	}
	_, err := c.Conn.Write(ciphertext)
	return err
}

// GenerateSessionTicket generates a new session ticket
func GenerateSessionTicket(password string) ([]byte, error) {
	// Ticket format: [expiry || encrypted_payload || mac]
	ticket := make([]byte, 64)

	// Set expiry (24 hours from now)
	expiry := time.Now().Add(24 * time.Hour).Unix()
	binary.BigEndian.PutUint64(ticket[0:8], uint64(expiry))

	// Generate random payload
	rand.Read(ticket[8:56])

	// Calculate MAC
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(ticket[:56])
	copy(ticket[56:], mac.Sum(nil)[:8])

	return ticket, nil
}

// VerifySessionTicket verifies a session ticket
func VerifySessionTicket(ticket []byte, password string) bool {
	if len(ticket) < 64 {
		return false
	}

	// Verify MAC
	mac := hmac.New(sha256.New, []byte(password))
	mac.Write(ticket[:56])
	expectedMAC := mac.Sum(nil)[:8]

	if !bytes.Equal(ticket[56:64], expectedMAC) {
		return false
	}

	// Check expiry
	expiry := int64(binary.BigEndian.Uint64(ticket[0:8]))
	return time.Now().Unix() < expiry
}

// ScrambleSuitListener wraps a listener for ScrambleSuit connections
type ScrambleSuitListener struct {
	net.Listener
	config *ScrambleSuitConfig
}

// ListenScrambleSuit creates a ScrambleSuit listener
func ListenScrambleSuit(listener net.Listener, config *ScrambleSuitConfig) (*ScrambleSuitListener, error) {
	if config == nil {
		return nil, fmt.Errorf("scramblesuit listener requires config")
	}

	return &ScrambleSuitListener{
		Listener: listener,
		config:   config,
	}, nil
}

// Accept accepts a ScrambleSuit connection
func (l *ScrambleSuitListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return AcceptScrambleSuit(conn, l.config)
}

// UniformDHKey represents a UniformDH key for authenticated handshake
type UniformDHKey struct {
	Private []byte
	Public  []byte
}

// GenerateUniformDHKey generates a new UniformDH key pair
func GenerateUniformDHKey() (*UniformDHKey, error) {
	key := &UniformDHKey{
		Private: make([]byte, 32),
		Public:  make([]byte, 32),
	}

	if _, err := rand.Read(key.Private); err != nil {
		return nil, err
	}

	// Clamp
	key.Private[0] &= 248
	key.Private[31] &= 127
	key.Private[31] |= 64

	// Calculate public key
	public, err := curve25519.X25519(key.Private, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(key.Public, public)

	return key, nil
}

// Helper to ensure bytes package is imported
var _ = bytes.NewBuffer(nil)
