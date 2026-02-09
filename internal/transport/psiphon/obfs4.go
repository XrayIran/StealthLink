// Package psiphon implements Psiphon protocol support
package psiphon

import (
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
	"golang.org/x/crypto/hkdf"
)

// Obfs4Config configures the obfs4 protocol
// Obfs4 is a pluggable transport that provides obfuscation based on ScrambleSuit
type Obfs4Config struct {
	// NodeID is the identity key for this node (32 bytes)
	NodeID []byte

	// PublicKey is the Curve25519 public key (32 bytes)
	PublicKey []byte

	// PrivateKey is the Curve25519 private key (32 bytes)
	PrivateKey []byte

	// DriftTolerance for clock drift in milliseconds
	DriftTolerance int

	// IATMode (Inter-Arrival Time Mode)
	// 0 = disabled, 1 = enabled, 2 = aggressive
	IATMode int
}

// GenerateObfs4Keys generates new obfs4 keys
func GenerateObfs4Keys() (*Obfs4Config, error) {
	cfg := &Obfs4Config{
		DriftTolerance: 86400000, // 24 hours
		IATMode:        0,
	}

	// Generate NodeID
	cfg.NodeID = make([]byte, 32)
	if _, err := rand.Read(cfg.NodeID); err != nil {
		return nil, err
	}

	// Generate Curve25519 keypair
	cfg.PrivateKey = make([]byte, 32)
	if _, err := rand.Read(cfg.PrivateKey); err != nil {
		return nil, err
	}

	// Clamp private key
	cfg.PrivateKey[0] &= 248
	cfg.PrivateKey[31] &= 127
	cfg.PrivateKey[31] |= 64

	// Generate public key
	cfg.PublicKey, _ = curve25519.X25519(cfg.PrivateKey, curve25519.Basepoint)

	return cfg, nil
}

// Obfs4Conn wraps a connection with obfs4 obfuscation
type Obfs4Conn struct {
	net.Conn
	config *Obfs4Config

	// Handshake state
	handshakeComplete atomic.Bool
	isServer          bool

	// Encryption keys
	encoderKey []byte
	decoderKey []byte

	// Nonce counters
	encoderNonce atomic.Uint64
	decoderNonce atomic.Uint64

	// Frame handling
	readBuf  []byte
	writeBuf []byte
	readMu   sync.Mutex
	writeMu  sync.Mutex

	// IAT (Inter-Arrival Time) mode
	iatMode int
}

// DialObfs4 connects to an obfs4 server
func DialObfs4(conn net.Conn, config *Obfs4Config) (*Obfs4Conn, error) {
	if config == nil {
		var err error
		config, err = GenerateObfs4Keys()
		if err != nil {
			return nil, err
		}
	}

	oc := &Obfs4Conn{
		Conn:     conn,
		config:   config,
		isServer: false,
		iatMode:  config.IATMode,
	}

	// Perform handshake
	if err := oc.clientHandshake(); err != nil {
		return nil, err
	}

	return oc, nil
}

// AcceptObfs4 accepts an obfs4 connection (server-side)
func AcceptObfs4(conn net.Conn, config *Obfs4Config) (*Obfs4Conn, error) {
	if config == nil {
		return nil, fmt.Errorf("obfs4 server requires config")
	}

	oc := &Obfs4Conn{
		Conn:     conn,
		config:   config,
		isServer: true,
		iatMode:  config.IATMode,
	}

	// Perform server handshake
	if err := oc.serverHandshake(); err != nil {
		return nil, err
	}

	return oc, nil
}

// clientHandshake performs the client-side handshake
func (c *Obfs4Conn) clientHandshake() error {
	// Generate ephemeral keypair
	ephemeralPrivate := make([]byte, 32)
	if _, err := rand.Read(ephemeralPrivate); err != nil {
		return err
	}

	// Clamp
	ephemeralPrivate[0] &= 248
	ephemeralPrivate[31] &= 127
	ephemeralPrivate[31] |= 64

	ephemeralPublic, _ := curve25519.X25519(ephemeralPrivate, curve25519.Basepoint)

	// Send public key
	if _, err := c.Conn.Write(ephemeralPublic); err != nil {
		return err
	}

	// Read server public key
	serverPublic := make([]byte, 32)
	if _, err := io.ReadFull(c.Conn, serverPublic); err != nil {
		return err
	}

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(ephemeralPrivate, serverPublic)
	if err != nil {
		return err
	}

	// Derive keys using HKDF
	c.deriveKeys(sharedSecret)

	// Mark handshake complete
	c.handshakeComplete.Store(true)

	return nil
}

// serverHandshake performs the server-side handshake
func (c *Obfs4Conn) serverHandshake() error {
	// Read client public key
	clientPublic := make([]byte, 32)
	if _, err := io.ReadFull(c.Conn, clientPublic); err != nil {
		return err
	}

	// Send server public key
	if _, err := c.Conn.Write(c.config.PublicKey); err != nil {
		return err
	}

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(c.config.PrivateKey, clientPublic)
	if err != nil {
		return err
	}

	// Derive keys
	c.deriveKeys(sharedSecret)

	// Mark handshake complete
	c.handshakeComplete.Store(true)

	return nil
}

// deriveKeys derives encryption keys from shared secret
func (c *Obfs4Conn) deriveKeys(sharedSecret []byte) {
	// Use HKDF to derive keys
	info := []byte("obfs4-xor-2024")

	hkdfReader := hkdf.New(sha256.New, sharedSecret, c.config.NodeID, info)

	keys := make([]byte, 64)
	io.ReadFull(hkdfReader, keys)

	if c.isServer {
		c.encoderKey = keys[32:64] // Server encrypts with second half
		c.decoderKey = keys[0:32]  // Server decrypts with first half
	} else {
		c.encoderKey = keys[0:32]  // Client encrypts with first half
		c.decoderKey = keys[32:64] // Client decrypts with second half
	}
}

// encryptFrame encrypts a frame using XOR-based stream cipher
func (c *Obfs4Conn) encryptFrame(plaintext []byte) []byte {
	nonce := c.encoderNonce.Add(1) - 1

	// Generate keystream
	keystream := c.generateKeystream(c.encoderKey, nonce, len(plaintext))

	// XOR encrypt
	ciphertext := make([]byte, len(plaintext))
	for i := range plaintext {
		ciphertext[i] = plaintext[i] ^ keystream[i]
	}

	return ciphertext
}

// decryptFrame decrypts a frame
func (c *Obfs4Conn) decryptFrame(ciphertext []byte) []byte {
	nonce := c.decoderNonce.Add(1) - 1

	// Generate keystream
	keystream := c.generateKeystream(c.decoderKey, nonce, len(ciphertext))

	// XOR decrypt
	plaintext := make([]byte, len(ciphertext))
	for i := range ciphertext {
		plaintext[i] = ciphertext[i] ^ keystream[i]
	}

	return plaintext
}

// generateKeystream generates a keystream using ChaCha20-like approach
func (c *Obfs4Conn) generateKeystream(key []byte, nonce uint64, length int) []byte {
	// Simple counter mode based on SHA256
	keystream := make([]byte, 0, length)
	counter := nonce

	for len(keystream) < length {
		// Create block: key || counter
		block := make([]byte, 40)
		copy(block, key)
		binary.BigEndian.PutUint64(block[32:40], counter)

		// Hash to generate keystream block
		hash := sha256.Sum256(block)
		keystream = append(keystream, hash[:]...)

		counter++
	}

	return keystream[:length]
}

// Read reads data from the obfs4 connection
func (c *Obfs4Conn) Read(p []byte) (int, error) {
	if !c.handshakeComplete.Load() {
		return 0, fmt.Errorf("handshake not complete")
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Return buffered data if available
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read frame length (2 bytes, big endian)
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}

	frameLen := binary.BigEndian.Uint16(lenBuf[:])
	if frameLen == 0 || frameLen > 16384 {
		return 0, fmt.Errorf("invalid frame length")
	}

	// Read and decrypt frame
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(c.Conn, frame); err != nil {
		return 0, err
	}

	plaintext := c.decryptFrame(frame)

	// Extract payload (skip padding)
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

// Write writes data to the obfs4 connection
func (c *Obfs4Conn) Write(p []byte) (int, error) {
	if !c.handshakeComplete.Load() {
		return 0, fmt.Errorf("handshake not complete")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	totalWritten := 0

	// Chunk data into frames (max 1400 bytes per frame for padding)
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > 1400 {
			chunkSize = 1400
		}

		chunk := p[:chunkSize]
		p = p[chunkSize:]

		// Build frame: [payload length || payload || padding]
		paddingLen := c.calculatePadding(len(chunk))
		frameLen := 2 + len(chunk) + paddingLen

		frame := make([]byte, frameLen)
		binary.BigEndian.PutUint16(frame[0:2], uint16(len(chunk)))
		copy(frame[2:], chunk)

		// Add random padding
		if paddingLen > 0 {
			rand.Read(frame[2+len(chunk):])
		}

		// Encrypt frame
		ciphertext := c.encryptFrame(frame)

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

// calculatePadding calculates padding based on uniform distribution
func (c *Obfs4Conn) calculatePadding(payloadLen int) int {
	// Uniform distribution between payload length and max frame size
	// This masks the actual payload size
	minPadding := 0
	maxPadding := 16384 - 2 - payloadLen

	if maxPadding <= 0 {
		return 0
	}

	// Generate random padding length
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomValue := binary.BigEndian.Uint32(randomBytes)

	padding := int(randomValue) % (maxPadding - minPadding + 1)
	return padding + minPadding
}

// Close closes the connection
func (c *Obfs4Conn) Close() error {
	return c.Conn.Close()
}

// Obfs4Listener wraps a listener for obfs4 connections
type Obfs4Listener struct {
	net.Listener
	config *Obfs4Config
}

// ListenObfs4 creates an obfs4 listener
func ListenObfs4(listener net.Listener, config *Obfs4Config) (*Obfs4Listener, error) {
	if config == nil {
		return nil, fmt.Errorf("obfs4 listener requires config")
	}

	return &Obfs4Listener{
		Listener: listener,
		config:   config,
	}, nil
}

// Accept accepts an obfs4 connection
func (l *Obfs4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return AcceptObfs4(conn, l.config)
}

// Obfs4ClientHandshake handles client-side obfs4 handshake
func Obfs4ClientHandshake(conn net.Conn, nodeID, publicKey []byte) (*Obfs4Conn, error) {
	config := &Obfs4Config{
		NodeID:    nodeID,
		PublicKey: publicKey,
	}
	return DialObfs4(conn, config)
}

// Obfs4ServerHandshake handles server-side obfs4 handshake
func Obfs4ServerHandshake(conn net.Conn, config *Obfs4Config) (*Obfs4Conn, error) {
	return AcceptObfs4(conn, config)
}

// IATWrapper wraps a connection with inter-arrival time obfuscation
type IATWrapper struct {
	net.Conn
	mode      int // 0 = disabled, 1 = normal, 2 = aggressive
	minDelay  time.Duration
	maxDelay  time.Duration
	writeMu   sync.Mutex
}

// NewIATWrapper creates a new IAT wrapper
func NewIATWrapper(conn net.Conn, mode int) *IATWrapper {
	w := &IATWrapper{
		Conn:     conn,
		mode:     mode,
		minDelay: 0,
		maxDelay: 10 * time.Millisecond,
	}

	if mode == 2 {
		w.maxDelay = 100 * time.Millisecond
	}

	return w
}

// Write writes with IAT delays
func (w *IATWrapper) Write(p []byte) (int, error) {
	if w.mode == 0 {
		return w.Conn.Write(p)
	}

	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	// Add random delay
	delay := w.randomDelay()
	time.Sleep(delay)

	return w.Conn.Write(p)
}

func (w *IATWrapper) randomDelay() time.Duration {
	randomBytes := make([]byte, 4)
	rand.Read(randomBytes)
	randomValue := binary.BigEndian.Uint32(randomBytes)

	delayRange := w.maxDelay - w.minDelay
	delay := time.Duration(randomValue) % delayRange
	return w.minDelay + delay
}
