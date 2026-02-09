// Package obfs provides obfuscation techniques for StealthLink.
// Salamander obfuscation is based on Hysteria's BLAKE2b-based XOR obfuscation.
package obfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// SalamanderConfig configures Salamander obfuscation.
type SalamanderConfig struct {
	Enabled bool   `yaml:"enabled"`
	Key     string `yaml:"key"`
}

// SalamanderObfuscator implements Hysteria-style BLAKE2b-based XOR obfuscation.
// Each packet has an 8-byte salt that is combined with the PSK to generate
// a unique XOR mask using BLAKE2b.
type SalamanderObfuscator struct {
	psk []byte
}

// NewSalamander creates a new Salamander obfuscator.
func NewSalamander(key string) (*SalamanderObfuscator, error) {
	if key == "" {
		return nil, fmt.Errorf("salamander key is required")
	}

	return &SalamanderObfuscator{
		psk: []byte(key),
	}, nil
}

// Obfuscate obfuscates the given data.
// Format: [8-byte salt][XOR-encrypted data]
func (s *SalamanderObfuscator) Obfuscate(data []byte) ([]byte, error) {
	// Generate random salt
	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Create XOR mask
	mask := s.deriveMask(salt, len(data))

	// XOR data
	result := make([]byte, 8+len(data))
	copy(result, salt)
	for i := range data {
		result[8+i] = data[i] ^ mask[i]
	}

	return result, nil
}

// Deobfuscate deobfuscates the given data.
func (s *SalamanderObfuscator) Deobfuscate(data []byte) ([]byte, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short for salamander")
	}

	// Extract salt
	salt := data[:8]
	encrypted := data[8:]

	// Create XOR mask
	mask := s.deriveMask(salt, len(encrypted))

	// XOR data
	result := make([]byte, len(encrypted))
	for i := range encrypted {
		result[i] = encrypted[i] ^ mask[i]
	}

	return result, nil
}

// deriveMask derives a XOR mask from the salt and PSK using BLAKE2b.
func (s *SalamanderObfuscator) deriveMask(salt []byte, length int) []byte {
	// BLAKE2b(PSK || salt)
	h, _ := blake2b.New512(nil)
	h.Write(s.psk)
	h.Write(salt)
	hash := h.Sum(nil)

	// Expand hash to required length using counter mode
	mask := make([]byte, length)
	copied := copy(mask, hash)

	for copied < length {
		h2, _ := blake2b.New512(nil)
		binary.BigEndian.PutUint64(hash, uint64(copied))
		h2.Write(hash)
		nextHash := h2.Sum(nil)
		copied += copy(mask[copied:], nextHash)
	}

	return mask
}

// SalamanderConn wraps a net.Conn with Salamander obfuscation.
type SalamanderConn struct {
	net.Conn
	obfuscator *SalamanderObfuscator
	readBuf    []byte
	writeBuf   []byte
	mu         sync.Mutex
}

// NewSalamanderConn creates a new Salamander-obfuscated connection.
func NewSalamanderConn(conn net.Conn, key string) (*SalamanderConn, error) {
	obf, err := NewSalamander(key)
	if err != nil {
		return nil, err
	}

	return &SalamanderConn{
		Conn:       conn,
		obfuscator: obf,
		readBuf:    make([]byte, 0, 65536),
		writeBuf:   make([]byte, 0, 65536),
	}, nil
}

// Read reads and deobfuscates data.
func (c *SalamanderConn) Read(b []byte) (n int, err error) {
	// Read obfuscated packet length first
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}

	pktLen := binary.BigEndian.Uint16(lenBuf[:])
	if pktLen == 0 || pktLen > 16384 {
		return 0, fmt.Errorf("invalid packet length: %d", pktLen)
	}

	// Read obfuscated packet
	obfData := make([]byte, pktLen)
	if _, err := io.ReadFull(c.Conn, obfData); err != nil {
		return 0, err
	}

	// Deobfuscate
	data, err := c.obfuscator.Deobfuscate(obfData)
	if err != nil {
		return 0, err
	}

	// Copy to buffer
	n = copy(b, data)
	if n < len(data) {
		// Store remainder for next read
		c.readBuf = append(c.readBuf, data[n:]...)
	}

	return n, nil
}

// Write writes and obfuscates data.
func (c *SalamanderConn) Write(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Obfuscate data
	obfData, err := c.obfuscator.Obfuscate(b)
	if err != nil {
		return 0, err
	}

	if len(obfData) > 16384 {
		return 0, fmt.Errorf("packet too large: %d", len(obfData))
	}

	// Send length prefix
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(obfData)))
	if _, err := c.Conn.Write(lenBuf[:]); err != nil {
		return 0, err
	}

	// Send obfuscated data
	if _, err := c.Conn.Write(obfData); err != nil {
		return 0, err
	}

	return len(b), nil
}

// SalamanderPacketConn wraps a net.PacketConn with Salamander obfuscation.
type SalamanderPacketConn struct {
	net.PacketConn
	obfuscator *SalamanderObfuscator
}

// NewSalamanderPacketConn creates a new Salamander-obfuscated packet connection.
func NewSalamanderPacketConn(conn net.PacketConn, key string) (*SalamanderPacketConn, error) {
	obf, err := NewSalamander(key)
	if err != nil {
		return nil, err
	}

	return &SalamanderPacketConn{
		PacketConn: conn,
		obfuscator: obf,
	}, nil
}

// ReadFrom reads and deobfuscates a packet.
func (c *SalamanderPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	// Read obfuscated packet
	buf := make([]byte, len(p)+8+2) // Extra space for salt and length
	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	if n < 8 {
		return 0, nil, fmt.Errorf("packet too short")
	}

	// Deobfuscate
	data, err := c.obfuscator.Deobfuscate(buf[:n])
	if err != nil {
		return 0, nil, err
	}

	return copy(p, data), addr, nil
}

// WriteTo writes and obfuscates a packet.
func (c *SalamanderPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	obfData, err := c.obfuscator.Obfuscate(p)
	if err != nil {
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(obfData, addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// XorConn wraps a net.Conn with XOR obfuscation
type XorConn struct {
	net.Conn
	obfuscator *XorObfuscator
	readBuf    []byte
}

// NewXorConn creates a new XOR-obfuscated connection
func NewXorConn(conn net.Conn, key string) (*XorConn, error) {
	return &XorConn{
		Conn:       conn,
		obfuscator: NewXorObfuscator(key),
		readBuf:    make([]byte, 0, 65536),
	}, nil
}

// Read reads and deobfuscates data
func (c *XorConn) Read(b []byte) (int, error) {
	// Read length prefix
	var lenBuf [2]byte
	if _, err := io.ReadFull(c.Conn, lenBuf[:]); err != nil {
		return 0, err
	}

	pktLen := binary.BigEndian.Uint16(lenBuf[:])
	if pktLen == 0 || pktLen > 16384 {
		return 0, fmt.Errorf("invalid packet length: %d", pktLen)
	}

	// Read encrypted packet
	encData := make([]byte, pktLen)
	if _, err := io.ReadFull(c.Conn, encData); err != nil {
		return 0, err
	}

	// Deobfuscate
	data := c.obfuscator.Deobfuscate(encData)

	// Copy to buffer
	n := copy(b, data)
	if n < len(data) {
		c.readBuf = append(c.readBuf, data[n:]...)
	}

	return n, nil
}

// Write writes and obfuscates data
func (c *XorConn) Write(b []byte) (int, error) {
	// Obfuscate data
	encData := c.obfuscator.Obfuscate(b)

	if len(encData) > 16384 {
		return 0, fmt.Errorf("packet too large: %d", len(encData))
	}

	// Send length prefix
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(encData)))
	if _, err := c.Conn.Write(lenBuf[:]); err != nil {
		return 0, err
	}

	// Send encrypted data
	if _, err := c.Conn.Write(encData); err != nil {
		return 0, err
	}

	return len(b), nil
}

// XorPacketConn wraps a net.PacketConn with XOR obfuscation
type XorPacketConn struct {
	net.PacketConn
	obfuscator *XorObfuscator
}

// NewXorPacketConn creates a new XOR-obfuscated packet connection
func NewXorPacketConn(conn net.PacketConn, key string) (*XorPacketConn, error) {
	return &XorPacketConn{
		PacketConn: conn,
		obfuscator: NewXorObfuscator(key),
	}, nil
}

// ReadFrom reads and deobfuscates a packet
func (c *XorPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, len(p))
	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	// Deobfuscate
	data := c.obfuscator.Deobfuscate(buf[:n])
	return copy(p, data), addr, nil
}

// WriteTo writes and obfuscates a packet
func (c *XorPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	encData := c.obfuscator.Obfuscate(p)
	_, err = c.PacketConn.WriteTo(encData, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// XorObfuscator implements simple XOR obfuscation with rotating key.
type XorObfuscator struct {
	key    []byte
	keyLen int
}

// NewXorObfuscator creates a new XOR obfuscator.
func NewXorObfuscator(key string) *XorObfuscator {
	keyBytes := []byte(key)
	if len(keyBytes) == 0 {
		keyBytes = []byte("default_key")
	}

	return &XorObfuscator{
		key:    keyBytes,
		keyLen: len(keyBytes),
	}
}

// Obfuscate XORs data with the key.
func (x *XorObfuscator) Obfuscate(data []byte) []byte {
	result := make([]byte, len(data))
	for i := range data {
		result[i] = data[i] ^ x.key[i%x.keyLen]
	}
	return result
}

// Deobfuscate is the same as Obfuscate for XOR.
func (x *XorObfuscator) Deobfuscate(data []byte) []byte {
	return x.Obfuscate(data)
}

// ObfsType represents the type of obfuscation.
type ObfsType string

const (
	ObfsTypeNone      ObfsType = "none"
	ObfsTypeSalamander ObfsType = "salamander"
	ObfsTypeXor       ObfsType = "xor"
)

// Config configures obfuscation.
type Config struct {
	Type        ObfsType          `yaml:"type"`
	Key         string            `yaml:"key"`
	Params      map[string]string `yaml:"params"`
}

// NewObfuscator creates an obfuscator based on config.
func NewObfuscator(config Config) (interface{}, error) {
	switch config.Type {
	case ObfsTypeNone, "":
		return nil, nil
	case ObfsTypeSalamander:
		return NewSalamander(config.Key)
	case ObfsTypeXor:
		return NewXorObfuscator(config.Key), nil
	default:
		return nil, fmt.Errorf("unknown obfuscation type: %s", config.Type)
	}
}
