package uqsp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// PacketMorpher implements QUIC Initial packet header morphing to defeat DPI.
// It XORs/shuffles packet headers based on a derived key.
type PacketMorpher struct {
	key     []byte
	enabled bool
	mu      sync.RWMutex
}

// NewPacketMorpher creates a new packet morpher with the given key.
func NewPacketMorpher(key string) *PacketMorpher {
	if key == "" {
		return &PacketMorpher{enabled: false}
	}

	// Derive a 32-byte key using SHA-256
	hash := sha256.Sum256([]byte(key))

	return &PacketMorpher{
		key:     hash[:],
		enabled: true,
	}
}

// Enabled returns whether morphing is enabled.
func (m *PacketMorpher) Enabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// SetEnabled enables or disables morphing.
func (m *PacketMorpher) SetEnabled(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled = enabled
}

// Morph morphs a QUIC Initial packet header.
// The packet buffer is modified in place.
func (m *PacketMorpher) Morph(packet []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled || len(packet) < 20 {
		return packet, nil
	}

	// Check if this is a QUIC Initial packet (first byte 0xC3 or similar)
	if !isQUICInitialPacket(packet) {
		return packet, nil
	}

	// Create a copy to avoid modifying the original
	morphed := make([]byte, len(packet)+4) // +4 for morphing nonce
	copy(morphed[4:], packet)

	// Add a 4-byte nonce at the beginning
	nonce := make([]byte, 4)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	copy(morphed[0:4], nonce)

	// XOR the packet content with the keystream
	// Skip the first byte (header flags) and DCIL/SCIL fields
	// to preserve QUIC compatibility
	keystream := m.generateKeystream(nonce, len(packet))

	// Morph starting after header fields (approximately byte 5-20 depending on CIDs)
	headerLen := m.calculateHeaderLength(packet)
	if headerLen < len(packet) {
		for i := headerLen; i < len(packet); i++ {
			morphed[i+4] = packet[i] ^ keystream[i]
		}
	}

	return morphed, nil
}

// Unmorph reverses the morphing operation.
func (m *PacketMorpher) Unmorph(packet []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if !m.enabled || len(packet) < 24 {
		return packet, nil
	}

	// Extract nonce from the first 4 bytes
	nonce := packet[0:4]
	original := make([]byte, len(packet)-4)
	copy(original, packet[4:])

	// Generate keystream and XOR back
	keystream := m.generateKeystream(nonce, len(original))

	headerLen := m.calculateHeaderLength(original)
	if headerLen < len(original) {
		for i := headerLen; i < len(original); i++ {
			original[i] = original[i] ^ keystream[i]
		}
	}

	return original, nil
}

// isQUICInitialPacket checks if the packet is a QUIC Initial packet.
func isQUICInitialPacket(packet []byte) bool {
	if len(packet) < 5 {
		return false
	}

	// QUIC Initial packets have first byte: 1STTTXXX where TTT=0 (Initial)
	// First byte: 0xC3 (Long header, Initial, version 1)
	firstByte := packet[0]

	// Check for long header (bit 7 set)
	if firstByte&0x80 == 0 {
		return false
	}

	// Extract packet type from bits 4-5
	packetType := (firstByte >> 4) & 0x03

	// Initial = 0
	return packetType == 0
}

// calculateHeaderLength estimates the QUIC header length.
func (m *PacketMorpher) calculateHeaderLength(packet []byte) int {
	if len(packet) < 5 {
		return len(packet)
	}

	// Long header format: flags(1) + version(4) + DCIL(1) + SCIL(1) + DCID + SCID + len(2) + packet_number
	// Minimum header is about 20 bytes
	return 20
}

// generateKeystream generates a keystream for XOR operations.
func (m *PacketMorpher) generateKeystream(nonce []byte, length int) []byte {
	// Simple keystream generation using SHA-256 in CTR-like mode
	keystream := make([]byte, 0, length)
	counter := uint64(0)

	for len(keystream) < length {
		// Create a block: nonce || counter || key
		block := make([]byte, 0, 44)
		block = append(block, nonce...)
		block = binary.BigEndian.AppendUint64(block, counter)
		block = append(block, m.key...)

		hash := sha256.Sum256(block)
		keystream = append(keystream, hash[:]...)
		counter++
	}

	return keystream[:length]
}

// MorpherConn wraps a net.PacketConn to apply morphing.
type MorpherConn struct {
	net.PacketConn
	morpher *PacketMorpher
}

// NewMorpherConn creates a new morphing packet connection.
func NewMorpherConn(conn net.PacketConn, morpher *PacketMorpher) *MorpherConn {
	return &MorpherConn{
		PacketConn: conn,
		morpher:    morpher,
	}
}

// WriteTo morphs and writes a packet.
func (c *MorpherConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if !c.morpher.Enabled() {
		return c.PacketConn.WriteTo(p, addr)
	}

	morphed, err := c.morpher.Morph(p)
	if err != nil {
		return 0, err
	}

	_, err = c.PacketConn.WriteTo(morphed, addr)
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

// ReadFrom reads and unmorphs a packet.
func (c *MorpherConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, addr, err = c.PacketConn.ReadFrom(p)
	if err != nil || !c.morpher.Enabled() || n < 4 {
		return n, addr, err
	}

	unmorphed, err := c.morpher.Unmorph(p[:n])
	if err != nil {
		return n, addr, nil // Return original on error
	}

	n = copy(p, unmorphed)
	return n, addr, nil
}

// MorphingConfig configures packet morphing.
type MorphingConfig struct {
	Enabled bool   `yaml:"enabled"`
	Key     string `yaml:"key"`
}

// ApplyDefaults applies default values.
func (c *MorphingConfig) ApplyDefaults() {
	if c.Key == "" && c.Enabled {
		// Generate a random key if enabled but not provided
		key := make([]byte, 32)
		if _, err := rand.Read(key); err == nil {
			c.Key = string(key)
		}
	}
}

// EarlyDatagramQueue buffers datagrams during handshake for 0-RTT pre-sending.
type EarlyDatagramQueue struct {
	queue   [][]byte
	targets []net.Addr
	mu      sync.Mutex
	maxSize int
}

// NewEarlyDatagramQueue creates a new early datagram queue.
func NewEarlyDatagramQueue(maxSize int) *EarlyDatagramQueue {
	if maxSize <= 0 {
		maxSize = 64 // Default max queued datagrams
	}
	return &EarlyDatagramQueue{
		queue:   make([][]byte, 0, maxSize),
		targets: make([]net.Addr, 0, maxSize),
		maxSize: maxSize,
	}
}

// Queue adds a datagram to the queue.
func (q *EarlyDatagramQueue) Queue(data []byte, target net.Addr) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.queue) >= q.maxSize {
		return false
	}

	// Copy the data
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	q.queue = append(q.queue, dataCopy)
	q.targets = append(q.targets, target)
	return true
}

// Flush sends all queued datagrams and clears the queue.
func (q *EarlyDatagramQueue) Flush(sendFunc func([]byte, net.Addr) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	var lastErr error
	for i, data := range q.queue {
		if err := sendFunc(data, q.targets[i]); err != nil {
			lastErr = err
		}
	}

	// Clear the queue
	q.queue = q.queue[:0]
	q.targets = q.targets[:0]

	return lastErr
}

// Size returns the current queue size.
func (q *EarlyDatagramQueue) Size() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.queue)
}

// Clear clears the queue without sending.
func (q *EarlyDatagramQueue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queue = q.queue[:0]
	q.targets = q.targets[:0]
}

// DatagramQueueConfig configures the early datagram queue.
type DatagramQueueConfig struct {
	Enabled bool          `yaml:"enabled"`
	MaxSize int           `yaml:"max_size"`
	Timeout time.Duration `yaml:"timeout"`
}

// ApplyDefaults applies default values.
func (c *DatagramQueueConfig) ApplyDefaults() {
	if c.MaxSize <= 0 {
		c.MaxSize = 64
	}
	if c.Timeout <= 0 {
		c.Timeout = 5 * time.Second
	}
}
