package behavior

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// TLSFragOverlay implements TLS ClientHello fragmentation to evade DPI.
// It fragments the ClientHello across multiple TCP segments, particularly
// at the SNI boundary to prevent deep packet inspection.
type TLSFragOverlay struct {
	EnabledField bool   `yaml:"enabled"`
	Strategy  string `yaml:"strategy"`   // "sni_split", "random", "fixed"
	ChunkSize int    `yaml:"chunk_size"` // bytes per fragment for fixed strategy
	MinDelay  int    `yaml:"min_delay"`  // ms between fragments
	MaxDelay  int    `yaml:"max_delay"`  // ms between fragments
	Randomize bool   `yaml:"randomize"`  // randomize fragment sizes
}

// Name returns the name of this overlay
func (t *TLSFragOverlay) Name() string {
	return "tlsfrag"
}

// Enabled returns whether this overlay is enabled (for Overlay interface)
func (t *TLSFragOverlay) Enabled() bool {
	return t.EnabledField
}

// Validate validates the configuration
func (t *TLSFragOverlay) Validate() error {
	if !t.EnabledField {
		return nil
	}

	switch t.Strategy {
	case "sni_split", "random", "fixed", "":
		// valid
	default:
		return fmt.Errorf("invalid tlsfrag strategy: %s", t.Strategy)
	}

	if t.Strategy == "" {
		t.Strategy = "sni_split"
	}

	if t.ChunkSize <= 0 {
		t.ChunkSize = 32
	}

	if t.MinDelay < 0 {
		t.MinDelay = 0
	}
	if t.MaxDelay < t.MinDelay {
		t.MaxDelay = t.MinDelay
	}

	return nil
}

// Apply applies the TLS fragmentation overlay to a connection
func (t *TLSFragOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !t.EnabledField {
		return conn, nil
	}

	return &tlsFragConn{
		Conn:     conn,
		overlay:  t,
		buffer:   make([]byte, 0, 16384),
		isClient: true, // Assume client mode by default
	}, nil
}

// GetFragmentSizes returns the fragment sizes for a given data length
func (t *TLSFragOverlay) GetFragmentSizes(totalLen int) []int {
	switch t.Strategy {
	case "sni_split":
		return t.getSNISplitSizes(totalLen)
	case "random":
		return t.getRandomSplitSizes(totalLen)
	case "fixed":
		return t.getFixedSplitSizes(totalLen)
	default:
		return []int{totalLen}
	}
}

// getSNISplitSizes splits at SNI boundary (approximately byte 50-100 for most handshakes)
func (t *TLSFragOverlay) getSNISplitSizes(totalLen int) []int {
	if totalLen <= 100 {
		return []int{totalLen}
	}

	// First fragment: up to SNI (typically around byte 50-80 for the record)
	// Second fragment: SNI and rest
	firstFrag := 50 + (randInt(30)) // 50-80 bytes
	if firstFrag > totalLen {
		firstFrag = totalLen / 2
	}

	return []int{firstFrag, totalLen - firstFrag}
}

// getRandomSplitSizes splits randomly
func (t *TLSFragOverlay) getRandomSplitSizes(totalLen int) []int {
	if totalLen <= t.ChunkSize {
		return []int{totalLen}
	}

	var sizes []int
	remaining := totalLen

	for remaining > 0 {
		chunk := t.ChunkSize
		if t.Randomize {
			chunk = randInt(t.ChunkSize) + 1
		}
		if chunk > remaining {
			chunk = remaining
		}
		sizes = append(sizes, chunk)
		remaining -= chunk

		// Limit number of fragments
		if len(sizes) >= 16 {
			if remaining > 0 {
				sizes[len(sizes)-1] += remaining
			}
			break
		}
	}

	return sizes
}

// getFixedSplitSizes splits into fixed-size chunks
func (t *TLSFragOverlay) getFixedSplitSizes(totalLen int) []int {
	if totalLen <= t.ChunkSize {
		return []int{totalLen}
	}

	var sizes []int
	remaining := totalLen

	for remaining > 0 {
		chunk := t.ChunkSize
		if chunk > remaining {
			chunk = remaining
		}
		sizes = append(sizes, chunk)
		remaining -= chunk
	}

	return sizes
}

// GetDelay returns the delay between fragments
func (t *TLSFragOverlay) GetDelay() time.Duration {
	if t.MinDelay == t.MaxDelay {
		return time.Duration(t.MinDelay) * time.Millisecond
	}

	delayRange := t.MaxDelay - t.MinDelay
	delay := t.MinDelay + randInt(delayRange)
	return time.Duration(delay) * time.Millisecond
}

// tlsFragConn wraps a connection for TLS fragmentation
type tlsFragConn struct {
	net.Conn
	overlay  *TLSFragOverlay
	buffer   []byte
	isClient bool
	mu       sync.Mutex
	fragBuf  []byte
}

// Write fragments TLS records during the handshake
func (c *tlsFragConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if this looks like a TLS ClientHello
	if c.isClient && isClientHello(b) {
		return c.writeFragmented(b)
	}

	// Pass through non-handshake data
	return c.Conn.Write(b)
}

// writeFragmented writes data in fragments
func (c *tlsFragConn) writeFragmented(b []byte) (int, error) {
	fragments := c.overlay.GetFragmentSizes(len(b))
	offset := 0
	totalWritten := 0

	for i, size := range fragments {
		if i > 0 {
			// Delay between fragments
			time.Sleep(c.overlay.GetDelay())
		}

		chunk := b[offset : offset+size]
		n, err := c.Conn.Write(chunk)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += n
		offset += size
	}

	return totalWritten, nil
}

// Read reads from the connection
func (c *tlsFragConn) Read(b []byte) (int, error) {
	return c.Conn.Read(b)
}

// isClientHello checks if data is a TLS ClientHello
func isClientHello(data []byte) bool {
	if len(data) < 6 {
		return false
	}

	// Check for TLS record layer: Content type 0x16 (Handshake)
	if data[0] != 0x16 {
		return false
	}

	// Check for valid TLS version
	version := binary.BigEndian.Uint16(data[1:3])
	if version < 0x0301 || version > 0x0304 {
		return false
	}

	// Check handshake type: ClientHello (0x01)
	if data[5] != 0x01 {
		return false
	}

	return true
}

// randInt returns a random int between 0 and max
func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(binary.BigEndian.Uint32(b)) % max
}

// TLSFragConfig configures TLS fragmentation
type TLSFragConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Strategy  string `yaml:"strategy"`
	ChunkSize int    `yaml:"chunk_size"`
	MinDelay  int    `yaml:"min_delay"`
	MaxDelay  int    `yaml:"max_delay"`
	Randomize bool   `yaml:"randomize"`
}

// ToOverlay converts config to overlay
func (c *TLSFragConfig) ToOverlay() *TLSFragOverlay {
	return &TLSFragOverlay{
		EnabledField: c.Enabled,
		Strategy:     c.Strategy,
		ChunkSize:    c.ChunkSize,
		MinDelay:     c.MinDelay,
		MaxDelay:     c.MaxDelay,
		Randomize:    c.Randomize,
	}
}

// TLSFragWriter wraps a writer to fragment TLS handshakes
type TLSFragWriter struct {
	net.Conn
	overlay *TLSFragOverlay
	mu      sync.Mutex
}

// NewTLSFragWriter creates a new TLS fragmentation writer
func NewTLSFragWriter(conn net.Conn, overlay *TLSFragOverlay) *TLSFragWriter {
	return &TLSFragWriter{
		Conn:    conn,
		overlay: overlay,
	}
}

// Write writes with fragmentation
func (w *TLSFragWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if isClientHello(b) {
		fragments := w.overlay.GetFragmentSizes(len(b))
		offset := 0
		totalWritten := 0

		for i, size := range fragments {
			if i > 0 {
				time.Sleep(w.overlay.GetDelay())
			}

			chunk := b[offset : offset+size]
			n, err := w.Conn.Write(chunk)
			if err != nil {
				return totalWritten, err
			}
			totalWritten += n
			offset += size
		}

		return totalWritten, nil
	}

	return w.Conn.Write(b)
}

// TLSFragMetrics tracks fragmentation statistics
type TLSFragMetrics struct {
	TotalFragments    uint64
	TotalBytes        uint64
	FragmentedHandshakes uint64
	mu                sync.RWMutex
}

// RecordFragment records a fragment
func (m *TLSFragMetrics) RecordFragment(bytes int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalFragments++
	m.TotalBytes += uint64(bytes)
}

// RecordHandshake records a fragmented handshake
func (m *TLSFragMetrics) RecordHandshake() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FragmentedHandshakes++
}

// GetStats returns current statistics
func (m *TLSFragMetrics) GetStats() (fragments, bytes, handshakes uint64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.TotalFragments, m.TotalBytes, m.FragmentedHandshakes
}

// FragmentTLSClientHello fragments a TLS ClientHello for evasion
func FragmentTLSClientHello(data []byte, strategy string, chunkSize int) [][]byte {
	if !isClientHello(data) {
		return [][]byte{data}
	}

	overlay := &TLSFragOverlay{
		Strategy:  strategy,
		ChunkSize: chunkSize,
	}

	sizes := overlay.GetFragmentSizes(len(data))
	fragments := make([][]byte, 0, len(sizes))
	offset := 0

	for _, size := range sizes {
		fragments = append(fragments, data[offset:offset+size])
		offset += size
	}

	return fragments
}

// ReassembleTLSFragments reassembles fragmented TLS records
func ReassembleTLSFragments(fragments [][]byte) []byte {
	totalLen := 0
	for _, f := range fragments {
		totalLen += len(f)
	}

	result := make([]byte, 0, totalLen)
	for _, f := range fragments {
		result = append(result, f...)
	}

	return result
}
