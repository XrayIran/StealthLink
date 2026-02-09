package tlsutil

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"
)

// FragmentConfig configures TLS Client Hello fragmentation.
type FragmentConfig struct {
	Enabled   bool          `yaml:"enabled"`
	Size      int           `yaml:"size"`       // Bytes per fragment (default: 32)
	DelayMin  time.Duration `yaml:"delay_min"`  // Min delay between fragments
	DelayMax  time.Duration `yaml:"delay_max"`  // Max delay between fragments
	Randomize bool          `yaml:"randomize"`  // Randomize fragment sizes

	// Advanced fragmentation options (from gfw_resist_tls_proxy)
	NumFragments int           `yaml:"num_fragments"`   // Total number of fragments (default: 87)
	FragmentSleep time.Duration `yaml:"fragment_sleep"` // Sleep between fragments (default: 8ms)
	Mode         FragmentMode  `yaml:"mode"`            // Fragmentation mode
}

// FragmentMode defines the fragmentation strategy
type FragmentMode int

const (
	// FragmentModeRandom splits data into random-sized fragments
	// Uses random sample of indices to create non-deterministic splits
	FragmentModeRandom FragmentMode = iota

	// FragmentModeFixed uses fixed-size fragments
	// Predictable splitting with consistent fragment sizes
	FragmentModeFixed

	// FragmentModeSNIAware splits specifically at SNI boundaries
	// Ensures SNI extension is split across fragments to evade detection
	FragmentModeSNIAware

	// FragmentModeRecord splits at TLS record layer
	// Creates multiple TLS records from single handshake record
	FragmentModeRecord
)

// ApplyDefaults sets default values for fragment configuration.
func (c *FragmentConfig) ApplyDefaults() {
	if c.Size <= 0 {
		c.Size = 32
	}
	if c.Size > 256 {
		c.Size = 256 // Cap max fragment size
	}
	if c.DelayMin < 0 {
		c.DelayMin = 0
	}
	if c.DelayMax < c.DelayMin {
		c.DelayMax = c.DelayMin
	}
	if c.DelayMax == 0 && c.DelayMin == 0 {
		c.DelayMax = 10 * time.Millisecond
	}

	// Advanced options defaults
	if c.NumFragments <= 0 {
		c.NumFragments = 87 // Default from gfw_resist_tls_proxy
	}
	if c.FragmentSleep <= 0 {
		c.FragmentSleep = 8 * time.Millisecond // Default from gfw_resist_tls_proxy
	}
}

// FragmentedConn wraps a net.Conn to fragment TLS Client Hello.
type FragmentedConn struct {
	net.Conn
	config     FragmentConfig
	buffer     []byte
	sent       int
	handshakeDone bool
}

// NewFragmentedConn creates a new connection that fragments TLS Client Hello.
func NewFragmentedConn(conn net.Conn, config FragmentConfig) *FragmentedConn {
	config.ApplyDefaults()
	return &FragmentedConn{
		Conn:   conn,
		config: config,
		buffer: make([]byte, 0, 65536),
	}
}

// Write intercepts TLS Client Hello and fragments it.
func (c *FragmentedConn) Write(p []byte) (int, error) {
	// If handshake is done, write normally
	if c.handshakeDone {
		return c.Conn.Write(p)
	}

	// Check if this looks like a TLS Client Hello
	// TLS record: ContentType (1) + Version (2) + Length (2) + HandshakeType (1) + Length (3) + ...
	if len(p) >= 6 && p[0] == 0x16 { // ContentType: Handshake
		// This is likely a TLS Client Hello, fragment it
		return c.writeFragmented(p)
	}

	// Not a Client Hello, write normally
	return c.Conn.Write(p)
}

// writeFragmented splits the TLS Client Hello into fragments.
func (c *FragmentedConn) writeFragmented(p []byte) (int, error) {
	totalLen := len(p)
	written := 0

	// Find SNI position if possible for smarter fragmentation
	sniPos := findSNIPosition(p)

	// Determine fragment sizes
	fragSizes := c.calculateFragments(totalLen, sniPos)

	for i, fragSize := range fragSizes {
		end := written + fragSize
		if end > totalLen {
			end = totalLen
		}

		frag := p[written:end]
		if _, err := c.Conn.Write(frag); err != nil {
			return written, err
		}
		written = end

		// Add delay between fragments (except after last)
		if i < len(fragSizes)-1 {
			c.applyFragmentDelay(i, len(fragSizes))
		}
	}

	c.handshakeDone = true
	return totalLen, nil
}

// applyFragmentDelay applies delay between fragments.
// Uses gfw_resist_tls_proxy strategy: fixed sleep to fill GFW cache.
func (c *FragmentedConn) applyFragmentDelay(fragIndex, totalFrags int) {
	// Use FragmentSleep if set (gfw_resist_tls_proxy style)
	if c.config.FragmentSleep > 0 {
		time.Sleep(c.config.FragmentSleep)
		return
	}

	// Fall back to random delay between DelayMin and DelayMax
	if c.config.DelayMin > 0 || c.config.DelayMax > 0 {
		delay := c.config.DelayMin
		if c.config.DelayMax > c.config.DelayMin {
			delay += time.Duration(rand.Int63n(int64(c.config.DelayMax - c.config.DelayMin)))
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
}

// calculateFragments determines fragment sizes based on mode.
func (c *FragmentedConn) calculateFragments(totalLen, sniPos int) []int {
	switch c.config.Mode {
	case FragmentModeRandom:
		return c.randomSampleFragments(totalLen)
	case FragmentModeSNIAware:
		return c.sniAwareFragments(totalLen, sniPos)
	case FragmentModeRecord:
		return c.recordFragments(totalLen)
	default: // FragmentModeFixed
		if c.config.Randomize {
			return c.randomFragments(totalLen, sniPos)
		}
		return c.fixedFragments(totalLen, sniPos)
	}
}

// randomSampleFragments creates fragments using random sampling (gfw_resist_tls_proxy style)
// This creates non-deterministic fragment boundaries that are harder to fingerprint.
func (c *FragmentedConn) randomSampleFragments(totalLen int) []int {
	numFrags := c.config.NumFragments
	if numFrags > totalLen-1 {
		numFrags = totalLen - 1
	}
	if numFrags < 2 {
		numFrags = 2
	}

	// Generate random split indices (like gfw_resist_tls_proxy)
	indices := make([]int, 0, numFrags-1)
	for len(indices) < numFrags-1 {
		idx := rand.Intn(totalLen-2) + 1 // Between 1 and totalLen-2
		// Ensure no duplicates
		duplicate := false
		for _, existing := range indices {
			if existing == idx {
				duplicate = true
				break
			}
		}
		if !duplicate {
			indices = append(indices, idx)
		}
	}

	// Sort indices
	for i := 0; i < len(indices); i++ {
		for j := i + 1; j < len(indices); j++ {
			if indices[i] > indices[j] {
				indices[i], indices[j] = indices[j], indices[i]
			}
		}
	}

	// Calculate fragment sizes from indices
	var sizes []int
	prev := 0
	for _, idx := range indices {
		sizes = append(sizes, idx-prev)
		prev = idx
	}
	sizes = append(sizes, totalLen-prev)

	return sizes
}

// sniAwareFragments creates fragments that specifically split at SNI boundaries
// to maximize the effectiveness of SNI obfuscation.
func (c *FragmentedConn) sniAwareFragments(totalLen, sniPos int) []int {
	if sniPos <= 0 || sniPos >= totalLen {
		// Fall back to random fragments if no SNI found
		return c.randomSampleFragments(totalLen)
	}

	var sizes []int

	// Split before SNI
	firstFragSize := sniPos
	if firstFragSize > c.config.Size {
		// Split the first part into multiple fragments
		remaining := firstFragSize
		for remaining > 0 {
			size := c.config.Size
			if size > remaining {
				size = remaining
			}
			sizes = append(sizes, size)
			remaining -= size
		}
	} else {
		sizes = append(sizes, firstFragSize)
	}

	// Split SNI extension itself into multiple small fragments
	sniEnd := sniPos + 100 // Approximate SNI extension size
	if sniEnd > totalLen {
		sniEnd = totalLen
	}
	sniRemaining := sniEnd - sniPos
	for sniRemaining > 0 {
		size := 8 + rand.Intn(16) // Small random fragments (8-24 bytes)
		if size > sniRemaining {
			size = sniRemaining
		}
		sizes = append(sizes, size)
		sniRemaining -= size
	}

	// Remaining data after SNI
	if sniEnd < totalLen {
		remaining := totalLen - sniEnd
		for remaining > 0 {
			size := c.config.Size + rand.Intn(c.config.Size)
			if size > remaining {
				size = remaining
			}
			sizes = append(sizes, size)
			remaining -= size
		}
	}

	return sizes
}

// recordFragments creates TLS record-level fragments
// This splits the TLS handshake record into multiple records.
func (c *FragmentedConn) recordFragments(totalLen int) []int {
	// For record-level fragmentation, we need to ensure each fragment
	// can become its own TLS record (with 5-byte header)
	fragSize := c.config.Size
	if fragSize < 16 {
		fragSize = 16 // Minimum practical fragment size
	}

	var sizes []int
	remaining := totalLen
	for remaining > 0 {
		size := fragSize
		if size > remaining {
			size = remaining
		}
		sizes = append(sizes, size)
		remaining -= size
	}

	return sizes
}

// fixedFragments creates fixed-size fragments.
func (c *FragmentedConn) fixedFragments(totalLen, sniPos int) []int {
	var sizes []int
	remaining := totalLen

	for remaining > 0 {
		size := c.config.Size
		if size > remaining {
			size = remaining
		}

		// If we're approaching SNI, adjust fragment to split at SNI boundary
		if sniPos > 0 {
			currentPos := totalLen - remaining
			nextPos := currentPos + size

			// If this fragment would cross SNI start, split at SNI
			if currentPos < sniPos && nextPos > sniPos {
				size = sniPos - currentPos
			}
		}

		sizes = append(sizes, size)
		remaining -= size
	}

	return sizes
}

// randomFragments creates random-size fragments.
func (c *FragmentedConn) randomFragments(totalLen, sniPos int) []int {
	var sizes []int
	remaining := totalLen
	minSize := c.config.Size / 2
	if minSize < 8 {
		minSize = 8
	}
	maxSize := c.config.Size * 2
	if maxSize > 256 {
		maxSize = 256
	}

	for remaining > 0 {
		size := minSize + rand.Intn(maxSize-minSize)
		if size > remaining {
			size = remaining
		}

		// If we're approaching SNI, adjust fragment to split at SNI boundary
		if sniPos > 0 {
			currentPos := totalLen - remaining
			nextPos := currentPos + size

			// If this fragment would cross SNI start, split at SNI
			if currentPos < sniPos && nextPos > sniPos {
				size = sniPos - currentPos
				if size < 8 {
					size = 8 // Minimum fragment size
				}
			}
		}

		sizes = append(sizes, size)
		remaining -= size
	}

	return sizes
}

// findSNIPosition locates the SNI extension in a TLS Client Hello.
// Returns -1 if not found.
func findSNIPosition(data []byte) int {
	if len(data) < 43 {
		return -1
	}

	// TLS Record Layer: ContentType (1) + Version (2) + Length (2)
	// Handshake: Type (1) + Length (3) + Version (2) + Random (32)
	// = 43 bytes before session ID length

	pos := 43

	// Skip session ID
	if pos >= len(data) {
		return -1
	}
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	// Skip cipher suites
	if pos+2 > len(data) {
		return -1
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2 + cipherSuitesLen

	// Skip compression methods
	if pos >= len(data) {
		return -1
	}
	compressionLen := int(data[pos])
	pos += 1 + compressionLen

	// Extensions length
	if pos+2 > len(data) {
		return -1
	}
	extensionsLen := int(binary.BigEndian.Uint16(data[pos:]))
	pos += 2

	// Parse extensions
	extEnd := pos + extensionsLen
	for pos+4 <= extEnd && pos+4 <= len(data) {
		extType := int(binary.BigEndian.Uint16(data[pos:]))
		extLen := int(binary.BigEndian.Uint16(data[pos+2:]))
		pos += 4

		// SNI extension type is 0x0000
		if extType == 0x0000 && pos+5 <= len(data) {
			// SNI list length (2) + SNI type (1) + SNI length (2)
			return pos
		}

		pos += extLen
	}

	return -1
}

// DialWithFragmentation dials a TLS connection with Client Hello fragmentation.
func DialWithFragmentation(network, addr string, tlsConfig *tls.Config, fragConfig FragmentConfig) (net.Conn, error) {
	fragConfig.ApplyDefaults()

	// Dial underlying connection
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Wrap with fragmentation
	fragConn := NewFragmentedConn(conn, fragConfig)

	// Perform TLS handshake over fragmented connection
	tlsConn := tls.Client(fragConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}

	return tlsConn, nil
}

// FragmentedListener wraps a listener to handle fragmented Client Hellos.
type FragmentedListener struct {
	net.Listener
}

// Accept accepts connections and handles reassembly if needed.
func (l *FragmentedListener) Accept() (net.Conn, error) {
	// For server side, we accept normally - fragmentation is client-side
	return l.Listener.Accept()
}

// EnableRecordLevelFragmentation enables TLS record-level fragmentation.
// This fragments at the TLS record layer rather than TCP layer.
func EnableRecordLevelFragmentation(conn net.Conn, fragSize int) net.Conn {
	return &recordFragmentedConn{
		Conn:     conn,
		fragSize: fragSize,
	}
}

type recordFragmentedConn struct {
	net.Conn
	fragSize int
}

func (c *recordFragmentedConn) Write(p []byte) (int, error) {
	// Check if this is a TLS record
	if len(p) >= 5 && p[0] == 0x16 {
		// Fragment TLS records
		return c.writeFragmentedRecords(p)
	}
	return c.Conn.Write(p)
}

func (c *recordFragmentedConn) writeFragmentedRecords(p []byte) (int, error) {
	// TLS record format: ContentType (1) + Version (2) + Length (2) + Data
	if len(p) < 5 {
		return c.Conn.Write(p)
	}

	contentType := p[0]
	version := binary.BigEndian.Uint16(p[1:3])
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))
	recordData := p[5:]

	if len(recordData) != recordLen {
		// Malformed record, write as-is
		return c.Conn.Write(p)
	}

	// If record is small enough, write as-is
	if recordLen <= c.fragSize {
		return c.Conn.Write(p)
	}

	// Fragment the record
	totalWritten := 0
	for offset := 0; offset < recordLen; offset += c.fragSize {
		end := offset + c.fragSize
		if end > recordLen {
			end = recordLen
		}

		fragLen := end - offset
		frag := make([]byte, 5+fragLen)
		frag[0] = contentType
		binary.BigEndian.PutUint16(frag[1:3], version)
		binary.BigEndian.PutUint16(frag[3:5], uint16(fragLen))
		copy(frag[5:], recordData[offset:end])

		n, err := c.Conn.Write(frag)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += n - 5 // Count only data bytes, not headers
	}

	return 5 + totalWritten, nil // Return original length
}

// FragmentPool manages a pool of pre-fragmented connections for reuse.
// This improves performance for high-throughput scenarios.
type FragmentPool struct {
	config    FragmentConfig
	tlsConfig *tls.Config
	mu        sync.RWMutex
	conns     []net.Conn
	maxSize   int
}

// NewFragmentPool creates a new connection pool for fragmented TLS connections.
func NewFragmentPool(tlsConfig *tls.Config, fragConfig FragmentConfig, maxSize int) *FragmentPool {
	if maxSize <= 0 {
		maxSize = 10
	}
	return &FragmentPool{
		config:    fragConfig,
		tlsConfig: tlsConfig,
		maxSize:   maxSize,
		conns:     make([]net.Conn, 0, maxSize),
	}
}

// Get retrieves a connection from the pool or creates a new one.
func (p *FragmentPool) Get(network, addr string) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to reuse an existing connection
	for i := len(p.conns) - 1; i >= 0; i-- {
		conn := p.conns[i]
		p.conns = p.conns[:i]

		// Check if connection is still valid
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			// Set a short read timeout to check liveness
			tcpConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 1)
			if _, err := conn.Read(buf); err == nil {
				tcpConn.SetReadDeadline(time.Time{}) // Clear deadline
				return conn, nil
			}
		}
		conn.Close()
	}

	// Create new connection
	return DialWithFragmentation(network, addr, p.tlsConfig, p.config)
}

// Put returns a connection to the pool.
func (p *FragmentPool) Put(conn net.Conn) {
	if conn == nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.conns) >= p.maxSize {
		// Pool is full, close the oldest connection
		if len(p.conns) > 0 {
			p.conns[0].Close()
			p.conns = p.conns[1:]
		}
	}

	p.conns = append(p.conns, conn)
}

// Close closes all connections in the pool.
func (p *FragmentPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.conns {
		conn.Close()
	}
	p.conns = p.conns[:0]
	return nil
}
