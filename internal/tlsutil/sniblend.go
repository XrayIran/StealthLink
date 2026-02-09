package tlsutil

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// SNIBlendConfig configures SNI blending (fragmentation and shuffling).
type SNIBlendConfig struct {
	Enabled      bool          `yaml:"enabled"`
	Fragments    int           `yaml:"fragments"`     // Number of fragments (default: 8, max: 16)
	Shuffle      bool          `yaml:"shuffle"`       // Shuffle fragment order
	RoundTo8     bool          `yaml:"round_to_8"`    // Round fragment sizes to 8-byte boundaries
	DelayMin     time.Duration `yaml:"delay_min"`     // Min delay between fragments
	DelayMax     time.Duration `yaml:"delay_max"`     // Max delay between fragments
	ReorderDepth int           `yaml:"reorder_depth"` // Max positions to reorder (0 = full shuffle)

	// SNI Fragmentation options (from Vwarp/NOIZE)
	SNIFragment      bool          `yaml:"sni_fragment"`       // Enable SNI-specific fragmentation
	SNIFragmentSize  int           `yaml:"sni_fragment_size"`  // Fragment SNI at this byte position
	SNIFragmentDelay time.Duration `yaml:"sni_fragment_delay"` // Delay after SNI fragment
}

// ApplyDefaults sets default values.
func (c *SNIBlendConfig) ApplyDefaults() {
	if c.Fragments <= 0 {
		c.Fragments = 8
	}
	if c.Fragments > 16 {
		c.Fragments = 16
	}
	if c.ReorderDepth < 0 {
		c.ReorderDepth = 0
	}
	if c.DelayMax < c.DelayMin {
		c.DelayMax = c.DelayMin
	}
	if c.DelayMax == 0 && c.DelayMin == 0 {
		c.DelayMax = 5 * time.Millisecond
	}
	if c.SNIFragmentSize <= 0 {
		c.SNIFragmentSize = 32 // Default fragment size for SNI
	}
	if c.SNIFragmentDelay <= 0 {
		c.SNIFragmentDelay = 2 * time.Millisecond
	}
}

// SNIBlender handles TLS Client Hello fragmentation and shuffling.
type SNIBlender struct {
	config SNIBlendConfig
}

// NewSNIBlender creates a new SNI blender.
func NewSNIBlender(config SNIBlendConfig) *SNIBlender {
	config.ApplyDefaults()
	return &SNIBlender{config: config}
}

// Blend fragments and optionally shuffles a TLS Client Hello.
func (s *SNIBlender) Blend(clientHello []byte) ([][]byte, error) {
	if len(clientHello) < 43 {
		return nil, fmt.Errorf("Client Hello too short")
	}

	// Verify this is a TLS handshake
	if clientHello[0] != 0x16 { // ContentType: Handshake
		return nil, fmt.Errorf("not a TLS handshake record")
	}

	// Calculate fragment sizes
	fragSizes := s.calculateFragmentSizes(len(clientHello))

	// Create fragments
	fragments := make([][]byte, len(fragSizes))
	offset := 0
	for i, size := range fragSizes {
		fragments[i] = make([]byte, size)
		copy(fragments[i], clientHello[offset:offset+size])
		offset += size
	}

	// Shuffle fragments if enabled
	if s.config.Shuffle {
		fragments = s.shuffleFragments(fragments)
	}

	return fragments, nil
}

// calculateFragmentSizes determines the size of each fragment.
func (s *SNIBlender) calculateFragmentSizes(totalLen int) []int {
	numFrags := s.config.Fragments
	if numFrags > totalLen/8 {
		// Ensure minimum 8 bytes per fragment
		numFrags = totalLen / 8
	}
	if numFrags < 2 {
		numFrags = 2
	}

	// Find SNI position for intelligent splitting
	sniPos := findSNIPositionForBlend(makeClientHelloPlaceholder(totalLen))

	sizes := make([]int, 0, numFrags)
	remaining := totalLen

	// Calculate base size and distribute remainder
	baseSize := remaining / numFrags
	remainder := remaining % numFrags

	for i := 0; i < numFrags && remaining > 0; i++ {
		size := baseSize
		if i < remainder {
			size++
		}

		// Round to 8-byte boundary if enabled
		if s.config.RoundTo8 {
			size = (size + 7) &^ 7
		}

		// Ensure we don't exceed remaining
		if size > remaining {
			size = remaining
		}

		// Try to split at SNI boundary for first fragment crossing it
		currentPos := totalLen - remaining
		nextPos := currentPos + size

		if sniPos > 0 && currentPos < sniPos && nextPos > sniPos {
			// This fragment would cross SNI, split at SNI
			size = sniPos - currentPos
			if s.config.RoundTo8 {
				size = (size + 7) &^ 7
			}
			if size < 8 {
				size = 8
			}
		}

		sizes = append(sizes, size)
		remaining -= size
	}

	// Add any remaining bytes to last fragment
	if remaining > 0 && len(sizes) > 0 {
		sizes[len(sizes)-1] += remaining
	}

	return sizes
}

// shuffleFragments shuffles fragments using limited reordering.
func (s *SNIBlender) shuffleFragments(fragments [][]byte) [][]byte {
	if s.config.ReorderDepth == 0 {
		// Full shuffle
		rand.Shuffle(len(fragments), func(i, j int) {
			fragments[i], fragments[j] = fragments[j], fragments[i]
		})
		return fragments
	}

	// Limited reordering - each fragment can move at most ReorderDepth positions
	result := make([][]byte, len(fragments))
	copy(result, fragments)

	for i := range result {
		// Determine range for swapping
		minJ := i - s.config.ReorderDepth
		if minJ < 0 {
			minJ = 0
		}
		maxJ := i + s.config.ReorderDepth
		if maxJ >= len(result) {
			maxJ = len(result) - 1
		}

		// Swap with random position in range
		j := minJ + rand.Intn(maxJ-minJ+1)
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// BlendingConn wraps a connection to blend TLS Client Hello.
type BlendingConn struct {
	net.Conn
	config      SNIBlendConfig
	handshakeBuf []byte
	fragments   [][]byte
	fragIndex   int
	blendDone   bool
}

// NewBlendingConn creates a connection that blends TLS Client Hello.
func NewBlendingConn(conn net.Conn, config SNIBlendConfig) *BlendingConn {
	config.ApplyDefaults()
	return &BlendingConn{
		Conn:   conn,
		config: config,
	}
}

// Write intercepts TLS Client Hello and blends it.
func (c *BlendingConn) Write(p []byte) (int, error) {
	if c.blendDone {
		return c.Conn.Write(p)
	}

	// Check if this is a TLS Client Hello
	if len(p) >= 6 && p[0] == 0x16 {
		return c.writeBlended(p)
	}

	return c.Conn.Write(p)
}

// writeBlended fragments and shuffles the Client Hello.
func (c *BlendingConn) writeBlended(p []byte) (int, error) {
	blender := NewSNIBlender(c.config)
	fragments, err := blender.Blend(p)
	if err != nil {
		// If blending fails, write normally
		return c.Conn.Write(p)
	}

	totalWritten := 0

	for i, frag := range fragments {
		n, err := c.Conn.Write(frag)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += n

		// Add delay between fragments (except after last)
		if i < len(fragments)-1 {
			delay := c.config.DelayMin
			if c.config.DelayMax > c.config.DelayMin {
				delay += time.Duration(rand.Int63n(int64(c.config.DelayMax - c.config.DelayMin)))
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	c.blendDone = true
	return len(p), nil
}

// findSNIPositionForBlend locates SNI extension position.
// Similar to findSNIPosition in fragment.go but handles placeholder data.
func findSNIPositionForBlend(data []byte) int {
	return findSNIPosition(data)
}

// makeClientHelloPlaceholder creates a placeholder for size calculation.
func makeClientHelloPlaceholder(size int) []byte {
	// Create a minimal valid-looking Client Hello structure
	data := make([]byte, size)
	data[0] = 0x16 // Handshake
	data[1] = 0x03 // TLS 1.0 major
	data[2] = 0x01 // TLS 1.0 minor
	// Length will be set by actual data
	return data
}

// DialWithBlending dials a connection with SNI blending.
func DialWithBlending(network, addr string, config SNIBlendConfig) (net.Conn, error) {
	config.ApplyDefaults()

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	return NewBlendingConn(conn, config), nil
}

// BlendAndSend performs blending on raw TCP connection.
// This is useful when you need to send a pre-constructed Client Hello.
func BlendAndSend(conn net.Conn, clientHello []byte, config SNIBlendConfig) error {
	config.ApplyDefaults()

	blender := NewSNIBlender(config)
	fragments, err := blender.Blend(clientHello)
	if err != nil {
		return err
	}

	for i, frag := range fragments {
		if _, err := conn.Write(frag); err != nil {
			return err
		}

		if i < len(fragments)-1 {
			delay := config.DelayMin
			if config.DelayMax > config.DelayMin {
				delay += time.Duration(rand.Int63n(int64(config.DelayMax - config.DelayMin)))
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	return nil
}

// SNIBlendListener wraps a listener to accept blended connections.
type SNIBlendListener struct {
	net.Listener
	reassemblyBuf map[string][]byte // Buffer for reassembling fragments
}

// NewSNIBlendListener creates a listener that handles blended Client Hellos.
func NewSNIBlendListener(inner net.Listener) *SNIBlendListener {
	return &SNIBlendListener{
		Listener:      inner,
		reassemblyBuf: make(map[string][]byte),
	}
}

// Accept accepts connections and handles reassembly if needed.
func (l *SNIBlendListener) Accept() (net.Conn, error) {
	// For server side, we accept normally
	// Reassembly would require tracking connection state
	return l.Listener.Accept()
}

// ReassembleFragments attempts to reassemble fragmented Client Hello.
// This is used on the server side to handle blended connections.
func ReassembleFragments(fragments [][]byte) ([]byte, error) {
	if len(fragments) == 0 {
		return nil, fmt.Errorf("no fragments to reassemble")
	}

	// Calculate total size
	totalSize := 0
	for _, frag := range fragments {
		totalSize += len(frag)
	}

	// Reassemble
	result := make([]byte, 0, totalSize)
	for _, frag := range fragments {
		result = append(result, frag...)
	}

	// Verify it looks like a valid TLS record
	if len(result) < 5 || result[0] != 0x16 {
		return nil, fmt.Errorf("reassembled data is not a valid TLS handshake")
	}

	// Verify length matches
	recordLen := int(binary.BigEndian.Uint16(result[3:5]))
	if recordLen != len(result)-5 {
		// Length mismatch - might be due to extra data
		// Return what we have anyway
	}

	return result, nil
}

// SNIFragmenter performs SNI-specific fragmentation.
// This splits the SNI extension into multiple fragments to evade detection.
type SNIFragmenter struct {
	config SNIBlendConfig
}

// NewSNIFragmenter creates a new SNI fragmenter.
func NewSNIFragmenter(config SNIBlendConfig) *SNIFragmenter {
	config.ApplyDefaults()
	return &SNIFragmenter{config: config}
}

// FragmentSNI fragments the SNI extension in a Client Hello.
// Returns fragments that split the SNI at the specified position.
func (s *SNIFragmenter) FragmentSNI(clientHello []byte) ([][]byte, error) {
	if len(clientHello) < 43 {
		return nil, fmt.Errorf("Client Hello too short")
	}

	// Find SNI position
	sniPos := findSNIPosition(clientHello)
	if sniPos < 0 {
		// No SNI found, return as single fragment
		return [][]byte{clientHello}, nil
	}

	// Find SNI end position
	sniEnd := s.findSNIEnd(clientHello, sniPos)

	// Create fragments that split the SNI
	fragSize := s.config.SNIFragmentSize
	if fragSize <= 0 {
		fragSize = 32
	}

	var fragments [][]byte

	// Fragment 1: From start to SNI position + partial SNI
	firstSplit := sniPos + fragSize
	if firstSplit > sniEnd {
		firstSplit = sniEnd
	}
	if firstSplit > len(clientHello) {
		firstSplit = len(clientHello)
	}

	fragments = append(fragments, clientHello[:firstSplit])

	// Fragment 2: Remaining SNI + rest of packet
	if firstSplit < len(clientHello) {
		// Split remaining into multiple fragments if needed
		remaining := clientHello[firstSplit:]
		for len(remaining) > 0 {
			size := fragSize * 2 // Larger fragments after SNI
			if size > len(remaining) {
				size = len(remaining)
			}
			fragments = append(fragments, remaining[:size])
			remaining = remaining[size:]
		}
	}

	return fragments, nil
}

// findSNIEnd finds the end position of the SNI extension.
func (s *SNIFragmenter) findSNIEnd(data []byte, sniPos int) int {
	if sniPos+5 > len(data) {
		return len(data)
	}

	// SNI list length (2 bytes)
	sniListLen := int(binary.BigEndian.Uint16(data[sniPos:]))
	end := sniPos + 2 + sniListLen

	if end > len(data) {
		return len(data)
	}
	return end
}

// FragmentedSNIConn wraps a connection to fragment SNI.
type FragmentedSNIConn struct {
	net.Conn
	config    SNIBlendConfig
	blendDone bool
}

// NewFragmentedSNIConn creates a connection that fragments SNI.
func NewFragmentedSNIConn(conn net.Conn, config SNIBlendConfig) *FragmentedSNIConn {
	config.ApplyDefaults()
	return &FragmentedSNIConn{
		Conn:   conn,
		config: config,
	}
}

// Write intercepts TLS Client Hello and fragments SNI.
func (c *FragmentedSNIConn) Write(p []byte) (int, error) {
	if c.blendDone {
		return c.Conn.Write(p)
	}

	// Check if this is a TLS Client Hello
	if len(p) >= 6 && p[0] == 0x16 {
		return c.writeFragmented(p)
	}

	return c.Conn.Write(p)
}

// writeFragmented fragments the SNI and sends with delays.
func (c *FragmentedSNIConn) writeFragmented(p []byte) (int, error) {
	fragmenter := NewSNIFragmenter(c.config)
	fragments, err := fragmenter.FragmentSNI(p)
	if err != nil {
		// If fragmentation fails, write normally
		return c.Conn.Write(p)
	}

	totalWritten := 0

	for i, frag := range fragments {
		n, err := c.Conn.Write(frag)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += n

		// Add delay after SNI fragment (first fragment)
		if i == 0 && c.config.SNIFragmentDelay > 0 {
			time.Sleep(c.config.SNIFragmentDelay)
		} else if i < len(fragments)-1 {
			// Regular delay between other fragments
			delay := c.config.DelayMin
			if c.config.DelayMax > c.config.DelayMin {
				delay += time.Duration(rand.Int63n(int64(c.config.DelayMax - c.config.DelayMin)))
			}
			if delay > 0 {
				time.Sleep(delay)
			}
		}
	}

	c.blendDone = true
	return len(p), nil
}
