package behavior

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
)

// AWGOverlay ports AmneziaWG 2.0 behaviors as a UQSP overlay.
// AWG (Amnezia WireGuard) adds junk packet injection and timing obfuscation.
type AWGOverlay struct {
	EnabledField bool
	JunkInterval time.Duration
	JunkMinSize  int
	JunkMaxSize  int
}

// NewAWGOverlay creates a new AWG overlay from config
func NewAWGOverlay(cfg config.AWGBehaviorConfig) *AWGOverlay {
	return &AWGOverlay{
		EnabledField: cfg.Enabled,
		JunkInterval: cfg.JunkInterval,
		JunkMinSize:  cfg.JunkMinSize,
		JunkMaxSize:  cfg.JunkMaxSize,
	}
}

// Name returns "awg"
func (o *AWGOverlay) Name() string {
	return "awg"
}

// Enabled returns whether this overlay is enabled
func (o *AWGOverlay) Enabled() bool {
	return o.EnabledField
}

// Apply applies AWG behavior to the connection
func (o *AWGOverlay) Apply(conn net.Conn) (net.Conn, error) {
	if !o.EnabledField {
		return conn, nil
	}

	wrapper := &awgConn{
		Conn:         conn,
		junkInterval: o.JunkInterval,
		junkMinSize:  o.JunkMinSize,
		junkMaxSize:  o.JunkMaxSize,
		stopJunk:     make(chan struct{}),
	}

	// Start junk packet injection
	go wrapper.junkLoop()

	return wrapper, nil
}

// awgConn wraps a connection with AWG behavior
type awgConn struct {
	net.Conn
	junkInterval time.Duration
	junkMinSize  int
	junkMaxSize  int
	stopJunk     chan struct{}
	mu           sync.Mutex
	closed       bool
}

// junkLoop sends periodic junk packets
func (c *awgConn) junkLoop() {
	if c.junkInterval <= 0 {
		c.junkInterval = 5 * time.Second
	}

	ticker := time.NewTicker(c.junkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.sendJunkPacket(); err != nil {
				return
			}
		case <-c.stopJunk:
			return
		}
	}
}

// sendJunkPacket sends a junk packet
func (c *awgConn) sendJunkPacket() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection closed")
	}

	// Generate junk packet size
	size := c.junkMinSize
	if c.junkMaxSize > c.junkMinSize {
		size += int(time.Now().UnixNano()) % (c.junkMaxSize - c.junkMinSize)
	}

	// Generate junk data
	junk := make([]byte, size)
	if _, err := rand.Read(junk); err != nil {
		return err
	}

	// Mark as junk packet (first byte indicates type)
	junk[0] = 0xFF // Junk packet marker

	// Write junk packet
	_, err := c.Conn.Write(junk)
	return err
}

// Read reads data from the connection, filtering out junk packets
func (c *awgConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil {
			return n, err
		}

		// Check if this is a junk packet
		if n > 0 && p[0] == 0xFF {
			// Junk packet, skip and read again
			continue
		}

		return n, nil
	}
}

// Write writes data to the connection
func (c *awgConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	return c.Conn.Write(p)
}

// Close closes the connection
func (c *awgConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.closed = true
	close(c.stopJunk)

	return c.Conn.Close()
}

// Ensure awgConn implements net.Conn
var _ net.Conn = (*awgConn)(nil)

// AWGConfig configures AWG behavior
type AWGConfig struct {
	// Junk packet settings
	JunkEnabled  bool
	JunkInterval time.Duration
	JunkMinSize  int
	JunkMaxSize  int

	// Timing obfuscation
	TimingObfuscation bool
	JitterMin         time.Duration
	JitterMax         time.Duration

	// Packet size randomization
	RandomizePacketSize bool
	MinPacketSize       int
	MaxPacketSize       int

	// Response timing
	ResponseDelayMin time.Duration
	ResponseDelayMax time.Duration
}

// DefaultAWGConfig returns default AWG configuration
func DefaultAWGConfig() *AWGConfig {
	return &AWGConfig{
		JunkEnabled:         true,
		JunkInterval:        5 * time.Second,
		JunkMinSize:         64,
		JunkMaxSize:         1024,
		TimingObfuscation:   true,
		JitterMin:           1 * time.Millisecond,
		JitterMax:           10 * time.Millisecond,
		RandomizePacketSize: true,
		MinPacketSize:       128,
		MaxPacketSize:       1400,
		ResponseDelayMin:    0,
		ResponseDelayMax:    5 * time.Millisecond,
	}
}

// AWGSession manages AWG session state
type AWGSession struct {
	SessionID    string
	CreatedAt    time.Time
	LastActive   time.Time
	JunkSent     uint64
	JunkBytes    uint64
	RealSent     uint64
	RealBytes    uint64
	JitterApplied time.Duration
}

// NewAWGSession creates a new AWG session
func NewAWGSession(sessionID string) *AWGSession {
	now := time.Now()
	return &AWGSession{
		SessionID:  sessionID,
		CreatedAt:  now,
		LastActive: now,
	}
}

// UpdateActivity updates the last active timestamp
func (s *AWGSession) UpdateActivity() {
	s.LastActive = time.Now()
}

// RecordJunk records junk packet statistics
func (s *AWGSession) RecordJunk(size int) {
	s.JunkSent++
	s.JunkBytes += uint64(size)
	s.UpdateActivity()
}

// RecordReal records real packet statistics
func (s *AWGSession) RecordReal(size int) {
	s.RealSent++
	s.RealBytes += uint64(size)
	s.UpdateActivity()
}

// RecordJitter records applied jitter
func (s *AWGSession) RecordJitter(jitter time.Duration) {
	s.JitterApplied += jitter
}

// GetStats returns session statistics
func (s *AWGSession) GetStats() AWGStats {
	return AWGStats{
		SessionID:     s.SessionID,
		Duration:      time.Since(s.CreatedAt),
		JunkSent:      s.JunkSent,
		JunkBytes:     s.JunkBytes,
		RealSent:      s.RealSent,
		RealBytes:     s.RealBytes,
		TotalPackets:  s.JunkSent + s.RealSent,
		TotalBytes:    s.JunkBytes + s.RealBytes,
		JunkRatio:     float64(s.JunkSent) / float64(s.JunkSent+s.RealSent+1),
		JitterApplied: s.JitterApplied,
	}
}

// AWGStats contains AWG session statistics
type AWGStats struct {
	SessionID     string
	Duration      time.Duration
	JunkSent      uint64
	JunkBytes     uint64
	RealSent      uint64
	RealBytes     uint64
	TotalPackets  uint64
	TotalBytes    uint64
	JunkRatio     float64
	JitterApplied time.Duration
}

// AWGPacket represents an AWG protocol packet
type AWGPacket struct {
	Type      uint8
	SessionID uint32
	Payload   []byte
}

// Packet types
const (
	AWGPacketTypeData  uint8 = 0x00
	AWGPacketTypeJunk  uint8 = 0xFF
	AWGPacketTypeInit  uint8 = 0x01
	AWGPacketTypeClose uint8 = 0x02
)

// Encode encodes an AWG packet
func (p *AWGPacket) Encode() []byte {
	buf := make([]byte, 5+len(p.Payload))
	buf[0] = p.Type
	binary.BigEndian.PutUint32(buf[1:5], p.SessionID)
	copy(buf[5:], p.Payload)
	return buf
}

// DecodeAWGPacket decodes an AWG packet
func DecodeAWGPacket(data []byte) (*AWGPacket, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("packet too short")
	}

	return &AWGPacket{
		Type:      data[0],
		SessionID: binary.BigEndian.Uint32(data[1:5]),
		Payload:   data[5:],
	}, nil
}

// GenerateJunkPacket generates a junk packet of specified size
func GenerateJunkPacket(size int) []byte {
	if size < 1 {
		size = 64
	}

	packet := make([]byte, size)
	packet[0] = AWGPacketTypeJunk

	if size > 5 {
		if _, err := rand.Read(packet[5:]); err != nil {
			// Fallback to pseudo-random
			for i := 5; i < size; i++ {
				packet[i] = byte(time.Now().UnixNano() % 256)
			}
		}
	}

	return packet
}

// CalculateJitter calculates a random jitter value
func CalculateJitter(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}

	diff := max - min
	// Generate random value between 0 and diff
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return min
	}

	randomVal := binary.BigEndian.Uint64(randomBytes)
	jitter := min + time.Duration(randomVal%uint64(diff))

	return jitter
}

// ApplyTimingObfuscation applies timing obfuscation to a connection operation
func ApplyTimingObfuscation(minDelay, maxDelay time.Duration, operation func() error) error {
	// Calculate jitter
	jitter := CalculateJitter(minDelay, maxDelay)

	// Apply delay
	time.Sleep(jitter)

	// Execute operation
	return operation()
}
