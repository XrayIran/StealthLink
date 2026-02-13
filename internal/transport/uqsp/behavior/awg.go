package behavior

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/kcpbase"
)

const (
	AWGPacketTypeData      uint8 = 0x00
	AWGPacketTypeJunk      uint8 = 0xFF
	AWGPacketTypeInit      uint8 = 0x01
	AWGPacketTypeResponse  uint8 = 0x02
	AWGPacketTypeCookie    uint8 = 0x03
	AWGPacketTypeTransport uint8 = 0x04
	AWGPacketTypeClose     uint8 = 0x05
	AWGPacketTypeUnderload uint8 = 0x06

	defaultJunkPacketCount    = 3
	defaultJunkPacketMinSize  = 50
	defaultJunkPacketMaxSize  = 1000
	defaultInitPacketJunkSize = 0
	defaultTransportJunkSize  = 0
)

type AWGMagicHeaders struct {
	InitPacketMagicHeader      []byte
	ResponsePacketMagicHeader  []byte
	UnderloadPacketMagicHeader []byte
	TransportPacketMagicHeader []byte
}

func DefaultAWGMagicHeaders() *AWGMagicHeaders {
	return &AWGMagicHeaders{
		InitPacketMagicHeader:      []byte{0x01, 0x00, 0x00, 0x00},
		ResponsePacketMagicHeader:  []byte{0x02, 0x00, 0x00, 0x00},
		UnderloadPacketMagicHeader: []byte{0x03, 0x00, 0x00, 0x00},
		TransportPacketMagicHeader: []byte{0x04, 0x00, 0x00, 0x00},
	}
}

func ParseMagicHeader(s string) []byte {
	if s == "" {
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return []byte(s)
	}
	return b
}

func GenerateMagicHeader() []byte {
	b := make([]byte, 4)
	kcpbase.FastRandom.Read(b)
	return b
}

// AWGOverlay ports AmneziaWG 2.0 behaviors as a UQSP overlay.
// AWG (Amnezia WireGuard) adds junk packet injection and timing obfuscation.
type AWGOverlay struct {
	EnabledField bool
	JunkInterval time.Duration
	JunkMinSize  int
	JunkMaxSize  int

	JunkPacketCount           int
	InitPacketJunkSize        int
	ResponsePacketJunkSize    int
	CookieReplyPacketJunkSize int
	TransportPacketJunkSize   int

	MagicHeaders *AWGMagicHeaders
	SpecialJunk  map[string][]byte

	// AmneziaWG 2.0 extended features
	SpecialJunkPackets  [5][]byte     // specialJunk1-5 from Amnezia
	SpecialJunkOptional bool          // allow peers that do not advertise/require special junk packets
	MTU                 int           // MTU for packet sizing
	PacketObfuscator    *PacketObfs   // Packet-level obfuscation
	TimingJitter        time.Duration // Max timing jitter

	session *AWGSession
}

// PacketObfs provides packet-level obfuscation for AWG
type PacketObfs struct {
	enabled    bool
	key        []byte
	seed       uint32
	paddingMin int
	paddingMax int
	counter    uint64
	counterMu  sync.Mutex
}

// NewPacketObfs creates a new packet obfuscator
func NewPacketObfs(key []byte, paddingMin, paddingMax int) *PacketObfs {
	seed := uint32(0)
	if len(key) >= 4 {
		seed = binary.BigEndian.Uint32(key[:4])
	}
	return &PacketObfs{
		enabled:    len(key) > 0,
		key:        key,
		seed:       seed,
		paddingMin: paddingMin,
		paddingMax: paddingMax,
	}
}

// Obfuscate applies obfuscation to outgoing packets
func (o *PacketObfs) Obfuscate(data []byte) []byte {
	if !o.enabled {
		return data
	}

	o.counterMu.Lock()
	o.counter++
	counter := o.counter
	o.counterMu.Unlock()

	// Add padding
	padding := o.paddingMin
	if o.paddingMax > o.paddingMin {
		padding += int(counter % uint64(o.paddingMax-o.paddingMin+1))
	}

	// Create obfuscated packet: [type(1)][counter(8)][len(2)][data][padding]
	buf := make([]byte, 1+8+2+len(data)+padding)
	buf[0] = AWGPacketTypeTransport
	binary.BigEndian.PutUint64(buf[1:9], counter)
	binary.BigEndian.PutUint16(buf[9:11], uint16(len(data)))
	copy(buf[11:], data)

	// XOR with key-derived stream
	for i := range buf[11:] {
		buf[11+i] ^= o.key[(counter+uint64(i))%uint64(len(o.key))]
	}

	// Fill padding with random
	if padding > 0 {
		kcpbase.FastRandom.Read(buf[11+len(data):])
	}

	return buf
}

// Deobfuscate removes obfuscation from incoming packets
func (o *PacketObfs) Deobfuscate(data []byte) ([]byte, error) {
	if !o.enabled {
		return data, nil
	}

	if len(data) < 11 {
		return nil, fmt.Errorf("packet too short for deobfuscation")
	}

	if data[0] != AWGPacketTypeTransport {
		return data, nil // Not obfuscated
	}

	counter := binary.BigEndian.Uint64(data[1:9])
	payloadLen := int(binary.BigEndian.Uint16(data[9:11]))

	if len(data) < 11+payloadLen {
		return nil, fmt.Errorf("packet truncated")
	}

	// Reverse XOR
	payload := make([]byte, payloadLen)
	for i := 0; i < payloadLen; i++ {
		payload[i] = data[11+i] ^ o.key[(counter+uint64(i))%uint64(len(o.key))]
	}

	return payload, nil
}

func NewAWGOverlay(cfg config.AWGBehaviorConfig) *AWGOverlay {
	o := &AWGOverlay{
		EnabledField:        cfg.Enabled,
		JunkInterval:        cfg.JunkInterval,
		JunkMinSize:         cfg.JunkMinSize,
		JunkMaxSize:         cfg.JunkMaxSize,
		MagicHeaders:        DefaultAWGMagicHeaders(),
		SpecialJunk:         make(map[string][]byte),
		SpecialJunkOptional: true,
		MTU:                 1280,
		TimingJitter:        10 * time.Millisecond,
	}

	if cfg.JunkPacketCount > 0 {
		o.JunkPacketCount = cfg.JunkPacketCount
	} else {
		o.JunkPacketCount = defaultJunkPacketCount
	}

	if cfg.JunkMinSize <= 0 {
		o.JunkMinSize = defaultJunkPacketMinSize
	}
	if cfg.JunkMaxSize <= 0 {
		o.JunkMaxSize = defaultJunkPacketMaxSize
	}
	if cfg.InitPacketJunkSize > 0 {
		o.InitPacketJunkSize = cfg.InitPacketJunkSize
	}
	if cfg.ResponsePacketJunkSize > 0 {
		o.ResponsePacketJunkSize = cfg.ResponsePacketJunkSize
	}
	if cfg.CookieReplyPacketJunkSize > 0 {
		o.CookieReplyPacketJunkSize = cfg.CookieReplyPacketJunkSize
	}
	if cfg.TransportPacketJunkSize > 0 {
		o.TransportPacketJunkSize = cfg.TransportPacketJunkSize
	}

	if cfg.MagicHeaders != nil {
		if cfg.MagicHeaders.Init != "" {
			o.MagicHeaders.InitPacketMagicHeader = ParseMagicHeader(cfg.MagicHeaders.Init)
		}
		if cfg.MagicHeaders.Response != "" {
			o.MagicHeaders.ResponsePacketMagicHeader = ParseMagicHeader(cfg.MagicHeaders.Response)
		}
		if cfg.MagicHeaders.Underload != "" {
			o.MagicHeaders.UnderloadPacketMagicHeader = ParseMagicHeader(cfg.MagicHeaders.Underload)
		}
		if cfg.MagicHeaders.Transport != "" {
			o.MagicHeaders.TransportPacketMagicHeader = ParseMagicHeader(cfg.MagicHeaders.Transport)
		}
	}
	// SpecialJunkOptional defaults to true (set above). If config sets
	// a value explicitly, honor it.
	if cfg.SpecialJunkOptional != nil {
		o.SpecialJunkOptional = *cfg.SpecialJunkOptional
	}

	// Generate special junk packets (AmneziaWG 2.0 feature)
	o.generateSpecialJunkPackets()

	o.session = NewAWGSession(generateSessionID())

	// Initialize packet obfuscator if obfuscation params are provided
	// Use JunkMinSize/JunkMaxSize as padding range for obfuscator
	if o.JunkMinSize > 0 || o.JunkMaxSize > 0 {
		// Derive obfuscation key from session ID
		obfsKey := []byte(o.session.SessionID)
		o.PacketObfuscator = NewPacketObfs(obfsKey, o.JunkMinSize, o.JunkMaxSize)
	}

	return o
}

// generateSpecialJunkPackets creates the 5 special junk packets used by AmneziaWG
func (o *AWGOverlay) generateSpecialJunkPackets() {
	for i := 0; i < 5; i++ {
		// Each special junk packet has a distinct size pattern
		size := 64 + i*128 + int(binary.BigEndian.Uint32(GenerateMagicHeader())%64)
		packet := make([]byte, size)
		kcpbase.FastRandom.Read(packet)

		// First byte marks as special junk type (0xF1-0xF5)
		packet[0] = 0xF1 + byte(i)

		// Add identifiable pattern
		binary.BigEndian.PutUint32(packet[1:5], uint32(i+1)<<24)
		o.SpecialJunkPackets[i] = packet
	}
}

// GetSpecialJunkPacket returns a special junk packet by index (1-5)
func (o *AWGOverlay) GetSpecialJunkPacket(idx int) []byte {
	if idx < 1 || idx > 5 {
		return nil
	}
	return o.SpecialJunkPackets[idx-1]
}

// InjectSpecialJunk sends a special junk packet at random intervals
func (o *AWGOverlay) InjectSpecialJunk(conn net.Conn) error {
	if !o.EnabledField {
		return nil
	}

	// Pick a random special junk packet
	idx := int(time.Now().UnixNano() % 5)
	packet := o.GetSpecialJunkPacket(idx + 1)
	if packet == nil {
		return nil
	}

	_, err := conn.Write(packet)
	return err
}

func generateSessionID() string {
	b := make([]byte, 16)
	kcpbase.FastRandom.Read(b)
	return hex.EncodeToString(b)
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
		obfs:         o.PacketObfuscator,
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
	obfs         *PacketObfs
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
		size += int(kcpbase.FastRandom.Int64n(int64(c.junkMaxSize - c.junkMinSize + 1)))
	}

	// Generate junk data
	junk := make([]byte, size)
	if _, err := kcpbase.FastRandom.Read(junk); err != nil {
		return err
	}

	// Mark as junk packet (first byte indicates type)
	junk[0] = 0xFF // Junk packet marker

	// Write junk packet
	_, err := c.Conn.Write(junk)
	return err
}

// Read reads data from the connection, filtering out junk packets and
// deobfuscating transport packets when PacketObfs is configured.
func (c *awgConn) Read(p []byte) (int, error) {
	buf := make([]byte, len(p)+64) // extra room for obfs header + padding
	for {
		n, err := c.Conn.Read(buf)
		if err != nil {
			return 0, err
		}
		if n == 0 {
			continue
		}

		// Check if this is a junk packet (0xFF) or special junk (0xF1-0xF5)
		if buf[0] == 0xFF || (buf[0] >= 0xF1 && buf[0] <= 0xF5) {
			continue
		}

		// Deobfuscate if PacketObfs is active
		if c.obfs != nil && n >= 11 && buf[0] == AWGPacketTypeTransport {
			payload, derr := c.obfs.Deobfuscate(buf[:n])
			if derr != nil {
				continue // drop malformed
			}
			nn := copy(p, payload)
			return nn, nil
		}

		nn := copy(p, buf[:n])
		return nn, nil
	}
}

// Write writes data to the connection, applying PacketObfs when configured.
func (c *awgConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if c.obfs != nil {
		obfuscated := c.obfs.Obfuscate(p)
		_, err := c.Conn.Write(obfuscated)
		if err != nil {
			return 0, err
		}
		return len(p), nil
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
	SessionID     string
	CreatedAt     time.Time
	LastActive    time.Time
	JunkSent      uint64
	JunkBytes     uint64
	RealSent      uint64
	RealBytes     uint64
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

type AWGPacket struct {
	Type      uint8
	SessionID uint32
	Payload   []byte
}

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
		if _, err := kcpbase.FastRandom.Read(packet[5:]); err != nil {
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
	jitter := min + time.Duration(kcpbase.FastRandom.Int64n(int64(diff+1)))

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
