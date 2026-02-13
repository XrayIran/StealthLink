// Package wireguard implements AmneziaWG-style junk packet injection.
// This provides traffic obfuscation similar to AmneziaWG's modifications.
package wireguard

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net"
	"stealthlink/internal/transport/kcpbase"
	"sync"
	"time"
)

// JunkConfig configures junk packet injection parameters.
// Based on AmneziaWG's configuration options.
type JunkConfig struct {
	Enabled bool `yaml:"enabled"`

	// Jc: Junk packet count - number of junk packets before handshake
	// Default: 3
	Jc int `yaml:"jc"`

	// Jmin: Minimum junk packet size
	// Default: 10 bytes
	Jmin int `yaml:"jmin"`

	// Jmax: Maximum junk packet size
	// Default: 30 bytes
	Jmax int `yaml:"jmax"`

	// S1: Init packet junk - extra bytes in init message
	// Default: 15 bytes
	S1 int `yaml:"s1"`

	// S2: Response junk - extra bytes in response message
	// Default: 18 bytes
	S2 int `yaml:"s2"`

	// S3: Cookie reply junk - extra bytes in cookie reply (AWG v2)
	// Default: 20 bytes
	S3 int `yaml:"s3"`

	// S4: Transport junk - extra bytes in transport packets (AWG v2)
	// Default: 23 bytes
	S4 int `yaml:"s4"`

	// JunkInterval is the interval between junk packets for timing obfuscation
	JunkInterval time.Duration

	// H1-H4: Custom magic headers
	// These replace the default WireGuard magic numbers
	H1 uint32 `yaml:"h1"` // Init magic header
	H2 uint32 `yaml:"h2"` // Response magic header
	H3 uint32 `yaml:"h3"` // Underload magic header
	H4 uint32 `yaml:"h4"` // Transport magic header

	// I1-I5: Special junk data patterns (AWG v1.5+)
	// These can mimic other protocols like DNS
	I1 []byte `yaml:"i1"`
	I2 []byte `yaml:"i2"`
	I3 []byte `yaml:"i3"`
	I4 []byte `yaml:"i4"`
	I5 []byte `yaml:"i5"`
}

// Default magic headers (can be customized)
const (
	DefaultH1 = uint32(1020325451) // Init magic
	DefaultH2 = uint32(3288052141) // Response magic
	DefaultH3 = uint32(1766607858) // Underload magic
	DefaultH4 = uint32(2528465083) // Transport magic
)

// ApplyDefaults sets default values for junk configuration.
func (c *JunkConfig) ApplyDefaults() {
	if c.Jc < 0 {
		c.Jc = 3
	}
	if c.Jmin <= 0 {
		c.Jmin = 10
	}
	if c.Jmax <= 0 {
		c.Jmax = 30
	}
	if c.Jmax < c.Jmin {
		c.Jmax = c.Jmin
	}
	if c.S1 < 0 {
		c.S1 = 15
	}
	if c.S2 < 0 {
		c.S2 = 18
	}
	if c.S3 < 0 {
		c.S3 = 20
	}
	if c.S4 < 0 {
		c.S4 = 23
	}
	if c.H1 == 0 {
		c.H1 = DefaultH1
	}
	if c.H2 == 0 {
		c.H2 = DefaultH2
	}
	if c.H3 == 0 {
		c.H3 = DefaultH3
	}
	if c.H4 == 0 {
		c.H4 = DefaultH4
	}
}

// GenerateJunkPacket generates a junk packet with random content.
func (c *JunkConfig) GenerateJunkPacket() []byte {
	c.ApplyDefaults()

	// Determine size
	size := c.Jmin
	if c.Jmax > c.Jmin {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(c.Jmax-c.Jmin+1)))
		size += int(n.Int64())
	}

	packet := make([]byte, size)
	kcpbase.FastRandom.Read(packet)
	return packet
}

// GenerateJunkPackets generates multiple junk packets.
func (c *JunkConfig) GenerateJunkPackets() [][]byte {
	c.ApplyDefaults()

	packets := make([][]byte, c.Jc)
	for i := 0; i < c.Jc; i++ {
		packets[i] = c.GenerateJunkPacket()
	}
	return packets
}

// GetInitJunk returns the extra junk bytes for init packets.
func (c *JunkConfig) GetInitJunk() []byte {
	c.ApplyDefaults()
	if c.S1 <= 0 {
		return nil
	}
	junk := make([]byte, c.S1)
	kcpbase.FastRandom.Read(junk)
	return junk
}

// GetResponseJunk returns the extra junk bytes for response packets.
func (c *JunkConfig) GetResponseJunk() []byte {
	c.ApplyDefaults()
	if c.S2 <= 0 {
		return nil
	}
	junk := make([]byte, c.S2)
	kcpbase.FastRandom.Read(junk)
	return junk
}

// GetCookieReplyJunk returns the extra junk bytes for cookie reply packets.
func (c *JunkConfig) GetCookieReplyJunk() []byte {
	c.ApplyDefaults()
	if c.S3 <= 0 {
		return nil
	}
	junk := make([]byte, c.S3)
	kcpbase.FastRandom.Read(junk)
	return junk
}

// GetTransportJunk returns the extra junk bytes for transport packets.
func (c *JunkConfig) GetTransportJunk() []byte {
	c.ApplyDefaults()
	if c.S4 <= 0 {
		return nil
	}
	junk := make([]byte, c.S4)
	kcpbase.FastRandom.Read(junk)
	return junk
}

// GetMagicHeaders returns the custom magic headers.
func (c *JunkConfig) GetMagicHeaders() (h1, h2, h3, h4 uint32) {
	c.ApplyDefaults()
	return c.H1, c.H2, c.H3, c.H4
}

// PacketType represents the type of WireGuard packet.
type PacketType byte

const (
	PacketTypeInit        PacketType = 1
	PacketTypeResponse    PacketType = 2
	PacketTypeCookieReply PacketType = 3
	PacketTypeTransport   PacketType = 4
)

// ObfuscatedPacket represents a packet with junk data appended.
type ObfuscatedPacket struct {
	Type    PacketType
	Header  uint32 // Magic header
	Payload []byte // Original payload
	Junk    []byte // Junk padding
}

// Marshal serializes the obfuscated packet.
func (p *ObfuscatedPacket) Marshal() []byte {
	totalLen := 4 + len(p.Payload) + len(p.Junk)
	buf := make([]byte, totalLen)

	// Write header
	binary.LittleEndian.PutUint32(buf[0:4], p.Header)

	// Write payload
	offset := 4
	copy(buf[offset:], p.Payload)
	offset += len(p.Payload)

	// Write junk
	copy(buf[offset:], p.Junk)

	return buf
}

// Unmarshal deserializes an obfuscated packet.
func (p *ObfuscatedPacket) Unmarshal(data []byte, expectedLen int) error {
	if len(data) < 4 {
		return fmt.Errorf("packet too short")
	}

	p.Header = binary.LittleEndian.Uint32(data[0:4])

	if len(data) > 4+expectedLen {
		p.Payload = data[4 : 4+expectedLen]
		p.Junk = data[4+expectedLen:]
	} else {
		p.Payload = data[4:]
		p.Junk = nil
	}

	return nil
}

// JunkInjector handles junk packet injection.
type JunkInjector struct {
	config *JunkConfig
}

// NewJunkInjector creates a new junk injector.
func NewJunkInjector(config *JunkConfig) *JunkInjector {
	if config == nil {
		config = &JunkConfig{}
	}
	config.ApplyDefaults()
	return &JunkInjector{config: config}
}

// InjectHandshakeJunk injects junk packets before handshake.
func (j *JunkInjector) InjectHandshakeJunk(sendFunc func([]byte) error) error {
	if !j.config.Enabled {
		return nil
	}

	packets := j.config.GenerateJunkPackets()
	for _, packet := range packets {
		if err := sendFunc(packet); err != nil {
			return err
		}
	}
	return nil
}

// ObfuscateInitPacket obfuscates an init packet.
func (j *JunkInjector) ObfuscateInitPacket(payload []byte) []byte {
	if !j.config.Enabled {
		return payload
	}

	junk := j.config.GetInitJunk()
	if len(junk) == 0 {
		return payload
	}

	packet := &ObfuscatedPacket{
		Type:    PacketTypeInit,
		Header:  j.config.H1,
		Payload: payload,
		Junk:    junk,
	}

	return packet.Marshal()
}

// ObfuscateResponsePacket obfuscates a response packet.
func (j *JunkInjector) ObfuscateResponsePacket(payload []byte) []byte {
	if !j.config.Enabled {
		return payload
	}

	junk := j.config.GetResponseJunk()
	if len(junk) == 0 {
		return payload
	}

	packet := &ObfuscatedPacket{
		Type:    PacketTypeResponse,
		Header:  j.config.H2,
		Payload: payload,
		Junk:    junk,
	}

	return packet.Marshal()
}

// ObfuscateTransportPacket obfuscates a transport packet.
func (j *JunkInjector) ObfuscateTransportPacket(payload []byte) []byte {
	if !j.config.Enabled {
		return payload
	}

	junk := j.config.GetTransportJunk()
	if len(junk) == 0 {
		return payload
	}

	packet := &ObfuscatedPacket{
		Type:    PacketTypeTransport,
		Header:  j.config.H4,
		Payload: payload,
		Junk:    junk,
	}

	return packet.Marshal()
}

// DeobfuscatePacket removes junk from an obfuscated packet.
func (j *JunkInjector) DeobfuscatePacket(data []byte, packetType PacketType, expectedPayloadLen int) ([]byte, error) {
	if !j.config.Enabled || len(data) <= expectedPayloadLen {
		return data, nil
	}

	var header uint32
	switch packetType {
	case PacketTypeInit:
		header = j.config.H1
	case PacketTypeResponse:
		header = j.config.H2
	case PacketTypeCookieReply:
		header = j.config.H3
	case PacketTypeTransport:
		header = j.config.H4
	}

	// Check if packet has our magic header
	if len(data) >= 4 && binary.LittleEndian.Uint32(data[0:4]) == header {
		packet := &ObfuscatedPacket{}
		if err := packet.Unmarshal(data, expectedPayloadLen); err != nil {
			return nil, err
		}
		return packet.Payload, nil
	}

	// No magic header, return as-is
	return data, nil
}

// GenerateDNSLikeJunk generates junk that looks like DNS queries.
// This can be used with I1-I5 parameters for protocol mimicry.
func (j *JunkInjector) GenerateDNSLikeJunk() []byte {
	// DNS-like structure: [length][data][length][data]...
	labels := 2 + makeRandomInt(3) // 2-4 labels
	packet := make([]byte, 0, 64)

	for i := 0; i < labels; i++ {
		labelLen := 3 + makeRandomInt(10) // 3-12 bytes per label
		packet = append(packet, byte(labelLen))
		label := make([]byte, labelLen)
		kcpbase.FastRandom.Read(label)
		// Make it look like valid DNS characters
		for j := range label {
			label[j] = 'a' + (label[j] % 26)
		}
		packet = append(packet, label...)
	}

	packet = append(packet, 0) // Null terminator

	// Add query type and class
	packet = append(packet, 0x00, 0x01) // Type A
	packet = append(packet, 0x00, 0x01) // Class IN

	return packet
}

func makeRandomInt(max int) int {
	if max <= 0 {
		return 0
	}
	return int(kcpbase.FastRandom.Int64n(int64(max)))
}

// AWGProfile represents a complete AmneziaWG configuration profile
type AWGProfile struct {
	// Junk packet injection parameters
	Jc   int // Junk packet count
	Jmin int // Minimum junk size
	Jmax int // Max junk size

	// Packet junk parameters
	S1 int // Init packet junk
	S2 int // Response junk
	S3 int // Cookie reply junk (AWG v2)
	S4 int // Transport junk (AWG v2)

	// Magic headers
	H1 uint32 // First junk packet size
	H2 uint32 // Second junk packet size
	H3 uint32 // Third junk packet size
	H4 uint32 // Fourth junk packet size
}

// TimingObfuscator provides advanced timing obfuscation for AWG
type TimingObfuscator struct {
	config        *JunkConfig
	baseInterval  time.Duration
	jitterPercent float64
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewTimingObfuscator creates a new timing obfuscator
func NewTimingObfuscator(config *JunkConfig, baseInterval time.Duration) *TimingObfuscator {
	if config == nil {
		config = &JunkConfig{}
		config.ApplyDefaults()
	}
	return &TimingObfuscator{
		config:        config,
		baseInterval:  baseInterval,
		jitterPercent: 0.3, // 30% jitter
		stopCh:        make(chan struct{}),
	}
}

// Start begins the timing obfuscation loop
func (t *TimingObfuscator) Start(sendFunc func([]byte) error) {
	if !t.config.Enabled {
		return
	}

	t.wg.Add(1)
	go t.obfuscationLoop(sendFunc)
}

// Stop stops the timing obfuscator
func (t *TimingObfuscator) Stop() {
	close(t.stopCh)
	t.wg.Wait()
}

// obfuscationLoop sends junk packets with randomized timing
func (t *TimingObfuscator) obfuscationLoop(sendFunc func([]byte) error) {
	defer t.wg.Done()

	ticker := time.NewTicker(t.calculateNextInterval())
	defer ticker.Stop()

	for {
		select {
		case <-t.stopCh:
			return
		case <-ticker.C:
			// Send junk packet
			junk := t.config.GenerateJunkPacket()
			if err := sendFunc(junk); err != nil {
				return
			}

			// Randomize next interval
			ticker.Reset(t.calculateNextInterval())
		}
	}
}

// calculateNextInterval calculates the next interval with jitter
func (t *TimingObfuscator) calculateNextInterval() time.Duration {
	if t.baseInterval <= 0 {
		t.baseInterval = 5 * time.Second
	}

	// Add jitter
	jitter := float64(t.baseInterval) * t.jitterPercent
	offset := time.Duration(kcpbase.FastRandom.Int64n(int64(2 * jitter))) - time.Duration(jitter)

	return t.baseInterval + offset
}

// SizeRandomizer provides packet size randomization
type SizeRandomizer struct {
	minSize      int
	maxSize      int
	targetSize   int
	distribution string // "uniform", "gaussian", "exponential"
}

// NewSizeRandomizer creates a new size randomizer
func NewSizeRandomizer(minSize, maxSize int, distribution string) *SizeRandomizer {
	if minSize <= 0 {
		minSize = 64
	}
	if maxSize <= minSize {
		maxSize = minSize * 10
	}
	if distribution == "" {
		distribution = "uniform"
	}
	return &SizeRandomizer{
		minSize:      minSize,
		maxSize:      maxSize,
		targetSize:   (minSize + maxSize) / 2,
		distribution: distribution,
	}
}

// RandomizeSize returns a randomized packet size
func (s *SizeRandomizer) RandomizeSize() int {
	switch s.distribution {
	case "gaussian":
		return s.gaussianSize()
	case "exponential":
		return s.exponentialSize()
	default: // uniform
		return s.uniformSize()
	}
}

// uniformSize returns a uniformly distributed size
func (s *SizeRandomizer) uniformSize() int {
	range_ := s.maxSize - s.minSize
	if range_ <= 0 {
		return s.minSize
	}
	return s.minSize + int(kcpbase.FastRandom.Int64n(int64(range_+1)))
}

// gaussianSize returns a gaussian distributed size (approximated)
func (s *SizeRandomizer) gaussianSize() int {
	// Box-Muller transform approximation
	u1 := kcpbase.FastRandom.Int64n(1000)
	u2 := kcpbase.FastRandom.Int64n(1000)

	f1 := float64(u1) / 1000.0
	f2 := float64(u2) / 1000.0

	// Standard normal
	z := math.Sqrt(-2*math.Log(f1+0.0001)) * math.Cos(2*math.Pi*f2)

	// Scale to our range
	mean := float64(s.targetSize)
	stddev := float64(s.maxSize-s.minSize) / 6 // 99.7% within range

	size := int(mean + z*stddev)
	if size < s.minSize {
		size = s.minSize
	}
	if size > s.maxSize {
		size = s.maxSize
	}
	return size
}

// exponentialSize returns an exponentially distributed size
func (s *SizeRandomizer) exponentialSize() int {
	// Generate exponential random variable
	u := kcpbase.FastRandom.Int64n(1000)
	f := float64(u) / 1000.0
	if f < 0.0001 {
		f = 0.0001
	}

	lambda := 1.0 / float64(s.targetSize-s.minSize)
	exp := -math.Log(f) / lambda

	size := s.minSize + int(exp)
	if size > s.maxSize {
		size = s.maxSize
	}
	return size
}

// PadToSize pads data to the target randomized size
func (s *SizeRandomizer) PadToSize(data []byte) []byte {
	targetSize := s.RandomizeSize()
	if len(data) >= targetSize {
		return data
	}

	padding := make([]byte, targetSize-len(data))
	kcpbase.FastRandom.Read(padding)
	return append(data, padding...)
}

// AWGConn wraps a connection with AmneziaWG obfuscation
type AWGConn struct {
	net.Conn
	injector     *JunkInjector
	timingObf    *TimingObfuscator
	sizeRandom   *SizeRandomizer
	writeMu      sync.Mutex
	obfuscateSNI bool
	sniDomain    string
}

// NewAWGConn creates a new AWG-wrapped connection
func NewAWGConn(conn net.Conn, config *JunkConfig, obfuscateSNI bool, sniDomain string) *AWGConn {
	if config == nil {
		config = &JunkConfig{}
		config.ApplyDefaults()
	}

	awg := &AWGConn{
		Conn:         conn,
		injector:     NewJunkInjector(config),
		sizeRandom:   NewSizeRandomizer(config.Jmin, config.Jmax, "gaussian"),
		obfuscateSNI: obfuscateSNI,
		sniDomain:    sniDomain,
	}

	if config.Enabled {
		awg.timingObf = NewTimingObfuscator(config, config.JunkInterval)
	}

	return awg
}

// StartTimingObfuscation starts the timing obfuscation goroutine
func (c *AWGConn) StartTimingObfuscation() {
	if c.timingObf != nil {
		c.timingObf.Start(func(junk []byte) error {
			_, err := c.Conn.Write(junk)
			return err
		})
	}
}

// StopTimingObfuscation stops the timing obfuscation
func (c *AWGConn) StopTimingObfuscation() {
	if c.timingObf != nil {
		c.timingObf.Stop()
	}
}

// Write writes data with AWG obfuscation
func (c *AWGConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Obfuscate transport packet
	data := c.injector.ObfuscateTransportPacket(p)

	// Apply size randomization padding
	data = c.sizeRandom.PadToSize(data)

	_, err := c.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read reads data and deobfuscates
func (c *AWGConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		return n, err
	}

	// Deobfuscate if needed
	if c.injector.config.Enabled && n >= 4 {
		data, deobfErr := c.injector.DeobfuscatePacket(p[:n], PacketTypeTransport, n-c.injector.config.S4-4)
		if deobfErr == nil && len(data) <= len(p) {
			copy(p, data)
			return len(data), nil
		}
	}

	return n, nil
}

// Close closes the connection
func (c *AWGConn) Close() error {
	c.StopTimingObfuscation()
	return c.Conn.Close()
}

// SNIObfuscator provides SNI obfuscation
type SNIObfuscator struct {
	fakeDomains []string
}

// NewSNIObfuscator creates a new SNI obfuscator
func NewSNIObfuscator(fakeDomains []string) *SNIObfuscator {
	if len(fakeDomains) == 0 {
		fakeDomains = []string{
			"www.google.com",
			"www.microsoft.com",
			"www.apple.com",
			"www.amazon.com",
			"cloudflare.com",
		}
	}
	return &SNIObfuscator{fakeDomains: fakeDomains}
}

// GetFakeSNI returns a random fake SNI
func (s *SNIObfuscator) GetFakeSNI() string {
	if len(s.fakeDomains) == 0 {
		return ""
	}
	n := kcpbase.FastRandom.Int64n(int64(len(s.fakeDomains)))
	return s.fakeDomains[n]
}

// ObfuscateClientHello obfuscates TLS Client Hello SNI
func (s *SNIObfuscator) ObfuscateClientHello(data []byte) []byte {
	// Simple SNI replacement - in real implementation would parse TLS properly
	if len(data) < 10 {
		return data
	}

	// Check if this looks like a TLS Client Hello
	if data[0] != 0x16 { // Not TLS Handshake
		return data
	}

	// Find and replace SNI (simplified - real implementation needs proper TLS parsing)
	fakeSNI := s.GetFakeSNI()
	if fakeSNI == "" {
		return data
	}

	// In a real implementation, this would properly parse the TLS ClientHello
	// and replace the SNI extension with the fake domain
	_ = fakeSNI
	return data
}
