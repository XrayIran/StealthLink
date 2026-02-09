// Package noize implements protocol mimicry and junk packet injection.
// Based on Vwarp's Noize obfuscation.
package noize

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Config configures Noize obfuscation.
type Config struct {
	Enabled          bool          `yaml:"enabled"`
	Preset           string        `yaml:"preset"`            // minimal, light, medium, heavy, stealth, gfw, firewall
	JunkInterval     time.Duration `yaml:"junk_interval"`     // Interval between junk packets
	JunkMinSize      int           `yaml:"junk_min_size"`     // Minimum junk packet size
	JunkMaxSize      int           `yaml:"junk_max_size"`     // Maximum junk packet size
	SignaturePackets []string      `yaml:"signature_packets"` // Packet types to mimic: http, https, dns, stun
	FragmentPackets  bool          `yaml:"fragment_packets"`  // Fragment initial packets
	BurstPackets     int           `yaml:"burst_packets"`     // Junk packets per burst interval
	BurstInterval    time.Duration `yaml:"burst_interval"`    // Interval between bursts
	MaxJunkPercent   int           `yaml:"max_junk_percent"`  // Soft budget of junk traffic (1-95)
	Adaptive         bool          `yaml:"adaptive"`          // Adapt junk behavior to observed conditions
}

// Preset configurations.
var presets = map[string]Config{
	"minimal": {
		JunkInterval:     0,
		JunkMinSize:      0,
		JunkMaxSize:      0,
		SignaturePackets: []string{},
		FragmentPackets:  false,
		BurstPackets:     1,
		MaxJunkPercent:   10,
	},
	"light": {
		JunkInterval:     30 * time.Second,
		JunkMinSize:      64,
		JunkMaxSize:      256,
		SignaturePackets: []string{"stun"},
		FragmentPackets:  false,
		BurstPackets:     1,
		MaxJunkPercent:   20,
	},
	"medium": {
		JunkInterval:     15 * time.Second,
		JunkMinSize:      64,
		JunkMaxSize:      512,
		SignaturePackets: []string{"dns", "stun"},
		FragmentPackets:  true,
		BurstPackets:     2,
		MaxJunkPercent:   30,
	},
	"heavy": {
		JunkInterval:     5 * time.Second,
		JunkMinSize:      128,
		JunkMaxSize:      1024,
		SignaturePackets: []string{"http", "dns", "stun"},
		FragmentPackets:  true,
		BurstPackets:     2,
		MaxJunkPercent:   50,
	},
	"stealth": {
		JunkInterval:     10 * time.Second,
		JunkMinSize:      256,
		JunkMaxSize:      1500,
		SignaturePackets: []string{"https", "dns"},
		FragmentPackets:  true,
		BurstPackets:     3,
		MaxJunkPercent:   55,
	},
	"gfw": {
		JunkInterval:     3 * time.Second,
		JunkMinSize:      200,
		JunkMaxSize:      1200,
		SignaturePackets: []string{"https", "dns", "stun"},
		FragmentPackets:  true,
		BurstPackets:     3,
		MaxJunkPercent:   60,
	},
	"firewall": {
		JunkInterval:     1 * time.Second,
		JunkMinSize:      100,
		JunkMaxSize:      1400,
		SignaturePackets: []string{"http", "https", "dns"},
		FragmentPackets:  true,
		BurstPackets:     4,
		MaxJunkPercent:   70,
	},
}

// ApplyPreset applies a preset configuration.
func (c *Config) ApplyPreset() {
	if preset, ok := presets[c.Preset]; ok {
		c.JunkInterval = preset.JunkInterval
		c.JunkMinSize = preset.JunkMinSize
		c.JunkMaxSize = preset.JunkMaxSize
		c.SignaturePackets = preset.SignaturePackets
		c.FragmentPackets = preset.FragmentPackets
	}
}

// ApplyDefaults sets default values.
func (c *Config) ApplyDefaults() {
	if c.Preset != "" {
		c.ApplyPreset()
	}
	if c.JunkInterval == 0 && c.Enabled {
		c.JunkInterval = 10 * time.Second
	}
	if c.JunkMinSize == 0 {
		c.JunkMinSize = 64
	}
	if c.JunkMaxSize == 0 {
		c.JunkMaxSize = 1024
	}
	if c.JunkMaxSize < c.JunkMinSize {
		c.JunkMaxSize = c.JunkMinSize
	}
	if c.BurstPackets <= 0 {
		c.BurstPackets = 1
	}
	if c.BurstInterval <= 0 {
		c.BurstInterval = c.JunkInterval
	}
	if c.MaxJunkPercent <= 0 {
		c.MaxJunkPercent = 30
	}
	if c.MaxJunkPercent > 95 {
		c.MaxJunkPercent = 95
	}
}

// Noize implements protocol mimicry.
type Noize struct {
	config Config
	stopCh chan struct{}
}

// New creates a new Noize instance.
func New(config Config) *Noize {
	config.ApplyDefaults()
	return &Noize{
		config: config,
		stopCh: make(chan struct{}),
	}
}

// Start starts the Noize junk packet generator.
func (n *Noize) Start(sender func([]byte) error) {
	if !n.config.Enabled || n.config.JunkInterval == 0 {
		return
	}

	go n.junkLoop(sender)
}

// Stop stops the Noize generator.
func (n *Noize) Stop() {
	close(n.stopCh)
}

func (n *Noize) junkLoop(sender func([]byte) error) {
	ticker := time.NewTicker(n.config.JunkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			junk := n.GenerateJunk()
			if err := sender(junk); err != nil {
				return
			}
		case <-n.stopCh:
			return
		}
	}
}

// GenerateJunk generates a junk packet.
func (n *Noize) GenerateJunk() []byte {
	size := n.config.JunkMinSize
	if n.config.JunkMaxSize > n.config.JunkMinSize {
		size += randInt(n.config.JunkMaxSize - n.config.JunkMinSize)
	}

	// Randomly select signature type if configured
	if len(n.config.SignaturePackets) > 0 {
		sigType := n.config.SignaturePackets[randInt(len(n.config.SignaturePackets))]
		return n.generateSignaturePacket(size, sigType)
	}

	// Random junk
	return randomBytes(size)
}

// generateSignaturePacket generates a packet mimicking a specific protocol.
func (n *Noize) generateSignaturePacket(size int, sigType string) []byte {
	switch sigType {
	case "http":
		return n.generateHTTPPacket(size)
	case "https":
		return n.generateHTTPSPacket(size)
	case "dns":
		return n.generateDNSPacket(size)
	case "stun":
		return n.generateSTUNPacket(size)
	default:
		return randomBytes(size)
	}
}

// generateHTTPPacket generates a fake HTTP request packet.
func (n *Noize) generateHTTPPacket(size int) []byte {
	methods := []string{"GET", "POST", "HEAD", "OPTIONS"}
	paths := []string{"/", "/index.html", "/api/v1/data", "/static/js/app.js", "/css/style.css"}
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
	}

	method := methods[randInt(len(methods))]
	path := paths[randInt(len(paths))]
	ua := userAgents[randInt(len(userAgents))]

	httpReq := method + " " + path + " HTTP/1.1\r\n" +
		"Host: " + randomDomain() + "\r\n" +
		"User-Agent: " + ua + "\r\n" +
		"Accept: */*\r\n" +
		"Connection: keep-alive\r\n\r\n"

	if len(httpReq) < size {
		// Pad with random data
		httpReq += string(randomBytes(size - len(httpReq)))
	}

	return []byte(httpReq[:size])
}

// generateHTTPSPacket generates a fake HTTPS (TLS) packet.
func (n *Noize) generateHTTPSPacket(size int) []byte {
	// TLS record header: ContentType (1) + Version (2) + Length (2)
	// ContentType 22 = Handshake
	// Version 0x0303 = TLS 1.2
	pkt := make([]byte, size)
	pkt[0] = 0x16 // Handshake
	pkt[1] = 0x03
	pkt[2] = 0x03 // TLS 1.2

	// Random length
	if size > 5 {
		dataLen := size - 5
		pkt[3] = byte(dataLen >> 8)
		pkt[4] = byte(dataLen)
		// Fill with random data to look like encrypted traffic
		copy(pkt[5:], randomBytes(size-5))
	}

	return pkt
}

// generateDNSPacket generates a fake DNS packet.
func (n *Noize) generateDNSPacket(size int) []byte {
	pkt := make([]byte, size)

	// DNS Header
	// Transaction ID
	pkt[0] = byte(randInt(256))
	pkt[1] = byte(randInt(256))

	// Flags: Standard query
	pkt[2] = 0x01
	pkt[3] = 0x00

	// Questions: 1
	pkt[4] = 0x00
	pkt[5] = 0x01

	// Answer RRs: 0
	pkt[6] = 0x00
	pkt[7] = 0x00

	// Authority RRs: 0
	pkt[8] = 0x00
	pkt[9] = 0x00

	// Additional RRs: 0
	pkt[10] = 0x00
	pkt[11] = 0x00

	// Query section (encoded domain)
	if size > 12 {
		domain := randomDomain()
		query := encodeDNSDomain(domain)
		copy(pkt[12:], query)

		// Query type A
		offset := 12 + len(query)
		if offset+4 <= size {
			pkt[offset] = 0x00
			pkt[offset+1] = 0x01 // A record
			pkt[offset+2] = 0x00
			pkt[offset+3] = 0x01 // IN class
		}
	}

	return pkt
}

// generateSTUNPacket generates a fake STUN packet.
func (n *Noize) generateSTUNPacket(size int) []byte {
	pkt := make([]byte, size)

	// STUN Message Type: Binding Request (0x0001)
	pkt[0] = 0x00
	pkt[1] = 0x01

	// Message Length
	msgLen := size - 20
	pkt[2] = byte(msgLen >> 8)
	pkt[3] = byte(msgLen)

	// Magic Cookie
	pkt[4] = 0x21
	pkt[5] = 0x12
	pkt[6] = 0xA4
	pkt[7] = 0x42

	// Transaction ID (12 bytes)
	copy(pkt[8:20], randomBytes(12))

	// Attributes (random data)
	if size > 20 {
		copy(pkt[20:], randomBytes(size-20))
	}

	return pkt
}

// encodeDNSDomain encodes a domain name for DNS packets.
func encodeDNSDomain(domain string) []byte {
	parts := splitDomain(domain)
	result := make([]byte, 0)

	for _, part := range parts {
		result = append(result, byte(len(part)))
		result = append(result, []byte(part)...)
	}
	result = append(result, 0) // Terminator

	return result
}

func splitDomain(domain string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(domain); i++ {
		if domain[i] == '.' {
			if i > start {
				parts = append(parts, domain[start:i])
			}
			start = i + 1
		}
	}
	if start < len(domain) {
		parts = append(parts, domain[start:])
	}
	return parts
}

// randomDomain generates a random domain name.
func randomDomain() string {
	tlds := []string{"com", "net", "org", "io", "co", "app", "dev"}
	words := []string{"api", "cdn", "static", "media", "content", "data", "app", "web", "mail", "cloud"}

	word := words[randInt(len(words))]
	tld := tlds[randInt(len(tlds))]
	subdomain := randomString(8)

	return subdomain + "." + word + "." + tld
}

// randomString generates a random alphanumeric string.
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[randInt(len(charset))]
	}
	return string(result)
}

// randomBytes generates random bytes.
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// Fallback to simple PRNG
		for i := range b {
			b[i] = byte(randInt(256))
		}
	}
	return b
}

// randInt returns a random int in range [0, max).
func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}
