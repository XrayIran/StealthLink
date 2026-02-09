// Package padding provides advanced padding techniques for anti-censorship.
package padding

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"
)

// XPaddingMethod defines the padding method to use.
type XPaddingMethod string

const (
	// MethodRandom uses random bytes (original behavior)
	MethodRandom XPaddingMethod = "random"
	// MethodRepeatX repeats a character X times (HPACK-friendly)
	MethodRepeatX XPaddingMethod = "repeat-x"
	// MethodTokenish uses base62 token-like strings (HPACK-friendly)
	MethodTokenish XPaddingMethod = "tokenish"
	// MethodSpaces uses space characters (highly compressible)
	MethodSpaces XPaddingMethod = "spaces"
	// MethodZero uses null bytes (highly compressible)
	MethodZero XPaddingMethod = "zero"
	// MethodTimestamp uses timestamp-based padding (dynamic)
	MethodTimestamp XPaddingMethod = "timestamp"
	// MethodUUID uses UUID-like strings (looks like real tokens)
	MethodUUID XPaddingMethod = "uuid"
	// MethodHex uses hex-encoded random data
	MethodHex XPaddingMethod = "hex"
	// MethodBase64 uses base64-encoded random data
	MethodBase64 XPaddingMethod = "base64"
)

// XPaddingConfig configures XPadding behavior.
type XPaddingConfig struct {
	Enabled   bool           `yaml:"enabled"`
	Min       int            `yaml:"min"`       // Minimum padding bytes
	Max       int            `yaml:"max"`       // Maximum padding bytes
	Method    XPaddingMethod `yaml:"method"`    // Padding method
	Placement Placement      `yaml:"placement"` // Where to place padding
}

// Placement defines where padding can be inserted.
type Placement string

const (
	PlaceHeader  Placement = "header"   // X-Pad header (default)
	PlaceCookie  Placement = "cookie"   // Cookie header
	PlaceReferer Placement = "referer"  // Referer header
	PlaceQuery   Placement = "query"    // Query parameter
	PlaceRandom  Placement = "random"   // Random placement
)

// ApplyDefaults sets default values.
func (c *XPaddingConfig) ApplyDefaults() {
	if c.Min < 0 {
		c.Min = 0
	}
	if c.Max <= 0 {
		c.Max = 100
	}
	if c.Max < c.Min {
		c.Max = c.Min
	}
	if c.Method == "" {
		c.Method = MethodRandom
	}
	if c.Placement == "" {
		c.Placement = PlaceHeader
	}
}

// Generate creates padding data based on configuration.
func (c *XPaddingConfig) Generate() []byte {
	c.ApplyDefaults()

	size := c.Min
	if c.Max > c.Min {
		size = c.Min + rand.Intn(c.Max-c.Min+1)
	}
	if size <= 0 {
		return nil
	}

	switch c.Method {
	case MethodRepeatX:
		return generateRepeatX(size)
	case MethodTokenish:
		return generateTokenish(size)
	case MethodSpaces:
		return generateSpaces(size)
	case MethodZero:
		return generateZeros(size)
	case MethodTimestamp:
		return generateTimestamp(size)
	case MethodUUID:
		return generateUUIDLike(size)
	case MethodHex:
		return generateHex(size)
	case MethodBase64:
		return generateBase64(size)
	default:
		return generateRandom(size)
	}
}

// GenerateString creates a string suitable for HTTP headers.
func (c *XPaddingConfig) GenerateString() string {
	data := c.Generate()
	if len(data) == 0 {
		return ""
	}

	// For HPACK-aware methods, return as-is or base64 encode
	switch c.Method {
	case MethodTokenish:
		// Tokenish is already header-safe
		return string(data)
	case MethodRepeatX, MethodSpaces:
		// These are header-safe but let's base64 for consistency
		return base64.StdEncoding.EncodeToString(data)
	default:
		return base64.StdEncoding.EncodeToString(data)
	}
}

// GetHeaderName returns the header name for the configured placement.
func (c *XPaddingConfig) GetHeaderName() string {
	switch c.Placement {
	case PlaceCookie:
		return "Cookie"
	case PlaceReferer:
		return "Referer"
	default:
		return "X-Pad"
	}
}

// GetHeaderValue returns the full header value including name if needed.
func (c *XPaddingConfig) GetHeaderValue() string {
	padding := c.GenerateString()
	if padding == "" {
		return ""
	}

	switch c.Placement {
	case PlaceCookie:
		// Return as cookie format: _pad=<value>
		return "_pad=" + padding
	case PlaceReferer:
		// Return as referer with padding path
		return "https://example.com/" + padding
	default:
		return padding
	}
}

// generateRandom creates random bytes.
func generateRandom(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

// generateRepeatX creates a repeated character pattern.
// This is HPACK-friendly as it compresses extremely well.
func generateRepeatX(n int) []byte {
	// Use 'X' as the repeated character
	b := make([]byte, n)
	for i := range b {
		b[i] = 'X'
	}
	return b
}

// generateTokenish creates base62 token-like strings.
// These look like real tokens but are random, and are HPACK-friendly
// due to repeated character patterns.
func generateTokenish(n int) []byte {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[rand.Intn(len(chars))]
	}
	return b
}

// generateSpaces creates space characters.
// Highly compressible with HPACK.
func generateSpaces(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = ' '
	}
	return b
}

// generateZeros creates null bytes.
// Highly compressible with HPACK/QPACK.
func generateZeros(n int) []byte {
	b := make([]byte, n)
	// Already zero-initialized
	return b
}

// generateTimestamp creates timestamp-based padding.
// Creates dynamic padding that changes with each request.
func generateTimestamp(n int) []byte {
	if n < 20 {
		return generateTokenish(n)
	}

	timestamp := time.Now().UnixNano()
	timestampStr := fmt.Sprintf("%d", timestamp)

	b := make([]byte, n)
	copy(b, timestampStr)

	// Fill remainder with random data
	for i := len(timestampStr); i < n; i++ {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

// generateUUIDLike creates UUID-like strings.
// Looks like real UUIDs: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
func generateUUIDLike(n int) []byte {
	if n < 36 {
		// Return shortened version
		return generateTokenish(n)
	}

	// Generate a full UUID-like string
	uuid := make([]byte, 36)
	hexChars := "0123456789abcdef"

	for i := 0; i < 36; i++ {
		switch i {
		case 8, 13, 18, 23:
			uuid[i] = '-'
		default:
			uuid[i] = hexChars[rand.Intn(len(hexChars))]
		}
	}

	if n <= 36 {
		return uuid[:n]
	}

	// Extend with additional random data
	b := make([]byte, n)
	copy(b, uuid)
	for i := 36; i < n; i++ {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

// generateHex creates hex-encoded random data.
func generateHex(n int) []byte {
	rawSize := (n + 1) / 2
	raw := generateRandom(rawSize)
	encoded := make([]byte, n)
	hex.Encode(encoded, raw)
	return encoded[:n]
}

// generateBase64 creates base64-encoded random data.
func generateBase64(n int) []byte {
	rawSize := n * 3 / 4
	if rawSize < 1 {
		rawSize = 1
	}
	raw := generateRandom(rawSize)
	encoded := base64.StdEncoding.EncodeToString(raw)
	if len(encoded) > n {
		return []byte(encoded[:n])
	}
	return []byte(encoded)
}

// MultiPadding applies padding to multiple placements.
type MultiPadding struct {
	Configs map[Placement]*XPaddingConfig
}

// NewMultiPadding creates a new multi-placement padding config.
func NewMultiPadding() *MultiPadding {
	return &MultiPadding{
		Configs: make(map[Placement]*XPaddingConfig),
	}
}

// Add adds a padding config for a specific placement.
func (m *MultiPadding) Add(placement Placement, config *XPaddingConfig) {
	m.Configs[placement] = config
}

// GenerateHeaders generates all padding headers.
func (m *MultiPadding) GenerateHeaders() map[string]string {
	headers := make(map[string]string)

	for placement, config := range m.Configs {
		if !config.Enabled {
			continue
		}

		value := config.GetHeaderValue()
		if value == "" {
			continue
		}

		var name string
		switch placement {
		case PlaceCookie:
			name = "Cookie"
		case PlaceReferer:
			name = "Referer"
		default:
			name = "X-Pad"
		}

		// Handle multiple cookies
		if existing, ok := headers[name]; ok && name == "Cookie" {
			headers[name] = existing + "; " + value
		} else {
			headers[name] = value
		}
	}

	return headers
}

// QueryPadding adds padding as query parameters.
type QueryPadding struct {
	ParamName string
	Min       int
	Max       int
}

// Apply adds padding to a URL.
func (q *QueryPadding) Apply(url string) string {
	if q.Min <= 0 && q.Max <= 0 {
		return url
	}

	size := q.Min
	if q.Max > q.Min {
		size = q.Min + rand.Intn(q.Max-q.Min+1)
	}
	if size <= 0 {
		return url
	}

	param := q.ParamName
	if param == "" {
		param = "_p"
	}

	padding := generateTokenish(size)
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}

	return url + separator + param + "=" + string(padding)
}

// HPACKOptimized returns padding optimized for HPACK compression.
// This creates padding that will be heavily compressed by HPACK
// while still providing size obfuscation at the TLS/TCP layer.
func HPACKOptimized(min, max int) *XPaddingConfig {
	return &XPaddingConfig{
		Enabled: true,
		Min:     min,
		Max:     max,
		Method:  MethodRepeatX,
	}
}

// SizeOptimized returns padding optimized for size obfuscation.
// This creates padding that appears random to evade size-based detection.
func SizeOptimized(min, max int) *XPaddingConfig {
	return &XPaddingConfig{
		Enabled: true,
		Min:     min,
		Max:     max,
		Method:  MethodTokenish,
	}
}

// DynamicPaddingManager manages rotating padding strategies.
// This makes padding patterns harder to fingerprint over time.
type DynamicPaddingManager struct {
	mu       sync.RWMutex
	methods  []XPaddingMethod
	current  int
	config   XPaddingConfig
	interval time.Duration
	stopCh   chan struct{}
}

// NewDynamicPaddingManager creates a padding manager that rotates methods.
func NewDynamicPaddingManager(min, max int, interval time.Duration) *DynamicPaddingManager {
	if interval <= 0 {
		interval = 5 * time.Minute
	}

	m := &DynamicPaddingManager{
		methods: []XPaddingMethod{
			MethodRepeatX,
			MethodTokenish,
			MethodSpaces,
			MethodZero,
			MethodUUID,
			MethodHex,
		},
		config: XPaddingConfig{
			Enabled: true,
			Min:     min,
			Max:     max,
		},
		interval: interval,
		stopCh:   make(chan struct{}),
	}

	// Start rotation goroutine
	go m.rotate()
	return m
}

// rotate periodically changes the padding method.
func (m *DynamicPaddingManager) rotate() {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.mu.Lock()
			m.current = (m.current + 1) % len(m.methods)
			m.config.Method = m.methods[m.current]
			m.mu.Unlock()
		case <-m.stopCh:
			return
		}
	}
}

// GetConfig returns the current padding configuration.
func (m *DynamicPaddingManager) GetConfig() XPaddingConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// Generate creates padding using the current method.
func (m *DynamicPaddingManager) Generate() []byte {
	config := m.GetConfig()
	return config.Generate()
}

// Stop stops the rotation goroutine.
func (m *DynamicPaddingManager) Stop() {
	close(m.stopCh)
}

// AdaptivePadding adjusts padding based on traffic patterns.
type AdaptivePadding struct {
	mu          sync.RWMutex
	baseConfig  XPaddingConfig
	trafficHist []int
	histSize    int
	maxPadding  int
}

// NewAdaptivePadding creates padding that adapts to traffic patterns.
func NewAdaptivePadding(baseMin, baseMax, maxPadding int) *AdaptivePadding {
	return &AdaptivePadding{
		baseConfig: XPaddingConfig{
			Enabled: true,
			Min:     baseMin,
			Max:     baseMax,
			Method:  MethodTokenish,
		},
		histSize:   100,
		maxPadding: maxPadding,
	}
}

// RecordTraffic records the size of outgoing traffic for adaptation.
func (a *AdaptivePadding) RecordTraffic(size int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.trafficHist = append(a.trafficHist, size)
	if len(a.trafficHist) > a.histSize {
		a.trafficHist = a.trafficHist[len(a.trafficHist)-a.histSize:]
	}
}

// GetConfig returns the adaptive configuration.
func (a *AdaptivePadding) GetConfig() XPaddingConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if len(a.trafficHist) == 0 {
		return a.baseConfig
	}

	// Calculate average traffic size
	sum := 0
	for _, size := range a.trafficHist {
		sum += size
	}
	avg := sum / len(a.trafficHist)

	// Adjust padding range based on traffic patterns
	config := a.baseConfig
	config.Max = avg / 4 // Padding up to 25% of average traffic
	if config.Max > a.maxPadding {
		config.Max = a.maxPadding
	}
	if config.Max < config.Min {
		config.Max = config.Min + 10
	}

	return config
}

// Generate creates adaptive padding.
func (a *AdaptivePadding) Generate() []byte {
	config := a.GetConfig()
	return config.Generate()
}
