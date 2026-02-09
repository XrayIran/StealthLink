package tlsutil

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

// EnhancedFragmentConfig extends FragmentConfig with additional strategies.
type EnhancedFragmentConfig struct {
	FragmentConfig `yaml:",inline"`

	// Adaptive enables adaptive fragmentation based on success rates
	Adaptive bool `yaml:"adaptive"`

	// AdaptiveInterval is how often to evaluate and adjust strategy
	AdaptiveInterval time.Duration `yaml:"adaptive_interval"`

	// BurstFragmentation sends fragments in bursts with gaps
	BurstFragmentation bool `yaml:"burst_fragmentation"`

	// BurstSize is the number of fragments per burst
	BurstSize int `yaml:"burst_size"`

	// BurstGap is the delay between bursts
	BurstGap time.Duration `yaml:"burst_gap"`

	// RandomizeTiming adds random delays between individual fragments
	RandomizeTiming bool `yaml:"randomize_timing"`

	// TimingVariance is the maximum random variance added to delays
	TimingVariance time.Duration `yaml:"timing_variance"`

	// RecordSplitting enables TLS record-layer splitting
	RecordSplitting bool `yaml:"record_splitting"`

	// MinRecordSize is the minimum TLS record size when splitting
	MinRecordSize int `yaml:"min_record_size"`
}

// ApplyDefaults sets default values.
func (c *EnhancedFragmentConfig) ApplyDefaults() {
	c.FragmentConfig.ApplyDefaults()

	if c.AdaptiveInterval <= 0 {
		c.AdaptiveInterval = 30 * time.Second
	}
	if c.BurstSize <= 0 {
		c.BurstSize = 5
	}
	if c.BurstGap <= 0 {
		c.BurstGap = 50 * time.Millisecond
	}
	if c.TimingVariance <= 0 {
		c.TimingVariance = 5 * time.Millisecond
	}
	if c.MinRecordSize <= 0 {
		c.MinRecordSize = 32
	}
}

// AdaptiveFragmenter implements adaptive fragmentation that learns
// the most effective strategy based on connection success rates.
type AdaptiveFragmenter struct {
	config     EnhancedFragmentConfig
	strategies []FragmentStrategy
	mu         sync.RWMutex
	stats      map[string]*StrategyStats
	current    string
}

// FragmentStrategy defines a fragmentation approach.
type FragmentStrategy struct {
	Name        string
	Mode        FragmentMode
	Size        int
	NumFragments int
	Sleep       time.Duration
	Randomize   bool
}

// StrategyStats tracks success/failure for a strategy.
type StrategyStats struct {
	Success int
	Failure int
	LastUsed time.Time
}

// SuccessRate returns the success rate for this strategy.
func (s *StrategyStats) SuccessRate() float64 {
	total := s.Success + s.Failure
	if total == 0 {
		return 0.5 // Neutral default
	}
	return float64(s.Success) / float64(total)
}

// NewAdaptiveFragmenter creates a new adaptive fragmenter.
func NewAdaptiveFragmenter(config EnhancedFragmentConfig) *AdaptiveFragmenter {
	config.ApplyDefaults()

	f := &AdaptiveFragmenter{
		config:  config,
		stats:   make(map[string]*StrategyStats),
		current: "default",
	}

	// Initialize with diverse strategies
	f.strategies = []FragmentStrategy{
		{"fixed-small", FragmentModeFixed, 16, 100, 5 * time.Millisecond, false},
		{"fixed-medium", FragmentModeFixed, 32, 87, 8 * time.Millisecond, false},
		{"fixed-large", FragmentModeFixed, 64, 50, 10 * time.Millisecond, false},
		{"random-small", FragmentModeRandom, 32, 100, 8 * time.Millisecond, true},
		{"random-medium", FragmentModeRandom, 48, 75, 12 * time.Millisecond, true},
		{"sni-aware", FragmentModeSNIAware, 32, 87, 8 * time.Millisecond, false},
		{"record-split", FragmentModeRecord, 64, 50, 10 * time.Millisecond, false},
	}

	// Initialize stats for each strategy
	for _, s := range f.strategies {
		f.stats[s.Name] = &StrategyStats{}
	}

	// Start adaptive evaluator
	if config.Adaptive {
		go f.adaptLoop()
	}

	return f
}

// GetStrategy returns the current best strategy.
func (f *AdaptiveFragmenter) GetStrategy() FragmentStrategy {
	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.config.Adaptive {
		return f.strategies[1] // fixed-medium default
	}

	// Return current best strategy
	for _, s := range f.strategies {
		if s.Name == f.current {
			return s
		}
	}

	return f.strategies[1]
}

// ReportSuccess reports a successful connection using current strategy.
func (f *AdaptiveFragmenter) ReportSuccess() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if stats, ok := f.stats[f.current]; ok {
		stats.Success++
		stats.LastUsed = time.Now()
	}
}

// ReportFailure reports a failed connection using current strategy.
func (f *AdaptiveFragmenter) ReportFailure() {
	f.mu.Lock()
	defer f.mu.Unlock()

	if stats, ok := f.stats[f.current]; ok {
		stats.Failure++
		stats.LastUsed = time.Now()
	}
}

func (f *AdaptiveFragmenter) adaptLoop() {
	ticker := time.NewTicker(f.config.AdaptiveInterval)
	defer ticker.Stop()

	for range ticker.C {
		f.evaluateAndAdapt()
	}
}

func (f *AdaptiveFragmenter) evaluateAndAdapt() {
	f.mu.Lock()
	defer f.mu.Unlock()

	bestStrategy := f.current
	bestRate := 0.0

	// Find strategy with best success rate
	for name, stats := range f.stats {
		rate := stats.SuccessRate()
		if rate > bestRate {
			bestRate = rate
			bestStrategy = name
		}
	}

	// Only switch if we have meaningful data
	totalAttempts := 0
	for _, stats := range f.stats {
		totalAttempts += stats.Success + stats.Failure
	}

	if totalAttempts >= 10 && bestStrategy != f.current {
		f.current = bestStrategy
	}
}

// EnhancedFragmentedConn wraps a connection with enhanced fragmentation.
type EnhancedFragmentedConn struct {
	net.Conn
	config    EnhancedFragmentConfig
	adaptive  *AdaptiveFragmenter
	handshakeDone bool
	mu        sync.Mutex
}

// NewEnhancedFragmentedConn creates a new enhanced fragmented connection.
func NewEnhancedFragmentedConn(conn net.Conn, config EnhancedFragmentConfig) *EnhancedFragmentedConn {
	config.ApplyDefaults()

	efc := &EnhancedFragmentedConn{
		Conn:   conn,
		config: config,
	}

	if config.Adaptive {
		efc.adaptive = NewAdaptiveFragmenter(config)
	}

	return efc
}

// Write implements fragmentation logic.
func (c *EnhancedFragmentedConn) Write(p []byte) (int, error) {
	if c.handshakeDone {
		return c.Conn.Write(p)
	}

	// Check if this is a TLS Client Hello
	if len(p) >= 6 && p[0] == 0x16 {
		return c.writeEnhancedFragmented(p)
	}

	return c.Conn.Write(p)
}

func (c *EnhancedFragmentedConn) writeEnhancedFragmented(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	totalLen := len(p)

	// Get fragmentation strategy
	var fragConfig FragmentConfig
	if c.adaptive != nil {
		strategy := c.adaptive.GetStrategy()
		fragConfig = FragmentConfig{
			Enabled:      true,
			Size:         strategy.Size,
			NumFragments: strategy.NumFragments,
			FragmentSleep: strategy.Sleep,
			Mode:         strategy.Mode,
			Randomize:    strategy.Randomize,
		}
	} else {
		fragConfig = c.config.FragmentConfig
	}

	// Create a temporary FragmentedConn to reuse existing logic
	tempConn := &FragmentedConn{
		Conn:   c.Conn,
		config: fragConfig,
	}

	// If burst fragmentation is enabled, use burst strategy
	if c.config.BurstFragmentation {
		err := c.writeBursts(p, fragConfig)
		if err != nil {
			if c.adaptive != nil {
				c.adaptive.ReportFailure()
			}
			return 0, err
		}
		c.handshakeDone = true
		if c.adaptive != nil {
			c.adaptive.ReportSuccess()
		}
		return totalLen, nil
	}

	// Use standard fragmentation with optional timing randomization
	sniPos := findSNIPosition(p)
	fragSizes := tempConn.calculateFragments(totalLen, sniPos)

	written := 0
	for i, fragSize := range fragSizes {
		end := written + fragSize
		if end > totalLen {
			end = totalLen
		}

		frag := p[written:end]
		if _, err := c.Conn.Write(frag); err != nil {
			if c.adaptive != nil {
				c.adaptive.ReportFailure()
			}
			return written, err
		}
		written = end

		// Apply delay between fragments
		if i < len(fragSizes)-1 {
			c.applyEnhancedDelay(i, len(fragSizes))
		}
	}

	c.handshakeDone = true
	if c.adaptive != nil {
		c.adaptive.ReportSuccess()
	}
	return totalLen, nil
}

func (c *EnhancedFragmentedConn) writeBursts(p []byte, config FragmentConfig) error {
	sniPos := findSNIPosition(p)

	tempConn := &FragmentedConn{
		Conn:   c.Conn,
		config: config,
	}

	fragSizes := tempConn.calculateFragments(len(p), sniPos)

	written := 0
	burstCount := 0

	for i, fragSize := range fragSizes {
		end := written + fragSize
		if end > len(p) {
			end = len(p)
		}

		frag := p[written:end]
		if _, err := c.Conn.Write(frag); err != nil {
			return err
		}
		written = end
		burstCount++

		// Check if we need a burst gap
		if burstCount >= c.config.BurstSize && i < len(fragSizes)-1 {
			time.Sleep(c.config.BurstGap)
			burstCount = 0
		} else if i < len(fragSizes)-1 {
			c.applyEnhancedDelay(i, len(fragSizes))
		}
	}

	return nil
}

func (c *EnhancedFragmentedConn) applyEnhancedDelay(fragIndex, totalFrags int) {
	baseDelay := c.config.FragmentSleep
	if baseDelay == 0 {
		baseDelay = c.config.DelayMin
		if c.config.DelayMax > c.config.DelayMin {
			baseDelay += time.Duration(int64(c.config.DelayMax-c.config.DelayMin)) / 2
		}
	}

	if c.config.RandomizeTiming {
		// Add random variance
		variance := time.Duration(0)
		if c.config.TimingVariance > 0 {
			variance = time.Duration(int64(c.config.TimingVariance) * (int64(fragIndex%3) - 1) / 2)
		}
		baseDelay += variance
		if baseDelay < 0 {
			baseDelay = 0
		}
	}

	if baseDelay > 0 {
		time.Sleep(baseDelay)
	}
}

// RecordFragmentedConn implements TLS record-layer fragmentation.
type RecordFragmentedConn struct {
	net.Conn
	minRecordSize int
	handshakeDone bool
}

// NewRecordFragmentedConn creates a connection with record-layer fragmentation.
func NewRecordFragmentedConn(conn net.Conn, minRecordSize int) *RecordFragmentedConn {
	if minRecordSize <= 0 {
		minRecordSize = 32
	}
	return &RecordFragmentedConn{
		Conn:          conn,
		minRecordSize: minRecordSize,
	}
}

// Write fragments TLS records at the record layer.
func (c *RecordFragmentedConn) Write(p []byte) (int, error) {
	if c.handshakeDone || len(p) < 5 || p[0] != 0x16 {
		return c.Conn.Write(p)
	}

	// Parse TLS record
	contentType := p[0]
	version := binary.BigEndian.Uint16(p[1:3])
	recordLen := int(binary.BigEndian.Uint16(p[3:5]))

	if len(p) < 5+recordLen {
		// Incomplete record, write as-is
		return c.Conn.Write(p)
	}

	recordData := p[5 : 5+recordLen]

	// If record is small enough, write as-is
	if recordLen <= c.minRecordSize*2 {
		c.handshakeDone = true
		return c.Conn.Write(p)
	}

	// Fragment into multiple TLS records
	totalWritten := 0
	for offset := 0; offset < recordLen; {
		// Vary fragment sizes to avoid fingerprinting
		fragSize := c.minRecordSize + (offset % c.minRecordSize)
		if fragSize > recordLen-offset {
			fragSize = recordLen - offset
		}

		frag := make([]byte, 5+fragSize)
		frag[0] = contentType
		binary.BigEndian.PutUint16(frag[1:3], version)
		binary.BigEndian.PutUint16(frag[3:5], uint16(fragSize))
		copy(frag[5:], recordData[offset:offset+fragSize])

		n, err := c.Conn.Write(frag)
		if err != nil {
			return totalWritten, err
		}
		totalWritten += n - 5
		offset += fragSize

		// Small delay between records
		if offset < recordLen {
			time.Sleep(time.Millisecond)
		}
	}

	c.handshakeDone = true
	return 5 + totalWritten, nil
}

// DialWithEnhancedFragmentation dials with enhanced fragmentation support.
func DialWithEnhancedFragmentation(network, addr string, tlsConfig *tls.Config, fragConfig EnhancedFragmentConfig) (net.Conn, error) {
	fragConfig.ApplyDefaults()

	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}

	// Wrap with record-layer fragmentation if enabled
	if fragConfig.RecordSplitting {
		conn = NewRecordFragmentedConn(conn, fragConfig.MinRecordSize)
	}

	// Wrap with enhanced fragmentation
	fragConn := NewEnhancedFragmentedConn(conn, fragConfig)

	// Perform TLS handshake
	tlsConn := tls.Client(fragConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		conn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Stats returns fragmentation statistics if adaptive mode is enabled.
func (c *EnhancedFragmentedConn) Stats() map[string]*StrategyStats {
	if c.adaptive == nil {
		return nil
	}
	c.adaptive.mu.RLock()
	defer c.adaptive.mu.RUnlock()

	// Return copy of stats
	stats := make(map[string]*StrategyStats)
	for k, v := range c.adaptive.stats {
		stats[k] = &StrategyStats{
			Success:  v.Success,
			Failure:  v.Failure,
			LastUsed: v.LastUsed,
		}
	}
	return stats
}

// CurrentStrategy returns the name of the currently active strategy.
func (c *EnhancedFragmentedConn) CurrentStrategy() string {
	if c.adaptive == nil {
		return "fixed"
	}
	c.adaptive.mu.RLock()
	defer c.adaptive.mu.RUnlock()
	return c.adaptive.current
}
