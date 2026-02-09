package kcpbase

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// BrutalController implements Hysteria2-style brutal congestion control.
// It sends at a fixed rate regardless of network conditions, suitable for
// high-bandwidth scenarios where traditional CC is too conservative.
type BrutalController struct {
	// Bandwidth in bytes per second
	bandwidthBps atomic.Int64

	// Pacing mode
	pacingMode atomic.Value // string

	// Statistics
	bytesSent     atomic.Uint64
	bytesReceived atomic.Uint64
	packetsSent   atomic.Uint64
	packetsRecv   atomic.Uint64

	// Rate limiting
	lastSendTime  atomic.Int64 // Unix nano
	tokens        atomic.Int64 // Token bucket for pacing

	mu sync.RWMutex
}

// NewBrutalController creates a new brutal congestion controller
func NewBrutalController(bandwidthMbps int, pacingMode string) *BrutalController {
	bc := &BrutalController{}
	bc.SetBandwidth(bandwidthMbps)
	bc.pacingMode.Store(pacingMode)
	return bc
}

// SetBandwidth sets the bandwidth in Mbps
func (bc *BrutalController) SetBandwidth(mbps int) {
	if mbps < 1 {
		mbps = 1
	}
	// Convert Mbps to bytes per second
	bps := int64(mbps) * 125000 // 1 Mbps = 125,000 bytes/second
	bc.bandwidthBps.Store(bps)
}

// GetBandwidth returns the current bandwidth in Mbps
func (bc *BrutalController) GetBandwidth() int {
	bps := bc.bandwidthBps.Load()
	return int(bps / 125000)
}

// SetPacingMode sets the pacing mode
func (bc *BrutalController) SetPacingMode(mode string) {
	bc.pacingMode.Store(mode)
}

// GetPacingMode returns the current pacing mode
func (bc *BrutalController) GetPacingMode() string {
	return bc.pacingMode.Load().(string)
}

// CanSend checks if we can send a packet of the given size
func (bc *BrutalController) CanSend(size int) bool {
	mode := bc.GetPacingMode()

	switch mode {
	case "aggressive":
		// No pacing in aggressive mode
		return true
	case "conservative":
		// Strict pacing in conservative mode
		return bc.checkTokenBucket(size)
	default: // "adaptive"
		// Adaptive pacing based on recent loss
		return bc.checkAdaptivePacing(size)
	}
}

// checkTokenBucket implements token bucket pacing
func (bc *BrutalController) checkTokenBucket(size int) bool {
	now := time.Now().UnixNano()
	last := bc.lastSendTime.Load()

	// Add tokens based on elapsed time
	elapsed := now - last
	if elapsed > 0 {
		bandwidth := bc.bandwidthBps.Load()
		tokensToAdd := (elapsed * bandwidth) / 1e9
		bc.tokens.Add(tokensToAdd)

		// Cap tokens at 1 second worth
		maxTokens := bandwidth
		for {
			current := bc.tokens.Load()
			if current <= maxTokens {
				break
			}
			if bc.tokens.CompareAndSwap(current, maxTokens) {
				break
			}
		}
	}

	// Try to consume tokens
	needed := int64(size)
	for {
		current := bc.tokens.Load()
		if current < needed {
			return false
		}
		if bc.tokens.CompareAndSwap(current, current-needed) {
			bc.lastSendTime.Store(now)
			return true
		}
	}
}

// checkAdaptivePacing implements adaptive pacing based on network conditions
func (bc *BrutalController) checkAdaptivePacing(size int) bool {
	// Start with token bucket
	if bc.checkTokenBucket(size) {
		return true
	}

	// If we don't have enough tokens, check if we should burst
	// Burst is allowed if we're under 50% of bandwidth in the last window
	stats := bc.GetStats()
	currentRate := stats.CurrentRateBps
	bandwidth := bc.bandwidthBps.Load()

	// Allow burst if we're under 50% of target
	if float64(currentRate) < float64(bandwidth)*0.5 {
		// Consume tokens even if negative (allow deficit)
		bc.tokens.Add(-int64(size))
		bc.lastSendTime.Store(time.Now().UnixNano())
		return true
	}

	return false
}

// WaitTime returns how long to wait before sending
func (bc *BrutalController) WaitTime(size int) time.Duration {
	if bc.CanSend(size) {
		return 0
	}

	bandwidth := bc.bandwidthBps.Load()
	if bandwidth == 0 {
		return 0
	}

	// Calculate time needed for enough tokens
	needed := int64(size)
	current := bc.tokens.Load()
	deficit := needed - current

	if deficit <= 0 {
		return 0
	}

	// Time = deficit / bandwidth
	nanos := (deficit * 1e9) / bandwidth
	return time.Duration(nanos)
}

// RecordSend records a sent packet
func (bc *BrutalController) RecordSend(size int) {
	bc.bytesSent.Add(uint64(size))
	bc.packetsSent.Add(1)
}

// RecordRecv records a received packet
func (bc *BrutalController) RecordRecv(size int) {
	bc.bytesReceived.Add(uint64(size))
	bc.packetsRecv.Add(1)
}

// GetStats returns brutal controller statistics
func (bc *BrutalController) GetStats() BrutalStats {
	return BrutalStats{
		BandwidthMbps: bc.GetBandwidth(),
		BytesSent:     bc.bytesSent.Load(),
		BytesReceived: bc.bytesReceived.Load(),
		PacketsSent:   bc.packetsSent.Load(),
		PacketsRecv:   bc.packetsRecv.Load(),
		CurrentTokens: bc.tokens.Load(),
	}
}

// BrutalStats contains brutal congestion control statistics
type BrutalStats struct {
	BandwidthMbps int
	BytesSent     uint64
	BytesReceived uint64
	PacketsSent   uint64
	PacketsRecv   uint64
	CurrentTokens int64
	CurrentRateBps float64
}

// CalculateWindowSize calculates the optimal window size for brutal CC
func CalculateWindowSize(bandwidthMbps int, rttMs float64) (sendWindow, recvWindow int) {
	// BDP = bandwidth * RTT
	// bandwidth in bytes/sec = Mbps * 125000
	// RTT in seconds = ms / 1000
	bdp := float64(bandwidthMbps) * 125000 * (rttMs / 1000.0)

	// Use 2x BDP for window size (allows for some buffering)
	window := int(bdp * 2 / 1350) // Convert to packet count (assuming 1350 MTU)

	if window < 64 {
		window = 64
	}
	if window > 65535 {
		window = 65535
	}

	return window, window
}

// BrutalPacer implements packet pacing for brutal congestion control
type BrutalPacer struct {
	bandwidthBps atomic.Int64
	interval     atomic.Int64 // nanoseconds between packets
	lastSend     atomic.Int64 // last send time
}

// NewBrutalPacer creates a new brutal pacer
func NewBrutalPacer(bandwidthMbps int) *BrutalPacer {
	bp := &BrutalPacer{}
	bp.SetBandwidth(bandwidthMbps)
	return bp
}

// SetBandwidth sets the bandwidth in Mbps
func (bp *BrutalPacer) SetBandwidth(mbps int) {
	if mbps < 1 {
		mbps = 1
	}
	bps := int64(mbps) * 125000
	bp.bandwidthBps.Store(bps)

	// Calculate interval for 1350-byte packets
	// interval = packet_size / bandwidth
	interval := (1350 * 1e9) / bps
	bp.interval.Store(interval)
}

// Pace applies pacing delay if needed
func (bp *BrutalPacer) Pace() {
	interval := bp.interval.Load()
	if interval <= 0 {
		return
	}

	now := time.Now().UnixNano()
	last := bp.lastSend.Load()

	// Calculate next send time
	next := last + interval

	if now < next {
		// Need to wait
		time.Sleep(time.Duration(next - now))
	}

	bp.lastSend.Store(time.Now().UnixNano())
}

// CanSend checks if we can send without pacing
func (bp *BrutalPacer) CanSend() bool {
	interval := bp.interval.Load()
	if interval <= 0 {
		return true
	}

	now := time.Now().UnixNano()
	last := bp.lastSend.Load()

	return now >= last+interval
}

// RateEstimator estimates the current sending rate
type RateEstimator struct {
	windowSize    time.Duration
	samples       []rateSample
	currentIndex  int
	mu            sync.RWMutex
}

type rateSample struct {
	timestamp time.Time
	bytes     int
}

// NewRateEstimator creates a new rate estimator
func NewRateEstimator(windowSize time.Duration) *RateEstimator {
	return &RateEstimator{
		windowSize: windowSize,
		samples:    make([]rateSample, 100),
	}
}

// AddSample adds a rate sample
func (re *RateEstimator) AddSample(bytes int) {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.samples[re.currentIndex] = rateSample{
		timestamp: time.Now(),
		bytes:     bytes,
	}
	re.currentIndex = (re.currentIndex + 1) % len(re.samples)
}

// GetRate returns the estimated rate in bytes per second
func (re *RateEstimator) GetRate() float64 {
	re.mu.RLock()
	defer re.mu.RUnlock()

	cutoff := time.Now().Add(-re.windowSize)
	var totalBytes int
	var count int

	for _, sample := range re.samples {
		if sample.timestamp.IsZero() || sample.timestamp.Before(cutoff) {
			continue
		}
		totalBytes += sample.bytes
		count++
	}

	if count == 0 {
		return 0
	}

	return float64(totalBytes) / re.windowSize.Seconds()
}

// CalculateBrutalParams calculates optimal parameters for brutal congestion control
func CalculateBrutalParams(bandwidthMbps int, rttMs float64, lossRate float64) BrutalParams {
	// Calculate BDP
	bdp := float64(bandwidthMbps) * 125000 * (rttMs / 1000.0)

	// Adjust for loss if significant
	if lossRate > 0.001 {
		// Increase window to compensate for loss
		bdp *= (1 + lossRate*10)
	}

	// Calculate window sizes
	sendWindow, recvWindow := CalculateWindowSize(bandwidthMbps, rttMs)

	// Calculate pacing interval
	packetSize := 1350
	bps := float64(bandwidthMbps) * 125000
	pacingInterval := float64(packetSize) / bps * 1e6 // microseconds

	return BrutalParams{
		SendWindow:     sendWindow,
		RecvWindow:     recvWindow,
		PacingInterval: time.Duration(pacingInterval) * time.Microsecond,
		MaxBurst:       int(math.Min(float64(sendWindow)/4, 64)),
		MinInterval:    time.Duration(pacingInterval/2) * time.Microsecond,
	}
}

// BrutalParams contains calculated brutal congestion control parameters
type BrutalParams struct {
	SendWindow     int
	RecvWindow     int
	PacingInterval time.Duration
	MaxBurst       int
	MinInterval    time.Duration
}
