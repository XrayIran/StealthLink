package kcpmux

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go/v5"
)

// BrutalCongestionControl implements Hysteria-style Brutal congestion control.
// It uses a rate-based approach with the formula:
// cwnd = bps * rtt * 2 / ackRate
//
// This maximizes throughput in bandwidth-constrained environments.
type BrutalCongestionControl struct {
	bandwidthBps int64  // Target bandwidth in bytes per second
	rttMs        int64  // Current RTT in milliseconds
	ackRate      uint64 // ACK rate (per 5-second window)

	// Congestion window
	cwnd     uint32
	cwndMu   sync.RWMutex

	// Tracking
	lastAckTime   time.Time
	ackCount      uint64
	windowStart   time.Time

	// EWMA RTT
	smoothRtt     float64
	rttVariance   float64

	// Control
	enabled       atomic.Bool
	stopCh        chan struct{}
}

// NewBrutalCC creates a new Brutal congestion control.
func NewBrutalCC(bandwidthMbps int) *BrutalCongestionControl {
	if bandwidthMbps <= 0 {
		bandwidthMbps = 100 // Default 100 Mbps
	}

	cc := &BrutalCongestionControl{
		bandwidthBps: int64(bandwidthMbps) * 1024 * 1024 / 8,
		rttMs:        50,   // Initial RTT estimate
		cwnd:         8192, // Initial cwnd
		smoothRtt:    50.0,
		rttVariance:  10.0,
		windowStart:  time.Now(),
		lastAckTime:  time.Now(),
		stopCh:       make(chan struct{}),
	}
	cc.enabled.Store(true)

	// Start background adjustment
	go cc.adjustmentLoop()

	return cc
}

// adjustmentLoop periodically adjusts the congestion window.
func (cc *BrutalCongestionControl) adjustmentLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-cc.stopCh:
			return
		case <-ticker.C:
			cc.adjust()
		}
	}
}

// adjust updates the congestion window based on current conditions.
func (cc *BrutalCongestionControl) adjust() {
	if !cc.enabled.Load() {
		return
	}

	rtt := float64(atomic.LoadInt64(&cc.rttMs)) / 1000.0 // Convert to seconds
	if rtt <= 0 {
		rtt = 0.05 // Minimum 50ms
	}

	bps := float64(atomic.LoadInt64(&cc.bandwidthBps))
	ackRate := float64(atomic.LoadUint64(&cc.ackRate))
	if ackRate < 1 {
		ackRate = 1
	}

	// Brutal formula: cwnd = bps * rtt * 2 / ackRate
	// This gives us a window size that targets the specified bandwidth
	newCwnd := bps * rtt * 2.0 / ackRate

	// Clamp to reasonable bounds
	minCwnd := 4096.0
	maxCwnd := float64(cc.bandwidthBps) * 0.5 // Max 500ms worth of data

	if newCwnd < minCwnd {
		newCwnd = minCwnd
	}
	if newCwnd > maxCwnd {
		newCwnd = maxCwnd
	}

	cc.cwndMu.Lock()
	cc.cwnd = uint32(newCwnd)
	cc.cwndMu.Unlock()

	// Reset ACK rate counter every 5 seconds
	if time.Since(cc.windowStart) > 5*time.Second {
		atomic.StoreUint64(&cc.ackRate, 1)
		cc.windowStart = time.Now()
	}
}

// OnACK is called when an ACK is received.
func (cc *BrutalCongestionControl) OnACK(rtt time.Duration) {
	if !cc.enabled.Load() {
		return
	}

	// Update RTT
	rttMs := rtt.Milliseconds()
	atomic.StoreInt64(&cc.rttMs, rttMs)

	// Update EWMA RTT
	alpha := 0.125
	beta := 0.25

	cc.cwndMu.Lock()
	delta := float64(rttMs) - cc.smoothRtt
	cc.smoothRtt += alpha * delta
	cc.rttVariance += beta * (math.Abs(delta) - cc.rttVariance)
	cc.cwndMu.Unlock()

	// Increment ACK counter
	atomic.AddUint64(&cc.ackRate, 1)

	cc.lastAckTime = time.Now()
}

// GetCWND returns the current congestion window.
func (cc *BrutalCongestionControl) GetCWND() uint32 {
	cc.cwndMu.RLock()
	defer cc.cwndMu.RUnlock()
	return cc.cwnd
}

// GetBandwidth returns the target bandwidth.
func (cc *BrutalCongestionControl) GetBandwidth() int64 {
	return atomic.LoadInt64(&cc.bandwidthBps)
}

// SetBandwidth updates the target bandwidth.
func (cc *BrutalCongestionControl) SetBandwidth(bandwidthMbps int) {
	if bandwidthMbps > 0 {
		atomic.StoreInt64(&cc.bandwidthBps, int64(bandwidthMbps)*1024*1024/8)
	}
}

// Stop stops the congestion control.
func (cc *BrutalCongestionControl) Stop() {
	if cc.enabled.CompareAndSwap(true, false) {
		close(cc.stopCh)
	}
}

// IsEnabled returns true if Brutal CC is enabled.
func (cc *BrutalCongestionControl) IsEnabled() bool {
	return cc.enabled.Load()
}

// GetStats returns current statistics.
func (cc *BrutalCongestionControl) GetStats() map[string]interface{} {
	cc.cwndMu.RLock()
	defer cc.cwndMu.RUnlock()

	return map[string]interface{}{
		"cwnd":           cc.cwnd,
		"rtt_ms":         atomic.LoadInt64(&cc.rttMs),
		"smooth_rtt_ms":  cc.smoothRtt,
		"rtt_variance":   cc.rttVariance,
		"bandwidth_bps":  atomic.LoadInt64(&cc.bandwidthBps),
		"ack_rate":       atomic.LoadUint64(&cc.ackRate),
		"enabled":        cc.enabled.Load(),
	}
}

// BrutalKCP wraps a KCP connection with Brutal congestion control.
type BrutalKCP struct {
	*kcp.UDPSession
	cc *BrutalCongestionControl
}

// NewBrutalKCP creates a new KCP connection with Brutal CC.
func NewBrutalKCP(conn *kcp.UDPSession, bandwidthMbps int) *BrutalKCP {
	return &BrutalKCP{
		UDPSession: conn,
		cc:         NewBrutalCC(bandwidthMbps),
	}
}

// SetMtu sets the MTU with Brutal CC considerations.
func (b *BrutalKCP) SetMtu(mtu int) bool {
	// Ensure MTU allows for target bandwidth
	minMtu := 576 // Minimum recommended MTU
	if mtu < minMtu {
		mtu = minMtu
	}
	return b.UDPSession.SetMtu(mtu)
}

// SetWindowSize sets the window size based on Brutal CC.
func (b *BrutalKCP) SetWindowSize(sndwnd, rcvwnd int) {
	// Use Brutal's calculated cwnd if enabled
	if b.cc.IsEnabled() {
		cwnd := int(b.cc.GetCWND())
		if sndwnd > cwnd {
			sndwnd = cwnd
		}
	}
	b.UDPSession.SetWindowSize(sndwnd, rcvwnd)
}

// GetStats returns Brutal CC statistics.
func (b *BrutalKCP) GetStats() map[string]interface{} {
	return b.cc.GetStats()
}

// Stop stops Brutal congestion control.
func (b *BrutalKCP) Stop() {
	b.cc.Stop()
}

// BandwidthController interface for rate limiting.
type BandwidthController struct {
	targetBps     int64
	currentTokens int64
	lastUpdate    time.Time
	mu            sync.Mutex
}

// NewBandwidthController creates a new bandwidth controller.
func NewBandwidthController(bandwidthMbps int) *BandwidthController {
	return &BandwidthController{
		targetBps:     int64(bandwidthMbps) * 1024 * 1024 / 8,
		currentTokens: 0,
		lastUpdate:    time.Now(),
	}
}

// Allow checks if the specified number of bytes can be sent.
func (bc *BandwidthController) Allow(bytes int) bool {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	// Add tokens based on time elapsed
	now := time.Now()
	elapsed := now.Sub(bc.lastUpdate).Seconds()
	bc.lastUpdate = now

	bc.currentTokens += int64(elapsed * float64(bc.targetBps))

	// Cap tokens at 1 second worth of bandwidth
	maxTokens := bc.targetBps
	if bc.currentTokens > maxTokens {
		bc.currentTokens = maxTokens
	}

	// Check if we have enough tokens
	if int64(bytes) <= bc.currentTokens {
		bc.currentTokens -= int64(bytes)
		return true
	}

	return false
}

// Wait waits until the specified number of bytes can be sent.
func (bc *BandwidthController) Wait(bytes int) {
	for !bc.Allow(bytes) {
		time.Sleep(time.Millisecond)
	}
}

// SetBandwidth updates the target bandwidth.
func (bc *BandwidthController) SetBandwidth(bandwidthMbps int) {
	bc.mu.Lock()
	defer bc.mu.Unlock()
	bc.targetBps = int64(bandwidthMbps) * 1024 * 1024 / 8
}
