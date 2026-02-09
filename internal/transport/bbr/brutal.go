// Package bbr implements Brutal congestion control ported from Hysteria.
// Brutal is a rate-based congestion control algorithm designed for high
// throughput in lossy network conditions.
package bbr

import (
	"fmt"
	"sync"
	"time"
)

// BrutalConfig configures the Brutal congestion controller
type BrutalConfig struct {
	// Enabled enables Brutal congestion control
	Enabled bool `yaml:"enabled"`

	// BandwidthMbps is the target bandwidth in Mbps
	BandwidthMbps int `yaml:"bandwidth_mbps"`

	// MinSampleCount is the minimum number of samples before adjusting ack rate
	MinSampleCount int `yaml:"min_sample_count"`

	// MinAckRate is the minimum acceptable acknowledgment rate (0.0-1.0)
	MinAckRate float64 `yaml:"min_ack_rate"`

	// CongestionWindowMultiplier controls the congestion window size
	CongestionWindowMultiplier float64 `yaml:"cwnd_multiplier"`
}

// ApplyDefaults sets default values for Brutal configuration
func (c *BrutalConfig) ApplyDefaults() {
	if c.BandwidthMbps <= 0 {
		c.BandwidthMbps = 100 // Default 100 Mbps
	}
	if c.MinSampleCount <= 0 {
		c.MinSampleCount = 50
	}
	if c.MinAckRate <= 0 {
		c.MinAckRate = 0.8
	}
	if c.CongestionWindowMultiplier <= 0 {
		c.CongestionWindowMultiplier = 2.0
	}
}

// RTTStatsProvider provides RTT statistics
type RTTStatsProvider interface {
	SmoothedRTT() time.Duration
	LatestRTT() time.Duration
	MinRTT() time.Duration
}

// BrutalSender implements rate-based congestion control
// Based on Hysteria's Brutal implementation
type BrutalSender struct {
	config *BrutalConfig

	// Target bandwidth in bytes per second
	bps uint64

	// RTT statistics provider
	rttStats RTTStatsProvider

	// Maximum datagram size
	maxDatagramSize uint64

	// Pacer for rate limiting
	pacer *Pacer

	// Packet info slots for 5-second sampling window
	pktInfoSlots [pktInfoSlotCount]pktInfo

	// Current acknowledgment rate (0.0-1.0)
	ackRate float64

	mu sync.RWMutex
}

const (
	// pktInfoSlotCount is the number of seconds we sample
	pktInfoSlotCount = 5

	// Default max datagram size
	defaultMaxDatagramSize = 1350
)

// pktInfo tracks packet information for a time slot
type pktInfo struct {
	Timestamp int64
	AckCount  uint64
	LossCount uint64
}

// Pacer implements a token bucket pacing algorithm
type Pacer struct {
	mu               sync.Mutex
	budgetAtLastSent uint64
	maxDatagramSize  uint64
	lastSentTime     time.Time
	getBandwidth     func() uint64 // in bytes/s
}

// NewPacer creates a new pacer
func NewPacer(getBandwidth func() uint64) *Pacer {
	return &Pacer{
		budgetAtLastSent: maxBurstPackets * defaultMaxDatagramSize,
		maxDatagramSize:  defaultMaxDatagramSize,
		getBandwidth:     getBandwidth,
	}
}

const (
	maxBurstPackets               = 10
	maxBurstPacingDelayMultiplier = 4
	minPacingDelay                = time.Microsecond
)

// SentPacket updates the pacer after sending a packet
func (p *Pacer) SentPacket(sendTime time.Time, size uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()

	budget := p.budget(sendTime)
	if size > budget {
		p.budgetAtLastSent = 0
	} else {
		p.budgetAtLastSent = budget - size
	}
	p.lastSentTime = sendTime
}

// Budget returns the current pacing budget
func (p *Pacer) Budget(now time.Time) uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.budget(now)
}

func (p *Pacer) budget(now time.Time) uint64 {
	if p.lastSentTime.IsZero() {
		return p.maxBurstSize()
	}

	elapsed := now.Sub(p.lastSentTime).Nanoseconds()
	bandwidth := p.getBandwidth()

	budget := p.budgetAtLastSent + (bandwidth*uint64(elapsed))/1e9

	maxBurst := p.maxBurstSize()
	if budget > maxBurst {
		budget = maxBurst
	}

	return budget
}

func (p *Pacer) maxBurstSize() uint64 {
	bw := p.getBandwidth()
	pacingDelay := time.Duration(maxBurstPacingDelayMultiplier) * minPacingDelay
	fromDelay := (uint64(pacingDelay.Nanoseconds()) * bw) / 1e9
	fromPackets := maxBurstPackets * p.maxDatagramSize

	if fromDelay > fromPackets {
		return fromDelay
	}
	return fromPackets
}

// TimeUntilSend returns when the next packet should be sent
func (p *Pacer) TimeUntilSend() time.Duration {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.budgetAtLastSent >= p.maxDatagramSize {
		return 0
	}

	diff := 1e9 * (p.maxDatagramSize - p.budgetAtLastSent)
	bw := p.getBandwidth()

	if bw == 0 {
		return minPacingDelay
	}

	d := diff / bw
	if diff%bw > 0 {
		d++
	}

	delay := time.Duration(d) * time.Nanosecond
	if delay < minPacingDelay {
		delay = minPacingDelay
	}

	return delay
}

// SetMaxDatagramSize sets the maximum datagram size
func (p *Pacer) SetMaxDatagramSize(size uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.maxDatagramSize = size
}

// NewBrutalSender creates a new Brutal congestion controller
func NewBrutalSender(config *BrutalConfig) *BrutalSender {
	config.ApplyDefaults()

	bps := uint64(config.BandwidthMbps) * 1000000 / 8 // Convert Mbps to bytes/sec

	sender := &BrutalSender{
		config:          config,
		bps:             bps,
		maxDatagramSize: defaultMaxDatagramSize,
		ackRate:         1.0,
	}

	sender.pacer = NewPacer(func() uint64 {
		sender.mu.RLock()
		ackRate := sender.ackRate
		sender.mu.RUnlock()
		return uint64(float64(sender.bps) / ackRate)
	})

	return sender
}

// SetRTTStatsProvider sets the RTT statistics provider
func (b *BrutalSender) SetRTTStatsProvider(provider RTTStatsProvider) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rttStats = provider
}

// TimeUntilSend returns the time until the next packet can be sent
func (b *BrutalSender) TimeUntilSend(bytesInFlight uint64) time.Duration {
	return b.pacer.TimeUntilSend()
}

// HasPacingBudget returns true if there's budget to send a packet
func (b *BrutalSender) HasPacingBudget(now time.Time) bool {
	return b.pacer.Budget(now) >= b.maxDatagramSize
}

// CanSend returns true if we can send with the given bytes in flight
func (b *BrutalSender) CanSend(bytesInFlight uint64) bool {
	return bytesInFlight <= b.GetCongestionWindow()
}

// GetCongestionWindow returns the current congestion window size
func (b *BrutalSender) GetCongestionWindow() uint64 {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.rttStats == nil {
		return 10240 // Default initial window
	}

	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return 10240
	}

	cwnd := uint64(float64(b.bps) * rtt.Seconds() * b.config.CongestionWindowMultiplier / b.ackRate)
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}

	return cwnd
}

// OnPacketSent is called when a packet is sent
func (b *BrutalSender) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
}

// OnPacketAcked is called when a packet is acknowledged
func (b *BrutalSender) OnPacketAcked(packetNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) {
	// Handled in OnCongestionEventEx
}

// OnCongestionEvent is called when a congestion event occurs
func (b *BrutalSender) OnCongestionEvent(packetNumber uint64, lostBytes uint64, priorInFlight uint64) {
	// Handled in OnCongestionEventEx
}

// AckedPacketInfo contains information about an acknowledged packet
type AckedPacketInfo struct {
	PacketNumber uint64
	Bytes        uint64
}

// LostPacketInfo contains information about a lost packet
type LostPacketInfo struct {
	PacketNumber uint64
	Bytes        uint64
}

// OnCongestionEventEx is called with detailed congestion event information
func (b *BrutalSender) OnCongestionEventEx(priorInFlight uint64, eventTime time.Time, ackedPackets []AckedPacketInfo, lostPackets []LostPacketInfo) {
	b.mu.Lock()
	defer b.mu.Unlock()

	currentTimestamp := eventTime.Unix()
	slot := currentTimestamp % pktInfoSlotCount

	if b.pktInfoSlots[slot].Timestamp == currentTimestamp {
		b.pktInfoSlots[slot].LossCount += uint64(len(lostPackets))
		b.pktInfoSlots[slot].AckCount += uint64(len(ackedPackets))
	} else {
		// Uninitialized slot or too old, reset
		b.pktInfoSlots[slot].Timestamp = currentTimestamp
		b.pktInfoSlots[slot].AckCount = uint64(len(ackedPackets))
		b.pktInfoSlots[slot].LossCount = uint64(len(lostPackets))
	}

	b.updateAckRate(currentTimestamp)
}

// updateAckRate updates the acknowledgment rate based on recent samples
func (b *BrutalSender) updateAckRate(currentTimestamp int64) {
	minTimestamp := currentTimestamp - pktInfoSlotCount

	var ackCount, lossCount uint64
	for _, info := range b.pktInfoSlots {
		if info.Timestamp < minTimestamp {
			continue
		}
		ackCount += info.AckCount
		lossCount += info.LossCount
	}

	total := ackCount + lossCount
	if total < uint64(b.config.MinSampleCount) {
		b.ackRate = 1.0
		return
	}

	rate := float64(ackCount) / float64(total)
	if rate < b.config.MinAckRate {
		b.ackRate = b.config.MinAckRate
	} else {
		b.ackRate = rate
	}
}

// SetMaxDatagramSize sets the maximum datagram size
func (b *BrutalSender) SetMaxDatagramSize(size uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.maxDatagramSize = size
	b.pacer.SetMaxDatagramSize(size)
}

// InSlowStart returns true if in slow start phase (always false for Brutal)
func (b *BrutalSender) InSlowStart() bool {
	return false
}

// InRecovery returns true if in recovery phase (always false for Brutal)
func (b *BrutalSender) InRecovery() bool {
	return false
}

// MaybeExitSlowStart is a no-op for Brutal
func (b *BrutalSender) MaybeExitSlowStart() {}

// OnRetransmissionTimeout is called on retransmission timeout
func (b *BrutalSender) OnRetransmissionTimeout(packetsRetransmitted bool) {}

// GetStats returns current Brutal statistics
func (b *BrutalSender) GetStats() BrutalStats {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var rtt time.Duration
	if b.rttStats != nil {
		rtt = b.rttStats.SmoothedRTT()
	}

	return BrutalStats{
		TargetBPS:     b.bps,
		AckRate:       b.ackRate,
		SmoothedRTT:   rtt,
		CongestionWnd: b.getCongestionWindowUnsafe(),
	}
}

func (b *BrutalSender) getCongestionWindowUnsafe() uint64 {
	if b.rttStats == nil {
		return 10240
	}

	rtt := b.rttStats.SmoothedRTT()
	if rtt <= 0 {
		return 10240
	}

	cwnd := uint64(float64(b.bps) * rtt.Seconds() * b.config.CongestionWindowMultiplier / b.ackRate)
	if cwnd < b.maxDatagramSize {
		cwnd = b.maxDatagramSize
	}

	return cwnd
}

// BrutalStats contains Brutal congestion control statistics
type BrutalStats struct {
	TargetBPS     uint64        `json:"target_bps"`
	AckRate       float64       `json:"ack_rate"`
	SmoothedRTT   time.Duration `json:"smoothed_rtt_ms"`
	CongestionWnd uint64        `json:"congestion_window"`
}

// String returns a string representation of the stats
func (s BrutalStats) String() string {
	return fmt.Sprintf("Brutal{target=%d Mbps, ack_rate=%.2f, rtt=%v, cwnd=%d}",
		s.TargetBPS*8/1000000, s.AckRate, s.SmoothedRTT, s.CongestionWnd)
}
