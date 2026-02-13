package uqsp

import (
	"fmt"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport/bbr"
)

// CongestionAlgorithm represents the congestion control algorithm
type CongestionAlgorithm int

const (
	// CongestionAlgorithmBBR uses BBR congestion control
	CongestionAlgorithmBBR CongestionAlgorithm = iota

	// CongestionAlgorithmBrutal uses Brutal congestion control (Hysteria)
	CongestionAlgorithmBrutal

	// CongestionAlgorithmCubic uses CUBIC congestion control
	CongestionAlgorithmCubic
)

// String returns the string representation of the algorithm
func (c CongestionAlgorithm) String() string {
	switch c {
	case CongestionAlgorithmBBR:
		return "bbr"
	case CongestionAlgorithmBrutal:
		return "brutal"
	case CongestionAlgorithmCubic:
		return "cubic"
	default:
		return "unknown"
	}
}

// ParseCongestionAlgorithm parses a congestion algorithm string
func ParseCongestionAlgorithm(s string) (CongestionAlgorithm, error) {
	switch s {
	case "bbr":
		return CongestionAlgorithmBBR, nil
	case "brutal":
		return CongestionAlgorithmBrutal, nil
	case "cubic":
		return CongestionAlgorithmCubic, nil
	default:
		return CongestionAlgorithmBBR, fmt.Errorf("unknown congestion algorithm: %s", s)
	}
}

// CongestionController is the interface for congestion control algorithms
type CongestionController interface {
	// OnPacketSent is called when a packet is sent
	OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64)

	// OnPacketAcked is called when a packet is acknowledged
	OnPacketAcked(packetNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time)

	// OnCongestionEvent is called when congestion is detected
	OnCongestionEvent(packetNumber uint64, lostBytes uint64, priorInFlight uint64)

	// GetCongestionWindow returns the current congestion window
	GetCongestionWindow() uint64

	// GetPacingDelay returns the pacing delay
	GetPacingDelay() time.Duration

	// InSlowStart returns true if in slow start phase
	InSlowStart() bool

	// InRecovery returns true if in recovery phase
	InRecovery() bool
}

// CongestionConfig configures congestion control
type CongestionConfig struct {
	// Algorithm is the congestion control algorithm
	Algorithm CongestionAlgorithm

	// Pacing is the pacing strategy
	Pacing string

	// AdaptiveMode enables adaptive algorithm switching
	AdaptiveMode bool

	// BrutalConfig is the configuration for Brutal CC
	BrutalConfig *bbr.BrutalConfig
}

// NewCongestionController creates a new congestion controller
func NewCongestionController(config *CongestionConfig) (CongestionController, error) {
	if config == nil {
		config = &CongestionConfig{
			Algorithm: CongestionAlgorithmBBR,
			Pacing:    "adaptive",
		}
	}

	switch config.Algorithm {
	case CongestionAlgorithmBrutal:
		return NewBrutalController(config.BrutalConfig), nil
	case CongestionAlgorithmBBR, CongestionAlgorithmCubic:
		// These are handled by QUIC internally
		// We return a no-op controller for these
		return &NoOpCongestionController{}, nil
	default:
		return &NoOpCongestionController{}, nil
	}
}

// BrutalController wraps the bbr.BrutalSender for UQSP
type BrutalController struct {
	sender *bbr.BrutalSender
}

// NewBrutalController creates a new Brutal congestion controller
func NewBrutalController(config *bbr.BrutalConfig) *BrutalController {
	if config == nil {
		config = &bbr.BrutalConfig{
			Enabled:       true,
			BandwidthMbps: 100,
		}
	}
	config.ApplyDefaults()

	return &BrutalController{
		sender: bbr.NewBrutalSender(config),
	}
}

// OnPacketSent is called when a packet is sent
func (b *BrutalController) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64) {
	b.sender.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytes, true)
}

// OnPacketAcked is called when a packet is acknowledged
func (b *BrutalController) OnPacketAcked(packetNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) {
	b.sender.OnPacketAcked(packetNumber, ackedBytes, priorInFlight, eventTime)
}

// OnCongestionEvent is called when congestion is detected
func (b *BrutalController) OnCongestionEvent(packetNumber uint64, lostBytes uint64, priorInFlight uint64) {
	b.sender.OnCongestionEvent(packetNumber, lostBytes, priorInFlight)
}

// GetCongestionWindow returns the current congestion window
func (b *BrutalController) GetCongestionWindow() uint64 {
	return b.sender.GetCongestionWindow()
}

// GetPacingDelay returns the pacing delay
func (b *BrutalController) GetPacingDelay() time.Duration {
	return b.sender.TimeUntilSend(0)
}

// InSlowStart returns true if in slow start phase
func (b *BrutalController) InSlowStart() bool {
	return b.sender.InSlowStart()
}

// InRecovery returns true if in recovery phase
func (b *BrutalController) InRecovery() bool {
	return b.sender.InRecovery()
}

// SetRTTStatsProvider sets the RTT stats provider
func (b *BrutalController) SetRTTStatsProvider(provider bbr.RTTStatsProvider) {
	b.sender.SetRTTStatsProvider(provider)
}

// GetStats returns Brutal statistics
func (b *BrutalController) GetStats() bbr.BrutalStats {
	return b.sender.GetStats()
}

// NoOpCongestionController is a no-op congestion controller
type NoOpCongestionController struct{}

// OnPacketSent is a no-op
func (n *NoOpCongestionController) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64) {
}

// OnPacketAcked is a no-op
func (n *NoOpCongestionController) OnPacketAcked(packetNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) {
}

// OnCongestionEvent is a no-op
func (n *NoOpCongestionController) OnCongestionEvent(packetNumber uint64, lostBytes uint64, priorInFlight uint64) {
}

// GetCongestionWindow returns a default value
func (n *NoOpCongestionController) GetCongestionWindow() uint64 {
	return 65535
}

// GetPacingDelay returns zero
func (n *NoOpCongestionController) GetPacingDelay() time.Duration {
	return 0
}

// InSlowStart returns false
func (n *NoOpCongestionController) InSlowStart() bool {
	return false
}

// InRecovery returns false
func (n *NoOpCongestionController) InRecovery() bool {
	return false
}

// Pacer implements packet pacing
type Pacer struct {
	congestionController CongestionController
	lastSendTime         time.Time
	pacingBudget         uint64
	rttEstimate          atomic.Int64
}

const defaultPacerRTT = 100 * time.Millisecond

// NewPacer creates a new pacer
func NewPacer(cc CongestionController) *Pacer {
	p := &Pacer{
		congestionController: cc,
		pacingBudget:         65535,
	}
	p.rttEstimate.Store(int64(defaultPacerRTT))
	return p
}

// UpdateRTT updates the measured RTT estimate used for pacing calculations.
func (p *Pacer) UpdateRTT(rtt time.Duration) {
	if rtt > 0 {
		p.rttEstimate.Store(int64(rtt))
	}
}

func (p *Pacer) getRTT() time.Duration {
	if v := p.rttEstimate.Load(); v > 0 {
		return time.Duration(v)
	}
	return defaultPacerRTT
}

// CanSend returns true if we can send now
func (p *Pacer) CanSend(now time.Time, packetSize uint64) bool {
	if !p.lastSendTime.IsZero() {
		elapsed := now.Sub(p.lastSendTime)
		cwnd := p.congestionController.GetCongestionWindow()
		rtt := p.getRTT()

		if rtt > 0 {
			increment := uint64(elapsed) * cwnd / uint64(rtt)
			p.pacingBudget += increment
			if p.pacingBudget > cwnd {
				p.pacingBudget = cwnd
			}
		}
	}

	return p.pacingBudget >= packetSize
}

// OnPacketSent updates the pacer after sending
func (p *Pacer) OnPacketSent(now time.Time, packetSize uint64) {
	if packetSize > p.pacingBudget {
		p.pacingBudget = 0
	} else {
		p.pacingBudget -= packetSize
	}
	p.lastSendTime = now
}

// TimeUntilSend returns the time until we can send
func (p *Pacer) TimeUntilSend(packetSize uint64) time.Duration {
	if p.pacingBudget >= packetSize {
		return 0
	}

	cwnd := p.congestionController.GetCongestionWindow()
	rtt := p.getRTT()

	if cwnd == 0 {
		return 0
	}

	needed := packetSize - p.pacingBudget
	delay := time.Duration(needed) * rtt / time.Duration(cwnd)

	if delay < time.Millisecond {
		delay = time.Millisecond
	}

	return delay
}

// AdaptiveCongestionController adapts between algorithms
type AdaptiveCongestionController struct {
	// current is the current congestion controller
	current CongestionController

	// algorithms is the list of available algorithms
	algorithms []CongestionController

	// currentIndex is the index of the current algorithm
	currentIndex int

	// lossRate is the current loss rate
	lossRate float64

	// throughput is the current throughput estimate
	throughput uint64

	// lastSwitchTime is the last algorithm switch time
	lastSwitchTime time.Time

	// switchCooldown is the minimum time between switches
	switchCooldown time.Duration
}

// NewAdaptiveCongestionController creates an adaptive congestion controller
func NewAdaptiveCongestionController(algorithms []CongestionController) *AdaptiveCongestionController {
	if len(algorithms) == 0 {
		algorithms = []CongestionController{&NoOpCongestionController{}}
	}

	return &AdaptiveCongestionController{
		current:        algorithms[0],
		algorithms:     algorithms,
		currentIndex:   0,
		lastSwitchTime: time.Now(),
		switchCooldown: 30 * time.Second,
	}
}

// OnPacketSent is called when a packet is sent
func (a *AdaptiveCongestionController) OnPacketSent(sentTime time.Time, bytesInFlight uint64, packetNumber uint64, bytes uint64) {
	a.current.OnPacketSent(sentTime, bytesInFlight, packetNumber, bytes)
}

// OnPacketAcked is called when a packet is acknowledged
func (a *AdaptiveCongestionController) OnPacketAcked(packetNumber uint64, ackedBytes uint64, priorInFlight uint64, eventTime time.Time) {
	a.current.OnPacketAcked(packetNumber, ackedBytes, priorInFlight, eventTime)
}

// OnCongestionEvent is called when congestion is detected
func (a *AdaptiveCongestionController) OnCongestionEvent(packetNumber uint64, lostBytes uint64, priorInFlight uint64) {
	a.current.OnCongestionEvent(packetNumber, lostBytes, priorInFlight)

	// Update loss rate
	if priorInFlight > 0 {
		a.lossRate = float64(lostBytes) / float64(priorInFlight)
	}

	// Consider switching algorithms
	a.maybeSwitchAlgorithm()
}

// GetCongestionWindow returns the current congestion window
func (a *AdaptiveCongestionController) GetCongestionWindow() uint64 {
	return a.current.GetCongestionWindow()
}

// GetPacingDelay returns the pacing delay
func (a *AdaptiveCongestionController) GetPacingDelay() time.Duration {
	return a.current.GetPacingDelay()
}

// InSlowStart returns true if in slow start phase
func (a *AdaptiveCongestionController) InSlowStart() bool {
	return a.current.InSlowStart()
}

// InRecovery returns true if in recovery phase
func (a *AdaptiveCongestionController) InRecovery() bool {
	return a.current.InRecovery()
}

// maybeSwitchAlgorithm considers switching congestion control algorithms
func (a *AdaptiveCongestionController) maybeSwitchAlgorithm() {
	// Check cooldown
	if time.Since(a.lastSwitchTime) < a.switchCooldown {
		return
	}

	// Simple heuristic: if loss rate is high, try a different algorithm
	if a.lossRate > 0.1 && len(a.algorithms) > 1 {
		a.currentIndex = (a.currentIndex + 1) % len(a.algorithms)
		a.current = a.algorithms[a.currentIndex]
		a.lastSwitchTime = time.Now()
		a.lossRate = 0
	}
}
