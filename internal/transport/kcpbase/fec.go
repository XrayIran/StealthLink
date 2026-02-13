package kcpbase

import (
	"math"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

// lossEvent tracks a packet loss event for the sliding window
type lossEvent struct {
	timestamp time.Time
	lost      bool
}

// FECController manages Forward Error Correction settings with auto-tuning and parity skip
type FECController struct {
	dataShards   atomic.Int32
	parityShards atomic.Int32
	autoTune     atomic.Bool

	paritySkipEnabled atomic.Bool
	lastDataTime      atomic.Int64 // UnixNano
	paritySkipped     atomic.Uint64

	// Auto-tuning state
	mu             sync.Mutex
	lossEvents     []lossEvent
	lastAdjustTime time.Time
	lastEvalTime   time.Time

	// Current network metrics (fed from outside)
	rttVar atomic.Int64 // Milliseconds
}

// NewFECController creates a new FEC controller
func NewFECController(dataShards, parityShards int, autoTune bool) *FECController {
	fc := &FECController{}
	fc.dataShards.Store(int32(dataShards))
	fc.parityShards.Store(int32(parityShards))
	fc.autoTune.Store(autoTune)
	fc.paritySkipEnabled.Store(true) // Default enabled per Requirement 15.4
	fc.lastAdjustTime = time.Now()
	fc.lastEvalTime = time.Now()

	metrics.SetKCPFECShards(int64(dataShards), int64(parityShards))
	return fc
}

// GetShards returns current FEC shard configuration
func (fc *FECController) GetShards() (dataShards, parityShards int) {
	return int(fc.dataShards.Load()), int(fc.parityShards.Load())
}

// SetShards sets FEC shard configuration
func (fc *FECController) SetShards(dataShards, parityShards int) {
	if dataShards < 3 {
		dataShards = 3
	}
	if dataShards > 20 {
		dataShards = 20
	}
	if parityShards < 1 {
		parityShards = 1
	}
	if parityShards > 10 {
		parityShards = 10
	}

	oldD := fc.dataShards.Swap(int32(dataShards))
	oldP := fc.parityShards.Swap(int32(parityShards))

	if oldD != int32(dataShards) || oldP != int32(parityShards) {
		metrics.IncKCPFECAutoTuneAdjustments()
		metrics.SetKCPFECShards(int64(dataShards), int64(parityShards))
	}
}

// SetParitySkip enables/disables parity skip optimization
func (fc *FECController) SetParitySkip(enabled bool) {
	fc.paritySkipEnabled.Store(enabled)
}

// RecordDataPacket updates the last data transmission time
func (fc *FECController) RecordDataPacket() {
	fc.lastDataTime.Store(time.Now().UnixNano())
}

// ShouldSkipParity returns true if parity should be skipped based on RTO
func (fc *FECController) ShouldSkipParity(rto time.Duration) bool {
	if !fc.paritySkipEnabled.Load() {
		return false
	}

	lastUnixNano := fc.lastDataTime.Load()
	if lastUnixNano == 0 {
		return false
	}

	lastTime := time.Unix(0, lastUnixNano)

	gap := time.Since(lastTime)
	if gap > rto {
		fc.paritySkipped.Add(1)
		metrics.IncKCPFECParitySkipped()
		return true
	}
	return false
}

// RecordPacket records packet statistics for auto-tuning
func (fc *FECController) RecordPacket(lost bool, rttVar time.Duration) {
	fc.rttVar.Store(rttVar.Milliseconds())

	if !fc.autoTune.Load() {
		return
	}

	fc.mu.Lock()
	now := time.Now()
	fc.lossEvents = append(fc.lossEvents, lossEvent{
		timestamp: now,
		lost:      lost,
	})

	// Clean up events older than 60 seconds
	cutoff := now.Add(-60 * time.Second)
	idx := 0
	for i, ev := range fc.lossEvents {
		if ev.timestamp.After(cutoff) {
			idx = i
			break
		}
	}
	if idx > 0 {
		fc.lossEvents = fc.lossEvents[idx:]
	}

	// Re-evaluate every 10 seconds (Requirement 10.3)
	if now.Sub(fc.lastEvalTime) >= 10*time.Second {
		fc.lastEvalTime = now
		fc.autoTuneFEC(now)
	}
	fc.mu.Unlock()
}

// autoTuneFEC adjusts FEC parameters based on observed loss
// Must be called with fc.mu locked
func (fc *FECController) autoTuneFEC(now time.Time) {
	// Cooldown: 30 seconds (Requirement 10.11)
	if now.Sub(fc.lastAdjustTime) < 30*time.Second {
		return
	}

	if len(fc.lossEvents) < 100 {
		// Not enough data yet
		return
	}

	lost := 0
	for _, ev := range fc.lossEvents {
		if ev.lost {
			lost++
		}
	}

	lossRate := float64(lost) / float64(len(fc.lossEvents))
	dataShards, parityShards := fc.GetShards()

	adjusted := false

	// Hysteresis rules (Requirement 10.7, 10.8, 10.9)
	if lossRate < 0.01 {
		if parityShards > 1 {
			parityShards--
			adjusted = true
		}
	} else if lossRate > 0.05 {
		if parityShards < 10 {
			parityShards++
			adjusted = true
		}
	}

	// RTT variance rule (Requirement 10.10)
	if fc.rttVar.Load() > 50 {
		if dataShards < 20 {
			dataShards++
			adjusted = true
		}
	} else if lossRate < 0.01 && dataShards > 5 {
		// Optimization: decrease data shards if network is stable to reduce computational overhead
		// (Not explicitly in requirements but good practice)
		// dataShards--
		// adjusted = true
	}

	if adjusted {
		fc.SetShards(dataShards, parityShards)
		fc.lastAdjustTime = now
	}
}

// GetStats returns FEC statistics
func (fc *FECController) GetStats() FECStats {
	fc.mu.Lock()
	defer fc.mu.Unlock()

	total := len(fc.lossEvents)
	lost := 0
	for _, ev := range fc.lossEvents {
		if ev.lost {
			lost++
		}
	}

	var lossRate float64
	if total > 0 {
		lossRate = float64(lost) / float64(total)
	}

	dataShards, parityShards := fc.GetShards()
	overhead := 0.0
	if dataShards+parityShards > 0 {
		overhead = float64(parityShards) / float64(dataShards+parityShards)
	}

	return FECStats{
		DataShards:    dataShards,
		ParityShards:  parityShards,
		TotalPackets:  uint64(total),
		LostPackets:   uint64(lost),
		LossRate:      lossRate,
		Overhead:      overhead,
		ParitySkipped: fc.paritySkipped.Load(),
	}
}

// FECStats contains FEC statistics
type FECStats struct {
	DataShards    int
	ParityShards  int
	TotalPackets  uint64
	LostPackets   uint64
	LossRate      float64
	Overhead      float64
	ParitySkipped uint64
}

// CalculateOptimalShards calculates optimal FEC parameters for a given loss rate
func CalculateOptimalShards(targetLossRate float64, maxOverhead float64) (dataShards, parityShards int) {
	dataShards = 10
	for parityShards = 1; parityShards <= 10; parityShards++ {
		overhead := float64(parityShards) / float64(dataShards+parityShards)
		if overhead > maxOverhead {
			break
		}
		effectiveLoss := math.Pow(targetLossRate, float64(parityShards+1))
		if effectiveLoss < targetLossRate/10 {
			break
		}
	}
	return dataShards, parityShards
}

// ShardCalculator helps calculate shard sizes
type ShardCalculator struct {
	dataShards   int
	parityShards int
	mtu          int
}

// NewShardCalculator creates a new shard calculator
func NewShardCalculator(dataShards, parityShards, mtu int) *ShardCalculator {
	return &ShardCalculator{
		dataShards:   dataShards,
		parityShards: parityShards,
		mtu:          mtu,
	}
}

// CalculateShardSize calculates the optimal shard size for a payload
func (sc *ShardCalculator) CalculateShardSize(payloadSize int) int {
	if sc.dataShards == 0 {
		return payloadSize
	}
	shardSize := (payloadSize + sc.dataShards - 1) / sc.dataShards
	maxShardSize := sc.mtu - 24 // KCP header overhead
	if shardSize > maxShardSize {
		shardSize = maxShardSize
	}
	return shardSize
}

// CalculateTotalOverhead calculates the total FEC overhead for a payload
func (sc *ShardCalculator) CalculateTotalOverhead(payloadSize int) int {
	if sc.dataShards == 0 {
		return 0
	}
	shardSize := sc.CalculateShardSize(payloadSize)
	totalShards := sc.dataShards + sc.parityShards
	return shardSize*totalShards - payloadSize
}
