package kcpbase

import (
	"math"
	"sync"
	"sync/atomic"
)

// FECController manages Forward Error Correction settings
type FECController struct {
	dataShards   atomic.Int32
	parityShards atomic.Int32
	autoTune     atomic.Bool

	// Statistics for auto-tuning
	packetsTotal   atomic.Uint64
	packetsLost    atomic.Uint64
	packetsRecovered atomic.Uint64

	mu sync.RWMutex
}

// NewFECController creates a new FEC controller
func NewFECController(dataShards, parityShards int, autoTune bool) *FECController {
	fc := &FECController{}
	fc.dataShards.Store(int32(dataShards))
	fc.parityShards.Store(int32(parityShards))
	fc.autoTune.Store(autoTune)
	return fc
}

// GetShards returns current FEC shard configuration
func (fc *FECController) GetShards() (dataShards, parityShards int) {
	return int(fc.dataShards.Load()), int(fc.parityShards.Load())
}

// SetShards sets FEC shard configuration
func (fc *FECController) SetShards(dataShards, parityShards int) {
	fc.dataShards.Store(int32(dataShards))
	fc.parityShards.Store(int32(parityShards))
}

// IsAutoTune returns whether auto-tuning is enabled
func (fc *FECController) IsAutoTune() bool {
	return fc.autoTune.Load()
}

// SetAutoTune enables/disables auto-tuning
func (fc *FECController) SetAutoTune(enabled bool) {
	fc.autoTune.Store(enabled)
}

// RecordPacket records packet statistics for auto-tuning
func (fc *FECController) RecordPacket(lost, recovered bool) {
	fc.packetsTotal.Add(1)
	if lost {
		fc.packetsLost.Add(1)
		if recovered {
			fc.packetsRecovered.Add(1)
		}
	}

	// Auto-tune every 1000 packets
	if fc.autoTune.Load() && fc.packetsTotal.Load()%1000 == 0 {
		fc.autoTuneFEC()
	}
}

// autoTuneFEC adjusts FEC parameters based on observed loss
func (fc *FECController) autoTuneFEC() {
	total := fc.packetsTotal.Load()
	lost := fc.packetsLost.Load()
	recovered := fc.packetsRecovered.Load()

	if total == 0 {
		return
	}

	lossRate := float64(lost) / float64(total)
	recoveryRate := float64(recovered) / float64(lost+1)

	dataShards, parityShards := fc.GetShards()

	// Adjust based on loss rate
	switch {
	case lossRate < 0.001:
		// Very low loss - reduce FEC overhead
		if parityShards > 1 {
			parityShards--
		}
	case lossRate < 0.01:
		// Low loss - maintain current or slight reduction
		if parityShards > dataShards/3 && parityShards > 2 {
			parityShards = dataShards / 3
		}
	case lossRate < 0.05:
		// Moderate loss - increase FEC
		if parityShards < dataShards/2 {
			parityShards = dataShards / 2
		}
	default:
		// High loss - aggressive FEC
		if parityShards < dataShards {
			parityShards = dataShards
		}
	}

	// Adjust based on recovery effectiveness
	if recoveryRate < 0.5 && lossRate > 0.01 {
		// FEC not recovering well, increase parity shards
		if parityShards < dataShards {
			parityShards++
		}
	}

	// Clamp values
	if dataShards < 1 {
		dataShards = 1
	}
	if parityShards < 0 {
		parityShards = 0
	}
	if dataShards > 255 {
		dataShards = 255
	}
	if parityShards > 255 {
		parityShards = 255
	}

	fc.SetShards(dataShards, parityShards)
}

// GetStats returns FEC statistics
func (fc *FECController) GetStats() FECStats {
	total := fc.packetsTotal.Load()
	lost := fc.packetsLost.Load()
	recovered := fc.packetsRecovered.Load()

	var lossRate, recoveryRate float64
	if total > 0 {
		lossRate = float64(lost) / float64(total)
	}
	if lost > 0 {
		recoveryRate = float64(recovered) / float64(lost)
	}

	dataShards, parityShards := fc.GetShards()
	overhead := 0.0
	if dataShards+parityShards > 0 {
		overhead = float64(parityShards) / float64(dataShards+parityShards)
	}

	return FECStats{
		DataShards:     dataShards,
		ParityShards:   parityShards,
		TotalPackets:   total,
		LostPackets:    lost,
		RecoveredPackets: recovered,
		LossRate:       lossRate,
		RecoveryRate:   recoveryRate,
		Overhead:       overhead,
		EffectiveLoss:  lossRate * (1 - recoveryRate),
	}
}

// FECStats contains FEC statistics
type FECStats struct {
	DataShards       int
	ParityShards     int
	TotalPackets     uint64
	LostPackets      uint64
	RecoveredPackets uint64
	LossRate         float64
	RecoveryRate     float64
	Overhead         float64
	EffectiveLoss    float64
}

// CalculateOptimalShards calculates optimal FEC parameters for a given loss rate
func CalculateOptimalShards(targetLossRate float64, maxOverhead float64) (dataShards, parityShards int) {
	// Start with default values
	dataShards = 10

	// Calculate required parity shards for target loss rate
	// Using simplified Reed-Solomon model
	// P(recovery) ≈ 1 - P(loss)^(parityShards+1)
	// We want effective loss rate < targetLossRate

	for parityShards = 1; parityShards <= dataShards; parityShards++ {
		overhead := float64(parityShards) / float64(dataShards+parityShards)
		if overhead > maxOverhead {
			// Reduce data shards to maintain overhead constraint
			dataShards = int(float64(parityShards) / maxOverhead) - parityShards
			if dataShards < 1 {
				dataShards = 1
			}
		}

		// Calculate effective loss rate with current configuration
		// Assuming independent losses with probability targetLossRate
		effectiveLoss := math.Pow(targetLossRate, float64(parityShards+1))

		if effectiveLoss < targetLossRate/10 {
			// Good enough
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

	// Calculate raw shard size
	shardSize := payloadSize / sc.dataShards
	if payloadSize%sc.dataShards != 0 {
		shardSize++
	}

	// Ensure shard size fits in MTU (accounting for headers)
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
	return shardSize * totalShards - payloadSize
}
