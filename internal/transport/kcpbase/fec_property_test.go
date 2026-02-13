package kcpbase

import (
	"testing"
	"time"

	"pgregory.net/rapid"
	"github.com/stretchr/testify/assert"
)

func TestProperty_FEC_BoundsEnforcement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		data := rapid.IntRange(0, 100).Draw(t, "data")
		parity := rapid.IntRange(0, 100).Draw(t, "parity")

		fc := NewFECController(10, 3, false)
		fc.SetShards(data, parity)

		d, p := fc.GetShards()
		assert.GreaterOrEqual(t, d, 3, "Data shards should be >= 3")
		assert.LessOrEqual(t, d, 20, "Data shards should be <= 20")
		assert.GreaterOrEqual(t, p, 1, "Parity shards should be >= 1")
		assert.LessOrEqual(t, p, 10, "Parity shards should be <= 10")
	})
}

func TestProperty_FEC_LossRateCalculation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numPackets := rapid.IntRange(10, 500).Draw(t, "numPackets")
		lostIndices := rapid.SliceOfN(rapid.IntRange(0, numPackets-1), 0, numPackets).Draw(t, "lostIndices")
		
		isLost := make(map[int]bool)
		for _, idx := range lostIndices {
			isLost[idx] = true
		}

		fc := NewFECController(10, 3, true)
		for i := 0; i < numPackets; i++ {
			fc.RecordPacket(isLost[i], 10*time.Millisecond)
		}

		stats := fc.GetStats()
		expectedLossRate := float64(len(isLost)) / float64(numPackets)
		
		assert.InDelta(t, expectedLossRate, stats.LossRate, 0.0001)
	})
}

func TestProperty_FEC_ParitySkipTiming(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		rto := time.Duration(rapid.IntRange(50, 150).Draw(t, "rtoMs")) * time.Millisecond
		isSkipExpected := rapid.Bool().Draw(t, "isSkipExpected")
		
		fc := NewFECController(10, 3, false)
		fc.SetParitySkip(true)
		
		fc.RecordDataPacket()
		if isSkipExpected {
			time.Sleep(rto + 50*time.Millisecond)
		} else {
			// Stay within RTO
			time.Sleep(rto / 2)
		}
		
		shouldSkip := fc.ShouldSkipParity(rto)
		if isSkipExpected {
			assert.True(t, shouldSkip, "Should skip if gap > RTO")
		} else {
			assert.False(t, shouldSkip, "Should not skip if gap <= RTO")
		}
	})
}

func TestProperty_FEC_ParityResume(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		fc := NewFECController(10, 3, false)
		fc.SetParitySkip(true)
		rto := 100 * time.Millisecond
		
		// Gap > RTO -> Skip
		fc.RecordDataPacket()
		time.Sleep(150 * time.Millisecond)
		assert.True(t, fc.ShouldSkipParity(rto))
		
		// Record fresh data packet -> Gap Reset
		fc.RecordDataPacket()
		assert.False(t, fc.ShouldSkipParity(rto), "Should resume parity after fresh data packet")
	})
}
