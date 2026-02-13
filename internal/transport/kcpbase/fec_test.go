package kcpbase

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFECController_ParitySkip(t *testing.T) {
	fc := NewFECController(10, 3, false)
	fc.SetParitySkip(true)
	rto := 100 * time.Millisecond

	// No data packet recorded yet
	assert.False(t, fc.ShouldSkipParity(rto))

	// Record data packet
	fc.RecordDataPacket()
	assert.False(t, fc.ShouldSkipParity(rto), "Should not skip immediately after data packet")

	// Wait for gap < RTO (safe margin)
	time.Sleep(20 * time.Millisecond)
	assert.False(t, fc.ShouldSkipParity(rto), "Should not skip if gap < RTO")

	// Wait for gap > RTO (safe margin)
	time.Sleep(150 * time.Millisecond)
	assert.True(t, fc.ShouldSkipParity(rto), "Should skip if gap > RTO")
	
	stats := fc.GetStats()
	assert.GreaterOrEqual(t, stats.ParitySkipped, uint64(1))

	// Disable parity skip
	fc.SetParitySkip(false)
	assert.False(t, fc.ShouldSkipParity(rto), "Should not skip if disabled")
}

func TestFECController_AutoTune(t *testing.T) {
	// Start with 10 data, 3 parity
	fc := NewFECController(10, 3, true)
	
	// Simulate packets
	for i := 0; i < 10; i++ {
		fc.RecordPacket(false, 10*time.Millisecond)
	}
	
	stats := fc.GetStats()
	assert.Equal(t, uint64(10), stats.TotalPackets)
}

func TestFECController_Bounds(t *testing.T) {
	fc := NewFECController(10, 3, false)
	
	fc.SetShards(1, 0) // Should be clamped to 3, 1
	d, p := fc.GetShards()
	assert.Equal(t, 3, d)
	assert.Equal(t, 1, p)
	
	fc.SetShards(100, 100) // Should be clamped to 20, 10
	d, p = fc.GetShards()
	assert.Equal(t, 20, d)
	assert.Equal(t, 10, p)
}

func TestShardCalculator(t *testing.T) {
	sc := NewShardCalculator(10, 3, 1500)
	
	// Payload 1000 bytes
	// Shard size = (1000 + 10 - 1) / 10 = 100
	assert.Equal(t, 100, sc.CalculateShardSize(1000))
	
	// Overhead = 100 * (10 + 3) - 1000 = 1300 - 1000 = 300
	assert.Equal(t, 300, sc.CalculateTotalOverhead(1000))
}
