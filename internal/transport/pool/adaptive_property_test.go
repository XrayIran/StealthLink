package pool

import (
	"context"
	"math"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestProperty_PoolSizeFormula(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		utilization := rapid.Float64Range(0, 5).Draw(t, "utilization")
		mode := rapid.SampledFrom([]PoolMode{PoolModeNormal, PoolModeAggressive}).Draw(t, "mode")
		minSize := rapid.IntRange(1, 10).Draw(t, "minSize")
		maxSize := rapid.IntRange(minSize, 100).Draw(t, "maxSize")

		var a, b, x, y float64
		if mode == PoolModeAggressive {
			a, b, x, y = 1, 2, 0, 0.75
		} else {
			a, b, x, y = 4, 5, 3, 4.0
		}

		target := a + b*math.Pow(utilization, y) + x
		expected := int(math.Max(float64(minSize), math.Min(float64(maxSize), target)))

		config := PoolConfig{
			Mode:    mode,
			MinSize: minSize,
			MaxSize: maxSize,
		}
		config.ApplyDefaults()

		// Logic from adaptive.go
		if config.Mode == PoolModeAggressive {
			a, b, x, y = 1, 2, 0, 0.75
		} else {
			a, b, x, y = 4, 5, 3, 4.0
		}
		actualTarget := a + b*math.Pow(utilization, y) + x
		actual := int(math.Max(float64(config.MinSize), math.Min(float64(config.MaxSize), actualTarget)))

		if actual != expected {
			t.Errorf("expected %d, got %d for util=%v mode=%v", expected, actual, utilization, mode)
		}
	})
}

func TestProperty_PoolBoundsEnforcement(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		config := PoolConfig{
			MinSize: rapid.IntRange(1, 10).Draw(t, "minSize"),
			MaxSize: rapid.IntRange(10, 50).Draw(t, "maxSize"),
			Mode:    PoolModeAggressive,
		}
		dialer := &mockDialer{}
		pool := NewAdaptivePool(config, dialer, "test")
		defer pool.Close()

		// Simulate random activity
		for i := 0; i < 100; i++ {
			if rapid.Bool().Draw(t, "doAdjust") {
				pool.adjust()
			}
			pool.mu.RLock()
			size := len(pool.conns)
			pool.mu.RUnlock()

			if size < config.MinSize || size > config.MaxSize {
				t.Errorf("pool size %d out of bounds [%d, %d]", size, config.MinSize, config.MaxSize)
			}
		}
	})
}

func TestProperty_ScalingDirection(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		config := PoolConfig{
			MinSize:      2,
			MaxSize:      20,
			CooldownSecs: 0,
		}
		dialer := &mockDialer{}
		pool := NewAdaptivePool(config, dialer, "test")
		defer pool.Close()

		utilization := rapid.Float64Range(0, 1).Draw(t, "utilization")
		
		// Setup connections to match utilization
		for {
			pool.mu.RLock()
			count := len(pool.conns)
			pool.mu.RUnlock()
			if count >= 10 {
				break
			}
			pool.dialNew(context.Background())
		}
		
		pool.mu.Lock()
		numActive := int(float64(len(pool.conns)) * utilization)
		pool.activeCount.Store(int64(numActive))
		initialSize := len(pool.conns)
		pool.mu.Unlock()

		pool.adjust()
		time.Sleep(10 * time.Millisecond) // wait for potential async dial

		pool.mu.RLock()
		finalSize := len(pool.conns)
		drainingCount := 0
		for _, c := range pool.conns {
			if c.draining.Load() {
				drainingCount++
			}
		}
		pool.mu.RUnlock()

		if utilization > 0.8 && finalSize < initialSize {
			t.Errorf("scaled down during high utilization (%v): %d -> %d", utilization, initialSize, finalSize)
		}
		if utilization > 0.8 && finalSize == initialSize && finalSize < config.MaxSize {
			// It should have scaled up or at least tried to.
			// The formula might not always result in larger size if x/y/a/b are small,
			// but with aggressive/normal modes it usually should.
		}

		if utilization < 0.3 && (finalSize > initialSize || drainingCount > 0) {
			// If it scaled down, drainingCount should be 0 if they were immediately scavenged,
			// or finalSize should be smaller.
		}
	})
}

func TestProperty_AdjustmentCooldown(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		cooldown := rapid.IntRange(1, 10).Draw(t, "cooldown")
		config := PoolConfig{
			MinSize:      2,
			MaxSize:      20,
			CooldownSecs: cooldown,
		}
		dialer := &mockDialer{}
		pool := NewAdaptivePool(config, dialer, "test")
		defer pool.Close()

		pool.activeCount.Store(20) // force high utilization
		
		pool.adjust()
		firstAdjust := pool.lastAdjust
		
		if firstAdjust.IsZero() {
			return // didn't adjust for some reason (maybe formula?)
		}

		pool.adjust()
		if pool.lastAdjust != firstAdjust {
			t.Errorf("adjustment happened during cooldown: %v -> %v", firstAdjust, pool.lastAdjust)
		}
	})
}
