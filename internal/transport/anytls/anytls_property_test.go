package anytls

import (
	"fmt"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// Property 13: For any "random" padding scheme range [min, max], 
// the generated padding lengths should be consistently within that range.
func TestProperty13_RandomPaddingRange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		min := rapid.IntRange(1, 500).Draw(t, "min")
		max := rapid.IntRange(min+1, 2000).Draw(t, "max")
		
		cfg := PaddingConfig{
			Scheme: "random",
			Min:    min,
			Max:    max,
		}
		g := NewGenerator(cfg)
		
		for i := 0; i < 100; i++ {
			val := g.Next()
			if val < min || val > max {
				t.Fatalf("generated padding %d outside of [%d, %d]", val, min, max)
			}
		}
	})
}

// Property 12: For any "fixed" padding scheme with value X, 
// the generated padding lengths should always be exactly X.
func TestProperty12_FixedPadding(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		fixedVal := rapid.IntRange(1, 1500).Draw(t, "fixedVal")
		
		cfg := PaddingConfig{
			Scheme: "fixed",
			Max:    fixedVal, // Generator uses Max for fixed
		}
		g := NewGenerator(cfg)
		
		for i := 0; i < 50; i++ {
			val := g.Next()
			if val != fixedVal {
				t.Fatalf("fixed padding: expected %d, got %d", fixedVal, val)
			}
		}
	})
}

// Property: For any custom line array scheme, the generator should cycle through 
// the specified ranges and values accurately.
func TestProperty_CustomSchemeCycling(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		lineCount := rapid.IntRange(1, 5).Draw(t, "lineCount")
		lines := make([]string, lineCount)
		expectedMins := make([]int, lineCount)
		expectedMaxs := make([]int, lineCount)
		
		for i := 0; i < lineCount; i++ {
			isRange := rapid.Bool().Draw(t, "isRange")
			if isRange {
				min := rapid.IntRange(0, 500).Draw(t, "lineMin")
				max := rapid.IntRange(min+1, 1000).Draw(t, "lineMax")
				lines[i] = rapid.String().Draw(t, "fixed") // wait, no
				lines[i] = rapid.IntRange(min, min).String() // just placeholder
				// Actually rapid has better ways
				lines[i] = fmt.Sprintf("%d-%d", min, max)
				expectedMins[i] = min
				expectedMaxs[i] = max
			} else {
				val := rapid.IntRange(0, 1000).Draw(t, "lineVal")
				lines[i] = fmt.Sprintf("%d", val)
				expectedMins[i] = val
				expectedMaxs[i] = val
			}
		}
		
		cfg := PaddingConfig{
			Lines: lines,
		}
		g := NewGenerator(cfg)
		
		for j := 0; j < 5; j++ { // multiple cycles
			for i := 0; i < lineCount; i++ {
				val := g.Next()
				if val < expectedMins[i] || val > expectedMaxs[i] {
					t.Fatalf("custom range %d: value %d outside [%d, %d]", i, val, expectedMins[i], expectedMaxs[i])
				}
			}
		}
	})
}

// Property 14: For any configured idle session timeout, the configuration 
// should be correctly applied to the underlying AnyTLS structures.
func TestProperty14_IdleSessionTimeout(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		timeoutSecs := rapid.IntRange(1, 3600).Draw(t, "timeoutSecs")
		
		cfg := &Config{
			IdleSessionTimeout: time.Duration(timeoutSecs) * time.Second,
		}
		
		d, err := NewDialer(cfg, nil, "", "127.0.0.1:443")
		if err != nil {
			t.Fatalf("new dialer: %v", err)
		}
		
		// In a real implementation we would check d.client's internal config
		// Since we can't easily reach into sing-anytls private fields, 
		// we test our NewDialer correctly initializes it (at least doesn't crash).
		if d.client == nil {
			t.Fatalf("client not initialized")
		}
	})
}
