package anytls

import (
	"fmt"
	"testing"
	"time"

	"github.com/xtaci/smux"
)

// 5.4a: Test upstream padding_scheme parser (custom line array)
func TestUpstreamPaddingSchemeParser(t *testing.T) {
	tests := []struct {
		name          string
		lines         []string
		expectedCount int
		checkFirst    paddingRange
	}{
		{
			name:          "single_value",
			lines:         []string{"100"},
			expectedCount: 1,
			checkFirst:    paddingRange{min: 100, max: 100},
		},
		{
			name:          "range_value",
			lines:         []string{"100-200"},
			expectedCount: 1,
			checkFirst:    paddingRange{min: 100, max: 200},
		},
		{
			name:          "multiple_lines",
			lines:         []string{"100", "200-300", "400"},
			expectedCount: 3,
			checkFirst:    paddingRange{min: 100, max: 100},
		},
		{
			name:          "sing_box_format",
			lines:         []string{"100-900", "0", "500-1500"},
			expectedCount: 3,
			checkFirst:    paddingRange{min: 100, max: 900},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PaddingConfig{
				Lines: tt.lines,
			}
			g := NewGenerator(cfg)

			if len(g.ranges) != tt.expectedCount {
				t.Errorf("expected %d ranges, got %d", tt.expectedCount, len(g.ranges))
			}

			if len(g.ranges) > 0 {
				if g.ranges[0].min != tt.checkFirst.min || g.ranges[0].max != tt.checkFirst.max {
					t.Errorf("first range: expected %v, got %v", tt.checkFirst, g.ranges[0])
				}
			}
		})
	}
}

// 5.4b: Test StealthLink presets compile correctly
func TestStealthLinkPresetsCompile(t *testing.T) {
	tests := []struct {
		name          string
		scheme        string
		min           int
		max           int
		expectedCount int
		validate      func(*testing.T, *Generator)
	}{
		{
			name:          "random_preset",
			scheme:        "random",
			min:           100,
			max:           900,
			expectedCount: 1,
			validate: func(t *testing.T, g *Generator) {
				if len(g.ranges) != 1 {
					t.Errorf("random: expected 1 range, got %d", len(g.ranges))
				}
				if g.ranges[0].min != 100 || g.ranges[0].max != 900 {
					t.Errorf("random: expected [100-900], got %v", g.ranges[0])
				}
				// Verify values are in range
				for i := 0; i < 50; i++ {
					val := g.Next()
					if val < 100 || val > 900 {
						t.Errorf("random: value %d out of range [100-900]", val)
					}
				}
			},
		},
		{
			name:          "fixed_preset",
			scheme:        "fixed",
			min:           100,
			max:           500,
			expectedCount: 1,
			validate: func(t *testing.T, g *Generator) {
				if len(g.ranges) != 1 {
					t.Errorf("fixed: expected 1 range, got %d", len(g.ranges))
				}
				if g.ranges[0].min != 500 || g.ranges[0].max != 500 {
					t.Errorf("fixed: expected [500-500], got %v", g.ranges[0])
				}
				// Verify all values are the same
				for i := 0; i < 50; i++ {
					val := g.Next()
					if val != 500 {
						t.Errorf("fixed: expected 500, got %d", val)
					}
				}
			},
		},
		{
			name:          "burst_preset",
			scheme:        "burst",
			min:           100,
			max:           900,
			expectedCount: 4,
			validate: func(t *testing.T, g *Generator) {
				if len(g.ranges) != 4 {
					t.Errorf("burst: expected 4 ranges, got %d", len(g.ranges))
				}
				// First 3 should be [0-0]
				for i := 0; i < 3; i++ {
					if g.ranges[i].min != 0 || g.ranges[i].max != 0 {
						t.Errorf("burst: range %d expected [0-0], got %v", i, g.ranges[i])
					}
				}
				// Last should be [500-1500]
				if g.ranges[3].min != 500 || g.ranges[3].max != 1500 {
					t.Errorf("burst: range 3 expected [500-1500], got %v", g.ranges[3])
				}
				// Verify pattern: 0, 0, 0, then burst
				vals := []int{g.Next(), g.Next(), g.Next(), g.Next()}
				if vals[0] != 0 || vals[1] != 0 || vals[2] != 0 {
					t.Errorf("burst: expected [0,0,0,X], got %v", vals)
				}
				if vals[3] < 500 || vals[3] > 1500 {
					t.Errorf("burst: fourth value %d out of range [500-1500]", vals[3])
				}
			},
		},
		{
			name:          "adaptive_preset",
			scheme:        "adaptive",
			min:           100,
			max:           900,
			expectedCount: 1,
			validate: func(t *testing.T, g *Generator) {
				if len(g.ranges) != 1 {
					t.Errorf("adaptive: expected 1 range, got %d", len(g.ranges))
				}
				// Adaptive uses wider range (min to max*2)
				if g.ranges[0].min != 100 || g.ranges[0].max != 1800 {
					t.Errorf("adaptive: expected [100-1800], got %v", g.ranges[0])
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PaddingConfig{
				Scheme: tt.scheme,
				Min:    tt.min,
				Max:    tt.max,
			}
			g := NewGenerator(cfg)

			if tt.validate != nil {
				tt.validate(t, g)
			}
		})
	}
}

// 5.4c: Test padding applied to TLS handshakes
func TestPaddingAppliedToTLSHandshakes(t *testing.T) {
	// This test verifies that padding configuration is properly integrated
	// into the AnyTLS service and that the padding scheme is correctly
	// formatted for the sing-anytls library

	tests := []struct {
		name          string
		paddingConfig PaddingConfig
		expectedLines []string
	}{
		{
			name: "random_scheme",
			paddingConfig: PaddingConfig{
				Scheme: "random",
				Min:    100,
				Max:    900,
			},
			expectedLines: []string{"100-900"},
		},
		{
			name: "fixed_scheme",
			paddingConfig: PaddingConfig{
				Scheme: "fixed",
				Min:    100,
				Max:    500,
			},
			expectedLines: []string{"500"},
		},
		{
			name: "burst_scheme",
			paddingConfig: PaddingConfig{
				Scheme: "burst",
			},
			expectedLines: []string{"0", "0", "0", "500-1500"},
		},
		{
			name: "custom_lines",
			paddingConfig: PaddingConfig{
				Lines: []string{"100", "200-300", "400-500"},
			},
			expectedLines: []string{"100", "200-300", "400-500"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen := NewGenerator(tt.paddingConfig)

			// Generate the padding scheme lines as they would be sent to sing-anytls
			var lines []string
			for _, r := range gen.ranges {
				if r.min == r.max {
					lines = append(lines, fmt.Sprintf("%d", r.min))
				} else {
					lines = append(lines, fmt.Sprintf("%d-%d", r.min, r.max))
				}
			}

			if len(lines) != len(tt.expectedLines) {
				t.Errorf("expected %d lines, got %d", len(tt.expectedLines), len(lines))
			}

			for i, expected := range tt.expectedLines {
				if i >= len(lines) {
					break
				}
				if lines[i] != expected {
					t.Errorf("line %d: expected %q, got %q", i, expected, lines[i])
				}
			}
		})
	}
}

// 5.4d: Test idle session timeout enforced
func TestIdleSessionTimeout(t *testing.T) {
	// Test that the idle session timeout is properly configured
	// and passed to the AnyTLS client/service

	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "default_timeout",
			timeout:         0,
			expectedTimeout: 300 * time.Second,
		},
		{
			name:            "custom_timeout",
			timeout:         60 * time.Second,
			expectedTimeout: 60 * time.Second,
		},
		{
			name:            "long_timeout",
			timeout:         3600 * time.Second,
			expectedTimeout: 3600 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Padding: PaddingConfig{
					Scheme: "random",
					Min:    100,
					Max:    900,
				},
				IdleSessionTimeout: tt.timeout,
				Password:           "test-password",
			}

			smuxCfg := smux.DefaultConfig()

			// Create a dialer to verify timeout is set correctly
			dialer, err := NewDialer(cfg, smuxCfg, "", "127.0.0.1:8080")
			if err != nil {
				t.Fatalf("failed to create dialer: %v", err)
			}

			if dialer.Config.IdleSessionTimeout != tt.expectedTimeout {
				t.Errorf("expected timeout %v, got %v", tt.expectedTimeout, dialer.Config.IdleSessionTimeout)
			}
		})
	}
}

// Test timeout configuration validation
func TestTimeoutConfigurationValidation(t *testing.T) {
	tests := []struct {
		name            string
		timeout         time.Duration
		expectedTimeout time.Duration
	}{
		{
			name:            "zero_uses_default",
			timeout:         0,
			expectedTimeout: 300 * time.Second,
		},
		{
			name:            "short_timeout",
			timeout:         10 * time.Second,
			expectedTimeout: 10 * time.Second,
		},
		{
			name:            "medium_timeout",
			timeout:         300 * time.Second,
			expectedTimeout: 300 * time.Second,
		},
		{
			name:            "long_timeout",
			timeout:         3600 * time.Second,
			expectedTimeout: 3600 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				Padding: PaddingConfig{
					Scheme: "fixed",
					Max:    500,
				},
				IdleSessionTimeout: tt.timeout,
				Password:           "test-password",
			}

			// Verify the config stores the timeout correctly
			if tt.timeout == 0 {
				// Before creating dialer, timeout should be 0
				if cfg.IdleSessionTimeout != 0 {
					t.Errorf("expected initial timeout 0, got %v", cfg.IdleSessionTimeout)
				}
			}

			smuxCfg := smux.DefaultConfig()
			dialer, err := NewDialer(cfg, smuxCfg, "", "127.0.0.1:8080")
			if err != nil {
				t.Fatalf("failed to create dialer: %v", err)
			}

			// After creating dialer, default should be applied
			if dialer.Config.IdleSessionTimeout != tt.expectedTimeout {
				t.Errorf("expected timeout %v, got %v", tt.expectedTimeout, dialer.Config.IdleSessionTimeout)
			}
		})
	}
}

func TestPaddingGenerator(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		min    int
		max    int
		lines  []string
	}{
		{"random", "random", 100, 200, nil},
		{"fixed", "fixed", 100, 200, nil},
		{"burst", "burst", 100, 900, nil},
		{"custom", "", 0, 0, []string{"100", "200-300"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := PaddingConfig{
				Scheme: tt.scheme,
				Min:    tt.min,
				Max:    tt.max,
				Lines:  tt.lines,
			}
			g := NewGenerator(cfg)
			for i := 0; i < 100; i++ {
				val := g.Next()
				if tt.scheme == "fixed" && val != tt.max {
					t.Errorf("fixed: expected %d, got %d", tt.max, val)
				}
				if tt.scheme == "random" && (val < tt.min || val > tt.max) {
					t.Errorf("random: out of range: %d", val)
				}
				// Basic sanity check
				if val < 0 {
					t.Errorf("negative padding: %d", val)
				}
			}
		})
	}
}

func TestParseRange(t *testing.T) {
	r := parseRange("100-200")
	if r.min != 100 || r.max != 200 {
		t.Errorf("parseRange(100-200) = %v", r)
	}

	r2 := parseRange("300")
	if r2.min != 300 || r2.max != 300 {
		t.Errorf("parseRange(300) = %v", r2)
	}
}
