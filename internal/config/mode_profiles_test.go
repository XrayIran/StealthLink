package config

import (
	"testing"
)

func TestAllModeProfiles(t *testing.T) {
	profiles := AllModeProfiles()
	if len(profiles) != 5 {
		t.Errorf("Expected 5 mode profiles, got %d", len(profiles))
	}

	expectedModes := []string{"4a", "4b", "4c", "4d", "4e"}
	for i, profile := range profiles {
		if profile.Mode != expectedModes[i] {
			t.Errorf("Expected mode %s at index %d, got %s", expectedModes[i], i, profile.Mode)
		}
	}
}

func TestGetModeProfile(t *testing.T) {
	tests := []struct {
		mode        string
		shouldExist bool
	}{
		{"4a", true},
		{"4b", true},
		{"4c", true},
		{"4d", true},
		{"4e", true},
		{"4f", false},
		{"invalid", false},
	}

	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			profile, exists := GetModeProfile(tt.mode)
			if exists != tt.shouldExist {
				t.Errorf("GetModeProfile(%s): expected exists=%v, got %v", tt.mode, tt.shouldExist, exists)
			}
			if exists && profile.Mode != tt.mode {
				t.Errorf("GetModeProfile(%s): expected mode=%s, got %s", tt.mode, tt.mode, profile.Mode)
			}
		})
	}
}

func TestMode4aProfile(t *testing.T) {
	profile := Mode4aProfile

	if profile.Mode != "4a" {
		t.Errorf("Expected mode 4a, got %s", profile.Mode)
	}
	if profile.Name != "XHTTP + Domain Fronting" {
		t.Errorf("Expected name 'XHTTP + Domain Fronting', got %s", profile.Name)
	}
	if !profile.Capabilities.StreamOriented {
		t.Error("Mode 4a should be stream-oriented")
	}
	if !profile.Capabilities.ZeroRTT {
		t.Error("Mode 4a should support 0-RTT")
	}
	if !profile.Capabilities.Fronting {
		t.Error("Mode 4a should support fronting")
	}
	if profile.Defaults.MTU != 1400 {
		t.Errorf("Expected MTU 1400, got %d", profile.Defaults.MTU)
	}
}

func TestMode4bProfile(t *testing.T) {
	profile := Mode4bProfile

	if profile.Mode != "4b" {
		t.Errorf("Expected mode 4b, got %s", profile.Mode)
	}
	if profile.Capabilities.StreamOriented {
		t.Error("Mode 4b should not be stream-oriented")
	}
	if !profile.Capabilities.ReplayProtection {
		t.Error("Mode 4b should have replay protection")
	}
	if profile.Defaults.MTU != 1460 {
		t.Errorf("Expected MTU 1460, got %d", profile.Defaults.MTU)
	}
}

func TestMode4cProfile(t *testing.T) {
	profile := Mode4cProfile

	if profile.Mode != "4c" {
		t.Errorf("Expected mode 4c, got %s", profile.Mode)
	}
	if !profile.Capabilities.CoverTraffic {
		t.Error("Mode 4c should support cover traffic")
	}
	if !profile.Defaults.PaddingEnabled {
		t.Error("Mode 4c should have padding enabled by default")
	}
}

func TestMode4dProfile(t *testing.T) {
	profile := Mode4dProfile

	if profile.Mode != "4d" {
		t.Errorf("Expected mode 4d, got %s", profile.Mode)
	}
	if !profile.Capabilities.PathMigration {
		t.Error("Mode 4d should support path migration")
	}
	if !profile.Capabilities.Multipath {
		t.Error("Mode 4d should support multipath")
	}
	if profile.Carrier.CongestionControl != "brutal" {
		t.Errorf("Expected brutal CC, got %s", profile.Carrier.CongestionControl)
	}
}

func TestMode4eProfile(t *testing.T) {
	profile := Mode4eProfile

	if profile.Mode != "4e" {
		t.Errorf("Expected mode 4e, got %s", profile.Mode)
	}
	if profile.Carrier.Mux != "trusttunnel-icmp" {
		t.Errorf("Expected trusttunnel-icmp mux, got %s", profile.Carrier.Mux)
	}
	if profile.Defaults.MTU != 1380 {
		t.Errorf("Expected MTU 1380, got %d", profile.Defaults.MTU)
	}
}

func TestCapabilityMatrix(t *testing.T) {
	matrix := GetCapabilityMatrix()

	if len(matrix.Capabilities) != 8 {
		t.Errorf("Expected 8 capability rows, got %d", len(matrix.Capabilities))
	}

	// Test specific capabilities
	for _, row := range matrix.Capabilities {
		switch row.Capability {
		case "StreamOriented":
			if !row.Mode4a || row.Mode4b || !row.Mode4c || !row.Mode4d || !row.Mode4e {
				t.Error("StreamOriented capability mismatch")
			}
		case "Fronting":
			if !row.Mode4a || row.Mode4b || row.Mode4c || row.Mode4d || row.Mode4e {
				t.Error("Fronting capability mismatch")
			}
		case "PathMigration":
			if row.Mode4a || row.Mode4b || row.Mode4c || !row.Mode4d || row.Mode4e {
				t.Error("PathMigration capability mismatch")
			}
		}
	}
}

func TestDefaultMode4aConfig(t *testing.T) {
	config := DefaultMode4aConfig()

	if config.SessionPlacement != "header" {
		t.Errorf("Expected header placement, got %s", config.SessionPlacement)
	}
	if config.CMaxReuseTimes != 32 {
		t.Errorf("Expected CMaxReuseTimes=32, got %d", config.CMaxReuseTimes)
	}
	if !config.XmuxEnabled {
		t.Error("Xmux should be enabled by default")
	}
}

func TestDefaultMode4bConfig(t *testing.T) {
	config := DefaultMode4bConfig()

	if config.AEADMode != "chacha20poly1305" {
		t.Errorf("Expected chacha20poly1305, got %s", config.AEADMode)
	}
	if !config.BatchIOEnabled {
		t.Error("Batch I/O should be enabled by default")
	}
	if config.BatchSize != 32 {
		t.Errorf("Expected BatchSize=32, got %d", config.BatchSize)
	}
}

func TestDefaultMode4cConfig(t *testing.T) {
	config := DefaultMode4cConfig()

	if config.TLSMode != "reality" {
		t.Errorf("Expected reality mode, got %s", config.TLSMode)
	}
	if config.SpiderConcurrency != 4 {
		t.Errorf("Expected SpiderConcurrency=4, got %d", config.SpiderConcurrency)
	}
	if config.PaddingScheme != "random" {
		t.Errorf("Expected random padding, got %s", config.PaddingScheme)
	}
}

func TestDefaultMode4dConfig(t *testing.T) {
	config := DefaultMode4dConfig()

	if !config.BrutalEnabled {
		t.Error("Brutal CC should be enabled by default")
	}
	if !config.FECEnabled {
		t.Error("FEC should be enabled by default")
	}
	if !config.AutoTune {
		t.Error("FEC auto-tune should be enabled by default")
	}
	if !config.EntropyAccelerated {
		t.Error("Hardware entropy should be enabled by default")
	}
}

func TestDefaultMode4eConfig(t *testing.T) {
	config := DefaultMode4eConfig()

	if config.HTTPVersion != "http2" {
		t.Errorf("Expected http2, got %s", config.HTTPVersion)
	}
	if !config.SessionRecoveryEnabled {
		t.Error("Session recovery should be enabled by default")
	}
	if config.RecoveryTimeout != 60 {
		t.Errorf("Expected RecoveryTimeout=60, got %d", config.RecoveryTimeout)
	}
}
