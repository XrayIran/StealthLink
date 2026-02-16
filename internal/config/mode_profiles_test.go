package config

import (
	"testing"
)

func TestAllModeProfiles(t *testing.T) {
	profiles := AllModeProfiles()
	if len(profiles) != 5 {
		t.Errorf("Expected 5 mode profiles, got %d", len(profiles))
	}

	expectedModes := []string{VariantHTTPPlus, VariantTCPPlus, VariantTLSPlus, VariantUDPPlus, VariantTLS}
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
		{VariantHTTPPlus, true},
		{VariantTCPPlus, true},
		{VariantTLSPlus, true},
		{VariantUDPPlus, true},
		{VariantTLS, true},
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

func TestModeHTTPPlusProfile(t *testing.T) {
	profile := Mode4aProfile

	if profile.Mode != VariantHTTPPlus {
		t.Errorf("Expected mode %s, got %s", VariantHTTPPlus, profile.Mode)
	}
	if profile.Name != "HTTP-Family (XHTTP)" {
		t.Errorf("Expected name 'HTTP-Family (XHTTP)', got %s", profile.Name)
	}
	if !profile.Capabilities.Streams {
		t.Error("Mode HTTP+ should support streams")
	}
	if profile.Defaults.MTU != 1400 {
		t.Errorf("Expected MTU 1400, got %d", profile.Defaults.MTU)
	}
}

func TestModeTCPPlusProfile(t *testing.T) {
	profile := Mode4bProfile

	if profile.Mode != VariantTCPPlus {
		t.Errorf("Expected mode %s, got %s", VariantTCPPlus, profile.Mode)
	}
	if !profile.Capabilities.Streams {
		t.Error("Mode TCP+ should support streams")
	}
	if profile.Defaults.MTU != 1400 {
		t.Errorf("Expected MTU 1400, got %d", profile.Defaults.MTU)
	}
}

func TestModeTLSPlusProfile(t *testing.T) {
	profile := Mode4cProfile

	if profile.Mode != VariantTLSPlus {
		t.Errorf("Expected mode %s, got %s", VariantTLSPlus, profile.Mode)
	}
	if !profile.Capabilities.Streams {
		t.Error("Mode TLS+ should support streams")
	}
}

func TestModeUDPPlusProfile(t *testing.T) {
	profile := Mode4dProfile

	if profile.Mode != VariantUDPPlus {
		t.Errorf("Expected mode %s, got %s", VariantUDPPlus, profile.Mode)
	}
	if !profile.Capabilities.Datagrams {
		t.Error("Mode UDP+ should support native datagrams")
	}
	if !profile.Capabilities.Capsules {
		t.Error("Mode UDP+ should support capsules")
	}
}

func TestModeTLSProfile(t *testing.T) {
	profile := Mode4eProfile

	if profile.Mode != VariantTLS {
		t.Errorf("Expected mode %s, got %s", VariantTLS, profile.Mode)
	}
	if profile.Carrier.Type != "trusttunnel" {
		t.Errorf("Expected trusttunnel carrier, got %s", profile.Carrier.Type)
	}
	if profile.Defaults.MTU != 1380 {
		t.Errorf("Expected MTU 1380, got %d", profile.Defaults.MTU)
	}
}

func TestCapabilityMatrix(t *testing.T) {
	matrix := GetCapabilityMatrix()

	if len(matrix.Capabilities) != 5 {
		t.Errorf("Expected 5 capability rows, got %d", len(matrix.Capabilities))
	}

	// Test specific capabilities
	for _, row := range matrix.Capabilities {
		switch row.Capability {
		case "Streams":
			if !row.Mode4a || !row.Mode4b || !row.Mode4c || !row.Mode4d || !row.Mode4e {
				t.Error("Streams capability mismatch")
			}
		case "Datagrams":
			if row.Mode4a || row.Mode4b || row.Mode4c || !row.Mode4d || row.Mode4e {
				t.Error("Datagrams capability mismatch")
			}
		}
	}
}

func TestDefaultModeHTTPPlusConfig(t *testing.T) {
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

func TestDefaultModeTCPPlusConfig(t *testing.T) {
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

func TestDefaultModeTLSPlusConfig(t *testing.T) {
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

func TestDefaultModeUDPPlusConfig(t *testing.T) {
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

func TestDefaultModeTLSConfig(t *testing.T) {
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
