package uqsp

import (
	"strings"
	"testing"

	"stealthlink/internal/config"
)

func TestBuildRawCarrierOverlaysIncludes4BBaseline(t *testing.T) {
	cfg := &config.UQSPConfig{}
	cfg.Carrier.Type = "rawtcp"
	cfg.Obfuscation.Profile = "adaptive"
	cfg.Behaviors.AWG.Enabled = true
	cfg.Behaviors.QPP.Enabled = true
	cfg.Behaviors.QPP.Key = "raw-overlay-qpp-test-key-32-bytes!"
	cfg.Behaviors.ViolatedTCP.Enabled = true

	overlays, err := buildRawCarrierOverlays(cfg, "shared-token", false)
	if err != nil {
		t.Fatalf("buildRawCarrierOverlays() error = %v", err)
	}
	if len(overlays) == 0 {
		t.Fatal("expected overlays for raw carrier")
	}

	hasGFW := false
	hasMorphing := false
	hasAWG := false
	hasQPP := false
	hasViolatedTCP := false
	for _, ov := range overlays {
		name := strings.ToLower(strings.TrimSpace(ov.Name()))
		switch name {
		case "gfwresist_tcp":
			hasGFW = true
		case "morphing":
			hasMorphing = true
		case "awg":
			hasAWG = true
		case "qpp":
			hasQPP = true
		case "violated_tcp":
			hasViolatedTCP = true
		}
	}
	if !hasGFW {
		t.Fatal("expected gfwresist_tcp overlay for raw carrier")
	}
	if !hasMorphing {
		t.Fatal("expected morphing overlay for obfuscation profile")
	}
	if !hasAWG {
		t.Fatal("expected awg overlay when enabled")
	}
	if !hasQPP {
		t.Fatal("expected qpp overlay when enabled with key")
	}
	if !hasViolatedTCP {
		t.Fatal("expected violated_tcp overlay when enabled")
	}
}

func TestApplyObfs4DerivedDefaultsFromToken(t *testing.T) {
	cfg := &config.Obfs4BehaviorConfig{}
	applyObfs4DerivedDefaults(cfg, "token-123")
	if strings.TrimSpace(cfg.Seed) == "" {
		t.Fatal("expected derived obfs4 seed")
	}
	if strings.TrimSpace(cfg.NodeID) == "" {
		t.Fatal("expected derived obfs4 node_id")
	}
}
