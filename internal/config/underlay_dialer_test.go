package config

import "testing"

func TestValidateUnderlayDialer_WARPFailurePolicyConflict(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.Dialer = "warp"
	cfg.Transport.WARPDialer.Engine = "builtin"
	cfg.Transport.WARPDialer.Required = true
	cfg.Transport.WARPDialer.FailurePolicy = "fail-open"
	if err := cfg.validateUnderlayDialer(); err == nil {
		t.Fatal("expected conflict between fail-open and required=true")
	}
}

func TestValidateUnderlayDialer_WARPEngineValidation(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.Dialer = "warp"
	cfg.Transport.WARPDialer.Engine = "invalid"
	if err := cfg.validateUnderlayDialer(); err == nil {
		t.Fatal("expected invalid engine validation error")
	}
}

func TestApplyDefaults_SetsWarpFailurePolicyFromRequired(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.WARPDialer.Required = true
	cfg.applyDefaults()
	if cfg.Transport.WARPDialer.FailurePolicy != "fail-closed" {
		t.Fatalf("expected fail-closed, got %q", cfg.Transport.WARPDialer.FailurePolicy)
	}
}

func TestApplyDefaults_MapsFailurePolicyToRequired(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.WARPDialer.FailurePolicy = "fail-closed"
	cfg.applyDefaults()
	if !cfg.Transport.WARPDialer.Required {
		t.Fatal("expected required=true for fail-closed")
	}
}

func TestValidateUnderlayDialer_SOCKSRequiresAddress(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.Dialer = "socks"
	if err := cfg.validateUnderlayDialer(); err == nil {
		t.Fatal("expected socks address validation error")
	}
}
