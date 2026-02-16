package uqsp

import (
	"testing"

	"stealthlink/internal/config"
)

func TestApplyVariantProfileTLSPlusPrefersAnyTLSWhenPasswordPresent(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.VariantProfile = config.VariantTLSPlus
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = "secret"

	ApplyVariantProfile(cfg)

	if !cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled {
		t.Fatal("expected anytls to be enabled for TLS+ when password is present")
	}
	if cfg.Transport.UQSP.Behaviors.TLSMirror.Enabled {
		t.Fatal("expected tlsmirror fallback to stay disabled when anytls is selected")
	}
}

func TestApplyVariantProfileTLSEnablesAnyTLSFromPassword(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.VariantProfile = config.VariantTLS
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = "secret"

	ApplyVariantProfile(cfg)

	if !cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled {
		t.Fatal("expected anytls to be enabled for TLS when password is present")
	}
	if cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMin != 8 || cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMax != 64 {
		t.Fatalf("unexpected anytls padding defaults: min=%d max=%d",
			cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMin,
			cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMax,
		)
	}
}
