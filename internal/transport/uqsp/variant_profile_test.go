package uqsp

import (
	"testing"

	"stealthlink/internal/config"
)

func TestApplyVariantProfile4cPrefersAnyTLSWhenPasswordPresent(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.VariantProfile = "4c"
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = "secret"

	ApplyVariantProfile(cfg)

	if !cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled {
		t.Fatal("expected anytls to be enabled for 4c when password is present")
	}
	if cfg.Transport.UQSP.Behaviors.TLSMirror.Enabled {
		t.Fatal("expected tlsmirror fallback to stay disabled when anytls is selected")
	}
}

func TestApplyVariantProfile4eEnablesAnyTLSFromPassword(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.VariantProfile = "4e"
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = "secret"

	ApplyVariantProfile(cfg)

	if !cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled {
		t.Fatal("expected anytls to be enabled for 4e when password is present")
	}
	if cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMin != 8 || cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMax != 64 {
		t.Fatalf("unexpected anytls padding defaults: min=%d max=%d",
			cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMin,
			cfg.Transport.UQSP.Behaviors.AnyTLS.PaddingMax,
		)
	}
}
