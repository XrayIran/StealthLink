package config

import (
	"encoding/base64"
	"testing"
)

func TestValidateVariantTLSMirrorServerPublicKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Behaviors.Reality.Enabled = true
	cfg.Transport.UQSP.Behaviors.Reality.Dest = "example.com"
	cfg.Transport.UQSP.Behaviors.Reality.PrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	cfg.Transport.UQSP.Behaviors.Reality.ServerPublicKey = base64.StdEncoding.EncodeToString(key)

	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("ValidateVariant returned error for valid server_public_key: %v", err)
	}
}

func TestValidateVariantTLSMirrorServerPublicKeyInvalid(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Behaviors.Reality.Enabled = true
	cfg.Transport.UQSP.Behaviors.Reality.Dest = "example.com"
	cfg.Transport.UQSP.Behaviors.Reality.PrivateKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="
	cfg.Transport.UQSP.Behaviors.Reality.ServerPublicKey = "not-a-valid-key"

	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected error for invalid server_public_key, got nil")
	}
}

func TestValidateVariantRejectsUnknownExplicitVariant(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "invalid"
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected error for unknown explicit variant")
	}
}

func TestValidateVariantRejectsLegacy4aAlias(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a"
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected legacy 4a alias to be rejected after cutover")
	}
}

func TestApplyVariantPreset4CPinsCarrierAndPQDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantTLSPlus
	cfg.applyDefaults()

	if cfg.Transport.UQSP.Carrier.Type != "xhttp" {
		t.Fatalf("expected %s carrier xhttp, got %q", VariantTLSPlus, cfg.Transport.UQSP.Carrier.Type)
	}
	if !cfg.Transport.UQSP.Behaviors.Vision.Enabled {
		t.Fatalf("expected vision enabled for %s preset", VariantTLSPlus)
	}
	if !cfg.Transport.UQSP.Security.PQKEM {
		t.Fatalf("expected pq_kem enabled for %s preset", VariantTLSPlus)
	}
	if !cfg.Transport.UQSP.Behaviors.TLSMirror.Enabled {
		t.Fatalf("expected tlsmirror enabled by default for %s preset", VariantTLSPlus)
	}
}

func TestValidateVariantRawTCPAllowsFakeTCPCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantTCPPlus
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("expected faketcp carrier to validate for %s, got: %v", VariantTCPPlus, err)
	}
}

func TestGetVariantDetectsFakeTCPAs4B(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	if got := cfg.GetVariant(); got != 1 {
		t.Fatalf("expected variant 1 (%s) for faketcp carrier, got %d", VariantTCPPlus, got)
	}
}

func TestApplyVariantPreset4EDefaultsToTrustTunnel(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantTLS
	cfg.applyDefaults()

	if cfg.Transport.UQSP.Carrier.Type != "trusttunnel" {
		t.Fatalf("expected %s carrier trusttunnel, got %q", VariantTLS, cfg.Transport.UQSP.Carrier.Type)
	}
	if !cfg.Transport.UQSP.Behaviors.CSTP.Enabled {
		t.Fatalf("expected CSTP enabled for %s preset", VariantTLS)
	}
}

func TestVariantCanBeSelectedFromTransportProfile(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.VariantProfile = VariantTLS
	cfg.applyDefaults()

	if got := cfg.GetVariant(); got != 4 {
		t.Fatalf("expected variant 4 from transport.uqsp.variant_profile, got %d", got)
	}
}

func TestValidateVariantDetectsConflictBetweenSelectors(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantHTTPPlus
	cfg.Transport.UQSP.VariantProfile = VariantUDPPlus
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected conflict validation error when variant selectors disagree")
	}
}

func TestLegacyNumericVariantRejected(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "3"
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected numeric variant to be rejected after cutover")
	}
}

func TestGetVariantDetectsAnyTLSAs4C(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled = true
	if got := cfg.GetVariant(); got != 2 {
		t.Fatalf("expected variant 2 (%s) for anytls behavior, got %d", VariantTLSPlus, got)
	}
}

func TestValidateVariantTLSMirrorRequiresAnyTLSPassword(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantTLSPlus
	cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled = true
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = ""
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected anytls password validation error")
	}
}

func TestValidateVariant4aRejectsIncompatibleCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantHTTPPlus
	cfg.Transport.UQSP.Carrier.Type = "trusttunnel"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatalf("expected %s carrier validation error", VariantHTTPPlus)
	}
}

func TestValidateVariant4aAllowsExplicitQUICCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantHTTPPlus
	cfg.Transport.UQSP.Carrier.Type = "quic"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("expected explicit quic carrier to validate for %s, got: %v", VariantHTTPPlus, err)
	}
}

func TestValidateVariant4eAllowsAnyTLSCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantTLS
	cfg.Transport.UQSP.Carrier.Type = "anytls"
	cfg.Transport.UQSP.Behaviors.CSTP.Enabled = true
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("expected anytls carrier to validate for %s, got: %v", VariantTLS, err)
	}
}

func TestValidateVariantTLSRequiresReverseForChiselCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantTLS
	cfg.Transport.UQSP.Carrier.Type = "chisel"
	cfg.Transport.UQSP.Behaviors.CSTP.Enabled = true
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatalf("expected %s chisel carrier to require reverse mode", VariantTLS)
	}
}

func TestValidateVariantTLSAllowsChiselCarrierInReverseMode(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Role = "gateway"
	cfg.Variant = VariantTLS
	cfg.Transport.UQSP.Carrier.Type = "chisel"
	cfg.Transport.UQSP.Behaviors.CSTP.Enabled = true
	cfg.Transport.UQSP.Reverse.Enabled = true
	cfg.Transport.UQSP.Reverse.Role = "client"
	cfg.Transport.UQSP.Reverse.AuthToken = "test-token"
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("expected %s chisel carrier to validate in reverse mode, got: %v", VariantTLS, err)
	}
}

func TestValidateVariantPolicyReverseRequiresAuthToken(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantHTTPPlus
	cfg.Transport.UQSP.Carrier.Type = "xhttp"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	cfg.Transport.UQSP.VariantPolicy = map[string]UQSPVariantPolicy{
		VariantHTTPPlus: {ReverseEnabled: boolPtr(true)},
	}
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected reverse auth token validation error for variant policy")
	}
}

func TestValidateVariantPolicyWarpDefaultsToFailClosed(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = VariantHTTPPlus
	cfg.Transport.UQSP.Carrier.Type = "xhttp"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	cfg.Transport.UQSP.VariantPolicy = map[string]UQSPVariantPolicy{
		VariantHTTPPlus: {WARPEnabled: boolPtr(true)},
	}
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if !cfg.WARP.Required {
		t.Fatal("expected variant-scoped warp to force fail-closed semantics")
	}
}

func boolPtr(v bool) *bool { return &v }
