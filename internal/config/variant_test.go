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

func TestApplyVariantPreset4CPinsCarrierAndPQDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4c"
	cfg.applyDefaults()

	if cfg.Transport.UQSP.Carrier.Type != "xhttp" {
		t.Fatalf("expected 4c carrier xhttp, got %q", cfg.Transport.UQSP.Carrier.Type)
	}
	if !cfg.Transport.UQSP.Behaviors.Vision.Enabled {
		t.Fatal("expected vision enabled for 4c preset")
	}
	if !cfg.Transport.UQSP.Security.PQKEM {
		t.Fatal("expected pq_kem enabled for 4c preset")
	}
	if !cfg.Transport.UQSP.Behaviors.TLSMirror.Enabled {
		t.Fatal("expected tlsmirror enabled by default for 4c preset")
	}
}

func TestValidateVariantRawTCPAllowsFakeTCPCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4b"
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("expected faketcp carrier to validate for 4b, got: %v", err)
	}
}

func TestGetVariantDetectsFakeTCPAs4B(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	if got := cfg.GetVariant(); got != 1 {
		t.Fatalf("expected variant 1 (4b) for faketcp carrier, got %d", got)
	}
}

func TestApplyVariantPreset4EDefaultsToTrustTunnel(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4e"
	cfg.applyDefaults()

	if cfg.Transport.UQSP.Carrier.Type != "trusttunnel" {
		t.Fatalf("expected 4e carrier trusttunnel, got %q", cfg.Transport.UQSP.Carrier.Type)
	}
	if !cfg.Transport.UQSP.Behaviors.CSTP.Enabled {
		t.Fatal("expected CSTP enabled for 4e preset")
	}
}

func TestVariantCanBeSelectedFromTransportProfile(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.VariantProfile = "4e"
	cfg.applyDefaults()

	if got := cfg.GetVariant(); got != 4 {
		t.Fatalf("expected variant 4 from transport.uqsp.variant_profile, got %d", got)
	}
}

func TestValidateVariantDetectsConflictBetweenSelectors(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a"
	cfg.Transport.UQSP.VariantProfile = "4d"
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected conflict validation error when variant selectors disagree")
	}
}

func TestLegacyNumericVariantStillAccepted(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "3" // Backward compatibility with older helpers.
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("expected numeric variant to remain valid, got: %v", err)
	}
}

func TestGetVariantDetectsAnyTLSAs4C(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled = true
	if got := cfg.GetVariant(); got != 2 {
		t.Fatalf("expected variant 2 (4c) for anytls behavior, got %d", got)
	}
}

func TestValidateVariantTLSMirrorRequiresAnyTLSPassword(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4c"
	cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled = true
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = ""
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected anytls password validation error")
	}
}

func TestValidateVariant4aRejectsNonXHTTPCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a"
	cfg.Transport.UQSP.Carrier.Type = "quic"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected 4a carrier validation error")
	}
}

func TestValidateVariantPolicyReverseRequiresAuthToken(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a"
	cfg.Transport.UQSP.Carrier.Type = "xhttp"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	cfg.Transport.UQSP.VariantPolicy = map[string]UQSPVariantPolicy{
		"4a": {ReverseEnabled: boolPtr(true)},
	}
	if err := cfg.ValidateVariant(); err == nil {
		t.Fatal("expected reverse auth token validation error for variant policy")
	}
}

func TestValidateVariantPolicyWarpDefaultsToFailClosed(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a"
	cfg.Transport.UQSP.Carrier.Type = "xhttp"
	cfg.Transport.UQSP.Behaviors.Vision.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.Enabled = true
	cfg.Transport.UQSP.Behaviors.ECH.PublicName = "cloudflare-ech.com"
	cfg.Transport.UQSP.VariantPolicy = map[string]UQSPVariantPolicy{
		"4a": {WARPEnabled: boolPtr(true)},
	}
	if err := cfg.ValidateVariant(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
	if !cfg.WARP.Required {
		t.Fatal("expected variant-scoped warp to force fail-closed semantics")
	}
}

func boolPtr(v bool) *bool { return &v }
