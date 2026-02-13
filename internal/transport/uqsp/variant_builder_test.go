package uqsp

import (
	"crypto/tls"
	"strings"
	"testing"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/uqsp/behavior"

	"github.com/xtaci/smux"
)

func TestVariantBuilderBuildAllVariants(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "quic"

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	variants := []ProtocolVariant{
		VariantXHTTP_TLS,
		VariantTLSMirror,
		VariantUDP,
	}

	for _, v := range variants {
		v := v
		t.Run(VariantName(v), func(t *testing.T) {
			proto, err := builder.Build(v)
			if err != nil {
				t.Fatalf("build variant %s: %v", VariantName(v), err)
			}
			if proto == nil || proto.variant.Carrier == nil {
				t.Fatalf("variant %s has nil carrier", VariantName(v))
			}
		})
	}
}

func TestVariantBuilderDefaultsForCarrierType(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = ""

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	tests := []ProtocolVariant{
		VariantXHTTP_TLS,
		VariantTrust,
	}

	for _, v := range tests {
		v := v
		t.Run(VariantName(v), func(t *testing.T) {
			proto, err := builder.Build(v)
			if err != nil {
				t.Fatalf("build variant %s: %v", VariantName(v), err)
			}
			if proto.variant.Carrier == nil {
				t.Fatalf("variant %s resolved to nil carrier", VariantName(v))
			}
		})
	}
}

func TestVariantBuilderReverseAndWARPWiring(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "quic"
	cfg.Transport.UQSP.Reverse.Enabled = true
	cfg.Transport.UQSP.Reverse.Role = "listener"
	cfg.Transport.UQSP.Reverse.ServerAddress = "127.0.0.1:0"
	cfg.WARP.Enabled = true

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantXHTTP_TLS)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if !proto.variant.EnableReverse || proto.variant.ReverseMode == nil {
		t.Fatalf("reverse mode not wired into variant")
	}
	if !proto.variant.EnableWARP || proto.variant.WARPConfig == nil {
		t.Fatalf("WARP config not wired into variant")
	}
}

func TestVariantBuilder4AIncludesGFWResistTLS(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "xhttp"

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantXHTTP_TLS)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if !containsOverlay(proto.variant.Behaviors, "gfwresist_tls") {
		t.Fatalf("expected gfwresist_tls overlay in 4a")
	}
}

func TestVariantBuilder4BIncludesGFWResistTCP(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "rawtcp"

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantRawTCP)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if !containsOverlay(proto.variant.Behaviors, "gfwresist_tcp") {
		t.Fatalf("expected gfwresist_tcp overlay in 4b")
	}
}

func TestVariantBuilder4CComposesMultipleTLSLookAlikes(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "xhttp"
	cfg.Transport.UQSP.Behaviors.Reality.Enabled = true
	cfg.Transport.UQSP.Behaviors.Reality.Dest = "www.microsoft.com:443"
	cfg.Transport.UQSP.Behaviors.Reality.PrivateKey = "test-private-key"
	cfg.Transport.UQSP.Behaviors.ShadowTLS.Enabled = true
	cfg.Transport.UQSP.Behaviors.ShadowTLS.Password = "test-password"
	cfg.Transport.UQSP.Behaviors.TLSMirror.Enabled = true

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantTLSMirror)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if !containsOverlay(proto.variant.Behaviors, "reality") {
		t.Fatalf("expected reality overlay in 4c")
	}
	if !containsOverlay(proto.variant.Behaviors, "shadowtls") {
		t.Fatalf("expected shadowtls overlay in 4c")
	}
	if !containsOverlay(proto.variant.Behaviors, "tlsmirror") {
		t.Fatalf("expected tlsmirror overlay in 4c")
	}
}

func TestVariantBuilder4DSkipsSalamanderWhenKeyMissing(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "quic"
	cfg.Transport.UQSP.Obfuscation.Profile = "adaptive"
	cfg.Transport.UQSP.Obfuscation.SalamanderKey = ""

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantUDP)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if containsOverlay(proto.variant.Behaviors, "salamander") {
		t.Fatalf("did not expect salamander overlay without key")
	}
}

func TestBuildVariantForRoleRejectsClientOnlyCarrierForGateway(t *testing.T) {
	cfg := &config.Config{}
	cfg.Role = "gateway"
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Carrier.Type = "xhttp" // client-only carrier

	_, _, err := BuildVariantForRole(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "token")
	if err == nil {
		t.Fatal("expected error for gateway using client-only xhttp carrier")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "does not support listen role") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildVariantForRoleRejectsDefault4AForGatewayWithoutReverse(t *testing.T) {
	cfg := &config.Config{}
	cfg.Role = "gateway"
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a" // default carrier resolves to xhttp (dial-only)

	_, _, err := BuildVariantForRole(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "token")
	if err == nil {
		t.Fatal("expected error for gateway 4a without reverse mode")
	}
}

func TestBuildVariantForRoleAllowsGateway4AWithReverse(t *testing.T) {
	cfg := &config.Config{}
	cfg.Role = "gateway"
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "4a"
	cfg.Transport.UQSP.Reverse.Enabled = true
	cfg.Transport.UQSP.Reverse.Role = "listener"
	cfg.Transport.UQSP.Reverse.ServerAddress = "127.0.0.1:0"

	proto, variant, err := BuildVariantForRole(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "token")
	if err != nil {
		t.Fatalf("expected reverse-enabled gateway 4a to build, got error: %v", err)
	}
	if proto == nil {
		t.Fatal("expected protocol, got nil")
	}
	if variant != VariantXHTTP_TLS {
		t.Fatalf("expected VariantXHTTP_TLS, got %v", variant)
	}
}

func TestVariantBuilder4EIncludesCSTPAndTLSFrag(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = "trusttunnel"
	cfg.Transport.UQSP.Behaviors.CSTP.Enabled = true
	cfg.Transport.UQSP.Behaviors.TLSFrag.Enabled = true

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantTrust)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if !containsOverlay(proto.variant.Behaviors, "cstp") {
		t.Fatalf("expected cstp overlay in 4e")
	}
	if !containsOverlay(proto.variant.Behaviors, "tlsfrag") {
		t.Fatalf("expected tlsfrag overlay in 4e")
	}
}

func TestVariantBuilder4EDefaultsToTrustTunnelCarrier(t *testing.T) {
	cfg := &config.Config{}
	cfg.Transport.UQSP.Carrier.Type = ""

	builder := NewVariantBuilder(cfg, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-test"},
	}, smux.DefaultConfig(), "")

	proto, err := builder.Build(VariantTrust)
	if err != nil {
		t.Fatalf("build variant: %v", err)
	}
	if proto == nil || proto.variant.Carrier == nil {
		t.Fatalf("variant 4e resolved to nil protocol or carrier")
	}
}

func TestVariantBuilderPerModePolicyOverrides(t *testing.T) {
	mkBuilder := func(cfg *config.Config) *VariantBuilder {
		return NewVariantBuilder(cfg, &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"uqsp-test"},
		}, smux.DefaultConfig(), "")
	}
	carrierFor := func(v ProtocolVariant) string {
		switch v {
		case VariantRawTCP:
			return "rawtcp"
		case VariantTrust:
			return "trusttunnel"
		default:
			return "quic"
		}
	}

	variantCases := []struct {
		name    string
		variant ProtocolVariant
		key     string
	}{
		{name: "4a", variant: VariantXHTTP_TLS, key: "4a"},
		{name: "4b", variant: VariantRawTCP, key: "4b"},
		{name: "4c", variant: VariantTLSMirror, key: "4c"},
		{name: "4d", variant: VariantUDP, key: "4d"},
		{name: "4e", variant: VariantTrust, key: "4e"},
	}

	t.Run("disable specific mode when global enabled", func(t *testing.T) {
		for _, tc := range variantCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Transport.UQSP.Carrier.Type = carrierFor(tc.variant)
				cfg.WARP.Enabled = true
				cfg.Transport.UQSP.Reverse.Enabled = true
				cfg.Transport.UQSP.VariantPolicy = map[string]config.UQSPVariantPolicy{
					tc.key: {WARPEnabled: boolPtr(false), ReverseEnabled: boolPtr(false)},
				}

				proto, err := mkBuilder(cfg).Build(tc.variant)
				if err != nil {
					t.Fatalf("build variant %s: %v", tc.name, err)
				}
				if proto.variant.EnableWARP {
					t.Fatalf("expected WARP disabled by variant policy for %s", tc.name)
				}
				if proto.variant.EnableReverse {
					t.Fatalf("expected reverse disabled by variant policy for %s", tc.name)
				}
			})
		}
	})

	t.Run("enable specific mode when global disabled", func(t *testing.T) {
		for _, tc := range variantCases {
			tc := tc
			t.Run(tc.name, func(t *testing.T) {
				cfg := &config.Config{}
				cfg.Transport.UQSP.Carrier.Type = carrierFor(tc.variant)
				cfg.WARP.Enabled = false
				cfg.Transport.UQSP.Reverse.Enabled = false
				cfg.Transport.UQSP.Reverse.Role = "listener"
				cfg.Transport.UQSP.Reverse.ServerAddress = "127.0.0.1:0"
				cfg.Transport.UQSP.VariantPolicy = map[string]config.UQSPVariantPolicy{
					tc.key: {WARPEnabled: boolPtr(true), ReverseEnabled: boolPtr(true)},
				}

				proto, err := mkBuilder(cfg).Build(tc.variant)
				if err != nil {
					t.Fatalf("build variant %s: %v", tc.name, err)
				}
				if !proto.variant.EnableWARP {
					t.Fatalf("expected WARP enabled by variant policy for %s", tc.name)
				}
				if !proto.variant.EnableReverse {
					t.Fatalf("expected reverse enabled by variant policy for %s", tc.name)
				}
				if proto.variant.ReverseMode == nil {
					t.Fatalf("expected reverse mode to be configured for %s", tc.name)
				}

				// 4a/4e should opt into HTTP registration in reverse mode.
				expectHTTPReg := tc.variant == VariantXHTTP_TLS || tc.variant == VariantTrust
				if proto.variant.ReverseMode.UseHTTPRegistration != expectHTTPReg {
					t.Fatalf("reverse HTTP registration mismatch for %s: got=%v want=%v",
						tc.name, proto.variant.ReverseMode.UseHTTPRegistration, expectHTTPReg)
				}
			})
		}
	})
}

func TestVariantPolicyKeysMatchAllKnownVariants(t *testing.T) {
	cases := []struct {
		variant ProtocolVariant
		wantKey string
	}{
		{VariantXHTTP_TLS, "4a"},
		{VariantRawTCP, "4b"},
		{VariantTLSMirror, "4c"},
		{VariantUDP, "4d"},
		{VariantTrust, "4e"},
	}
	for _, tc := range cases {
		if got := variantPolicyKey(tc.variant); got != tc.wantKey {
			t.Fatalf("variantPolicyKey(%s)=%q want=%q", VariantName(tc.variant), got, tc.wantKey)
		}
	}

	if got := variantPolicyKey(ProtocolVariant(99)); got != "" {
		t.Fatalf("variantPolicyKey(unknown)=%q want empty", got)
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func containsOverlay(overlays []behavior.Overlay, name string) bool {
	for _, o := range overlays {
		if strings.EqualFold(strings.TrimSpace(o.Name()), name) {
			return true
		}
	}
	return false
}
