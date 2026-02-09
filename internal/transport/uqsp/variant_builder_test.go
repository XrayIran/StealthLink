package uqsp

import (
	"crypto/tls"
	"testing"

	"stealthlink/internal/config"

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
