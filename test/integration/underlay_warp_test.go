package integration

import (
	"crypto/tls"
	"testing"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
	"stealthlink/internal/transport/uqsp"

	"github.com/xtaci/smux"
)

func TestUnderlayWarpSelectable_AllVariants(t *testing.T) {
	t.Setenv("STEALTHLINK_WARP_DIALER_MOCK", "1")

	variants := []struct {
		id      string
		carrier string
	}{
		{"4a", "xhttp"},
		{"4b", "rawtcp"},
		{"4c", "xhttp"},
		{"4d", "quic"},
		{"4e", "trusttunnel"},
	}

	for _, tc := range variants {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			cfg := newVariantConfig(tc.id, tc.carrier)
			cfg.Transport.Dialer = "warp"
			cfg.Transport.WARPDialer = config.WARPDialer{
				Mode:     "consumer", // operator-facing profile
				Engine:   "",         // default internal engine
				Required: true,
			}

			tlsCfg := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"underlay-warp-test"},
			}

			proto, _, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
			if err != nil {
				t.Fatalf("BuildVariantForRole: %v", err)
			}
			defer proto.Close()

			if proto.UnderlayDialer() == nil {
				t.Fatal("expected UnderlayDialer to be set")
			}
			if got := proto.UnderlayDialer().Type(); got != "warp" {
				t.Fatalf("UnderlayDialer.Type()=%q want %q", got, "warp")
			}

			if got := metrics.GetUnderlaySelected(); got != "warp" {
				t.Fatalf("metrics underlay_selected=%q want %q", got, "warp")
			}
			if got := metrics.GetWARPHealth(); got != "up" {
				t.Fatalf("metrics warp_health=%q want %q", got, "up")
			}
		})
	}
}
