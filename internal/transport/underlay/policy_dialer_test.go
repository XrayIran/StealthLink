package underlay

import (
	"os"
	"testing"

	"stealthlink/internal/config"
	"stealthlink/internal/routing"
)

func TestPolicyDialerSelectsWarpByDomainSuffix(t *testing.T) {
	os.Setenv("STEALTHLINK_WARP_DIALER_MOCK", "1")
	t.Cleanup(func() { os.Unsetenv("STEALTHLINK_WARP_DIALER_MOCK") })

	cfg := &config.Transport{
		Dialer: "policy",
		WARPDialer: config.WARPDialer{
			Engine:   "builtin",
			Required: false,
		},
		DialerPolicy: config.DialerPolicyConfig{
			Enabled: true,
			Default: "direct",
			Rules: []routing.Rule{
				{
					Name:     "warp-for-example",
					Priority: 100,
					Enabled:  true,
					Matchers: []*routing.Matcher{{Type: routing.MatchTypeDomainSuffix, Pattern: ".example.com"}},
					Action:   routing.Action{Type: routing.ActionTypeChain, Chain: "warp"},
				},
			},
		},
	}

	d, err := NewPolicyDialer(cfg)
	if err != nil {
		t.Fatalf("NewPolicyDialer: %v", err)
	}
	_, typ, err := d.selectDialer("tcp", "api.example.com:443")
	if err != nil {
		t.Fatalf("selectDialer: %v", err)
	}
	if typ != "warp" {
		t.Fatalf("expected warp, got %q", typ)
	}

	_, typ, err = d.selectDialer("tcp", "other.test:443")
	if err != nil {
		t.Fatalf("selectDialer default: %v", err)
	}
	if typ != "direct" {
		t.Fatalf("expected direct default, got %q", typ)
	}
}
