package underlay

import (
	"os"
	"testing"

	"stealthlink/internal/config"
)

func TestNewWARPDialer_MockMode_AllowsOperatorModes(t *testing.T) {
	t.Setenv("STEALTHLINK_WARP_DIALER_MOCK", "1")

	// transport.warp_dialer.mode is an operator-facing profile ("consumer"/etc.)
	// and must not be forwarded into internal/warp engine selection.
	cases := []string{"consumer", "zero-trust", "connector", "anything"}
	for _, mode := range cases {
		mode := mode
		t.Run(mode, func(t *testing.T) {
			d, err := NewWARPDialer(config.WARPDialer{
				Mode:     mode,
				Engine:   "", // default engine
				Required: true,
			})
			if err != nil {
				t.Fatalf("NewWARPDialer: %v", err)
			}
			if d.Type() != "warp" {
				t.Fatalf("Type()=%q want %q", d.Type(), "warp")
			}
			if got := d.Health(); got != "up" {
				t.Fatalf("Health()=%q want %q", got, "up")
			}
			_ = d.Close()
		})
	}
}

func TestNewWARPDialer_MockMode_ClearsEnvIsolation(t *testing.T) {
	// Guard against other tests leaking env var state.
	if os.Getenv("STEALTHLINK_WARP_DIALER_MOCK") == "1" {
		t.Skip("STEALTHLINK_WARP_DIALER_MOCK already set in environment")
	}
}
