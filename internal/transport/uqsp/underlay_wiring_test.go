package uqsp

import (
	"crypto/tls"
	"testing"

	"stealthlink/internal/config"

	"github.com/xtaci/smux"
)

func TestBuildVariantForRole_WiresUnderlayDialer(t *testing.T) {
	cfg := &config.Config{}
	cfg.Role = "agent"
	cfg.Transport.Type = "uqsp"
	cfg.Variant = "UDP+"
	cfg.Transport.UQSP.Carrier.Type = "quic"

	proto, _, err := BuildVariantForRole(cfg, &tls.Config{InsecureSkipVerify: true}, smux.DefaultConfig(), "token")
	if err != nil {
		t.Fatalf("BuildVariantForRole: %v", err)
	}
	defer proto.Close()

	if proto.variant.UnderlayDialer == nil {
		t.Fatalf("underlay dialer is nil")
	}
	if got := proto.variant.UnderlayDialer.Type(); got != "direct" {
		t.Fatalf("underlay type = %q, want %q", got, "direct")
	}
}
