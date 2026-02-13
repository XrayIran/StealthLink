package uqsp

import (
	"crypto/tls"
	"testing"

	"stealthlink/internal/config"

	"github.com/xtaci/smux"
)

func TestLegacyDialerSelectCarrierTrustTunnel(t *testing.T) {
	cfg := &config.UQSPConfig{}
	cfg.Carrier.Type = "trusttunnel"
	cfg.Carrier.TrustTunnel.Server = "https://example.com"

	d := NewDialer(cfg, &tls.Config{InsecureSkipVerify: true}, smux.DefaultConfig(), "token")
	c, err := d.selectCarrier()
	if err != nil {
		t.Fatalf("selectCarrier() error = %v", err)
	}
	if c == nil {
		t.Fatal("expected trusttunnel carrier, got nil")
	}
	if got := c.Network(); got != "tcp" {
		t.Fatalf("carrier network = %q, want tcp", got)
	}
}

func TestLegacyListenerSelectCarrierTrustTunnel(t *testing.T) {
	cfg := &config.UQSPConfig{}
	cfg.Carrier.Type = "trusttunnel"
	cfg.Carrier.TrustTunnel.Server = "https://example.com"

	l := &Listener{
		Config:     cfg,
		TLSConfig:  &tls.Config{InsecureSkipVerify: true},
		SmuxConfig: smux.DefaultConfig(),
		AuthToken:  "token",
	}

	c, err := l.selectCarrier()
	if err != nil {
		t.Fatalf("selectCarrier() error = %v", err)
	}
	if c == nil {
		t.Fatal("expected trusttunnel carrier, got nil")
	}
	if got := c.Network(); got != "tcp" {
		t.Fatalf("carrier network = %q, want tcp", got)
	}
}
