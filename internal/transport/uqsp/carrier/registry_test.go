package carrier

import (
	"crypto/tls"
	"testing"

	"stealthlink/internal/config"

	"github.com/xtaci/smux"
)

func TestSelectCarrierFakeTCP(t *testing.T) {
	cfg := config.UQSPCarrierConfig{
		Type: "faketcp",
	}
	c, err := SelectCarrier(cfg, &tls.Config{InsecureSkipVerify: true}, smux.DefaultConfig(), "shared-token")
	if err != nil {
		t.Fatalf("SelectCarrier() error = %v", err)
	}
	if c == nil {
		t.Fatal("SelectCarrier() returned nil carrier for faketcp")
	}
	if got := c.Network(); got != "udp" {
		t.Fatalf("carrier network = %q, want udp", got)
	}
}

func TestSelectCarrierMASQUE(t *testing.T) {
	cfg := config.UQSPCarrierConfig{
		Type: "masque",
		MASQUE: config.MASQUECarrierConfig{
			TunnelType: "udp",
		},
	}
	c, err := SelectCarrier(cfg, &tls.Config{InsecureSkipVerify: true}, smux.DefaultConfig(), "shared-token")
	if err != nil {
		t.Fatalf("SelectCarrier() error = %v", err)
	}
	if c == nil {
		t.Fatal("SelectCarrier() returned nil carrier for masque")
	}
	if got := c.Network(); got != "quic" {
		t.Fatalf("carrier network = %q, want quic", got)
	}
}

func TestSelectCarrierKCP(t *testing.T) {
	cfg := config.UQSPCarrierConfig{
		Type: "kcp",
		KCP: config.KCPBaseCarrierConfig{
			Mode:         "standard",
			Block:        "none",
			DataShards:   10,
			ParityShards: 3,
		},
	}
	c, err := SelectCarrier(cfg, &tls.Config{InsecureSkipVerify: true}, smux.DefaultConfig(), "shared-token")
	if err != nil {
		t.Fatalf("SelectCarrier() error = %v", err)
	}
	if c == nil {
		t.Fatal("SelectCarrier() returned nil carrier for kcp")
	}
	if got := c.Network(); got != "udp" {
		t.Fatalf("carrier network = %q, want udp", got)
	}
}

func TestSupportsListenAndDial(t *testing.T) {
	if SupportsListen("xhttp") {
		t.Fatal("xhttp should be dial-only")
	}
	if SupportsListen("chisel") {
		t.Fatal("chisel should be dial-only")
	}
	if !SupportsListen("webtunnel") {
		t.Fatal("webtunnel should support listen")
	}
	if !SupportsDial("xhttp") {
		t.Fatal("xhttp should support dial")
	}
	if SupportsDial("unknown-carrier") {
		t.Fatal("unknown carrier should not support dial")
	}
}
