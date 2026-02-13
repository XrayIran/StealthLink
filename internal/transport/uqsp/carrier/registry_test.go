package carrier

import (
	"testing"

	"stealthlink/internal/config"

	"github.com/xtaci/smux"
)

func TestSelectCarrierFakeTCP(t *testing.T) {
	cfg := config.UQSPCarrierConfig{
		Type: "faketcp",
	}
	c, err := SelectCarrier(cfg, smux.DefaultConfig(), "shared-token")
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
