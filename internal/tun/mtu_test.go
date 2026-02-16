package tun

import "testing"

func TestValidateMTUBounds(t *testing.T) {
	if err := ValidateMTU(67); err == nil {
		t.Fatalf("expected error for too-small MTU")
	}
	if err := ValidateMTU(68); err != nil {
		t.Fatalf("unexpected error at minimum MTU: %v", err)
	}
	if err := ValidateMTU(65535); err != nil {
		t.Fatalf("unexpected error at max MTU: %v", err)
	}
	if err := ValidateMTU(65536); err == nil {
		t.Fatalf("expected error for too-large MTU")
	}
}

func TestMTUOverheadKnown(t *testing.T) {
	if got := MTUOverhead("wireguard"); got < 60 {
		t.Fatalf("expected wireguard overhead >= 60, got %d", got)
	}
	if got := MTUOverhead("udp"); got != 28 {
		t.Fatalf("expected udp overhead 28, got %d", got)
	}
}

func TestCalculateInnerMTUClamps(t *testing.T) {
	if got := CalculateInnerMTU(100, 1000); got != 68 {
		t.Fatalf("expected clamp to 68, got %d", got)
	}
}
