package quicmux

import "testing"

func TestConfigApplyDefaults(t *testing.T) {
	c := &Config{}
	c.ApplyDefaults()
	if c.HandshakeTimeout <= 0 {
		t.Fatalf("expected HandshakeTimeout default")
	}
	if c.MaxIdleTimeout <= 0 {
		t.Fatalf("expected MaxIdleTimeout default")
	}
	if c.KeepAlivePeriod <= 0 {
		t.Fatalf("expected KeepAlivePeriod default")
	}
	if c.MaxIncomingStreams <= 0 || c.MaxIncomingUniStreams <= 0 {
		t.Fatalf("expected stream defaults")
	}
}
