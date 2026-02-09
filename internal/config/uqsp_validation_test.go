package config

import "testing"

func TestApplyUQSPDefaultsSetsCarrierFingerprints(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyUQSPDefaults()

	if cfg.Transport.UQSP.Carrier.WebTunnel.TLSFingerprint == "" {
		t.Fatal("webtunnel tls_fingerprint should have a secure default")
	}
	if cfg.Transport.UQSP.Carrier.Chisel.TLSFingerprint == "" {
		t.Fatal("chisel tls_fingerprint should have a secure default")
	}
	if cfg.Transport.UQSP.Carrier.XHTTP.TLSFingerprint == "" {
		t.Fatal("xhttp tls_fingerprint should have a secure default")
	}
}

func TestValidateUQSPRejectsReverseWithoutAuthToken(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyUQSPDefaults()
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Reverse.Enabled = true
	cfg.Transport.UQSP.Reverse.Role = "listener"
	cfg.Transport.UQSP.Reverse.AuthToken = ""
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected reverse auth token validation error")
	}
}

func TestValidateUQSPRejectsMissingCarrierFingerprint(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyUQSPDefaults()
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Carrier.WebTunnel.TLSFingerprint = ""
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected missing carrier tls_fingerprint validation error")
	}
}
