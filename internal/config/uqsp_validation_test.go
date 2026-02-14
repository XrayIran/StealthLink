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

func TestValidateUQSPRuntimeMode(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Runtime.Mode = "invalid"
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected runtime.mode validation error")
	}
}

func TestValidateUQSPVariantProfile(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.VariantProfile = "4d"
	if err := cfg.ValidateUQSP(); err != nil {
		t.Fatalf("expected valid variant_profile, got: %v", err)
	}
	cfg.Transport.UQSP.VariantProfile = "bad"
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected invalid variant_profile validation error")
	}
}

func TestUQSPRuntimeModeDefaultsToUnified(t *testing.T) {
	cfg := &Config{}
	if got := cfg.UQSPRuntimeMode(); got != "unified" {
		t.Fatalf("expected unified default runtime mode, got %q", got)
	}
	cfg.Transport.UQSP.Runtime.Mode = "legacy"
	if got := cfg.UQSPRuntimeMode(); got != "legacy" {
		t.Fatalf("expected legacy runtime mode, got %q", got)
	}
}

func TestApplyUQSPDefaultsSetsDatagramReassemblyDefaults(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyUQSPDefaults()

	if cfg.Transport.UQSP.Datagrams.ReassemblyTimeout <= 0 {
		t.Fatal("datagrams.reassembly_timeout should default to > 0")
	}
	if cfg.Transport.UQSP.Datagrams.MaxReassemblyBytes < 64*1024 {
		t.Fatal("datagrams.max_reassembly_bytes should default to sane minimum")
	}
}

func TestValidateUQSPRejectsInvalidDatagramReassemblySettings(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Datagrams.ReassemblyTimeout = 0
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected reassembly_timeout validation error")
	}

	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Datagrams.MaxReassemblyBytes = 1024
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected max_reassembly_bytes validation error")
	}
}

func TestValidateUQSPFakeHTTPBehaviorValidation(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Behaviors.ViolatedTCP.FakeHTTPEnabled = true
	cfg.Transport.UQSP.Behaviors.ViolatedTCP.FakeHTTPHost = ""
	cfg.Transport.UQSP.Behaviors.ViolatedTCP.FakeHTTPUserAgent = "ua"
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected fake_http_host validation error")
	}
}

func TestApplyUQSPDefaultsSetsAWGSpecialJunkOptional(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyUQSPDefaults()

	if cfg.Transport.UQSP.Behaviors.AWG.SpecialJunkOptional == nil || !*cfg.Transport.UQSP.Behaviors.AWG.SpecialJunkOptional {
		t.Fatal("awg.special_junk_optional should default to true")
	}
}

func TestApplyUQSPDefaultsSetsFakeTCPConfig(t *testing.T) {
	cfg := &Config{}
	cfg.ApplyUQSPDefaults()

	ftc := cfg.Transport.UQSP.Carrier.FakeTCP
	if ftc.MTU == 0 {
		t.Fatal("faketcp.mtu should have a default")
	}
	if ftc.WindowSize == 0 {
		t.Fatal("faketcp.window_size should have a default")
	}
	if ftc.RTO <= 0 {
		t.Fatal("faketcp.rto should default to > 0")
	}
	if ftc.Keepalive <= 0 {
		t.Fatal("faketcp.keepalive should default to > 0")
	}
	if ftc.KeepaliveIdle <= 0 {
		t.Fatal("faketcp.keepalive_idle should default to > 0")
	}
	if !ftc.FakeHTTP.IsEnabled() {
		t.Fatal("faketcp.fake_http.enabled should default to true")
	}
}

func TestApplyUQSPDefaultsHonorsExplicitOptOuts(t *testing.T) {
	cfg := &Config{}
	disabled := false
	cfg.Transport.UQSP.Behaviors.AWG.SpecialJunkOptional = &disabled
	cfg.Transport.UQSP.Carrier.FakeTCP.FakeHTTP.Enabled = &disabled
	cfg.ApplyUQSPDefaults()

	if cfg.Transport.UQSP.Behaviors.AWG.SpecialJunkOptional == nil || *cfg.Transport.UQSP.Behaviors.AWG.SpecialJunkOptional {
		t.Fatal("awg.special_junk_optional=false should be preserved")
	}
	if cfg.Transport.UQSP.Carrier.FakeTCP.FakeHTTP.IsEnabled() {
		t.Fatal("faketcp.fake_http.enabled=false should be preserved")
	}
}

func TestValidateUQSPRejectsFakeTCPBadMTU(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	cfg.Transport.UQSP.Carrier.FakeTCP.MTU = 100 // Below minimum
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected faketcp.mtu validation error for value below 576")
	}
}

func TestValidateUQSPRejectsFakeTCPBadWindowSize(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	cfg.Transport.UQSP.Carrier.FakeTCP.WindowSize = 512 // Below minimum
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected faketcp.window_size validation error")
	}
}

func TestValidateUQSPRejectsFakeTCPAEADWithoutKey(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "faketcp"
	cfg.Transport.UQSP.Carrier.FakeTCP.AEADMode = "chacha20poly1305"
	cfg.Transport.UQSP.Carrier.FakeTCP.CryptoKey = ""
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected faketcp.crypto_key validation error when aead_mode is enabled")
	}
}

func TestValidateUQSPRejectsInvalidXHTTPMetadataPlacement(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.XHTTP.Metadata.Session.Placement = "invalid"
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected xhttp metadata placement validation error")
	}
}

func TestValidateUQSPRejectsAnyTLSWithoutPassword(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Behaviors.AnyTLS.Enabled = true
	cfg.Transport.UQSP.Behaviors.AnyTLS.Password = ""
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected anytls password validation error")
	}
}

func TestValidateUQSPAcceptsMASQUECarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "masque"
	cfg.Transport.UQSP.Carrier.MASQUE.TunnelType = "udp"
	if err := cfg.ValidateUQSP(); err != nil {
		t.Fatalf("expected valid masque carrier config, got: %v", err)
	}
}

func TestValidateUQSPRejectsMASQUEBadTunnelType(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "masque"
	cfg.Transport.UQSP.Carrier.MASQUE.TunnelType = "nope"
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected masque tunnel_type validation error")
	}
}

func TestValidateUQSPAcceptsKCPCarrier(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "kcp"
	cfg.Transport.UQSP.Carrier.KCP.Mode = "standard"
	if err := cfg.ValidateUQSP(); err != nil {
		t.Fatalf("expected valid kcp carrier config, got: %v", err)
	}
}

func TestValidateUQSPRejectsKCPBadBatchSize(t *testing.T) {
	cfg := &Config{}
	cfg.Transport.Type = "uqsp"
	cfg.ApplyUQSPDefaults()
	cfg.Transport.UQSP.Carrier.Type = "kcp"
	cfg.Transport.UQSP.Carrier.KCP.BatchSize = 0
	if err := cfg.ValidateUQSP(); err == nil {
		t.Fatal("expected kcp batch_size validation error")
	}
}
