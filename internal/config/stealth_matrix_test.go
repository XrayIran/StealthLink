package config

import "testing"

func TestUQSPConfigLoad(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "minimal", body: ""},
		{name: "with-handshake", body: "handshake:\n      auth_mode: token\n      enable_0rtt: true"},
		{name: "with-streams", body: "streams:\n      max_concurrent: 200\n      flow_control_window: 2097152"},
		{name: "with-datagrams", body: "datagrams:\n      max_size: 1400\n      relay_mode: capsule"},
		{name: "with-congestion", body: "congestion:\n      algorithm: brutal\n      bandwidth_mbps: 200"},
		{name: "with-obfuscation", body: "obfuscation:\n      profile: salamander\n      salamander_key: testkey123"},
		{name: "with-awg", body: "awg_profile:\n      enabled: true\n      junk_interval: 10s"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uqspConfig := ""
			if tc.body != "" {
				uqspConfig = "    " + tc.body
			}
			path := writeCfg(t, "role: agent\nagent:\n  id: a1\n  gateway_addr: \"203.0.113.1:8443\"\ntransport:\n  type: uqsp\n  uqsp:\n"+uqspConfig+"\nsecurity:\n  shared_key: \"k\"\nservices:\n  - name: svc\n    protocol: tcp\n    target: \"127.0.0.1:22\"\n")
			if _, err := Load(path); err != nil {
				t.Fatalf("unexpected load error: %v", err)
			}
		})
	}
}

func TestUQSPValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name:    "valid-defaults",
			body:    "transport:\n  type: uqsp\n  uqsp: {}",
			wantErr: false,
		},
		{
			name:    "invalid-auth-mode",
			body:    "transport:\n  type: uqsp\n  uqsp:\n    handshake:\n      auth_mode: invalid",
			wantErr: true,
		},
		{
			name:    "invalid-congestion-algorithm",
			body:    "transport:\n  type: uqsp\n  uqsp:\n    congestion:\n      algorithm: invalid",
			wantErr: true,
		},
		{
			name:    "invalid-relay-mode",
			body:    "transport:\n  type: uqsp\n  uqsp:\n    datagrams:\n      relay_mode: invalid",
			wantErr: true,
		},
		{
			name:    "salamander-without-key",
			body:    "transport:\n  type: uqsp\n  uqsp:\n    obfuscation:\n      profile: salamander",
			wantErr: true,
		},
		{
			name:    "valid-salamander",
			body:    "transport:\n  type: uqsp\n  uqsp:\n    obfuscation:\n      profile: salamander\n      salamander_key: testkey123",
			wantErr: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCfg(t, "role: agent\nagent:\n  id: a1\n  gateway_addr: \"203.0.113.1:8443\"\n"+tc.body+"\nsecurity:\n  shared_key: \"k\"\nservices:\n  - name: svc\n    protocol: tcp\n    target: \"127.0.0.1:22\"\n")
			_, err := Load(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected load error: %v", err)
				}
			}
		})
	}
}

// TestLegacyStealthRejected ensures old stealth configs are rejected
func TestLegacyStealthRejected(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "stealth-tcp", body: "type: stealth\n  stealth:\n    carrier:\n      kind: tcp\n    camouflage:\n      mode: tls\n      profile: plain-tls"},
		{name: "stealth-quic", body: "type: stealth\n  stealth:\n    carrier:\n      kind: quic"},
		{name: "stealth-kcp", body: "type: stealth\n  stealth:\n    carrier:\n      kind: kcp"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeCfg(t, "role: agent\nagent:\n  id: a1\n  gateway_addr: \"203.0.113.1:8443\"\ntransport:\n  "+tc.body+"\nsecurity:\n  shared_key: \"k\"\nservices:\n  - name: svc\n    protocol: tcp\n    target: \"127.0.0.1:22\"\n")
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for legacy stealth config, got nil")
			}
			if !contains(err.Error(), "transport.type=uqsp") {
				t.Fatalf("expected error to mention UQSP migration, got: %v", err)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
