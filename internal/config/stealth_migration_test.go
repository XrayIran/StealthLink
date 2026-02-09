package config

import (
	"strings"
	"testing"
)

func TestLegacyTransportBlocksRejected(t *testing.T) {
	sampleBodies := map[string]string{
		"tls":         "tls:\n    server_name: example.com",
		"wss":         "wss:\n    path: /_sl",
		"h2":          "h2:\n    path: /_sl",
		"xhttp":       "xhttp:\n    path: /_sl",
		"reality":     "reality:\n    private_key: abc",
		"shadowtls":   "shadowtls:\n    password: p",
		"tlsmirror":   "tlsmirror:\n    enabled: true",
		"quic":        "quic:\n    enable_0rtt: true",
		"masque":      "masque:\n    tunnel_type: udp",
		"dtls":        "dtls:\n    psk: p",
		"kcp":         "kcp:\n    block: aes",
		"rawtcp":      "rawtcp:\n    interface: eth0",
		"raw_adapter": "raw_adapter:\n    mode: rawtcp",
		"auto":        "auto:\n    candidates: [wss]",
	}

	for legacyKey, expectPath := range removedTransportBlocks {
		legacyBody, ok := sampleBodies[legacyKey]
		if !ok {
			t.Fatalf("missing sample body for legacy key %s", legacyKey)
		}
		t.Run(legacyKey, func(t *testing.T) {
			path := writeCfg(t, "role: agent\nagent:\n  id: a1\n  gateway_addr: \"127.0.0.1:8443\"\ntransport:\n  type: stealth\n  "+legacyBody+"\nsecurity:\n  shared_key: \"k\"\nservices:\n  - name: svc\n    protocol: tcp\n    target: \"127.0.0.1:22\"\n")
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error for legacy key %s", legacyKey)
			}
			if !strings.Contains(err.Error(), "transport."+legacyKey+" has been removed") {
				t.Fatalf("unexpected error message: %v", err)
			}
			if !strings.Contains(err.Error(), expectPath) {
				t.Fatalf("expected migration path %q in error, got: %v", expectPath, err)
			}
		})
	}
}

// TestStealthRawModeLegacyAliasRejected is disabled - legacy stealth transport removed in favor of UQSP
// Raw mode validation is now handled at the UQSP transport layer.
func TestStealthRawModeLegacyAliasRejected(t *testing.T) {
	t.Skip("Legacy stealth transport removed - UQSP is the only supported transport")
}

// TestStealthSelectionProbeTimeoutValidation is disabled - legacy stealth transport removed in favor of UQSP
// Selection/probing features are now handled differently in UQSP transport.
func TestStealthSelectionProbeTimeoutValidation(t *testing.T) {
	t.Skip("Legacy stealth transport removed - UQSP is the only supported transport")
}
