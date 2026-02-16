package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_AllowsTransportDialerWarpBlocks(t *testing.T) {
	path := writeTempCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "203.0.113.1:8443"
transport:
  type: uqsp
  mode: "HTTP+"
  dialer: warp
  warp_dialer:
    engine: builtin
    required: false
security:
  shared_key: "k"
services:
  - name: vpn
    protocol: tcp
    target: "127.0.0.1:22"
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected load success, got: %v", err)
	}
}

func TestLoad_AllowsTransportDialerSocksBlocks(t *testing.T) {
	path := writeTempCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "203.0.113.1:8443"
transport:
  type: uqsp
  mode: "HTTP+"
  dialer: socks
  socks_dialer:
    address: "127.0.0.1:1080"
security:
  shared_key: "k"
services:
  - name: vpn
    protocol: tcp
    target: "127.0.0.1:22"
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected load success, got: %v", err)
	}
}

func TestLoad_RejectsTransportPipelineStill(t *testing.T) {
	path := writeTempCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "127.0.0.1:8443"
transport:
  type: uqsp
  pipeline:
    enabled: true
    nodes:
      - id: a
        type: obfs
    edges: []
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    target: "127.0.0.1:22"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "transport.pipeline has been removed") {
		t.Fatalf("expected pipeline removal error, got: %v", err)
	}
}

func TestLoad_AllowsTransportDialerPolicyBlocks(t *testing.T) {
	path := writeTempCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "203.0.113.1:8443"
transport:
  type: uqsp
  mode: "HTTP+"
  dialer: policy
  dialer_policy:
    enabled: true
    default: direct
    rules:
      - name: warp-for-example
        priority: 100
        enabled: true
        matchers:
          - type: domain_suffix
            pattern: ".example.com"
        action:
          type: chain
          chain: warp
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    target: "127.0.0.1:22"
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected load success, got: %v", err)
	}
}
