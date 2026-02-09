package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeCfg(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cfg.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPipelineTransportBlockRejected(t *testing.T) {
	path := writeCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "127.0.0.1:8443"
transport:
  type: stealth
  pipeline:
    enabled: true
    nodes:
      - id: a
        type: obfs
      - id: b
        type: frame
    edges:
      - from: a
        to: b
      - from: b
        to: a
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    target: "127.0.0.1:22"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "transport.pipeline has been removed; use transport.stealth.*") {
		t.Fatalf("expected transport.pipeline removal error, got: %v", err)
	}
}

func TestOIDCProviderValidation(t *testing.T) {
	path := writeCfg(t, `role: gateway
gateway:
  listen: ":8443"
transport:
  type: uqsp
security:
  shared_key: "k"
auth:
  providers:
    - name: oidc-main
      type: oidc
      enabled: true
      oidc:
        issuer: "https://issuer.example"
services:
  - name: svc
    protocol: tcp
    listen: ":2222"
`)
	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), "requires issuer, audience, hs256_secret") {
		t.Fatalf("expected oidc validation error, got: %v", err)
	}
}

func TestXHTTPGatewayAllowed(t *testing.T) {
	path := writeCfg(t, `role: gateway
gateway:
  listen: ":8443"
transport:
  type: uqsp
  uqsp:
    handshake:
      auth_mode: token
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    listen: ":2222"
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("unexpected load error: %v", err)
	}
}
