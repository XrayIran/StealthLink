package config

import (
	"strings"
	"testing"
)

func TestLoad_RejectsLoopbackGatewayAddrByDefault(t *testing.T) {
	path := writeCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "127.0.0.1:8443"
transport:
  type: uqsp
  mode: "HTTP+"
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    target: "127.0.0.1:22"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error for loopback gateway_addr")
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected loopback error, got: %v", err)
	}
}

func TestLoad_AllowsLoopbackGatewayAddrWhenExplicitlyEnabled(t *testing.T) {
	path := writeCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "127.0.0.1:8443"
  allow_loopback_gateway_addr: true
transport:
  type: uqsp
  mode: "HTTP+"
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    target: "127.0.0.1:22"
`)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected load success with allow_loopback_gateway_addr, got: %v", err)
	}
}

func TestLoad_RejectsGatewayAddrMissingPort(t *testing.T) {
	path := writeCfg(t, `role: agent
agent:
  id: a1
  gateway_addr: "203.0.113.1"
transport:
  type: uqsp
  mode: "HTTP+"
security:
  shared_key: "k"
services:
  - name: svc
    protocol: tcp
    target: "127.0.0.1:22"
`)
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error for missing port")
	}
	if !strings.Contains(err.Error(), "host:port") && !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected host:port error, got: %v", err)
	}
}
