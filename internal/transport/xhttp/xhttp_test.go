package xhttp

import "testing"

func TestApplyDefaults(t *testing.T) {
	var cfg Config
	cfg.ApplyDefaults()
	if cfg.Mode != ModeStreamOne {
		t.Fatalf("unexpected default mode: %s", cfg.Mode)
	}
	if cfg.Path != "/_sl" {
		t.Fatalf("unexpected default path: %s", cfg.Path)
	}
	if cfg.MaxConnections <= 0 || cfg.PacketSize <= 0 {
		t.Fatalf("defaults not applied: max_connections=%d packet_size=%d", cfg.MaxConnections, cfg.PacketSize)
	}
}

func TestBuildHeadersIncludesXHTTPFields(t *testing.T) {
	cfg := Config{
		Mode:       ModePacketUp,
		Path:       "/x",
		PacketSize: 2048,
		Headers:    map[string]string{"X-Test": "1"},
	}
	cfg.ApplyDefaults()
	h := buildHeaders(cfg)
	if h["X-Test"] != "1" {
		t.Fatalf("expected custom header")
	}
	if h["X-XHTTP-Mode"] != string(ModePacketUp) {
		t.Fatalf("expected X-XHTTP-Mode, got %q", h["X-XHTTP-Mode"])
	}
	if h["X-XHTTP-Packet-Size"] != "2048" {
		t.Fatalf("expected packet size header, got %q", h["X-XHTTP-Packet-Size"])
	}
	if h["X-XHTTP-KeepAlive"] == "" {
		t.Fatalf("expected keepalive header")
	}
}
