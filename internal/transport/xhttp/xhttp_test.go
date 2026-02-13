package xhttp

import (
	"net/http"
	"net/url"
	"stealthlink/internal/transport/xhttpmeta"
	"testing"
)

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
	if cfg.SessionPlacement != PlacementHeader {
		t.Fatalf("unexpected session placement: %s", cfg.SessionPlacement)
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
	
	metaCfg := xhttpmeta.MetadataConfig{
		Session: xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.SessionPlacement), Key: cfg.SessionKey},
		Seq:     xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.SequencePlacement), Key: cfg.SequenceKey},
		Mode:    xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.MetadataPlacement), Key: "X-Stealthlink-Mode"},
	}
	metaValues := xhttpmeta.MetadataValues{
		SessionID: "test-sid",
		Seq:       1,
		Mode:      string(cfg.Mode),
	}

	h := buildHeaders(cfg, metaCfg, metaValues)
	if h["X-Test"] != "1" {
		t.Fatalf("expected custom header")
	}
	// Session ID should be base64url encoded. Key is canonicalized by http.Header.
	if h["X-Session-Id"] == "" {
		t.Fatalf("expected X-Session-Id")
	}
	if h["X-Stealthlink-Mode"] != string(ModePacketUp) {
		t.Fatalf("expected X-Stealthlink-Mode, got %q", h["X-Stealthlink-Mode"])
	}
	if h["X-Xhttp-Packet-Size"] != "2048" {
		t.Fatalf("expected packet size header, got %q", h["X-Xhttp-Packet-Size"])
	}
}

func TestPlacementIntegration(t *testing.T) {
	tests := []struct {
		name      string
		placement MetadataPlacement
		check     func(t *testing.T, u string, h map[string]string, c []*http.Cookie)
	}{
		{
			name:      "Header",
			placement: PlacementHeader,
			check: func(t *testing.T, u string, h map[string]string, c []*http.Cookie) {
				if h["X-Session-Id"] == "" {
					t.Error("missing session ID in headers")
				}
				if h["X-Seq"] != "1" {
					t.Errorf("got seq=%q, want 1", h["X-Seq"])
				}
			},
		},
		{
			name:      "Query",
			placement: PlacementQuery,
			check: func(t *testing.T, u string, h map[string]string, c []*http.Cookie) {
				parsed, _ := url.Parse(u)
				if parsed.Query().Get("X-Session-ID") == "" {
					t.Error("missing session ID in query")
				}
				if parsed.Query().Get("X-Seq") != "1" {
					t.Error("missing seq in query")
				}
			},
		},
		{
			name:      "Cookie",
			placement: PlacementCookie,
			check: func(t *testing.T, u string, h map[string]string, c []*http.Cookie) {
				foundID := false
				foundSeq := false
				for _, cookie := range c {
					if cookie.Name == "X-Session-ID" {
						foundID = true
					}
					if cookie.Name == "X-Seq" {
						foundSeq = true
					}
				}
				if !foundID || !foundSeq {
					t.Error("missing session ID or seq in cookies")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				SessionPlacement:  tt.placement,
				SequencePlacement: tt.placement,
			}
			cfg.ApplyDefaults()

			metaCfg := xhttpmeta.MetadataConfig{
				Session: xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.SessionPlacement), Key: cfg.SessionKey},
				Seq:     xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.SequencePlacement), Key: cfg.SequenceKey},
				Mode:    xhttpmeta.FieldConfig{Placement: xhttpmeta.Placement(cfg.MetadataPlacement), Key: "X-Stealthlink-Mode"},
			}
			metaValues := xhttpmeta.MetadataValues{
				SessionID: "test-sid",
				Seq:       1,
				Mode:      string(cfg.Mode),
			}

			rawURL := "https://example.com/api"
			u, _ := xhttpmeta.BuildURL(rawURL, metaCfg, metaValues)
			h := buildHeaders(cfg, metaCfg, metaValues)
			c := buildCookies(cfg, metaCfg, metaValues)

			tt.check(t, u, h, c)
		})
	}
}
