package xhttpmeta

import (
	"net/http"
	"net/url"
	"testing"
)

func TestApplyDefaults(t *testing.T) {
	var cfg MetadataConfig
	cfg.ApplyDefaults()
	if cfg.Session.Placement != PlacementHeader {
		t.Fatalf("session placement=%q", cfg.Session.Placement)
	}
	if cfg.Seq.Placement != PlacementHeader {
		t.Fatalf("seq placement=%q", cfg.Seq.Placement)
	}
	if cfg.Mode.Placement != PlacementHeader {
		t.Fatalf("mode placement=%q", cfg.Mode.Placement)
	}
	if cfg.Session.Key != "X-Session-ID" || cfg.Seq.Key != "X-Seq" || cfg.Mode.Key != "X-Stealthlink-Mode" {
		t.Fatalf("unexpected keys: %+v", cfg)
	}
}

func TestApplyToRequest(t *testing.T) {
	u, _ := url.Parse("https://example.com/base")
	req := &http.Request{URL: u, Header: make(http.Header)}

	cfg := MetadataConfig{
		Session: FieldConfig{Placement: PlacementHeader, Key: "X-Session-ID"},
		Seq:     FieldConfig{Placement: PlacementQuery, Key: "seq"},
		Mode:    FieldConfig{Placement: PlacementCookie, Key: "mode"},
	}
	values := MetadataValues{SessionID: "abc", Seq: 12, Mode: "stream-one"}
	if err := ApplyToRequest(req, cfg, values); err != nil {
		t.Fatalf("ApplyToRequest error: %v", err)
	}

	// Session ID should be base64url encoded: abc -> YWJj
	if got := req.Header.Get("X-Session-ID"); got != "YWJj" {
		t.Fatalf("session header=%q", got)
	}
	if got := req.URL.Query().Get("seq"); got != "12" {
		t.Fatalf("seq query=%q", got)
	}
	foundCookie := false
	for _, c := range req.Cookies() {
		if c.Name == "mode" && c.Value == "stream-one" {
			foundCookie = true
			break
		}
	}
	if !foundCookie {
		t.Fatal("expected mode cookie")
	}
}

func TestBuildURLPathPlacement(t *testing.T) {
	cfg := MetadataConfig{
		Session: FieldConfig{Placement: PlacementPath, Key: "sid"},
		Seq:     FieldConfig{Placement: PlacementPath, Key: "seq"},
		Mode:    FieldConfig{Placement: PlacementHeader, Key: "X-Stealthlink-Mode"},
	}
	out, err := BuildURL("https://example.com/xhttp", cfg, MetadataValues{
		SessionID: "abc",
		Seq:       9,
		Mode:      "stream-one",
	})
	if err != nil {
		t.Fatalf("BuildURL error: %v", err)
	}
	// Session ID "abc" -> "YWJj"
	if out != "https://example.com/xhttp/sid/YWJj/seq/9" {
		t.Fatalf("url=%q", out)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	placements := []Placement{PlacementHeader, PlacementPath, PlacementQuery, PlacementCookie}
	for _, p := range placements {
		t.Run(string(p), func(t *testing.T) {
			cfg := MetadataConfig{
				Session: FieldConfig{Placement: p, Key: "sid"},
				Seq:     FieldConfig{Placement: p, Key: "seq"},
				Mode:    FieldConfig{Placement: p, Key: "mode"},
			}
			values := MetadataValues{
				SessionID: "test-session-123",
				Seq:       987654321,
				Mode:      "packet-up",
			}

			u, _ := url.Parse("https://example.com/api")
			req, _ := http.NewRequest(http.MethodPost, u.String(), nil)
			
			enc := NewPlacementEncoder(cfg)
			if err := enc.Encode(req, values); err != nil {
				t.Fatalf("Encode error: %v", err)
			}

			dec := NewPlacementDecoder(cfg)
			got, err := dec.Decode(req)
			if err != nil {
				t.Fatalf("Decode error: %v", err)
			}

			if got.SessionID != values.SessionID {
				t.Errorf("got SessionID=%q, want %q", got.SessionID, values.SessionID)
			}
			if got.Seq != values.Seq {
				t.Errorf("got Seq=%v, want %v", got.Seq, values.Seq)
			}
			if got.Mode != values.Mode {
				t.Errorf("got Mode=%q, want %q", got.Mode, values.Mode)
			}
		})
	}
}

func TestValidation(t *testing.T) {
	v := &KeyValidator{}
	
	// Valid keys
	if err := v.ValidateKey("X-Valid-Key", PlacementHeader); err != nil {
		t.Errorf("valid header key failed: %v", err)
	}
	if err := v.ValidateKey("valid_cookie", PlacementCookie); err != nil {
		t.Errorf("valid cookie key failed: %v", err)
	}

	// Invalid keys
	if err := v.ValidateKey("Invalid Key", PlacementHeader); err == nil {
		t.Error("header key with space should fail")
	}
	if err := v.ValidateKey("Invalid@Key", PlacementCookie); err == nil {
		t.Error("cookie key with @ should fail")
	}

	// Collision
	cfg := MetadataConfig{
		Session: FieldConfig{Key: "collision", Placement: PlacementHeader},
		Seq:     FieldConfig{Key: "collision", Placement: PlacementQuery},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("config with colliding keys should fail")
	}
}
