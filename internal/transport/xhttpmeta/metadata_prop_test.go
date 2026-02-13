package xhttpmeta

import (
	"net/http"
	"net/url"
	"testing"

	"pgregory.net/rapid"
)

func TestPropertyRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pGen := rapid.SampledFrom([]Placement{PlacementHeader, PlacementPath, PlacementQuery, PlacementCookie})

		cfg := MetadataConfig{
			Session: FieldConfig{
				Placement: pGen.Draw(t, "session_placement"),
				Key:       rapid.StringMatching(`[a-zA-Z0-9]{1,16}`).Draw(t, "session_key"),
			},
			Seq: FieldConfig{
				Placement: pGen.Draw(t, "seq_placement"),
				Key:       rapid.StringMatching(`[a-zA-Z0-9]{1,16}`).Draw(t, "seq_key"),
			},
			Mode: FieldConfig{
				Placement: pGen.Draw(t, "mode_placement"),
				Key:       rapid.StringMatching(`[a-zA-Z0-9]{1,16}`).Draw(t, "mode_key"),
			},
		}

		// Ensure no key collisions for the test
		if cfg.Session.Key == cfg.Seq.Key || cfg.Session.Key == cfg.Mode.Key || cfg.Seq.Key == cfg.Mode.Key {
			return
		}

		values := MetadataValues{
			SessionID: rapid.StringMatching(`[a-zA-Z0-9-]{1,64}`).Draw(t, "session_id"),
			Seq:       rapid.Uint64().Draw(t, "seq"),
			Mode:      rapid.StringMatching(`[a-z]{1,16}`).Draw(t, "mode"),
		}

		u, _ := url.Parse("https://example.com/api")
		req, _ := http.NewRequest(http.MethodPost, u.String(), nil)

		enc := NewPlacementEncoder(cfg)
		if err := enc.Encode(req, values); err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		dec := NewPlacementDecoder(cfg)
		got, err := dec.Decode(req)
		if err != nil {
			t.Fatalf("Decode failed: %v", err)
		}

		if got.SessionID != values.SessionID {
			t.Errorf("SessionID mismatch: got %q, want %q", got.SessionID, values.SessionID)
		}
		if got.Seq != values.Seq {
			t.Errorf("Seq mismatch: got %v, want %v", got.Seq, values.Seq)
		}
		if got.Mode != values.Mode {
			t.Errorf("Mode mismatch: got %q, want %q", got.Mode, values.Mode)
		}
	})
}

func TestPropertyKeyValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		key := rapid.String().Draw(t, "key")
		p := rapid.SampledFrom([]Placement{PlacementHeader, PlacementCookie}).Draw(t, "placement")

		v := &KeyValidator{}
		err := v.ValidateKey(key, p)

		// If key contains non-token characters, it should fail
		hasInvalid := false
		if key == "" {
			hasInvalid = true
		} else {
			for _, r := range key {
				if !isToken(r) {
					hasInvalid = true
					break
				}
			}
		}

		if hasInvalid && err == nil {
			t.Errorf("Invalid key %q for %s accepted", key, p)
		}
		if !hasInvalid && err != nil {
			t.Errorf("Valid key %q for %s rejected: %v", key, p, err)
		}
	})
}

func TestPropertySessionIDLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sidLen := rapid.IntRange(0, 300).Draw(t, "sid_len")
		sid := ""
		for i := 0; i < sidLen; i++ {
			sid += "a"
		}

		cfg := MetadataConfig{}
		cfg.ApplyDefaults()
		enc := NewPlacementEncoder(cfg)

		req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
		err := enc.Encode(req, MetadataValues{SessionID: sid})

		if sidLen > 128 && err == nil {
			t.Errorf("SessionID of length %d accepted, should be rejected", sidLen)
		}
		if sidLen <= 128 && err != nil {
			t.Errorf("SessionID of length %d rejected: %v", sidLen, err)
		}
	})
}

// TestPropertyPlacementConsistency verifies Property 4:
// For any XHTTP session, all packets in that session should use the same
// placement strategy for session ID and sequence numbers.
func TestPropertyPlacementConsistency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pGen := rapid.SampledFrom([]Placement{PlacementHeader, PlacementPath, PlacementQuery, PlacementCookie})

		// Create a single config (simulating a session)
		cfg := MetadataConfig{
			Session: FieldConfig{
				Placement: pGen.Draw(t, "session_placement"),
				Key:       rapid.StringMatching(`[a-zA-Z0-9]{1,16}`).Draw(t, "session_key"),
			},
			Seq: FieldConfig{
				Placement: pGen.Draw(t, "seq_placement"),
				Key:       rapid.StringMatching(`[a-zA-Z0-9]{1,16}`).Draw(t, "seq_key"),
			},
			Mode: FieldConfig{
				Placement: pGen.Draw(t, "mode_placement"),
				Key:       rapid.StringMatching(`[a-zA-Z0-9]{1,16}`).Draw(t, "mode_key"),
			},
		}

		// Ensure no key collisions
		if cfg.Session.Key == cfg.Seq.Key || cfg.Session.Key == cfg.Mode.Key || cfg.Seq.Key == cfg.Mode.Key {
			return
		}

		// Create a single encoder (simulating a session)
		enc := NewPlacementEncoder(cfg)
		dec := NewPlacementDecoder(cfg)

		// Generate multiple requests (simulating packets in a session)
		numRequests := rapid.IntRange(2, 10).Draw(t, "num_requests")
		sessionID := rapid.StringMatching(`[a-zA-Z0-9-]{1,64}`).Draw(t, "session_id")

		for i := 0; i < numRequests; i++ {
			values := MetadataValues{
				SessionID: sessionID, // Same session ID for all requests
				Seq:       rapid.Uint64().Draw(t, "seq"),
				Mode:      rapid.StringMatching(`[a-z]{1,16}`).Draw(t, "mode"),
			}

			u, _ := url.Parse("https://example.com/api")
			req, _ := http.NewRequest(http.MethodPost, u.String(), nil)

			if err := enc.Encode(req, values); err != nil {
				t.Fatalf("Encode failed for request %d: %v", i, err)
			}

			// Verify the placement strategy is consistent by decoding
			got, err := dec.Decode(req)
			if err != nil {
				t.Fatalf("Decode failed for request %d: %v", i, err)
			}

			// Verify session ID is consistent
			if got.SessionID != sessionID {
				t.Errorf("Request %d: SessionID mismatch: got %q, want %q", i, got.SessionID, sessionID)
			}

			// Verify sequence number is correctly encoded/decoded
			if got.Seq != values.Seq {
				t.Errorf("Request %d: Seq mismatch: got %v, want %v", i, got.Seq, values.Seq)
			}

			// Verify mode is correctly encoded/decoded
			if got.Mode != values.Mode {
				t.Errorf("Request %d: Mode mismatch: got %q, want %q", i, got.Mode, values.Mode)
			}
		}

		// Additional check: verify that the encoder config hasn't changed
		if enc.Config.Session.Placement != cfg.Session.Placement {
			t.Errorf("Session placement changed during session")
		}
		if enc.Config.Seq.Placement != cfg.Seq.Placement {
			t.Errorf("Seq placement changed during session")
		}
		if enc.Config.Mode.Placement != cfg.Mode.Placement {
			t.Errorf("Mode placement changed during session")
		}
	})
}
