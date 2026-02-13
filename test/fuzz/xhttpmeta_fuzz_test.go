package fuzz

import (
	"net/http"
	"net/url"
	"testing"

	"stealthlink/internal/transport/xhttpmeta"
)

// FuzzXHTTPMetaDecode tests XHTTP metadata encoding/decoding for all placement types.
// This fuzzer tests path, query, header, and cookie placements to catch panic/crash inputs.
func FuzzXHTTPMetaDecode(f *testing.F) {
	// Seed corpus with valid examples
	f.Add("session123", uint64(42), "stream-one", uint8(0)) // header
	f.Add("abc", uint64(1), "mode", uint8(1))               // path
	f.Add("xyz", uint64(999), "test", uint8(2))             // query
	f.Add("s1", uint64(0), "m1", uint8(3))                  // cookie

	f.Fuzz(func(t *testing.T, sessionID string, seq uint64, mode string, placementType uint8) {
		// Map placementType to actual placement
		var placement xhttpmeta.Placement
		switch placementType % 4 {
		case 0:
			placement = xhttpmeta.PlacementHeader
		case 1:
			placement = xhttpmeta.PlacementPath
		case 2:
			placement = xhttpmeta.PlacementQuery
		case 3:
			placement = xhttpmeta.PlacementCookie
		}

		// Create config with the selected placement
		cfg := xhttpmeta.MetadataConfig{
			Session: xhttpmeta.FieldConfig{Placement: placement, Key: "session"},
			Seq:     xhttpmeta.FieldConfig{Placement: placement, Key: "seq"},
			Mode:    xhttpmeta.FieldConfig{Placement: placement, Key: "mode"},
		}

		values := xhttpmeta.MetadataValues{
			SessionID: sessionID,
			Seq:       seq,
			Mode:      mode,
		}

		// Test BuildURL (path/query placements)
		_, _ = xhttpmeta.BuildURL("https://example.com/base", cfg, values)

		// Test ApplyToRequest (all placements)
		u, err := url.Parse("https://example.com/test")
		if err != nil {
			return // Invalid URL, skip
		}

		req := &http.Request{
			URL:    u,
			Header: make(http.Header),
		}

		// This should not panic even with malformed inputs
		_ = xhttpmeta.ApplyToRequest(req, cfg, values)

		// Verify we can read back the values without panicking
		switch placement {
		case xhttpmeta.PlacementHeader:
			_ = req.Header.Get("session")
			_ = req.Header.Get("seq")
			_ = req.Header.Get("mode")
		case xhttpmeta.PlacementQuery:
			_ = req.URL.Query().Get("session")
			_ = req.URL.Query().Get("seq")
			_ = req.URL.Query().Get("mode")
		case xhttpmeta.PlacementCookie:
			_ = req.Cookies()
		case xhttpmeta.PlacementPath:
			_ = req.URL.Path
		}
	})
}
