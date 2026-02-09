package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"stealthlink/internal/config"
)

func TestDashboardEndpoints(t *testing.T) {
	cfg := &config.Config{}
	cfg.Role = "gateway"
	cfg.Transport.Type = "uqsp"
	api := NewDashboardAPI(cfg, func() any { return []string{"tun0"} })

	for _, p := range []string{"/api/v1/status", "/api/v1/tunnels", "/api/v1/metrics", "/api/v1/config"} {
		r := httptest.NewRequest(http.MethodGet, p, nil)
		w := httptest.NewRecorder()
		api.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: unexpected code %d", p, w.Code)
		}
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("%s: invalid json: %v", p, err)
		}
	}
}
