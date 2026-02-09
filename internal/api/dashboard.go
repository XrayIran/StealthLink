package api

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
)

// DashboardAPI exposes a dashboard-friendly JSON API surface.
type DashboardAPI struct {
	cfg       *config.Config
	tunnelFn  func() any
	started   atomic.Bool
	buildInfo string
}

func NewDashboardAPI(cfg *config.Config, tunnelFn func() any) *DashboardAPI {
	return &DashboardAPI{cfg: cfg, tunnelFn: tunnelFn}
}

func (d *DashboardAPI) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", d.handleStatus)
	mux.HandleFunc("/api/v1/tunnels", d.handleTunnels)
	mux.HandleFunc("/api/v1/metrics", d.handleMetrics)
	mux.HandleFunc("/api/v1/config", d.handleConfig)
	return mux
}

func (d *DashboardAPI) handleStatus(w http.ResponseWriter, _ *http.Request) {
	d.started.Store(true)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"started": d.started.Load(),
		"transport": func() string {
			if d.cfg == nil {
				return "unknown"
			}
			return d.cfg.Transport.Type
		}(),
		"role": func() string {
			if d.cfg == nil {
				return "unknown"
			}
			return d.cfg.Role
		}(),
	})
}

func (d *DashboardAPI) handleTunnels(w http.ResponseWriter, _ *http.Request) {
	var tunnels any = []any{}
	if d.tunnelFn != nil {
		tunnels = d.tunnelFn()
	}
	writeJSON(w, http.StatusOK, map[string]any{"tunnels": tunnels})
}

func (d *DashboardAPI) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"metrics": metrics.SnapshotData(),
	})
}

func (d *DashboardAPI) handleConfig(w http.ResponseWriter, _ *http.Request) {
	if d.cfg == nil {
		writeJSON(w, http.StatusOK, map[string]any{"config": map[string]any{}})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"config": map[string]any{
			"role":      d.cfg.Role,
			"transport": d.cfg.Transport.Type,
			"variant":   d.cfg.VariantName(),
			"warp":      d.cfg.WARP.Enabled,
			"reverse":   d.cfg.Transport.UQSP.Reverse.Enabled,
			"metrics":   d.cfg.Metrics.Listen,
		},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
