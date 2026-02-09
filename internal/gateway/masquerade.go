package gateway

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// MasqueradeConfig configures backend masquerade behavior.
type MasqueradeConfig struct {
	Enabled        bool              `yaml:"enabled"`
	BackendURL     string            `yaml:"backend_url"`      // URL to proxy to when auth fails
	HealthEndpoint string            `yaml:"health_endpoint"`  // Health check endpoint (default: /health)
	VersionEndpoint string           `yaml:"version_endpoint"` // Version endpoint (default: /version)
	StaticFiles    map[string]string `yaml:"static_files"`     // Static file mappings
	IndexFile      string            `yaml:"index_file"`       // Index file for root path
	StatusCode     int               `yaml:"status_code"`      // Status code for fallback (default: 404)
	ResponseBody   string            `yaml:"response_body"`    // Response body for fallback
	Headers        map[string]string `yaml:"headers"`          // Headers to add to responses
}

// ApplyDefaults sets default values.
func (c *MasqueradeConfig) ApplyDefaults() {
	if c.HealthEndpoint == "" {
		c.HealthEndpoint = "/health"
	}
	if c.VersionEndpoint == "" {
		c.VersionEndpoint = "/version"
	}
	if c.StatusCode == 0 {
		c.StatusCode = 404
	}
}

// MasqueradeHandler provides plausible deniability by behaving like a normal web server.
type MasqueradeHandler struct {
	config     MasqueradeConfig
	backend    *httputil.ReverseProxy
	startTime  time.Time
	version    string
}

// NewMasqueradeHandler creates a new masquerade handler.
func NewMasqueradeHandler(config MasqueradeConfig) (*MasqueradeHandler, error) {
	config.ApplyDefaults()

	h := &MasqueradeHandler{
		config:    config,
		startTime: time.Now(),
		version:   "1.0.0",
	}

	if config.BackendURL != "" {
		backendURL, err := url.Parse(config.BackendURL)
		if err != nil {
			return nil, fmt.Errorf("invalid backend URL: %w", err)
		}
		h.backend = httputil.NewSingleHostReverseProxy(backendURL)
	}

	return h, nil
}

// ServeHTTP implements http.Handler.
func (h *MasqueradeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add configured headers
	for k, v := range h.config.Headers {
		w.Header().Set(k, v)
	}

	// Handle health endpoint
	if r.URL.Path == h.config.HealthEndpoint {
		h.handleHealth(w, r)
		return
	}

	// Handle version endpoint
	if r.URL.Path == h.config.VersionEndpoint {
		h.handleVersion(w, r)
		return
	}

	// Handle static files
	if content, ok := h.config.StaticFiles[r.URL.Path]; ok {
		h.handleStatic(w, r, content)
		return
	}

	// Handle index file for root
	if r.URL.Path == "/" && h.config.IndexFile != "" {
		if content, ok := h.config.StaticFiles[h.config.IndexFile]; ok {
			h.handleStatic(w, r, content)
			return
		}
	}

	// Try backend proxy if configured
	if h.backend != nil {
		h.backend.ServeHTTP(w, r)
		return
	}

	// Default fallback response
	h.handleFallback(w, r)
}

// handleHealth responds with health status.
func (h *MasqueradeHandler) handleHealth(w http.ResponseWriter, r *http.Request) {
	status := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(h.startTime).String(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(status)
}

// handleVersion responds with version information.
func (h *MasqueradeHandler) handleVersion(w http.ResponseWriter, r *http.Request) {
	info := map[string]string{
		"version":   h.version,
		"build":     "release",
		"platform":  "linux",
		"go_version": "1.21",
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(info)
}

// handleStatic serves static content.
func (h *MasqueradeHandler) handleStatic(w http.ResponseWriter, r *http.Request, content string) {
	// Detect content type based on extension
	contentType := "text/plain"
	if strings.HasSuffix(r.URL.Path, ".html") {
		contentType = "text/html"
	} else if strings.HasSuffix(r.URL.Path, ".css") {
		contentType = "text/css"
	} else if strings.HasSuffix(r.URL.Path, ".js") {
		contentType = "application/javascript"
	} else if strings.HasSuffix(r.URL.Path, ".json") {
		contentType = "application/json"
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, content)
}

// handleFallback responds with default fallback.
func (h *MasqueradeHandler) handleFallback(w http.ResponseWriter, r *http.Request) {
	body := h.config.ResponseBody
	if body == "" {
		body = fmt.Sprintf("<!DOCTYPE html><html><body><h1>%d %s</h1><p>The requested resource was not found.</p></body></html>",
			h.config.StatusCode, http.StatusText(h.config.StatusCode))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx/1.18.0") // Pretend to be nginx
	w.WriteHeader(h.config.StatusCode)
	io.WriteString(w, body)
}

// ShouldMasquerade returns true if the request should be handled by masquerade.
// This is typically called when authentication fails.
func (h *MasqueradeHandler) ShouldMasquerade(r *http.Request) bool {
	// Always masquerade for non-WebSocket HTTP requests
	if r.Header.Get("Upgrade") == "websocket" {
		return false
	}
	return true
}

// MasqueradeResponse generates a generic response for unauthenticated requests.
func MasqueradeResponse(w http.ResponseWriter, statusCode int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx/1.18.0")
	w.WriteHeader(statusCode)

	body := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>%d %s</title></head>
<body>
<center><h1>%d %s</h1></center>
<hr><center>nginx/1.18.0</center>
</body>
</html>`, statusCode, http.StatusText(statusCode), statusCode, http.StatusText(statusCode))

	io.WriteString(w, body)
}

// AltSvcHeader returns an Alt-Svc header for HTTP/3 advertisement.
func AltSvcHeader(port int) string {
	return fmt.Sprintf(`h3=":%d"; ma=86400, h3-29=":%d"; ma=86400`, port, port)
}

// AddAltSvc adds Alt-Svc header for HTTP/3 support.
func AddAltSvc(w http.ResponseWriter, port int) {
	w.Header().Add("Alt-Svc", AltSvcHeader(port))
}

// CommonStaticFiles returns a set of common static files for masquerade.
func CommonStaticFiles() map[string]string {
	return map[string]string{
		"/": `<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>Welcome</h1>
<p>This is a standard web server.</p>
</body>
</html>`,
		"/robots.txt": `User-agent: *
Disallow: /`,
		"/favicon.ico": "", // Empty favicon
	}
}

// WebServerMasquerade returns a masquerade config that looks like a generic web server.
func WebServerMasquerade() MasqueradeConfig {
	return MasqueradeConfig{
		Enabled:        true,
		HealthEndpoint: "/health",
		VersionEndpoint: "/version",
		StaticFiles:    CommonStaticFiles(),
		IndexFile:      "/",
		StatusCode:     404,
		Headers: map[string]string{
			"X-Frame-Options": "SAMEORIGIN",
			"X-Content-Type-Options": "nosniff",
		},
	}
}

// CDNMasquerade returns a masquerade config that looks like a CDN edge node.
func CDNMasquerade() MasqueradeConfig {
	return MasqueradeConfig{
		Enabled:        true,
		HealthEndpoint: "/health",
		StatusCode:     403,
		Headers: map[string]string{
			"Cache-Control": "public, max-age=3600",
			"X-Cache":       "HIT",
			"X-Edge-Location": "edge-001",
		},
	}
}
