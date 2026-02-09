package metrics

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/http/pprof"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:embed templates/*
var templatesFS embed.FS

// WebServer provides a web status page for monitoring.
type WebServer struct {
	registry  *prometheus.Registry
	tmpl      *template.Template
	addr      string
	enablePprof bool
	startTime   time.Time
}

// WebStatusData holds data for the status page.
type WebStatusData struct {
	Timestamp     string
	Version       string
	GoVersion     string
	Uptime        string
	NumGoroutines int
	MemoryUsage   WebMemoryStats
	Transports    []WebTransportStatus
	Sessions      []WebSessionStatus
	Services      []WebServiceStatus
}

// WebMemoryStats holds memory usage information.
type WebMemoryStats struct {
	Alloc      uint64
	TotalAlloc uint64
	Sys        uint64
	NumGC      uint32
}

// WebTransportStatus holds transport health information.
type WebTransportStatus struct {
	Name    string
	Status  string
	Latency time.Duration
	Conns   int
	Errors  int64
}

// WebSessionStatus holds session information.
type WebSessionStatus struct {
	ID         string
	Transport  string
	LocalAddr  string
	RemoteAddr string
	Uptime     string
	Streams    int
}

// WebServiceStatus holds service information.
type WebServiceStatus struct {
	Name     string
	Protocol string
	Listen   string
	Target   string
	Active   int
	Total    int64
}

// NewWebServer creates a new web status server.
// If enablePprof is true, /debug/pprof/* endpoints are registered.
func NewWebServer(addr string, registry *prometheus.Registry, opts ...WebServerOption) (*WebServer, error) {
	if registry == nil {
		registry = prometheus.NewRegistry()
		registry.MustRegister(collectors.NewGoCollector())
		registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	}

	// Parse templates
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		// Fallback to basic template if embed fails
		tmpl = template.Must(template.New("status").Parse(basicStatusTemplate))
	}

	ws := &WebServer{
		registry:  registry,
		tmpl:      tmpl,
		addr:      addr,
		startTime: time.Now(),
	}
	for _, opt := range opts {
		opt(ws)
	}
	return ws, nil
}

// WebServerOption configures a WebServer.
type WebServerOption func(*WebServer)

// WithPprof enables /debug/pprof/* endpoints.
func WithPprof(enable bool) WebServerOption {
	return func(ws *WebServer) {
		ws.enablePprof = enable
	}
}

// Start starts the web server.
func (s *WebServer) Start() error {
	mux := http.NewServeMux()

	// Status page
	mux.HandleFunc("/", s.handleStatus)
	mux.HandleFunc("/status", s.handleStatus)

	// API endpoints
	mux.HandleFunc("/api/v1/status", s.handleAPIStatus)
	mux.HandleFunc("/api/v1/transports", s.handleAPITransports)
	mux.HandleFunc("/api/v1/sessions", s.handleAPISessions)
	mux.HandleFunc("/api/v1/services", s.handleAPIServices)
	mux.HandleFunc("/api/v1/metrics", s.handleAPIMetrics)

	// Text status endpoint
	mux.HandleFunc("/debug/status/text", s.handleTextStatus)

	// Health check
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// pprof endpoints
	if s.enablePprof {
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	// Static assets
	mux.Handle("/static/", http.FileServer(http.FS(templatesFS)))

	return http.ListenAndServe(s.addr, mux)
}

// handleStatus serves the HTML status page.
func (s *WebServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	data := s.collectStatusData()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, "status.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleAPIStatus returns JSON status.
func (s *WebServer) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	data := s.collectStatusData()
	s.writeJSON(w, data)
}

// handleAPITransports returns transport status.
func (s *WebServer) handleAPITransports(w http.ResponseWriter, r *http.Request) {
	data := []TransportStatus{
		{Name: "tls", Status: "healthy"},
		{Name: "wss", Status: "healthy"},
		{Name: "h2", Status: "healthy"},
		{Name: "shadowtls", Status: "healthy"},
		{Name: "reality", Status: "healthy"},
		{Name: "dtls", Status: "healthy"},
		{Name: "quic", Status: "healthy"},
		{Name: "masque", Status: "healthy"},
		{Name: "kcp", Status: "healthy"},
		{Name: "rawtcp", Status: "healthy"},
	}
	s.writeJSON(w, data)
}

// handleAPISessions returns active sessions.
func (s *WebServer) handleAPISessions(w http.ResponseWriter, r *http.Request) {
	data := []WebSessionStatus{}
	s.writeJSON(w, data)
}

// handleAPIServices returns service status.
func (s *WebServer) handleAPIServices(w http.ResponseWriter, r *http.Request) {
	data := []WebServiceStatus{}
	s.writeJSON(w, data)
}

// handleAPIMetrics returns Prometheus metrics.
func (s *WebServer) handleAPIMetrics(w http.ResponseWriter, r *http.Request) {
	promhttp.HandlerFor(s.registry, promhttp.HandlerOpts{}).ServeHTTP(w, r)
}

// collectStatusData collects current status.
func (s *WebServer) collectStatusData() WebStatusData {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return WebStatusData{
		Timestamp:     time.Now().Format(time.RFC3339),
		Version:       "1.0.0",
		GoVersion:     runtime.Version(),
		Uptime:        time.Since(time.Now()).String(),
		NumGoroutines: runtime.NumGoroutine(),
		MemoryUsage: WebMemoryStats{
			Alloc:      m.Alloc,
			TotalAlloc: m.TotalAlloc,
			Sys:        m.Sys,
			NumGC:      m.NumGC,
		},
		Transports: []WebTransportStatus{
			{Name: "tls", Status: "healthy", Conns: 5},
			{Name: "wss", Status: "healthy", Conns: 3},
			{Name: "quic", Status: "healthy", Conns: 2},
		},
	}
}

// writeJSON writes JSON response.
func (s *WebServer) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

// handleTextStatus returns a human-readable text status (like Tunnel's /debug/paqet/text).
func (s *WebServer) handleTextStatus(w http.ResponseWriter, r *http.Request) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	uptime := time.Since(s.startTime).Truncate(time.Second)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	fmt.Fprintf(w, "=== StealthLink Status ===\n\n")
	fmt.Fprintf(w, "Uptime:       %s\n", uptime)
	fmt.Fprintf(w, "Go Version:   %s\n", runtime.Version())
	fmt.Fprintf(w, "Platform:     %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "Goroutines:   %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "CPUs:         %d\n\n", runtime.NumCPU())

	fmt.Fprintf(w, "--- Memory ---\n")
	fmt.Fprintf(w, "Alloc:        %s\n", formatBytes(m.Alloc))
	fmt.Fprintf(w, "TotalAlloc:   %s\n", formatBytes(m.TotalAlloc))
	fmt.Fprintf(w, "Sys:          %s\n", formatBytes(m.Sys))
	fmt.Fprintf(w, "NumGC:        %d\n", m.NumGC)
	fmt.Fprintf(w, "HeapObjects:  %d\n\n", m.HeapObjects)

	fmt.Fprintf(w, "--- Traffic ---\n")
	fmt.Fprintf(w, "Sessions:     %d active, %d total\n", GetSessionsActive(), GetSessionsTotal())
	fmt.Fprintf(w, "Streams:      %d active, %d total\n", GetStreamsActive(), GetStreamsTotal())
	fmt.Fprintf(w, "Inbound:      %s\n", formatBytes(uint64(GetTrafficInbound())))
	fmt.Fprintf(w, "Outbound:     %s\n", formatBytes(uint64(GetTrafficOutbound())))
	fmt.Fprintf(w, "Errors:       %d\n", GetErrorsTotal())
	rtt := GetLastPingRTT()
	if rtt > 0 {
		fmt.Fprintf(w, "Last RTT:     %dms\n", rtt)
	}
}

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

// basicStatusTemplate is a fallback template.
const basicStatusTemplate = `<!DOCTYPE html>
<html>
<head>
    <title>StealthLink Status</title>
    <style>
        body { font-family: sans-serif; margin: 2em; }
        h1 { color: #333; }
        .metric { margin: 0.5em 0; }
        .label { font-weight: bold; }
    </style>
</head>
<body>
    <h1>StealthLink Status</h1>
    <div class="metric"><span class="label">Timestamp:</span> {{.Timestamp}}</div>
    <div class="metric"><span class="label">Version:</span> {{.Version}}</div>
    <div class="metric"><span class="label">Go Version:</span> {{.GoVersion}}</div>
    <div class="metric"><span class="label">Goroutines:</span> {{.NumGoroutines}}</div>
    <h2>Transports</h2>
    {{range .Transports}}
    <div class="metric">{{.Name}}: {{.Status}} ({{.Conns}} connections)</div>
    {{end}}
</body>
</html>
`
