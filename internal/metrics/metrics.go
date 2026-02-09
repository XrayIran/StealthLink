package metrics

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type Snapshot struct {
	SessionsTotal             int64                              `json:"sessions_total"`
	SessionsActive            int64                              `json:"sessions_active"`
	StreamsTotal              int64                              `json:"streams_total"`
	StreamsActive             int64                              `json:"streams_active"`
	UDPSessions               int64                              `json:"udp_sessions"`
	Errors                    int64                              `json:"errors"`
	LastPingRTTMs             int64                              `json:"last_ping_rtt_ms"`
	TrafficBytesTotal         int64                              `json:"traffic_bytes_total"`
	TrafficBytesInbound       int64                              `json:"traffic_bytes_inbound"`
	TrafficBytesOutbound      int64                              `json:"traffic_bytes_outbound"`
	SocketsOpen               int64                              `json:"sockets_open"`
	ObfsJunkPacketsTotal      int64                              `json:"obfs_junk_packets_total"`
	ObfsSignaturePacketsTotal int64                              `json:"obfs_signature_packets_total"`
	UpdatedUnix               int64                              `json:"updated_unix"`
	Services                  map[string]int64                   `json:"services_active,omitempty"`
	TransportSessions         map[string]int64                   `json:"transport_sessions_active,omitempty"`
	TCPTelemetry              TCPTelemetrySnapshot               `json:"tcp_telemetry,omitempty"`
	TCPSessions               []TCPSessionMetricsSnapshot        `json:"tcp_sessions,omitempty"`
	Carriers                  map[string]*CarrierMetricsSnapshot `json:"carriers,omitempty"`

	// UQSP metrics
	UQSPSessionsTotal    int64 `json:"uqsp_sessions_total"`
	UQSPStreamsActive    int64 `json:"uqsp_streams_active"`
	UQSPDatagramSessions int64 `json:"uqsp_datagram_sessions_active"`
	UQSPCapsulesTotal    int64 `json:"uqsp_capsules_total"`
	UQSPObfuscationOps   int64 `json:"uqsp_obfuscation_ops"`
	UQSPCongestionEvents int64 `json:"uqsp_congestion_events"`
	UQSPReplayDrops      int64 `json:"uqsp_replay_drops"`
	UQSPHandshakeTotal   int64 `json:"uqsp_handshake_total"`
	UQSPHandshakeAvgMs   int64 `json:"uqsp_handshake_avg_ms"`
}

var (
	sessionsTotal   atomic.Int64
	sessionsActive  atomic.Int64
	streamsTotal    atomic.Int64
	streamsActive   atomic.Int64
	udpSessions     atomic.Int64
	errorsTotal     atomic.Int64
	lastPingRTTMs   atomic.Int64
	trafficBytes    atomic.Int64
	trafficInBytes  atomic.Int64
	trafficOutBytes atomic.Int64
	openSockets     atomic.Int64
	obfsJunkPackets atomic.Int64
	obfsSigPackets  atomic.Int64
	serviceActive   sync.Map // name -> *atomic.Int64
	transportActive sync.Map // transport -> *atomic.Int64

	// UQSP-specific metrics
	uqspSessionsTotal      atomic.Int64
	uqspStreamsActive      atomic.Int64
	uqspDatagramSessions   atomic.Int64
	uqspCapsulesTotal      atomic.Int64
	uqspObfuscationOps     atomic.Int64
	uqspCongestionEvents   atomic.Int64
	uqspReplayDrops        atomic.Int64
	uqspHandshakeTotal     atomic.Int64
	uqspHandshakeDuration  atomic.Int64 // nanoseconds, for histogram
)

func IncSessions()               { sessionsTotal.Add(1); sessionsActive.Add(1); openSockets.Add(1) }
func DecSessions()               { sessionsActive.Add(-1); openSockets.Add(-1) }
func IncStreams()                { streamsTotal.Add(1); streamsActive.Add(1); openSockets.Add(1) }
func DecStreams()                { streamsActive.Add(-1); openSockets.Add(-1) }
func SetUDPSessions(n int64)     { udpSessions.Store(n) }
func IncErrors()                 { errorsTotal.Add(1) }
func SetPingRTT(d time.Duration) { lastPingRTTMs.Store(d.Milliseconds()) }
func AddTraffic(n int64) {
	if n > 0 {
		trafficBytes.Add(n)
	}
}
func AddTrafficInbound(n int64) {
	if n > 0 {
		trafficInBytes.Add(n)
		trafficBytes.Add(n)
	}
}
func AddTrafficOutbound(n int64) {
	if n > 0 {
		trafficOutBytes.Add(n)
		trafficBytes.Add(n)
	}
}
func SetSocketsOpen(n int64) { openSockets.Store(n) }
func IncObfsJunkPackets(n int64) {
	if n > 0 {
		obfsJunkPackets.Add(n)
	}
}
func IncObfsSignaturePackets(n int64) {
	if n > 0 {
		obfsSigPackets.Add(n)
	}
}
func IncTransportSession(name string) {
	if name == "" {
		return
	}
	v, _ := transportActive.LoadOrStore(name, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}
func DecTransportSession(name string) {
	if name == "" {
		return
	}
	if v, ok := transportActive.Load(name); ok {
		v.(*atomic.Int64).Add(-1)
	}
}
func IncService(name string) {
	if name == "" {
		return
	}
	v, _ := serviceActive.LoadOrStore(name, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}
func DecService(name string) {
	if name == "" {
		return
	}
	if v, ok := serviceActive.Load(name); ok {
		v.(*atomic.Int64).Add(-1)
	}
}

// UQSP metrics functions
func IncUQSPSessions()      { uqspSessionsTotal.Add(1) }
func IncUQSPStreamsActive() { uqspStreamsActive.Add(1) }
func DecUQSPStreamsActive() { uqspStreamsActive.Add(-1) }
func SetUQSPDatagramSessions(n int64) { uqspDatagramSessions.Store(n) }
func IncUQSPDatagramSessions() { uqspDatagramSessions.Add(1) }
func DecUQSPDatagramSessions() { uqspDatagramSessions.Add(-1) }
func IncUQSPcapsules(n int64) {
	if n > 0 {
		uqspCapsulesTotal.Add(n)
	}
}
func IncUQSPobfuscationOps() { uqspObfuscationOps.Add(1) }
func IncUQSPcongestionEvent() { uqspCongestionEvents.Add(1) }
func IncUQSPreplayDrops() { uqspReplayDrops.Add(1) }
func IncUQSPhandshake() { uqspHandshakeTotal.Add(1) }
func AddUQSPhandshakeDuration(d time.Duration) {
	uqspHandshakeDuration.Add(d.Nanoseconds())
}
func GetUQSPhandshakeAvgMs() int64 {
	total := uqspHandshakeTotal.Load()
	if total == 0 {
		return 0
	}
	return uqspHandshakeDuration.Load() / total / 1e6
}

// Getter functions for text status and status CLI.
func GetSessionsTotal() int64    { return sessionsTotal.Load() }
func GetSessionsActive() int64   { return sessionsActive.Load() }
func GetStreamsTotal() int64     { return streamsTotal.Load() }
func GetStreamsActive() int64    { return streamsActive.Load() }
func GetErrorsTotal() int64     { return errorsTotal.Load() }
func GetLastPingRTT() int64     { return lastPingRTTMs.Load() }
func GetTrafficInbound() int64  { return trafficInBytes.Load() }
func GetTrafficOutbound() int64 { return trafficOutBytes.Load() }

func SnapshotData() Snapshot {
	svcs := make(map[string]int64)
	transports := make(map[string]int64)
	serviceActive.Range(func(k, v any) bool {
		svcs[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	transportActive.Range(func(k, v any) bool {
		transports[k.(string)] = v.(*atomic.Int64).Load()
		return true
	})
	return Snapshot{
		SessionsTotal:             sessionsTotal.Load(),
		SessionsActive:            sessionsActive.Load(),
		StreamsTotal:              streamsTotal.Load(),
		StreamsActive:             streamsActive.Load(),
		UDPSessions:               udpSessions.Load(),
		Errors:                    errorsTotal.Load(),
		LastPingRTTMs:             lastPingRTTMs.Load(),
		TrafficBytesTotal:         trafficBytes.Load(),
		TrafficBytesInbound:       trafficInBytes.Load(),
		TrafficBytesOutbound:      trafficOutBytes.Load(),
		SocketsOpen:               openSockets.Load(),
		ObfsJunkPacketsTotal:      obfsJunkPackets.Load(),
		ObfsSignaturePacketsTotal: obfsSigPackets.Load(),
		UpdatedUnix:               time.Now().Unix(),
		Services:                  svcs,
		TransportSessions:         transports,
		TCPTelemetry:              GetTCPTelemetry(),
		TCPSessions:               GetAllTCPSessionMetrics(),
		Carriers:                  GetCarrierMetrics(),
		// UQSP metrics
		UQSPSessionsTotal:     uqspSessionsTotal.Load(),
		UQSPStreamsActive:     uqspStreamsActive.Load(),
		UQSPDatagramSessions:  uqspDatagramSessions.Load(),
		UQSPCapsulesTotal:     uqspCapsulesTotal.Load(),
		UQSPObfuscationOps:    uqspObfuscationOps.Load(),
		UQSPCongestionEvents:  uqspCongestionEvents.Load(),
		UQSPReplayDrops:       uqspReplayDrops.Load(),
		UQSPHandshakeTotal:    uqspHandshakeTotal.Load(),
		UQSPHandshakeAvgMs:    GetUQSPhandshakeAvgMs(),
	}
}

// TransportStatus holds transport health information.
type TransportStatus struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Conns  int    `json:"connections"`
	Errors int64  `json:"errors"`
}

// SessionInfo holds session information.
type SessionInfo struct {
	ID         string `json:"id"`
	Transport  string `json:"transport"`
	LocalAddr  string `json:"local_addr"`
	RemoteAddr string `json:"remote_addr"`
	Uptime     string `json:"uptime"`
	Streams    int    `json:"streams"`
}

// ServiceInfo holds service information.
type ServiceInfo struct {
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen,omitempty"`
	Target   string `json:"target,omitempty"`
	Active   int64  `json:"active"`
	Total    int64  `json:"total"`
}

var (
	transportStatus sync.Map // name -> *TransportStatus
	sessionInfo     sync.Map // id -> *SessionInfo
	serviceInfo     sync.Map // name -> *ServiceInfo
)

// SetTransportStatus sets the status for a transport.
func SetTransportStatus(name, status string, conns int, errors int64) {
	transportStatus.Store(name, &TransportStatus{
		Name:   name,
		Status: status,
		Conns:  conns,
		Errors: errors,
	})
}

// SetSessionInfo sets session information.
func SetSessionInfo(id string, info *SessionInfo) {
	sessionInfo.Store(id, info)
}

// RemoveSessionInfo removes session information.
func RemoveSessionInfo(id string) {
	sessionInfo.Delete(id)
}

// SetServiceInfo sets service information.
func SetServiceInfo(name string, info *ServiceInfo) {
	serviceInfo.Store(name, info)
}

// GetTransportStatuses returns all transport statuses.
func GetTransportStatuses() []TransportStatus {
	var result []TransportStatus
	transportStatus.Range(func(k, v any) bool {
		result = append(result, *v.(*TransportStatus))
		return true
	})
	return result
}

// GetSessionInfos returns all session information.
func GetSessionInfos() []SessionInfo {
	var result []SessionInfo
	sessionInfo.Range(func(k, v any) bool {
		result = append(result, *v.(*SessionInfo))
		return true
	})
	return result
}

// GetServiceInfos returns all service information.
func GetServiceInfos() []ServiceInfo {
	var result []ServiceInfo
	serviceInfo.Range(func(k, v any) bool {
		result = append(result, *v.(*ServiceInfo))
		return true
	})
	return result
}

func Start(addr string, authToken string) {
	if addr == "" {
		return
	}
	if !isLoopback(addr) && authToken == "" {
		log.Printf("metrics not started: refusing to expose unauthenticated endpoint on %s", addr)
		return
	}
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if authToken != "" && r.Header.Get("Authorization") != "Bearer "+authToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next(w, r)
		}
	}

	// Legacy metrics endpoint
	mux.HandleFunc("/metrics", auth(func(w http.ResponseWriter, r *http.Request) {
		st := SnapshotData()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(st)
	}))

	// Prometheus metrics endpoint
	mux.HandleFunc("/metrics/prom", auth(PromHandler))

	// Health check endpoint
	mux.HandleFunc("/healthz", auth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	}))

	// API v1 endpoints
	mux.HandleFunc("/api/v1/status", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"metrics":   SnapshotData(),
			"timestamp": time.Now().Unix(),
		})
	}))

	mux.HandleFunc("/api/v1/transports", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetTransportStatuses())
	}))

	mux.HandleFunc("/api/v1/sessions", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetSessionInfos())
	}))

	mux.HandleFunc("/api/v1/services", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetServiceInfos())
	}))

	// TCP telemetry endpoints
	mux.HandleFunc("/api/v1/tcp/sessions", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetAllTCPSessionMetrics())
	}))

	mux.HandleFunc("/api/v1/tcp/telemetry", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetTCPTelemetry())
	}))

	mux.HandleFunc("/api/v1/tcp/carriers", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(GetCarrierMetrics())
	}))

	go func() {
		_ = http.ListenAndServe(addr, mux)
	}()
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
