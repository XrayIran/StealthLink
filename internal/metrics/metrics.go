package metrics

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type PathPolicyLatencyQuantiles struct {
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
}

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
	RawENOBUFSTotal      int64 `json:"raw_enobufs_total"`
	RawWriteRetriesTotal int64 `json:"raw_write_retries_total"`
	RawDropsTotal        int64 `json:"raw_drops_total"`
	UQSPReassemblyEvicts int64 `json:"uqsp_reassembly_evictions_total"`

	// Reverse mode metrics
	ReverseReconnectAttemptsTotal int64 `json:"reverse_reconnect_attempts_total"`
	ReverseReconnectTimeout       int64 `json:"reverse_reconnect_timeout"`
	ReverseReconnectRefused       int64 `json:"reverse_reconnect_refused"`
	ReverseReconnectReset         int64 `json:"reverse_reconnect_reset"`
	ReverseConnectionsActive      int64 `json:"reverse_connections_active"`

	// Underlay dialer metrics
	UnderlaySelected                string                                `json:"underlay_selected"` // "direct" | "warp" | "socks"
	ActivePathVariant               string                                `json:"active_path_variant"`
	WARPHealth                      string                                `json:"warp_health"` // "up" | "down"
	PathPolicyWinnerSelectionsTotal map[string]int64                      `json:"path_policy_winner_selections_total,omitempty"`
	PathPolicyReracesTotal          int64                                 `json:"path_policy_reraces_total"`
	PathPolicyDialLatencyMs         map[string]PathPolicyLatencyQuantiles `json:"path_policy_dial_latency_ms,omitempty"`

	// Xmux metrics
	XmuxConnectionReusesTotal    int64            `json:"xmux_connection_reuses_total"`
	XmuxConnectionRotationsTotal map[string]int64 `json:"xmux_connection_rotations_total"`
	XmuxActiveConnections        int64            `json:"xmux_active_connections"`

	// FakeTCP metrics
	FakeTCPAEADAuthFailuresTotal int64            `json:"faketcp_aead_auth_failures_total"`
	FakeTCPKeyDerivationsTotal   int64            `json:"faketcp_key_derivations_total"`
	FakeTCPEncryptedBytesTotal   map[string]int64 `json:"faketcp_encrypted_bytes_total"`

	// REALITY spider metrics
	RealitySpiderFetchesTotal    int64   `json:"reality_spider_fetches_total"`
	RealitySpiderDurationSeconds float64 `json:"reality_spider_duration_seconds"`
	RealitySpiderURLsCrawled     int64   `json:"reality_spider_urls_crawled"`
	// Entropy metrics
	EntropyBytesGeneratedTotal map[string]int64 `json:"entropy_bytes_generated_total"`
	EntropyReseedsTotal        int64            `json:"entropy_reseeds_total"`
	EntropyMethod              map[string]int64 `json:"entropy_method"`

	// KCP FEC metrics
	KCPFECParitySkippedTotal       int64 `json:"kcp_fec_parity_skipped_total"`
	KCPFECAutoTuneAdjustmentsTotal int64 `json:"kcp_fec_auto_tune_adjustments_total"`
	KCPFECDataShards               int64 `json:"kcp_fec_data_shards"`
	KCPFECParityShards             int64 `json:"kcp_fec_parity_shards"`

	// Smux shaper metrics
	SmuxShaperControlFramesTotal         int64 `json:"smux_shaper_control_frames_total"`
	SmuxShaperDataFramesTotal            int64 `json:"smux_shaper_data_frames_total"`
	SmuxShaperQueueSize                  int64 `json:"smux_shaper_queue_size"`
	SmuxShaperStarvationPreventionsTotal int64 `json:"smux_shaper_starvation_preventions_total"`

	// Connection pool metrics
	PoolSize             int64            `json:"pool_size"`
	PoolUtilization      float64          `json:"pool_utilization"`
	PoolWaitTimeMs       int64            `json:"pool_wait_time_ms"`
	PoolAdjustmentsTotal map[string]int64 `json:"pool_adjustments_total"`

	// Security/deprecation metrics
	ReverseAuthRejectsTotal   int64 `json:"reverse_auth_rejects_total"`
	HandshakeFailuresTotal    int64 `json:"handshake_failures_total"`
	DeprecatedLegacyModeTotal int64 `json:"deprecated_legacy_mode_total"`
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
	uqspSessionsTotal     atomic.Int64
	uqspStreamsActive     atomic.Int64
	uqspDatagramSessions  atomic.Int64
	uqspCapsulesTotal     atomic.Int64
	uqspObfuscationOps    atomic.Int64
	uqspCongestionEvents  atomic.Int64
	uqspReplayDrops       atomic.Int64
	uqspHandshakeTotal    atomic.Int64
	uqspHandshakeDuration atomic.Int64 // nanoseconds, for histogram
	rawENOBUFSTotal       atomic.Int64
	rawWriteRetriesTotal  atomic.Int64
	rawDropsTotal         atomic.Int64
	uqspReassemblyEvicts  atomic.Int64

	// Reverse mode metrics
	reverseReconnectAttemptsTotal atomic.Int64
	reverseReconnectTimeout       atomic.Int64
	reverseReconnectRefused       atomic.Int64
	reverseReconnectReset         atomic.Int64
	reverseConnectionsActive      atomic.Int64

	// Underlay dialer metrics
	underlaySelected  atomic.Value // string: "direct" | "warp" | "socks"
	activePathVariant atomic.Value // string: "HTTP+" | "TCP+" | "TLS+" | "UDP+" | "TLS" | "legacy"
	warpHealth        atomic.Value // string: "up" | "down"
	pathPolicyWinners sync.Map     // candidate -> *atomic.Int64
	pathPolicyReraces atomic.Int64
	pathPolicyLatency sync.Map // candidate -> *latencyWindow

	// Xmux metrics
	xmuxReuses            atomic.Int64
	xmuxRotations         sync.Map // reason -> *atomic.Int64
	xmuxActiveConnections atomic.Int64

	// FakeTCP metrics
	faketcpAEADAuthFailures atomic.Int64
	faketcpKeyDerivations   atomic.Int64
	faketcpEncryptedBytes   sync.Map // direction -> *atomic.Int64

	// REALITY spider metrics
	realitySpiderFetches       atomic.Int64
	realitySpiderDurationNanos atomic.Int64
	realitySpiderURLsCrawled   atomic.Int64

	// Entropy metrics
	entropyBytesGenerated sync.Map // class -> *atomic.Int64
	entropyReseeds        atomic.Int64
	entropyMethod         sync.Map // method -> *atomic.Int64

	// KCP FEC metrics
	kcpFECParitySkipped       atomic.Int64
	kcpFECAutoTuneAdjustments atomic.Int64
	kcpFECDataShards          atomic.Int64
	kcpFECParityShards        atomic.Int64

	// Smux shaper metrics
	smuxShaperControlFrames         atomic.Int64
	smuxShaperDataFrames            atomic.Int64
	smuxShaperQueueSize             atomic.Int64
	smuxShaperStarvationPreventions atomic.Int64

	// Connection pool metrics
	poolSize        atomic.Int64
	poolUtilization atomic.Uint64 // bit-cast float64
	poolWaitTimeMs  atomic.Int64
	poolAdjustments sync.Map // direction -> *atomic.Int64

	reverseAuthRejects   atomic.Int64
	handshakeFailures    atomic.Int64
	deprecatedLegacyMode atomic.Int64

	// Mesh networking metrics
	meshNodeActive       atomic.Bool
	meshNATType          atomic.Value // string
	meshPeersTotal       atomic.Int64
	meshPeersJoined      atomic.Int64
	meshPeersLeft        atomic.Int64
	meshRelayPackets     atomic.Int64
	meshRouteUpdates     atomic.Int64
	meshHolePunchSuccess atomic.Int64
	meshHolePunchFail    atomic.Int64
)

type latencyWindow struct {
	mu      sync.Mutex
	samples []float64
}

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
func IncUQSPSessions()                { uqspSessionsTotal.Add(1) }
func IncUQSPStreamsActive()           { uqspStreamsActive.Add(1) }
func DecUQSPStreamsActive()           { uqspStreamsActive.Add(-1) }
func SetUQSPDatagramSessions(n int64) { uqspDatagramSessions.Store(n) }
func IncUQSPDatagramSessions()        { uqspDatagramSessions.Add(1) }
func DecUQSPDatagramSessions()        { uqspDatagramSessions.Add(-1) }
func IncUQSPcapsules(n int64) {
	if n > 0 {
		uqspCapsulesTotal.Add(n)
	}
}
func IncUQSPobfuscationOps()  { uqspObfuscationOps.Add(1) }
func IncUQSPcongestionEvent() { uqspCongestionEvents.Add(1) }
func IncUQSPreplayDrops()     { uqspReplayDrops.Add(1) }
func IncUQSPhandshake()       { uqspHandshakeTotal.Add(1) }
func AddUQSPhandshakeDuration(d time.Duration) {
	uqspHandshakeDuration.Add(d.Nanoseconds())
}
func IncRawENOBUFS()             { rawENOBUFSTotal.Add(1) }
func IncRawWriteRetry()          { rawWriteRetriesTotal.Add(1) }
func IncRawDrop()                { rawDropsTotal.Add(1) }
func IncUQSPReassemblyEviction() { uqspReassemblyEvicts.Add(1) }
func GetUQSPhandshakeAvgMs() int64 {
	total := uqspHandshakeTotal.Load()
	if total == 0 {
		return 0
	}
	return uqspHandshakeDuration.Load() / total / 1e6
}

// Underlay dialer metrics functions
func SetUnderlaySelected(dialerType string) {
	underlaySelected.Store(dialerType)
}

func SetActivePathVariant(variant string) {
	if variant == "" {
		return
	}
	activePathVariant.Store(variant)
}

func GetActivePathVariant() string {
	v := activePathVariant.Load()
	if v == nil {
		return "unknown"
	}
	return v.(string)
}

func GetUnderlaySelected() string {
	v := underlaySelected.Load()
	if v == nil {
		return "direct" // default
	}
	return v.(string)
}

func SetWARPHealth(status string) {
	warpHealth.Store(status)
}

func GetWARPHealth() string {
	v := warpHealth.Load()
	if v == nil {
		return "down" // default
	}
	return v.(string)
}

func IncPathPolicyWinnerSelection(candidate string) {
	if candidate == "" {
		return
	}
	v, _ := pathPolicyWinners.LoadOrStore(candidate, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

func IncPathPolicyRerace() { pathPolicyReraces.Add(1) }

func ObservePathPolicyDialLatency(candidate string, d time.Duration) {
	if candidate == "" || d <= 0 {
		return
	}
	v, _ := pathPolicyLatency.LoadOrStore(candidate, &latencyWindow{})
	w := v.(*latencyWindow)
	w.mu.Lock()
	defer w.mu.Unlock()
	// Keep a bounded rolling window to limit memory while preserving recent behavior.
	if len(w.samples) >= 256 {
		copy(w.samples, w.samples[1:])
		w.samples = w.samples[:255]
	}
	w.samples = append(w.samples, float64(d)/float64(time.Millisecond))
}

func pathPolicyLatencySnapshot() map[string]PathPolicyLatencyQuantiles {
	out := make(map[string]PathPolicyLatencyQuantiles)
	pathPolicyLatency.Range(func(k, v any) bool {
		candidate, ok := k.(string)
		if !ok || candidate == "" {
			return true
		}
		w := v.(*latencyWindow)
		w.mu.Lock()
		samples := append([]float64(nil), w.samples...)
		w.mu.Unlock()
		if len(samples) == 0 {
			return true
		}
		sort.Float64s(samples)
		out[candidate] = PathPolicyLatencyQuantiles{
			P50Ms: quantile(samples, 0.50),
			P95Ms: quantile(samples, 0.95),
		}
		return true
	})
	return out
}

func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	if q <= 0 {
		return sorted[0]
	}
	if q >= 1 {
		return sorted[len(sorted)-1]
	}
	idx := int(float64(len(sorted)-1) * q)
	return sorted[idx]
}

// Reverse mode metrics functions
func IncReverseReconnectAttempts()            { reverseReconnectAttemptsTotal.Add(1) }
func IncReverseReconnectTimeout()             { reverseReconnectTimeout.Add(1) }
func IncReverseReconnectRefused()             { reverseReconnectRefused.Add(1) }
func IncReverseReconnectReset()               { reverseReconnectReset.Add(1) }
func IncReverseConnectionsActive()            { reverseConnectionsActive.Add(1) }
func DecReverseConnectionsActive()            { reverseConnectionsActive.Add(-1) }
func GetReverseReconnectAttemptsTotal() int64 { return reverseReconnectAttemptsTotal.Load() }
func GetReverseReconnectTimeout() int64       { return reverseReconnectTimeout.Load() }
func GetReverseReconnectRefused() int64       { return reverseReconnectRefused.Load() }
func GetReverseReconnectReset() int64         { return reverseReconnectReset.Load() }
func GetReverseConnectionsActive() int64      { return reverseConnectionsActive.Load() }

// Xmux metrics functions
func IncXmuxReuse() { xmuxReuses.Add(1) }
func IncXmuxRotation(reason string) {
	if reason == "" {
		return
	}
	v, _ := xmuxRotations.LoadOrStore(reason, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}
func IncXmuxActiveConnections()        { xmuxActiveConnections.Add(1) }
func DecXmuxActiveConnections()        { xmuxActiveConnections.Add(-1) }
func SetXmuxActiveConnections(n int64) { xmuxActiveConnections.Store(n) }

// FakeTCP metrics functions
func IncFakeTCPAEADAuthFailures() { faketcpAEADAuthFailures.Add(1) }
func IncFakeTCPKeyDerivations()   { faketcpKeyDerivations.Add(1) }
func AddFakeTCPEncryptedBytes(n int64, direction string) {
	if n <= 0 || direction == "" {
		return
	}
	v, _ := faketcpEncryptedBytes.LoadOrStore(direction, &atomic.Int64{})
	v.(*atomic.Int64).Add(n)
}

// REALITY spider metrics functions
func IncRealitySpiderFetch() { realitySpiderFetches.Add(1) }
func AddRealitySpiderDuration(d time.Duration) {
	realitySpiderDurationNanos.Add(d.Nanoseconds())
}
func SetRealitySpiderURLsCrawled(n int64) { realitySpiderURLsCrawled.Store(n) }
func IncRealitySpiderURLsCrawled()        { realitySpiderURLsCrawled.Add(1) }
func DecRealitySpiderURLsCrawled()        { realitySpiderURLsCrawled.Add(-1) }

// Entropy metrics functions
func AddEntropyBytes(n int64, class string) {
	if n <= 0 || class == "" {
		return
	}
	v, _ := entropyBytesGenerated.LoadOrStore(class, &atomic.Int64{})
	v.(*atomic.Int64).Add(n)
}
func IncEntropyReseeds() { entropyReseeds.Add(1) }
func SetEntropyMethod(method string, active bool) {
	if method == "" {
		return
	}
	v, _ := entropyMethod.LoadOrStore(method, &atomic.Int64{})
	if active {
		v.(*atomic.Int64).Store(1)
	} else {
		v.(*atomic.Int64).Store(0)
	}
}

// KCP FEC metrics functions
func IncKCPFECParitySkipped()       { kcpFECParitySkipped.Add(1) }
func IncKCPFECAutoTuneAdjustments() { kcpFECAutoTuneAdjustments.Add(1) }
func SetKCPFECShards(data, parity int64) {
	kcpFECDataShards.Store(data)
	kcpFECParityShards.Store(parity)
}

// Smux shaper metrics functions
func IncSmuxShaperControlFrames()         { smuxShaperControlFrames.Add(1) }
func IncSmuxShaperDataFrames()            { smuxShaperDataFrames.Add(1) }
func SetSmuxShaperQueueSize(n int64)      { smuxShaperQueueSize.Store(n) }
func IncSmuxShaperStarvationPreventions() { smuxShaperStarvationPreventions.Add(1) }

// Connection pool metrics functions
func SetPoolSize(n int64) { poolSize.Store(n) }
func SetPoolUtilization(u float64) {
	poolUtilization.Store(uint64(u * 1e6)) // store as micros for precision
}
func ObservePoolWaitTime(d time.Duration) {
	if d < 0 {
		d = 0
	}
	poolWaitTimeMs.Store(d.Milliseconds())
}
func IncPoolAdjustment(direction string) {
	if direction == "" {
		return
	}
	v, _ := poolAdjustments.LoadOrStore(direction, &atomic.Int64{})
	v.(*atomic.Int64).Add(1)
}

func IncReverseAuthRejects()   { reverseAuthRejects.Add(1) }
func IncHandshakeFailure()     { handshakeFailures.Add(1) }
func IncDeprecatedLegacyMode() { deprecatedLegacyMode.Add(1) }

// Mesh networking metrics functions
func SetMeshNodeActive(active bool) { meshNodeActive.Store(active) }
func SetMeshNATType(natType string) { meshNATType.Store(natType) }
func SetMeshPeersTotal(n int64)     { meshPeersTotal.Store(n) }
func IncMeshPeersJoined()           { meshPeersJoined.Add(1) }
func IncMeshPeersLeft()             { meshPeersLeft.Add(1) }
func IncMeshRelayPackets()          { meshRelayPackets.Add(1) }
func IncMeshRouteUpdates()          { meshRouteUpdates.Add(1) }
func IncMeshHolePunchSuccess()      { meshHolePunchSuccess.Add(1) }
func IncMeshHolePunchFail()         { meshHolePunchFail.Add(1) }
func GetMeshNATType() string {
	v := meshNATType.Load()
	if v == nil {
		return "Unknown"
	}
	return v.(string)
}

// Getter functions for text status and status CLI.
func GetSessionsTotal() int64   { return sessionsTotal.Load() }
func GetSessionsActive() int64  { return sessionsActive.Load() }
func GetStreamsTotal() int64    { return streamsTotal.Load() }
func GetStreamsActive() int64   { return streamsActive.Load() }
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
		UQSPSessionsTotal:    uqspSessionsTotal.Load(),
		UQSPStreamsActive:    uqspStreamsActive.Load(),
		UQSPDatagramSessions: uqspDatagramSessions.Load(),
		UQSPCapsulesTotal:    uqspCapsulesTotal.Load(),
		UQSPObfuscationOps:   uqspObfuscationOps.Load(),
		UQSPCongestionEvents: uqspCongestionEvents.Load(),
		UQSPReplayDrops:      uqspReplayDrops.Load(),
		UQSPHandshakeTotal:   uqspHandshakeTotal.Load(),
		UQSPHandshakeAvgMs:   GetUQSPhandshakeAvgMs(),
		RawENOBUFSTotal:      rawENOBUFSTotal.Load(),
		RawWriteRetriesTotal: rawWriteRetriesTotal.Load(),
		RawDropsTotal:        rawDropsTotal.Load(),
		UQSPReassemblyEvicts: uqspReassemblyEvicts.Load(),
		// Reverse mode metrics
		ReverseReconnectAttemptsTotal: reverseReconnectAttemptsTotal.Load(),
		ReverseReconnectTimeout:       reverseReconnectTimeout.Load(),
		ReverseReconnectRefused:       reverseReconnectRefused.Load(),
		ReverseReconnectReset:         reverseReconnectReset.Load(),
		ReverseConnectionsActive:      reverseConnectionsActive.Load(),
		// Underlay dialer metrics
		UnderlaySelected:  GetUnderlaySelected(),
		ActivePathVariant: GetActivePathVariant(),
		WARPHealth:        GetWARPHealth(),
		PathPolicyWinnerSelectionsTotal: func() map[string]int64 {
			m := make(map[string]int64)
			pathPolicyWinners.Range(func(k, v any) bool {
				m[k.(string)] = v.(*atomic.Int64).Load()
				return true
			})
			return m
		}(),
		PathPolicyReracesTotal:  pathPolicyReraces.Load(),
		PathPolicyDialLatencyMs: pathPolicyLatencySnapshot(),
		// Xmux metrics
		XmuxConnectionReusesTotal: xmuxReuses.Load(),
		XmuxConnectionRotationsTotal: func() map[string]int64 {
			m := make(map[string]int64)
			xmuxRotations.Range(func(k, v any) bool {
				m[k.(string)] = v.(*atomic.Int64).Load()
				return true
			})
			return m
		}(),
		XmuxActiveConnections: xmuxActiveConnections.Load(),

		// FakeTCP metrics
		FakeTCPAEADAuthFailuresTotal: faketcpAEADAuthFailures.Load(),
		FakeTCPKeyDerivationsTotal:   faketcpKeyDerivations.Load(),
		FakeTCPEncryptedBytesTotal: func() map[string]int64 {
			m := make(map[string]int64)
			faketcpEncryptedBytes.Range(func(k, v any) bool {
				m[k.(string)] = v.(*atomic.Int64).Load()
				return true
			})
			return m
		}(),

		// REALITY spider metrics
		RealitySpiderFetchesTotal:    realitySpiderFetches.Load(),
		RealitySpiderDurationSeconds: float64(realitySpiderDurationNanos.Load()) / 1e9,
		RealitySpiderURLsCrawled:     realitySpiderURLsCrawled.Load(),

		// Entropy metrics
		EntropyBytesGeneratedTotal: func() map[string]int64 {
			m := make(map[string]int64)
			entropyBytesGenerated.Range(func(k, v any) bool {
				m[k.(string)] = v.(*atomic.Int64).Load()
				return true
			})
			return m
		}(),
		EntropyReseedsTotal: entropyReseeds.Load(),
		EntropyMethod: func() map[string]int64 {
			m := make(map[string]int64)
			entropyMethod.Range(func(k, v any) bool {
				m[k.(string)] = v.(*atomic.Int64).Load()
				return true
			})
			return m
		}(),
		// KCP FEC metrics
		KCPFECParitySkippedTotal:       kcpFECParitySkipped.Load(),
		KCPFECAutoTuneAdjustmentsTotal: kcpFECAutoTuneAdjustments.Load(),
		KCPFECDataShards:               kcpFECDataShards.Load(),
		KCPFECParityShards:             kcpFECParityShards.Load(),

		// Smux shaper metrics
		SmuxShaperControlFramesTotal:         smuxShaperControlFrames.Load(),
		SmuxShaperDataFramesTotal:            smuxShaperDataFrames.Load(),
		SmuxShaperQueueSize:                  smuxShaperQueueSize.Load(),
		SmuxShaperStarvationPreventionsTotal: smuxShaperStarvationPreventions.Load(),

		// Connection pool metrics
		PoolSize:        poolSize.Load(),
		PoolUtilization: float64(poolUtilization.Load()) / 1e6,
		PoolWaitTimeMs:  poolWaitTimeMs.Load(),
		PoolAdjustmentsTotal: func() map[string]int64 {
			m := make(map[string]int64)
			poolAdjustments.Range(func(k, v any) bool {
				m[k.(string)] = v.(*atomic.Int64).Load()
				return true
			})
			return m
		}(),
		ReverseAuthRejectsTotal:   reverseAuthRejects.Load(),
		HandshakeFailuresTotal:    handshakeFailures.Load(),
		DeprecatedLegacyModeTotal: deprecatedLegacyMode.Load(),
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

func Start(addr string, authToken string, enablePprof bool) {
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

	if enablePprof {
		// pprof endpoints are served on the metrics listener and protected by the same auth gate.
		mux.HandleFunc("/debug/pprof/", auth(pprof.Index))
		mux.HandleFunc("/debug/pprof/cmdline", auth(pprof.Cmdline))
		mux.HandleFunc("/debug/pprof/profile", auth(pprof.Profile))
		mux.HandleFunc("/debug/pprof/symbol", auth(pprof.Symbol))
		mux.HandleFunc("/debug/pprof/trace", auth(pprof.Trace))
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
