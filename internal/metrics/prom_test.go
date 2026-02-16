package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func seedAllMetrics() {
	IncSessions()
	IncStreams()
	SetUDPSessions(5)
	IncErrors()
	SetPingRTT(15 * time.Millisecond)
	AddTrafficInbound(1024)
	AddTrafficOutbound(2048)
	SetSocketsOpen(10)
	IncObfsJunkPackets(3)
	IncObfsSignaturePackets(2)
	IncRawENOBUFS()
	IncRawWriteRetry()
	IncRawDrop()
	IncUQSPReassemblyEviction()
	SetUnderlaySelected("warp")
	SetActivePathVariant("UDP+")
	SetWARPHealth("up")
	IncPathPolicyWinnerSelection("warp")
	IncPathPolicyWinnerSelection("direct")
	IncPathPolicyRerace()
	ObservePathPolicyDialLatency("warp", 20*time.Millisecond)
	ObservePathPolicyDialLatency("warp", 40*time.Millisecond)
	ObservePathPolicyDialLatency("warp", 80*time.Millisecond)
	ObservePathPolicyDialLatency("direct", 10*time.Millisecond)
	IncReverseReconnectAttempts()
	IncReverseConnectionsActive()
	IncTransportSession("quic")
	IncTransportSession("kcp")
	IncXmuxReuse()
	IncXmuxRotation("max_age")
	IncXmuxRotation("idle")
	IncXmuxActiveConnections()
	IncFakeTCPAEADAuthFailures()
	IncFakeTCPKeyDerivations()
	AddFakeTCPEncryptedBytes(512, "tx")
	AddFakeTCPEncryptedBytes(256, "rx")
	IncRealitySpiderFetch()
	AddRealitySpiderDuration(100 * time.Millisecond)
	SetRealitySpiderURLsCrawled(42)
	AddEntropyBytes(4096, "main")
	AddEntropyBytes(2048, "reserve")
	IncEntropyReseeds()
	SetEntropyMethod("getrandom", true)
	IncKCPFECParitySkipped()
	IncKCPFECAutoTuneAdjustments()
	SetKCPFECShards(10, 4)
	IncSmuxShaperControlFrames()
	IncSmuxShaperDataFrames()
	SetSmuxShaperQueueSize(100)
	IncSmuxShaperStarvationPreventions()
	SetPoolSize(50)
	SetPoolUtilization(0.75)
	ObservePoolWaitTime(25 * time.Millisecond)
	IncPoolAdjustment("up")
	IncPoolAdjustment("down")
	IncReverseAuthRejects()
	IncHandshakeFailure()
	IncDeprecatedLegacyMode()
	RecordCarrierConnection("quic")
	RecordCarrierConnection("kcp")
	RecordCarrierTraffic("quic", 1000, 2000)
}

func TestPromHandler_AllMetricsPresent(t *testing.T) {
	seedAllMetrics()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics/prom", nil)
	PromHandler(rr, req)

	if rr.Code != 200 {
		t.Fatalf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	expectedMetrics := []string{
		"stealthlink_sessions_total",
		"stealthlink_sessions_active",
		"stealthlink_streams_total",
		"stealthlink_streams_active",
		"stealthlink_udp_sessions",
		"stealthlink_errors_total",
		"stealthlink_last_ping_rtt_ms",
		"stealthlink_traffic_bytes_total",
		"stealthlink_traffic_bytes_inbound",
		"stealthlink_traffic_bytes_outbound",
		"stealthlink_sockets_open",
		"stealthlink_obfs_junk_packets_total",
		"stealthlink_obfs_signature_packets_total",
		"stealthlink_raw_enobufs_total",
		"stealthlink_raw_write_retries_total",
		"stealthlink_raw_drops_total",
		"stealthlink_uqsp_reassembly_evictions_total",
		"stealthlink_underlay_selected",
		"stealthlink_active_path_variant",
		"stealthlink_warp_health",
		"stealthlink_path_policy_winner_selections_total",
		"stealthlink_path_policy_reraces_total",
		"stealthlink_path_policy_dial_latency_ms",
		"stealthlink_reverse_reconnect_attempts_total",
		"stealthlink_reverse_connections_active",
		"stealthlink_reverse_auth_rejects_total",
		"stealthlink_handshake_failures_total",
		"stealthlink_deprecated_legacy_mode_total",
		"stealthlink_transport_sessions_active",
		"stealthlink_xmux_connection_reuses_total",
		"stealthlink_xmux_connection_rotations_total",
		"stealthlink_xmux_active_connections",
		"stealthlink_faketcp_aead_auth_failures_total",
		"stealthlink_faketcp_key_derivations_total",
		"stealthlink_faketcp_encrypted_bytes_total",
		"stealthlink_reality_spider_fetches_total",
		"stealthlink_reality_spider_duration_seconds",
		"stealthlink_reality_spider_urls_crawled",
		"stealthlink_entropy_bytes_generated_total",
		"stealthlink_entropy_reseeds_total",
		"stealthlink_entropy_method",
		"stealthlink_kcp_fec_parity_skipped_total",
		"stealthlink_kcp_fec_auto_tune_adjustments_total",
		"stealthlink_kcp_fec_data_shards",
		"stealthlink_kcp_fec_parity_shards",
		"stealthlink_smux_shaper_control_frames_total",
		"stealthlink_smux_shaper_data_frames_total",
		"stealthlink_smux_shaper_queue_size",
		"stealthlink_smux_shaper_starvation_preventions_total",
		"stealthlink_pool_size",
		"stealthlink_pool_utilization",
		"stealthlink_pool_wait_time_ms",
		"stealthlink_pool_adjustments_total",
		"stealthlink_tcp_average_rtt_ms",
		"stealthlink_tcp_loss_events_total",
		"stealthlink_tcp_retransmits_total",
		"stealthlink_tcp_average_cwnd",
		"stealthlink_tcp_session_count",
		"stealthlink_tcp_carrier_connections_total",
		"stealthlink_tcp_carrier_connections_active",
		"stealthlink_tcp_carrier_bytes_sent_total",
		"stealthlink_tcp_carrier_bytes_received_total",
		"stealthlink_tcp_carrier_errors_total",
		"stealthlink_tcp_carrier_average_rtt_ms",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("expected metric %q not found in Prometheus output", metric)
		}
	}

	labeledChecks := []struct {
		label    string
		contains string
	}{
		{`stealthlink_underlay_selected{type="warp"}`, "1"},
		{`stealthlink_active_path_variant{variant="UDP+"}`, "1"},
		{`stealthlink_warp_health{status="up"}`, "1"},
		{`stealthlink_path_policy_winner_selections_total{candidate="warp"}`, ""},
		{`stealthlink_path_policy_reraces_total`, ""},
		{`stealthlink_path_policy_dial_latency_ms{candidate="warp",quantile="0.50"}`, ""},
		{`stealthlink_path_policy_dial_latency_ms{candidate="warp",quantile="0.95"}`, ""},
		{`stealthlink_xmux_connection_rotations_total{reason="max_age"}`, ""},
		{`stealthlink_xmux_connection_rotations_total{reason="idle"}`, ""},
		{`stealthlink_faketcp_encrypted_bytes_total{direction="tx"}`, "512"},
		{`stealthlink_faketcp_encrypted_bytes_total{direction="rx"}`, "256"},
		{`stealthlink_entropy_bytes_generated_total{class="main"}`, "4096"},
		{`stealthlink_entropy_method{method="getrandom"}`, "1"},
		{`stealthlink_pool_adjustments_total{direction="up"}`, ""},
		{`stealthlink_tcp_carrier_connections_total{carrier="quic"}`, "1"},
		{`stealthlink_tcp_carrier_bytes_sent_total{carrier="quic"}`, "1000"},
		{`stealthlink_tcp_carrier_bytes_received_total{carrier="quic"}`, "2000"},
	}

	for _, check := range labeledChecks {
		if !strings.Contains(body, check.label) {
			t.Errorf("expected labeled metric %q not found in output", check.label)
		}
	}
}

func TestPromHandler_HelpAndTypeHeaders(t *testing.T) {
	seedAllMetrics()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics/prom", nil)
	PromHandler(rr, req)

	body := rr.Body.String()

	helpCount := strings.Count(body, "# HELP stealthlink_")
	if helpCount < 30 {
		t.Errorf("expected at least 30 # HELP headers, got %d", helpCount)
	}

	typeCount := strings.Count(body, "# TYPE stealthlink_")
	if typeCount < 30 {
		t.Errorf("expected at least 30 # TYPE headers, got %d", typeCount)
	}

	helpTypePairs := []string{
		"# HELP stealthlink_sessions_total",
		"# TYPE stealthlink_sessions_total counter",
		"# HELP stealthlink_streams_total",
		"# TYPE stealthlink_streams_total counter",
		"# HELP stealthlink_udp_sessions",
		"# TYPE stealthlink_udp_sessions gauge",
		"# HELP stealthlink_errors_total",
		"# TYPE stealthlink_errors_total counter",
		"# HELP stealthlink_last_ping_rtt_ms",
		"# TYPE stealthlink_last_ping_rtt_ms gauge",
		"# HELP stealthlink_traffic_bytes_total",
		"# TYPE stealthlink_traffic_bytes_total counter",
		"# HELP stealthlink_sockets_open",
		"# TYPE stealthlink_sockets_open gauge",
		"# HELP stealthlink_underlay_selected",
		"# TYPE stealthlink_underlay_selected gauge",
		"# HELP stealthlink_active_path_variant",
		"# TYPE stealthlink_active_path_variant gauge",
		"# HELP stealthlink_warp_health",
		"# TYPE stealthlink_warp_health gauge",
		"# HELP stealthlink_path_policy_winner_selections_total",
		"# TYPE stealthlink_path_policy_winner_selections_total counter",
		"# HELP stealthlink_path_policy_reraces_total",
		"# TYPE stealthlink_path_policy_reraces_total counter",
		"# HELP stealthlink_path_policy_dial_latency_ms",
		"# TYPE stealthlink_path_policy_dial_latency_ms gauge",
		"# HELP stealthlink_reverse_reconnect_attempts_total",
		"# TYPE stealthlink_reverse_reconnect_attempts_total counter",
		"# HELP stealthlink_xmux_connection_reuses_total",
		"# TYPE stealthlink_xmux_connection_reuses_total counter",
		"# HELP stealthlink_xmux_active_connections",
		"# TYPE stealthlink_xmux_active_connections gauge",
		"# HELP stealthlink_kcp_fec_data_shards",
		"# TYPE stealthlink_kcp_fec_data_shards gauge",
		"# HELP stealthlink_pool_size",
		"# TYPE stealthlink_pool_size gauge",
		"# HELP stealthlink_pool_wait_time_ms",
		"# TYPE stealthlink_pool_wait_time_ms gauge",
		"# HELP stealthlink_tcp_average_rtt_ms",
		"# TYPE stealthlink_tcp_average_rtt_ms gauge",
	}

	for _, expected := range helpTypePairs {
		if !strings.Contains(body, expected) {
			t.Errorf("expected %q not found in Prometheus output", expected)
		}
	}
}

func TestPromHandler_ZeroState(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/metrics/prom", nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PromHandler panicked: %v", r)
		}
	}()

	PromHandler(rr, req)

	if rr.Code != 200 {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	body := rr.Body.String()

	if !strings.Contains(body, "stealthlink_sessions_total") {
		t.Error("expected stealthlink_sessions_total metric")
	}
	if !strings.Contains(body, "stealthlink_streams_total") {
		t.Error("expected stealthlink_streams_total metric")
	}
	if !strings.Contains(body, "stealthlink_errors_total") {
		t.Error("expected stealthlink_errors_total metric")
	}
	if !strings.Contains(body, "stealthlink_udp_sessions") {
		t.Error("expected stealthlink_udp_sessions metric")
	}
	if !strings.Contains(body, "stealthlink_sockets_open") {
		t.Error("expected stealthlink_sockets_open metric")
	}

	if !strings.Contains(body, "# HELP stealthlink_sessions_total") {
		t.Error("expected HELP header for sessions_total")
	}
	if !strings.Contains(body, "# TYPE stealthlink_sessions_total counter") {
		t.Error("expected TYPE header for sessions_total")
	}

	if !strings.Contains(body, "# HELP stealthlink_streams_total") {
		t.Error("expected HELP header for streams_total")
	}
	if !strings.Contains(body, "# TYPE stealthlink_streams_total counter") {
		t.Error("expected TYPE header for streams_total")
	}

	if !strings.Contains(body, "# HELP stealthlink_errors_total") {
		t.Error("expected HELP header for errors_total")
	}
	if !strings.Contains(body, "# TYPE stealthlink_errors_total counter") {
		t.Error("expected TYPE header for errors_total")
	}
}
