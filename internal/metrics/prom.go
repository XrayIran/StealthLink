package metrics

import (
	"fmt"
	"net/http"
)

func PromHandler(w http.ResponseWriter, r *http.Request) {
	st := SnapshotData()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	fmt.Fprintf(w, "# HELP stealthlink_sessions_total Total number of sessions created\n")
	fmt.Fprintf(w, "# TYPE stealthlink_sessions_total counter\n")
	fmt.Fprintf(w, "stealthlink_sessions_total %d\n", st.SessionsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_sessions_active Currently active sessions\n")
	fmt.Fprintf(w, "# TYPE stealthlink_sessions_active gauge\n")
	fmt.Fprintf(w, "stealthlink_sessions_active %d\n", st.SessionsActive)

	fmt.Fprintf(w, "# HELP stealthlink_streams_total Total number of streams created\n")
	fmt.Fprintf(w, "# TYPE stealthlink_streams_total counter\n")
	fmt.Fprintf(w, "stealthlink_streams_total %d\n", st.StreamsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_streams_active Currently active streams\n")
	fmt.Fprintf(w, "# TYPE stealthlink_streams_active gauge\n")
	fmt.Fprintf(w, "stealthlink_streams_active %d\n", st.StreamsActive)

	fmt.Fprintf(w, "# HELP stealthlink_udp_sessions Current number of UDP sessions\n")
	fmt.Fprintf(w, "# TYPE stealthlink_udp_sessions gauge\n")
	fmt.Fprintf(w, "stealthlink_udp_sessions %d\n", st.UDPSessions)

	fmt.Fprintf(w, "# HELP stealthlink_errors_total Total number of errors\n")
	fmt.Fprintf(w, "# TYPE stealthlink_errors_total counter\n")
	fmt.Fprintf(w, "stealthlink_errors_total %d\n", st.Errors)

	fmt.Fprintf(w, "# HELP stealthlink_last_ping_rtt_ms Last ping RTT in milliseconds\n")
	fmt.Fprintf(w, "# TYPE stealthlink_last_ping_rtt_ms gauge\n")
	fmt.Fprintf(w, "stealthlink_last_ping_rtt_ms %d\n", st.LastPingRTTMs)

	fmt.Fprintf(w, "# HELP stealthlink_traffic_bytes_total Total traffic in bytes\n")
	fmt.Fprintf(w, "# TYPE stealthlink_traffic_bytes_total counter\n")
	fmt.Fprintf(w, "stealthlink_traffic_bytes_total %d\n", st.TrafficBytesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_traffic_bytes_inbound Total inbound traffic in bytes\n")
	fmt.Fprintf(w, "# TYPE stealthlink_traffic_bytes_inbound counter\n")
	fmt.Fprintf(w, "stealthlink_traffic_bytes_inbound %d\n", st.TrafficBytesInbound)

	fmt.Fprintf(w, "# HELP stealthlink_traffic_bytes_outbound Total outbound traffic in bytes\n")
	fmt.Fprintf(w, "# TYPE stealthlink_traffic_bytes_outbound counter\n")
	fmt.Fprintf(w, "stealthlink_traffic_bytes_outbound %d\n", st.TrafficBytesOutbound)

	fmt.Fprintf(w, "# HELP stealthlink_sockets_open Currently open sockets\n")
	fmt.Fprintf(w, "# TYPE stealthlink_sockets_open gauge\n")
	fmt.Fprintf(w, "stealthlink_sockets_open %d\n", st.SocketsOpen)

	fmt.Fprintf(w, "# HELP stealthlink_obfs_junk_packets_total Total obfuscation junk packets sent\n")
	fmt.Fprintf(w, "# TYPE stealthlink_obfs_junk_packets_total counter\n")
	fmt.Fprintf(w, "stealthlink_obfs_junk_packets_total %d\n", st.ObfsJunkPacketsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_obfs_signature_packets_total Total obfuscation signature packets sent\n")
	fmt.Fprintf(w, "# TYPE stealthlink_obfs_signature_packets_total counter\n")
	fmt.Fprintf(w, "stealthlink_obfs_signature_packets_total %d\n", st.ObfsSignaturePacketsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_raw_enobufs_total Total ENOBUFS errors on raw sockets\n")
	fmt.Fprintf(w, "# TYPE stealthlink_raw_enobufs_total counter\n")
	fmt.Fprintf(w, "stealthlink_raw_enobufs_total %d\n", st.RawENOBUFSTotal)

	fmt.Fprintf(w, "# HELP stealthlink_raw_write_retries_total Total write retries on raw sockets\n")
	fmt.Fprintf(w, "# TYPE stealthlink_raw_write_retries_total counter\n")
	fmt.Fprintf(w, "stealthlink_raw_write_retries_total %d\n", st.RawWriteRetriesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_raw_drops_total Total packet drops on raw sockets\n")
	fmt.Fprintf(w, "# TYPE stealthlink_raw_drops_total counter\n")
	fmt.Fprintf(w, "stealthlink_raw_drops_total %d\n", st.RawDropsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_uqsp_reassembly_evictions_total Total UQSP datagram reassembly evictions\n")
	fmt.Fprintf(w, "# TYPE stealthlink_uqsp_reassembly_evictions_total counter\n")
	fmt.Fprintf(w, "stealthlink_uqsp_reassembly_evictions_total %d\n", st.UQSPReassemblyEvicts)

	// Underlay + WARP metrics (operator visibility)
	fmt.Fprintf(w, "# HELP stealthlink_underlay_selected Currently selected underlay (1=selected)\n")
	fmt.Fprintf(w, "# TYPE stealthlink_underlay_selected gauge\n")
	for _, t := range []string{"direct", "warp", "socks"} {
		v := 0
		if st.UnderlaySelected == t {
			v = 1
		}
		fmt.Fprintf(w, "stealthlink_underlay_selected{type=%q} %d\n", t, v)
	}

	fmt.Fprintf(w, "# HELP stealthlink_active_path_variant Currently active UQSP path variant (1=active)\n")
	fmt.Fprintf(w, "# TYPE stealthlink_active_path_variant gauge\n")
	for _, variant := range []string{"HTTP+", "TCP+", "TLS+", "UDP+", "TLS", "legacy", "unknown"} {
		v := 0
		if st.ActivePathVariant == variant {
			v = 1
		}
		fmt.Fprintf(w, "stealthlink_active_path_variant{variant=%q} %d\n", variant, v)
	}

	fmt.Fprintf(w, "# HELP stealthlink_warp_health Current WARP health (1=active)\n")
	fmt.Fprintf(w, "# TYPE stealthlink_warp_health gauge\n")
	for _, s := range []string{"up", "down"} {
		v := 0
		if st.WARPHealth == s {
			v = 1
		}
		fmt.Fprintf(w, "stealthlink_warp_health{status=%q} %d\n", s, v)
	}

	fmt.Fprintf(w, "# HELP stealthlink_path_policy_winner_selections_total Total winner selections per path-policy candidate\n")
	fmt.Fprintf(w, "# TYPE stealthlink_path_policy_winner_selections_total counter\n")
	for candidate, n := range st.PathPolicyWinnerSelectionsTotal {
		fmt.Fprintf(w, "stealthlink_path_policy_winner_selections_total{candidate=%q} %d\n", candidate, n)
	}

	fmt.Fprintf(w, "# HELP stealthlink_path_policy_reraces_total Total path-policy re-races\n")
	fmt.Fprintf(w, "# TYPE stealthlink_path_policy_reraces_total counter\n")
	fmt.Fprintf(w, "stealthlink_path_policy_reraces_total %d\n", st.PathPolicyReracesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_path_policy_dial_latency_ms Path-policy dial latency quantiles by candidate\n")
	fmt.Fprintf(w, "# TYPE stealthlink_path_policy_dial_latency_ms gauge\n")
	for candidate, q := range st.PathPolicyDialLatencyMs {
		fmt.Fprintf(w, "stealthlink_path_policy_dial_latency_ms{candidate=%q,quantile=%q} %.3f\n", candidate, "0.50", q.P50Ms)
		fmt.Fprintf(w, "stealthlink_path_policy_dial_latency_ms{candidate=%q,quantile=%q} %.3f\n", candidate, "0.95", q.P95Ms)
	}

	// Reverse mode metrics
	fmt.Fprintf(w, "# HELP stealthlink_reverse_reconnect_attempts_total Total reverse reconnect attempts\n")
	fmt.Fprintf(w, "# TYPE stealthlink_reverse_reconnect_attempts_total counter\n")
	fmt.Fprintf(w, "stealthlink_reverse_reconnect_attempts_total %d\n", st.ReverseReconnectAttemptsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_reverse_connections_active Current active reverse connections\n")
	fmt.Fprintf(w, "# TYPE stealthlink_reverse_connections_active gauge\n")
	fmt.Fprintf(w, "stealthlink_reverse_connections_active %d\n", st.ReverseConnectionsActive)

	fmt.Fprintf(w, "# HELP stealthlink_reverse_auth_rejects_total Total reverse authentication rejects\n")
	fmt.Fprintf(w, "# TYPE stealthlink_reverse_auth_rejects_total counter\n")
	fmt.Fprintf(w, "stealthlink_reverse_auth_rejects_total %d\n", st.ReverseAuthRejectsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_handshake_failures_total Total failed handshakes\n")
	fmt.Fprintf(w, "# TYPE stealthlink_handshake_failures_total counter\n")
	fmt.Fprintf(w, "stealthlink_handshake_failures_total %d\n", st.HandshakeFailuresTotal)

	fmt.Fprintf(w, "# HELP stealthlink_deprecated_legacy_mode_total Total legacy-mode deprecation hits\n")
	fmt.Fprintf(w, "# TYPE stealthlink_deprecated_legacy_mode_total counter\n")
	fmt.Fprintf(w, "stealthlink_deprecated_legacy_mode_total %d\n", st.DeprecatedLegacyModeTotal)

	for name, n := range st.TransportSessions {
		fmt.Fprintf(w, "stealthlink_transport_sessions_active{transport=%q} %d\n", name, n)
	}

	// Xmux metrics
	fmt.Fprintf(w, "# HELP stealthlink_xmux_connection_reuses_total Total number of Xmux connection reuses\n")
	fmt.Fprintf(w, "# TYPE stealthlink_xmux_connection_reuses_total counter\n")
	fmt.Fprintf(w, "stealthlink_xmux_connection_reuses_total %d\n", st.XmuxConnectionReusesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_xmux_connection_rotations_total Total number of Xmux connection rotations by reason\n")
	fmt.Fprintf(w, "# TYPE stealthlink_xmux_connection_rotations_total counter\n")
	for reason, n := range st.XmuxConnectionRotationsTotal {
		fmt.Fprintf(w, "stealthlink_xmux_connection_rotations_total{reason=%q} %d\n", reason, n)
	}

	fmt.Fprintf(w, "# HELP stealthlink_xmux_active_connections Current number of active Xmux connections\n")
	fmt.Fprintf(w, "# TYPE stealthlink_xmux_active_connections gauge\n")
	fmt.Fprintf(w, "stealthlink_xmux_active_connections %d\n", st.XmuxActiveConnections)

	// FakeTCP metrics
	fmt.Fprintf(w, "# HELP stealthlink_faketcp_aead_auth_failures_total Total number of FakeTCP AEAD authentication failures\n")
	fmt.Fprintf(w, "# TYPE stealthlink_faketcp_aead_auth_failures_total counter\n")
	fmt.Fprintf(w, "stealthlink_faketcp_aead_auth_failures_total %d\n", st.FakeTCPAEADAuthFailuresTotal)

	fmt.Fprintf(w, "# HELP stealthlink_faketcp_key_derivations_total Total number of FakeTCP key derivations\n")
	fmt.Fprintf(w, "# TYPE stealthlink_faketcp_key_derivations_total counter\n")
	fmt.Fprintf(w, "stealthlink_faketcp_key_derivations_total %d\n", st.FakeTCPKeyDerivationsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_faketcp_encrypted_bytes_total Total number of FakeTCP encrypted bytes by direction\n")
	fmt.Fprintf(w, "# TYPE stealthlink_faketcp_encrypted_bytes_total counter\n")
	for dir, n := range st.FakeTCPEncryptedBytesTotal {
		fmt.Fprintf(w, "stealthlink_faketcp_encrypted_bytes_total{direction=%q} %d\n", dir, n)
	}

	// REALITY spider metrics
	fmt.Fprintf(w, "# HELP stealthlink_reality_spider_fetches_total Total number of REALITY spider fetches\n")
	fmt.Fprintf(w, "# TYPE stealthlink_reality_spider_fetches_total counter\n")
	fmt.Fprintf(w, "stealthlink_reality_spider_fetches_total %d\n", st.RealitySpiderFetchesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_reality_spider_duration_seconds Total REALITY spider crawl duration in seconds\n")
	fmt.Fprintf(w, "# TYPE stealthlink_reality_spider_duration_seconds counter\n")
	fmt.Fprintf(w, "stealthlink_reality_spider_duration_seconds %.3f\n", st.RealitySpiderDurationSeconds)

	fmt.Fprintf(w, "# HELP stealthlink_reality_spider_urls_crawled Current number of URLs in REALITY spider crawl queue\n")
	fmt.Fprintf(w, "# TYPE stealthlink_reality_spider_urls_crawled gauge\n")
	fmt.Fprintf(w, "stealthlink_reality_spider_urls_crawled %d\n", st.RealitySpiderURLsCrawled)

	// Entropy metrics
	fmt.Fprintf(w, "# HELP stealthlink_entropy_bytes_generated_total Total random bytes generated\n")
	fmt.Fprintf(w, "# TYPE stealthlink_entropy_bytes_generated_total counter\n")
	for class, n := range st.EntropyBytesGeneratedTotal {
		fmt.Fprintf(w, "stealthlink_entropy_bytes_generated_total{class=%q} %d\n", class, n)
	}

	fmt.Fprintf(w, "# HELP stealthlink_entropy_reseeds_total Total entropy source reseeds\n")
	fmt.Fprintf(w, "# TYPE stealthlink_entropy_reseeds_total counter\n")
	fmt.Fprintf(w, "stealthlink_entropy_reseeds_total %d\n", st.EntropyReseedsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_entropy_method Active entropy method (1=active)\n")
	fmt.Fprintf(w, "# TYPE stealthlink_entropy_method gauge\n")
	for method, n := range st.EntropyMethod {
		fmt.Fprintf(w, "stealthlink_entropy_method{method=%q} %d\n", method, n)
	}

	// KCP FEC metrics
	fmt.Fprintf(w, "# HELP stealthlink_kcp_fec_parity_skipped_total Total number of KCP FEC parity packets skipped\n")
	fmt.Fprintf(w, "# TYPE stealthlink_kcp_fec_parity_skipped_total counter\n")
	fmt.Fprintf(w, "stealthlink_kcp_fec_parity_skipped_total %d\n", st.KCPFECParitySkippedTotal)

	fmt.Fprintf(w, "# HELP stealthlink_kcp_fec_auto_tune_adjustments_total Total number of KCP FEC auto-tune parameter changes\n")
	fmt.Fprintf(w, "# TYPE stealthlink_kcp_fec_auto_tune_adjustments_total counter\n")
	fmt.Fprintf(w, "stealthlink_kcp_fec_auto_tune_adjustments_total %d\n", st.KCPFECAutoTuneAdjustmentsTotal)

	fmt.Fprintf(w, "# HELP stealthlink_kcp_fec_data_shards Current number of KCP FEC data shards\n")
	fmt.Fprintf(w, "# TYPE stealthlink_kcp_fec_data_shards gauge\n")
	fmt.Fprintf(w, "stealthlink_kcp_fec_data_shards %d\n", st.KCPFECDataShards)

	fmt.Fprintf(w, "# HELP stealthlink_kcp_fec_parity_shards Current number of KCP FEC parity shards\n")
	fmt.Fprintf(w, "# TYPE stealthlink_kcp_fec_parity_shards gauge\n")
	fmt.Fprintf(w, "stealthlink_kcp_fec_parity_shards %d\n", st.KCPFECParityShards)

	// Smux shaper metrics
	fmt.Fprintf(w, "# HELP stealthlink_smux_shaper_control_frames_total Total number of smux control frames transmitted\n")
	fmt.Fprintf(w, "# TYPE stealthlink_smux_shaper_control_frames_total counter\n")
	fmt.Fprintf(w, "stealthlink_smux_shaper_control_frames_total %d\n", st.SmuxShaperControlFramesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_smux_shaper_data_frames_total Total number of smux data frames transmitted\n")
	fmt.Fprintf(w, "# TYPE stealthlink_smux_shaper_data_frames_total counter\n")
	fmt.Fprintf(w, "stealthlink_smux_shaper_data_frames_total %d\n", st.SmuxShaperDataFramesTotal)

	fmt.Fprintf(w, "# HELP stealthlink_smux_shaper_queue_size Current smux shaper queue size\n")
	fmt.Fprintf(w, "# TYPE stealthlink_smux_shaper_queue_size gauge\n")
	fmt.Fprintf(w, "stealthlink_smux_shaper_queue_size %d\n", st.SmuxShaperQueueSize)

	fmt.Fprintf(w, "# HELP stealthlink_smux_shaper_starvation_preventions_total Total smux data starvation preventions\n")
	fmt.Fprintf(w, "# TYPE stealthlink_smux_shaper_starvation_preventions_total counter\n")
	fmt.Fprintf(w, "stealthlink_smux_shaper_starvation_preventions_total %d\n", st.SmuxShaperStarvationPreventionsTotal)

	// Connection pool metrics
	fmt.Fprintf(w, "# HELP stealthlink_pool_size Current connection pool size\n")
	fmt.Fprintf(w, "# TYPE stealthlink_pool_size gauge\n")
	fmt.Fprintf(w, "stealthlink_pool_size %d\n", st.PoolSize)

	fmt.Fprintf(w, "# HELP stealthlink_pool_utilization Connection pool utilization ratio\n")
	fmt.Fprintf(w, "# TYPE stealthlink_pool_utilization gauge\n")
	fmt.Fprintf(w, "stealthlink_pool_utilization %.3f\n", st.PoolUtilization)

	fmt.Fprintf(w, "# HELP stealthlink_pool_wait_time_ms Last observed connection pool wait time in milliseconds\n")
	fmt.Fprintf(w, "# TYPE stealthlink_pool_wait_time_ms gauge\n")
	fmt.Fprintf(w, "stealthlink_pool_wait_time_ms %d\n", st.PoolWaitTimeMs)

	fmt.Fprintf(w, "# HELP stealthlink_pool_adjustments_total Total connection pool adjustments by direction\n")
	fmt.Fprintf(w, "# TYPE stealthlink_pool_adjustments_total counter\n")
	for dir, n := range st.PoolAdjustmentsTotal {
		fmt.Fprintf(w, "stealthlink_pool_adjustments_total{direction=%q} %d\n", dir, n)
	}

	// TCP telemetry metrics
	writeTCPTelemetryPrometheus(w)
}

func writeTCPTelemetryPrometheus(w http.ResponseWriter) {
	telemetry := GetTCPTelemetry()

	// Global TCP metrics
	fmt.Fprintf(w, "# HELP stealthlink_tcp_average_rtt_ms Average TCP RTT in milliseconds\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_average_rtt_ms gauge\n")
	fmt.Fprintf(w, "stealthlink_tcp_average_rtt_ms %.3f\n", telemetry.AverageRTTMs)

	fmt.Fprintf(w, "# HELP stealthlink_tcp_loss_events_total Total TCP loss events\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_loss_events_total counter\n")
	fmt.Fprintf(w, "stealthlink_tcp_loss_events_total %d\n", telemetry.TotalLossEvents)

	fmt.Fprintf(w, "# HELP stealthlink_tcp_retransmits_total Total TCP retransmissions\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_retransmits_total counter\n")
	fmt.Fprintf(w, "stealthlink_tcp_retransmits_total %d\n", telemetry.TotalRetransmits)

	fmt.Fprintf(w, "# HELP stealthlink_tcp_average_cwnd Average congestion window\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_average_cwnd gauge\n")
	fmt.Fprintf(w, "stealthlink_tcp_average_cwnd %d\n", telemetry.AverageCwnd)

	fmt.Fprintf(w, "# HELP stealthlink_tcp_session_count Current TCP session count with telemetry\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_session_count gauge\n")
	fmt.Fprintf(w, "stealthlink_tcp_session_count %d\n", telemetry.SessionCount)

	// Per-carrier metrics
	fmt.Fprintf(w, "# HELP stealthlink_tcp_carrier_connections_total Total connections per carrier\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_carrier_connections_total counter\n")
	fmt.Fprintf(w, "# HELP stealthlink_tcp_carrier_connections_active Active connections per carrier\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_carrier_connections_active gauge\n")
	fmt.Fprintf(w, "# HELP stealthlink_tcp_carrier_bytes_sent_total Total bytes sent per carrier\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_carrier_bytes_sent_total counter\n")
	fmt.Fprintf(w, "# HELP stealthlink_tcp_carrier_bytes_received_total Total bytes received per carrier\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_carrier_bytes_received_total counter\n")
	fmt.Fprintf(w, "# HELP stealthlink_tcp_carrier_errors_total Total errors per carrier\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_carrier_errors_total counter\n")
	fmt.Fprintf(w, "# HELP stealthlink_tcp_carrier_average_rtt_ms Average RTT per carrier\n")
	fmt.Fprintf(w, "# TYPE stealthlink_tcp_carrier_average_rtt_ms gauge\n")

	for name, carrier := range telemetry.Carriers {
		fmt.Fprintf(w, "stealthlink_tcp_carrier_connections_total{carrier=%q} %d\n", name, carrier.Connections)
		fmt.Fprintf(w, "stealthlink_tcp_carrier_connections_active{carrier=%q} %d\n", name, carrier.ActiveConns)
		fmt.Fprintf(w, "stealthlink_tcp_carrier_bytes_sent_total{carrier=%q} %d\n", name, carrier.BytesSent)
		fmt.Fprintf(w, "stealthlink_tcp_carrier_bytes_received_total{carrier=%q} %d\n", name, carrier.BytesRecv)
		fmt.Fprintf(w, "stealthlink_tcp_carrier_errors_total{carrier=%q} %d\n", name, carrier.Errors)
		fmt.Fprintf(w, "stealthlink_tcp_carrier_average_rtt_ms{carrier=%q} %.3f\n", name, carrier.AverageRTT)
	}
}
