package metrics

import (
	"fmt"
	"net/http"
)

func PromHandler(w http.ResponseWriter, r *http.Request) {
	st := SnapshotData()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "stealthlink_sessions_total %d\n", st.SessionsTotal)
	fmt.Fprintf(w, "stealthlink_sessions_active %d\n", st.SessionsActive)
	fmt.Fprintf(w, "stealthlink_streams_total %d\n", st.StreamsTotal)
	fmt.Fprintf(w, "stealthlink_streams_active %d\n", st.StreamsActive)
	fmt.Fprintf(w, "stealthlink_udp_sessions %d\n", st.UDPSessions)
	fmt.Fprintf(w, "stealthlink_errors_total %d\n", st.Errors)
	fmt.Fprintf(w, "stealthlink_last_ping_rtt_ms %d\n", st.LastPingRTTMs)
	fmt.Fprintf(w, "stealthlink_traffic_bytes_total %d\n", st.TrafficBytesTotal)
	fmt.Fprintf(w, "stealthlink_traffic_bytes_inbound %d\n", st.TrafficBytesInbound)
	fmt.Fprintf(w, "stealthlink_traffic_bytes_outbound %d\n", st.TrafficBytesOutbound)
	fmt.Fprintf(w, "stealthlink_sockets_open %d\n", st.SocketsOpen)
	fmt.Fprintf(w, "stealthlink_obfs_junk_packets_total %d\n", st.ObfsJunkPacketsTotal)
	fmt.Fprintf(w, "stealthlink_obfs_signature_packets_total %d\n", st.ObfsSignaturePacketsTotal)
	for name, n := range st.TransportSessions {
		fmt.Fprintf(w, "stealthlink_transport_sessions_active{transport=%q} %d\n", name, n)
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
