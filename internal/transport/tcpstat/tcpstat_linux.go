// Package tcpstat provides TCP connection statistics extraction via TCP_INFO.
// This is ported from the tproxy project for StealthLink integration.
package tcpstat

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// TCPInfo mirrors the Linux kernel TCP_INFO struct.
// This provides detailed TCP connection statistics for telemetry and
// congestion control decisions.
type TCPInfo struct {
	// TCP state information
	State       uint8 `json:"state"`        // TCP state (ESTABLISHED, etc.)
	CAState     uint8 `json:"ca_state"`     // Congestion avoidance state
	Retransmits uint8 `json:"retransmits"`  // Number of retransmits
	Probes      uint8 `json:"probes"`       // Number of probes
	Backoff     uint8 `json:"backoff"`      // Backoff count
	Options     uint8 `json:"options"`      // TCP options enabled
	WScale      uint8 `json:"w_scale"`      // Window scaling factor
	AppLimited  uint8 `json:"app_limited"`  // Application limited flag

	// Timing information (microseconds)
	RTO  uint32 `json:"rto"`  // Retransmission timeout
	ATO  uint32 `json:"ato"`  // Ack timeout
	RTT  uint32 `json:"rtt"`  // Smoothed round trip time
	RTTVar uint32 `json:"rtt_var"` // RTT variance
	MinRTT uint32 `json:"min_rtt"` // Minimum RTT seen

	// Segment information
	SndMSS uint32 `json:"snd_mss"` // Send MSS
	RcvMSS uint32 `json:"rcv_mss"` // Receive MSS

	// Window and congestion control
	SndCwnd     uint32 `json:"snd_cwnd"`     // Send congestion window
	SndSsThresh uint32 `json:"snd_ss_thresh"` // Slow start threshold
	RcvSsThresh uint32 `json:"rcv_ss_thresh"` // Receive slow start threshold
	RcvSpace    uint32 `json:"rcv_space"`    // Receive space

	// Packet counts
	Unacked      uint32 `json:"unacked"`       // Unacknowledged packets
	Sacked       uint32 `json:"sacked"`        // SACKed packets
	Lost         uint32 `json:"lost"`          // Lost packets
	Retrans      uint32 `json:"retrans"`       // Retransmitted packets
	Fackets      uint32 `json:"f_ackets"`      // Forward acknowledgments
	TotalRetrans uint32 `json:"total_retrans"` // Total retransmissions

	// Timing of last events (in jiffies or ms depending on kernel)
	LastDataSent uint32 `json:"last_data_sent"`
	LastAckSent  uint32 `json:"last_ack_sent"`
	LastDataRecv uint32 `json:"last_data_recv"`
	LastAckRecv  uint32 `json:"last_ack_recv"`

	// Path and performance
	PathMTU     uint32 `json:"p_mtu"`      // Path MTU
	AdvMSS      uint32 `json:"adv_mss"`    // Advertised MSS
	Reordering  uint32 `json:"reordering"` // Reordering metric
	RcvRTT      uint32 `json:"rcv_rtt"`    // Receive RTT

	// BBR and pacing
	PacingRate    int64 `json:"pacing_rate"`     // Current pacing rate (bytes/sec)
	MaxPacingRate int64 `json:"max_pacing_rate"` // Maximum pacing rate
	DeliveryRate  int64 `json:"delivery_rate"`   // Delivery rate (bytes/sec)

	// Byte counts
	BytesAcked    int64 `json:"bytes_acked"`    // Total bytes acknowledged
	BytesReceived int64 `json:"bytes_received"` // Total bytes received
	BytesSent     int64 `json:"bytes_sent"`     // Total bytes sent
	BytesRetrans  int64 `json:"bytes_retrans"`  // Total bytes retransmitted
	NotSentBytes  uint32 `json:"notsent_bytes"` // Bytes not yet sent

	// Segment counts
	SegsOut     int32  `json:"segs_out"`     // Segments sent
	SegsIn      int32  `json:"segs_in"`      // Segments received
	DataSegsIn  uint32 `json:"data_segs_in"`  // Data segments received
	DataSegsOut uint32 `json:"data_segs_out"` // Data segments sent

	// Busy time statistics (microseconds)
	BusyTime      int64 `json:"busy_time"`       // Time busy sending
	RWndLimited   int64 `json:"r_wnd_limited"`   // Time limited by receive window
	SndBufLimited int64 `json:"snd_buf_limited"` // Time limited by send buffer

	// Delivery statistics
	Delivered   uint32 `json:"delivered"`    // Delivered packets
	DeliveredCE uint32 `json:"delivered_ce"` // Delivered packets with CE

	// SACK and reordering
	DSackDups uint32 `json:"d_sack_dups"` // DSACK duplicates
	ReordSeen uint32 `json:"reord_seen"`  // Reordering events seen
}

// Metrics provides derived metrics from TCPInfo
type Metrics struct {
	RTTUs         uint32  // RTT in microseconds
	RTTVarUs      uint32  // RTT variance in microseconds
	SndCwnd       uint32  // Send congestion window
	PacingRateBps int64   // Pacing rate in bytes/sec
	DeliveryRateBps int64 // Delivery rate in bytes/sec
	BytesRetrans  int64   // Bytes retransmitted
	TotalRetrans  uint32  // Total retransmissions
	MinRTTUs      uint32  // Minimum RTT in microseconds
	LossRate      float64 // Loss rate (0.0-1.0)
	BytesSent     int64   // Total bytes sent
	BytesReceived int64   // Total bytes received
}

// GetTCPInfo extracts TCP_INFO from a TCP connection.
// This requires Linux and appropriate permissions.
func GetTCPInfo(conn *net.TCPConn) (*TCPInfo, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("get raw connection: %w", err)
	}

	tcpInfo := TCPInfo{}
	size := unsafe.Sizeof(tcpInfo)

	var errno syscall.Errno
	err = rawConn.Control(func(fd uintptr) {
		_, _, errno = syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			syscall.SOL_TCP,
			syscall.TCP_INFO,
			uintptr(unsafe.Pointer(&tcpInfo)),
			uintptr(unsafe.Pointer(&size)),
			0,
		)
	})
	if err != nil {
		return nil, fmt.Errorf("control failed: %w", err)
	}
	if errno != 0 {
		return nil, fmt.Errorf("syscall failed: %w", errno)
	}

	return &tcpInfo, nil
}

// GetMetrics extracts derived metrics from a TCP connection
func GetMetrics(conn *net.TCPConn) (*Metrics, error) {
	info, err := GetTCPInfo(conn)
	if err != nil {
		return nil, err
	}

	return &Metrics{
		RTTUs:           info.RTT,
		RTTVarUs:        info.RTTVar,
		SndCwnd:         info.SndCwnd,
		PacingRateBps:   info.PacingRate,
		DeliveryRateBps: info.DeliveryRate,
		BytesRetrans:    info.BytesRetrans,
		TotalRetrans:    info.TotalRetrans,
		MinRTTUs:        info.MinRTT,
		LossRate:        0.0, // Calculated separately with delta
		BytesSent:       info.BytesSent,
		BytesReceived:   info.BytesReceived,
	}, nil
}

// GetRetransRate calculates the retransmission rate between two TCPInfo samples.
// Returns the percentage of bytes that were retransmitted (0.0-1.0).
func GetRetransRate(pre, curr *TCPInfo) float64 {
	if pre == nil || curr == nil {
		return 0
	}

	bytesDelta := curr.BytesSent - pre.BytesSent
	if bytesDelta <= 0 {
		return 0
	}

	retransDelta := curr.BytesRetrans - pre.BytesRetrans
	if retransDelta <= 0 {
		return 0
	}

	lostRate := float64(retransDelta) / float64(bytesDelta)
	if lostRate < 0 {
		return 0
	}
	if lostRate > 1 {
		return 1
	}

	return lostRate
}

// GetLossRate calculates packet loss rate between two samples
func GetLossRate(pre, curr *TCPInfo) float64 {
	if pre == nil || curr == nil {
		return 0
	}

	segsDelta := int64(curr.SegsOut) - int64(pre.SegsOut)
	if segsDelta <= 0 {
		return 0
	}

	retransDelta := int64(curr.TotalRetrans) - int64(pre.TotalRetrans)
	if retransDelta <= 0 {
		return 0
	}

	lossRate := float64(retransDelta) / float64(segsDelta)
	if lossRate < 0 {
		return 0
	}
	if lossRate > 1 {
		return 1
	}

	return lossRate
}

// RTTMs returns RTT in milliseconds
func (ti *TCPInfo) RTTMs() uint32 {
	return ti.RTT / 1000
}

// RTTVarMs returns RTT variance in milliseconds
func (ti *TCPInfo) RTTVarMs() uint32 {
	return ti.RTTVar / 1000
}

// MinRTTMs returns minimum RTT in milliseconds
func (ti *TCPInfo) MinRTTMs() uint32 {
	return ti.MinRTT / 1000
}

// ToMetrics converts TCPInfo to Metrics with optional previous sample for loss calculation
func (ti *TCPInfo) ToMetrics(prev *TCPInfo) *Metrics {
	m := &Metrics{
		RTTUs:           ti.RTT,
		RTTVarUs:        ti.RTTVar,
		SndCwnd:         ti.SndCwnd,
		PacingRateBps:   ti.PacingRate,
		DeliveryRateBps: ti.DeliveryRate,
		BytesRetrans:    ti.BytesRetrans,
		TotalRetrans:    ti.TotalRetrans,
		MinRTTUs:        ti.MinRTT,
		BytesSent:       ti.BytesSent,
		BytesReceived:   ti.BytesReceived,
	}

	if prev != nil {
		m.LossRate = GetRetransRate(prev, ti)
	}

	return m
}

// StateString returns a human-readable TCP state
func (ti *TCPInfo) StateString() string {
	states := []string{
		"ESTABLISHED",
		"SYN_SENT",
		"SYN_RECV",
		"FIN_WAIT1",
		"FIN_WAIT2",
		"TIME_WAIT",
		"CLOSE",
		"CLOSE_WAIT",
		"LAST_ACK",
		"LISTEN",
		"CLOSING",
	}

	if ti.State < uint8(len(states)) {
		return states[ti.State]
	}
	return "UNKNOWN"
}

// CAStateString returns a human-readable congestion avoidance state
func (ti *TCPInfo) CAStateString() string {
	caStates := []string{
		"OPEN",
		"DISORDER",
		"CWR",
		"RECOVERY",
		"LOSS",
	}

	if ti.CAState < uint8(len(caStates)) {
		return caStates[ti.CAState]
	}
	return "UNKNOWN"
}
