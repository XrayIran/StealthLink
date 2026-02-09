//go:build !linux

// Package tcpstat provides TCP connection statistics extraction.
// This is a stub implementation for non-Linux platforms.
package tcpstat

import (
	"errors"
	"net"
)

var ErrNotSupported = errors.New("TCP_INFO is only supported on Linux")

// TCPInfo is a stub for non-Linux platforms
type TCPInfo struct {
	State      uint8  `json:"state"`
	RTT        uint32 `json:"rtt"`
	RTTVar     uint32 `json:"rtt_var"`
	SndCwnd    uint32 `json:"snd_cwnd"`
	PacingRate int64  `json:"pacing_rate"`
	BytesSent  int64  `json:"bytes_sent"`
}

// Metrics is a stub for non-Linux platforms
type Metrics struct {
	RTTUs         uint32
	RTTVarUs      uint32
	SndCwnd       uint32
	PacingRateBps int64
	LossRate      float64
}

// GetTCPInfo returns an error on non-Linux platforms
func GetTCPInfo(conn *net.TCPConn) (*TCPInfo, error) {
	return nil, ErrNotSupported
}

// GetMetrics returns an error on non-Linux platforms
func GetMetrics(conn *net.TCPConn) (*Metrics, error) {
	return nil, ErrNotSupported
}

// GetRetransRate always returns 0 on non-Linux platforms
func GetRetransRate(pre, curr *TCPInfo) float64 {
	return 0
}

// GetLossRate always returns 0 on non-Linux platforms
func GetLossRate(pre, curr *TCPInfo) float64 {
	return 0
}

// RTTMs returns 0 on non-Linux platforms
func (ti *TCPInfo) RTTMs() uint32 {
	return 0
}

// RTTVarMs returns 0 on non-Linux platforms
func (ti *TCPInfo) RTTVarMs() uint32 {
	return 0
}

// ToMetrics returns an empty Metrics on non-Linux platforms
func (ti *TCPInfo) ToMetrics(prev *TCPInfo) *Metrics {
	return &Metrics{}
}

// StateString returns "UNKNOWN" on non-Linux platforms
func (ti *TCPInfo) StateString() string {
	return "UNKNOWN"
}

// CAStateString returns "UNKNOWN" on non-Linux platforms
func (ti *TCPInfo) CAStateString() string {
	return "UNKNOWN"
}
