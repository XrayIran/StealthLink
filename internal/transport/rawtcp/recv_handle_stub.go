//go:build !cgo
// +build !cgo

package rawtcp

import (
	"fmt"
	"net"
)

// RecvHandle is unavailable when StealthLink is built without cgo/libpcap.
type RecvHandle struct{}

func NewRecvHandle(_ *packetConfig) (*RecvHandle, error) {
	return nil, fmt.Errorf("rawtcp recv handle requires cgo/libpcap")
}

func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	if h == nil {
		return nil, nil, fmt.Errorf("rawtcp recv handle is nil")
	}
	return nil, nil, fmt.Errorf("rawtcp recv handle requires cgo/libpcap")
}

func (h *RecvHandle) Close() {}

// buildBPFFilter is retained for config/test parity when cgo is disabled.
func buildBPFFilter(cfg *packetConfig) string {
	base := fmt.Sprintf("tcp and dst port %d", cfg.port)
	switch cfg.bpfProfile {
	case "strict":
		return fmt.Sprintf("(%s) and (tcp[tcpflags] & (tcp-push|tcp-ack) != 0)", base)
	case "stealth":
		return fmt.Sprintf("(%s) and (tcp[tcpflags] & (tcp-push|tcp-ack) != 0) and not (tcp[tcpflags] & tcp-rst != 0) and not (tcp[tcpflags] = tcp-syn) and not (tcp[tcpflags] & 0xc0 != 0 and tcp[tcpflags] & (tcp-push|tcp-ack) = 0)", base)
	default:
		return base
	}
}

// parseEtherIPTCP is unavailable without pcap capture support.
func parseEtherIPTCP(_ []byte) ([]byte, uint16, []byte, bool) {
	return nil, 0, nil, false
}
