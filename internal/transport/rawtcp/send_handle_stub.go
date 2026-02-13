//go:build !cgo
// +build !cgo

package rawtcp

import (
	"fmt"
	"net"

	"stealthlink/internal/config"
)

// SendHandle is unavailable when StealthLink is built without cgo/libpcap.
type SendHandle struct{}

func NewSendHandle(_ *packetConfig) (*SendHandle, error) {
	return nil, fmt.Errorf("rawtcp send handle requires cgo/libpcap")
}

func (h *SendHandle) Write(_ []byte, _ *net.UDPAddr) error {
	if h == nil {
		return fmt.Errorf("rawtcp send handle is nil")
	}
	return fmt.Errorf("rawtcp send handle requires cgo/libpcap")
}

func (h *SendHandle) setClientTCPF(_ net.Addr, _ []config.TCPFlags) {}

func (h *SendHandle) Close() {}
