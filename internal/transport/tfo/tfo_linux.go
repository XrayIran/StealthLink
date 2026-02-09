//go:build linux

package tfo

import (
	"syscall"
)

// TCP Fast Open constants.
const (
	TCP_FASTOPEN     = 23 // syscall.TCP_FASTOPEN
	TCP_FASTOPEN_CONNECT = 30 // Linux 4.11+
)

// setTFOSocketOption sets TCP Fast Open socket option on Linux.
func setTFOSocketOption(fd uintptr, queueSize int) error {
	// For client connections, we use TCP_FASTOPEN_CONNECT (Linux 4.11+)
	// For server connections, we use TCP_FASTOPEN with queue size

	// Try TCP_FASTOPEN_CONNECT first (client-side)
	if err := syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN_CONNECT, 1); err == nil {
		return nil
	}

	// Fall back to TCP_FASTOPEN with queue size (works for both)
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, queueSize)
}

// setTFOListenerOption sets TFO options for listeners.
func setTFOListenerOption(fd uintptr, queueSize int) error {
	return syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, TCP_FASTOPEN, queueSize)
}
