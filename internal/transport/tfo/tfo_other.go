//go:build !linux

package tfo

import (
	"syscall"
)

// setTFOSocketOption sets TCP Fast Open socket option.
// Stub for non-Linux platforms.
func setTFOSocketOption(fd uintptr, queueSize int) error {
	// TFO not supported on this platform
	return nil
}

// setTFOListenerOption sets TFO options for listeners.
func setTFOListenerOption(fd uintptr, queueSize int) error {
	// TFO not supported on this platform
	return nil
}
