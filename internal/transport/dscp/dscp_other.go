//go:build !linux
// +build !linux

package dscp

import (
	"fmt"
	"net"
)

// setPlatformDSCP is a no-op on non-Linux platforms.
func setPlatformDSCP(conn net.Conn, dscp int) error {
	// DSCP setting is not supported on this platform
	return nil
}

// SetOnListener returns the listener unchanged on non-Linux platforms.
func SetOnListener(ln net.Listener, dscp int) net.Listener {
	return ln
}
