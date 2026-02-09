//go:build !linux
// +build !linux

package kcpmux

import (
	"fmt"
	"net"
)

// setDSCPOnConn is a no-op on non-Linux platforms.
func setDSCPOnConn(conn net.Conn, dscp int) error {
	return nil // DSCP setting not supported on this platform
}

// SetDSCPByClass is a no-op on non-Linux platforms.
func SetDSCPByClass(conn net.Conn, class string) error {
	return nil // DSCP setting not supported on this platform
}
