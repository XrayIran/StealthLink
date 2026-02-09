//go:build !linux
// +build !linux

package multiport

import (
	"fmt"
	"net"
)

// GetOriginalDestination is not supported on non-Linux platforms.
func GetOriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	return nil, fmt.Errorf("SO_ORIGINAL_DST not supported on this platform")
}

// GetOriginalDestinationUDP is not supported on non-Linux platforms.
func GetOriginalDestinationUDP(conn *net.UDPConn) (*net.UDPAddr, error) {
	return nil, fmt.Errorf("SO_ORIGINAL_DST not supported on this platform")
}
