//go:build linux
// +build linux

package kcpmux

import (
	"fmt"
	"net"
	"syscall"
)

// setDSCPOnConn sets the DSCP/TOS field on a UDP connection (Linux-specific).
func setDSCPOnConn(conn net.Conn, dscp int) error {
	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("not a UDP connection")
	}

	file, err := udpConn.File()
	if err != nil {
		return fmt.Errorf("get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Set IP_TOS (DSCP is in the upper 6 bits of TOS)
	tos := dscp << 2
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
}

// SetDSCPByClass sets DSCP using traffic class names.
func SetDSCPByClass(conn net.Conn, class string) error {
	var dscp int
	switch class {
	case "ef":
		dscp = 46 // Expedited Forwarding
	case "af11":
		dscp = 10 // Assured Forwarding 11
	case "af12":
		dscp = 12 // Assured Forwarding 12
	case "af13":
		dscp = 14 // Assured Forwarding 13
	case "af21":
		dscp = 18 // Assured Forwarding 21
	case "af22":
		dscp = 20 // Assured Forwarding 22
	case "af23":
		dscp = 22 // Assured Forwarding 23
	case "af31":
		dscp = 26 // Assured Forwarding 31
	case "af32":
		dscp = 28 // Assured Forwarding 32
	case "af33":
		dscp = 30 // Assured Forwarding 33
	case "af41":
		dscp = 34 // Assured Forwarding 41
	case "af42":
		dscp = 36 // Assured Forwarding 42
	case "af43":
		dscp = 38 // Assured Forwarding 43
	case "cs0":
		dscp = 0 // Class Selector 0
	case "cs1":
		dscp = 8 // Class Selector 1
	case "cs2":
		dscp = 16 // Class Selector 2
	case "cs3":
		dscp = 24 // Class Selector 3
	case "cs4":
		dscp = 32 // Class Selector 4
	case "cs5":
		dscp = 40 // Class Selector 5
	case "cs6":
		dscp = 48 // Class Selector 6
	case "cs7":
		dscp = 56 // Class Selector 7
	default:
		return fmt.Errorf("unknown traffic class: %s", class)
	}
	return setDSCPOnConn(conn, dscp)
}
