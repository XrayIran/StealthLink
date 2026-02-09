//go:build linux
// +build linux

package dscp

import (
	"fmt"
	"net"
	"syscall"
)

// setPlatformDSCP sets DSCP on Linux using syscalls.
func setPlatformDSCP(conn net.Conn, dscp int) error {
	switch c := conn.(type) {
	case *net.TCPConn:
		return setTCPDSCP(c, dscp)
	case *net.UDPConn:
		return setUDPDSCP(c, dscp)
	default:
		// Try to get file descriptor from generic conn
		return fmt.Errorf("unsupported connection type: %T", conn)
	}
}

func setTCPDSCP(conn *net.TCPConn, dscp int) error {
	file, err := conn.File()
	if err != nil {
		return fmt.Errorf("get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Set IP_TOS (DSCP is in the upper 6 bits of TOS)
	tos := dscp << 2

	// Try IPv4 first
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos); err != nil {
		// Try IPv6
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos); err != nil {
			return fmt.Errorf("set DSCP: %w", err)
		}
	}

	return nil
}

func setUDPDSCP(conn *net.UDPConn, dscp int) error {
	file, err := conn.File()
	if err != nil {
		return fmt.Errorf("get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Set IP_TOS (DSCP is in the upper 6 bits of TOS)
	tos := dscp << 2

	// Try IPv4 first
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos); err != nil {
		// Try IPv6
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos); err != nil {
			return fmt.Errorf("set DSCP: %w", err)
		}
	}

	return nil
}

// SetOnListener sets DSCP for all connections accepted by a listener.
// This must be called after accept and requires wrapping the listener.
func SetOnListener(ln net.Listener, dscp int) net.Listener {
	return &dscpListener{
		Listener: ln,
		dscp:     dscp,
	}
}

type dscpListener struct {
	net.Listener
	dscp int
}

func (ln *dscpListener) Accept() (net.Conn, error) {
	conn, err := ln.Listener.Accept()
	if err != nil {
		return nil, err
	}

	if err := setPlatformDSCP(conn, ln.dscp); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return conn, nil
}
