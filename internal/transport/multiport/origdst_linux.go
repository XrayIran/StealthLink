//go:build linux
// +build linux

package multiport

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	SO_ORIGINAL_DST = 80
)

// GetOriginalDestination retrieves the original destination address
// for a connection that was redirected using iptables REDIRECT/TPROXY.
// Uses SO_ORIGINAL_DST socket option.
func GetOriginalDestination(conn net.Conn) (*net.TCPAddr, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("not a TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return nil, fmt.Errorf("get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Get original destination using SO_ORIGINAL_DST
	// This returns a sockaddr_in structure
	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	}

	// Convert to net.TCPAddr
	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port<<8) // Convert from network byte order

	return &net.TCPAddr{
		IP:   ip,
		Port: port,
	}, nil
}

// GetOriginalDestinationUDP retrieves the original destination for UDP.
func GetOriginalDestinationUDP(conn *net.UDPConn) (*net.UDPAddr, error) {
	file, err := conn.File()
	if err != nil {
		return nil, fmt.Errorf("get file descriptor: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_IP),
		uintptr(SO_ORIGINAL_DST),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, fmt.Errorf("getsockopt SO_ORIGINAL_DST failed: %v", errno)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(addr.Port>>8) | int(addr.Port<<8)

	return &net.UDPAddr{
		IP:   ip,
		Port: port,
	}, nil
}
