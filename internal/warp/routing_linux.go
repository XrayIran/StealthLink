//go:build linux && netlink

package warp

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
)

// Netlink constants
const (
	nlmsgAlignTo = 4
	rtaAlignTo   = 4

	sizeofNlMsghdr = 16
	sizeofRtMsg    = 12
	sizeofRtAttr   = 4
)

// nlmsgAlign rounds length up to netlink alignment boundary
func nlmsgAlign(len int) int {
	return (len + nlmsgAlignTo - 1) &^ (nlmsgAlignTo - 1)
}

// rtaAlign rounds length up to RTA alignment boundary
func rtaAlign(len int) int {
	return (len + rtaAlignTo - 1) &^ (rtaAlignTo - 1)
}

// addDefaultRouteViaInterface adds a default route through the specified interface.
func addDefaultRouteViaInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	// Build default route message (0.0.0.0/0)
	msg := buildDefaultRouteMsg(iface.Index)
	return sendNetlinkRouteMsg(fd, syscall.RTM_NEWROUTE, msg)
}

// addRouteViaInterface adds a route through the specified interface.
func addRouteViaInterface(ifaceName string, destination string, gateway string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	_, dstNet, err := net.ParseCIDR(destination)
	if err != nil {
		return fmt.Errorf("invalid destination: %w", err)
	}

	var gwIP net.IP
	if gateway != "" {
		gwIP = net.ParseIP(gateway)
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	msg := buildRouteMsg(iface.Index, dstNet, gwIP)
	return sendNetlinkRouteMsg(fd, syscall.RTM_NEWROUTE, msg)
}

// removeRoutesViaInterface removes routes associated with the interface.
func removeRoutesViaInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil // Interface doesn't exist, nothing to do
	}

	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	// Flush routes for this interface
	// We do this by sending a DELROUTE message with the interface index
	msg := buildFlushRouteMsg(iface.Index)
	return sendNetlinkRouteMsg(fd, syscall.RTM_DELROUTE, msg)
}

// buildDefaultRouteMsg builds a netlink message for a default route.
func buildDefaultRouteMsg(ifIndex int) []byte {
	// rtmsg: family(1) + dst_len(1) + src_len(1) + tos(1) + table(1) + protocol(1) + scope(1) + type(1) + flags(4)
	msg := make([]byte, sizeofRtMsg)
	msg[0] = syscall.AF_INET // IPv4
	msg[1] = 0               // dst_len = 0 (default route)
	msg[2] = 0               // src_len
	msg[3] = 0               // tos
	msg[4] = syscall.RT_TABLE_MAIN
	msg[5] = syscall.RTPROT_BOOT
	msg[6] = syscall.RT_SCOPE_UNIVERSE
	msg[7] = syscall.RTN_UNICAST
	binary.LittleEndian.PutUint32(msg[8:12], 0) // flags

	// RTA_OIF attribute (output interface)
	oifBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(oifBuf, uint32(ifIndex))
	msg = addRtAttr(msg, syscall.RTA_OIF, oifBuf)

	// RTA_PRIORITY attribute (metric)
	metricBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(metricBuf, 100) // Higher priority (lower metric)
	msg = addRtAttr(msg, syscall.RTA_PRIORITY, metricBuf)

	return msg
}

// buildRouteMsg builds an RTM_NEWROUTE netlink message payload.
func buildRouteMsg(ifIndex int, dst *net.IPNet, gw net.IP) []byte {
	family := byte(syscall.AF_INET)
	dstIP := dst.IP.To4()
	if dstIP == nil {
		family = byte(syscall.AF_INET6)
		dstIP = dst.IP.To16()
	}
	ones, _ := dst.Mask.Size()

	// rtmsg: family(1) + dst_len(1) + src_len(1) + tos(1) + table(1) + protocol(1) + scope(1) + type(1) + flags(4)
	msg := make([]byte, sizeofRtMsg)
	msg[0] = family
	msg[1] = byte(ones) // dst_len
	msg[2] = 0          // src_len
	msg[3] = 0          // tos
	msg[4] = syscall.RT_TABLE_MAIN
	msg[5] = syscall.RTPROT_BOOT
	msg[6] = syscall.RT_SCOPE_UNIVERSE
	msg[7] = syscall.RTN_UNICAST
	binary.LittleEndian.PutUint32(msg[8:12], 0) // flags

	// RTA_DST attribute
	msg = addRtAttr(msg, syscall.RTA_DST, dstIP)

	// RTA_GATEWAY attribute (if gateway specified)
	if gw != nil {
		gwBytes := gw.To4()
		if gwBytes == nil {
			gwBytes = gw.To16()
		}
		if gwBytes != nil {
			msg = addRtAttr(msg, syscall.RTA_GATEWAY, gwBytes)
		}
	}

	// RTA_OIF attribute (output interface)
	oifBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(oifBuf, uint32(ifIndex))
	msg = addRtAttr(msg, syscall.RTA_OIF, oifBuf)

	return msg
}

// buildFlushRouteMsg builds a message to flush routes for an interface.
func buildFlushRouteMsg(ifIndex int) []byte {
	// Build a wildcard route message for the interface
	msg := make([]byte, sizeofRtMsg)
	msg[0] = syscall.AF_INET
	msg[4] = syscall.RT_TABLE_MAIN
	msg[5] = syscall.RTPROT_BOOT

	// RTA_OIF attribute
	oifBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(oifBuf, uint32(ifIndex))
	msg = addRtAttr(msg, syscall.RTA_OIF, oifBuf)

	return msg
}

// addRtAttr appends a netlink route attribute to a buffer.
func addRtAttr(buf []byte, attrType uint16, data []byte) []byte {
	attrLen := uint16(sizeofRtAttr + len(data))
	aligned := rtaAlign(int(attrLen))

	attr := make([]byte, aligned)
	binary.LittleEndian.PutUint16(attr[0:2], attrLen)
	binary.LittleEndian.PutUint16(attr[2:4], attrType)
	copy(attr[4:], data)

	return append(buf, attr...)
}

// sendNetlinkRouteMsg sends a netlink message for route operations.
func sendNetlinkRouteMsg(fd int, msgType uint16, payload []byte) error {
	totalLen := sizeofNlMsghdr + len(payload)
	msg := make([]byte, nlmsgAlign(totalLen))

	// nlmsghdr
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen)) // nlmsg_len
	binary.LittleEndian.PutUint16(msg[4:6], msgType)          // nlmsg_type
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL)
	binary.LittleEndian.PutUint32(msg[8:12], 1)            // nlmsg_seq
	binary.LittleEndian.PutUint32(msg[12:16], uint32(syscall.Getpid())) // nlmsg_pid

	copy(msg[sizeofNlMsghdr:], payload)

	dest := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(fd, msg, 0, dest); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}

	// Read ACK
	ackBuf := make([]byte, 1024)
	n, _, err := syscall.Recvfrom(fd, ackBuf, 0)
	if err != nil {
		return fmt.Errorf("netlink recv: %w", err)
	}

	if n < sizeofNlMsghdr+4 {
		return nil
	}

	respType := binary.LittleEndian.Uint16(ackBuf[4:6])
	if respType == syscall.NLMSG_ERROR {
		errno := int32(binary.LittleEndian.Uint32(ackBuf[sizeofNlMsghdr : sizeofNlMsghdr+4]))
		if errno == 0 {
			return nil
		}
		return fmt.Errorf("netlink error: %s", syscall.Errno(-errno))
	}

	return nil
}
