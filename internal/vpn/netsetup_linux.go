//go:build linux && netlink

package vpn

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// Netlink constants not in syscall package
const (
	nlmsgAlignTo = 4
	rtaAlignTo   = 4

	// ifaddrmsg size: family(1) + prefixlen(1) + flags(1) + scope(1) + index(4) = 8
	sizeofIfAddrmsg = 8

	// ifinfomsg size: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4) = 16
	sizeofIfInfomsg = 16

	// rtmsg size: family(1) + dst_len(1) + src_len(1) + tos(1) + table(1) + protocol(1) + scope(1) + type(1) + flags(4) = 12
	sizeofRtMsg = 12

	// nlmsghdr size: len(4) + type(2) + flags(2) + seq(4) + pid(4) = 16
	sizeofNlMsghdr = 16

	// rtattr size: len(2) + type(2) = 4
	sizeofRtAttr = 4
)

// nlmsgAlign rounds length up to netlink alignment boundary
func nlmsgAlign(len int) int {
	return (len + nlmsgAlignTo - 1) &^ (nlmsgAlignTo - 1)
}

// rtaAlign rounds length up to RTA alignment boundary
func rtaAlign(len int) int {
	return (len + rtaAlignTo - 1) &^ (rtaAlignTo - 1)
}

// SetupInterface configures the network interface on Linux using netlink syscalls.
func SetupInterface(cfg NetworkConfig) error {
	// Get interface index
	iface, err := net.InterfaceByName(cfg.InterfaceName)
	if err != nil {
		return fmt.Errorf("interface not found: %w", err)
	}

	// Parse IP and mask
	ip, ipNet, err := net.ParseCIDR(cfg.InterfaceIP)
	if err != nil {
		return fmt.Errorf("invalid interface IP: %w", err)
	}

	// Add IP address to interface using netlink
	if err := addAddress(iface.Index, ip, ipNet); err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}

	// Set MTU if specified
	if cfg.MTU > 0 {
		if err := setMTU(iface.Index, cfg.MTU); err != nil {
			return fmt.Errorf("failed to set MTU: %w", err)
		}
	}

	// Bring interface up
	if err := setInterfaceUp(iface.Index); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	// Add routes
	for _, route := range cfg.Routes {
		if err := addRoute(iface.Index, route.Destination, route.Gateway); err != nil {
			return fmt.Errorf("failed to add route %s: %w", route.Destination, err)
		}
	}

	return nil
}

// addAddress adds an IP address to an interface using netlink.
func addAddress(ifIndex int, ip net.IP, ipNet *net.IPNet) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	// Bind to netlink
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	family := syscall.AF_INET
	ipBytes := ip.To4()
	if ipBytes == nil {
		family = syscall.AF_INET6
		ipBytes = ip.To16()
	}

	ones, _ := ipNet.Mask.Size()

	msg := buildAddrMsg(ifIndex, family, ipBytes, ones)
	return sendNetlinkMsg(fd, syscall.RTM_NEWADDR, msg)
}

// setInterfaceUp brings an interface up.
func setInterfaceUp(ifIndex int) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	msg := buildLinkMsg(ifIndex, syscall.IFF_UP)
	return sendNetlinkMsg(fd, syscall.RTM_SETLINK, msg)
}

// setMTU sets the MTU on an interface.
func setMTU(ifIndex int, mtu int) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_ROUTE)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)

	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return err
	}

	msg := buildLinkMsgWithMTU(ifIndex, mtu)
	return sendNetlinkMsg(fd, syscall.RTM_SETLINK, msg)
}

// addRoute adds a route to the routing table.
func addRoute(ifIndex int, destination, gateway string) error {
	_, dstNet, err := net.ParseCIDR(destination)
	if err != nil {
		return err
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

	msg := buildRouteMsg(ifIndex, dstNet, gwIP)
	return sendNetlinkMsg(fd, syscall.RTM_NEWROUTE, msg)
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

// buildAddrMsg builds an RTM_NEWADDR netlink message payload (ifaddrmsg + attrs).
func buildAddrMsg(ifIndex int, family int, ip []byte, prefixLen int) []byte {
	// ifaddrmsg: family(1) + prefixlen(1) + flags(1) + scope(1) + index(4)
	msg := make([]byte, sizeofIfAddrmsg)
	msg[0] = byte(family)
	msg[1] = byte(prefixLen)
	msg[2] = 0 // flags
	msg[3] = 0 // scope: RT_SCOPE_UNIVERSE
	binary.LittleEndian.PutUint32(msg[4:8], uint32(ifIndex))

	// IFA_LOCAL attribute
	msg = addRtAttr(msg, syscall.IFA_LOCAL, ip)

	// IFA_ADDRESS attribute
	msg = addRtAttr(msg, syscall.IFA_ADDRESS, ip)

	return msg
}

// buildLinkMsg builds an RTM_SETLINK netlink message payload (ifinfomsg).
func buildLinkMsg(ifIndex int, flags int) []byte {
	// ifinfomsg: family(1) + pad(1) + type(2) + index(4) + flags(4) + change(4)
	msg := make([]byte, sizeofIfInfomsg)
	msg[0] = syscall.AF_UNSPEC // family
	msg[1] = 0                 // pad
	binary.LittleEndian.PutUint16(msg[2:4], 0) // type
	binary.LittleEndian.PutUint32(msg[4:8], uint32(ifIndex))
	binary.LittleEndian.PutUint32(msg[8:12], uint32(flags))
	binary.LittleEndian.PutUint32(msg[12:16], uint32(flags)) // change mask = same as flags

	return msg
}

// buildLinkMsgWithMTU builds an RTM_SETLINK message with MTU attribute.
func buildLinkMsgWithMTU(ifIndex int, mtu int) []byte {
	msg := make([]byte, sizeofIfInfomsg)
	msg[0] = syscall.AF_UNSPEC
	binary.LittleEndian.PutUint32(msg[4:8], uint32(ifIndex))

	// IFLA_MTU attribute
	mtuBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(mtuBuf, uint32(mtu))
	msg = addRtAttr(msg, syscall.IFLA_MTU, mtuBuf)

	return msg
}

// buildRouteMsg builds an RTM_NEWROUTE netlink message payload (rtmsg + attrs).
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

// sendNetlinkMsg sends a netlink message and waits for ACK.
func sendNetlinkMsg(fd int, msgType uint16, payload []byte) error {
	// Build complete netlink message: nlmsghdr + payload
	totalLen := sizeofNlMsghdr + len(payload)
	msg := make([]byte, nlmsgAlign(totalLen))

	// nlmsghdr
	binary.LittleEndian.PutUint32(msg[0:4], uint32(totalLen))        // nlmsg_len
	binary.LittleEndian.PutUint16(msg[4:6], msgType)                 // nlmsg_type
	binary.LittleEndian.PutUint16(msg[6:8], syscall.NLM_F_REQUEST|syscall.NLM_F_ACK|syscall.NLM_F_CREATE|syscall.NLM_F_EXCL) // nlmsg_flags
	binary.LittleEndian.PutUint32(msg[8:12], 1)                      // nlmsg_seq
	binary.LittleEndian.PutUint32(msg[12:16], uint32(os.Getpid()))    // nlmsg_pid

	// Copy payload after header
	copy(msg[sizeofNlMsghdr:], payload)

	// Send
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
		return nil // No error info, assume success
	}

	// Parse nlmsghdr of response
	respType := binary.LittleEndian.Uint16(ackBuf[4:6])
	if respType == syscall.NLMSG_ERROR {
		// nlmsgerr: error(4) + nlmsghdr(16)
		errno := int32(binary.LittleEndian.Uint32(ackBuf[sizeofNlMsghdr : sizeofNlMsghdr+4]))
		if errno == 0 {
			return nil // ACK (success)
		}
		return fmt.Errorf("netlink error: %s", syscall.Errno(-errno))
	}

	return nil
}

// RemoveInterface removes the network interface configuration.
func RemoveInterface(ifaceName string) error {
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

	// Set interface down
	msg := buildLinkMsg(iface.Index, 0) // flags=0 to bring down
	// For bringing down, change mask should be IFF_UP
	binary.LittleEndian.PutUint32(msg[8:12], 0)                    // flags = 0 (down)
	binary.LittleEndian.PutUint32(msg[12:16], uint32(syscall.IFF_UP)) // change = IFF_UP

	return sendNetlinkMsg(fd, syscall.RTM_SETLINK, msg)
}

// checkNetlinkAvailable checks if netlink is available (always true on Linux).
func checkNetlinkAvailable() bool {
	return os.Geteuid() == 0
}

// Ensure unsafe import is used (needed for potential future alignment checks)
var _ = unsafe.Sizeof(0)
