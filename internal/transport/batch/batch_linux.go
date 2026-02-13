//go:build linux
// +build linux

package batch

import (
	"encoding/binary"
	"errors"
	"net"
	"syscall"
	"unsafe"

	"sync"

	"golang.org/x/sys/unix"
)

var (
	iovecsPool = sync.Pool{
		New: func() interface{} { return make([]unix.Iovec, 64) },
	}
	mmsghdrPool = sync.Pool{
		New: func() interface{} { return make([]mmsghdr, 64) },
	}
	rawAddrsPool = sync.Pool{
		New: func() interface{} { return make([][128]byte, 64) },
	}
	sockaddr4Pool = sync.Pool{
		New: func() interface{} { return make([]unix.RawSockaddrInet4, 64) },
	}
	sockaddr6Pool = sync.Pool{
		New: func() interface{} { return make([]unix.RawSockaddrInet6, 64) },
	}
)

type mmsghdr struct {
	Hdr    unix.Msghdr
	MsgLen uint32
	_      [4]byte
}

var errENOSYS = errors.New("sendmmsg/recvmmsg not supported")

func fdFromUDPConn(conn *net.UDPConn) (int, error) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	var fdErr error
	err = rawConn.Control(func(f uintptr) {
		fd = int(f)
	})
	if err != nil {
		return -1, err
	}
	return fd, fdErr
}

func udpAddrToSockaddr(addr *net.UDPAddr) (unsafe.Pointer, uint32) {
	if addr == nil {
		return nil, 0
	}
	ip4 := addr.IP.To4()
	if ip4 != nil {
		sa := &unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Port:   htons(uint16(addr.Port)),
		}
		copy(sa.Addr[:], ip4)
		return unsafe.Pointer(sa), unix.SizeofSockaddrInet4
	}
	sa := &unix.RawSockaddrInet6{
		Family:   unix.AF_INET6,
		Port:     htons(uint16(addr.Port)),
		Scope_id: zoneToID(addr.Zone),
	}
	copy(sa.Addr[:], addr.IP.To16())
	return unsafe.Pointer(sa), unix.SizeofSockaddrInet6
}

func sockaddrToUDPAddr(rsa *byte, rsaLen uint32) *net.UDPAddr {
	if rsa == nil || rsaLen == 0 {
		return nil
	}
	family := *(*uint16)(unsafe.Pointer(rsa))
	switch family {
	case unix.AF_INET:
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(rsa))
		return &net.UDPAddr{
			IP:   net.IPv4(sa.Addr[0], sa.Addr[1], sa.Addr[2], sa.Addr[3]),
			Port: int(ntohs(sa.Port)),
		}
	case unix.AF_INET6:
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(rsa))
		ip := make(net.IP, net.IPv6len)
		copy(ip, sa.Addr[:])
		return &net.UDPAddr{
			IP:   ip,
			Port: int(ntohs(sa.Port)),
			Zone: zoneFromID(sa.Scope_id),
		}
	}
	return nil
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func ntohs(v uint16) uint16 {
	b := (*[2]byte)(unsafe.Pointer(&v))
	return binary.BigEndian.Uint16(b[:])
}

func zoneFromID(id uint32) string {
	if id == 0 {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(id))
	if err != nil {
		return ""
	}
	return iface.Name
}

func zoneToID(zone string) uint32 {
	if zone == "" {
		return 0
	}
	iface, err := net.InterfaceByName(zone)
	if err != nil {
		return 0
	}
	return uint32(iface.Index)
}

func sendmmsg(fd int, hdrs []mmsghdr, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(
		unix.SYS_SENDMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&hdrs[0])),
		uintptr(len(hdrs)),
		uintptr(flags),
		0, 0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func recvmmsg(fd int, hdrs []mmsghdr, flags int) (int, error) {
	n, _, errno := syscall.Syscall6(
		unix.SYS_RECVMMSG,
		uintptr(fd),
		uintptr(unsafe.Pointer(&hdrs[0])),
		uintptr(len(hdrs)),
		uintptr(flags),
		0, 0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

func sendBatchFallback(conn *net.UDPConn, msgs [][]byte) (int, error) {
	sent := 0
	for _, msg := range msgs {
		if _, err := conn.Write(msg); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func sendBatchAddrFallback(conn *net.UDPConn, msgs [][]byte, addrs []*net.UDPAddr) (int, error) {
	sent := 0
	for i, msg := range msgs {
		if _, err := conn.WriteToUDP(msg, addrs[i]); err != nil {
			return sent, err
		}
		sent++
	}
	return sent, nil
}

func recvBatchFallback(conn *net.UDPConn, buffers [][]byte) (int, []int, []net.Addr, error) {
	if len(buffers) == 0 {
		return 0, nil, nil, nil
	}
	n, addr, err := conn.ReadFromUDP(buffers[0])
	if err != nil {
		return 0, nil, nil, err
	}
	return 1, []int{n}, []net.Addr{addr}, nil
}

func SendBatch(conn *net.UDPConn, msgs [][]byte) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if len(msgs) > 64 {
		msgs = msgs[:64]
	}

	fd, err := fdFromUDPConn(conn)
	if err != nil {
		return sendBatchFallback(conn, msgs)
	}

	iovecs := iovecsPool.Get().([]unix.Iovec)
	defer iovecsPool.Put(iovecs)
	hdrs := mmsghdrPool.Get().([]mmsghdr)
	defer mmsghdrPool.Put(hdrs)

	for i, msg := range msgs {
		if len(msg) > 0 {
			iovecs[i].Base = &msg[0]
			iovecs[i].SetLen(len(msg))
		}
		hdrs[i].Hdr.Iov = &iovecs[i]
		hdrs[i].Hdr.SetIovlen(1)
		hdrs[i].Hdr.Name = nil
		hdrs[i].Hdr.Namelen = 0
		hdrs[i].MsgLen = 0
	}

	totalSent := 0
	batchHdrs := hdrs[:len(msgs)]
	for totalSent < len(batchHdrs) {
		n, err := sendmmsg(fd, batchHdrs[totalSent:], 0)
		if err != nil {
			if errors.Is(err, syscall.ENOSYS) {
				return sendBatchFallback(conn, msgs[totalSent:])
			}
			return totalSent, err
		}
		if n == 0 {
			break
		}
		totalSent += n
	}
	return totalSent, nil
}

func SendBatchAddr(conn *net.UDPConn, msgs [][]byte, addrs []*net.UDPAddr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	if len(msgs) != len(addrs) {
		return 0, errors.New("batch: msgs and addrs length mismatch")
	}
	if len(msgs) > 64 {
		msgs = msgs[:64]
		addrs = addrs[:64]
	}

	fd, err := fdFromUDPConn(conn)
	if err != nil {
		return sendBatchAddrFallback(conn, msgs, addrs)
	}

	iovecs := iovecsPool.Get().([]unix.Iovec)
	defer iovecsPool.Put(iovecs)
	hdrs := mmsghdrPool.Get().([]mmsghdr)
	defer mmsghdrPool.Put(hdrs)
	sockaddrs4 := sockaddr4Pool.Get().([]unix.RawSockaddrInet4)
	defer sockaddr4Pool.Put(sockaddrs4)
	sockaddrs6 := sockaddr6Pool.Get().([]unix.RawSockaddrInet6)
	defer sockaddr6Pool.Put(sockaddrs6)

	for i, msg := range msgs {
		if len(msg) > 0 {
			iovecs[i].Base = &msg[0]
			iovecs[i].SetLen(len(msg))
		}
		hdrs[i].Hdr.Iov = &iovecs[i]
		hdrs[i].Hdr.SetIovlen(1)
		hdrs[i].MsgLen = 0

		addr := addrs[i]
		if addr != nil {
			ip4 := addr.IP.To4()
			if ip4 != nil {
				sockaddrs4[i] = unix.RawSockaddrInet4{Family: unix.AF_INET, Port: htons(uint16(addr.Port))}
				copy(sockaddrs4[i].Addr[:], ip4)
				hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs4[i]))
				hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
			} else {
				sockaddrs6[i] = unix.RawSockaddrInet6{Family: unix.AF_INET6, Port: htons(uint16(addr.Port)), Scope_id: zoneToID(addr.Zone)}
				copy(sockaddrs6[i].Addr[:], addr.IP.To16())
				hdrs[i].Hdr.Name = (*byte)(unsafe.Pointer(&sockaddrs6[i]))
				hdrs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
			}
		} else {
			hdrs[i].Hdr.Name = nil
			hdrs[i].Hdr.Namelen = 0
		}
	}

	totalSent := 0
	batchHdrs := hdrs[:len(msgs)]
	for totalSent < len(batchHdrs) {
		n, err := sendmmsg(fd, batchHdrs[totalSent:], 0)
		if err != nil {
			if errors.Is(err, syscall.ENOSYS) {
				return sendBatchAddrFallback(conn, msgs[totalSent:], addrs[totalSent:])
			}
			return totalSent, err
		}
		if n == 0 {
			break
		}
		totalSent += n
	}
	return totalSent, nil
}

func RecvBatch(conn *net.UDPConn, buffers [][]byte) (int, []net.Addr, error) {
	if len(buffers) == 0 {
		return 0, nil, nil
	}
	if len(buffers) > 64 {
		buffers = buffers[:64]
	}

	fd, err := fdFromUDPConn(conn)
	if err != nil {
		n, lens, addrs, ferr := recvBatchFallback(conn, buffers)
		if ferr != nil {
			return 0, nil, ferr
		}
		if n > 0 {
			buffers[0] = buffers[0][:lens[0]]
		}
		return n, addrs, nil
	}

	iovecs := iovecsPool.Get().([]unix.Iovec)
	defer iovecsPool.Put(iovecs)
	hdrs := mmsghdrPool.Get().([]mmsghdr)
	defer mmsghdrPool.Put(hdrs)
	rawAddrs := rawAddrsPool.Get().([][128]byte)
	defer rawAddrsPool.Put(rawAddrs)

	for i, buf := range buffers {
		if len(buf) > 0 {
			iovecs[i].Base = &buf[0]
			iovecs[i].SetLen(len(buf))
		}
		hdrs[i].Hdr.Iov = &iovecs[i]
		hdrs[i].Hdr.SetIovlen(1)
		hdrs[i].Hdr.Name = &rawAddrs[i][0]
		hdrs[i].Hdr.Namelen = 128
		hdrs[i].MsgLen = 0
	}

	n, err := recvmmsg(fd, hdrs[:len(buffers)], unix.MSG_WAITFORONE)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) {
			nf, lens, addrs, ferr := recvBatchFallback(conn, buffers)
			if ferr != nil {
				return 0, nil, ferr
			}
			if nf > 0 {
				buffers[0] = buffers[0][:lens[0]]
			}
			return nf, addrs, nil
		}
		return 0, nil, err
	}

	addrs := make([]net.Addr, n)
	for i := 0; i < n; i++ {
		buffers[i] = buffers[i][:hdrs[i].MsgLen]
		addrs[i] = sockaddrToUDPAddr(hdrs[i].Hdr.Name, hdrs[i].Hdr.Namelen)
	}
	return n, addrs, nil
}

type BatchSender struct {
	conn    *net.UDPConn
	maxSize int
	msgs    [][]byte
}

func NewBatchSender(conn *net.UDPConn, maxBatch int) *BatchSender {
	return &BatchSender{
		conn:    conn,
		maxSize: maxBatch,
		msgs:    make([][]byte, 0, maxBatch),
	}
}

func (b *BatchSender) Add(msg []byte) (sent int, err error) {
	b.msgs = append(b.msgs, msg)
	if len(b.msgs) >= b.maxSize {
		return b.Flush()
	}
	return 0, nil
}

func (b *BatchSender) Flush() (int, error) {
	if len(b.msgs) == 0 {
		return 0, nil
	}
	n, err := SendBatch(b.conn, b.msgs)
	b.msgs = b.msgs[:0]
	return n, err
}

func (b *BatchSender) Close() error {
	_, err := b.Flush()
	return err
}

type BatchReceiver struct {
	conn       *net.UDPConn
	maxSize    int
	buffers    [][]byte
	bufferSize int
}

func NewBatchReceiver(conn *net.UDPConn, maxBatch int, bufferSize int) *BatchReceiver {
	buffers := make([][]byte, maxBatch)
	for i := range buffers {
		buffers[i] = make([]byte, bufferSize)
	}
	return &BatchReceiver{
		conn:       conn,
		maxSize:    maxBatch,
		buffers:    buffers,
		bufferSize: bufferSize,
	}
}

func (b *BatchReceiver) Receive() ([][]byte, []net.Addr, error) {
	for i := range b.buffers {
		b.buffers[i] = b.buffers[i][:b.bufferSize]
	}

	n, addrs, err := RecvBatch(b.conn, b.buffers)
	if err != nil {
		return nil, nil, err
	}

	msgs := make([][]byte, n)
	for i := 0; i < n; i++ {
		msgs[i] = make([]byte, len(b.buffers[i]))
		copy(msgs[i], b.buffers[i])
	}
	return msgs, addrs[:n], nil
}
