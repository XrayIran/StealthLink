package vpn

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	MaxPacketSize = 65535
	DefaultMTU    = 1400
)

type PacketHandler struct {
	mu          sync.Mutex
	tunDev      io.ReadWriteCloser
	transport   io.ReadWriteCloser
	mtu         int
	localIP     net.IP
	remoteIP    net.IP
	localMAC    net.HardwareAddr
	remoteMAC   net.HardwareAddr
	stats       PacketStats
	closed      bool
	onPacketIn  func([]byte)
	onPacketOut func([]byte)
}

type PacketStats struct {
	BytesIn    uint64
	BytesOut   uint64
	PacketsIn  uint64
	PacketsOut uint64
	Errors     uint64
	Dropped    uint64
	StartTime  time.Time
	LastActive time.Time
}

type PacketHandlerConfig struct {
	MTU       int
	LocalIP   net.IP
	RemoteIP  net.IP
	LocalMAC  net.HardwareAddr
	RemoteMAC net.HardwareAddr
}

func NewPacketHandler(cfg PacketHandlerConfig) *PacketHandler {
	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = DefaultMTU
	}
	return &PacketHandler{
		mtu:       mtu,
		localIP:   cfg.LocalIP,
		remoteIP:  cfg.RemoteIP,
		localMAC:  cfg.LocalMAC,
		remoteMAC: cfg.RemoteMAC,
		stats: PacketStats{
			StartTime: time.Now(),
		},
	}
}

func (h *PacketHandler) SetTUNDevice(dev io.ReadWriteCloser) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tunDev = dev
}

func (h *PacketHandler) SetTransport(t io.ReadWriteCloser) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.transport = t
}

func (h *PacketHandler) Start(ctx context.Context) error {
	h.mu.Lock()
	if h.tunDev == nil || h.transport == nil {
		h.mu.Unlock()
		return fmt.Errorf("TUN device and transport must be set before starting")
	}
	h.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		h.readFromTUNLoop(ctx)
	}()

	go func() {
		defer wg.Done()
		h.readFromTransportLoop(ctx)
	}()

	go func() {
		<-ctx.Done()
		h.Close()
	}()

	return nil
}

func (h *PacketHandler) readFromTUNLoop(ctx context.Context) {
	buf := make([]byte, MaxPacketSize)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := h.tunDev.Read(buf)
		if err != nil {
			if h.isClosed() {
				return
			}
			h.stats.Errors++
			continue
		}

		if n < 20 {
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		if err := h.writePacketToTransport(packet); err != nil {
			h.stats.Errors++
			continue
		}

		h.stats.BytesOut += uint64(n)
		h.stats.PacketsOut++
		h.stats.LastActive = time.Now()

		if h.onPacketOut != nil {
			h.onPacketOut(packet)
		}
	}
}

func (h *PacketHandler) readFromTransportLoop(ctx context.Context) {
	headerBuf := make([]byte, 4)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_, err := io.ReadFull(h.transport, headerBuf)
		if err != nil {
			if h.isClosed() {
				return
			}
			h.stats.Errors++
			continue
		}

		packetLen := binary.BigEndian.Uint32(headerBuf)
		if packetLen > uint32(h.mtu) || packetLen == 0 {
			h.stats.Dropped++
			continue
		}

		packet := make([]byte, packetLen)
		_, err = io.ReadFull(h.transport, packet)
		if err != nil {
			if h.isClosed() {
				return
			}
			h.stats.Errors++
			continue
		}

		if !h.isValidIPPacket(packet) {
			h.stats.Dropped++
			continue
		}

		if _, err := h.tunDev.Write(packet); err != nil {
			h.stats.Errors++
			continue
		}

		h.stats.BytesIn += uint64(len(packet))
		h.stats.PacketsIn++
		h.stats.LastActive = time.Now()

		if h.onPacketIn != nil {
			h.onPacketIn(packet)
		}
	}
}

func (h *PacketHandler) writePacketToTransport(packet []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(packet)))

	if _, err := h.transport.Write(header); err != nil {
		return err
	}
	if _, err := h.transport.Write(packet); err != nil {
		return err
	}
	return nil
}

func (h *PacketHandler) isValidIPPacket(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}

	version := packet[0] >> 4
	switch version {
	case 4:
		if len(packet) < 20 {
			return false
		}
		headerLen := int(packet[0]&0x0F) * 4
		if headerLen < 20 || headerLen > len(packet) {
			return false
		}
		return true
	case 6:
		if len(packet) < 40 {
			return false
		}
		return true
	default:
		return false
	}
}

func (h *PacketHandler) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

func (h *PacketHandler) Close() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil
	}
	h.closed = true
	if h.tunDev != nil {
		h.tunDev.Close()
	}
	if h.transport != nil {
		h.transport.Close()
	}
	return nil
}

func (h *PacketHandler) Stats() PacketStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.stats
}

func (h *PacketHandler) SetOnPacketIn(fn func([]byte)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onPacketIn = fn
}

func (h *PacketHandler) SetOnPacketOut(fn func([]byte)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.onPacketOut = fn
}

func (h *PacketHandler) MTU() int {
	return h.mtu
}

func ParseIPv4Header(packet []byte) (*IPv4Header, error) {
	if len(packet) < 20 {
		return nil, fmt.Errorf("packet too short for IPv4 header")
	}

	version := packet[0] >> 4
	if version != 4 {
		return nil, fmt.Errorf("not an IPv4 packet")
	}

	header := &IPv4Header{
		Version:        int(version),
		IHL:            int(packet[0] & 0x0F),
		TOS:            packet[1],
		TotalLength:    binary.BigEndian.Uint16(packet[2:4]),
		ID:             binary.BigEndian.Uint16(packet[4:6]),
		Flags:          binary.BigEndian.Uint16(packet[6:8]) >> 13,
		FragmentOffset: binary.BigEndian.Uint16(packet[6:8]) & 0x1FFF,
		TTL:            packet[8],
		Protocol:       packet[9],
		Checksum:       binary.BigEndian.Uint16(packet[10:12]),
		SrcIP:          net.IP(packet[12:16]),
		DstIP:          net.IP(packet[16:20]),
	}

	return header, nil
}

type IPv4Header struct {
	Version        int
	IHL            int
	TOS            uint8
	TotalLength    uint16
	ID             uint16
	Flags          uint16
	FragmentOffset uint16
	TTL            uint8
	Protocol       uint8
	Checksum       uint16
	SrcIP          net.IP
	DstIP          net.IP
}

func (h *IPv4Header) IsTCP() bool {
	return h.Protocol == 6
}

func (h *IPv4Header) IsUDP() bool {
	return h.Protocol == 17
}

func (h *IPv4Header) IsICMP() bool {
	return h.Protocol == 1
}

type PacketFilter interface {
	Allow(packet []byte) bool
}

type AllowAllFilter struct{}

func (f *AllowAllFilter) Allow(packet []byte) bool {
	return true
}

type CIDRFilter struct {
	nets []*net.IPNet
}

func NewCIDRFilter(cidrs []string) (*CIDRFilter, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("parse CIDR %s: %w", cidr, err)
		}
		nets = append(nets, n)
	}
	return &CIDRFilter{nets: nets}, nil
}

func (f *CIDRFilter) Allow(packet []byte) bool {
	if len(packet) < 20 {
		return false
	}

	var dstIP net.IP
	version := packet[0] >> 4
	switch version {
	case 4:
		if len(packet) < 20 {
			return false
		}
		dstIP = net.IP(packet[16:20])
	case 6:
		if len(packet) < 40 {
			return false
		}
		dstIP = net.IP(packet[24:40])
	default:
		return false
	}

	for _, n := range f.nets {
		if n.Contains(dstIP) {
			return true
		}
	}
	return len(f.nets) == 0
}

type PacketQueue struct {
	mu       sync.Mutex
	packets  [][]byte
	maxSize  int
	overflow bool
}

func NewPacketQueue(maxSize int) *PacketQueue {
	return &PacketQueue{
		packets: make([][]byte, 0),
		maxSize: maxSize,
	}
}

func (q *PacketQueue) Push(packet []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.packets) >= q.maxSize {
		q.overflow = true
		return false
	}

	p := make([]byte, len(packet))
	copy(p, packet)
	q.packets = append(q.packets, p)
	return true
}

func (q *PacketQueue) Pop() ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.packets) == 0 {
		return nil, false
	}

	packet := q.packets[0]
	q.packets = q.packets[1:]
	return packet, true
}

func (q *PacketQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.packets)
}

func (q *PacketQueue) Overflow() bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.overflow
}
