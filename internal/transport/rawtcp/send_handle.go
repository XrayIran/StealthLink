package rawtcp

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/config"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type flagIterator struct {
	items []config.TCPFlags
	index atomic.Uint64
}

func (it *flagIterator) Next() config.TCPFlags {
	i := it.index.Add(1)
	n := uint64(len(it.items))
	if n&(n-1) == 0 {
		return it.items[i&(n-1)]
	}
	return it.items[i%n]
}

type tcpFlagState struct {
	tcpF       flagIterator
	clientTCPF map[uint64]*flagIterator
	mu         sync.RWMutex
}

type SendHandle struct {
	handle      *pcap.Handle
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	time        uint32
	tsCounter   uint32
	tcpF        tcpFlagState
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	bufPool     sync.Pool
	optPool     sync.Pool
}

type tcpOptBuf struct {
	mss   [2]byte
	ws    [1]byte
	synTS [8]byte
	ackTS [8]byte
	syn   [5]layers.TCPOption
	ack   [3]layers.TCPOption
}

func newTCPOptBuf() *tcpOptBuf {
	b := &tcpOptBuf{
		mss: [2]byte{0x05, 0xb4},
		ws:  [1]byte{8},
	}
	b.syn[0] = layers.TCPOption{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: b.mss[:]}
	b.syn[1] = layers.TCPOption{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2}
	b.syn[2] = layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: b.synTS[:]}
	b.syn[3] = layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
	b.syn[4] = layers.TCPOption{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: b.ws[:]}

	b.ack[0] = layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
	b.ack[1] = layers.TCPOption{OptionType: layers.TCPOptionKindNop, OptionLength: 1}
	b.ack[2] = layers.TCPOption{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: b.ackTS[:]}
	return b
}

func NewSendHandle(cfg *packetConfig) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("pcap handle: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("set pcap direction out: %v", err)
		}
	}

	sh := &SendHandle{
		handle:  handle,
		srcPort: uint16(cfg.port),
		tcpF: tcpFlagState{
			tcpF:       flagIterator{items: cfg.tcpLocal},
			clientTCPF: make(map[uint64]*flagIterator),
		},
		time: uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: cfg.iface.HardwareAddr}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
		optPool: sync.Pool{
			New: func() any {
				return newTCPOptBuf()
			},
		},
	}
	if cfg.ipv4Addr != nil {
		sh.srcIPv4 = cfg.ipv4Addr.IP
		sh.srcIPv4RHWA = cfg.ipv4Router
	}
	if cfg.ipv6Addr != nil {
		sh.srcIPv6 = cfg.ipv6Addr.IP
		sh.srcIPv6RHWA = cfg.ipv6Router
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      184,
		TTL:      64,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: 184,
		HopLimit:     64,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(dstPort uint16, f config.TCPFlags, opt *tcpOptBuf) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		binary.BigEndian.PutUint32(opt.synTS[0:4], tsVal)
		binary.BigEndian.PutUint32(opt.synTS[4:8], 0)
		tcp.Options = opt.syn[:]
		tcp.Seq = 1 + (counter & 0x7)
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(opt.ackTS[0:4], tsVal)
		binary.BigEndian.PutUint32(opt.ackTS[4:8], tsEcr)
		tcp.Options = opt.ack[:]
		seq := h.time + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	opt := h.optPool.Get().(*tcpOptBuf)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
		h.optPool.Put(opt)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(dstPort, f, opt)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}
	return h.handle.WritePacketData(buf.Bytes())
}

// Predefined flag combinations for cycling (from paqet techniques)
var defaultFlagCycles = []config.TCPFlags{
	{PSH: true, ACK: true}, // PA - Standard data push
	{SYN: true},            // S - Connection initiation
	{ACK: true},            // A - Pure acknowledgment
	{SYN: true, ACK: true}, // SA - SYN-ACK
	{PSH: true, ACK: true}, // PA (duplicate for weight)
	{ACK: true},            // A (duplicate for weight)
}

// randomFlagCycle returns a randomized flag sequence based on seed
func randomFlagCycle(seed uint64) []config.TCPFlags {
	// Create a copy to avoid modifying global
	flags := make([]config.TCPFlags, len(defaultFlagCycles))
	copy(flags, defaultFlagCycles)

	// Simple shuffle based on seed
	r := rand.New(rand.NewSource(int64(seed)))
	r.Shuffle(len(flags), func(i, j int) {
		flags[i], flags[j] = flags[j], flags[i]
	})
	return flags
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) config.TCPFlags {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hashAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []config.TCPFlags) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	defer h.tcpF.mu.Unlock()

	// If no custom flags provided, use randomized cycle
	if len(f) == 0 {
		seed := uint64(time.Now().UnixNano()) ^ uint64(a.IP[0]) ^ uint64(a.Port)
		f = randomFlagCycle(seed)
	}

	h.tcpF.clientTCPF[hashAddr(a.IP, uint16(a.Port))] = &flagIterator{items: f}
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
