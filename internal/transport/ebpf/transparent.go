package ebpf

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"stealthlink/internal/metrics"
)

const (
	BPFInsnSize     = 8
	MaxBPFInsns     = 4096
	SO_ATTACH_BPF   = 50
	SO_DETACH_BPF   = 27
	DefaultMarkSkip = 0x100
)

type BPFProgram struct {
	fd       int
	insns    []BPFInsn
	attached bool
	mu       sync.Mutex
}

type BPFInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

type TransparentProxyConfig struct {
	Enabled       bool
	MarkDirect    uint32
	MarkProxy     uint32
	RedirectPort  int
	BypassLAN     bool
	BypassLocal   bool
	DirectSubnets []string
}

type EBPFTransparentProxy struct {
	config   TransparentProxyConfig
	programs map[int]*BPFProgram
	sockMap  map[int]int
	running  bool
	mu       sync.RWMutex
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewEBPFTransparentProxy(cfg TransparentProxyConfig) *EBPFTransparentProxy {
	if cfg.MarkDirect == 0 {
		cfg.MarkDirect = DefaultMarkSkip
	}
	if cfg.MarkProxy == 0 {
		cfg.MarkProxy = 0x200
	}
	if cfg.RedirectPort == 0 {
		cfg.RedirectPort = 1080
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &EBPFTransparentProxy{
		config:   cfg,
		programs: make(map[int]*BPFProgram),
		sockMap:  make(map[int]int),
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (p *EBPFTransparentProxy) Start() error {
	if !p.config.Enabled {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return nil
	}

	p.running = true
	metrics.SetTransportStatus("ebpf", "active", 0, 0)

	return nil
}

func (p *EBPFTransparentProxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return nil
	}

	for fd, prog := range p.programs {
		if prog.attached {
			p.detachProgram(fd, prog)
		}
		if prog.fd > 0 {
			syscall.Close(prog.fd)
		}
	}

	p.programs = make(map[int]*BPFProgram)
	p.running = false
	metrics.SetTransportStatus("ebpf", "inactive", 0, 0)

	return nil
}

func (p *EBPFTransparentProxy) attachProgram(sockfd int, prog *BPFProgram) error {
	if prog.fd <= 0 {
		return fmt.Errorf("invalid bpf program fd")
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(sockfd),
		syscall.SOL_SOCKET,
		SO_ATTACH_BPF,
		uintptr(unsafe.Pointer(&prog.fd)),
		4,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("attach bpf: %v", errno)
	}

	prog.attached = true
	return nil
}

func (p *EBPFTransparentProxy) detachProgram(sockfd int, prog *BPFProgram) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(sockfd),
		syscall.SOL_SOCKET,
		SO_DETACH_BPF,
		uintptr(unsafe.Pointer(&prog.fd)),
		4,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("detach bpf: %v", errno)
	}

	prog.attached = false
	return nil
}

func buildDirectTrafficFilter(cfg TransparentProxyConfig) []BPFInsn {
	var insns []BPFInsn

	insns = append(insns, BPFInsn{
		Code: 0x28,
		K:    0x0000000c,
	})

	insns = append(insns, BPFInsn{
		Code: 0x15,
		Jt:   0,
		Jf:   1,
		K:    0x00000800,
	})

	insns = append(insns, BPFInsn{
		Code: 0x28,
		K:    0x0000001e,
	})

	insns = append(insns, BPFInsn{
		Code: 0x15,
		Jt:   0,
		Jf:   1,
		K:    0x00000006,
	})

	insns = append(insns, BPFInsn{
		Code: 0x20,
		K:    0x0000001a,
	})

	insns = append(insns, BPFInsn{
		Code: 0x15,
		Jt:   0,
		Jf:   1,
		K:    binary.BigEndian.Uint32(net.ParseIP("127.0.0.1").To4()),
	})

	insns = append(insns, BPFInsn{
		Code: 0x06,
		K:    cfg.MarkDirect,
	})

	insns = append(insns, BPFInsn{
		Code: 0x06,
		K:    cfg.MarkProxy,
	})

	return insns
}

func buildUDPRedirectFilter(port int) []BPFInsn {
	return []BPFInsn{
		{Code: 0x28, K: 0x0000000c},
		{Code: 0x15, Jt: 0, Jf: 0, K: 0x00000800},
		{Code: 0x30, K: 0x00000017},
		{Code: 0x15, Jt: 0, Jf: 0, K: 0x00000011},
		{Code: 0x28, K: 0x00000014},
		{Code: 0x45, Jt: 0, Jf: 0, K: uint32(port)},
		{Code: 0x06, K: 0x00000000},
		{Code: 0x06, K: 0x00000001},
	}
}

func (p *EBPFTransparentProxy) CreateSocketFilter(sockType int) ([]BPFInsn, error) {
	switch sockType {
	case syscall.SOCK_STREAM:
		return buildDirectTrafficFilter(p.config), nil
	case syscall.SOCK_DGRAM:
		return buildUDPRedirectFilter(p.config.RedirectPort), nil
	default:
		return nil, fmt.Errorf("unsupported socket type: %d", sockType)
	}
}

type TrafficClassifier struct {
	directCIDRs []*net.IPNet
	proxyPort   int
	mu          sync.RWMutex
}

func NewTrafficClassifier(proxyPort int) *TrafficClassifier {
	c := &TrafficClassifier{
		proxyPort: proxyPort,
	}

	defaultBypass := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	for _, cidr := range defaultBypass {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			c.directCIDRs = append(c.directCIDRs, network)
		}
	}

	return c
}

func (c *TrafficClassifier) ShouldDirect(dst net.IP, port int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if port == c.proxyPort {
		return true
	}

	if dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsLinkLocalMulticast() {
		return true
	}

	for _, cidr := range c.directCIDRs {
		if cidr.Contains(dst) {
			return true
		}
	}

	return false
}

func (c *TrafficClassifier) AddDirectCIDR(cidr string) error {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.directCIDRs = append(c.directCIDRs, network)
	return nil
}

func (c *TrafficClassifier) RemoveDirectCIDR(cidr string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i, n := range c.directCIDRs {
		if n.String() == cidr {
			c.directCIDRs = append(c.directCIDRs[:i], c.directCIDRs[i+1:]...)
			break
		}
	}
}

type SocketTagger struct {
	fd   int
	mark uint32
}

func NewSocketTagger(mark uint32) *SocketTagger {
	return &SocketTagger{mark: mark}
}

func (t *SocketTagger) TagSocket(sockfd int) error {
	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(sockfd),
		syscall.SOL_SOCKET,
		syscall.SO_MARK,
		uintptr(unsafe.Pointer(&t.mark)),
		4,
		0,
	)

	if errno != 0 {
		return fmt.Errorf("set socket mark: %v", errno)
	}

	return nil
}

func (t *SocketTagger) SetFD(sockfd int) {
	t.fd = sockfd
}

func GetOriginalDst(sockfd int) (net.IP, int, error) {
	var addr syscall.RawSockaddrInet4
	addrLen := uint32(unsafe.Sizeof(addr))

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(sockfd),
		syscall.SOL_IP,
		80,
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addrLen)),
		0,
	)

	if errno != 0 {
		return nil, 0, fmt.Errorf("get original dst: %v", errno)
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))

	return ip, port, nil
}
