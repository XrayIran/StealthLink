// Package rawtcp provides a unified raw transport with multiple modes:
// - tcp: Raw TCP using pcap + KCP (original rawtcp)
// - faketcp: UDP disguised as TCP with state machine
// - icmp: ICMP echo tunneling
//
// This consolidates the previous separate faketcp/ and icmptun/ packages
// into a unified interface with mode selection.
package rawtcp

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport"
	"stealthlink/internal/transport/faketcp"
	"stealthlink/internal/transport/icmptun"

	"github.com/xtaci/smux"
)

// RawMode represents the raw transport mode
type RawMode string

const (
	// RawModeTCP uses raw TCP with pcap + KCP
	RawModeTCP RawMode = "tcp"
	// RawModeFakeTCP uses UDP disguised as TCP
	RawModeFakeTCP RawMode = "faketcp"
	// RawModeICMP uses ICMP echo tunneling
	RawModeICMP RawMode = "icmp"
)

// TCPFlagCombo represents a combination of TCP flags for cycling
type TCPFlagCombo struct {
	SYN bool
	ACK bool
	PSH bool
	RST bool
	FIN bool
	URG bool
}

// UnifiedConfig holds configuration for the unified raw transport
type UnifiedConfig struct {
	// Mode selects the raw transport mode
	Mode RawMode `yaml:"mode"`

	// TCP configuration for tcp mode
	TCP config.RawTCPConfig `yaml:"tcp"`

	// KCP configuration (used by tcp mode)
	KCP config.KCPConfig `yaml:"kcp"`

	// FakeTCP configuration for faketcp mode
	FakeTCP faketcp.Config `yaml:"faketcp"`

	// ICMP configuration for icmp mode
	ICMP icmptun.Config `yaml:"icmp"`

	// BufferPool configuration
	BufferPool BufferPoolConfig `yaml:"buffer_pool"`

	// TCPFlags for flag cycling (DPI evasion)
	TCPFlags []TCPFlagCombo `yaml:"tcp_flags"`

	// Smux configuration
	Smux *smux.Config `yaml:"-"`

	// Guard token
	Guard string `yaml:"-"`
}

// BufferPoolConfig configures the buffer pool for reduced GC pressure
type BufferPoolConfig struct {
	Enabled     bool `yaml:"enabled"`
	MinSize     int  `yaml:"min_size"`
	MaxSize     int  `yaml:"max_size"`
	InitialCap  int  `yaml:"initial_cap"`
	MaxIdle     int  `yaml:"max_idle"`
}

// ApplyDefaults sets default values
func (c *UnifiedConfig) ApplyDefaults() {
	if c.Mode == "" {
		c.Mode = RawModeTCP
	}

	// Apply KCP defaults
	if c.KCP.Block == "" {
		c.KCP.Block = "aes"
	}
	if c.KCP.PacketGuardMagic == "" {
		c.KCP.PacketGuardMagic = "PQT1"
	}
	if c.KCP.PacketGuardWindow == 0 {
		c.KCP.PacketGuardWindow = 30
	}
	if c.KCP.MTU == 0 {
		c.KCP.MTU = 1350
	}
	if c.KCP.SndWnd == 0 {
		c.KCP.SndWnd = 1024
	}
	if c.KCP.RcvWnd == 0 {
		c.KCP.RcvWnd = 1024
	}

	// Apply buffer pool defaults
	if c.BufferPool.MinSize == 0 {
		c.BufferPool.MinSize = 1024
	}
	if c.BufferPool.MaxSize == 0 {
		c.BufferPool.MaxSize = 65536
	}
	if c.BufferPool.InitialCap == 0 {
		c.BufferPool.InitialCap = 64
	}
	if c.BufferPool.MaxIdle == 0 {
		c.BufferPool.MaxIdle = 128
	}

	// Apply FakeTCP defaults
	if c.FakeTCP.MTU == 0 {
		c.FakeTCP.MTU = 1400
	}
	if c.FakeTCP.WindowSize == 0 {
		c.FakeTCP.WindowSize = 65535
	}
	if c.FakeTCP.RTO == 0 {
		c.FakeTCP.RTO = 200 * time.Millisecond
	}
	if c.FakeTCP.Keepalive == 0 {
		c.FakeTCP.Keepalive = 30 * time.Second
	}
	if c.FakeTCP.KeepaliveIdle == 0 {
		c.FakeTCP.KeepaliveIdle = 60 * time.Second
	}

	// Apply ICMP defaults
	c.ICMP.ApplyDefaults()
}

// UnifiedDialer implements transport.Dialer for unified raw transport
type UnifiedDialer struct {
	config *UnifiedConfig
}

// UnifiedListener implements transport.Listener for unified raw transport
type UnifiedListener struct {
	mode     RawMode
	inner    transport.Listener
	config   *UnifiedConfig
	closed   atomic.Bool
}

// NewUnifiedDialer creates a new unified raw transport dialer
func NewUnifiedDialer(config *UnifiedConfig) *UnifiedDialer {
	config.ApplyDefaults()
	return &UnifiedDialer{config: config}
}

// Dial connects using the configured raw mode
func (d *UnifiedDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	switch d.config.Mode {
	case RawModeTCP:
		return d.dialTCP(ctx, addr)
	case RawModeFakeTCP:
		return d.dialFakeTCP(ctx, addr)
	case RawModeICMP:
		return d.dialICMP(ctx, addr)
	default:
		return nil, fmt.Errorf("unsupported raw mode: %s", d.config.Mode)
	}
}

func (d *UnifiedDialer) dialTCP(ctx context.Context, addr string) (transport.Session, error) {
	dialer := NewDialer(d.config.TCP, d.config.KCP, d.config.Smux)
	return dialer.Dial(ctx, addr)
}

func (d *UnifiedDialer) dialFakeTCP(ctx context.Context, addr string) (transport.Session, error) {
	dialer := faketcp.NewDialer(&d.config.FakeTCP, d.config.Smux, d.config.Guard)
	return dialer.Dial(ctx, addr)
}

func (d *UnifiedDialer) dialICMP(ctx context.Context, addr string) (transport.Session, error) {
	dialer := icmptun.NewDialer(d.config.ICMP, d.config.Smux, d.config.Guard)
	return dialer.Dial(ctx, addr)
}

// NewUnifiedListener creates a new unified raw transport listener
func NewUnifiedListener(addr string, config *UnifiedConfig) (*UnifiedListener, error) {
	config.ApplyDefaults()

	var inner transport.Listener
	var err error

	switch config.Mode {
	case RawModeTCP:
		inner, err = Listen(config.TCP, config.KCP, config.Smux)
	case RawModeFakeTCP:
		inner, err = faketcp.Listen(addr, &config.FakeTCP, config.Smux, config.Guard)
	case RawModeICMP:
		inner, err = icmptun.Listen(addr, config.ICMP, config.Smux, config.Guard)
	default:
		return nil, fmt.Errorf("unsupported raw mode: %s", config.Mode)
	}

	if err != nil {
		return nil, err
	}

	return &UnifiedListener{
		mode:   config.Mode,
		inner:  inner,
		config: config,
	}, nil
}

// Accept accepts a connection
func (l *UnifiedListener) Accept() (transport.Session, error) {
	if l.closed.Load() {
		return nil, fmt.Errorf("listener closed")
	}
	return l.inner.Accept()
}

// Close closes the listener
func (l *UnifiedListener) Close() error {
	l.closed.Store(true)
	return l.inner.Close()
}

// Addr returns the listener address
func (l *UnifiedListener) Addr() net.Addr {
	return l.inner.Addr()
}

// Mode returns the current raw mode
func (l *UnifiedListener) Mode() RawMode {
	return l.mode
}

// BufferPool provides efficient buffer reuse for raw transport
type BufferPool struct {
	config BufferPoolConfig
	pools  map[int]*sync.Pool
	mu     sync.RWMutex
}

// NewBufferPool creates a new buffer pool
func NewBufferPool(config BufferPoolConfig) *BufferPool {
	bp := &BufferPool{
		config: config,
		pools:  make(map[int]*sync.Pool),
	}

	// Create pools for common sizes
	sizes := []int{1024, 2048, 4096, 8192, 16384, 32768, 65536}
	for _, size := range sizes {
		if size >= config.MinSize && size <= config.MaxSize {
			bp.pools[size] = bp.createPool(size)
		}
	}

	return bp
}

func (bp *BufferPool) createPool(size int) *sync.Pool {
	return &sync.Pool{
		New: func() interface{} {
			return make([]byte, size)
		},
	}
}

// Get gets a buffer of at least the requested size
func (bp *BufferPool) Get(size int) []byte {
	if !bp.config.Enabled {
		return make([]byte, size)
	}

	// Round up to nearest pool size
	poolSize := bp.roundUp(size)
	if poolSize > bp.config.MaxSize {
		return make([]byte, size)
	}

	bp.mu.RLock()
	pool, ok := bp.pools[poolSize]
	bp.mu.RUnlock()

	if !ok {
		return make([]byte, size)
	}

	buf := pool.Get().([]byte)
	if len(buf) < size {
		// Pool buffer too small, allocate new
		pool.Put(buf)
		return make([]byte, size)
	}

	return buf[:size]
}

// Put returns a buffer to the pool
func (bp *BufferPool) Put(buf []byte) {
	if !bp.config.Enabled || buf == nil {
		return
	}

	capSize := cap(buf)
	if capSize < bp.config.MinSize || capSize > bp.config.MaxSize {
		return // Don't pool unusual sizes
	}

	poolSize := bp.roundUp(capSize)
	if poolSize != capSize {
		return // Only pool exact sizes
	}

	bp.mu.RLock()
	pool, ok := bp.pools[poolSize]
	bp.mu.RUnlock()

	if ok {
		pool.Put(buf[:capSize])
	}
}

func (bp *BufferPool) roundUp(size int) int {
	// Round up to next power of 2 or common buffer size
	sizes := []int{1024, 2048, 4096, 8192, 16384, 32768, 65536}
	for _, s := range sizes {
		if s >= size {
			return s
		}
	}
	return size
}

// TCPFlagCycler cycles through TCP flag combinations for DPI evasion
type TCPFlagCycler struct {
	flags    []TCPFlagCombo
	current  atomic.Int32
	enabled  bool
}

// NewTCPFlagCycler creates a new flag cycler
func NewTCPFlagCycler(flags []TCPFlagCombo) *TCPFlagCycler {
	if len(flags) == 0 {
		// Default flag combinations
		flags = []TCPFlagCombo{
			{SYN: true},
			{SYN: true, ACK: true},
			{ACK: true},
			{ACK: true, PSH: true},
		}
	}

	return &TCPFlagCycler{
		flags:   flags,
		enabled: len(flags) > 1,
	}
}

// Next returns the next flag combination
func (c *TCPFlagCycler) Next() TCPFlagCombo {
	if !c.enabled {
		return TCPFlagCombo{ACK: true}
	}

	idx := c.current.Add(1) % int32(len(c.flags))
	return c.flags[idx]
}

// Current returns the current flag combination
func (c *TCPFlagCycler) Current() TCPFlagCombo {
	if !c.enabled {
		return TCPFlagCombo{ACK: true}
	}

	idx := c.current.Load() % int32(len(c.flags))
	return c.flags[idx]
}

// ToByte converts a flag combo to a TCP flags byte
func (fc *TCPFlagCombo) ToByte() uint8 {
	var flags uint8
	if fc.FIN {
		flags |= 0x01
	}
	if fc.SYN {
		flags |= 0x02
	}
	if fc.RST {
		flags |= 0x04
	}
	if fc.PSH {
		flags |= 0x08
	}
	if fc.ACK {
		flags |= 0x10
	}
	if fc.URG {
		flags |= 0x20
	}
	return flags
}

// ModeFromString converts a string to RawMode
func ModeFromString(s string) (RawMode, error) {
	switch s {
	case "tcp", "rawtcp":
		return RawModeTCP, nil
	case "faketcp", "fake_tcp":
		return RawModeFakeTCP, nil
	case "icmp":
		return RawModeICMP, nil
	default:
		return "", fmt.Errorf("unknown raw mode: %s", s)
	}
}

// IsValidMode checks if a mode string is valid
func IsValidMode(s string) bool {
	_, err := ModeFromString(s)
	return err == nil
}
