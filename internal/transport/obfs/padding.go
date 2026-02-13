package obfs

import (
	"encoding/binary"
	"fmt"
	"net"
	"stealthlink/internal/transport/kcpbase"
	"sync"
)

// PaddingObfuscator implements padding-based obfuscation.
// It adds random padding to packets to obscure their true size.
type PaddingObfuscator struct {
	minPadding int
	maxPadding int
	strategy   PaddingStrategy
}

// PaddingStrategy determines how padding is generated
type PaddingStrategy string

const (
	// StrategyRandom uses random padding sizes
	StrategyRandom PaddingStrategy = "random"
	// StrategyFixed uses a fixed padding size
	StrategyFixed PaddingStrategy = "fixed"
	// StrategyPower2 pads to power-of-2 sizes
	StrategyPower2 PaddingStrategy = "power2"
	// StrategyMTU pads to MTU size
	StrategyMTU PaddingStrategy = "mtu"
)

// NewPaddingObfuscator creates a new padding obfuscator
func NewPaddingObfuscator(params map[string]string) (Obfuscator, error) {
	minPadding := 0
	maxPadding := 128
	strategy := StrategyRandom

	if params["min"] != "" {
		fmt.Sscanf(params["min"], "%d", &minPadding)
	}
	if params["max"] != "" {
		fmt.Sscanf(params["max"], "%d", &maxPadding)
	}
	if params["strategy"] != "" {
		strategy = PaddingStrategy(params["strategy"])
	}

	if minPadding < 0 {
		minPadding = 0
	}
	if maxPadding < minPadding {
		maxPadding = minPadding
	}

	return &PaddingObfuscator{
		minPadding: minPadding,
		maxPadding: maxPadding,
		strategy:   strategy,
	}, nil
}

// WrapConn wraps a connection with padding obfuscation
func (p *PaddingObfuscator) WrapConn(conn net.Conn) (net.Conn, error) {
	return &paddingConn{
		Conn:       conn,
		minPadding: p.minPadding,
		maxPadding: p.maxPadding,
		strategy:   p.strategy,
	}, nil
}

// WrapPacketConn wraps a packet connection with padding obfuscation
func (p *PaddingObfuscator) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	return &paddingPacketConn{
		PacketConn: conn,
		minPadding: p.minPadding,
		maxPadding: p.maxPadding,
		strategy:   p.strategy,
	}, nil
}

// GenerateJunk generates padding data
func (p *PaddingObfuscator) GenerateJunk() []byte {
	size := p.calculatePaddingSize(0)
	if size <= 0 {
		return nil
	}
	junk := make([]byte, size)
	kcpbase.FastRandom.Read(junk)
	return junk
}

// Type returns TypePadding
func (p *PaddingObfuscator) Type() Type {
	return TypePadding
}

// Ensure PaddingObfuscator implements Obfuscator
var _ Obfuscator = (*PaddingObfuscator)(nil)

// calculatePaddingSize calculates the padding size based on strategy
func (p *PaddingObfuscator) calculatePaddingSize(dataLen int) int {
	switch p.strategy {
	case StrategyFixed:
		return p.maxPadding

	case StrategyRandom:
		if p.maxPadding <= p.minPadding {
			return p.minPadding
		}
		return p.minPadding + int(kcpbase.FastRandom.Int64n(int64(p.maxPadding-p.minPadding+1)))

	case StrategyPower2:
		// Pad to next power of 2
		target := 1
		for target < dataLen+p.minPadding {
			target <<= 1
		}
		return target - dataLen

	case StrategyMTU:
		// Pad to MTU (assuming 1400 bytes for safety)
		mtu := 1400
		if dataLen >= mtu {
			return 0
		}
		return mtu - dataLen

	default:
		return p.minPadding
	}
}

// paddingConn wraps a net.Conn with padding
type paddingConn struct {
	net.Conn
	minPadding int
	maxPadding int
	strategy   PaddingStrategy
	readBuf    []byte
	mu         sync.Mutex
}

// Read reads data, stripping padding
func (c *paddingConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we have buffered data
	if len(c.readBuf) > 0 {
		n := copy(p, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Read length prefix (4 bytes: actual data length)
	var lenBuf [4]byte
	if _, err := c.Conn.Read(lenBuf[:]); err != nil {
		return 0, err
	}

	actualLen := binary.BigEndian.Uint32(lenBuf[:])
	if actualLen > 65536 {
		return 0, fmt.Errorf("invalid length: %d", actualLen)
	}

	// Read data + padding
	buf := make([]byte, actualLen)
	if _, err := c.Conn.Read(buf); err != nil {
		return 0, err
	}

	// Copy to output
	n := copy(p, buf)
	if n < len(buf) {
		c.readBuf = buf[n:]
	}

	return n, nil
}

// Write writes data with padding
func (c *paddingConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Calculate padding
	paddingSize := c.calculatePaddingSize(len(p))

	// Build packet: [length (4)][data (N)][padding (M)]
	packet := make([]byte, 4+len(p)+paddingSize)
	binary.BigEndian.PutUint32(packet, uint32(len(p)))
	copy(packet[4:], p)
	if paddingSize > 0 {
		kcpbase.FastRandom.Read(packet[4+len(p):])
	}

	_, err := c.Conn.Write(packet)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// calculatePaddingSize calculates padding size based on strategy
func (c *paddingConn) calculatePaddingSize(dataLen int) int {
	switch c.strategy {
	case StrategyFixed:
		return c.maxPadding
	case StrategyRandom:
		if c.maxPadding <= c.minPadding {
			return c.minPadding
		}
		return c.minPadding + int(kcpbase.FastRandom.Int64n(int64(c.maxPadding-c.minPadding+1)))
	case StrategyPower2:
		target := 1
		for target < dataLen+c.minPadding {
			target <<= 1
		}
		return target - dataLen
	case StrategyMTU:
		mtu := 1400
		if dataLen >= mtu {
			return 0
		}
		return mtu - dataLen
	default:
		return c.minPadding
	}
}

// paddingPacketConn wraps a net.PacketConn with padding
type paddingPacketConn struct {
	net.PacketConn
	minPadding int
	maxPadding int
	strategy   PaddingStrategy
}

// ReadFrom reads a packet, stripping padding
func (c *paddingPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	buf := make([]byte, len(p)+c.maxPadding+4)
	n, addr, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}

	if n < 4 {
		return 0, nil, fmt.Errorf("packet too short")
	}

	actualLen := binary.BigEndian.Uint32(buf[:4])
	if int(actualLen) > n-4 || int(actualLen) > len(p) {
		return 0, nil, fmt.Errorf("invalid length")
	}

	return copy(p, buf[4:4+actualLen]), addr, nil
}

// calculatePaddingSize calculates padding size based on strategy
func (c *paddingPacketConn) calculatePaddingSize(dataLen int) int {
	switch c.strategy {
	case StrategyFixed:
		return c.maxPadding
	case StrategyRandom:
		if c.maxPadding <= c.minPadding {
			return c.minPadding
		}
		return c.minPadding + int(kcpbase.FastRandom.Int64n(int64(c.maxPadding-c.minPadding+1)))
	case StrategyPower2:
		target := 1
		for target < dataLen+c.minPadding {
			target <<= 1
		}
		return target - dataLen
	case StrategyMTU:
		mtu := 1400
		if dataLen >= mtu {
			return 0
		}
		return mtu - dataLen
	default:
		return c.minPadding
	}
}

// WriteTo writes a packet with padding
func (c *paddingPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	paddingSize := c.calculatePaddingSize(len(p))

	packet := make([]byte, 4+len(p)+paddingSize)
	binary.BigEndian.PutUint32(packet, uint32(len(p)))
	copy(packet[4:], p)
	if paddingSize > 0 {
		kcpbase.FastRandom.Read(packet[4+len(p):])
	}

	_, err = c.PacketConn.WriteTo(packet, addr)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// AWGObfuscator implements AmneziaWG-style junk injection
type AWGObfuscator struct {
	jc           int           // Junk packet count
	jmin, jmax   int           // Junk size range
	s1, s2       int           // Init/response junk
	h1, h2, h3, h4 int         // Junk packet sizes
	interval     int           // Junk interval (packets)
	packetCount  int
}

// NewAWGObfuscator creates a new AWG obfuscator
func NewAWGObfuscator(params map[string]string) (Obfuscator, error) {
	a := &AWGObfuscator{
		jc:       4,
		jmin:     64,
		jmax:     1024,
		s1:       0,
		s2:       0,
		h1:       1,
		h2:       2,
		h3:       3,
		h4:       4,
		interval: 100,
	}

	// Parse params if provided
	if params["jc"] != "" {
		fmt.Sscanf(params["jc"], "%d", &a.jc)
	}
	if params["jmin"] != "" {
		fmt.Sscanf(params["jmin"], "%d", &a.jmin)
	}
	if params["jmax"] != "" {
		fmt.Sscanf(params["jmax"], "%d", &a.jmax)
	}

	return a, nil
}

// WrapConn wraps a connection with AWG obfuscation
func (a *AWGObfuscator) WrapConn(conn net.Conn) (net.Conn, error) {
	return &awgConn{
		Conn:        conn,
		obfuscator:  a,
	}, nil
}

// WrapPacketConn wraps a packet connection with AWG obfuscation
func (a *AWGObfuscator) WrapPacketConn(conn net.PacketConn) (net.PacketConn, error) {
	return &awgPacketConn{
		PacketConn: conn,
		obfuscator: a,
	}, nil
}

// GenerateJunk generates AWG-style junk packets
func (a *AWGObfuscator) GenerateJunk() []byte {
	size := a.jmin
	if a.jmax > a.jmin {
		size += int(kcpbase.FastRandom.Int64n(int64(a.jmax - a.jmin + 1)))
	}

	junk := make([]byte, size)
	kcpbase.FastRandom.Read(junk)

	// Mark as junk packet
	junk[0] = 0xFF

	return junk
}

// Type returns TypeAWG
func (a *AWGObfuscator) Type() Type {
	return TypeAWG
}

// Ensure AWGObfuscator implements Obfuscator
var _ Obfuscator = (*AWGObfuscator)(nil)

// shouldInjectJunk returns true if junk should be injected
func (a *AWGObfuscator) shouldInjectJunk() bool {
	a.packetCount++
	return a.packetCount%a.interval == 0
}

// awgConn wraps a net.Conn with AWG junk injection
type awgConn struct {
	net.Conn
	obfuscator *AWGObfuscator
}

// Read reads data, filtering out junk packets
func (c *awgConn) Read(p []byte) (int, error) {
	for {
		n, err := c.Conn.Read(p)
		if err != nil {
			return n, err
		}

		// Check if this is a junk packet
		if n > 0 && p[0] == 0xFF {
			// Junk packet, skip and read again
			continue
		}

		return n, nil
	}
}

// Write writes data, occasionally injecting junk
func (c *awgConn) Write(p []byte) (int, error) {
	// Check if we should inject junk
	if c.obfuscator.shouldInjectJunk() {
		junk := c.obfuscator.GenerateJunk()
		c.Conn.Write(junk)
	}

	return c.Conn.Write(p)
}

// awgPacketConn wraps a net.PacketConn with AWG junk injection
type awgPacketConn struct {
	net.PacketConn
	obfuscator *AWGObfuscator
}

// ReadFrom reads a packet, filtering out junk
func (c *awgPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = c.PacketConn.ReadFrom(p)
		if err != nil {
			return 0, nil, err
		}

		// Check if this is a junk packet
		if n > 0 && p[0] == 0xFF {
			continue
		}

		return n, addr, nil
	}
}

// WriteTo writes a packet, occasionally injecting junk
func (c *awgPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.obfuscator.shouldInjectJunk() {
		junk := c.obfuscator.GenerateJunk()
		c.PacketConn.WriteTo(junk, addr)
	}

	return c.PacketConn.WriteTo(p, addr)
}
