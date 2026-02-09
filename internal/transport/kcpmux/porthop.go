package kcpmux

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"
	"stealthlink/internal/transport/kcputil"

	"github.com/xtaci/kcp-go/v5"
)

// PortHopConfig configures UDP port hopping.
type PortHopConfig struct {
	Enabled    bool          `yaml:"enabled"`     // Enable port hopping
	PortRange  string        `yaml:"port_range"`  // Port range (e.g., "3000-4000")
	Interval   time.Duration `yaml:"interval"`    // Hop interval (default: 30s)
	Overlap    time.Duration `yaml:"overlap"`     // Connection overlap during hop (default: 5s)
	Randomize  bool          `yaml:"randomize"`   // Randomize port selection
}

// ApplyDefaults sets default values.
func (c *PortHopConfig) ApplyDefaults() {
	if c.Interval <= 0 {
		c.Interval = 30 * time.Second
	}
	if c.Overlap <= 0 {
		c.Overlap = 5 * time.Second
	}
	if c.PortRange == "" {
		c.PortRange = "3000-4000"
	}
}

// ParsePortRange parses a port range string like "3000-4000".
func ParsePortRange(s string) (min, max int, err error) {
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid port range format: %s", s)
	}

	min, err = strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid min port: %w", err)
	}

	max, err = strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid max port: %w", err)
	}

	if min < 1 || max > 65535 || min >= max {
		return 0, 0, fmt.Errorf("invalid port range: %d-%d", min, max)
	}

	return min, max, nil
}

// PortHopDialer is a KCP dialer with port hopping support.
type PortHopDialer struct {
	config      PortHopConfig
	baseDialer  *Dialer
	minPort     int
	maxPort     int
	currentPort int
	hopTimer    *time.Timer
	mu          sync.RWMutex
	conns       map[int]*hopConnection
	closed      atomic.Bool
}

// hopConnection tracks a hopping connection.
type hopConnection struct {
	conn      *kcp.UDPSession
	pc        net.PacketConn
	port      int
	createdAt time.Time
	lastUsed  time.Time
}

// NewPortHopDialer creates a new port hopping dialer.
func NewPortHopDialer(config PortHopConfig, baseDialer *Dialer) (*PortHopDialer, error) {
	config.ApplyDefaults()

	minPort, maxPort, err := ParsePortRange(config.PortRange)
	if err != nil {
		return nil, err
	}

	d := &PortHopDialer{
		config:      config,
		baseDialer:  baseDialer,
		minPort:     minPort,
		maxPort:     maxPort,
		currentPort: randomPort(minPort, maxPort),
		conns:       make(map[int]*hopConnection),
	}

	// Start hop timer
	go d.hopLoop()

	return d, nil
}

// Dial connects with port hopping.
func (d *PortHopDialer) Dial(ctx context.Context, addr string) (*hopSession, error) {
	if d.closed.Load() {
		return nil, fmt.Errorf("dialer closed")
	}

	// Get current port
	d.mu.RLock()
	port := d.currentPort
	d.mu.RUnlock()

	// Create connection on current port
	conn, err := d.dialOnPort(ctx, addr, port)
	if err != nil {
		return nil, err
	}

	session := &hopSession{
		dialer: d,
		conn:   conn,
		port:   port,
		addr:   addr,
	}

	// Track connection
	d.mu.Lock()
	d.conns[port] = conn
	d.mu.Unlock()

	return session, nil
}

func (d *PortHopDialer) dialOnPort(ctx context.Context, addr string, port int) (*hopConnection, error) {
	// Create local address with specific port
	localAddr := &net.UDPAddr{Port: port}

	pc, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on port %d: %w", port, err)
	}

	// Get the actual port (may be different if port was in use)
	actualPort := pc.LocalAddr().(*net.UDPAddr).Port

	// Create KCP connection
	block, err := kcputil.NewBlock(d.baseDialer.Cfg.Block, d.baseDialer.Cfg.Key)
	if err != nil {
		pc.Close()
		return nil, err
	}

	dShard, pShard := d.baseDialer.Cfg.DShard, d.baseDialer.Cfg.PShard
	if d.baseDialer.fecTuner != nil {
		dShard, pShard = d.baseDialer.fecTuner.GetShards()
	}

	pcWrapped := transport.NewPacketGuardConn(pc, transport.PacketGuardConfig{
		Enabled: d.baseDialer.Cfg.PacketGuard,
		Magic:   d.baseDialer.Cfg.PacketGuardMagic,
		Window:  time.Duration(d.baseDialer.Cfg.PacketGuardWindow) * time.Second,
		Skew:    d.baseDialer.Cfg.PacketGuardSkew,
		Key:     d.baseDialer.Cfg.Key,
	})

	conn, err := kcp.NewConn(addr, block, dShard, pShard, pcWrapped)
	if err != nil {
		pc.Close()
		return nil, err
	}

	kcputil.Apply(conn, d.baseDialer.Cfg)

	return &hopConnection{
		conn:      conn,
		pc:        pc,
		port:      actualPort,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}, nil
}

func (d *PortHopDialer) hopLoop() {
	ticker := time.NewTicker(d.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if d.closed.Load() {
				return
			}
			d.performHop()
		}
	}
}

func (d *PortHopDialer) performHop() {
	// Select new port
	newPort := d.selectNewPort()

	d.mu.Lock()
	oldPort := d.currentPort
	d.currentPort = newPort
	conns := make(map[int]*hopConnection)
	for k, v := range d.conns {
		conns[k] = v
	}
	d.mu.Unlock()

	// Mark old connections for cleanup after overlap period
	go d.cleanupAfterOverlap(oldPort, conns[oldPort])
}

func (d *PortHopDialer) selectNewPort() int {
	if d.config.Randomize {
		return randomPort(d.minPort, d.maxPort)
	}

	// Sequential port selection
	d.mu.RLock()
	current := d.currentPort
	d.mu.RUnlock()

	next := current + 1
	if next > d.maxPort {
		next = d.minPort
	}
	return next
}

func (d *PortHopDialer) cleanupAfterOverlap(port int, conn *hopConnection) {
	if conn == nil {
		return
	}

	// Wait for overlap period
	time.Sleep(d.config.Overlap)

	// Close old connection
	d.mu.Lock()
	delete(d.conns, port)
	d.mu.Unlock()

	conn.conn.Close()
	conn.pc.Close()
}

func (d *PortHopDialer) Close() error {
	if d.closed.CompareAndSwap(false, true) {
		d.mu.Lock()
		for _, conn := range d.conns {
			conn.conn.Close()
			conn.pc.Close()
		}
		d.conns = make(map[int]*hopConnection)
		d.mu.Unlock()
	}
	return nil
}

func randomPort(min, max int) int {
	return min + rand.Intn(max-min+1)
}

// hopSession wraps a port-hopping connection.
type hopSession struct {
	dialer *PortHopDialer
	conn   *hopConnection
	port   int
	addr   string
	mu     sync.RWMutex
}

func (s *hopSession) Read(p []byte) (n int, err error) {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("connection closed")
	}

	n, err = conn.conn.Read(p)
	if err == nil {
		conn.lastUsed = time.Now()
	}
	return n, err
}

func (s *hopSession) Write(p []byte) (n int, err error) {
	s.mu.RLock()
	conn := s.conn
	s.mu.RUnlock()

	if conn == nil {
		return 0, fmt.Errorf("connection closed")
	}

	n, err = conn.conn.Write(p)
	if err == nil {
		conn.lastUsed = time.Now()
	}
	return n, err
}

func (s *hopSession) Close() error {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()

	if conn != nil {
		s.dialer.mu.Lock()
		delete(s.dialer.conns, s.port)
		s.dialer.mu.Unlock()

		conn.conn.Close()
		conn.pc.Close()
	}
	return nil
}

func (s *hopSession) LocalAddr() net.Addr  { return s.conn.conn.LocalAddr() }
func (s *hopSession) RemoteAddr() net.Addr { return s.conn.conn.RemoteAddr() }

func (s *hopSession) SetDeadline(t time.Time) error      { return s.conn.conn.SetDeadline(t) }
func (s *hopSession) SetReadDeadline(t time.Time) error  { return s.conn.conn.SetReadDeadline(t) }
func (s *hopSession) SetWriteDeadline(t time.Time) error { return s.conn.conn.SetWriteDeadline(t) }

// MigrateToPort migrates the session to a new port.
func (s *hopSession) MigrateToPort(ctx context.Context, newPort int) error {
	// Create new connection on new port
	newConn, err := s.dialer.dialOnPort(ctx, s.addr, newPort)
	if err != nil {
		return err
	}

	// Swap connections
	s.mu.Lock()
	oldConn := s.conn
	s.conn = newConn
	s.port = newPort
	s.mu.Unlock()

	// Update dialer's connection tracking
	s.dialer.mu.Lock()
	delete(s.dialer.conns, oldConn.port)
	s.dialer.conns[newPort] = newConn
	s.dialer.mu.Unlock()

	// Close old connection after a short delay
	go func() {
		time.Sleep(s.dialer.config.Overlap)
		oldConn.conn.Close()
		oldConn.pc.Close()
	}()

	return nil
}
