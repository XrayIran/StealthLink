// Package taptun implements Layer 2 tap device tunneling for StealthLink.
// It provides Ethernet-over-IP capability with protocol transparency.
package taptun

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/songgao/water"
	"github.com/xtaci/smux"
)

// Config configures Layer 2 tap tunneling.
type Config struct {
	// Device name pattern (leave empty for auto)
	DeviceName string `yaml:"device_name"`

	// MTU for the tap device
	MTU int `yaml:"mtu"`

	// MAC address to use (leave empty for auto)
	MACAddress string `yaml:"mac_address"`

	// Enable promiscuous mode
	Promiscuous bool `yaml:"promiscuous"`

	// Allowed Ethernet types (0 = all)
	AllowedTypes []uint16 `yaml:"allowed_types"`

	// Bridge mode - act as a bridge instead of router
	BridgeMode bool `yaml:"bridge_mode"`
}

// ApplyDefaults sets default values for tap configuration.
func (c *Config) ApplyDefaults() {
	if c.MTU <= 0 {
		c.MTU = 1500 // Standard Ethernet MTU
	}
	if c.MTU > 9000 {
		c.MTU = 9000 // Jumbo frame limit
	}
	if len(c.AllowedTypes) == 0 {
		// Allow all by default
		c.AllowedTypes = []uint16{0}
	}
}

// Dialer implements transport.Dialer for tap tunnel.
type Dialer struct {
	config *Config
	tap    *water.Interface
	smux   *smux.Config
	guard  string
}

// NewDialer creates a new tap tunnel dialer.
func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string) (*Dialer, error) {
	cfg.ApplyDefaults()

	// Create tap device
	tapConfig := water.Config{
		DeviceType: water.TAP,
	}

	if cfg.DeviceName != "" {
		tapConfig.Name = cfg.DeviceName
	}

	tap, err := water.New(tapConfig)
	if err != nil {
		return nil, fmt.Errorf("create tap: %w", err)
	}

	return &Dialer{
		config: cfg,
		tap:    tap,
		smux:   smuxCfg,
		guard:  guard,
	}, nil
}

// Dial connects to a tap tunnel server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	// Establish TCP connection to server
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial server: %w", err)
	}

	// Send guard token
	if err := transport.SendGuard(conn, d.guard); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send guard: %w", err)
	}

	// Start smux
	sess, err := smux.Client(conn, d.smux)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("create smux: %w", err)
	}

	// Create tap session
	tapSess := &tapSession{
		dialer:  d,
		sess:    sess,
		conn:    conn,
		tap:     d.tap,
		readCh:  make(chan []byte, 100),
		writeCh: make(chan []byte, 100),
		closeCh: make(chan struct{}),
		closed:  atomic.Bool{},
	}

	// Start packet forwarding
	go tapSess.readFromTap()
	go tapSess.readFromTunnel()
	go tapSess.writeToTap()

	return tapSess, nil
}

// GetTapDevice returns the tap device.
func (d *Dialer) GetTapDevice() *water.Interface {
	return d.tap
}

// Close closes the dialer and tap device.
func (d *Dialer) Close() error {
	if d.tap != nil {
		return d.tap.Close()
	}
	return nil
}

// Listener implements transport.Listener for tap tunnel.
type Listener struct {
	config *Config
	tap    *water.Interface
	smux   *smux.Config
	guard  string

	listener net.Listener
	sessions chan *tapSession
	closeCh  chan struct{}
	closed   atomic.Bool
}

// Listen creates a tap tunnel listener.
func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	cfg.ApplyDefaults()

	// Create tap device
	tapConfig := water.Config{
		DeviceType: water.TAP,
	}

	if cfg.DeviceName != "" {
		tapConfig.Name = cfg.DeviceName
	}

	tap, err := water.New(tapConfig)
	if err != nil {
		return nil, fmt.Errorf("create tap: %w", err)
	}

	// Listen for incoming connections
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = tap.Close()
		return nil, fmt.Errorf("listen: %w", err)
	}

	l := &Listener{
		config:   cfg,
		tap:      tap,
		smux:     smuxCfg,
		guard:    guard,
		listener: ln,
		sessions: make(chan *tapSession, 16),
		closeCh:  make(chan struct{}),
	}

	// Start accepting connections
	go l.acceptLoop()

	return l, nil
}

func (l *Listener) acceptLoop() {
	for {
		select {
		case <-l.closeCh:
			return
		default:
		}

		conn, err := l.listener.Accept()
		if err != nil {
			if l.closed.Load() {
				return
			}
			continue
		}

		// Handle connection
		go l.handleConnection(conn)
	}
}

func (l *Listener) handleConnection(conn net.Conn) {
	// Receive guard token
	if err := transport.RecvGuard(conn, l.guard); err != nil {
		_ = conn.Close()
		return
	}

	// Start smux
	sess, err := smux.Server(conn, l.smux)
	if err != nil {
		_ = conn.Close()
		return
	}

	// Create tap session
	tapSess := &tapSession{
		listener: l,
		sess:     sess,
		conn:     conn,
		tap:      l.tap,
		readCh:   make(chan []byte, 100),
		writeCh:  make(chan []byte, 100),
		closeCh:  make(chan struct{}),
		closed:   atomic.Bool{},
	}

	// Start packet forwarding
	go tapSess.readFromTap()
	go tapSess.readFromTunnel()
	go tapSess.writeToTap()

	// Notify of new session
	select {
	case l.sessions <- tapSess:
	case <-l.closeCh:
		_ = tapSess.Close()
	}
}

// Accept accepts a tap tunnel connection.
func (l *Listener) Accept() (transport.Session, error) {
	select {
	case <-l.closeCh:
		return nil, fmt.Errorf("listener closed")
	case session := <-l.sessions:
		return session, nil
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	if l.closed.CompareAndSwap(false, true) {
		close(l.closeCh)
		err := l.listener.Close()
		if l.tap != nil {
			_ = l.tap.Close()
		}
		return err
	}
	return nil
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// GetTapDevice returns the tap device.
func (l *Listener) GetTapDevice() *water.Interface {
	return l.tap
}

// tapSession implements transport.Session for tap tunneling.
type tapSession struct {
	dialer   *Dialer
	listener *Listener
	sess     *smux.Session
	conn     net.Conn
	tap      *water.Interface
	readCh   chan []byte
	writeCh  chan []byte
	closeCh  chan struct{}
	closed   atomic.Bool
}

func (s *tapSession) readFromTap() {
	buf := make([]byte, s.getMTU())

	for {
		select {
		case <-s.closeCh:
			return
		default:
		}

		n, err := s.tap.Read(buf)
		if err != nil {
			if !s.closed.Load() {
				s.Close()
			}
			return
		}

		if n > 0 {
			// Filter by Ethernet type if configured
			if s.allowedType(buf[:n]) {
				data := make([]byte, n)
				copy(data, buf[:n])

				select {
				case s.writeCh <- data:
				case <-s.closeCh:
					return
				}
			}
		}
	}
}

func (s *tapSession) readFromTunnel() {
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}

		stream, err := s.sess.AcceptStream()
		if err != nil {
			if !s.closed.Load() {
				s.Close()
			}
			return
		}

		go s.handleStream(stream)
	}
}

func (s *tapSession) handleStream(stream net.Conn) {
	defer stream.Close()

	buf := make([]byte, s.getMTU())
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}

		if n > 0 {
			data := make([]byte, n)
			copy(data, buf[:n])

			select {
			case s.readCh <- data:
			case <-s.closeCh:
				return
			}
		}
	}
}

func (s *tapSession) writeToTap() {
	for {
		select {
		case <-s.closeCh:
			return
		case data := <-s.readCh:
			if _, err := s.tap.Write(data); err != nil {
				s.Close()
				return
			}
		}
	}
}

func (s *tapSession) allowedType(frame []byte) bool {
	var config *Config
	if s.dialer != nil {
		config = s.dialer.config
	} else if s.listener != nil {
		config = s.listener.config
	}

	if config == nil || len(config.AllowedTypes) == 0 {
		return true // Allow all
	}

	if len(frame) < 14 {
		return false // Invalid Ethernet frame
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	for _, allowed := range config.AllowedTypes {
		if allowed == 0 || allowed == etherType {
			return true
		}
	}

	return false
}

func (s *tapSession) getMTU() int {
	var config *Config
	if s.dialer != nil {
		config = s.dialer.config
	} else if s.listener != nil {
		config = s.listener.config
	}

	if config != nil && config.MTU > 0 {
		return config.MTU
	}
	return 1500
}

// OpenStream opens a new stream over the tap tunnel.
func (s *tapSession) OpenStream() (net.Conn, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	stream, err := s.sess.OpenStream()
	if err != nil {
		return nil, err
	}

	return &tapStream{
		stream:  stream,
		session: s,
	}, nil
}

// AcceptStream accepts a stream over the tap tunnel.
func (s *tapSession) AcceptStream() (net.Conn, error) {
	if s.closed.Load() {
		return nil, fmt.Errorf("session closed")
	}

	stream, err := s.sess.AcceptStream()
	if err != nil {
		return nil, err
	}

	return &tapStream{
		stream:  stream,
		session: s,
	}, nil
}

// Close closes the tap session.
func (s *tapSession) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		close(s.closeCh)
		close(s.readCh)
		close(s.writeCh)

		if s.sess != nil {
			_ = s.sess.Close()
		}
		if s.conn != nil {
			_ = s.conn.Close()
		}
	}
	return nil
}

func (s *tapSession) LocalAddr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return nil
}

func (s *tapSession) RemoteAddr() net.Addr {
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return nil
}

// tapStream wraps a stream with tap-specific functionality.
type tapStream struct {
	stream  net.Conn
	session *tapSession
}

func (ts *tapStream) Read(p []byte) (n int, err error) {
	return ts.stream.Read(p)
}

func (ts *tapStream) Write(p []byte) (n int, err error) {
	// Write Ethernet frame to stream
	return ts.stream.Write(p)
}

func (ts *tapStream) Close() error {
	return ts.stream.Close()
}

func (ts *tapStream) LocalAddr() net.Addr {
	return ts.stream.LocalAddr()
}

func (ts *tapStream) RemoteAddr() net.Addr {
	return ts.stream.RemoteAddr()
}

func (ts *tapStream) SetDeadline(t time.Time) error {
	return ts.stream.SetDeadline(t)
}

func (ts *tapStream) SetReadDeadline(t time.Time) error {
	return ts.stream.SetReadDeadline(t)
}

func (ts *tapStream) SetWriteDeadline(t time.Time) error {
	return ts.stream.SetWriteDeadline(t)
}

// PacketFilter provides Ethernet frame filtering.
type PacketFilter struct {
	allowedMACs  map[string]bool
	allowedTypes map[uint16]bool
	mu           sync.RWMutex
}

// NewPacketFilter creates a new packet filter.
func NewPacketFilter() *PacketFilter {
	return &PacketFilter{
		allowedMACs:  make(map[string]bool),
		allowedTypes: make(map[uint16]bool),
	}
}

// AllowMAC adds a MAC address to the allow list.
func (pf *PacketFilter) AllowMAC(mac string) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.allowedMACs[mac] = true
}

// AllowType adds an Ethernet type to the allow list.
func (pf *PacketFilter) AllowType(etherType uint16) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	pf.allowedTypes[etherType] = true
}

// Filter checks if a packet should be allowed.
func (pf *PacketFilter) Filter(packet []byte) bool {
	pf.mu.RLock()
	defer pf.mu.RUnlock()

	// Parse Ethernet frame
	if len(packet) < 14 {
		return false
	}

	// Check Ethernet type
	etherType := binary.BigEndian.Uint16(packet[12:14])
	if len(pf.allowedTypes) > 0 {
		if !pf.allowedTypes[etherType] {
			return false
		}
	}

	// Check source/destination MAC
	if len(pf.allowedMACs) > 0 {
		srcMAC := net.HardwareAddr(packet[0:6]).String()
		dstMAC := net.HardwareAddr(packet[6:12]).String()
		if !pf.allowedMACs[srcMAC] && !pf.allowedMACs[dstMAC] {
			return false
		}
	}

	return true
}

// ParseEthernetFrame parses an Ethernet frame.
func ParseEthernetFrame(data []byte) (*layers.Ethernet, error) {
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, fmt.Errorf("not an Ethernet frame")
	}
	eth, _ := ethLayer.(*layers.Ethernet)
	return eth, nil
}

// CreateEthernetFrame creates a new Ethernet frame.
func CreateEthernetFrame(srcMAC, dstMAC net.HardwareAddr, etherType uint16, payload []byte) []byte {
	frame := make([]byte, 14+len(payload))
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[14:], payload)
	return frame
}

// Bridge provides Layer 2 bridging functionality.
type Bridge struct {
	interfaces map[string]*water.Interface
	mu         sync.RWMutex
}

// NewBridge creates a new bridge.
func NewBridge() *Bridge {
	return &Bridge{
		interfaces: make(map[string]*water.Interface),
	}
}

// AddInterface adds a tap interface to the bridge.
func (b *Bridge) AddInterface(name string, iface *water.Interface) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.interfaces[name] = iface
}

// RemoveInterface removes a tap interface from the bridge.
func (b *Bridge) RemoveInterface(name string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if iface, ok := b.interfaces[name]; ok {
		_ = iface.Close()
		delete(b.interfaces, name)
	}
}

// Forward forwards packets between interfaces.
func (b *Bridge) Forward(exclude string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for name, iface := range b.interfaces {
		if name == exclude {
			continue
		}

		go func(i *water.Interface) {
			buf := make([]byte, 1500)
			for {
				n, err := i.Read(buf)
				if err != nil {
					return
				}

				// Forward to all other interfaces
				b.mu.RLock()
				for otherName, otherIface := range b.interfaces {
					if otherName != name {
						_, _ = otherIface.Write(buf[:n])
					}
				}
				b.mu.RUnlock()
			}
		}(iface)
	}

	return nil
}

// Stats provides tap tunnel statistics.
type Stats struct {
	PacketsReceived uint64
	PacketsSent     uint64
	BytesReceived   uint64
	BytesSent       uint64
	Errors          uint64
}

// TapStatsCollector collects statistics for a tap interface.
type TapStatsCollector struct {
	stats Stats
	mu    sync.RWMutex
}

// NewTapStatsCollector creates a new stats collector.
func NewTapStatsCollector() *TapStatsCollector {
	return &TapStatsCollector{}
}

// RecordReceived records a received packet.
func (sc *TapStatsCollector) RecordReceived(bytes int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stats.PacketsReceived++
	sc.stats.BytesReceived += uint64(bytes)
}

// RecordSent records a sent packet.
func (sc *TapStatsCollector) RecordSent(bytes int) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stats.PacketsSent++
	sc.stats.BytesSent += uint64(bytes)
}

// RecordError records an error.
func (sc *TapStatsCollector) RecordError() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stats.Errors++
}

// GetStats returns the current stats.
func (sc *TapStatsCollector) GetStats() Stats {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.stats
}

// Reset resets the stats.
func (sc *TapStatsCollector) Reset() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.stats = Stats{}
}

// Common Ethernet types
const (
	EthernetTypeIPv4 = 0x0800
	EthernetTypeARP  = 0x0806
	EthernetTypeIPv6 = 0x86DD
	EthernetTypeVLAN = 0x8100
)

// IsIPv4 checks if an Ethernet frame contains IPv4.
func IsIPv4(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	return binary.BigEndian.Uint16(frame[12:14]) == EthernetTypeIPv4
}

// IsIPv6 checks if an Ethernet frame contains IPv6.
func IsIPv6(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	return binary.BigEndian.Uint16(frame[12:14]) == EthernetTypeIPv6
}

// IsARP checks if an Ethernet frame contains ARP.
func IsARP(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	return binary.BigEndian.Uint16(frame[12:14]) == EthernetTypeARP
}

// ExtractMAC extracts source and destination MAC from an Ethernet frame.
func ExtractMAC(frame []byte) (src, dst net.HardwareAddr, err error) {
	if len(frame) < 12 {
		return nil, nil, fmt.Errorf("frame too short")
	}
	dst = make(net.HardwareAddr, 6)
	copy(dst, frame[0:6])
	src = make(net.HardwareAddr, 6)
	copy(src, frame[6:12])
	return src, dst, nil
}
