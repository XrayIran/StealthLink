// Package faketcp implements a NAT-friendly fake TCP over UDP.
// It simulates a full TCP state machine in userspace while using
// UDP as the underlying transport, making it appear like normal
// TCP flows to middleboxes while remaining userspace controlled.
package faketcp

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"

	"github.com/xtaci/smux"
)

// Packet types for fake TCP.
const (
	PacketTypeSYN       = 0x01
	PacketTypeSYNACK    = 0x02
	PacketTypeACK       = 0x03
	PacketTypeData      = 0x04
	PacketTypeFIN       = 0x05
	PacketTypeRST       = 0x06
	PacketTypeKeepalive = 0x07
)

// Header size for fake TCP packets.
const HeaderSize = 24

// Config holds fake TCP configuration.
type Config struct {
	MTU           int           // Maximum transmission unit
	WindowSize    int           // TCP window size
	RTO           time.Duration // Retransmission timeout
	Keepalive     time.Duration // Keepalive interval
	KeepaliveIdle time.Duration // Idle time before keepalive
}

// DefaultConfig returns a default configuration.
func DefaultConfig() *Config {
	return &Config{
		MTU:           1400,
		WindowSize:    65535,
		RTO:           200 * time.Millisecond,
		Keepalive:     30 * time.Second,
		KeepaliveIdle: 60 * time.Second,
	}
}

// Dialer implements transport.Dialer for fake TCP.
type Dialer struct {
	Config *Config
	Smux   *smux.Config
	Guard  string
}

// Listener implements transport.Listener for fake TCP.
type Listener struct {
	conn      *net.UDPConn
	config    *Config
	smux      *smux.Config
	guard     string
	sessions  sync.Map // map[string]*fakeSession
	acceptCh  chan *fakeSession
	closeCh   chan struct{}
	closeOnce sync.Once
}

// NewDialer creates a new fake TCP dialer.
func NewDialer(cfg *Config, smuxCfg *smux.Config, guard string) *Dialer {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if smuxCfg == nil {
		smuxCfg = smux.DefaultConfig()
	}
	return &Dialer{
		Config: cfg,
		Smux:   smuxCfg,
		Guard:  guard,
	}
}

// Listen creates a fake TCP listener.
func Listen(addr string, cfg *Config, smuxCfg *smux.Config, guard string) (*Listener, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if smuxCfg == nil {
		smuxCfg = smux.DefaultConfig()
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	l := &Listener{
		conn:     conn,
		config:   cfg,
		smux:     smuxCfg,
		guard:    guard,
		acceptCh: make(chan *fakeSession, 128),
		closeCh:  make(chan struct{}),
	}

	// Start the accept loop
	go l.acceptLoop()

	return l, nil
}

// acceptLoop handles incoming packets.
func (l *Listener) acceptLoop() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}

		if n < HeaderSize {
			continue // Too small
		}

		// Parse header
		pkt := parsePacket(buf[:n])
		if pkt == nil {
			continue
		}

		// Find or create session
		sessionKey := addr.String()
		if val, ok := l.sessions.Load(sessionKey); ok {
			session := val.(*fakeSession)
			session.handlePacket(pkt)
		} else if pkt.Type == PacketTypeSYN {
			// New connection
			session := l.newSession(addr)
			session.handlePacket(pkt)
		}
	}
}

// newSession creates a new fake TCP session.
func (l *Listener) newSession(addr *net.UDPAddr) *fakeSession {
	s := &fakeSession{
		listener: l,
		remote:   addr,
		state:    StateListen,
		window:   newWindow(l.config.WindowSize),
		config:   l.config,
		readCh:   make(chan *packet, 256),
		writeCh:  make(chan []byte, 256),
		closeCh:  make(chan struct{}),
		readyCh:  make(chan struct{}, 1),
	}
	l.sessions.Store(addr.String(), s)
	return s
}

// Accept accepts a new fake TCP connection.
func (l *Listener) Accept() (transport.Session, error) {
	select {
	case session := <-l.acceptCh:
		if l.guard != "" {
			guard := make([]byte, len(l.guard))
			if _, err := io.ReadFull(session, guard); err != nil {
				_ = session.Close()
				return nil, fmt.Errorf("read guard: %w", err)
			}
			expected := []byte(l.guard)
			if len(guard) != len(expected) || subtle.ConstantTimeCompare(guard, expected) != 1 {
				_ = session.Close()
				return nil, fmt.Errorf("invalid guard token")
			}
		}

		smuxSession, err := smux.Server(session, l.smux)
		if err != nil {
			_ = session.Close()
			return nil, fmt.Errorf("smux: %w", err)
		}

		return &sessionWrapper{
			session: session,
			smux:    smuxSession,
		}, nil
	case <-l.closeCh:
		return nil, fmt.Errorf("listener closed")
	}
}

// Close closes the listener.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closeCh)
	})
	return l.conn.Close()
}

// Addr returns the listener address.
func (l *Listener) Addr() net.Addr {
	return l.conn.LocalAddr()
}

// Dial connects to a fake TCP server.
func (d *Dialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("dial UDP: %w", err)
	}

	// Create session
	session := &fakeSession{
		conn:    conn,
		config:  d.Config,
		state:   StateClosed,
		window:  newWindow(d.Config.WindowSize),
		readCh:  make(chan *packet, 256),
		writeCh: make(chan []byte, 256),
		closeCh: make(chan struct{}),
		readyCh: make(chan struct{}, 1),
	}

	// Perform handshake
	if err := session.connect(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}

	// Send guard token
	if d.Guard != "" {
		if _, err := session.Write([]byte(d.Guard)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("send guard: %w", err)
		}
	}

	// Start smux
	smuxSession, err := smux.Client(session, d.Smux)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smux: %w", err)
	}

	return &sessionWrapper{
		session: session,
		smux:    smuxSession,
	}, nil
}

// fakeSession represents a fake TCP session.
type fakeSession struct {
	listener *Listener
	conn     *net.UDPConn
	remote   *net.UDPAddr
	state    State
	window   *window
	config   *Config

	// Sequence numbers
	sndUna uint32 // Send unacknowledged
	sndNxt uint32 // Send next
	rcvNxt uint32 // Receive next

	// Channels
	readCh    chan *packet
	writeCh   chan []byte
	closeCh   chan struct{}
	readyCh   chan struct{}
	closeOnce sync.Once
	readBuf   []byte

	// Guards
	mu sync.RWMutex
}

// connect performs the client-side handshake.
func (s *fakeSession) connect() error {
	s.mu.Lock()
	s.state = StateSynSent
	s.mu.Unlock()

	s.startClientReceiveLoop()

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		synSeq := atomic.LoadUint32(&s.sndNxt)
		syn := &packet{
			Type: PacketTypeSYN,
			Seq:  synSeq,
		}
		if err := s.sendPacket(syn); err != nil {
			return err
		}
		atomic.CompareAndSwapUint32(&s.sndNxt, synSeq, synSeq+1)

		select {
		case <-s.readyCh:
			return nil
		case <-time.After(s.config.RTO):
		case <-s.closeCh:
			return fmt.Errorf("connection closed")
		}
	}

	return fmt.Errorf("handshake timeout after %d attempts", maxRetries)
}

func (s *fakeSession) startClientReceiveLoop() {
	if s.conn == nil {
		return
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-s.closeCh:
				return
			default:
			}

			_ = s.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, err := s.conn.Read(buf)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				s.handleRST(nil)
				return
			}
			if n < HeaderSize {
				continue
			}
			pkt := parsePacket(buf[:n])
			if pkt == nil {
				continue
			}
			s.handlePacket(pkt)
		}
	}()
}

// handlePacket processes an incoming packet.
func (s *fakeSession) handlePacket(pkt *packet) {
	switch pkt.Type {
	case PacketTypeSYN:
		s.handleSYN(pkt)
	case PacketTypeSYNACK:
		s.handleSYNACK(pkt)
	case PacketTypeACK:
		s.handleACK(pkt)
	case PacketTypeData:
		s.handleData(pkt)
	case PacketTypeFIN:
		s.handleFIN(pkt)
	case PacketTypeRST:
		s.handleRST(pkt)
	case PacketTypeKeepalive:
		// Just update activity timestamp
	}
}

func (s *fakeSession) handleSYN(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateListen {
		return
	}

	// Initialize receive sequence
	s.rcvNxt = pkt.Seq + 1

	// Send SYN-ACK
	synack := &packet{
		Type: PacketTypeSYNACK,
		Seq:  s.sndNxt,
		Ack:  s.rcvNxt,
	}
	_ = s.sendPacket(synack)
	s.sndNxt++

	s.state = StateSynReceived
}

func (s *fakeSession) handleSYNACK(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StateSynSent {
		return
	}

	// Update sequence numbers
	s.sndUna = pkt.Ack
	s.rcvNxt = pkt.Seq + 1

	// Send ACK
	ack := &packet{
		Type: PacketTypeACK,
		Seq:  s.sndNxt,
		Ack:  s.rcvNxt,
	}
	_ = s.sendPacket(ack)

	s.state = StateEstablished
	select {
	case s.readyCh <- struct{}{}:
	default:
	}
}

func (s *fakeSession) handleACK(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update send window
	if pkt.Ack > s.sndUna {
		s.sndUna = pkt.Ack
	}

	if s.state == StateSynReceived {
		s.state = StateEstablished
		select {
		case s.readyCh <- struct{}{}:
		default:
		}
		if s.listener != nil {
			select {
			case s.listener.acceptCh <- s:
			default:
			}
		}
	}
}

func (s *fakeSession) handleData(pkt *packet) {
	s.mu.Lock()

	if s.state != StateEstablished {
		s.mu.Unlock()
		return
	}

	// Check sequence number
	if pkt.Seq != s.rcvNxt {
		// Out of order - queue or drop
		s.mu.Unlock()
		return
	}

	// Update receive sequence
	s.rcvNxt += uint32(len(pkt.Payload))

	// Send ACK
	ack := &packet{
		Type: PacketTypeACK,
		Seq:  s.sndNxt,
		Ack:  s.rcvNxt,
	}
	payload := make([]byte, len(pkt.Payload))
	copy(payload, pkt.Payload)
	s.mu.Unlock()

	_ = s.sendPacket(ack)
	select {
	case <-s.closeCh:
	case s.readCh <- &packet{Type: PacketTypeData, Payload: payload}:
	}
}

func (s *fakeSession) handleFIN(pkt *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case StateEstablished:
		s.state = StateCloseWait
	case StateFinWait1:
		s.state = StateClosing
	case StateFinWait2:
		s.state = StateTimeWait
	}
}

func (s *fakeSession) handleRST(_ *packet) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.state = StateClosed
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
}

// sendPacket sends a packet.
func (s *fakeSession) sendPacket(pkt *packet) error {
	data := encodePacket(pkt)

	if s.conn != nil {
		_, err := s.conn.Write(data)
		return err
	}

	if s.listener != nil {
		_, err := s.listener.conn.WriteToUDP(data, s.remote)
		return err
	}

	return fmt.Errorf("no connection")
}

// Read implements net.Conn.
func (s *fakeSession) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	if len(s.readBuf) > 0 {
		n = copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	select {
	case <-s.closeCh:
		return 0, io.EOF
	case pkt := <-s.readCh:
		if pkt == nil || len(pkt.Payload) == 0 {
			return 0, nil
		}
		n = copy(p, pkt.Payload)
		if n < len(pkt.Payload) {
			s.mu.Lock()
			s.readBuf = append(s.readBuf[:0], pkt.Payload[n:]...)
			s.mu.Unlock()
		}
		return n, nil
	}
}

// Write implements net.Conn.
func (s *fakeSession) Write(p []byte) (n int, err error) {
	s.mu.RLock()
	if s.state != StateEstablished {
		s.mu.RUnlock()
		return 0, fmt.Errorf("connection not established")
	}
	s.mu.RUnlock()

	// Send data packet
	pkt := &packet{
		Type:    PacketTypeData,
		Seq:     atomic.AddUint32(&s.sndNxt, uint32(len(p))) - uint32(len(p)),
		Payload: p,
	}

	if err := s.sendPacket(pkt); err != nil {
		return 0, err
	}

	return len(p), nil
}

// Close implements net.Conn.
func (s *fakeSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch s.state {
	case StateEstablished:
		s.state = StateFinWait1
		fin := &packet{
			Type: PacketTypeFIN,
			Seq:  s.sndNxt,
		}
		_ = s.sendPacket(fin)
	case StateCloseWait:
		s.state = StateLastAck
		fin := &packet{
			Type: PacketTypeFIN,
			Seq:  s.sndNxt,
		}
		_ = s.sendPacket(fin)
	}

	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// LocalAddr implements net.Conn.
func (s *fakeSession) LocalAddr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return s.listener.conn.LocalAddr()
}

// RemoteAddr implements net.Conn.
func (s *fakeSession) RemoteAddr() net.Addr {
	if s.remote != nil {
		return s.remote
	}
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return nil
}

// SetDeadline implements net.Conn.
func (s *fakeSession) SetDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetDeadline(t)
	}
	return nil
}

// SetReadDeadline implements net.Conn.
func (s *fakeSession) SetReadDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetReadDeadline(t)
	}
	return nil
}

// SetWriteDeadline implements net.Conn.
func (s *fakeSession) SetWriteDeadline(t time.Time) error {
	if s.conn != nil {
		return s.conn.SetWriteDeadline(t)
	}
	return nil
}

// packet represents a fake TCP packet.
type packet struct {
	Type    uint8
	Flags   uint8
	Seq     uint32
	Ack     uint32
	Window  uint16
	Payload []byte
}

// parsePacket parses a packet from bytes.
func parsePacket(data []byte) *packet {
	if len(data) < HeaderSize {
		return nil
	}

	pkt := &packet{
		Type:   data[0],
		Flags:  data[1],
		Seq:    binary.BigEndian.Uint32(data[2:6]),
		Ack:    binary.BigEndian.Uint32(data[6:10]),
		Window: binary.BigEndian.Uint16(data[10:12]),
	}

	if len(data) > HeaderSize {
		pkt.Payload = data[HeaderSize:]
	}

	return pkt
}

// encodePacket encodes a packet to bytes.
func encodePacket(pkt *packet) []byte {
	data := make([]byte, HeaderSize+len(pkt.Payload))
	data[0] = pkt.Type
	data[1] = pkt.Flags
	binary.BigEndian.PutUint32(data[2:6], pkt.Seq)
	binary.BigEndian.PutUint32(data[6:10], pkt.Ack)
	binary.BigEndian.PutUint16(data[10:12], pkt.Window)
	// 12-23 reserved for future use
	copy(data[HeaderSize:], pkt.Payload)
	return data
}

// sessionWrapper wraps a fakeSession for transport.Session.
type sessionWrapper struct {
	session *fakeSession
	smux    *smux.Session
}

func (w *sessionWrapper) OpenStream() (net.Conn, error) {
	return w.smux.OpenStream()
}

func (w *sessionWrapper) AcceptStream() (net.Conn, error) {
	return w.smux.AcceptStream()
}

func (w *sessionWrapper) Close() error {
	if w.smux != nil {
		_ = w.smux.Close()
	}
	return w.session.Close()
}

func (w *sessionWrapper) LocalAddr() net.Addr  { return w.session.LocalAddr() }
func (w *sessionWrapper) RemoteAddr() net.Addr { return w.session.RemoteAddr() }
