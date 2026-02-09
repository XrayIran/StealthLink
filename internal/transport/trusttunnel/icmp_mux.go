//go:build ignore

package trusttunnel

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ICMPMuxConfig configures ICMP multiplexing
type ICMPMuxConfig struct {
	Enabled           bool
	EchoInterval      time.Duration
	ConnectionTimeout time.Duration
	MaxConnections    int
	ICMPID            uint16
}

// DefaultICMPCmuxConfig returns default ICMP multiplexing configuration
func DefaultICMPCmuxConfig() *ICMPMuxConfig {
	return &ICMPMuxConfig{
		Enabled:           false,
		EchoInterval:      5 * time.Second,
		ConnectionTimeout: 60 * time.Second,
		MaxConnections:    100,
		ICMPID:            0, // Auto-assign
	}
}

// ICMPMux implements ICMP tunneling with multiplexing support.
// It allows multiple logical connections over a single ICMP tunnel.
type ICMPMux struct {
	config *ICMPMuxConfig

	// Underlying ICMP connection
	icmpConn *net.IPConn
	connMu   sync.RWMutex

	// Connection management
	sessions    map[uint32]*ICMPSession
	sessionMu   sync.RWMutex
	nextSession atomic.Uint32

	// ICMP ID for echo requests
	icmpID atomic.Uint32

	// Sequence number management
	sequenceNum atomic.Uint32

	// Background tasks
	stopCh chan struct{}
	wg     sync.WaitGroup

	// Obfuscation
	obfuscate bool
	obfKey    []byte
}

// ICMPSession represents a multiplexed session over ICMP
type ICMPSession struct {
	ID       uint32
	localAddr  net.Addr
	remoteAddr net.Addr
	CreatedAt  time.Time
	LastActive time.Time

	// Data channels
	readCh  chan []byte
	writeCh chan []byte
	closeCh chan struct{}
	closed  atomic.Bool

	// Statistics
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	mux *ICMPMux
}

// NewICMPMux creates a new ICMP multiplexer
func NewICMPMux(config *ICMPMuxConfig) (*ICMPMux, error) {
	if config == nil {
		config = DefaultICMPCmuxConfig()
	}

	mux := &ICMPMux{
		config:   config,
		sessions: make(map[uint32]*ICMPSession),
		stopCh:   make(chan struct{}),
	}

	if config.ICMPID == 0 {
		// Generate random ICMP ID
		mux.icmpID.Store(uint16(time.Now().UnixNano() & 0xFFFF))
	} else {
		mux.icmpID.Store(config.ICMPID)
	}

	return mux, nil
}

// Listen starts listening for ICMP packets
func (m *ICMPMux) Listen(localAddr string) error {
	if !m.config.Enabled {
		return fmt.Errorf("ICMP multiplexing is not enabled")
	}

	// Open ICMP connection
	addr, err := net.ResolveIPAddr("ip4:icmp", localAddr)
	if err != nil {
		return fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenIP("ip4:icmp", addr)
	if err != nil {
		return fmt.Errorf("listen ICMP: %w", err)
	}

	m.connMu.Lock()
	m.icmpConn = conn
	m.connMu.Unlock()

	// Start receiver
	m.wg.Add(1)
	go m.receiver()

	// Start keepalive
	if m.config.EchoInterval > 0 {
		m.wg.Add(1)
		go m.keepaliveLoop()
	}

	// Start session cleaner
	m.wg.Add(1)
	go m.sessionCleaner()

	return nil
}

// Dial creates a new ICMP session to a remote host
func (m *ICMPMux) Dial(ctx context.Context, remoteAddr string) (*ICMPSession, error) {
	if !m.config.Enabled {
		return nil, fmt.Errorf("ICMP multiplexing is not enabled")
	}

	// Ensure we have a connection
	m.connMu.RLock()
	conn := m.icmpConn
	m.connMu.RUnlock()

	if conn == nil {
		// Open local ICMP socket
		if err := m.Listen("0.0.0.0"); err != nil {
			return nil, err
		}
	}

	// Resolve remote address
	raddr, err := net.ResolveIPAddr("ip4", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve remote address: %w", err)
	}

	// Create session
	session := m.createSession(raddr)

	// Send initial echo request
	if err := m.sendEchoRequest(session); err != nil {
		m.removeSession(session.ID)
		return nil, fmt.Errorf("send echo request: %w", err)
	}

	return session, nil
}

// createSession creates a new ICMP session
func (m *ICMPMux) createSession(remoteAddr net.Addr) *ICMPSession {
	session := &ICMPSession{
		ID:         m.nextSession.Add(1),
		RemoteAddr: remoteAddr,
		CreatedAt:  time.Now(),
		LastActive: time.Now(),
		readCh:     make(chan []byte, 32),
		writeCh:    make(chan []byte, 32),
		closeCh:    make(chan struct{}),
		mux:        m,
	}

	m.sessionMu.Lock()
	m.sessions[session.ID] = session
	m.sessionMu.Unlock()

	return session
}

// removeSession removes a session
func (m *ICMPMux) removeSession(id uint32) {
	m.sessionMu.Lock()
	session, ok := m.sessions[id]
	if ok {
		delete(m.sessions, id)
	}
	m.sessionMu.Unlock()

	if ok {
		session.Close()
	}
}

// GetSession retrieves a session by ID
func (m *ICMPMux) GetSession(id uint32) (*ICMPSession, bool) {
	m.sessionMu.RLock()
	defer m.sessionMu.RUnlock()
	session, ok := m.sessions[id]
	return session, ok
}

// receiver receives and processes ICMP packets
func (m *ICMPMux) receiver() {
	defer m.wg.Done()

	buf := make([]byte, 65536)
	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		m.connMu.RLock()
		conn := m.icmpConn
		m.connMu.RUnlock()

		if conn == nil {
			return
		}

		conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				continue
			}
			return
		}

		// Process packet
		m.processPacket(buf[:n], addr)
	}
}

// processPacket processes a received ICMP packet
func (m *ICMPMux) processPacket(data []byte, addr net.Addr) {
	if len(data) < 8 {
		return
	}

	// Parse ICMP header
	icmpType := data[0]
	icmpCode := data[1]
	checksum := binary.BigEndian.Uint16(data[2:4])
	id := binary.BigEndian.Uint16(data[4:6])
	seq := binary.BigEndian.Uint16(data[6:8])

	_ = checksum
	_ = seq

	// Check if this is our ICMP ID
	if id != m.icmpID.Load() {
		return
	}

	switch icmpType {
	case 0: // Echo Reply
		m.handleEchoReply(data[8:], addr)
	case 8: // Echo Request
		m.handleEchoRequest(data[8:], addr)
	case 13: // Timestamp Request
		m.handleTimestampRequest(data, addr)
	default:
		// Check for encapsulated data
		if icmpCode == 0 && len(data) > 8 {
			m.handleDataPacket(data[8:], addr)
		}
	}
}

// handleEchoReply handles ICMP echo reply
func (m *ICMPMux) handleEchoReply(payload []byte, addr net.Addr) {
	if len(payload) < 4 {
		return
	}

	// Extract session ID from payload
	sessionID := binary.BigEndian.Uint32(payload[:4])
	data := payload[4:]

	// Find session
	session, ok := m.GetSession(sessionID)
	if !ok {
		return
	}

	session.LastActive = time.Now()

	// Send to session
	select {
	case session.readCh <- data:
		session.bytesIn.Add(uint64(len(data)))
	default:
	}
}

// handleEchoRequest handles ICMP echo request
func (m *ICMPMux) handleEchoRequest(payload []byte, addr net.Addr) {
	// Send echo reply
	m.sendEchoReply(payload, addr)
}

// handleTimestampRequest handles ICMP timestamp request
func (m *ICMPMux) handleTimestampRequest(data []byte, addr net.Addr) {
	// Send timestamp reply
	reply := make([]byte, len(data))
	copy(reply, data)
	reply[0] = 14 // Timestamp Reply

	// Set originate timestamp
	now := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(reply[8:12], now)
	binary.BigEndian.PutUint32(reply[12:16], now)
	binary.BigEndian.PutUint32(reply[16:20], now)

	m.connMu.RLock()
	conn := m.icmpConn
	m.connMu.RUnlock()

	if conn != nil {
		conn.WriteTo(reply, addr)
	}
}

// handleDataPacket handles encapsulated data
func (m *ICMPMux) handleDataPacket(data []byte, addr net.Addr) {
	if len(data) < 4 {
		return
	}

	sessionID := binary.BigEndian.Uint32(data[:4])
	payload := data[4:]

	session, ok := m.GetSession(sessionID)
	if !ok {
		return
	}

	session.LastActive = time.Now()

	select {
	case session.readCh <- payload:
		session.bytesIn.Add(uint64(len(payload)))
	default:
	}
}

// sendEchoRequest sends an ICMP echo request
func (m *ICMPMux) sendEchoRequest(session *ICMPSession) error {
	m.connMu.RLock()
	conn := m.icmpConn
	m.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no ICMP connection")
	}

	// Build echo request with session ID in payload
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, session.ID)

	pkt := m.buildICMPPacket(8, 0, payload)

	_, err := conn.WriteTo(pkt, session.RemoteAddr)
	if err == nil {
		session.bytesOut.Add(uint64(len(pkt)))
	}

	return err
}

// sendEchoReply sends an ICMP echo reply
func (m *ICMPMux) sendEchoReply(payload []byte, addr net.Addr) error {
	m.connMu.RLock()
	conn := m.icmpConn
	m.connMu.RUnlock()

	if conn == nil {
		return fmt.Errorf("no ICMP connection")
	}

	pkt := m.buildICMPPacket(0, 0, payload)

	_, err := conn.WriteTo(pkt, addr)
	return err
}

// buildICMPPacket builds an ICMP packet
func (m *ICMPMux) buildICMPPacket(icmpType, icmpCode byte, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	pkt[0] = icmpType
	pkt[1] = icmpCode
	// Checksum (2-3) - will be calculated by kernel
	binary.BigEndian.PutUint16(pkt[4:6], m.icmpID.Load())
	binary.BigEndian.PutUint16(pkt[6:8], m.sequenceNum.Add(1))
	copy(pkt[8:], payload)

	return pkt
}

// keepaliveLoop sends periodic keepalive echo requests
func (m *ICMPMux) keepaliveLoop() {
	defer m.wg.Done()

	ticker := time.NewTicker(m.config.EchoInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sendKeepalives()
		}
	}
}

// sendKeepalives sends keepalive to all sessions
func (m *ICMPMux) sendKeepalives() {
	m.sessionMu.RLock()
	sessions := make([]*ICMPSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.sessionMu.RUnlock()

	for _, session := range sessions {
		if !session.closed.Load() {
			m.sendEchoRequest(session)
		}
	}
}

// sessionCleaner removes expired sessions
func (m *ICMPMux) sessionCleaner() {
	defer m.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.cleanExpiredSessions()
		}
	}
}

// cleanExpiredSessions removes expired sessions
func (m *ICMPMux) cleanExpiredSessions() {
	m.sessionMu.Lock()
	defer m.sessionMu.Unlock()

	now := time.Now()
	for id, session := range m.sessions {
		if now.Sub(session.LastActive) > m.config.ConnectionTimeout {
			delete(m.sessions, id)
			go session.Close()
		}
	}
}

// Close closes the ICMP multiplexer
func (m *ICMPMux) Close() error {
	close(m.stopCh)

	// Close all sessions
	m.sessionMu.Lock()
	for _, session := range m.sessions {
		go session.Close()
	}
	m.sessions = make(map[uint32]*ICMPSession)
	m.sessionMu.Unlock()

	// Wait for goroutines
	m.wg.Wait()

	// Close connection
	m.connMu.Lock()
	if m.icmpConn != nil {
		m.icmpConn.Close()
	}
	m.connMu.Unlock()

	return nil
}

// ICMPSession methods

// Read reads data from the session
func (s *ICMPSession) Read(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("session closed")
	}

	select {
	case data := <-s.readCh:
		n := copy(p, data)
		return n, nil
	case <-s.closeCh:
		return 0, fmt.Errorf("session closed")
	}
}

// Write writes data to the session
func (s *ICMPSession) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("session closed")
	}

	// Build packet with session ID
	payload := make([]byte, 4+len(p))
	binary.BigEndian.PutUint32(payload, s.ID)
	copy(payload[4:], p)

	// Send via ICMP echo request
	err := s.mux.sendEchoRequest(s)
	if err != nil {
		return 0, err
	}

	s.bytesOut.Add(uint64(len(p)))
	return len(p), nil
}

// Close closes the session
func (s *ICMPSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(s.closeCh)
	s.mux.removeSession(s.ID)

	return nil
}

// LocalAddr returns the local address
func (s *ICMPSession) LocalAddr() net.Addr {
	return s.localAddr
}

// RemoteAddr returns the remote address
func (s *ICMPSession) RemoteAddr() net.Addr {
	return s.remoteAddr
}

// SetDeadline sets the deadline
func (s *ICMPSession) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the read deadline
func (s *ICMPSession) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline
func (s *ICMPSession) SetWriteDeadline(t time.Time) error {
	return nil
}

// Ensure ICMPSession implements net.Conn
var _ net.Conn = (*ICMPSession)(nil)

// GetStats returns session statistics
func (s *ICMPSession) GetStats() ICMPStats {
	return ICMPStats{
		ID:       s.ID,
		BytesIn:  s.bytesIn.Load(),
		BytesOut: s.bytesOut.Load(),
		Duration: time.Since(s.CreatedAt),
	}
}

// ICMPStats contains ICMP session statistics
type ICMPStats struct {
	ID       uint32
	BytesIn  uint64
	BytesOut uint64
	Duration time.Duration
}
