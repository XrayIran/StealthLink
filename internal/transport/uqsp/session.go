package uqsp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"

	quic "github.com/quic-go/quic-go"
	"github.com/xtaci/smux"
)

var (
	// ErrSessionClosed is returned when the session is closed
	ErrSessionClosed = errors.New("session closed")

	// ErrStreamLimitExceeded is returned when stream limit is exceeded
	ErrStreamLimitExceeded = errors.New("stream limit exceeded")

	// ErrUDPSessionNotFound is returned when UDP session is not found
	ErrUDPSessionNotFound = errors.New("UDP session not found")

	// ErrInvalidSessionID is returned when session ID is invalid
	ErrInvalidSessionID = errors.New("invalid session ID")
)

// SessionManager manages UQSP sessions including streams and UDP associations
type SessionManager struct {
	// QUIC connection
	conn *quic.Conn

	// smux session for stream multiplexing
	smuxSess *smux.Session

	// Configuration
	config *Config

	// UDP session registry
	udpSessions   map[uint32]*udpSession
	udpSessionMu  sync.RWMutex
	nextSessionID uint32

	// Control stream for session management
	controlStream *controlStreamHandler

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	// Metrics callback
	onStreamOpened    func()
	onStreamClosed    func()
	onUDPSessionOpen  func()
	onUDPSessionClose func()
}

// Config holds UQSP session configuration
type Config struct {
	// Stream configuration
	MaxConcurrentStreams  int
	FlowControlWindow     int
	MaxIncomingStreams    int64
	MaxIncomingUniStreams int64

	// Datagram configuration
	MaxDatagramSize      int
	EnableFragmentation  bool
	MaxIncomingDatagrams int

	// Timeouts
	HandshakeTimeout time.Duration
	MaxIdleTimeout   time.Duration
	KeepAlivePeriod  time.Duration

	// Capabilities
	Capabilities CapabilityFlag
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		MaxConcurrentStreams:  100,
		FlowControlWindow:     1048576,
		MaxIncomingStreams:    1024,
		MaxIncomingUniStreams: 128,
		MaxDatagramSize:       1350,
		EnableFragmentation:   true,
		MaxIncomingDatagrams:  1024,
		HandshakeTimeout:      DefaultHandshakeTimeout,
		MaxIdleTimeout:        DefaultMaxIdleTimeout,
		KeepAlivePeriod:       DefaultKeepAlivePeriod,
		Capabilities:          CapabilityDatagram | CapabilityCapsule | Capability0RTT,
	}
}

// udpSession represents a UDP relay session
type udpSession struct {
	id         uint32
	targetAddr *net.UDPAddr
	contextID  uint64
	createdAt  time.Time
	lastActive time.Time

	// Datagram queue
	datagramCh chan *UDPDatagram

	// Close callback
	onClose func()
}

// UDPDatagram represents a UDP datagram with metadata
type UDPDatagram struct {
	SessionID  uint32
	ContextID  uint64
	Data       []byte
	TargetAddr *net.UDPAddr
}

// NewSessionManager creates a new UQSP session manager
func NewSessionManager(conn *quic.Conn, smuxSess *smux.Session, config *Config) *SessionManager {
	ctx, cancel := context.WithCancel(context.Background())

	if config == nil {
		config = DefaultConfig()
	}

	sm := &SessionManager{
		conn:          conn,
		smuxSess:      smuxSess,
		config:        config,
		udpSessions:   make(map[uint32]*udpSession),
		nextSessionID: 1,
		ctx:           ctx,
		cancel:        cancel,
	}

	return sm
}

// Start starts the session manager goroutines
func (sm *SessionManager) Start() error {
	// Start control stream handler
	cs, err := sm.acceptOrOpenControlStream()
	if err != nil {
		return fmt.Errorf("control stream: %w", err)
	}
	sm.controlStream = cs

	// Control frames are required for UDP session lifecycle, and also act as a
	// fallback datagram carrier when native QUIC datagrams aren't available.
	go sm.controlReadLoop()

	// Native QUIC datagrams, if negotiated.
	if sm.config != nil && sm.config.Capabilities.Has(CapabilityDatagram) {
		go sm.datagramReadLoop()
	}

	// Start keepalive
	go sm.keepaliveLoop()

	// Start scavenger for UDP sessions
	go sm.scavengerLoop()

	return nil
}

// Close closes the session manager
func (sm *SessionManager) Close() error {
	if !sm.closed.CompareAndSwap(false, true) {
		return nil
	}

	sm.cancel()

	// Close all UDP sessions
	sm.udpSessionMu.Lock()
	for _, sess := range sm.udpSessions {
		sm.closeUDPSessionLocked(sess)
	}
	sm.udpSessions = make(map[uint32]*udpSession)
	sm.udpSessionMu.Unlock()

	// Close control stream
	if sm.controlStream != nil {
		sm.controlStream.Close()
	}

	// Close smux session
	if sm.smuxSess != nil {
		_ = sm.smuxSess.Close()
	}

	// Close QUIC connection
	if sm.conn != nil {
		return sm.conn.CloseWithError(0, "session closed")
	}

	return nil
}

// OpenStream opens a new stream
func (sm *SessionManager) OpenStream() (net.Conn, error) {
	if sm.closed.Load() {
		return nil, ErrSessionClosed
	}

	conn, err := sm.smuxSess.OpenStream()
	if err != nil {
		return nil, err
	}

	if sm.onStreamOpened != nil {
		sm.onStreamOpened()
	}

	return &streamWrapper{
		Stream: conn,
		onClose: func() {
			if sm.onStreamClosed != nil {
				sm.onStreamClosed()
			}
		},
	}, nil
}

// AcceptStream accepts a new stream
func (sm *SessionManager) AcceptStream() (net.Conn, error) {
	if sm.closed.Load() {
		return nil, ErrSessionClosed
	}

	conn, err := sm.smuxSess.AcceptStream()
	if err != nil {
		return nil, err
	}

	if sm.onStreamOpened != nil {
		sm.onStreamOpened()
	}

	return &streamWrapper{
		Stream: conn,
		onClose: func() {
			if sm.onStreamClosed != nil {
				sm.onStreamClosed()
			}
		},
	}, nil
}

// OpenUDPSession opens a new UDP relay session
func (sm *SessionManager) OpenUDPSession(targetAddr string) (uint32, error) {
	if sm.closed.Load() {
		return 0, ErrSessionClosed
	}

	addr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return 0, fmt.Errorf("resolve UDP addr: %w", err)
	}

	sm.udpSessionMu.Lock()
	defer sm.udpSessionMu.Unlock()

	// Check limit
	if len(sm.udpSessions) >= sm.config.MaxConcurrentStreams {
		return 0, ErrStreamLimitExceeded
	}

	// Allocate session ID
	sessionID := sm.nextSessionID
	sm.nextSessionID++

	// Create session
	sess := &udpSession{
		id:         sessionID,
		targetAddr: addr,
		createdAt:  time.Now(),
		lastActive: time.Now(),
		datagramCh: make(chan *UDPDatagram, sm.config.MaxIncomingDatagrams),
		onClose: func() {
			if sm.onUDPSessionClose != nil {
				sm.onUDPSessionClose()
			}
		},
	}

	sm.udpSessions[sessionID] = sess

	// Send control message to peer
	if sm.controlStream != nil {
		info := &UDPSessionInfo{
			SessionID:  sessionID,
			TargetAddr: targetAddr,
		}
		payload := &ControlPayload{
			ControlType: ControlTypeOpenUDPSession,
			Data:        info.Encode(),
		}
		if err := sm.controlStream.SendControl(payload); err != nil {
			delete(sm.udpSessions, sessionID)
			return 0, fmt.Errorf("send control: %w", err)
		}
	}

	if sm.onUDPSessionOpen != nil {
		sm.onUDPSessionOpen()
	}

	return sessionID, nil
}

// CloseUDPSession closes a UDP session
func (sm *SessionManager) CloseUDPSession(sessionID uint32) error {
	sm.udpSessionMu.Lock()
	defer sm.udpSessionMu.Unlock()

	sess, ok := sm.udpSessions[sessionID]
	if !ok {
		return ErrUDPSessionNotFound
	}

	sm.closeUDPSessionLocked(sess)

	// Send control message to peer
	if sm.controlStream != nil {
		info := &UDPSessionInfo{SessionID: sessionID}
		payload := &ControlPayload{
			ControlType: ControlTypeCloseUDPSession,
			Data:        info.Encode(),
		}
		_ = sm.controlStream.SendControl(payload)
	}

	return nil
}

// GetUDPSession gets a UDP session by ID
func (sm *SessionManager) GetUDPSession(sessionID uint32) (*udpSession, error) {
	sm.udpSessionMu.RLock()
	defer sm.udpSessionMu.RUnlock()

	sess, ok := sm.udpSessions[sessionID]
	if !ok {
		return nil, ErrUDPSessionNotFound
	}

	return sess, nil
}

// SendDatagram sends a datagram to a UDP session
func (sm *SessionManager) SendDatagram(sessionID uint32, data []byte) error {
	if sm.closed.Load() {
		return ErrSessionClosed
	}

	sess, err := sm.GetUDPSession(sessionID)
	if err != nil {
		return err
	}

	// Update activity
	sess.lastActive = time.Now()

	// Send via QUIC datagram if supported
	if sm.config.Capabilities.Has(CapabilityDatagram) {
		return sm.sendNativeDatagram(sessionID, data)
	}

	// Otherwise send via control stream
	if sm.controlStream != nil {
		return sm.controlStream.SendDatagram(sessionID, data)
	}

	return errors.New("no datagram transport available")
}

// ReceiveDatagram receives a datagram from a UDP session
func (sm *SessionManager) ReceiveDatagram(sessionID uint32) (*UDPDatagram, error) {
	sess, err := sm.GetUDPSession(sessionID)
	if err != nil {
		return nil, err
	}

	select {
	case dg, ok := <-sess.datagramCh:
		if !ok || dg == nil {
			return nil, ErrSessionClosed
		}
		return dg, nil
	case <-sm.ctx.Done():
		return nil, ErrSessionClosed
	}
}

// LocalAddr returns the local address
func (sm *SessionManager) LocalAddr() net.Addr {
	if sm.conn == nil {
		return nil
	}
	return sm.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (sm *SessionManager) RemoteAddr() net.Addr {
	if sm.conn == nil {
		return nil
	}
	return sm.conn.RemoteAddr()
}

// SetMetricsCallbacks sets metrics callbacks
func (sm *SessionManager) SetMetricsCallbacks(
	onStreamOpened func(),
	onStreamClosed func(),
	onUDPSessionOpen func(),
	onUDPSessionClose func(),
) {
	sm.onStreamOpened = onStreamOpened
	sm.onStreamClosed = onStreamClosed
	sm.onUDPSessionOpen = onUDPSessionOpen
	sm.onUDPSessionClose = onUDPSessionClose
}

// Internal methods

func (sm *SessionManager) acceptOrOpenControlStream() (*controlStreamHandler, error) {
	// For server: accept control stream
	// For client: open control stream
	// This is determined by whether we can accept or need to open

	// Try to accept first (server side)
	ctx, cancel := context.WithTimeout(sm.ctx, sm.config.HandshakeTimeout)
	defer cancel()

	stream, err := sm.conn.AcceptStream(ctx)
	if err == nil {
		return newControlStreamHandler(stream, sm), nil
	}

	// Try to open (client side)
	stream, err = sm.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}

	return newControlStreamHandler(stream, sm), nil
}

func (sm *SessionManager) sendNativeDatagram(sessionID uint32, data []byte) error {
	// Encode session ID prefix
	buf := make([]byte, 4+len(data))
	buf[0] = byte(sessionID >> 24)
	buf[1] = byte(sessionID >> 16)
	buf[2] = byte(sessionID >> 8)
	buf[3] = byte(sessionID)
	copy(buf[4:], data)

	return sm.conn.SendDatagram(buf)
}

func (sm *SessionManager) handleDatagram(data []byte) {
	if len(data) < 4 {
		return
	}

	sessionID := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	payload := data[4:]

	sm.udpSessionMu.RLock()
	sess, ok := sm.udpSessions[sessionID]
	sm.udpSessionMu.RUnlock()

	if !ok {
		return
	}

	sess.lastActive = time.Now()

	select {
	case sess.datagramCh <- &UDPDatagram{
		SessionID:  sessionID,
		Data:       payload,
		TargetAddr: sess.targetAddr,
	}:
	default:
		// Drop if queue is full
	}
}

func (sm *SessionManager) controlReadLoop() {
	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		// Read frame header (fixed 11 bytes).
		var hb [11]byte
		if _, err := io.ReadFull(sm.controlStream.stream, hb[:]); err != nil {
			return
		}
		h := &FrameHeader{}
		if err := h.Decode(hb[:]); err != nil {
			return
		}

		if h.Length == 0 {
			// Heartbeat.
			continue
		}

		payload := make([]byte, h.Length)
		if _, err := io.ReadFull(sm.controlStream.stream, payload); err != nil {
			return
		}

		switch h.Type {
		case FrameTypeControl, FrameTypeClose:
			cp := &ControlPayload{}
			if err := cp.Decode(payload); err != nil {
				continue
			}
			sm.handleControlPayload(cp)
		default:
			// Ignore.
		}
	}
}

func (sm *SessionManager) handleControlPayload(cp *ControlPayload) {
	switch cp.ControlType {
	case ControlTypeOpenUDPSession:
		info := &UDPSessionInfo{}
		if err := info.Decode(cp.Data); err != nil {
			return
		}
		addr, err := net.ResolveUDPAddr("udp", info.TargetAddr)
		if err != nil {
			return
		}

		sm.udpSessionMu.Lock()
		defer sm.udpSessionMu.Unlock()

		// Idempotent open (peer may retransmit / reconnect).
		if _, exists := sm.udpSessions[info.SessionID]; exists {
			return
		}
		if info.SessionID >= sm.nextSessionID {
			sm.nextSessionID = info.SessionID + 1
		}

		sess := &udpSession{
			id:         info.SessionID,
			targetAddr: addr,
			contextID:  info.ContextID,
			createdAt:  time.Now(),
			lastActive: time.Now(),
			datagramCh: make(chan *UDPDatagram, sm.config.MaxIncomingDatagrams),
			onClose: func() {
				if sm.onUDPSessionClose != nil {
					sm.onUDPSessionClose()
				}
			},
		}
		sm.udpSessions[info.SessionID] = sess
		if sm.onUDPSessionOpen != nil {
			sm.onUDPSessionOpen()
		}

	case ControlTypeCloseUDPSession:
		info := &UDPSessionInfo{}
		if err := info.Decode(cp.Data); err != nil {
			return
		}
		sm.udpSessionMu.Lock()
		defer sm.udpSessionMu.Unlock()
		sess, ok := sm.udpSessions[info.SessionID]
		if !ok {
			return
		}
		sm.closeUDPSessionLocked(sess)

	case ControlTypeUDPSessionAssoc:
		// Data is: [sessionID(4)] [payload...]
		sm.handleDatagram(cp.Data)
	default:
		// Ignore.
	}
}

func (sm *SessionManager) datagramReadLoop() {
	for {
		select {
		case <-sm.ctx.Done():
			return
		default:
		}

		data, err := sm.conn.ReceiveDatagram(sm.ctx)
		if err != nil {
			return
		}
		sm.handleDatagram(data)
	}
}

func (sm *SessionManager) closeUDPSessionLocked(sess *udpSession) {
	close(sess.datagramCh)
	delete(sm.udpSessions, sess.id)
	if sess.onClose != nil {
		sess.onClose()
	}
}

func (sm *SessionManager) keepaliveLoop() {
	ticker := time.NewTicker(sm.config.KeepAlivePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if sm.controlStream != nil {
				_ = sm.controlStream.SendHeartbeat()
			}
		case <-sm.ctx.Done():
			return
		}
	}
}

func (sm *SessionManager) scavengerLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			sm.scavengeIdleSessions()
		case <-sm.ctx.Done():
			return
		}
	}
}

func (sm *SessionManager) scavengeIdleSessions() {
	timeout := sm.config.MaxIdleTimeout
	if timeout == 0 {
		timeout = DefaultMaxIdleTimeout
	}

	sm.udpSessionMu.Lock()
	defer sm.udpSessionMu.Unlock()

	now := time.Now()
	for id, sess := range sm.udpSessions {
		if now.Sub(sess.lastActive) > timeout {
			sm.closeUDPSessionLocked(sess)
			// Send close notification
			if sm.controlStream != nil {
				info := &UDPSessionInfo{SessionID: id}
				payload := &ControlPayload{
					ControlType: ControlTypeCloseUDPSession,
					Data:        info.Encode(),
				}
				_ = sm.controlStream.SendControl(payload)
			}
		}
	}
}

// Session implements transport.Session interface
func (sm *SessionManager) Session() transport.Session {
	return &sessionAdapter{sm: sm}
}

// sessionAdapter adapts SessionManager to transport.Session interface
type sessionAdapter struct {
	sm *SessionManager
}

func (s *sessionAdapter) OpenStream() (net.Conn, error) {
	return s.sm.OpenStream()
}

func (s *sessionAdapter) AcceptStream() (net.Conn, error) {
	return s.sm.AcceptStream()
}

func (s *sessionAdapter) Close() error {
	return s.sm.Close()
}

func (s *sessionAdapter) LocalAddr() net.Addr {
	return s.sm.LocalAddr()
}

func (s *sessionAdapter) RemoteAddr() net.Addr {
	return s.sm.RemoteAddr()
}

func (s *sessionAdapter) SupportsNativeDatagrams() bool {
	if s.sm == nil || s.sm.config == nil {
		return false
	}
	return s.sm.config.Capabilities.Has(CapabilityDatagram)
}

func (s *sessionAdapter) OpenDatagramSession() (uint32, error) {
	// We don't care about a target address for pure peer-to-peer datagrams.
	// Use a well-formed dummy UDP address for the existing session machinery.
	return s.sm.OpenUDPSession("0.0.0.0:0")
}

func (s *sessionAdapter) WaitDatagramSession(ctx context.Context, sessionID uint32) error {
	t := time.NewTicker(10 * time.Millisecond)
	defer t.Stop()
	for {
		if _, err := s.sm.GetUDPSession(sessionID); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
		}
	}
}

func (s *sessionAdapter) CloseDatagramSession(sessionID uint32) error {
	return s.sm.CloseUDPSession(sessionID)
}

func (s *sessionAdapter) SendDatagram(sessionID uint32, payload []byte) error {
	return s.sm.SendDatagram(sessionID, payload)
}

func (s *sessionAdapter) ReceiveDatagram(sessionID uint32) ([]byte, error) {
	dg, err := s.sm.ReceiveDatagram(sessionID)
	if err != nil {
		return nil, err
	}
	if dg == nil {
		return nil, ErrSessionClosed
	}
	return dg.Data, nil
}

// streamWrapper wraps smux.Stream with close callback
type streamWrapper struct {
	*smux.Stream
	onClose func()
	closed  atomic.Bool
}

func (s *streamWrapper) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		if s.onClose != nil {
			defer s.onClose()
		}
	}
	return s.Stream.Close()
}

// controlStreamHandler handles the control stream
type controlStreamHandler struct {
	stream *quic.Stream
	sm     *SessionManager
	mu     sync.Mutex
}

func newControlStreamHandler(stream *quic.Stream, sm *SessionManager) *controlStreamHandler {
	return &controlStreamHandler{
		stream: stream,
		sm:     sm,
	}
}

// CarrierSessionManager manages UQSP sessions for non-QUIC carriers.
// It provides a simplified session management without QUIC-specific features.
type CarrierSessionManager struct {
	// Underlying connection (from carrier)
	conn net.Conn

	// smux session for stream multiplexing
	smuxSess *smux.Session

	// Configuration
	config *Config

	// Lifecycle management
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	// Metrics callback
	onStreamOpened func()
	onStreamClosed func()
}

// NewCarrierSessionManager creates a new carrier-based session manager
func NewCarrierSessionManager(conn net.Conn, smuxSess *smux.Session, config *Config) *CarrierSessionManager {
	ctx, cancel := context.WithCancel(context.Background())

	if config == nil {
		config = DefaultConfig()
	}

	return &CarrierSessionManager{
		conn:     conn,
		smuxSess: smuxSess,
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start starts the session manager
func (csm *CarrierSessionManager) Start() error {
	// For carrier-based sessions, we don't have QUIC datagrams
	// Start keepalive if needed
	go csm.keepaliveLoop()
	return nil
}

// Close closes the session manager
func (csm *CarrierSessionManager) Close() error {
	if !csm.closed.CompareAndSwap(false, true) {
		return nil
	}

	csm.cancel()

	// Close smux session
	if csm.smuxSess != nil {
		_ = csm.smuxSess.Close()
	}

	// Close underlying connection
	if csm.conn != nil {
		return csm.conn.Close()
	}

	return nil
}

// OpenStream opens a new stream
func (csm *CarrierSessionManager) OpenStream() (net.Conn, error) {
	if csm.closed.Load() {
		return nil, ErrSessionClosed
	}

	conn, err := csm.smuxSess.OpenStream()
	if err != nil {
		return nil, err
	}

	if csm.onStreamOpened != nil {
		csm.onStreamOpened()
	}

	return &carrierStreamWrapper{
		Stream: conn,
		onClose: func() {
			if csm.onStreamClosed != nil {
				csm.onStreamClosed()
			}
		},
	}, nil
}

// AcceptStream accepts a new stream
func (csm *CarrierSessionManager) AcceptStream() (net.Conn, error) {
	if csm.closed.Load() {
		return nil, ErrSessionClosed
	}

	conn, err := csm.smuxSess.AcceptStream()
	if err != nil {
		return nil, err
	}

	if csm.onStreamOpened != nil {
		csm.onStreamOpened()
	}

	return &carrierStreamWrapper{
		Stream: conn,
		onClose: func() {
			if csm.onStreamClosed != nil {
				csm.onStreamClosed()
			}
		},
	}, nil
}

// LocalAddr returns the local address
func (csm *CarrierSessionManager) LocalAddr() net.Addr {
	if csm.conn == nil {
		return nil
	}
	return csm.conn.LocalAddr()
}

// RemoteAddr returns the remote address
func (csm *CarrierSessionManager) RemoteAddr() net.Addr {
	if csm.conn == nil {
		return nil
	}
	return csm.conn.RemoteAddr()
}

// SetMetricsCallbacks sets metrics callbacks
func (csm *CarrierSessionManager) SetMetricsCallbacks(
	onStreamOpened func(),
	onStreamClosed func(),
) {
	csm.onStreamOpened = onStreamOpened
	csm.onStreamClosed = onStreamClosed
}

func (csm *CarrierSessionManager) keepaliveLoop() {
	ticker := time.NewTicker(csm.config.KeepAlivePeriod)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send keepalive via smux (no-op as smux handles keepalive internally)
		case <-csm.ctx.Done():
			return
		}
	}
}

// Session implements transport.Session interface
func (csm *CarrierSessionManager) Session() transport.Session {
	return &carrierSessionAdapter{csm: csm}
}

// carrierSessionAdapter adapts CarrierSessionManager to transport.Session interface
type carrierSessionAdapter struct {
	csm *CarrierSessionManager
}

func (s *carrierSessionAdapter) OpenStream() (net.Conn, error) {
	return s.csm.OpenStream()
}

func (s *carrierSessionAdapter) AcceptStream() (net.Conn, error) {
	return s.csm.AcceptStream()
}

func (s *carrierSessionAdapter) Close() error {
	return s.csm.Close()
}

func (s *carrierSessionAdapter) LocalAddr() net.Addr {
	return s.csm.LocalAddr()
}

func (s *carrierSessionAdapter) RemoteAddr() net.Addr {
	return s.csm.RemoteAddr()
}

// carrierStreamWrapper wraps smux.Stream with close callback
type carrierStreamWrapper struct {
	*smux.Stream
	onClose func()
	closed  atomic.Bool
}

func (s *carrierStreamWrapper) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		if s.onClose != nil {
			defer s.onClose()
		}
	}
	return s.Stream.Close()
}

func (c *controlStreamHandler) SendControl(payload *ControlPayload) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	data := payload.Encode()
	header := &FrameHeader{
		Type:   FrameTypeControl,
		Length: uint16(len(data)),
	}

	if _, err := c.stream.Write(header.Encode()); err != nil {
		return err
	}
	_, err := c.stream.Write(data)
	return err
}

func (c *controlStreamHandler) SendDatagram(sessionID uint32, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Encode as control frame with datagram data
	payload := make([]byte, 4+len(data))
	payload[0] = byte(sessionID >> 24)
	payload[1] = byte(sessionID >> 16)
	payload[2] = byte(sessionID >> 8)
	payload[3] = byte(sessionID)
	copy(payload[4:], data)

	cp := &ControlPayload{
		ControlType: ControlTypeUDPSessionAssoc,
		Data:        payload,
	}

	return c.SendControl(cp)
}

func (c *controlStreamHandler) SendHeartbeat() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	header := &FrameHeader{
		Type:   FrameTypeHeartbeat,
		Length: 0,
	}

	_, err := c.stream.Write(header.Encode())
	return err
}

func (c *controlStreamHandler) Close() error {
	return c.stream.Close()
}
