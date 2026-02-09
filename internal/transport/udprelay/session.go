// Package udprelay provides a unified UDP reliability layer with
// fragmentation, reassembly, and session management.
package udprelay

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// SessionID uniquely identifies a UDP relay session
type SessionID uint64

// GenerateSessionID creates a new random session ID
func GenerateSessionID() SessionID {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback to timestamp-based
		return SessionID(time.Now().UnixNano())
	}
	return SessionID(binary.BigEndian.Uint64(b[:]))
}

// SessionConfig configures a UDP relay session
type SessionConfig struct {
	// Local address
	LocalAddr net.Addr
	// Remote address
	RemoteAddr net.Addr

	// MTU for this session (adaptive)
	MTU int

	// Timeouts
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration

	// Reliability parameters
	WindowSize     int
	MaxRetries     int
	RetryInterval  time.Duration

	// Fragmentation
	MaxFragmentSize int
	EnableFragment  bool
}

// DefaultSessionConfig returns default session configuration
func DefaultSessionConfig() *SessionConfig {
	return &SessionConfig{
		MTU:             1400,
		HandshakeTimeout: 10 * time.Second,
		IdleTimeout:      60 * time.Second,
		WindowSize:      128,
		MaxRetries:      5,
		RetryInterval:   200 * time.Millisecond,
		MaxFragmentSize: 1200,
		EnableFragment:  true,
	}
}

// SessionState represents the state of a session
type SessionState int32

const (
	SessionStateInit       SessionState = iota // Initial state
	SessionStateHandshaking                    // Handshake in progress
	SessionStateEstablished                    // Active session
	SessionStateClosing                        // Graceful close
	SessionStateClosed                         // Closed
)

func (s SessionState) String() string {
	switch s {
	case SessionStateInit:
		return "init"
	case SessionStateHandshaking:
		return "handshaking"
	case SessionStateEstablished:
		return "established"
	case SessionStateClosing:
		return "closing"
	case SessionStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// Session represents a UDP relay session with reliability
type Session struct {
	id       SessionID
	config   *SessionConfig
	state    atomic.Int32
	created  time.Time
	lastRecv atomic.Int64 // Unix nano
	lastSent atomic.Int64 // Unix nano

	// Connection reference
	conn net.PacketConn

	// Reliability
	window *SlidingWindow

	// Fragmentation
	fragReassembler *Reassembler
	fragSequencer   atomic.Uint32

	// Flow control
	sendQuota    atomic.Int64
	recvQuota    atomic.Int64
	rttEstimator *RTTEstimator

	// Callbacks
	onData   func([]byte)
	onClose  func()
	onError  func(error)

	// Internal
	mu       sync.RWMutex
	closeCh  chan struct{}
	sendCh   chan *Packet
	recvBuf  chan []byte
}

// NewSession creates a new UDP relay session
func NewSession(id SessionID, conn net.PacketConn, config *SessionConfig) *Session {
	if config == nil {
		config = DefaultSessionConfig()
	}

	s := &Session{
		id:              id,
		config:          config,
		conn:            conn,
		created:         time.Now(),
		window:          NewSlidingWindow(config.WindowSize),
		fragReassembler: NewReassembler(30 * time.Second),
		rttEstimator:    NewRTTEstimator(),
		closeCh:         make(chan struct{}),
		sendCh:          make(chan *Packet, config.WindowSize),
		recvBuf:         make(chan []byte, config.WindowSize),
	}

	s.state.Store(int32(SessionStateInit))
	s.updateActivity()

	return s
}

// ID returns the session ID
func (s *Session) ID() SessionID {
	return s.id
}

// State returns the current session state
func (s *Session) State() SessionState {
	return SessionState(s.state.Load())
}

// setState updates the session state
func (s *Session) setState(state SessionState) {
	s.state.Store(int32(state))
}

// updateActivity updates last activity timestamps
func (s *Session) updateActivity() {
	now := time.Now().UnixNano()
	s.lastRecv.Store(now)
	s.lastSent.Store(now)
}

// updateRecvActivity updates only receive timestamp
func (s *Session) updateRecvActivity() {
	s.lastRecv.Store(time.Now().UnixNano())
}

// updateSendActivity updates only send timestamp
func (s *Session) updateSendActivity() {
	s.lastSent.Store(time.Now().UnixNano())
}

// IsIdle returns true if the session has been idle longer than IdleTimeout
func (s *Session) IsIdle() bool {
	idle := s.config.IdleTimeout
	if idle <= 0 {
		idle = 60 * time.Second
	}
	lastRecv := time.Unix(0, s.lastRecv.Load())
	lastSent := time.Unix(0, s.lastSent.Load())
	lastActivity := lastRecv
	if lastSent.After(lastRecv) {
		lastActivity = lastSent
	}
	return time.Since(lastActivity) > idle
}

// Age returns the session age
func (s *Session) Age() time.Duration {
	return time.Since(s.created)
}

// StartHandshake initiates the handshake process
func (s *Session) StartHandshake() error {
	if s.State() != SessionStateInit {
		return fmt.Errorf("session not in init state: %s", s.State())
	}

	s.setState(SessionStateHandshaking)

	// Send handshake packet
	handshake := &Packet{
		Header: PacketHeader{
			SessionID: s.id,
			Type:      PacketTypeHandshake,
			SeqNum:    0,
		},
		Payload: s.encodeHandshake(),
	}

	return s.sendPacket(handshake)
}

// HandleHandshake processes a handshake packet
func (s *Session) HandleHandshake(payload []byte) error {
	if len(payload) < 8 {
		return fmt.Errorf("handshake too short")
	}

	// Parse peer's MTU
	peerMTU := binary.BigEndian.Uint32(payload[:4])

	// Adapt our MTU to peer's
	s.mu.Lock()
	if int(peerMTU) < s.config.MTU {
		s.config.MTU = int(peerMTU)
	}
	s.mu.Unlock()

	if s.State() == SessionStateInit {
		// Accept and establish
		s.setState(SessionStateEstablished)
		// Send handshake ACK
		ack := &Packet{
			Header: PacketHeader{
				SessionID: s.id,
				Type:      PacketTypeHandshakeAck,
				SeqNum:    0,
			},
		}
		_ = s.sendPacket(ack)
	} else if s.State() == SessionStateHandshaking {
		// Our handshake was acknowledged
		s.setState(SessionStateEstablished)
	}

	return nil
}

// encodeHandshake encodes handshake data
func (s *Session) encodeHandshake() []byte {
	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[:4], uint32(s.config.MTU))
	binary.BigEndian.PutUint32(data[4:8], uint32(s.config.WindowSize))
	return data
}

// Send sends data through the session
func (s *Session) Send(data []byte) error {
	if s.State() != SessionStateEstablished {
		return fmt.Errorf("session not established: %s", s.State())
	}

	// Fragment if needed
	fragments := s.fragment(data)

	for _, frag := range fragments {
		select {
		case s.sendCh <- frag:
		case <-s.closeCh:
			return fmt.Errorf("session closed")
		}
	}

	return nil
}

// fragment fragments data if needed
func (s *Session) fragment(data []byte) []*Packet {
	if !s.config.EnableFragment || len(data) <= s.config.MaxFragmentSize {
		// No fragmentation needed
		return []*Packet{{
			Header: PacketHeader{
				SessionID: s.id,
				Type:      PacketTypeData,
				SeqNum:    s.window.NextSendSeq(),
			},
			Payload: data,
		}}
	}

	// Calculate fragments
	fragSize := s.config.MaxFragmentSize - PacketHeaderSize - FragmentHeaderSize
	numFrags := (len(data) + fragSize - 1) / fragSize
	fragID := uint16(s.fragSequencer.Add(1))

	fragments := make([]*Packet, 0, numFrags)
	offset := 0

	for i := 0; i < numFrags; i++ {
		end := offset + fragSize
		if end > len(data) {
			end = len(data)
		}

		fragHeader := FragmentHeader{
			FragID:     fragID,
			FragIndex:  uint16(i),
			FragTotal:  uint16(numFrags),
			FragOffset: uint32(offset),
		}

		pkt := &Packet{
			Header: PacketHeader{
				SessionID: s.id,
				Type:      PacketTypeFragment,
				SeqNum:    s.window.NextSendSeq(),
			},
			Payload: fragHeader.Encode(data[offset:end]),
		}

		fragments = append(fragments, pkt)
		offset = end
	}

	return fragments
}

// HandlePacket processes an incoming packet
func (s *Session) HandlePacket(pkt *Packet, from net.Addr) {
	s.updateRecvActivity()

	switch pkt.Header.Type {
	case PacketTypeHandshake:
		_ = s.HandleHandshake(pkt.Payload)
	case PacketTypeHandshakeAck:
		_ = s.HandleHandshake([]byte{})
	case PacketTypeData:
		s.handleData(pkt)
	case PacketTypeFragment:
		s.handleFragment(pkt)
	case PacketTypeACK:
		s.handleACK(pkt)
	case PacketTypePing:
		s.handlePing(pkt, from)
	case PacketTypePong:
		s.handlePong(pkt)
	case PacketTypeClose:
		s.Close()
	}
}

// handleData processes a data packet
func (s *Session) handleData(pkt *Packet) {
	if !s.window.IsExpected(pkt.Header.SeqNum) {
		// Out of window, send duplicate ACK
		s.sendACK(s.window.ExpectedSeq())
		return
	}

	// Deliver data
	select {
	case s.recvBuf <- pkt.Payload:
		s.window.AdvanceRecv(pkt.Header.SeqNum)
		s.sendACK(pkt.Header.SeqNum + 1)
	default:
		// Buffer full, drop packet
	}
}

// handleFragment processes a fragment
func (s *Session) handleFragment(pkt *Packet) {
	fragHeader, data, err := DecodeFragment(pkt.Payload)
	if err != nil {
		return
	}

	complete, reassembled := s.fragReassembler.AddFragment(fragHeader, data)
	if complete && reassembled != nil {
		// Deliver reassembled data
		select {
		case s.recvBuf <- reassembled:
			s.sendACK(pkt.Header.SeqNum + 1)
		default:
		}
	}
}

// handleACK processes an ACK
func (s *Session) handleACK(pkt *Packet) {
	if len(pkt.Payload) >= 4 {
		ackSeq := binary.BigEndian.Uint32(pkt.Payload[:4])
		s.window.Ack(ackSeq)
	}
}

// handlePing responds to a ping
func (s *Session) handlePing(pkt *Packet, from net.Addr) {
	pong := &Packet{
		Header: PacketHeader{
			SessionID: s.id,
			Type:      PacketTypePong,
			SeqNum:    pkt.Header.SeqNum,
		},
		Payload: pkt.Payload,
	}
	_ = s.sendPacket(pong)
}

// handlePong updates RTT
func (s *Session) handlePong(pkt *Packet) {
	if len(pkt.Payload) >= 8 {
		timestamp := int64(binary.BigEndian.Uint64(pkt.Payload[:8]))
		rtt := time.Since(time.Unix(0, timestamp))
		s.rttEstimator.Update(rtt)
	}
}

// sendACK sends an ACK
func (s *Session) sendACK(seq uint32) {
	ack := &Packet{
		Header: PacketHeader{
			SessionID: s.id,
			Type:      PacketTypeACK,
			SeqNum:    seq,
		},
		Payload: make([]byte, 4),
	}
	binary.BigEndian.PutUint32(ack.Payload, seq)
	_ = s.sendPacket(ack)
}

// sendPacket sends a packet
func (s *Session) sendPacket(pkt *Packet) error {
	if s.config.RemoteAddr == nil {
		return fmt.Errorf("remote address not set")
	}

	data := pkt.Encode()
	_, err := s.conn.WriteTo(data, s.config.RemoteAddr)
	if err == nil {
		s.updateSendActivity()
	}
	return err
}

// Recv receives data from the session (blocking)
func (s *Session) Recv() ([]byte, error) {
	if s.State() == SessionStateClosed {
		return nil, fmt.Errorf("session closed")
	}

	select {
	case data := <-s.recvBuf:
		return data, nil
	case <-s.closeCh:
		return nil, fmt.Errorf("session closed")
	}
}

// Close closes the session
func (s *Session) Close() error {
	if !s.state.CompareAndSwap(int32(SessionStateEstablished), int32(SessionStateClosing)) {
		// Try to close from any state
		oldState := s.State()
		if oldState == SessionStateClosed || oldState == SessionStateClosing {
			return nil
		}
		s.setState(SessionStateClosing)
	}

	// Send close packet
	closePkt := &Packet{
		Header: PacketHeader{
			SessionID: s.id,
			Type:      PacketTypeClose,
		},
	}
	_ = s.sendPacket(closePkt)

	close(s.closeCh)
	s.setState(SessionStateClosed)

	if s.onClose != nil {
		s.onClose()
	}

	return nil
}

// GetStats returns session statistics
func (s *Session) GetStats() SessionStats {
	return SessionStats{
		SessionID:    s.id,
		State:        s.State().String(),
		Created:      s.created,
		LastRecv:     time.Unix(0, s.lastRecv.Load()),
		LastSent:     time.Unix(0, s.lastSent.Load()),
		RTT:          s.rttEstimator.RTT(),
		WindowSize:   s.window.CurrentSize(),
		PendingACKs:  s.window.PendingCount(),
	}
}

// SessionStats contains session statistics
type SessionStats struct {
	SessionID   SessionID
	State       string
	Created     time.Time
	LastRecv    time.Time
	LastSent    time.Time
	RTT         time.Duration
	WindowSize  int
	PendingACKs int
}
