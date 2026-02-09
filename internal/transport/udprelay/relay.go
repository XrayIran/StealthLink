// Package udprelay provides UDP reliability with fragmentation, reassembly,
// and session management.
package udprelay

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RelayConfig configures the UDP relay
type RelayConfig struct {
	// Local address to bind
	LocalAddr string

	// MTU for outgoing packets
	MTU int

	// Session management
	MaxSessions    int
	SessionTimeout time.Duration

	// Fairness scheduling
	EnableFairness bool

	// Replay protection
	EnableReplayProtection bool
	ReplayWindowSize       int64
}

// DefaultRelayConfig returns default relay configuration
func DefaultRelayConfig() *RelayConfig {
	return &RelayConfig{
		LocalAddr:              ":0",
		MTU:                    1400,
		MaxSessions:            1000,
		SessionTimeout:         60 * time.Second,
		EnableFairness:         true,
		EnableReplayProtection: true,
		ReplayWindowSize:       1 << 20, // ~1 million packets
	}
}

// Relay is a UDP relay server with reliability and session management
type Relay struct {
	config *RelayConfig
	conn   net.PacketConn

	// Sessions
	sessions    map[SessionID]*Session
	sessionsMu  sync.RWMutex

	// Fairness scheduling
	readyQueue  chan *Session
	sessionList []*Session
	currentIdx  atomic.Int32

	// Replay protection window (64-bit)
	replayWindow *ReplayWindow

	// Control
	closeCh chan struct{}
	closed  atomic.Bool

	// Metrics
	packetsIn   atomic.Uint64
	packetsOut  atomic.Uint64
	bytesIn     atomic.Uint64
	bytesOut    atomic.Uint64
	drops       atomic.Uint64
}

// NewRelay creates a new UDP relay
func NewRelay(config *RelayConfig) (*Relay, error) {
	if config == nil {
		config = DefaultRelayConfig()
	}

	addr, err := net.ResolveUDPAddr("udp", config.LocalAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}

	r := &Relay{
		config:       config,
		conn:         conn,
		sessions:     make(map[SessionID]*Session),
		readyQueue:   make(chan *Session, 1024),
		closeCh:      make(chan struct{}),
		replayWindow: NewReplayWindow(config.ReplayWindowSize),
	}

	go r.readLoop()
	go r.scheduleLoop()
	go r.gcLoop()

	return r, nil
}

// Addr returns the local address
func (r *Relay) Addr() net.Addr {
	return r.conn.LocalAddr()
}

// readLoop reads packets and dispatches them
func (r *Relay) readLoop() {
	buf := make([]byte, 2048)
	for {
		if r.closed.Load() {
			return
		}

		n, from, err := r.conn.ReadFrom(buf)
		if err != nil {
			if r.closed.Load() {
				return
			}
			continue
		}

		if n < PacketHeaderSize {
			continue
		}

		// Decode packet
		pkt, err := DecodePacket(buf[:n])
		if err != nil {
			r.drops.Add(1)
			continue
		}

		// Replay protection check
		if r.config.EnableReplayProtection {
			if !r.replayWindow.CheckAndAdd(pkt.Header.SeqNum) {
				// Duplicate or replay
				r.drops.Add(1)
				continue
			}
		}

		r.packetsIn.Add(1)
		r.bytesIn.Add(uint64(n))

		// Dispatch to session
		r.dispatch(pkt, from)
	}
}

// dispatch routes packets to the appropriate session
func (r *Relay) dispatch(pkt *Packet, from net.Addr) {
	r.sessionsMu.RLock()
	session, exists := r.sessions[pkt.Header.SessionID]
	r.sessionsMu.RUnlock()

	if exists {
		session.HandlePacket(pkt, from)
		return
	}

	// New session (if handshake)
	if pkt.Header.Type == PacketTypeHandshake {
		r.handleNewSession(pkt, from)
	}
}

// handleNewSession creates a new session from handshake
func (r *Relay) handleNewSession(pkt *Packet, from net.Addr) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	// Check max sessions
	if len(r.sessions) >= r.config.MaxSessions {
		// Remove oldest idle session
		r.removeOldestIdle()
	}

	// Create new session
	sessionID := pkt.Header.SessionID
	if sessionID == 0 {
		sessionID = GenerateSessionID()
	}

	config := &SessionConfig{
		RemoteAddr:       from,
		MTU:              r.config.MTU,
		IdleTimeout:      r.config.SessionTimeout,
		WindowSize:       128,
		MaxRetries:       5,
		RetryInterval:    200 * time.Millisecond,
		MaxFragmentSize:  r.config.MTU - PacketHeaderSize - FragmentHeaderSize,
		EnableFragment:   true,
	}

	session := NewSession(sessionID, r.conn, config)
	session.onClose = func() {
		r.removeSession(sessionID)
	}

	r.sessions[sessionID] = session

	// Handle the handshake
	go session.HandleHandshake(pkt.Payload)
}

// removeOldestIdle removes the oldest idle session
func (r *Relay) removeOldestIdle() {
	var oldest *Session
	for _, s := range r.sessions {
		if s.IsIdle() {
			if oldest == nil || s.lastRecv.Load() < oldest.lastRecv.Load() {
				oldest = s
			}
		}
	}
	if oldest != nil {
		_ = oldest.Close()
		delete(r.sessions, oldest.id)
	}
}

// removeSession removes a session
func (r *Relay) removeSession(id SessionID) {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()
	delete(r.sessions, id)
}

// scheduleLoop implements fairness scheduling
func (r *Relay) scheduleLoop() {
	if !r.config.EnableFairness {
		return
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.closeCh:
			return
		case <-ticker.C:
			r.fairSchedule()
		}
	}
}

// fairSchedule schedules sessions fairly using round-robin
func (r *Relay) fairSchedule() {
	r.sessionsMu.RLock()
	sessions := make([]*Session, 0, len(r.sessions))
	for _, s := range r.sessions {
		if s.State() == SessionStateEstablished {
			sessions = append(sessions, s)
		}
	}
	r.sessionsMu.RUnlock()

	if len(sessions) == 0 {
		return
	}

	// Round-robin scheduling
	idx := int(r.currentIdx.Add(1)) % len(sessions)
	session := sessions[idx]

	// Try to process one packet from this session
	select {
	case r.readyQueue <- session:
	default:
	}
}

// gcLoop removes expired sessions
func (r *Relay) gcLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.closeCh:
			return
		case <-ticker.C:
			r.gcSessions()
		}
	}
}

// gcSessions garbage collects idle sessions
func (r *Relay) gcSessions() {
	r.sessionsMu.Lock()
	defer r.sessionsMu.Unlock()

	for id, s := range r.sessions {
		if s.IsIdle() || s.State() == SessionStateClosed {
			_ = s.Close()
			delete(r.sessions, id)
		}
	}
}

// Connect establishes a new session to a remote address
func (r *Relay) Connect(ctx context.Context, addr string) (*Session, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve address: %w", err)
	}

	sessionID := GenerateSessionID()
	config := &SessionConfig{
		RemoteAddr:       remoteAddr,
		MTU:              r.config.MTU,
		IdleTimeout:      r.config.SessionTimeout,
		WindowSize:       128,
		MaxRetries:       5,
		RetryInterval:    200 * time.Millisecond,
		MaxFragmentSize:  r.config.MTU - PacketHeaderSize - FragmentHeaderSize,
		EnableFragment:   true,
	}

	session := NewSession(sessionID, r.conn, config)
	session.onClose = func() {
		r.removeSession(sessionID)
	}

	r.sessionsMu.Lock()
	r.sessions[sessionID] = session
	r.sessionsMu.Unlock()

	// Start handshake
	if err := session.StartHandshake(); err != nil {
		r.removeSession(sessionID)
		return nil, err
	}

	// Wait for handshake to complete
	ctx, cancel := context.WithTimeout(ctx, config.HandshakeTimeout)
	defer cancel()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			r.removeSession(sessionID)
			return nil, fmt.Errorf("handshake timeout")
		case <-ticker.C:
			if session.State() == SessionStateEstablished {
				return session, nil
			}
		}
	}
}

// GetSession returns a session by ID
func (r *Relay) GetSession(id SessionID) (*Session, bool) {
	r.sessionsMu.RLock()
	defer r.sessionsMu.RUnlock()
	s, ok := r.sessions[id]
	return s, ok
}

// GetStats returns relay statistics
func (r *Relay) GetStats() RelayStats {
	r.sessionsMu.RLock()
	sessionCount := len(r.sessions)
	r.sessionsMu.RUnlock()

	return RelayStats{
		PacketsIn:    r.packetsIn.Load(),
		PacketsOut:   r.packetsOut.Load(),
		BytesIn:      r.bytesIn.Load(),
		BytesOut:     r.bytesOut.Load(),
		Drops:        r.drops.Load(),
		SessionCount: sessionCount,
		ReplaySize:   r.replayWindow.Size(),
	}
}

// Close closes the relay
func (r *Relay) Close() error {
	if !r.closed.CompareAndSwap(false, true) {
		return nil
	}

	close(r.closeCh)

	r.sessionsMu.Lock()
	for _, s := range r.sessions {
		_ = s.Close()
	}
	r.sessions = make(map[SessionID]*Session)
	r.sessionsMu.Unlock()

	return r.conn.Close()
}

// RelayStats contains relay statistics
type RelayStats struct {
	PacketsIn    uint64
	PacketsOut   uint64
	BytesIn      uint64
	BytesOut     uint64
	Drops        uint64
	SessionCount int
	ReplaySize   int64
}

// ReplayWindow provides replay protection using a 64-bit sliding window
type ReplayWindow struct {
	window  int64
	baseSeq uint32
	mu      sync.RWMutex
	size    int64
}

// NewReplayWindow creates a new replay window
func NewReplayWindow(size int64) *ReplayWindow {
	return &ReplayWindow{
		size: size,
	}
}

// CheckAndAdd checks if a sequence number is new and adds it to the window
func (w *ReplayWindow) CheckAndAdd(seq uint32) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// If this is a new base sequence, shift window
	if seq > w.baseSeq {
		diff := seq - w.baseSeq
		if diff >= 64 {
			w.window = 0
		} else {
			w.window <<= diff
		}
		w.baseSeq = seq
	}

	// Check if within window
	if seq > w.baseSeq {
		return false // Future packet, shouldn't happen due to above
	}

	diff := w.baseSeq - seq
	if diff >= 64 {
		return false // Too old
	}

	bit := uint64(1) << diff
	if w.window&int64(bit) != 0 {
		return false // Already seen
	}

	w.window |= int64(bit)
	return true
}

// Size returns the current window size in entries
func (w *ReplayWindow) Size() int64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.size
}
