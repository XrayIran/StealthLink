package rawpacket

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// RecoveryManager manages connection recovery for raw packet transports.
// It implements udp2raw-style connection recovery with anti-replay protection,
// heartbeat-based failure detection, and automatic port changing.
type RecoveryManager struct {
	config RecoveryConfig

	// Connection state
	connected    atomic.Bool
	lastActivity atomic.Int64 // Unix nano

	// Sequence numbers for anti-replay
	sendSeq      atomic.Uint64
	recvSeq      atomic.Uint64
	recvWindow   *SlidingWindow

	// Heartbeat
	heartbeatTicker *time.Ticker
	stopHeartbeat   chan struct{}

	// Port management
	currentPort   atomic.Uint32
	portHistory   []uint32
	portMu        sync.RWMutex

	// Retry state
	retryCount    atomic.Int32
	lastRetryTime atomic.Int64

	// Callbacks
	onDisconnect  func()
	onReconnect   func(newAddr net.Addr) error

	mu sync.RWMutex
}

// NewRecoveryManager creates a new recovery manager
func NewRecoveryManager(config RecoveryConfig) *RecoveryManager {
	rm := &RecoveryManager{
		config:        config,
		recvWindow:    NewSlidingWindow(config.AntiReplayWindow),
		stopHeartbeat: make(chan struct{}),
		portHistory:   make([]uint32, 0, 10),
	}

	if config.Enabled {
		rm.startHeartbeat()
	}

	return rm
}

// SetCallbacks sets the disconnect and reconnect callbacks
func (rm *RecoveryManager) SetCallbacks(onDisconnect func(), onReconnect func(newAddr net.Addr) error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.onDisconnect = onDisconnect
	rm.onReconnect = onReconnect
}

// startHeartbeat starts the heartbeat loop
func (rm *RecoveryManager) startHeartbeat() {
	if !rm.config.Enabled {
		return
	}

	rm.heartbeatTicker = time.NewTicker(rm.config.HeartbeatInterval)
	go func() {
		for {
			select {
			case <-rm.heartbeatTicker.C:
				rm.checkHeartbeat()
			case <-rm.stopHeartbeat:
				return
			}
		}
	}()
}

// stopHeartbeat stops the heartbeat loop
func (rm *RecoveryManager) stopHeartbeatLoop() {
	if rm.heartbeatTicker != nil {
		rm.heartbeatTicker.Stop()
		close(rm.stopHeartbeat)
	}
}

// checkHeartbeat checks if the connection is still alive
func (rm *RecoveryManager) checkHeartbeat() {
	if !rm.connected.Load() {
		return
	}

	lastActivity := time.Unix(0, rm.lastActivity.Load())
	if time.Since(lastActivity) > rm.config.HeartbeatTimeout {
		// Connection appears dead, trigger recovery
		rm.handleDisconnect()
	}
}

// handleDisconnect handles connection loss
func (rm *RecoveryManager) handleDisconnect() {
	rm.mu.Lock()
	onDisconnect := rm.onDisconnect
	onReconnect := rm.onReconnect
	rm.mu.Unlock()

	// Mark as disconnected
	rm.connected.Store(false)

	// Call disconnect callback
	if onDisconnect != nil {
		onDisconnect()
	}

	// Attempt recovery if enabled
	if rm.config.AutoPortChange && onReconnect != nil {
		rm.attemptRecovery(onReconnect)
	}
}

// attemptRecovery attempts to recover the connection
func (rm *RecoveryManager) attemptRecovery(onReconnect func(newAddr net.Addr) error) {
	// Check retry limit
	if rm.retryCount.Load() >= int32(rm.config.MaxRetries) {
		return
	}

	// Check retry interval
	lastRetry := time.Unix(0, rm.lastRetryTime.Load())
	if time.Since(lastRetry) < rm.config.HeartbeatTimeout {
		return
	}

	rm.retryCount.Add(1)
	rm.lastRetryTime.Store(time.Now().UnixNano())

	// Generate new port if enabled
	var newAddr net.Addr
	if rm.config.AutoPortChange {
		newPort := rm.generateNewPort()
		newAddr = &net.UDPAddr{
			Port: int(newPort),
		}
	}

	// Attempt reconnect
	if err := onReconnect(newAddr); err != nil {
		// Recovery failed, will retry on next heartbeat
		return
	}

	// Recovery successful
	rm.connected.Store(true)
	rm.retryCount.Store(0)
	rm.UpdateActivity()
}

// generateNewPort generates a new random port for recovery
func (rm *RecoveryManager) generateNewPort() uint32 {
	rm.portMu.Lock()
	defer rm.portMu.Unlock()

	// Generate random port in ephemeral range (32768-60999)
	var port uint32
	for {
		b := make([]byte, 2)
		rand.Read(b)
		port = uint32(binary.BigEndian.Uint16(b))%28232 + 32768

		// Check if port was recently used
		used := false
		for _, p := range rm.portHistory {
			if p == port {
				used = true
				break
			}
		}

		if !used {
			break
		}
	}

	// Add to history
	rm.portHistory = append(rm.portHistory, port)
	if len(rm.portHistory) > 10 {
		rm.portHistory = rm.portHistory[1:]
	}

	rm.currentPort.Store(port)
	return port
}

// UpdateActivity updates the last activity timestamp
func (rm *RecoveryManager) UpdateActivity() {
	rm.lastActivity.Store(time.Now().UnixNano())
	rm.connected.Store(true)
}

// IsConnected returns whether the connection is considered active
func (rm *RecoveryManager) IsConnected() bool {
	return rm.connected.Load()
}

// GetNextSeq returns the next sequence number for sending
func (rm *RecoveryManager) GetNextSeq() uint64 {
	return rm.sendSeq.Add(1)
}

// ValidateSeq validates a received sequence number (anti-replay)
func (rm *RecoveryManager) ValidateSeq(seq uint64) bool {
	if !rm.config.Enabled {
		return true
	}

	return rm.recvWindow.Validate(seq)
}

// MarkSeq marks a sequence number as received
func (rm *RecoveryManager) MarkSeq(seq uint64) {
	if !rm.config.Enabled {
		return
	}

	rm.recvWindow.Mark(seq)
	rm.recvSeq.Store(seq)
}

// Close closes the recovery manager
func (rm *RecoveryManager) Close() error {
	rm.stopHeartbeatLoop()
	rm.connected.Store(false)
	return nil
}

// GetStats returns recovery statistics
func (rm *RecoveryManager) GetStats() RecoveryStats {
	return RecoveryStats{
		Connected:     rm.connected.Load(),
		SendSeq:       rm.sendSeq.Load(),
		RecvSeq:       rm.recvSeq.Load(),
		RetryCount:    int(rm.retryCount.Load()),
		LastActivity:  time.Unix(0, rm.lastActivity.Load()),
	}
}

// RecoveryStats contains recovery statistics
type RecoveryStats struct {
	Connected    bool
	SendSeq      uint64
	RecvSeq      uint64
	RetryCount   int
	LastActivity time.Time
}

// SlidingWindow implements a sliding window for anti-replay protection
type SlidingWindow struct {
	windowSize uint64
	baseSeq    atomic.Uint64
	bitmap     []uint64 // Each bit represents a sequence number
	mu         sync.RWMutex
}

// NewSlidingWindow creates a new sliding window
func NewSlidingWindow(size uint64) *SlidingWindow {
	// Size in bits, rounded up to multiple of 64
	numWords := (size + 63) / 64
	return &SlidingWindow{
		windowSize: size,
		bitmap:     make([]uint64, numWords),
	}
}

// Validate checks if a sequence number is valid (not a replay)
func (sw *SlidingWindow) Validate(seq uint64) bool {
	sw.mu.RLock()
	defer sw.mu.RUnlock()

	base := sw.baseSeq.Load()

	// Check if sequence number is too old
	if seq < base {
		return false
	}

	// Check if sequence number is too new (would extend window too far)
	if seq >= base+sw.windowSize {
		return true // Allow, will shift window
	}

	// Check if already received
	offset := seq - base
	wordIndex := offset / 64
	bitIndex := offset % 64

	return sw.bitmap[wordIndex]&(1<<bitIndex) == 0
}

// Mark marks a sequence number as received
func (sw *SlidingWindow) Mark(seq uint64) {
	sw.mu.Lock()
	defer sw.mu.Unlock()

	base := sw.baseSeq.Load()

	// Shift window if necessary
	if seq >= base+sw.windowSize {
		sw.shiftWindow(seq - base - sw.windowSize + 1)
		base = sw.baseSeq.Load()
	}

	// Mark as received
	offset := seq - base
	if offset >= sw.windowSize {
		return // Too far ahead, ignore
	}

	wordIndex := offset / 64
	bitIndex := offset % 64

	if wordIndex < uint64(len(sw.bitmap)) {
		sw.bitmap[wordIndex] |= 1 << bitIndex
	}
}

// shiftWindow shifts the sliding window
func (sw *SlidingWindow) shiftWindow(delta uint64) {
	if delta == 0 {
		return
	}

	wordsToShift := delta / 64
	bitsToShift := delta % 64

	// Shift bitmap
	if wordsToShift >= uint64(len(sw.bitmap)) {
		// Clear entire bitmap
		for i := range sw.bitmap {
			sw.bitmap[i] = 0
		}
	} else {
		// Shift words
		for i := 0; i < len(sw.bitmap)-int(wordsToShift); i++ {
			sw.bitmap[i] = sw.bitmap[i+int(wordsToShift)]
		}
		// Clear shifted words
		for i := len(sw.bitmap) - int(wordsToShift); i < len(sw.bitmap); i++ {
			sw.bitmap[i] = 0
		}

		// Shift bits within words
		if bitsToShift > 0 {
			for i := 0; i < len(sw.bitmap)-1; i++ {
				sw.bitmap[i] = (sw.bitmap[i] >> bitsToShift) |
					(sw.bitmap[i+1] << (64 - bitsToShift))
			}
			sw.bitmap[len(sw.bitmap)-1] >>= bitsToShift
		}
	}

	// Update base
	sw.baseSeq.Add(delta)
}

// GetWindow returns the current window state
func (sw *SlidingWindow) GetWindow() (base uint64, bitmap []uint64) {
	sw.mu.RLock()
	defer sw.mu.RUnlock()
	return sw.baseSeq.Load(), append([]uint64(nil), sw.bitmap...)
}

// ConnectionState represents the state of a recoverable connection
type ConnectionState struct {
	LocalAddr    net.Addr
	RemoteAddr   net.Addr
	SeqLocal     uint64
	SeqRemote    uint64
	Connected    bool
	LastActivity time.Time
}

// StateManager manages connection states for multiple connections
type StateManager struct {
	states map[string]*ConnectionState
	mu     sync.RWMutex
}

// NewStateManager creates a new state manager
func NewStateManager() *StateManager {
	return &StateManager{
		states: make(map[string]*ConnectionState),
	}
}

// GetState gets or creates a connection state
func (sm *StateManager) GetState(id string) *ConnectionState {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if state, ok := sm.states[id]; ok {
		return state
	}

	state := &ConnectionState{}
	sm.states[id] = state
	return state
}

// UpdateState updates a connection state
func (sm *StateManager) UpdateState(id string, update func(*ConnectionState)) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	state, ok := sm.states[id]
	if !ok {
		state = &ConnectionState{}
		sm.states[id] = state
	}

	update(state)
}

// RemoveState removes a connection state
func (sm *StateManager) RemoveState(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.states, id)
}

// GetAllStates returns all connection states
func (sm *StateManager) GetAllStates() map[string]*ConnectionState {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	result := make(map[string]*ConnectionState, len(sm.states))
	for k, v := range sm.states {
		result[k] = v
	}
	return result
}

// PersistState persists connection state for recovery after restart
func (sm *StateManager) PersistState(id string) ([]byte, error) {
	sm.mu.RLock()
	state, ok := sm.states[id]
	sm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("state not found: %s", id)
	}

	// Simple binary serialization
	// In production, use proper serialization like protobuf
	data := make([]byte, 0, 64)
	data = append(data, byte(state.SeqLocal))
	data = append(data, byte(state.SeqLocal>>8))
	data = append(data, byte(state.SeqLocal>>16))
	data = append(data, byte(state.SeqLocal>>24))
	data = append(data, byte(state.SeqLocal>>32))
	data = append(data, byte(state.SeqLocal>>40))
	data = append(data, byte(state.SeqLocal>>48))
	data = append(data, byte(state.SeqLocal>>56))

	return data, nil
}

// RestoreState restores connection state from persisted data
func (sm *StateManager) RestoreState(id string, data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("invalid state data")
	}

	seqLocal := uint64(data[0]) |
		uint64(data[1])<<8 |
		uint64(data[2])<<16 |
		uint64(data[3])<<24 |
		uint64(data[4])<<32 |
		uint64(data[5])<<40 |
		uint64(data[6])<<48 |
		uint64(data[7])<<56

	sm.UpdateState(id, func(state *ConnectionState) {
		state.SeqLocal = seqLocal
	})

	return nil
}
