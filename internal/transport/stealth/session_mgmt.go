// Package stealth provides session management improvements including
// exponential backoff (from chisel) and session scavenger (from kcptun).
package stealth

import (
	"context"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"
)

// BackoffConfig configures exponential backoff behavior
type BackoffConfig struct {
	Initial    time.Duration // Initial backoff duration
	Max        time.Duration // Maximum backoff duration
	Multiplier float64       // Backoff multiplier
	Jitter     bool          // Add random jitter
}

// DefaultBackoffConfig returns a default backoff configuration
func DefaultBackoffConfig() *BackoffConfig {
	return &BackoffConfig{
		Initial:    100 * time.Millisecond,
		Max:        30 * time.Second,
		Multiplier: 2.0,
		Jitter:     true,
	}
}

// Backoff implements exponential backoff for connection retries
type Backoff struct {
	config  *BackoffConfig
	current time.Duration
	attempt int
	mu      sync.Mutex
}

// NewBackoff creates a new exponential backoff
func NewBackoff(config *BackoffConfig) *Backoff {
	if config == nil {
		config = DefaultBackoffConfig()
	}
	return &Backoff{
		config:  config,
		current: config.Initial,
		attempt: 0,
	}
}

// Next returns the next backoff duration
func (b *Backoff) Next() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.attempt++

	// Calculate backoff with exponential increase
	backoff := b.current
	if b.config.Multiplier > 0 {
		next := time.Duration(float64(b.current) * b.config.Multiplier)
		if next > b.config.Max {
			next = b.config.Max
		}
		b.current = next
	}

	// Add jitter to avoid thundering herd
	if b.config.Jitter {
		jitter := time.Duration(rand.Float64() * float64(backoff) * 0.1)
		backoff = backoff + jitter
	}

	if backoff > b.config.Max {
		return b.config.Max
	}
	return backoff
}

// Reset resets the backoff to initial state
func (b *Backoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.current = b.config.Initial
	b.attempt = 0
}

// Current returns the current backoff duration without incrementing
func (b *Backoff) Current() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current
}

// Attempts returns the number of backoff attempts
func (b *Backoff) Attempts() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.attempt
}

// SessionManager manages transport sessions with scavenger and health checking
type SessionManager struct {
	sessions    map[string]*managedSession
	mu          sync.RWMutex
	scavenger   *Scavenger
	backoffPool map[string]*Backoff
	backoffMu   sync.Mutex
}

// managedSession wraps a transport session with metadata
type managedSession struct {
	session    transport.Session
	id         string
	createdAt  time.Time
	lastUsed   time.Time
	useCount   atomic.Int64
	idleCount  atomic.Int64
	closed     atomic.Bool
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	sm := &SessionManager{
		sessions:    make(map[string]*managedSession),
		backoffPool: make(map[string]*Backoff),
	}
	return sm
}

// StartScavenger starts the session scavenger with the given interval
func (sm *SessionManager) StartScavenger(interval time.Duration, idleThreshold time.Duration) {
	if sm.scavenger != nil {
		return // Already started
	}

	sm.scavenger = &Scavenger{
		manager:       sm,
		interval:      interval,
		idleThreshold: idleThreshold,
		stopCh:        make(chan struct{}),
	}

	go sm.scavenger.run()
}

// StopScavenger stops the session scavenger
func (sm *SessionManager) StopScavenger() {
	if sm.scavenger != nil {
		sm.scavenger.stop()
		sm.scavenger = nil
	}
}

// AddSession adds a session to the manager
func (sm *SessionManager) AddSession(id string, session transport.Session) *managedSession {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Close existing session with same ID
	if existing, ok := sm.sessions[id]; ok {
		existing.Close()
	}

	ms := &managedSession{
		session:   session,
		id:        id,
		createdAt: time.Now(),
		lastUsed:  time.Now(),
	}
	sm.sessions[id] = ms

	// Reset backoff for this session
	sm.backoffMu.Lock()
	delete(sm.backoffPool, id)
	sm.backoffMu.Unlock()

	return ms
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(id string) (*managedSession, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	ms, ok := sm.sessions[id]
	if ok && !ms.closed.Load() {
		ms.lastUsed = time.Now()
		ms.useCount.Add(1)
		return ms, true
	}
	return nil, false
}

// RemoveSession removes a session from the manager
func (sm *SessionManager) RemoveSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if ms, ok := sm.sessions[id]; ok {
		ms.Close()
		delete(sm.sessions, id)
	}
}

// GetBackoff gets or creates a backoff for the given ID
func (sm *SessionManager) GetBackoff(id string, config *BackoffConfig) *Backoff {
	sm.backoffMu.Lock()
	defer sm.backoffMu.Unlock()

	if b, ok := sm.backoffPool[id]; ok {
		return b
	}

	b := NewBackoff(config)
	sm.backoffPool[id] = b
	return b
}

// ResetBackoff resets the backoff for the given ID
func (sm *SessionManager) ResetBackoff(id string) {
	sm.backoffMu.Lock()
	defer sm.backoffMu.Unlock()

	if b, ok := sm.backoffPool[id]; ok {
		b.Reset()
	}
}

// GetStats returns session manager statistics
func (sm *SessionManager) GetStats() SessionStats {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	stats := SessionStats{
		TotalSessions: len(sm.sessions),
		Sessions:      make(map[string]SessionInfo),
	}

	for id, ms := range sm.sessions {
		stats.Sessions[id] = SessionInfo{
			CreatedAt:   ms.createdAt,
			LastUsed:    ms.lastUsed,
			UseCount:    ms.useCount.Load(),
			IdleCount:   ms.idleCount.Load(),
			IsClosed:    ms.closed.Load(),
			IdleTime:    time.Since(ms.lastUsed),
		}
	}

	return stats
}

// SessionStats holds session manager statistics
type SessionStats struct {
	TotalSessions int
	Sessions      map[string]SessionInfo
}

// SessionInfo holds information about a managed session
type SessionInfo struct {
	CreatedAt time.Time
	LastUsed  time.Time
	UseCount  int64
	IdleCount int64
	IsClosed  bool
	IdleTime  time.Duration
}

// Close closes the session manager and all managed sessions
func (sm *SessionManager) Close() error {
	sm.StopScavenger()

	sm.mu.Lock()
	defer sm.mu.Unlock()

	for _, ms := range sm.sessions {
		ms.Close()
	}
	sm.sessions = make(map[string]*managedSession)

	return nil
}

// Scavenger periodically cleans up idle sessions
type Scavenger struct {
	manager       *SessionManager
	interval      time.Duration
	idleThreshold time.Duration
	stopCh        chan struct{}
	stopped       atomic.Bool
}

// run runs the scavenger loop
func (s *Scavenger) run() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.scavenge()
		case <-s.stopCh:
			return
		}
	}
}

// scavenge removes idle sessions
func (s *Scavenger) scavenge() {
	s.manager.mu.Lock()
	defer s.manager.mu.Unlock()

	now := time.Now()
	for id, ms := range s.manager.sessions {
		if ms.closed.Load() {
			delete(s.manager.sessions, id)
			continue
		}

		idle := now.Sub(ms.lastUsed)
		if idle > s.idleThreshold {
			ms.idleCount.Add(1)

			// Close session if it's been idle too long
			if idle > s.idleThreshold*2 {
				ms.Close()
				delete(s.manager.sessions, id)
			}
		}
	}
}

// stop stops the scavenger
func (s *Scavenger) stop() {
	if s.stopped.CompareAndSwap(false, true) {
		close(s.stopCh)
	}
}

// Close closes the managed session
func (ms *managedSession) Close() {
	if ms.closed.CompareAndSwap(false, true) {
		if ms.session != nil {
			_ = ms.session.Close()
		}
	}
}

// Session returns the underlying transport session
func (ms *managedSession) Session() transport.Session {
	return ms.session
}

// ID returns the session ID
func (ms *managedSession) ID() string {
	return ms.id
}

// CreatedAt returns the session creation time
func (ms *managedSession) CreatedAt() time.Time {
	return ms.createdAt
}

// LastUsed returns the last usage time
func (ms *managedSession) LastUsed() time.Time {
	return ms.lastUsed
}

// UseCount returns the number of times the session was used
func (ms *managedSession) UseCount() int64 {
	return ms.useCount.Load()
}

// IsClosed returns true if the session is closed
func (ms *managedSession) IsClosed() bool {
	return ms.closed.Load()
}

// RetryDialer wraps a dialer with exponential backoff retry logic
type RetryDialer struct {
	dialer transport.Dialer
	config *BackoffConfig
	maxRetries int
}

// NewRetryDialer creates a new retry dialer
func NewRetryDialer(dialer transport.Dialer, config *BackoffConfig, maxRetries int) *RetryDialer {
	if maxRetries <= 0 {
		maxRetries = 3
	}
	return &RetryDialer{
		dialer:     dialer,
		config:     config,
		maxRetries: maxRetries,
	}
}

// Dial dials with exponential backoff retry
func (d *RetryDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	backoff := NewBackoff(d.config)

	var lastErr error
	for attempt := 0; attempt < d.maxRetries; attempt++ {
		session, err := d.dialer.Dial(ctx, addr)
		if err == nil {
			return session, nil
		}
		lastErr = err

		// Don't retry on context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Wait before retry (except on last attempt)
		if attempt < d.maxRetries-1 {
			delay := backoff.Next()
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
	}

	return nil, lastErr
}
