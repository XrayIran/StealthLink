package transport

import (
	"net"
	"sync"
	"time"
)

type peerFailState struct {
	failures int
	lastFail time.Time
}

type PeerRateLimiter struct {
	mu          sync.Mutex
	fails       map[string]peerFailState
	maxFailures int
	window      time.Duration
}

func NewPeerRateLimiter(maxFailures int, window time.Duration) *PeerRateLimiter {
	if maxFailures <= 0 {
		maxFailures = 1
	}
	if window <= 0 {
		window = 2 * time.Minute
	}
	return &PeerRateLimiter{
		fails:       make(map[string]peerFailState),
		maxFailures: maxFailures,
		window:      window,
	}
}

func (l *PeerRateLimiter) PeerKey(conn net.Conn) string {
	if conn == nil || conn.RemoteAddr() == nil {
		return ""
	}
	return conn.RemoteAddr().String()
}

func (l *PeerRateLimiter) IsLimited(conn net.Conn) bool {
	if l == nil {
		return false
	}
	key := l.PeerKey(conn)
	if key == "" {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	state, ok := l.fails[key]
	if !ok {
		return false
	}
	if time.Since(state.lastFail) > l.window {
		delete(l.fails, key)
		return false
	}
	return state.failures >= l.maxFailures
}

func (l *PeerRateLimiter) RecordFailure(conn net.Conn) {
	if l == nil {
		return
	}
	key := l.PeerKey(conn)
	if key == "" {
		return
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	state := l.fails[key]
	if time.Since(state.lastFail) > l.window {
		state.failures = 0
	}
	state.failures++
	state.lastFail = now
	l.fails[key] = state
}

func (l *PeerRateLimiter) Clear(conn net.Conn) {
	if l == nil {
		return
	}
	key := l.PeerKey(conn)
	if key == "" {
		return
	}

	l.mu.Lock()
	delete(l.fails, key)
	l.mu.Unlock()
}
