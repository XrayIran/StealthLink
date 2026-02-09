package mux

import (
	"net"

	"stealthlink/internal/transport"
)

// Limiter bounds the total number of concurrent streams within a process.
// If max is <= 0, it is a no-op.
type Limiter struct {
	sem chan struct{}
}

func NewLimiter(max int) *Limiter {
	if max <= 0 {
		return nil
	}
	return &Limiter{sem: make(chan struct{}, max)}
}

// Acquire reserves one slot. No-op when limiter is nil.
func (l *Limiter) Acquire() {
	if l == nil {
		return
	}
	l.sem <- struct{}{}
}

// TryAcquire attempts to reserve a slot without blocking. Returns false if limit reached.
func (l *Limiter) TryAcquire() bool {
	if l == nil {
		return true
	}
	select {
	case l.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees a slot. Safe to call multiple times.
func (l *Limiter) Release() {
	if l == nil {
		return
	}
	select {
	case <-l.sem:
	default:
	}
}

// WrapSession decorates a transport.Session so that each stream
// acquisition counts against the limiter and is released when the
// stream is closed.
func WrapSession(sess transport.Session, l *Limiter) transport.Session {
	if l == nil {
		return sess
	}
	return &limitedSession{Session: sess, limiter: l}
}

type limitedSession struct {
	transport.Session
	limiter *Limiter
}

func (s *limitedSession) OpenStream() (net.Conn, error) {
	s.limiter.Acquire()
	c, err := s.Session.OpenStream()
	if err != nil {
		s.limiter.Release()
		return nil, err
	}
	return &limitedConn{Conn: c, limiter: s.limiter}, nil
}

func (s *limitedSession) AcceptStream() (net.Conn, error) {
	s.limiter.Acquire()
	c, err := s.Session.AcceptStream()
	if err != nil {
		s.limiter.Release()
		return nil, err
	}
	return &limitedConn{Conn: c, limiter: s.limiter}, nil
}

type limitedConn struct {
	net.Conn
	limiter *Limiter
	closed  bool
}

func (c *limitedConn) Close() error {
	if !c.closed {
		c.closed = true
		c.limiter.Release()
	}
	return c.Conn.Close()
}
