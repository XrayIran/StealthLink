// Package xhttp implements XMux multiplexing for XHTTP transport.
//
// XMux provides efficient connection pooling and reuse for XHTTP modes,
// adapting the multiplexing approach from xray-core's XHTTP implementation.
package xhttp

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/transport"
)

// XMuxConfig configures XMux multiplexing behavior.
type XMuxConfig struct {
	// Enabled enables XMux multiplexing
	Enabled bool `yaml:"enabled"`

	// MaxConnections is the maximum number of concurrent connections per endpoint
	MaxConnections int `yaml:"max_connections"`

	// ReuseTime is how long a connection can be reused after last activity
	ReuseTime time.Duration `yaml:"reuse_time"`

	// ConnectTimeout is the timeout for establishing new connections
	ConnectTimeout time.Duration `yaml:"connect_timeout"`

	// Mode specifies how connections are used: "random" or "round-robin"
	Mode XMuxMode `yaml:"mode"`
}

// XMuxMode defines connection selection mode.
type XMuxMode string

const (
	// XMuxModeRandom selects connections randomly (default, harder to fingerprint)
	XMuxModeRandom XMuxMode = "random"

	// XMuxModeRoundRobin selects connections in round-robin order
	XMuxModeRoundRobin XMuxMode = "round-robin"
)

// ApplyDefaults sets default values.
func (c *XMuxConfig) ApplyDefaults() {
	if c.MaxConnections <= 0 {
		c.MaxConnections = 2
	}
	if c.ReuseTime <= 0 {
		c.ReuseTime = 30 * time.Second
	}
	if c.ConnectTimeout <= 0 {
		c.ConnectTimeout = 10 * time.Second
	}
	if c.Mode == "" {
		c.Mode = XMuxModeRandom
	}
}

// pooledConn wraps a transport.Session for connection pooling.
type pooledConn struct {
	session   transport.Session
	lastUsed  time.Time
	inUse     int32
	id        uint64
	refCount  int32
}

func (p *pooledConn) markUsed() {
	atomic.StoreInt32(&p.inUse, 1)
	p.lastUsed = time.Now()
}

func (p *pooledConn) markIdle() {
	atomic.StoreInt32(&p.inUse, 0)
	p.lastUsed = time.Now()
}

func (p *pooledConn) isIdle() bool {
	return atomic.LoadInt32(&p.inUse) == 0
}

func (p *pooledConn) isExpired(reuseTime time.Duration) bool {
	return time.Since(p.lastUsed) > reuseTime
}

// XMuxPool manages a pool of XHTTP connections.
type XMuxPool struct {
	config    XMuxConfig
	dialer    transport.Dialer
	conns     []*pooledConn
	mu        sync.RWMutex
	nextID    uint64
	closed    int32
	scavenger *time.Ticker
	stopCh    chan struct{}
}

// NewXMuxPool creates a new XMux connection pool.
func NewXMuxPool(config XMuxConfig, dialer transport.Dialer) *XMuxPool {
	config.ApplyDefaults()

	pool := &XMuxPool{
		config:    config,
		dialer:    dialer,
		conns:     make([]*pooledConn, 0, config.MaxConnections),
		stopCh:    make(chan struct{}),
		scavenger: time.NewTicker(5 * time.Second),
	}

	// Start scavenger goroutine
	go pool.scavenge()

	return pool
}

// Get gets a connection from the pool or creates a new one.
func (p *XMuxPool) Get(ctx context.Context) (transport.Session, error) {
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, transport.ErrPoolClosed
	}

	// Try to find an idle connection
	if session := p.findIdle(); session != nil {
		return session, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double-check after acquiring lock
	if atomic.LoadInt32(&p.closed) == 1 {
		return nil, transport.ErrPoolClosed
	}

	// If we have room, create a new connection
	if len(p.conns) < p.config.MaxConnections {
		session, err := p.dialNew(ctx)
		if err != nil {
			return nil, err
		}
		return session, nil
	}

	// Pool is full, select one by mode
	pc := p.selectByMode()
	if pc != nil {
		pc.markUsed()
		return &pooledSession{pool: p, pc: pc, Session: pc.session}, nil
	}

	// All connections are busy, wait a bit and retry
	p.mu.Unlock()
	select {
	case <-time.After(10 * time.Millisecond):
		p.mu.Lock()
	case <-ctx.Done():
		p.mu.Lock()
		return nil, ctx.Err()
	}

	return p.Get(ctx)
}

// Put returns a connection to the pool.
func (p *XMuxPool) Put(session transport.Session) {
	if ps, ok := session.(*pooledSession); ok {
		ps.pc.markIdle()
	}
}

// Close closes the pool and all connections.
func (p *XMuxPool) Close() error {
	if !atomic.CompareAndSwapInt32(&p.closed, 0, 1) {
		return nil
	}

	close(p.stopCh)
	p.scavenger.Stop()

	p.mu.Lock()
	defer p.mu.Unlock()

	var firstErr error
	for _, pc := range p.conns {
		if pc.session != nil {
			if err := pc.session.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	p.conns = p.conns[:0]

	return firstErr
}

// Stats returns pool statistics.
func (p *XMuxPool) Stats() XMuxStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := XMuxStats{
		Total: len(p.conns),
	}

	for _, pc := range p.conns {
		if pc.isIdle() {
			stats.Idle++
		} else {
			stats.Active++
		}
	}

	return stats
}

func (p *XMuxPool) findIdle() transport.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Collect idle connections
	idle := make([]*pooledConn, 0, len(p.conns))
	for _, pc := range p.conns {
		if pc.isIdle() && !pc.isExpired(p.config.ReuseTime) {
			idle = append(idle, pc)
		}
	}

	if len(idle) == 0 {
		return nil
	}

	// Select by mode
	var selected *pooledConn
	switch p.config.Mode {
	case XMuxModeRoundRobin:
		// Simple round-robin based on ID
		minID := uint64(^uint64(0))
		for _, pc := range idle {
			if pc.id < minID {
				minID = pc.id
				selected = pc
			}
		}
	default: // XMuxModeRandom
		// Pick random idle connection
		selected = idle[time.Now().UnixNano()%int64(len(idle))]
	}

	if selected != nil {
		selected.markUsed()
		return &pooledSession{pool: p, pc: selected, Session: selected.session}
	}

	return nil
}

func (p *XMuxPool) dialNew(ctx context.Context) (transport.Session, error) {
	dialCtx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
	defer cancel()

	session, err := p.dialer.Dial(dialCtx, "")
	if err != nil {
		return nil, err
	}

	pc := &pooledConn{
		session:  session,
		lastUsed: time.Now(),
		id:       atomic.AddUint64(&p.nextID, 1),
	}
	pc.markUsed()

	p.conns = append(p.conns, pc)

	return &pooledSession{pool: p, pc: pc, Session: session}, nil
}

func (p *XMuxPool) selectByMode() *pooledConn {
	if len(p.conns) == 0 {
		return nil
	}

	switch p.config.Mode {
	case XMuxModeRoundRobin:
		// Find least recently used
		var selected *pooledConn
		oldest := time.Now()
		for _, pc := range p.conns {
			if pc.lastUsed.Before(oldest) {
				oldest = pc.lastUsed
				selected = pc
			}
		}
		return selected
	default: // XMuxModeRandom
		return p.conns[time.Now().UnixNano()%int64(len(p.conns))]
	}
}

func (p *XMuxPool) scavenge() {
	for {
		select {
		case <-p.scavenger.C:
			p.doScavenge()
		case <-p.stopCh:
			return
		}
	}
}

func (p *XMuxPool) doScavenge() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if atomic.LoadInt32(&p.closed) == 1 {
		return
	}

	active := make([]*pooledConn, 0, len(p.conns))
	for _, pc := range p.conns {
		if pc.isIdle() && pc.isExpired(p.config.ReuseTime) {
			// Close expired connection
			pc.session.Close()
		} else {
			active = append(active, pc)
		}
	}
	p.conns = active
}

// pooledSession wraps a pooled connection to track usage.
type pooledSession struct {
	pool *XMuxPool
	pc   *pooledConn
	transport.Session
	closed int32
}

func (ps *pooledSession) Close() error {
	if atomic.CompareAndSwapInt32(&ps.closed, 0, 1) {
		ps.pool.Put(ps)
		// Don't actually close, just return to pool
		return nil
	}
	return nil
}

func (ps *pooledSession) LocalAddr() net.Addr {
	return ps.Session.LocalAddr()
}

func (ps *pooledSession) RemoteAddr() net.Addr {
	return ps.Session.RemoteAddr()
}

// XMuxStats contains pool statistics.
type XMuxStats struct {
	Total  int
	Active int
	Idle   int
}

// XMuxDialer wraps a dialer with XMux pooling.
type XMuxDialer struct {
	pool *XMuxPool
}

// NewXMuxDialer creates a new XMux-enabled dialer.
func NewXMuxDialer(config XMuxConfig, dialer transport.Dialer) *XMuxDialer {
	return &XMuxDialer{
		pool: NewXMuxPool(config, dialer),
	}
}

// Dial implements transport.Dialer.
func (d *XMuxDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	return d.pool.Get(ctx)
}

// Close closes the dialer and its pool.
func (d *XMuxDialer) Close() error {
	return d.pool.Close()
}

// Stats returns pool statistics.
func (d *XMuxDialer) Stats() XMuxStats {
	return d.pool.Stats()
}
