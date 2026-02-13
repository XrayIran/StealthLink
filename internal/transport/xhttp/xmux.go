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

	"stealthlink/internal/metrics"
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

	// CMaxReuseTimes caps how many borrow/return cycles a connection can serve (default: 32).
	CMaxReuseTimes int `yaml:"c_max_reuse_times"`

	// HMaxRequestTimes caps request count per pooled connection before retirement (default: 100).
	HMaxRequestTimes int `yaml:"h_max_request_times"`

	// HMaxReusableSecs caps the wall-clock lifetime for a pooled connection (default: 3600).
	HMaxReusableSecs int `yaml:"h_max_reusable_secs"`

	// DrainTimeout is the maximum duration to wait for a draining connection (default: 30s).
	DrainTimeout time.Duration `yaml:"drain_timeout"`

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
	if c.CMaxReuseTimes <= 0 {
		c.CMaxReuseTimes = 32
	}
	if c.HMaxRequestTimes <= 0 {
		c.HMaxRequestTimes = 100
	}
	if c.HMaxReusableSecs <= 0 {
		c.HMaxReusableSecs = 3600
	}
	if c.DrainTimeout <= 0 {
		c.DrainTimeout = 30 * time.Second
	}
}

// pooledConn wraps a transport.Session for connection pooling.
type pooledConn struct {
	session      transport.Session
	lastUsed     time.Time
	createdAt    time.Time
	inUse        int32
	id           uint64
	requestCount uint64
	reuseCount   uint64
	draining     int32
	drainStart   time.Time
}

func (p *pooledConn) markUsed() {
	atomic.StoreInt32(&p.inUse, 1)
	p.lastUsed = time.Now()
	atomic.AddUint64(&p.reuseCount, 1)
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

func (p *pooledConn) isDraining() bool {
	return atomic.LoadInt32(&p.draining) == 1
}

func (p *pooledConn) markDraining() {
	if atomic.CompareAndSwapInt32(&p.draining, 0, 1) {
		p.drainStart = time.Now()
	}
}

func (p *pooledConn) shouldRetire(cfg XMuxConfig) bool {
	if cfg.CMaxReuseTimes > 0 && int(atomic.LoadUint64(&p.reuseCount)) >= cfg.CMaxReuseTimes {
		return true
	}
	if cfg.HMaxRequestTimes > 0 && int(atomic.LoadUint64(&p.requestCount)) >= cfg.HMaxRequestTimes {
		return true
	}
	if cfg.HMaxReusableSecs > 0 && time.Since(p.createdAt) >= time.Duration(cfg.HMaxReusableSecs)*time.Second {
		return true
	}
	return false
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

// Get retrieves a connection from the pool or creates a new one.
func (p *XMuxPool) Get(ctx context.Context, addr string) (transport.Session, error) {
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

	// If we have room (counting only non-draining), create a new connection
	nonDrainingCount := 0
	for _, c := range p.conns {
		if !c.isDraining() {
			nonDrainingCount++
		}
	}

	if nonDrainingCount < p.config.MaxConnections {
		session, err := p.dialNew(ctx, addr)
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

	return p.Get(ctx, addr)
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
			if pc.isDraining() {
				stats.Draining++
			} else {
				stats.Idle++
			}
		} else {
			stats.Active++
		}
	}

	return stats
}

func (p *XMuxPool) findIdle() transport.Session {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Collect healthy idle connections
	idle := make([]*pooledConn, 0, len(p.conns))
	for _, pc := range p.conns {
		if pc.isIdle() && !pc.isExpired(p.config.ReuseTime) && !pc.isDraining() {
			if pc.shouldRetire(p.config) {
				pc.markDraining()
				metrics.IncXmuxRotation(p.getRotationReason(pc))
				continue
			}
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
		// Pick least recently used idle connection
		oldest := time.Now()
		for _, pc := range idle {
			if pc.lastUsed.Before(oldest) {
				oldest = pc.lastUsed
				selected = pc
			}
		}
	default: // XMuxModeRandom
		// Pick random idle connection
		selected = idle[time.Now().UnixNano()%int64(len(idle))]
	}

	if selected != nil {
		selected.markUsed()
		metrics.IncXmuxReuse()
		return &pooledSession{pool: p, pc: selected, Session: selected.session}
	}

	return nil
}

func (p *XMuxPool) getRotationReason(pc *pooledConn) string {
	if p.config.CMaxReuseTimes > 0 && int(atomic.LoadUint64(&pc.reuseCount)) >= p.config.CMaxReuseTimes {
		return "reuse_limit"
	}
	if p.config.HMaxRequestTimes > 0 && int(atomic.LoadUint64(&pc.requestCount)) >= p.config.HMaxRequestTimes {
		return "request_limit"
	}
	if p.config.HMaxReusableSecs > 0 && time.Since(pc.createdAt) >= time.Duration(p.config.HMaxReusableSecs)*time.Second {
		return "age_limit"
	}
	return "unknown"
}

func (p *XMuxPool) dialNew(ctx context.Context, addr string) (transport.Session, error) {
	// For the Dial call, we use a timeout
	dialCtx, cancel := context.WithTimeout(ctx, p.config.ConnectTimeout)
	defer cancel()

	// But the session itself should outlive the dial timeout.
	// We use the original ctx but stripped of cancellation for the session itself
	// if the transport binds it (like h2mux does).
	// Starting Go 1.21 we can use context.WithoutCancel(ctx)
	// For now, let's use context.Background() but propagate values if any.
	
	session, err := p.dialer.Dial(dialCtx, addr)
	if err != nil {
		return nil, err
	}

	pc := &pooledConn{
		session:   session,
		lastUsed:  time.Now(),
		createdAt: time.Now(),
		id:        atomic.AddUint64(&p.nextID, 1),
	}
	pc.markUsed()

	p.conns = append(p.conns, pc)
	metrics.IncXmuxActiveConnections()

	return &pooledSession{pool: p, pc: pc, Session: session}, nil
}

func (p *XMuxPool) selectByMode() *pooledConn {
	if len(p.conns) == 0 {
		return nil
	}

	// Filter out draining connections
	available := make([]*pooledConn, 0, len(p.conns))
	for _, pc := range p.conns {
		if !pc.isDraining() {
			available = append(available, pc)
		}
	}

	if len(available) == 0 {
		return nil
	}

	var selected *pooledConn
	switch p.config.Mode {
	case XMuxModeRoundRobin:
		// Find least recently used among available
		oldest := time.Now()
		for _, pc := range available {
			if pc.lastUsed.Before(oldest) {
				oldest = pc.lastUsed
				selected = pc
			}
		}
	default: // XMuxModeRandom
		selected = available[time.Now().UnixNano()%int64(len(available))]
	}

	if selected != nil && selected.shouldRetire(p.config) {
		selected.markDraining()
		metrics.IncXmuxRotation(p.getRotationReason(selected))
		// We can still use it for this one last borrow, but it's now draining
	}

	return selected
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
		shouldClose := false
		if pc.isIdle() {
			if pc.isExpired(p.config.ReuseTime) || pc.isDraining() || pc.shouldRetire(p.config) {
				shouldClose = true
			}
		} else if pc.isDraining() && time.Since(pc.drainStart) > p.config.DrainTimeout {
			// Enforce drain timeout even if not idle
			shouldClose = true
		} else if !pc.isDraining() && pc.shouldRetire(p.config) {
			// Proactively mark as draining if it should retire
			pc.markDraining()
			metrics.IncXmuxRotation(p.getRotationReason(pc))
		}

		if shouldClose {
			// Close connection
			pc.session.Close()
			metrics.DecXmuxActiveConnections()
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
		ps.pc.markIdle()
		// Don't actually close, just return to pool
		return nil
	}
	return nil
}

func (ps *pooledSession) OpenStream() (net.Conn, error) {
	conn, err := ps.Session.OpenStream()
	if err == nil {
		atomic.AddUint64(&ps.pc.requestCount, 1)
	}
	return conn, err
}

func (ps *pooledSession) LocalAddr() net.Addr {
	return ps.Session.LocalAddr()
}

func (ps *pooledSession) RemoteAddr() net.Addr {
	return ps.Session.RemoteAddr()
}

// XMuxStats contains pool statistics.
type XMuxStats struct {
	Total    int
	Active   int
	Idle     int
	Draining int
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
	return d.pool.Get(ctx, addr)
}

// Close closes the dialer and its pool.
func (d *XMuxDialer) Close() error {
	return d.pool.Close()
}

// Stats returns pool statistics.
func (d *XMuxDialer) Stats() XMuxStats {
	return d.pool.Stats()
}
