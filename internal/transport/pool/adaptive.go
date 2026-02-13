package pool

import (
	"context"
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
	"stealthlink/internal/transport"
)

// PoolMode defines the scaling aggressiveness of the pool.
type PoolMode string

const (
	PoolModeNormal     PoolMode = "normal"
	PoolModeAggressive PoolMode = "aggressive"
)

// PoolConfig configures the adaptive connection pool.
type PoolConfig struct {
	Mode         PoolMode      `yaml:"mode"`
	MinSize      int           `yaml:"min_size"`
	MaxSize      int           `yaml:"max_size"`
	CooldownSecs int           `yaml:"cooldown_secs"`
	DrainTimeout time.Duration `yaml:"drain_timeout"`
}

// ApplyDefaults sets default values for PoolConfig.
func (c *PoolConfig) ApplyDefaults() {
	if c.MinSize <= 0 {
		c.MinSize = 2
	}
	if c.MaxSize <= 0 {
		c.MaxSize = 32
	}
	if c.MaxSize < c.MinSize {
		c.MaxSize = c.MinSize
	}
	if c.CooldownSecs <= 0 {
		c.CooldownSecs = 30
	}
	if c.DrainTimeout <= 0 {
		c.DrainTimeout = 60 * time.Second
	}
	if c.Mode == "" {
		c.Mode = PoolModeNormal
	}
}

// pooledSession wraps a transport.Session with usage tracking.
type pooledSession struct {
	transport.Session
	pool       *AdaptivePool
	id         uint64
	createdAt  time.Time
	lastUsed   atomic.Value // time.Time
	inUse      atomic.Bool
	draining   atomic.Bool
	drainStart time.Time
}

func (s *pooledSession) Close() error {
	s.pool.release(s)
	return nil
}

// AdaptivePool implements an auto-scaling connection pool.
type AdaptivePool struct {
	config PoolConfig
	dialer transport.Dialer
	addr   string

	mu          sync.RWMutex
	conns       []*pooledSession
	nextID      uint64
	lastAdjust  time.Time
	closed      atomic.Bool
	activeCount atomic.Int64
	utilWindow  []float64
	utilMu      sync.Mutex

	stopCh chan struct{}
}

// NewAdaptivePool creates a new adaptive connection pool.
func NewAdaptivePool(config PoolConfig, dialer transport.Dialer, addr string) *AdaptivePool {
	config.ApplyDefaults()
	p := &AdaptivePool{
		config: config,
		dialer: dialer,
		addr:   addr,
		conns:  make([]*pooledSession, 0, config.MaxSize),
		stopCh: make(chan struct{}),
	}

	// Initialize with min size
	for i := 0; i < config.MinSize; i++ {
		p.dialNew(context.Background())
	}

	go p.maintainer()
	return p
}

func (p *AdaptivePool) dialNew(ctx context.Context) {
	session, err := p.dialer.Dial(ctx, p.addr)
	if err != nil {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	ps := &pooledSession{
		Session:   session,
		pool:      p,
		id:        atomic.AddUint64(&p.nextID, 1),
		createdAt: time.Now(),
	}
	ps.lastUsed.Store(time.Now())
	p.conns = append(p.conns, ps)
	metrics.SetPoolSize(int64(len(p.conns)))
}

func (p *AdaptivePool) maintainer() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.adjust()
		case <-p.stopCh:
			return
		}
	}
}

func (p *AdaptivePool) adjust() {
	p.mu.Lock()
	currentSize := len(p.conns)
	active := p.activeCount.Load()
	p.mu.Unlock()

	utilization := 0.0
	if currentSize > 0 {
		utilization = float64(active) / float64(currentSize)
	}

	metrics.SetPoolUtilization(utilization)

	if time.Since(p.lastAdjust) < time.Duration(p.config.CooldownSecs)*time.Second {
		return
	}

	var a, b, x, y float64
	if p.config.Mode == PoolModeAggressive {
		a, b, x, y = 1, 2, 0, 0.75
	} else {
		a, b, x, y = 4, 5, 3, 4.0
	}

	// target = max(min_size, min(max_size, a + b * utilization^y + x))
	target := a + b*math.Pow(utilization, y) + x
	targetInt := int(math.Max(float64(p.config.MinSize), math.Min(float64(p.config.MaxSize), target)))

	p.mu.Lock()
	defer p.mu.Unlock()

	if targetInt > currentSize && utilization > 0.8 {
		// Scale up
		diff := targetInt - currentSize
		maxStep := int(math.Max(1, float64(currentSize)*0.25))
		if diff > maxStep {
			diff = maxStep
		}

		for i := 0; i < diff; i++ {
			go p.dialNew(context.Background())
		}
		p.lastAdjust = time.Now()
		metrics.IncPoolAdjustment("up")
		log.Printf("[Pool] Connection pool adjusted: size=%d, utilization=%.2f%% (scaled up)", currentSize+diff, utilization*100)
	} else if targetInt < currentSize && utilization < 0.3 {
		// Scale down
		diff := currentSize - targetInt
		maxStep := int(math.Max(1, float64(currentSize)*0.25))
		if diff > maxStep {
			diff = maxStep
		}

		// Mark for drain
		marked := 0
		for _, c := range p.conns {
			if !c.draining.Load() && marked < diff {
				c.draining.Store(true)
				c.drainStart = time.Now()
				marked++
			}
		}

		if marked > 0 {
			p.lastAdjust = time.Now()
			metrics.IncPoolAdjustment("down")
			log.Printf("[Pool] Connection pool adjusted: size=%d, utilization=%.2f%% (scaled down)", currentSize-marked, utilization*100)
		}
	}

	// Scavenge drained or expired connections
	p.scavenge()
}

func (p *AdaptivePool) scavenge() {
	// Must be called with lock held
	var active []*pooledSession
	for _, c := range p.conns {
		shouldClose := false
		if c.draining.Load() {
			if !c.inUse.Load() || time.Since(c.drainStart) > p.config.DrainTimeout {
				shouldClose = true
			}
		}

		if shouldClose {
			c.Session.Close()
		} else {
			active = append(active, c)
		}
	}
	p.conns = active
	metrics.SetPoolSize(int64(len(p.conns)))
}

// Get finds an available session or dials a new one if permitted.
func (p *AdaptivePool) Get(ctx context.Context) (transport.Session, error) {
	if p.closed.Load() {
		return nil, transport.ErrPoolClosed
	}

	p.mu.RLock()
	// Try to find an idle non-draining connection
	for _, c := range p.conns {
		if !c.inUse.Load() && !c.draining.Load() {
			if c.inUse.CompareAndSwap(false, true) {
				c.lastUsed.Store(time.Now())
				p.activeCount.Add(1)
				p.mu.RUnlock()
				return c, nil
			}
		}
	}
	p.mu.RUnlock()

	// If no idle connection, check if we can dial new one (temporary burst)
	// Actually the requirements say target determines the size.
	// But if everything is busy, we might want to dial anyway if below max.

	p.mu.Lock()
	if len(p.conns) < p.config.MaxSize {
		p.mu.Unlock()
		p.dialNew(ctx)
		return p.Get(ctx)
	}
	p.mu.Unlock()

	// Wait for one to become available
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			p.mu.RLock()
			for _, c := range p.conns {
				if !c.inUse.Load() && !c.draining.Load() {
					if c.inUse.CompareAndSwap(false, true) {
						c.lastUsed.Store(time.Now())
						p.activeCount.Add(1)
						p.mu.RUnlock()
						return c, nil
					}
				}
			}
			p.mu.RUnlock()
		}
	}
}

func (p *AdaptivePool) release(s *pooledSession) {
	if s.inUse.CompareAndSwap(true, false) {
		p.activeCount.Add(-1)
		s.lastUsed.Store(time.Now())
	}
}

// Close closes the pool.
func (p *AdaptivePool) Close() error {
	if p.closed.CompareAndSwap(false, true) {
		close(p.stopCh)
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, c := range p.conns {
			c.Session.Close()
		}
		p.conns = nil
		return nil
	}
	return nil
}

// Dialer wrapper
type AdaptiveDialer struct {
	pools  sync.Map // addr -> *AdaptivePool
	dialer transport.Dialer
	config PoolConfig
}

func NewAdaptiveDialer(config PoolConfig, dialer transport.Dialer) *AdaptiveDialer {
	return &AdaptiveDialer{
		dialer: dialer,
		config: config,
	}
}

func (d *AdaptiveDialer) Dial(ctx context.Context, addr string) (transport.Session, error) {
	p, ok := d.pools.Load(addr)
	if !ok {
		p, _ = d.pools.LoadOrStore(addr, NewAdaptivePool(d.config, d.dialer, addr))
	}
	return p.(*AdaptivePool).Get(ctx)
}

func (d *AdaptiveDialer) Close() error {
	d.pools.Range(func(key, value any) bool {
		value.(*AdaptivePool).Close()
		return true
	})
	return nil
}
