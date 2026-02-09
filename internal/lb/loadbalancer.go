// Package lb provides multi-egress load balancing for scaling and redundancy.
package lb

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Strategy represents the load balancing strategy.
type Strategy string

const (
	RoundRobin   Strategy = "round-robin"
	LeastConn    Strategy = "least-conn"
	Weighted     Strategy = "weighted"
	Random       Strategy = "random"
	Hash         Strategy = "hash"
)

// Target represents a backend target.
type Target struct {
	Address    string
	Weight     int
	Active     bool
	Latency    time.Duration
	Conns      int64
	Failures   int64
	LastCheck  time.Time
}

// LoadBalancer distributes connections across multiple targets.
type LoadBalancer struct {
	targets       []*Target
	strategy      Strategy
	currentIndex  uint64
	resetInterval time.Duration
	mu            sync.RWMutex
	checkInterval time.Duration
	checkTimeout  time.Duration
}

// Config holds load balancer configuration.
type Config struct {
	Targets       []string
	Strategy      Strategy
	ResetInterval time.Duration
	CheckInterval time.Duration
	CheckTimeout  time.Duration
}

// New creates a new load balancer.
func New(cfg *Config) (*LoadBalancer, error) {
	if len(cfg.Targets) == 0 {
		return nil, fmt.Errorf("no targets configured")
	}

	if cfg.Strategy == "" {
		cfg.Strategy = RoundRobin
	}
	if cfg.ResetInterval == 0 {
		cfg.ResetInterval = 1 * time.Hour
	}
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 30 * time.Second
	}
	if cfg.CheckTimeout == 0 {
		cfg.CheckTimeout = 5 * time.Second
	}

	targets := make([]*Target, len(cfg.Targets))
	for i, addr := range cfg.Targets {
		targets[i] = &Target{
			Address: addr,
			Weight:  1,
			Active:  true,
		}
	}

	lb := &LoadBalancer{
		targets:       targets,
		strategy:      cfg.Strategy,
		resetInterval: cfg.ResetInterval,
		checkInterval: cfg.CheckInterval,
		checkTimeout:  cfg.CheckTimeout,
	}

	return lb, nil
}

// Start starts the health check and reset loops.
func (lb *LoadBalancer) Start(ctx context.Context) {
	// Health check loop
	go func() {
		ticker := time.NewTicker(lb.checkInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				lb.healthCheck()
			case <-ctx.Done():
				return
			}
		}
	}()

	// Reset loop
	go func() {
		ticker := time.NewTicker(lb.resetInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				lb.reset()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Next returns the next target based on the strategy.
func (lb *LoadBalancer) Next(key string) (*Target, error) {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	// Filter active targets
	var active []*Target
	for _, t := range lb.targets {
		if t.Active {
			active = append(active, t)
		}
	}

	if len(active) == 0 {
		return nil, fmt.Errorf("no active targets")
	}

	switch lb.strategy {
	case RoundRobin:
		idx := atomic.AddUint64(&lb.currentIndex, 1) % uint64(len(active))
		return active[idx], nil

	case LeastConn:
		var least *Target
		for _, t := range active {
			if least == nil || t.Conns < least.Conns {
				least = t
			}
		}
		return least, nil

	case Weighted:
		totalWeight := 0
		for _, t := range active {
			totalWeight += t.Weight
		}
		if totalWeight == 0 {
			return active[0], nil
		}

		r := randInt(totalWeight)
		for _, t := range active {
			r -= t.Weight
			if r < 0 {
				return t, nil
			}
		}
		return active[0], nil

	case Random:
		return active[randInt(len(active))], nil

	case Hash:
		idx := hashString(key) % uint64(len(active))
		return active[idx], nil

	default:
		return active[0], nil
	}
}

// healthCheck performs health checks on all targets.
func (lb *LoadBalancer) healthCheck() {
	lb.mu.RLock()
	targets := make([]*Target, len(lb.targets))
	copy(targets, lb.targets)
	lb.mu.RUnlock()

	for _, t := range targets {
		go func(target *Target) {
			active := lb.checkTarget(target)
			lb.mu.Lock()
			target.Active = active
			target.LastCheck = time.Now()
			lb.mu.Unlock()
		}(t)
	}
}

// checkTarget checks if a target is healthy.
func (lb *LoadBalancer) checkTarget(t *Target) bool {
	conn, err := net.DialTimeout("tcp", t.Address, lb.checkTimeout)
	if err != nil {
		atomic.AddInt64(&t.Failures, 1)
		return false
	}
	conn.Close()
	return true
}

// reset clears detection state.
func (lb *LoadBalancer) reset() {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for _, t := range lb.targets {
		t.Failures = 0
		t.Conns = 0
	}
}

// AddTarget adds a new target.
func (lb *LoadBalancer) AddTarget(addr string, weight int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	lb.targets = append(lb.targets, &Target{
		Address: addr,
		Weight:  weight,
		Active:  true,
	})
}

// RemoveTarget removes a target.
func (lb *LoadBalancer) RemoveTarget(addr string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	for i, t := range lb.targets {
		if t.Address == addr {
			lb.targets = append(lb.targets[:i], lb.targets[i+1:]...)
			return
		}
	}
}

// Targets returns a copy of all targets.
func (lb *LoadBalancer) Targets() []*Target {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	result := make([]*Target, len(lb.targets))
	copy(result, lb.targets)
	return result
}

// RecordConnection records a new connection to a target.
func (lb *LoadBalancer) RecordConnection(t *Target) {
	atomic.AddInt64(&t.Conns, 1)
}

// RecordDisconnection records a disconnection from a target.
func (lb *LoadBalancer) RecordDisconnection(t *Target) {
	atomic.AddInt64(&t.Conns, -1)
}

// hashString generates a hash from a string.
func hashString(s string) uint64 {
	var h uint64 = 5381
	for i := 0; i < len(s); i++ {
		h = ((h << 5) + h) + uint64(s[i])
	}
	return h
}

// randInt returns a random integer in [0, max).
func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	return int(time.Now().UnixNano() % int64(max))
}

// Dialer is a load balancing dialer.
type Dialer struct {
	lb *LoadBalancer
}

// NewDialer creates a new load balancing dialer.
func NewDialer(lb *LoadBalancer) *Dialer {
	return &Dialer{lb: lb}
}

// Dial connects to a target selected by the load balancer.
func (d *Dialer) Dial(ctx context.Context, key string) (net.Conn, error) {
	target, err := d.lb.Next(key)
	if err != nil {
		return nil, err
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target.Address)
	if err != nil {
		return nil, err
	}

	d.lb.RecordConnection(target)

	return &connWrapper{
		Conn:   conn,
		lb:     d.lb,
		target: target,
	}, nil
}

// connWrapper wraps a connection to track disconnections.
type connWrapper struct {
	net.Conn
	lb     *LoadBalancer
	target *Target
	closed bool
	mu     sync.Mutex
}

// Close closes the connection and records disconnection.
func (c *connWrapper) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}
	c.closed = true

	c.lb.RecordDisconnection(c.target)
	return c.Conn.Close()
}
