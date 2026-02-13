package multiport

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/metrics"
)

type PortSelectionMode int

const (
	ModeRandom PortSelectionMode = iota
	ModeRoundRobin
	ModeWeighted
	ModeAdaptive
)

type PortRange struct {
	Start int
	End   int
}

type MultiportDialerConfig struct {
	PortRanges    []PortRange
	SelectionMode PortSelectionMode
	HopInterval   time.Duration
	MaxAttempts   int
	Timeout       time.Duration
	Weights       []int
}

type MultiportDialer struct {
	config       MultiportDialerConfig
	allPorts     []int
	currentIndex atomic.Int64
	portHistory  sync.Map
	connCount    sync.Map
	mu           sync.RWMutex
}

func NewMultiportDialer(cfg MultiportDialerConfig) (*MultiportDialer, error) {
	if len(cfg.PortRanges) == 0 {
		cfg.PortRanges = []PortRange{
			{Start: 1024, End: 65535},
		}
	}
	if cfg.SelectionMode == 0 {
		cfg.SelectionMode = ModeRandom
	}
	if cfg.HopInterval == 0 {
		cfg.HopInterval = 30 * time.Second
	}
	if cfg.MaxAttempts == 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}

	var allPorts []int
	for _, pr := range cfg.PortRanges {
		for port := pr.Start; port <= pr.End; port++ {
			allPorts = append(allPorts, port)
		}
	}

	if len(cfg.Weights) > 0 && len(cfg.Weights) != len(cfg.PortRanges) {
		return nil, fmt.Errorf("weights length must match port ranges length")
	}

	return &MultiportDialer{
		config:   cfg,
		allPorts: allPorts,
	}, nil
}

func (d *MultiportDialer) Dial(ctx context.Context, network, host string) (net.Conn, error) {
	var lastErr error

	for attempt := 0; attempt < d.config.MaxAttempts; attempt++ {
		port := d.selectPort()
		addr := fmt.Sprintf("%s:%d", host, port)

		dialCtx, cancel := context.WithTimeout(ctx, d.config.Timeout)
		var dialer net.Dialer
		conn, err := dialer.DialContext(dialCtx, network, addr)
		cancel()

		if err != nil {
			lastErr = err
			d.recordFailure(port)
			continue
		}

		d.recordSuccess(port)
		metrics.IncTransportSession("multiport")
		return &multiportConn{
			Conn:   conn,
			dialer: d,
			port:   port,
		}, nil
	}

	return nil, fmt.Errorf("all dial attempts failed: %w", lastErr)
}

func (d *MultiportDialer) DialSpecificPort(ctx context.Context, network, host string, port int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	dialCtx, cancel := context.WithTimeout(ctx, d.config.Timeout)
	var dialer net.Dialer
	conn, err := dialer.DialContext(dialCtx, network, addr)
	cancel()

	if err != nil {
		return nil, err
	}

	d.recordSuccess(port)
	metrics.IncTransportSession("multiport")
	return &multiportConn{
		Conn:   conn,
		dialer: d,
		port:   port,
	}, nil
}

func (d *MultiportDialer) selectPort() int {
	switch d.config.SelectionMode {
	case ModeRandom:
		return d.selectRandom()
	case ModeRoundRobin:
		return d.selectRoundRobin()
	case ModeWeighted:
		return d.selectWeighted()
	case ModeAdaptive:
		return d.selectAdaptive()
	default:
		return d.selectRandom()
	}
}

func (d *MultiportDialer) selectRandom() int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(d.allPorts))))
	return d.allPorts[n.Int64()]
}

func (d *MultiportDialer) selectRoundRobin() int {
	idx := d.currentIndex.Add(1) % int64(len(d.allPorts))
	return d.allPorts[idx]
}

func (d *MultiportDialer) selectWeighted() int {
	if len(d.config.Weights) == 0 {
		return d.selectRandom()
	}

	totalWeight := 0
	for _, w := range d.config.Weights {
		totalWeight += w
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(totalWeight)))
	target := int(n.Int64())

	cumWeight := 0
	rangeStart := 0
	for i, w := range d.config.Weights {
		cumWeight += w
		if target < cumWeight {
			pr := d.config.PortRanges[i]
			portOffset := target - (cumWeight - w)
			if portOffset < 0 {
				portOffset = 0
			}
			port := pr.Start + (portOffset % (pr.End - pr.Start + 1))
			return port
		}
		rangeStart += d.config.PortRanges[i].End - d.config.PortRanges[i].Start + 1
	}

	return d.selectRandom()
}

func (d *MultiportDialer) selectAdaptive() int {
	type portStats struct {
		port      int
		successes int
		failures  int
		lastUsed  time.Time
	}

	var candidates []portStats
	now := time.Now()

	for _, port := range d.allPorts {
		var stats portStats
		stats.port = port

		if val, ok := d.portHistory.Load(port); ok {
			h := val.(struct {
				successes int
				failures  int
				lastUsed  time.Time
			})
			stats.successes = h.successes
			stats.failures = h.failures
			stats.lastUsed = h.lastUsed
		}

		if now.Sub(stats.lastUsed) < d.config.HopInterval {
			continue
		}

		candidates = append(candidates, stats)
	}

	if len(candidates) == 0 {
		return d.selectRandom()
	}

	bestScore := -1.0
	bestPort := candidates[0].port

	for _, c := range candidates {
		total := c.successes + c.failures
		if total == 0 {
			return c.port
		}

		successRate := float64(c.successes) / float64(total)
		recencyBonus := 0.0
		if c.lastUsed.IsZero() {
			recencyBonus = 0.1
		}

		score := successRate + recencyBonus
		if score > bestScore {
			bestScore = score
			bestPort = c.port
		}
	}

	return bestPort
}

func (d *MultiportDialer) recordSuccess(port int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	type portStats struct {
		successes int
		failures  int
		lastUsed  time.Time
	}

	val, loaded := d.portHistory.LoadOrStore(port, portStats{successes: 1, lastUsed: time.Now()})

	if loaded {
		stats := val.(portStats)
		stats.successes++
		stats.lastUsed = time.Now()
		d.portHistory.Store(port, stats)
	}
}

func (d *MultiportDialer) recordFailure(port int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	type portStats struct {
		successes int
		failures  int
		lastUsed  time.Time
	}

	val, loaded := d.portHistory.LoadOrStore(port, portStats{failures: 1, lastUsed: time.Now()})

	if loaded {
		stats := val.(portStats)
		stats.failures++
		stats.lastUsed = time.Now()
		d.portHistory.Store(port, stats)
	}
}

func (d *MultiportDialer) GetPortStats(port int) (successes, failures int) {
	val, ok := d.portHistory.Load(port)
	if !ok {
		return 0, 0
	}
	stats := val.(struct {
		successes int
		failures  int
		lastUsed  time.Time
	})
	return stats.successes, stats.failures
}

func (d *MultiportDialer) GetActivePortCount() int {
	count := 0
	d.connCount.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

type multiportConn struct {
	net.Conn
	dialer *MultiportDialer
	port   int
	closed atomic.Bool
}

func (c *multiportConn) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	metrics.DecTransportSession("multiport")
	return c.Conn.Close()
}

type PortHopper struct {
	dialer       *MultiportDialer
	host         string
	network      string
	enabled      atomic.Bool
	interval     time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	onPortChange func(oldPort, newPort int)
}

func NewPortHopper(dialer *MultiportDialer, network, host string, interval time.Duration) *PortHopper {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortHopper{
		dialer:   dialer,
		host:     host,
		network:  network,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (h *PortHopper) Start(initialPort int) (net.Conn, error) {
	conn, err := h.dialer.DialSpecificPort(h.ctx, h.network, h.host, initialPort)
	if err != nil {
		return nil, err
	}

	h.enabled.Store(true)
	return conn, nil
}

func (h *PortHopper) Stop() {
	h.enabled.Store(false)
	h.cancel()
	h.wg.Wait()
}

func (h *PortHopper) SetOnPortChange(fn func(oldPort, newPort int)) {
	h.onPortChange = fn
}

func (h *PortHopper) GetCurrentPort() int {
	return 0
}

type PortRangeSet struct {
	ranges []PortRange
}

func NewPortRangeSet(ranges ...PortRange) *PortRangeSet {
	return &PortRangeSet{ranges: ranges}
}

func (s *PortRangeSet) Contains(port int) bool {
	for _, r := range s.ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}

func (s *PortRangeSet) RandomPort() int {
	totalPorts := 0
	for _, r := range s.ranges {
		totalPorts += r.End - r.Start + 1
	}

	n, _ := rand.Int(rand.Reader, big.NewInt(int64(totalPorts)))
	target := int(n.Int64())

	for _, r := range s.ranges {
		rangeSize := r.End - r.Start + 1
		if target < rangeSize {
			return r.Start + target
		}
		target -= rangeSize
	}

	return s.ranges[0].Start
}

func (s *PortRangeSet) AllPorts() []int {
	var ports []int
	for _, r := range s.ranges {
		for port := r.Start; port <= r.End; port++ {
			ports = append(ports, port)
		}
	}
	return ports
}
