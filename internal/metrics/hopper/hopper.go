// Package hopper provides per-hop latency tracking for transport paths.
package hopper

import (
	"sync"
	"sync/atomic"
	"time"
)

// Hop represents a single hop in the transport path
type Hop struct {
	Name     string
	Type     string
	Position int

	// Latency metrics
	latencyTotal atomic.Int64 // microseconds
	latencyCount atomic.Uint64
	latencyMin   atomic.Int64
	latencyMax   atomic.Int64

	// Errors
	errorsTotal atomic.Uint64
	lastError   string
	errorMu     sync.RWMutex

	// Throughput
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64

	// Active connections
	activeConns atomic.Int32
}

// NewHop creates a new hop
func NewHop(name, hopType string, position int) *Hop {
	h := &Hop{
		Name:     name,
		Type:     hopType,
		Position: position,
	}
	h.latencyMin.Store(-1) // -1 means unset
	return h
}

// RecordLatency records a latency measurement
func (h *Hop) RecordLatency(latency time.Duration) {
	micros := latency.Microseconds()

	h.latencyTotal.Add(micros)
	h.latencyCount.Add(1)

	// Update min
	for {
		oldMin := h.latencyMin.Load()
		if oldMin == -1 || micros < oldMin {
			if h.latencyMin.CompareAndSwap(oldMin, micros) {
				break
			}
		} else {
			break
		}
	}

	// Update max
	for {
		oldMax := h.latencyMax.Load()
		if micros > oldMax {
			if h.latencyMax.CompareAndSwap(oldMax, micros) {
				break
			}
		} else {
			break
		}
	}
}

// RecordError records an error
func (h *Hop) RecordError(err string) {
	h.errorsTotal.Add(1)
	h.errorMu.Lock()
	h.lastError = err
	h.errorMu.Unlock()
}

// AddBytes adds bytes to throughput counters
func (h *Hop) AddBytes(in, out uint64) {
	h.bytesIn.Add(in)
	h.bytesOut.Add(out)
}

// ConnStarted marks a connection start
func (h *Hop) ConnStarted() {
	h.activeConns.Add(1)
}

// ConnEnded marks a connection end
func (h *Hop) ConnEnded() {
	h.activeConns.Add(-1)
}

// GetStats returns hop statistics
func (h *Hop) GetStats() HopStats {
	count := h.latencyCount.Load()
	var avg int64
	if count > 0 {
		avg = h.latencyTotal.Load() / int64(count)
	}

	min := h.latencyMin.Load()
	if min == -1 {
		min = 0
	}

	h.errorMu.RLock()
	lastErr := h.lastError
	h.errorMu.RUnlock()

	return HopStats{
		Name:        h.Name,
		Type:        h.Type,
		Position:    h.Position,
		AvgLatency:  time.Duration(avg) * time.Microsecond,
		MinLatency:  time.Duration(min) * time.Microsecond,
		MaxLatency:  time.Duration(h.latencyMax.Load()) * time.Microsecond,
		ErrorCount:  h.errorsTotal.Load(),
		LastError:   lastErr,
		BytesIn:     h.bytesIn.Load(),
		BytesOut:    h.bytesOut.Load(),
		ActiveConns: h.activeConns.Load(),
	}
}

// HopStats contains hop statistics
type HopStats struct {
	Name        string
	Type        string
	Position    int
	AvgLatency  time.Duration
	MinLatency  time.Duration
	MaxLatency  time.Duration
	ErrorCount  uint64
	LastError   string
	BytesIn     uint64
	BytesOut    uint64
	ActiveConns int32
}

// Path represents a complete transport path with multiple hops
type Path struct {
	ID   string
	Name string
	hops []*Hop
	mu   sync.RWMutex
}

// NewPath creates a new path
func NewPath(id, name string) *Path {
	return &Path{
		ID:   id,
		Name: name,
		hops: make([]*Hop, 0),
	}
}

// AddHop adds a hop to the path
func (p *Path) AddHop(hop *Hop) {
	p.mu.Lock()
	defer p.mu.Unlock()
	hop.Position = len(p.hops)
	p.hops = append(p.hops, hop)
}

// GetHop gets a hop by name
func (p *Path) GetHop(name string) *Hop {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, h := range p.hops {
		if h.Name == name {
			return h
		}
	}
	return nil
}

// GetHops returns all hops
func (p *Path) GetHops() []*Hop {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]*Hop, len(p.hops))
	copy(result, p.hops)
	return result
}

// GetStats returns stats for all hops
func (p *Path) GetStats() PathStats {
	p.mu.RLock()
	defer p.mu.RUnlock()

	stats := PathStats{
		ID:       p.ID,
		Name:     p.Name,
		HopCount: len(p.hops),
		Hops:     make([]HopStats, len(p.hops)),
	}

	var totalLatency time.Duration
	for i, h := range p.hops {
		hopStats := h.GetStats()
		stats.Hops[i] = hopStats
		totalLatency += hopStats.AvgLatency
	}

	stats.TotalLatency = totalLatency
	return stats
}

// PathStats contains path statistics
type PathStats struct {
	ID           string
	Name         string
	HopCount     int
	TotalLatency time.Duration
	Hops         []HopStats
}

// Registry manages multiple paths
type Registry struct {
	paths map[string]*Path
	mu    sync.RWMutex
}

// NewRegistry creates a new path registry
func NewRegistry() *Registry {
	return &Registry{
		paths: make(map[string]*Path),
	}
}

// Register registers a path
func (r *Registry) Register(path *Path) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.paths[path.ID] = path
}

// Unregister removes a path
func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.paths, id)
}

// GetPath gets a path by ID
func (r *Registry) GetPath(id string) *Path {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.paths[id]
}

// GetAllPaths returns all paths
func (r *Registry) GetAllPaths() []*Path {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*Path, 0, len(r.paths))
	for _, p := range r.paths {
		result = append(result, p)
	}
	return result
}

// GetAllStats returns stats for all paths
func (r *Registry) GetAllStats() []PathStats {
	r.mu.RLock()
	paths := make([]*Path, 0, len(r.paths))
	for _, p := range r.paths {
		paths = append(paths, p)
	}
	r.mu.RUnlock()

	stats := make([]PathStats, len(paths))
	for i, p := range paths {
		stats[i] = p.GetStats()
	}
	return stats
}

// Global registry
var Global = NewRegistry()

// LatencyTimer helps measure latency
type LatencyTimer struct {
	start time.Time
	hop   *Hop
}

// StartLatencyTimer starts a latency timer
func (h *Hop) StartLatencyTimer() *LatencyTimer {
	return &LatencyTimer{
		start: time.Now(),
		hop:   h,
	}
}

// Stop stops the timer and records the latency
func (t *LatencyTimer) Stop() {
	if t.hop != nil {
		t.hop.RecordLatency(time.Since(t.start))
	}
}

// LatencyHistogram tracks latency distribution
type LatencyHistogram struct {
	buckets []time.Duration
	counts  []atomic.Uint64
	total   atomic.Uint64
}

// NewLatencyHistogram creates a latency histogram
func NewLatencyHistogram() *LatencyHistogram {
	buckets := []time.Duration{
		1 * time.Millisecond,
		5 * time.Millisecond,
		10 * time.Millisecond,
		25 * time.Millisecond,
		50 * time.Millisecond,
		100 * time.Millisecond,
		250 * time.Millisecond,
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		5 * time.Second,
	}

	return &LatencyHistogram{
		buckets: buckets,
		counts:  make([]atomic.Uint64, len(buckets)+1),
	}
}

// Record records a latency
func (h *LatencyHistogram) Record(latency time.Duration) {
	for i, bucket := range h.buckets {
		if latency <= bucket {
			h.counts[i].Add(1)
			h.total.Add(1)
			return
		}
	}
	h.counts[len(h.buckets)].Add(1)
	h.total.Add(1)
}

// GetPercentile returns the latency at a given percentile (0-100)
func (h *LatencyHistogram) GetPercentile(p float64) time.Duration {
	if p < 0 || p > 100 {
		return 0
	}

	total := h.total.Load()
	if total == 0 {
		return 0
	}

	target := uint64(float64(total) * p / 100)
	var cumulative uint64

	for i := range h.counts {
		cumulative += h.counts[i].Load()
		if cumulative >= target {
			if i < len(h.buckets) {
				return h.buckets[i]
			}
			return h.buckets[len(h.buckets)-1] * 2
		}
	}

	return 0
}
