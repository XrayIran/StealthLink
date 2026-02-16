// Package racing implements Happy Eyeballs-style connection racing
// for fast and resilient transport selection.
package racing

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Candidate represents a transport candidate for racing
type Candidate struct {
	Name      string
	Priority  int
	Dialer    DialerFunc
	Latency   time.Duration
	Weight    float64
	Metadata  map[string]string
}

// DialerFunc is a function that creates a connection
type DialerFunc func(ctx context.Context) (net.Conn, error)

// Result represents the result of a race
type Result struct {
	Winner    *Candidate
	Conn      net.Conn
	Latency   time.Duration
	Attempts  int
	Errors    []error
}

// Racer performs connection races
type Racer struct {
	candidates []*Candidate
	mu         sync.RWMutex

	// Configuration
	initialDelay    time.Duration
	parallelAttempts int
	timeout         time.Duration

	// Metrics
	racesTotal   atomic.Uint64
	racesWon     atomic.Uint64
	racesFailed  atomic.Uint64
}

// NewRacer creates a new connection racer
func NewRacer() *Racer {
	return &Racer{
		candidates:       make([]*Candidate, 0),
		initialDelay:     250 * time.Millisecond,
		parallelAttempts: 2,
		timeout:          30 * time.Second,
	}
}

// SetConfig configures the racer
func (r *Racer) SetConfig(initialDelay time.Duration, parallel int, timeout time.Duration) {
	r.initialDelay = initialDelay
	r.parallelAttempts = parallel
	r.timeout = timeout
}

// AddCandidate adds a transport candidate
func (r *Racer) AddCandidate(c *Candidate) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Insert by priority
	inserted := false
	for i, existing := range r.candidates {
		if c.Priority < existing.Priority {
			r.candidates = append(r.candidates[:i], append([]*Candidate{c}, r.candidates[i:]...)...)
			inserted = true
			break
		}
	}

	if !inserted {
		r.candidates = append(r.candidates, c)
	}
}

// RemoveCandidate removes a candidate by name
func (r *Racer) RemoveCandidate(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, c := range r.candidates {
		if c.Name == name {
			r.candidates = append(r.candidates[:i], r.candidates[i+1:]...)
			return
		}
	}
}

// GetCandidates returns all candidates
func (r *Racer) GetCandidates() []*Candidate {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*Candidate, len(r.candidates))
	copy(result, r.candidates)
	return result
}

// Race performs a connection race among candidates
func (r *Racer) Race(ctx context.Context) (*Result, error) {
	r.racesTotal.Add(1)

	r.mu.RLock()
	candidates := make([]*Candidate, len(r.candidates))
	copy(candidates, r.candidates)
	r.mu.RUnlock()

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidates available")
	}

	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// Result channel
	type candidateResult struct {
		candidate *Candidate
		conn      net.Conn
		latency   time.Duration
		err       error
	}

	resultCh := make(chan candidateResult, len(candidates))
	attempted := make(map[string]bool)
	var errors []error
	var errorsMu sync.Mutex

	// Start racing
	start := time.Now()

	// Try candidates in batches based on parallelAttempts
	for i := 0; i < len(candidates); i += r.parallelAttempts {
		batch := candidates[i:min(i+r.parallelAttempts, len(candidates))]

		var wg sync.WaitGroup
		for _, c := range batch {
			if attempted[c.Name] {
				continue
			}
			attempted[c.Name] = true

			wg.Add(1)
			go func(candidate *Candidate) {
				defer wg.Done()

				candidateStart := time.Now()
				conn, err := candidate.Dialer(ctx)
				latency := time.Since(candidateStart)

				if err != nil {
					errorsMu.Lock()
					errors = append(errors, fmt.Errorf("%s: %w", candidate.Name, err))
					errorsMu.Unlock()
					return
				}

				select {
				case resultCh <- candidateResult{
					candidate: candidate,
					conn:      conn,
					latency:   latency,
				}:
				case <-ctx.Done():
					conn.Close()
				}
			}(c)
		}

		// Wait for batch completion or result
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case result := <-resultCh:
			r.racesWon.Add(1)

			// Snapshot errors before background goroutines can append more.
			errorsMu.Lock()
			errSnapshot := make([]error, len(errors))
			copy(errSnapshot, errors)
			errorsMu.Unlock()

			// Close other connections that may have succeeded
			go func() {
				wg.Wait()
				for {
					select {
					case other := <-resultCh:
						if other.conn != nil {
							other.conn.Close()
						}
					case <-time.After(100 * time.Millisecond):
						return
					}
				}
			}()

			// Update candidate latency for future races
			result.candidate.Latency = time.Since(start)

			return &Result{
				Winner:   result.candidate,
				Conn:     result.conn,
				Latency:  time.Since(start),
				Attempts: len(attempted),
				Errors:   errSnapshot,
			}, nil

		case <-done:
			// Batch completed without success, continue to next
			continue

		case <-ctx.Done():
			r.racesFailed.Add(1)
			errorsMu.Lock()
			snapshot := fmt.Sprintf("%v", errors)
			errorsMu.Unlock()
			return nil, fmt.Errorf("race timeout: %s", snapshot)
		}
	}

	r.racesFailed.Add(1)
	errorsMu.Lock()
	snapshot := fmt.Sprintf("%v", errors)
	errorsMu.Unlock()
	return nil, fmt.Errorf("all candidates failed: %s", snapshot)
}

// RaceWithFallback races candidates with fallback to best historical performer
func (r *Racer) RaceWithFallback(ctx context.Context) (*Result, error) {
	// First try racing
	result, err := r.Race(ctx)
	if err == nil {
		return result, nil
	}

	// If race failed, try fallback to lowest latency candidate
	r.mu.RLock()
	candidates := make([]*Candidate, len(r.candidates))
	copy(candidates, r.candidates)
	r.mu.RUnlock()

	var best *Candidate
	for _, c := range candidates {
		if c.Latency > 0 {
			if best == nil || c.Latency < best.Latency {
				best = c
			}
		}
	}

	if best == nil && len(candidates) > 0 {
		best = candidates[0]
	}

	if best == nil {
		return nil, err
	}

	// Try fallback
	start := time.Now()
	conn, dialErr := best.Dialer(ctx)
	if dialErr != nil {
		return nil, fmt.Errorf("race failed: %v, fallback failed: %w", err, dialErr)
	}

	return &Result{
		Winner:   best,
		Conn:     conn,
		Latency:  time.Since(start),
		Attempts: len(candidates) + 1,
		Errors:   []error{err},
	}, nil
}

// GetStats returns racing statistics
func (r *Racer) GetStats() RacerStats {
	r.mu.RLock()
	candidateCount := len(r.candidates)
	r.mu.RUnlock()

	return RacerStats{
		RacesTotal:     r.racesTotal.Load(),
		RacesWon:       r.racesWon.Load(),
		RacesFailed:    r.racesFailed.Load(),
		CandidateCount: candidateCount,
	}
}

// RacerStats contains racing statistics
type RacerStats struct {
	RacesTotal     uint64
	RacesWon       uint64
	RacesFailed    uint64
	CandidateCount int
}

// UpdateWeights updates candidate weights based on performance
func (r *Racer) UpdateWeights() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.candidates) == 0 {
		return
	}

	// Calculate weights inversely proportional to latency
	var totalWeight float64
	for _, c := range r.candidates {
		if c.Latency > 0 {
			// Weight = 1 / latency (in seconds)
			weight := 1.0 / c.Latency.Seconds()
			c.Weight = weight
			totalWeight += weight
		} else {
			c.Weight = 1.0 // Default weight
			totalWeight += 1.0
		}
	}

	// Normalize weights
	for _, c := range r.candidates {
		c.Weight = c.Weight / totalWeight
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// AdaptiveRacer adapts based on network conditions
type AdaptiveRacer struct {
	*Racer

	successHistory map[string][]time.Duration
	historyMu      sync.RWMutex

	adaptInterval time.Duration
}

// NewAdaptiveRacer creates a new adaptive racer
func NewAdaptiveRacer() *AdaptiveRacer {
	ar := &AdaptiveRacer{
		Racer:          NewRacer(),
		successHistory: make(map[string][]time.Duration),
		adaptInterval:  5 * time.Minute,
	}

	go ar.adaptationLoop()

	return ar
}

// adaptationLoop periodically adapts candidate weights
func (ar *AdaptiveRacer) adaptationLoop() {
	ticker := time.NewTicker(ar.adaptInterval)
	defer ticker.Stop()

	for range ticker.C {
		ar.UpdateWeights()
	}
}

// RecordSuccess records a successful connection
func (ar *AdaptiveRacer) RecordSuccess(candidate string, latency time.Duration) {
	ar.historyMu.Lock()
	defer ar.historyMu.Unlock()

	history := ar.successHistory[candidate]
	history = append(history, latency)

	// Keep last 10 samples
	if len(history) > 10 {
		history = history[len(history)-10:]
	}

	ar.successHistory[candidate] = history

	// Update candidate latency with moving average
	var sum time.Duration
	for _, l := range history {
		sum += l
	}

	ar.mu.RLock()
	for _, c := range ar.candidates {
		if c.Name == candidate {
			c.Latency = sum / time.Duration(len(history))
			break
		}
	}
	ar.mu.RUnlock()
}

// GetAverageLatency returns the average latency for a candidate
func (ar *AdaptiveRacer) GetAverageLatency(candidate string) (time.Duration, bool) {
	ar.historyMu.RLock()
	defer ar.historyMu.RUnlock()

	history, ok := ar.successHistory[candidate]
	if !ok || len(history) == 0 {
		return 0, false
	}

	var sum time.Duration
	for _, l := range history {
		sum += l
	}

	return sum / time.Duration(len(history)), true
}
