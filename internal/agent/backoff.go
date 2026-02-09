// Package agent provides reconnection strategies with jitter and circuit breaker.
package agent

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// ReconnectStrategy provides configurable reconnection behavior.
type ReconnectStrategy struct {
	InitialInterval  time.Duration
	MaxInterval      time.Duration
	MaxRetries       int
	JitterPercent    float64
	CircuitBreaker   *CircuitBreaker

	currentInterval time.Duration
	attempts        int
	mu              sync.Mutex
}

// NewReconnectStrategy creates a new reconnection strategy.
func NewReconnectStrategy() *ReconnectStrategy {
	return &ReconnectStrategy{
		InitialInterval: 1 * time.Second,
		MaxInterval:     60 * time.Second,
		MaxRetries:      0, // 0 = unlimited
		JitterPercent:   0.1,
		currentInterval: 1 * time.Second,
	}
}

// NextBackoff calculates the next backoff duration.
func (r *ReconnectStrategy) NextBackoff() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Check circuit breaker
	if r.CircuitBreaker != nil && !r.CircuitBreaker.Allow() {
		return r.MaxInterval
	}

	// Calculate jitter
	jitter := time.Duration(0)
	if r.JitterPercent > 0 {
		jitter = time.Duration(float64(r.currentInterval) * r.JitterPercent * (rand.Float64()*2 - 1))
	}

	backoff := r.currentInterval + jitter

	// Exponential backoff
	r.currentInterval = time.Duration(float64(r.currentInterval) * 2)
	if r.currentInterval > r.MaxInterval {
		r.currentInterval = r.MaxInterval
	}

	r.attempts++
	return backoff
}

// Reset resets the strategy.
func (r *ReconnectStrategy) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.currentInterval = r.InitialInterval
	r.attempts = 0
	if r.CircuitBreaker != nil {
		r.CircuitBreaker.Reset()
	}
}

// ShouldRetry returns true if we should retry.
func (r *ReconnectStrategy) ShouldRetry() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.MaxRetries == 0 || r.attempts < r.MaxRetries
}

// Attempts returns the number of attempts made.
func (r *ReconnectStrategy) Attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.attempts
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	failureThreshold int
	resetTimeout     time.Duration
	failures         int
	lastFailure      time.Time
	state            CircuitState
	mu               sync.RWMutex
}

// CircuitState represents the circuit breaker state.
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		state:            StateClosed,
	}
}

// Allow returns true if the operation should be allowed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return true
	case StateOpen:
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			cb.state = StateHalfOpen
			return true
		}
		return false
	case StateHalfOpen:
		return true
	}

	return true
}

// RecordSuccess records a successful operation.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateHalfOpen:
		cb.state = StateClosed
		cb.failures = 0
	case StateClosed:
		cb.failures = 0
	}
}

// RecordFailure records a failed operation.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	switch cb.state {
	case StateHalfOpen:
		cb.state = StateOpen
	case StateClosed:
		if cb.failures >= cb.failureThreshold {
			cb.state = StateOpen
		}
	}
}

// State returns the current state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Reset resets the circuit breaker.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.state = StateClosed
	cb.failures = 0
}

// String returns the state name.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ExponentialBackoff calculates exponential backoff with jitter.
func ExponentialBackoff(attempt int, base, max time.Duration, jitter float64) time.Duration {
	backoff := base
	for i := 0; i < attempt; i++ {
		backoff *= 2
		if backoff > max {
			backoff = max
			break
		}
	}

	if jitter > 0 {
		j := time.Duration(float64(backoff) * jitter * (rand.Float64()*2 - 1))
		backoff += j
	}

	return backoff
}

// Retry executes a function with retry logic.
func Retry(ctx context.Context, strategy *ReconnectStrategy, fn func() error) error {
	for {
		err := fn()
		if err == nil {
			return nil
		}

		if !strategy.ShouldRetry() {
			return err
		}

		backoff := strategy.NextBackoff()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
			continue
		}
	}
}
