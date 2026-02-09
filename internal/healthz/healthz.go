// Package healthz provides health check endpoints with minimal authentication
// and a haproxy-style health checking framework with state transitions.
package healthz

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Status represents the health status.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// Check represents a single health check.
type Check struct {
	Name        string        `json:"name"`
	Status      Status        `json:"status"`
	Message     string        `json:"message,omitempty"`
	LastChecked time.Time     `json:"last_checked"`
	Duration    time.Duration `json:"duration_ms"`
}

// Result is the aggregate health check result.
type Result struct {
	Status    Status    `json:"status"`
	Checks    []Check   `json:"checks"`
	Timestamp time.Time `json:"timestamp"`
}

// Checker is the interface for health checks.
type Checker interface {
	Name() string
	Check(ctx context.Context) error
}

// CheckerFunc is an adapter for simple checker functions.
type CheckerFunc struct {
	NameVal string
	CheckFn func(ctx context.Context) error
}

// Name returns the checker name.
func (c CheckerFunc) Name() string { return c.NameVal }

// Check runs the check.
func (c CheckerFunc) Check(ctx context.Context) error { return c.CheckFn(ctx) }

// HealthChecker manages multiple health checks.
type HealthChecker struct {
	mu       sync.RWMutex
	checks   map[string]Checker
	results  map[string]Check
	interval time.Duration
	token    string // Simple auth token
}

// New creates a new health checker.
func New(token string) *HealthChecker {
	return &HealthChecker{
		checks:   make(map[string]Checker),
		results:  make(map[string]Check),
		interval: 30 * time.Second,
		token:    token,
	}
}

// Register registers a health check.
func (h *HealthChecker) Register(checker Checker) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.checks[checker.Name()] = checker
}

// Unregister removes a health check.
func (h *HealthChecker) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.checks, name)
	delete(h.results, name)
}

// RunChecks runs all registered checks.
func (h *HealthChecker) RunChecks(ctx context.Context) Result {
	h.mu.RLock()
	checks := make([]Checker, 0, len(h.checks))
	for _, c := range h.checks {
		checks = append(checks, c)
	}
	h.mu.RUnlock()

	result := Result{
		Status:    StatusHealthy,
		Timestamp: time.Now(),
		Checks:    make([]Check, 0, len(checks)),
	}

	for _, checker := range checks {
		check := h.runCheck(ctx, checker)
		result.Checks = append(result.Checks, check)

		// Aggregate status
		if check.Status == StatusUnhealthy && result.Status != StatusUnhealthy {
			result.Status = StatusUnhealthy
		} else if check.Status == StatusDegraded && result.Status == StatusHealthy {
			result.Status = StatusDegraded
		}
	}

	return result
}

// runCheck runs a single check.
func (h *HealthChecker) runCheck(ctx context.Context, checker Checker) Check {
	start := time.Now()
	check := Check{
		Name:        checker.Name(),
		LastChecked: start,
	}

	// Run with timeout
	checkCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	err := checker.Check(checkCtx)
	check.Duration = time.Since(start)

	if err != nil {
		check.Status = StatusUnhealthy
		check.Message = err.Error()
	} else {
		check.Status = StatusHealthy
	}

	// Store result
	h.mu.Lock()
	h.results[checker.Name()] = check
	h.mu.Unlock()

	return check
}

// GetResult returns the last check result for a specific check.
func (h *HealthChecker) GetResult(name string) (Check, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	check, ok := h.results[name]
	return check, ok
}

// Start starts the background check loop.
func (h *HealthChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			h.RunChecks(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// HTTPHandler returns an HTTP handler for health checks.
func (h *HealthChecker) HTTPHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check auth token if configured
		if h.token != "" {
			auth := r.Header.Get("Authorization")
			if auth != "Bearer "+h.token {
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "unauthorized",
				})
				return
			}
		}

		// Run checks
		result := h.RunChecks(r.Context())

		// Set status code based on health
		switch result.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK) // Still OK but degraded
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
}

// SimpleCheck creates a simple checker from a function.
func SimpleCheck(name string, fn func() error) Checker {
	return CheckerFunc{
		NameVal: name,
		CheckFn: func(ctx context.Context) error {
			return fn()
		},
	}
}

// TCPCheck checks if a TCP port is reachable.
func TCPCheck(name, addr string) Checker {
	return CheckerFunc{
		NameVal: name,
		CheckFn: func(ctx context.Context) error {
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return err
			}
			conn.Close()
			return nil
		},
	}
}

// HTTPCheck checks if an HTTP endpoint is healthy.
func HTTPCheck(name, url string) Checker {
	return CheckerFunc{
		NameVal: name,
		CheckFn: func(ctx context.Context) error {
			req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
			if err != nil {
				return err
			}

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode >= 500 {
				return fmt.Errorf("HTTP %d", resp.StatusCode)
			}
			return nil
		},
	}
}

// CompositeCheck runs multiple checks and reports the worst status.
func CompositeCheck(name string, checks ...Checker) Checker {
	return CheckerFunc{
		NameVal: name,
		CheckFn: func(ctx context.Context) error {
			var lastErr error
			for _, c := range checks {
				if err := c.Check(ctx); err != nil {
					lastErr = err
				}
			}
			return lastErr
		},
	}
}

// ==================== HAProxy-style Backend Health Checking ====================

// BackendState represents the health state of a backend
type BackendState int

const (
	// StateStopped backend is administratively stopped
	StateStopped BackendState = iota
	// StateStarting backend is starting up
	StateStarting
	// StateRunning backend is healthy and serving traffic
	StateRunning
	// StateStopping backend is stopping
	StateStopping
	// StateDown backend has failed health checks
	StateDown
)

func (s BackendState) String() string {
	switch s {
	case StateStopped:
		return "stopped"
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StateStopping:
		return "stopping"
	case StateDown:
		return "down"
	default:
		return "unknown"
	}
}

// BackendCheckType represents the type of health check
type BackendCheckType string

const (
	// BackendCheckTypeTCP performs a simple TCP connection check
	BackendCheckTypeTCP BackendCheckType = "tcp"
	// BackendCheckTypeHTTP performs an HTTP GET check
	BackendCheckTypeHTTP BackendCheckType = "http"
	// BackendCheckTypeHTTPS performs an HTTPS GET check
	BackendCheckTypeHTTPS BackendCheckType = "https"
	// BackendCheckTypeTLS performs a TLS handshake check
	BackendCheckTypeTLS BackendCheckType = "tls"
)

// BackendConfig configures health checking behavior
type BackendConfig struct {
	// CheckType is the type of health check to perform
	CheckType BackendCheckType `yaml:"check_type"`

	// Interval between health checks
	Interval time.Duration `yaml:"interval"`

	// RiseCount is the number of consecutive successful checks
	// required to transition from down to up
	RiseCount int `yaml:"rise_count"`

	// FallCount is the number of consecutive failed checks
	// required to transition from up to down
	FallCount int `yaml:"fall_count"`

	// Timeout for each health check
	Timeout time.Duration `yaml:"timeout"`

	// FastInterval is the check interval during state transitions
	FastInterval time.Duration `yaml:"fast_interval"`

	// HTTPPath is the path for HTTP/HTTPS checks
	HTTPPath string `yaml:"http_path"`

	// HTTPExpectedStatus is the expected HTTP status code
	HTTPExpectedStatus int `yaml:"http_expected_status"`

	// TLSServerName for TLS checks
	TLSServerName string `yaml:"tls_server_name"`

	// TLSSkipVerify skips TLS certificate verification
	TLSSkipVerify bool `yaml:"tls_skip_verify"`
}

// DefaultBackendConfig returns a default health check configuration
func DefaultBackendConfig() *BackendConfig {
	return &BackendConfig{
		CheckType:          BackendCheckTypeTCP,
		Interval:           30 * time.Second,
		RiseCount:          2,
		FallCount:          3,
		Timeout:            5 * time.Second,
		FastInterval:       2 * time.Second,
		HTTPPath:           "/health",
		HTTPExpectedStatus: 200,
	}
}

// ApplyDefaults applies default values to the configuration
func (c *BackendConfig) ApplyDefaults() {
	defaults := DefaultBackendConfig()

	if c.Interval == 0 {
		c.Interval = defaults.Interval
	}
	if c.RiseCount == 0 {
		c.RiseCount = defaults.RiseCount
	}
	if c.FallCount == 0 {
		c.FallCount = defaults.FallCount
	}
	if c.Timeout == 0 {
		c.Timeout = defaults.Timeout
	}
	if c.FastInterval == 0 {
		c.FastInterval = defaults.FastInterval
	}
	if c.HTTPPath == "" {
		c.HTTPPath = defaults.HTTPPath
	}
	if c.HTTPExpectedStatus == 0 {
		c.HTTPExpectedStatus = defaults.HTTPExpectedStatus
	}
}

// BackendChecker performs health checks on backends
type BackendChecker struct {
	config   *BackendConfig
	backends map[string]*Backend
	mu       sync.RWMutex
	stopCh   chan struct{}
	stopped  atomic.Bool
	wg       sync.WaitGroup
}

// Backend represents a backend to health check
type Backend struct {
	ID       string
	Address  string
	State    atomic.Int32 // BackendState
	checker  *BackendChecker

	// Health check counters
	consecutiveSuccess atomic.Int32
	consecutiveFailure atomic.Int32

	// Statistics
	lastCheck   atomic.Value // time.Time
	lastSuccess atomic.Value // time.Time
	lastFailure atomic.Value // time.Time
	totalChecks atomic.Int64
	totalFails  atomic.Int64

	// Callbacks
	onStateChange func(id string, oldState, newState BackendState)
	onFailure     func(id string, err error)
}

// NewBackendChecker creates a new backend health checker
func NewBackendChecker(config *BackendConfig) *BackendChecker {
	if config == nil {
		config = DefaultBackendConfig()
	}
	config.ApplyDefaults()

	return &BackendChecker{
		config:   config,
		backends: make(map[string]*Backend),
		stopCh:   make(chan struct{}),
	}
}

// AddBackend adds a backend to check
func (c *BackendChecker) AddBackend(id, address string) *Backend {
	c.mu.Lock()
	defer c.mu.Unlock()

	b := &Backend{
		ID:      id,
		Address: address,
		checker: c,
	}
	b.State.Store(int32(StateStarting))
	b.lastCheck.Store(time.Time{})
	b.lastSuccess.Store(time.Time{})
	b.lastFailure.Store(time.Time{})

	c.backends[id] = b
	return b
}

// RemoveBackend removes a backend from checking
func (c *BackendChecker) RemoveBackend(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if b, ok := c.backends[id]; ok {
		b.SetState(StateStopped)
		delete(c.backends, id)
	}
}

// GetBackend gets a backend by ID
func (c *BackendChecker) GetBackend(id string) (*Backend, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	b, ok := c.backends[id]
	return b, ok
}

// GetAllBackends returns all backends
func (c *BackendChecker) GetAllBackends() []*Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()

	backends := make([]*Backend, 0, len(c.backends))
	for _, b := range c.backends {
		backends = append(backends, b)
	}
	return backends
}

// Start starts the health checker
func (c *BackendChecker) Start() {
	if c.stopped.Load() {
		return
	}

	c.mu.RLock()
	backends := make([]*Backend, 0, len(c.backends))
	for _, b := range c.backends {
		backends = append(backends, b)
	}
	c.mu.RUnlock()

	for _, b := range backends {
		c.wg.Add(1)
		go c.checkLoop(b)
	}
}

// Stop stops the health checker
func (c *BackendChecker) Stop() {
	if c.stopped.CompareAndSwap(false, true) {
		close(c.stopCh)
		c.wg.Wait()
	}
}

// checkLoop runs the health check loop for a backend
func (c *BackendChecker) checkLoop(b *Backend) {
	defer c.wg.Done()

	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()

	// Perform initial check immediately
	c.check(b)

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.check(b)

			// Adjust interval based on state
			state := b.GetState()
			if state == StateStarting || state == StateStopping {
				ticker.Reset(c.config.FastInterval)
			} else {
				ticker.Reset(c.config.Interval)
			}
		}
	}
}

// check performs a single health check
func (c *BackendChecker) check(b *Backend) {
	b.totalChecks.Add(1)
	b.lastCheck.Store(time.Now())

	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	err := c.performCheck(ctx, b)

	if err == nil {
		b.consecutiveSuccess.Add(1)
		b.consecutiveFailure.Store(0)
		b.lastSuccess.Store(time.Now())

		// Check if we should transition to running
		if b.GetState() != StateRunning {
			if b.consecutiveSuccess.Load() >= int32(c.config.RiseCount) {
				b.SetState(StateRunning)
			}
		}
	} else {
		b.consecutiveFailure.Add(1)
		b.consecutiveSuccess.Store(0)
		b.lastFailure.Store(time.Now())
		b.totalFails.Add(1)

		if b.onFailure != nil {
			b.onFailure(b.ID, err)
		}

		// Check if we should transition to down
		if b.GetState() == StateRunning {
			if b.consecutiveFailure.Load() >= int32(c.config.FallCount) {
				b.SetState(StateDown)
			}
		}
	}
}

// performCheck performs the actual health check
func (c *BackendChecker) performCheck(ctx context.Context, b *Backend) error {
	switch c.config.CheckType {
	case BackendCheckTypeTCP:
		return c.checkTCP(ctx, b)
	case BackendCheckTypeHTTP:
		return c.checkHTTP(ctx, b, false)
	case BackendCheckTypeHTTPS:
		return c.checkHTTP(ctx, b, true)
	case BackendCheckTypeTLS:
		return c.checkTLS(ctx, b)
	default:
		return fmt.Errorf("unknown check type: %s", c.config.CheckType)
	}
}

func (c *BackendChecker) checkTCP(ctx context.Context, b *Backend) error {
	dialer := &net.Dialer{Timeout: c.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", b.Address)
	if err != nil {
		return err
	}
	defer conn.Close()
	return nil
}

func (c *BackendChecker) checkHTTP(ctx context.Context, b *Backend, useTLS bool) error {
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s%s", scheme, b.Address, c.config.HTTPPath)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	client := &http.Client{
		Timeout: c.config.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName:         c.config.TLSServerName,
				InsecureSkipVerify: c.config.TLSSkipVerify,
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != c.config.HTTPExpectedStatus {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func (c *BackendChecker) checkTLS(ctx context.Context, b *Backend) error {
	dialer := &net.Dialer{Timeout: c.config.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", b.Address)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsConfig := &tls.Config{
		ServerName:         c.config.TLSServerName,
		InsecureSkipVerify: c.config.TLSSkipVerify,
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	defer tlsConn.Close()

	return nil
}

// GetState returns the current state of the backend
func (b *Backend) GetState() BackendState {
	return BackendState(b.State.Load())
}

// SetState sets the state of the backend
func (b *Backend) SetState(newState BackendState) {
	oldState := b.GetState()
	if oldState != newState {
		b.State.Store(int32(newState))
		if b.onStateChange != nil {
			b.onStateChange(b.ID, oldState, newState)
		}
	}
}

// IsHealthy returns true if the backend is healthy
func (b *Backend) IsHealthy() bool {
	return b.GetState() == StateRunning
}

// OnStateChange sets the state change callback
func (b *Backend) OnStateChange(fn func(id string, oldState, newState BackendState)) {
	b.onStateChange = fn
}

// OnFailure sets the failure callback
func (b *Backend) OnFailure(fn func(id string, err error)) {
	b.onFailure = fn
}

// Stats returns health check statistics
func (b *Backend) Stats() BackendStats {
	lastCheck, _ := b.lastCheck.Load().(time.Time)
	lastSuccess, _ := b.lastSuccess.Load().(time.Time)
	lastFailure, _ := b.lastFailure.Load().(time.Time)

	return BackendStats{
		ID:                 b.ID,
		Address:            b.Address,
		State:              b.GetState(),
		LastCheck:          lastCheck,
		LastSuccess:        lastSuccess,
		LastFailure:        lastFailure,
		TotalChecks:        b.totalChecks.Load(),
		TotalFailures:      b.totalFails.Load(),
		ConsecutiveSuccess: b.consecutiveSuccess.Load(),
		ConsecutiveFailure: b.consecutiveFailure.Load(),
	}
}

// BackendStats holds health check statistics
type BackendStats struct {
	ID                 string
	Address            string
	State              BackendState
	LastCheck          time.Time
	LastSuccess        time.Time
	LastFailure        time.Time
	TotalChecks        int64
	TotalFailures      int64
	ConsecutiveSuccess int32
	ConsecutiveFailure int32
}

// GetHealthyBackends returns all healthy backends
func (c *BackendChecker) GetHealthyBackends() []*Backend {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var healthy []*Backend
	for _, b := range c.backends {
		if b.IsHealthy() {
			healthy = append(healthy, b)
		}
	}
	return healthy
}

// GetStats returns statistics for all backends
func (c *BackendChecker) GetStats() map[string]BackendStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[string]BackendStats, len(c.backends))
	for id, b := range c.backends {
		stats[id] = b.Stats()
	}
	return stats
}
