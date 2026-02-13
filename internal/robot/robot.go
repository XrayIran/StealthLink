// Package robot implements automated reconfiguration and recovery robot for StealthLink.
// It provides auto-recovery on tunnel failure, periodic tunnel reset, and health monitoring.
package robot

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"stealthlink/internal/healthz"
)

// Config configures the recovery robot.
type Config struct {
	// Health check interval
	HealthInterval time.Duration `yaml:"health_interval"`

	// Tunnel reset interval (periodic reset)
	ResetInterval time.Duration `yaml:"reset_interval"`

	// Max consecutive failures before recovery action
	MaxFailures int `yaml:"max_failures"`

	// Backoff between recovery attempts
	RecoveryBackoff time.Duration `yaml:"recovery_backoff"`

	// Enable periodic tunnel reset
	EnablePeriodicReset bool `yaml:"enable_periodic_reset"`

	// Enable auto-recovery on failure
	EnableAutoRecovery bool `yaml:"enable_auto_recovery"`

	// Command to execute on recovery
	RecoveryCommand string `yaml:"recovery_command"`
}

// ApplyDefaults sets default values for robot configuration.
func (c *Config) ApplyDefaults() {
	if c.HealthInterval <= 0 {
		c.HealthInterval = 30 * time.Second
	}
	if c.ResetInterval <= 0 {
		c.ResetInterval = 24 * time.Hour // Daily reset
	}
	if c.MaxFailures <= 0 {
		c.MaxFailures = 3
	}
	if c.RecoveryBackoff <= 0 {
		c.RecoveryBackoff = 10 * time.Second
	}
}

// Robot provides automated tunnel management and recovery.
type Robot struct {
	config  *Config
	checker *healthz.HealthChecker
	mu      sync.RWMutex

	// State tracking
	failures  atomic.Int32
	lastReset time.Time
	lastCheck time.Time
	status    string
	statusMu  sync.RWMutex

	// Recovery callbacks
	onRecovery []func() error
	onReset    []func() error
	onFailure  []func(error)

	// Control
	ctx     context.Context
	cancel  context.CancelFunc
	closeCh chan struct{}
	closed  atomic.Bool
}

// New creates a new recovery robot.
func New(cfg *Config, checker *healthz.HealthChecker) *Robot {
	cfg.ApplyDefaults()

	ctx, cancel := context.WithCancel(context.Background())

	r := &Robot{
		config:     cfg,
		checker:    checker,
		ctx:        ctx,
		cancel:     cancel,
		closeCh:    make(chan struct{}),
		onRecovery: make([]func() error, 0),
		onReset:    make([]func() error, 0),
		onFailure:  make([]func(error), 0),
	}

	r.setStatus("initialized")

	return r
}

// Start begins the robot's monitoring and recovery loop.
func (r *Robot) Start() {
	// Start health monitoring loop
	go r.healthLoop()

	// Start periodic reset if enabled
	if r.config.EnablePeriodicReset {
		go r.resetLoop()
	}

	r.setStatus("running")
	log.Printf("[Robot] Started with health interval=%v, reset interval=%v",
		r.config.HealthInterval, r.config.ResetInterval)
}

// Stop stops the robot.
func (r *Robot) Stop() {
	if r.closed.CompareAndSwap(false, true) {
		r.cancel()
		close(r.closeCh)
		r.setStatus("stopped")
		log.Printf("[Robot] Stopped")
	}
}

// healthLoop performs periodic health checks.
func (r *Robot) healthLoop() {
	ticker := time.NewTicker(r.config.HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.performHealthCheck()
		}
	}
}

// performHealthCheck runs health checks and triggers recovery if needed.
func (r *Robot) performHealthCheck() {
	r.mu.Lock()
	r.lastCheck = time.Now()
	r.mu.Unlock()

	result := r.checker.RunChecks(r.ctx)

	// Check overall status
	if result.Status == healthz.StatusUnhealthy {
		failures := r.failures.Add(1)
		log.Printf("[Robot] Health check failed (failure #%d): %v",
			failures, result.Checks)

		// Trigger failure callbacks
		r.triggerFailures(fmt.Errorf("health check failed: %v", result.Checks))

		// Check if we need to recover
		if failures >= int32(r.config.MaxFailures) && r.config.EnableAutoRecovery {
			log.Printf("[Robot] Threshold reached, initiating recovery...")
			go r.recover()
		}
	} else {
		// Reset failure counter on success
		r.failures.Store(0)

		if result.Status == healthz.StatusDegraded {
			log.Printf("[Robot] Health check degraded: %v", result.Checks)
		} else {
			log.Printf("[Robot] Health check passed")
		}
	}

	r.setStatus(string(result.Status))
}

// resetLoop performs periodic tunnel resets.
func (r *Robot) resetLoop() {
	ticker := time.NewTicker(r.config.ResetInterval)
	defer ticker.Stop()

	// Initial delay to stagger resets
	time.Sleep(time.Duration(r.config.ResetInterval / 2))

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.performReset()
		}
	}
}

// performReset performs a tunnel reset.
func (r *Robot) performReset() {
	log.Printf("[Robot] Performing periodic tunnel reset...")

	r.mu.Lock()
	r.lastReset = time.Now()
	r.mu.Unlock()

	// Execute reset callbacks
	for i, callback := range r.onReset {
		if err := callback(); err != nil {
			log.Printf("[Robot] Reset callback %d failed: %v", i, err)
		}
	}

	// Reset failure counter
	r.failures.Store(0)

	log.Printf("[Robot] Tunnel reset complete")
}

// recover performs recovery actions.
func (r *Robot) recover() {
	log.Printf("[Robot] Starting recovery...")

	// Reset failure counter first
	r.failures.Store(0)

	// Execute recovery callbacks
	for i, callback := range r.onRecovery {
		log.Printf("[Robot] Running recovery callback %d/%d", i+1, len(r.onRecovery))
		if err := callback(); err != nil {
			log.Printf("[Robot] Recovery callback %d failed: %v", i+1, err)
			// Continue with other callbacks
		} else {
			log.Printf("[Robot] Recovery callback %d succeeded", i+1)
		}
	}

	// Execute recovery command if configured
	if r.config.RecoveryCommand != "" {
		log.Printf("[Robot] Executing recovery command: %s", r.config.RecoveryCommand)
		if err := r.executeCommand(r.config.RecoveryCommand); err != nil {
			log.Printf("[Robot] Recovery command failed: %v", err)
		} else {
			log.Printf("[Robot] Recovery command succeeded")
		}
	}

	// Wait before rechecking
	time.Sleep(r.config.RecoveryBackoff)

	// Verify recovery
	result := r.checker.RunChecks(r.ctx)
	if result.Status == healthz.StatusHealthy {
		log.Printf("[Robot] Recovery successful!")
		r.setStatus("recovered")
	} else {
		log.Printf("[Robot] Recovery failed, status: %v", result.Checks)
		r.failures.Add(int32(r.config.MaxFailures))
		r.setStatus("recovery-failed")
	}
}

// AddRecoveryCallback adds a callback to be executed during recovery.
func (r *Robot) AddRecoveryCallback(fn func() error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRecovery = append(r.onRecovery, fn)
}

// AddResetCallback adds a callback to be executed during periodic reset.
func (r *Robot) AddResetCallback(fn func() error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onReset = append(r.onReset, fn)
}

// AddFailureCallback adds a callback to be executed on failure.
func (r *Robot) AddFailureCallback(fn func(error)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onFailure = append(r.onFailure, fn)
}

// triggerFailures executes all failure callbacks.
func (r *Robot) triggerFailures(err error) {
	r.mu.RLock()
	callbacks := make([]func(error), len(r.onFailure))
	copy(callbacks, r.onFailure)
	r.mu.RUnlock()

	for _, callback := range callbacks {
		go callback(err)
	}
}

// executeCommand executes a recovery command with a 30-second timeout.
// The command string is split on whitespace and executed directly (no shell).
// Shell metacharacters are rejected to prevent command injection.
func (r *Robot) executeCommand(cmd string) error {
	// Reject shell metacharacters to prevent injection.
	if strings.ContainsAny(cmd, "|;&$`\\\"'(){}[]<>!~*?#") {
		return fmt.Errorf("command contains disallowed shell metacharacters: %s", cmd)
	}

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty command")
	}

	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()

	execCmd := exec.CommandContext(ctx, parts[0], parts[1:]...)
	output, err := execCmd.CombinedOutput()
	if len(output) > 0 {
		log.Printf("[Robot] Command output: %s", strings.TrimSpace(string(output)))
	}
	if err != nil {
		return fmt.Errorf("command %q failed: %w", parts[0], err)
	}
	return nil
}

// setStatus updates the robot status.
func (r *Robot) setStatus(status string) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.status = status
}

// GetStatus returns the current status.
func (r *Robot) GetStatus() string {
	r.statusMu.RLock()
	defer r.statusMu.RUnlock()
	return r.status
}

// GetStats returns robot statistics.
func (r *Robot) GetStats() Stats {
	r.mu.RLock()
	lastCheck := r.lastCheck
	lastReset := r.lastReset
	healthInterval := r.config.HealthInterval
	resetInterval := r.config.ResetInterval
	r.mu.RUnlock()

	r.statusMu.RLock()
	status := r.status
	r.statusMu.RUnlock()

	return Stats{
		Status:         status,
		Failures:       int(r.failures.Load()),
		LastCheck:      lastCheck,
		LastReset:      lastReset,
		HealthInterval: healthInterval,
		ResetInterval:  resetInterval,
	}
}

// Stats holds robot statistics.
type Stats struct {
	Status         string        `json:"status"`
	Failures       int           `json:"failures"`
	LastCheck      time.Time     `json:"last_check"`
	LastReset      time.Time     `json:"last_reset"`
	HealthInterval time.Duration `json:"health_interval"`
	ResetInterval  time.Duration `json:"reset_interval"`
}

// ManualReset triggers a manual tunnel reset.
func (r *Robot) ManualReset() error {
	log.Printf("[Robot] Manual reset requested")
	r.performReset()
	return nil
}

// ManualRecovery triggers a manual recovery.
func (r *Robot) ManualRecovery() error {
	log.Printf("[Robot] Manual recovery requested")
	go r.recover()
	return nil
}

// TunnelManager manages tunnel lifecycle with robot integration.
type TunnelManager struct {
	robot   *Robot
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

// Tunnel represents a managed tunnel.
type Tunnel struct {
	Name        string
	Addr        string
	Transport   string
	Connected   bool
	LastError   error
	Established time.Time
	mu          sync.RWMutex
}

// NewTunnelManager creates a new tunnel manager.
func NewTunnelManager(robot *Robot) *TunnelManager {
	return &TunnelManager{
		robot:   robot,
		tunnels: make(map[string]*Tunnel),
	}
}

// AddTunnel adds a tunnel to management.
func (tm *TunnelManager) AddTunnel(name, addr, transport string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	tm.tunnels[name] = &Tunnel{
		Name:      name,
		Addr:      addr,
		Transport: transport,
		Connected: false,
	}

	// Register health check for this tunnel
	tm.robot.checker.Register(healthz.TCPCheck(name+"_tcp", addr))

	log.Printf("[TunnelManager] Added tunnel: %s (%s)", name, transport)
}

// RemoveTunnel removes a tunnel from management.
func (tm *TunnelManager) RemoveTunnel(name string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	delete(tm.tunnels, name)
	tm.robot.checker.Unregister(name + "_tcp")

	log.Printf("[TunnelManager] Removed tunnel: %s", name)
}

// GetTunnel returns a tunnel by name.
func (tm *TunnelManager) GetTunnel(name string) (*Tunnel, bool) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	t, ok := tm.tunnels[name]
	return t, ok
}

// ListTunnels returns all managed tunnels.
func (tm *TunnelManager) ListTunnels() []*Tunnel {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, t)
	}
	return tunnels
}

// MarkConnected marks a tunnel as connected.
func (tm *TunnelManager) MarkConnected(name string) {
	tm.mu.RLock()
	t, ok := tm.tunnels[name]
	tm.mu.RUnlock()

	if ok {
		t.mu.Lock()
		t.Connected = true
		t.LastError = nil
		if t.Established.IsZero() {
			t.Established = time.Now()
		}
		t.mu.Unlock()
	}
}

// MarkDisconnected marks a tunnel as disconnected.
func (tm *TunnelManager) MarkDisconnected(name string, err error) {
	tm.mu.RLock()
	t, ok := tm.tunnels[name]
	tm.mu.RUnlock()

	if ok {
		t.mu.Lock()
		t.Connected = false
		t.LastError = err
		t.mu.Unlock()
	}
}

// IsConnected checks if a tunnel is connected.
func (tm *TunnelManager) IsConnected(name string) bool {
	tm.mu.RLock()
	t, ok := tm.tunnels[name]
	tm.mu.RUnlock()

	if ok {
		t.mu.RLock()
		defer t.mu.RUnlock()
		return t.Connected
	}
	return false
}

// SetupRobotCallbacks sets up standard robot callbacks for tunnel management.
func (tm *TunnelManager) SetupRobotCallbacks() {
	// Recovery callback: reconnect all tunnels
	tm.robot.AddRecoveryCallback(func() error {
		return tm.reconnectAll()
	})

	// Reset callback: reset all tunnels
	tm.robot.AddResetCallback(func() error {
		return tm.resetAll()
	})

	// Failure callback: log failure
	tm.robot.AddFailureCallback(func(err error) {
		log.Printf("[TunnelManager] Failure detected: %v", err)
	})
}

// reconnectAll attempts to reconnect all disconnected tunnels.
func (tm *TunnelManager) reconnectAll() error {
	tm.mu.RLock()
	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, t)
	}
	tm.mu.RUnlock()

	var lastErr error
	for _, t := range tunnels {
		t.mu.RLock()
		connected := t.Connected
		t.mu.RUnlock()

		if !connected {
			log.Printf("[TunnelManager] Reconnecting tunnel: %s", t.Name)
			// In production, this would trigger actual reconnection
			// For now, just mark as connected
			tm.MarkConnected(t.Name)
		}
	}

	return lastErr
}

// resetAll resets all tunnels.
func (tm *TunnelManager) resetAll() error {
	tm.mu.RLock()
	tunnels := make([]*Tunnel, 0, len(tm.tunnels))
	for _, t := range tm.tunnels {
		tunnels = append(tunnels, t)
	}
	tm.mu.RUnlock()

	log.Printf("[TunnelManager] Resetting %d tunnels", len(tunnels))

	for _, t := range tunnels {
		// Disconnect and reconnect
		tm.MarkDisconnected(t.Name, fmt.Errorf("periodic reset"))
		time.Sleep(100 * time.Millisecond)
		tm.MarkConnected(t.Name)
	}

	return nil
}

// GetConnectionRate returns the percentage of connected tunnels.
func (tm *TunnelManager) GetConnectionRate() float64 {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	if len(tm.tunnels) == 0 {
		return 0
	}

	connected := 0
	for _, t := range tm.tunnels {
		t.mu.RLock()
		if t.Connected {
			connected++
		}
		t.mu.RUnlock()
	}

	return float64(connected) / float64(len(tm.tunnels)) * 100
}

// CircuitBreaker implements circuit breaker pattern for tunnel connections.
type CircuitBreaker struct {
	name         string
	threshold    int
	resetTimeout time.Duration

	mu          sync.RWMutex
	failures    int
	lastFailure time.Time
	state       CircuitState
}

// CircuitState represents circuit breaker state.
type CircuitState int

const (
	StateClosed CircuitState = iota
	StateOpen
	StateHalfOpen
)

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(name string, threshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:         name,
		threshold:    threshold,
		resetTimeout: resetTimeout,
		state:        StateClosed,
	}
}

// Allow checks if an operation should be allowed.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Check if we should attempt reset
	if cb.state == StateOpen && time.Since(cb.lastFailure) > cb.resetTimeout {
		cb.state = StateHalfOpen
		log.Printf("[CircuitBreaker] %s: Transitioning to half-open", cb.name)
	}

	return cb.state != StateOpen
}

// Success records a successful operation.
func (cb *CircuitBreaker) Success() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.failures = 0
		log.Printf("[CircuitBreaker] %s: Circuit reset to closed", cb.name)
	}
}

// Failure records a failed operation.
func (cb *CircuitBreaker) Failure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastFailure = time.Now()

	if cb.failures >= cb.threshold && cb.state != StateOpen {
		cb.state = StateOpen
		log.Printf("[CircuitBreaker] %s: Circuit opened after %d failures",
			cb.name, cb.failures)
	}
}

// GetState returns the current circuit breaker state.
func (cb *CircuitBreaker) GetState() CircuitState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetFailures returns the current failure count.
func (cb *CircuitBreaker) GetFailures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}
