// Package chaos provides chaos testing for transport resilience.
package chaos

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// Experiment represents a chaos experiment
type Experiment struct {
	Name        string
	Description string
	Type        ExperimentType
	Target      string
	Parameters  map[string]interface{}

	// Control
	Duration    time.Duration
	Interval    time.Duration
	Probability float64

	// State
	running   atomic.Bool
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// ExperimentType represents the type of chaos experiment
type ExperimentType string

const (
	ExperimentLatency      ExperimentType = "latency"
	ExperimentPacketLoss   ExperimentType = "packet_loss"
	ExperimentCorruption   ExperimentType = "corruption"
	ExperimentDuplication  ExperimentType = "duplication"
	ExperimentReorder      ExperimentType = "reorder"
	ExperimentDisconnect   ExperimentType = "disconnect"
	ExperimentPartition    ExperimentType = "partition"
)

// Result represents experiment results
type Result struct {
	Experiment    string
	Type          ExperimentType
	Duration      time.Duration
	Injections    uint64
	Errors        uint64
	StartTime     time.Time
	EndTime       time.Time
}

// Harness manages chaos experiments
type Harness struct {
	experiments map[string]*Experiment
	mu          sync.RWMutex
	results     []Result
	resultsMu   sync.RWMutex
}

// NewHarness creates a new chaos testing harness
func NewHarness() *Harness {
	return &Harness{
		experiments: make(map[string]*Experiment),
		results:     make([]Result, 0),
	}
}

// Register registers an experiment
func (h *Harness) Register(exp *Experiment) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.experiments[exp.Name] = exp
}

// Unregister removes an experiment
func (h *Harness) Unregister(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.experiments, name)
}

// Start starts an experiment
func (h *Harness) Start(name string) error {
	h.mu.RLock()
	exp, ok := h.experiments[name]
	h.mu.RUnlock()

	if !ok {
		return fmt.Errorf("experiment not found: %s", name)
	}

	if exp.running.Load() {
		return fmt.Errorf("experiment already running: %s", name)
	}

	exp.running.Store(true)
	exp.stopCh = make(chan struct{})

	exp.wg.Add(1)
	go h.runExperiment(exp)

	return nil
}

// Stop stops an experiment
func (h *Harness) Stop(name string) error {
	h.mu.RLock()
	exp, ok := h.experiments[name]
	h.mu.RUnlock()

	if !ok {
		return fmt.Errorf("experiment not found: %s", name)
	}

	if !exp.running.Load() {
		return nil
	}

	close(exp.stopCh)
	exp.wg.Wait()

	return nil
}

// runExperiment runs an experiment
func (h *Harness) runExperiment(exp *Experiment) {
	defer exp.wg.Done()

	result := Result{
		Experiment: exp.Name,
		Type:       exp.Type,
		StartTime:  time.Now(),
	}

	ticker := time.NewTicker(exp.Interval)
	defer ticker.Stop()

	timeout := time.AfterFunc(exp.Duration, func() {
		h.Stop(exp.Name)
	})
	defer timeout.Stop()

	for {
		select {
		case <-exp.stopCh:
			result.EndTime = time.Now()
			result.Duration = result.EndTime.Sub(result.StartTime)

			h.resultsMu.Lock()
			h.results = append(h.results, result)
			h.resultsMu.Unlock()

			exp.running.Store(false)
			return

		case <-ticker.C:
			if rand.Float64() < exp.Probability {
				if err := h.injectFault(exp); err != nil {
					result.Errors++
				} else {
					result.Injections++
				}
			}
		}
	}
}

// injectFault injects a fault based on experiment type
func (h *Harness) injectFault(exp *Experiment) error {
	switch exp.Type {
	case ExperimentLatency:
		return h.injectLatency(exp)
	case ExperimentPacketLoss:
		return h.injectPacketLoss(exp)
	case ExperimentCorruption:
		return h.injectCorruption(exp)
	case ExperimentDisconnect:
		return h.injectDisconnect(exp)
	default:
		return fmt.Errorf("unknown experiment type: %s", exp.Type)
	}
}

// injectLatency injects artificial latency
func (h *Harness) injectLatency(exp *Experiment) error {
	delay, ok := exp.Parameters["delay"].(time.Duration)
	if !ok {
		delay = 100 * time.Millisecond
	}

	time.Sleep(delay)
	return nil
}

// injectPacketLoss simulates packet loss
func (h *Harness) injectPacketLoss(exp *Experiment) error {
	lossRate, ok := exp.Parameters["rate"].(float64)
	if !ok {
		lossRate = 0.1
	}

	if rand.Float64() < lossRate {
		return fmt.Errorf("packet dropped")
	}
	return nil
}

// injectCorruption corrupts data
func (h *Harness) injectCorruption(exp *Experiment) error {
	// In a real implementation, this would corrupt packet data
	return nil
}

// injectDisconnect simulates a disconnection
func (h *Harness) injectDisconnect(exp *Experiment) error {
	duration, ok := exp.Parameters["duration"].(time.Duration)
	if !ok {
		duration = 5 * time.Second
	}

	// Block for the disconnect duration
	time.Sleep(duration)
	return fmt.Errorf("connection reset")
}

// GetResults returns all experiment results
func (h *Harness) GetResults() []Result {
	h.resultsMu.RLock()
	defer h.resultsMu.RUnlock()
	result := make([]Result, len(h.results))
	copy(result, h.results)
	return result
}

// IsRunning returns whether an experiment is running
func (h *Harness) IsRunning(name string) bool {
	h.mu.RLock()
	exp, ok := h.experiments[name]
	h.mu.RUnlock()

	if !ok {
		return false
	}
	return exp.running.Load()
}

// ListExperiments returns all experiment names
func (h *Harness) ListExperiments() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	names := make([]string, 0, len(h.experiments))
	for name := range h.experiments {
		names = append(names, name)
	}
	return names
}

// NetworkChaos provides network-level chaos injection
type NetworkChaos struct {
	Latency      time.Duration
	Jitter       time.Duration
	PacketLoss   float64
	Corruption   float64
	Duplication  float64
	Reorder      float64
	Bandwidth    int64 // bytes per second
}

// Apply applies network chaos to a data flow
func (nc *NetworkChaos) Apply(data []byte) ([]byte, error) {
	// Apply packet loss
	if rand.Float64() < nc.PacketLoss {
		return nil, fmt.Errorf("packet lost")
	}

	// Apply corruption
	if rand.Float64() < nc.Corruption {
		corrupted := make([]byte, len(data))
		copy(corrupted, data)
		// Flip random bit
		if len(corrupted) > 0 {
			pos := rand.Intn(len(corrupted))
			bit := uint(rand.Intn(8))
			corrupted[pos] ^= 1 << bit
		}
		data = corrupted
	}

	// Apply duplication
	if rand.Float64() < nc.Duplication {
		// Return data twice would need higher-level coordination
	}

	// Apply latency
	latency := nc.Latency
	if nc.Jitter > 0 {
		jitter := time.Duration(rand.Int63n(int64(nc.Jitter*2))) - nc.Jitter
		latency += jitter
	}
	if latency > 0 {
		time.Sleep(latency)
	}

	return data, nil
}

// Scenario defines a chaos testing scenario
type Scenario struct {
	Name        string
	Description string
	Steps       []Step
}

// Step represents a single step in a scenario
type Step struct {
	Action     string
	Target     string
	Parameters map[string]interface{}
	Duration   time.Duration
}

// RunScenario runs a chaos scenario
func (h *Harness) RunScenario(ctx context.Context, scenario *Scenario) error {
	for i, step := range scenario.Steps {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := h.executeStep(step); err != nil {
			return fmt.Errorf("step %d failed: %w", i, err)
		}

		if step.Duration > 0 {
			select {
			case <-time.After(step.Duration):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return nil
}

// executeStep executes a single scenario step
func (h *Harness) executeStep(step Step) error {
	switch step.Action {
	case "start":
		return h.Start(step.Target)
	case "stop":
		return h.Stop(step.Target)
	case "wait":
		// Duration handled in RunScenario
		return nil
	default:
		return fmt.Errorf("unknown action: %s", step.Action)
	}
}

// StressTest runs a stress test with increasing load
func (h *Harness) StressTest(ctx context.Context, target string, initialLoad int, step int, duration time.Duration) error {
	load := initialLoad

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Create experiment for this load level
		exp := &Experiment{
			Name:        fmt.Sprintf("stress_%d", load),
			Type:        ExperimentPacketLoss,
			Target:      target,
			Duration:    duration,
			Interval:    time.Second / time.Duration(load),
			Probability: float64(load) / 1000,
			Parameters: map[string]interface{}{
				"rate": float64(load) / 10000,
			},
		}

		h.Register(exp)
		if err := h.Start(exp.Name); err != nil {
			return err
		}

		select {
		case <-time.After(duration):
			h.Stop(exp.Name)
			h.Unregister(exp.Name)
		case <-ctx.Done():
			h.Stop(exp.Name)
			return ctx.Err()
		}

		// Increase load
		load += step
		if load > 10000 {
			break
		}
	}

	return nil
}
