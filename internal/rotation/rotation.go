// Package rotation provides periodic key and port rotation for enhanced stealth.
package rotation

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// RotationManager manages periodic key and port rotation.
type RotationManager struct {
	interval     time.Duration
	keyGenerator func() string
	portPool     []int
	currentKey   string
	currentPort  int
	keyIndex     int
	portIndex    int
	mu           sync.RWMutex
	onRotate     func(oldKey, newKey string, oldPort, newPort int)
	stopCh       chan struct{}
}

// Config holds rotation configuration.
type Config struct {
	Interval     time.Duration
	KeyGenerator func() string
	PortPool     []int
	OnRotate     func(oldKey, newKey string, oldPort, newPort int)
}

// NewManager creates a new rotation manager.
func NewManager(cfg *Config) *RotationManager {
	if cfg.Interval <= 0 {
		cfg.Interval = 1 * time.Hour
	}
	if cfg.KeyGenerator == nil {
		cfg.KeyGenerator = GenerateRandomKey
	}

	return &RotationManager{
		interval:     cfg.Interval,
		keyGenerator: cfg.KeyGenerator,
		portPool:     cfg.PortPool,
		currentKey:   cfg.KeyGenerator(),
		currentPort:  selectPort(cfg.PortPool, 0),
		onRotate:     cfg.OnRotate,
		stopCh:       make(chan struct{}),
	}
}

// Start starts the rotation loop.
func (r *RotationManager) Start(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.Rotate()
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		}
	}
}

// Stop stops the rotation loop.
func (r *RotationManager) Stop() {
	close(r.stopCh)
}

// Rotate performs a manual rotation.
func (r *RotationManager) Rotate() {
	r.mu.Lock()
	defer r.mu.Unlock()

	oldKey := r.currentKey
	oldPort := r.currentPort

	// Rotate key
	r.currentKey = r.keyGenerator()
	r.keyIndex++

	// Rotate port if pool is configured
	if len(r.portPool) > 0 {
		r.portIndex = (r.portIndex + 1) % len(r.portPool)
		r.currentPort = r.portPool[r.portIndex]
	}

	// Notify callback
	if r.onRotate != nil {
		go r.onRotate(oldKey, r.currentKey, oldPort, r.currentPort)
	}
}

// CurrentKey returns the current key.
func (r *RotationManager) CurrentKey() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentKey
}

// CurrentPort returns the current port.
func (r *RotationManager) CurrentPort() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.currentPort
}

// selectPort selects a port from the pool.
func selectPort(pool []int, index int) int {
	if len(pool) == 0 {
		return 0
	}
	return pool[index%len(pool)]
}

// GenerateRandomKey generates a random key.
func GenerateRandomKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based key
		return fmt.Sprintf("key-%d", time.Now().UnixNano())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// GenerateKeyFromSeed generates a deterministic key from a seed.
func GenerateKeyFromSeed(seed string, iteration int) string {
	data := fmt.Sprintf("%s-%d", seed, iteration)
	b := make([]byte, 32)
	copy(b, data)
	return base64.URLEncoding.EncodeToString(b)
}

// PortRange generates a range of ports.
func PortRange(start, end int) []int {
	ports := make([]int, 0, end-start+1)
	for i := start; i <= end; i++ {
		ports = append(ports, i)
	}
	return ports
}

// RandomPorts generates n random ports from a range.
func RandomPorts(n, min, max int) []int {
	ports := make([]int, n)
	for i := 0; i < n; i++ {
		ports[i] = min + randInt(max-min+1)
	}
	return ports
}

func randInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(b[0])%max + int(b[1])%max + int(b[2])%max + int(b[3])%max
}

// KeyRotator rotates keys only.
type KeyRotator struct {
	mu       sync.RWMutex
	current  string
	interval time.Duration
	gen      func() string
}

// NewKeyRotator creates a new key rotator.
func NewKeyRotator(interval time.Duration, gen func() string) *KeyRotator {
	if gen == nil {
		gen = GenerateRandomKey
	}
	return &KeyRotator{
		current:  gen(),
		interval: interval,
		gen:      gen,
	}
}

// Current returns the current key.
func (k *KeyRotator) Current() string {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current
}

// Rotate rotates to a new key.
func (k *KeyRotator) Rotate() string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.current = k.gen()
	return k.current
}

// PortRotator rotates ports only.
type PortRotator struct {
	mu       sync.RWMutex
	ports    []int
	current  int
	index    int
	interval time.Duration
}

// NewPortRotator creates a new port rotator.
func NewPortRotator(ports []int) *PortRotator {
	if len(ports) == 0 {
		ports = []int{8080, 8443, 9443}
	}
	return &PortRotator{
		ports:   ports,
		current: ports[0],
	}
}

// Current returns the current port.
func (p *PortRotator) Current() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// Rotate rotates to the next port.
func (p *PortRotator) Rotate() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.index = (p.index + 1) % len(p.ports)
	p.current = p.ports[p.index]
	return p.current
}

// Schedule represents a rotation schedule.
type Schedule struct {
	Interval   time.Duration
	KeyRotate  bool
	PortRotate bool
	TimeWindow struct {
		Start time.Time
		End   time.Time
	}
}

// ShouldRotate returns true if rotation should occur.
func (s *Schedule) ShouldRotate(lastRotation time.Time) bool {
	if time.Since(lastRotation) < s.Interval {
		return false
	}

	now := time.Now()
	if !s.TimeWindow.Start.IsZero() && now.Before(s.TimeWindow.Start) {
		return false
	}
	if !s.TimeWindow.End.IsZero() && now.After(s.TimeWindow.End) {
		return false
	}

	return true
}
