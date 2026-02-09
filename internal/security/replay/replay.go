// Package replay provides consolidated replay attack protection.
// It supports multiple window implementations: bit window, bloom filter, and hybrid.
package replay

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"sync/atomic"
)

// Detector is the interface for replay detection
type Detector interface {
	// Check returns true if the packet is new (not a replay)
	Check(identifier []byte) bool
	// CheckAndAdd checks and adds the identifier atomically
	CheckAndAdd(identifier []byte) bool
	// Reset clears all state
	Reset()
	// Size returns the current state size
	Size() int64
}

// Type represents the type of replay detector
type Type string

const (
	TypeBitWindow   Type = "bitwindow"  // 64-bit sliding window
	TypeBloomFilter Type = "bloom"      // Bloom filter
	TypeHybrid      Type = "hybrid"     // Both bit window + bloom filter
)

// Config configures replay protection
type Config struct {
	Type Type
	// Bit window config
	WindowSize int
	// Bloom filter config
	BloomSize      uint
	BloomHashes    uint
	FalsePositive  float64
}

// DefaultConfig returns the default replay protection config
func DefaultConfig() *Config {
	return &Config{
		Type:          TypeHybrid,
		WindowSize:    64,
		BloomSize:     1 << 20, // ~1 million entries
		BloomHashes:   4,
		FalsePositive: 0.001,
	}
}

// New creates a new replay detector based on config
func New(config *Config) (Detector, error) {
	if config == nil {
		config = DefaultConfig()
	}

	switch config.Type {
	case TypeBitWindow:
		// Use existing BitWindow from bitwindow.go
		return &bitWindowAdapter{NewBitWindow(config.WindowSize)}, nil
	case TypeBloomFilter:
		return NewBloomFilter(config.BloomSize, config.BloomHashes), nil
	case TypeHybrid:
		return NewHybrid(config), nil
	default:
		return nil, fmt.Errorf("unknown replay detector type: %s", config.Type)
	}
}

// bitWindowAdapter adapts the existing BitWindow to the Detector interface
type bitWindowAdapter struct {
	bw *BitWindow
}

func (a *bitWindowAdapter) Check(identifier []byte) bool {
	if len(identifier) < 8 {
		h := sha256.Sum256(identifier)
		identifier = h[:8]
	}
	seq := uint64(identifier[0])<<56 | uint64(identifier[1])<<48 |
		uint64(identifier[2])<<40 | uint64(identifier[3])<<32 |
		uint64(identifier[4])<<24 | uint64(identifier[5])<<16 |
		uint64(identifier[6])<<8 | uint64(identifier[7])
	return a.bw.IsValid(seq)
}

func (a *bitWindowAdapter) CheckAndAdd(identifier []byte) bool {
	if len(identifier) < 8 {
		h := sha256.Sum256(identifier)
		identifier = h[:8]
	}
	seq := uint64(identifier[0])<<56 | uint64(identifier[1])<<48 |
		uint64(identifier[2])<<40 | uint64(identifier[3])<<32 |
		uint64(identifier[4])<<24 | uint64(identifier[5])<<16 |
		uint64(identifier[6])<<8 | uint64(identifier[7])
	return a.bw.IsValid(seq)
}

func (a *bitWindowAdapter) Reset() {
	a.bw.Reset()
}

func (a *bitWindowAdapter) Size() int64 {
	return int64(a.bw.Size())
}

// Hybrid combines bit window and bloom filter
type Hybrid struct {
	window *BitWindow
	bloom  *BloomFilter
	mu     sync.RWMutex
}

// NewHybrid creates a new hybrid detector
func NewHybrid(config *Config) *Hybrid {
	return &Hybrid{
		window: NewBitWindow(config.WindowSize),
		bloom:  NewBloomFilter(config.BloomSize, config.BloomHashes),
	}
}

// Check checks both detectors
func (h *Hybrid) Check(identifier []byte) bool {
	return h.window.IsValid(extractSeq(identifier)) && h.bloom.Check(identifier)
}

// CheckAndAdd checks and adds to both detectors
func (h *Hybrid) CheckAndAdd(identifier []byte) bool {
	// Must pass both checks
	if !h.window.IsValid(extractSeq(identifier)) {
		return false
	}

	if !h.bloom.CheckAndAdd(identifier) {
		return false
	}

	return true
}

// Reset clears both detectors
func (h *Hybrid) Reset() {
	h.window.Reset()
	h.bloom.Reset()
}

// Size returns the combined size
func (h *Hybrid) Size() int64 {
	return int64(h.window.Size()) + h.bloom.Size()
}

func extractSeq(identifier []byte) uint64 {
	if len(identifier) < 8 {
		h := sha256.Sum256(identifier)
		identifier = h[:8]
	}
	return uint64(identifier[0])<<56 | uint64(identifier[1])<<48 |
		uint64(identifier[2])<<40 | uint64(identifier[3])<<32 |
		uint64(identifier[4])<<24 | uint64(identifier[5])<<16 |
		uint64(identifier[6])<<8 | uint64(identifier[7])
}

// BloomFilter provides bloom filter based replay detection
type BloomFilter struct {
	bits    []uint64
	size    uint
	hashes  uint
	count   atomic.Int64
	mu      sync.RWMutex
}

// NewBloomFilter creates a new bloom filter
func NewBloomFilter(size uint, hashes uint) *BloomFilter {
	// Round up to nearest 64
	numWords := (size + 63) / 64
	return &BloomFilter{
		bits:   make([]uint64, numWords),
		size:   size,
		hashes: hashes,
	}
}

// Check checks if the identifier might be new
func (b *BloomFilter) Check(identifier []byte) bool {
	return !b.mightContain(identifier)
}

// CheckAndAdd checks and adds the identifier
func (b *BloomFilter) CheckAndAdd(identifier []byte) bool {
	if b.mightContain(identifier) {
		return false
	}

	b.add(identifier)
	return true
}

func (b *BloomFilter) mightContain(data []byte) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for i := uint(0); i < b.hashes; i++ {
		idx := b.hash(data, i)
		word := idx / 64
		bit := idx % 64

		if word >= uint(len(b.bits)) {
			continue
		}

		if b.bits[word]&(1<<bit) == 0 {
			return false
		}
	}

	return true
}

func (b *BloomFilter) add(data []byte) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := uint(0); i < b.hashes; i++ {
		idx := b.hash(data, i)
		word := idx / 64
		bit := idx % 64

		if word < uint(len(b.bits)) {
			b.bits[word] |= 1 << bit
		}
	}

	b.count.Add(1)
}

func (b *BloomFilter) hash(data []byte, seed uint) uint {
	// FNV-like hash
	const prime64 = 1099511628211
	const offset64 = 14695981039346656037

	h := offset64 + uint64(seed)*prime64
	for _, c := range data {
		h = (h ^ uint64(c)) * prime64
	}

	return uint(h % uint64(b.size))
}

// Reset clears the filter
func (b *BloomFilter) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i := range b.bits {
		b.bits[i] = 0
	}
	b.count.Store(0)
}

// Size returns the size of the filter
func (b *BloomFilter) Size() int64 {
	return int64(len(b.bits) * 8)
}

// Global provides a global replay detector instance
var Global Detector
var globalOnce sync.Once

// InitGlobal initializes the global replay detector
func InitGlobal(config *Config) error {
	var err error
	globalOnce.Do(func() {
		Global, err = New(config)
	})
	return err
}

// GlobalCheck is a convenience function for global check
func GlobalCheck(identifier []byte) bool {
	if Global == nil {
		return true // Pass through if not initialized
	}
	return Global.Check(identifier)
}

// GlobalCheckAndAdd is a convenience function for global check and add
func GlobalCheckAndAdd(identifier []byte) bool {
	if Global == nil {
		return true
	}
	return Global.CheckAndAdd(identifier)
}

// Window64 is a 64-bit replay window compatible with the replay package interface
type Window64 struct {
	window  uint64
	baseSeq uint64
	mu      sync.RWMutex
}

// NewWindow64 creates a new 64-bit replay window
func NewWindow64() *Window64 {
	return &Window64{}
}

// Check checks a sequence number
func (w *Window64) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Update base if newer
	if seq > w.baseSeq {
		diff := seq - w.baseSeq
		if diff >= 64 {
			w.window = 0
		} else {
			w.window <<= diff
		}
		w.baseSeq = seq
	}

	// Check if within window
	if seq > w.baseSeq {
		return true
	}

	diff := w.baseSeq - seq
	if diff >= 64 {
		return false
	}

	bit := uint64(1) << diff
	return w.window&bit == 0
}

// CheckAndAdd checks and adds a sequence number
func (w *Window64) CheckAndAdd(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq > w.baseSeq {
		diff := seq - w.baseSeq
		if diff >= 64 {
			w.window = 0
		} else {
			w.window <<= diff
		}
		w.baseSeq = seq
	}

	if seq <= w.baseSeq {
		diff := w.baseSeq - seq
		if diff >= 64 {
			return false
		}

		bit := uint64(1) << diff
		if w.window&bit != 0 {
			return false
		}

		w.window |= bit
	}

	return true
}

// Reset clears the window
func (w *Window64) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.window = 0
	w.baseSeq = 0
}

// Size returns 8 bytes
func (w *Window64) Size() int {
	return 8
}

// Stats provides replay detector statistics
type Stats struct {
	TotalChecks   uint64
	ReplaysFound  uint64
	MemoryUsed    int64
	FalsePositives uint64
}

// StatsCollector collects statistics from detectors
type StatsCollector struct {
	detector Detector
}

// NewStatsCollector creates a new stats collector
func NewStatsCollector(d Detector) *StatsCollector {
	return &StatsCollector{detector: d}
}

// GetStats returns current statistics
func (s *StatsCollector) GetStats() Stats {
	return Stats{
		MemoryUsed: s.detector.Size(),
	}
}
