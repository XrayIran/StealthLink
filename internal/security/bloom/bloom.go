// Package bloom implements dual rotating Bloom filters for replay protection.
// This is inspired by shadowsocks-rust's ping-pong Bloom filter implementation.
package bloom

import (
	"hash/fnv"
	"math"
	"sync"
	"time"
)

// Filter implements a rotating Bloom filter for replay detection.
type Filter struct {
	mu          sync.RWMutex
	current     *bloomFilter
	previous    *bloomFilter
	capacity    uint64
	errorRate   float64
	rotateEvery time.Duration
	lastRotate  time.Time
}

// bloomFilter is a single Bloom filter.
type bloomFilter struct {
	bits     []uint64
	size     uint64
	numHash  uint64
	count    uint64
}

// New creates a new dual rotating Bloom filter.
//
// For server: capacity=1,000,000, errorRate=1e-6
// For client: capacity=10,000, errorRate=1e-15
func New(capacity uint64, errorRate float64) *Filter {
	return NewWithRotation(capacity, errorRate, 60*time.Second)
}

// NewWithRotation creates a Bloom filter with custom rotation interval.
func NewWithRotation(capacity uint64, errorRate float64, rotateEvery time.Duration) *Filter {
	return &Filter{
		capacity:    capacity,
		errorRate:   errorRate,
		rotateEvery: rotateEvery,
		lastRotate:  time.Now(),
		current:     newBloomFilter(capacity, errorRate),
		previous:    newBloomFilter(capacity, errorRate),
	}
}

// CheckAndAdd checks if an element exists and adds it to the filter.
// Returns true if the element was already present (suspected replay).
func (f *Filter) CheckAndAdd(data []byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if rotation is needed
	if time.Since(f.lastRotate) > f.rotateEvery {
		f.rotate()
	}

	// Check current filter
	if f.current.contains(data) {
		return true
	}

	// Check previous filter
	if f.previous.contains(data) {
		return true
	}

	// Add to current filter
	f.current.add(data)
	return false
}

// Check checks if an element exists without adding it.
func (f *Filter) Check(data []byte) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return f.current.contains(data) || f.previous.contains(data)
}

// Add adds an element to the filter.
func (f *Filter) Add(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Check if rotation is needed
	if time.Since(f.lastRotate) > f.rotateEvery {
		f.rotate()
	}

	f.current.add(data)
}

// rotate swaps current and previous filters and clears the new current.
func (f *Filter) rotate() {
	f.previous = f.current
	f.current = newBloomFilter(f.capacity, f.errorRate)
	f.lastRotate = time.Now()
}

// Reset clears both filters.
func (f *Filter) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.current = newBloomFilter(f.capacity, f.errorRate)
	f.previous = newBloomFilter(f.capacity, f.errorRate)
	f.lastRotate = time.Now()
}

// Stats returns current filter statistics.
func (f *Filter) Stats() map[string]interface{} {
	f.mu.RLock()
	defer f.mu.RUnlock()

	return map[string]interface{}{
		"current_count":  f.current.count,
		"previous_count": f.previous.count,
		"capacity":       f.capacity,
		"error_rate":     f.errorRate,
		"time_to_rotate": f.rotateEvery - time.Since(f.lastRotate),
	}
}

// newBloomFilter creates a new Bloom filter with optimal size.
func newBloomFilter(capacity uint64, errorRate float64) *bloomFilter {
	// Calculate optimal bit array size
	// m = -n * ln(p) / (ln(2)^2)
	size := uint64(-float64(capacity) * math.Log(errorRate) / (math.Ln2 * math.Ln2))

	// Round up to nearest 64 bits
	numWords := (size + 63) / 64
	size = numWords * 64

	// Calculate optimal number of hash functions
	// k = m/n * ln(2)
	numHash := uint64(float64(size) / float64(capacity) * math.Ln2)
	if numHash < 1 {
		numHash = 1
	}
	if numHash > 30 {
		numHash = 30
	}

	return &bloomFilter{
		bits:    make([]uint64, numWords),
		size:    size,
		numHash: numHash,
	}
}

// contains checks if data is possibly in the filter.
func (b *bloomFilter) contains(data []byte) bool {
	h1, h2 := b.hash(data)

	for i := uint64(0); i < b.numHash; i++ {
		idx := (h1 + i*h2) % b.size
		wordIdx := idx / 64
		bitIdx := idx % 64

		if b.bits[wordIdx]&(1<<bitIdx) == 0 {
			return false
		}
	}
	return true
}

// add inserts data into the filter.
func (b *bloomFilter) add(data []byte) {
	h1, h2 := b.hash(data)

	for i := uint64(0); i < b.numHash; i++ {
		idx := (h1 + i*h2) % b.size
		wordIdx := idx / 64
		bitIdx := idx % 64

		b.bits[wordIdx] |= 1 << bitIdx
	}

	b.count++
}

// hash generates two hash values using double hashing.
func (b *bloomFilter) hash(data []byte) (h1, h2 uint64) {
	h := fnv.New64a()
	h.Write(data)
	h1 = h.Sum64()

	h.Reset()
	h.Write(data)
	h.Write([]byte{0x5c}) // Different seed
	h2 = h.Sum64()

	if h2 == 0 {
		h2 = 1
	}

	return h1, h2
}

// SlidingWindow implements a time-based sliding window for replay detection.
type SlidingWindow struct {
	mu          sync.RWMutex
	window      map[uint64]time.Time
	windowSize  time.Duration
	maxSize     int
}

// NewSlidingWindow creates a new sliding window replay detector.
func NewSlidingWindow(windowSize time.Duration, maxSize int) *SlidingWindow {
	return &SlidingWindow{
		window:     make(map[uint64]time.Time),
		windowSize: windowSize,
		maxSize:    maxSize,
	}
}

// CheckAndAdd checks if a nonce exists and adds it.
func (w *SlidingWindow) CheckAndAdd(nonce uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()

	// Clean old entries if needed
	if len(w.window) > w.maxSize {
		w.cleanup(now)
	}

	// Check if nonce exists
	if ts, exists := w.window[nonce]; exists {
		// Check if still within window
		if now.Sub(ts) < w.windowSize {
			return true // Replay detected
		}
	}

	// Add/update nonce
	w.window[nonce] = now
	return false
}

// cleanup removes old entries from the window.
func (w *SlidingWindow) cleanup(now time.Time) {
	for nonce, ts := range w.window {
		if now.Sub(ts) > w.windowSize {
			delete(w.window, nonce)
		}
	}
}

// HybridFilter combines Bloom filter with sliding window for high accuracy.
type HybridFilter struct {
	bloom   *Filter
	window  *SlidingWindow
	mu      sync.RWMutex
}

// NewHybrid creates a new hybrid replay filter.
func NewHybrid(bloomCapacity uint64, bloomErrorRate float64, windowSize time.Duration, windowMaxSize int) *HybridFilter {
	return &HybridFilter{
		bloom:  New(bloomCapacity, bloomErrorRate),
		window: NewSlidingWindow(windowSize, windowMaxSize),
	}
}

// CheckAndAdd checks if data is a replay using both Bloom filter and sliding window.
func (h *HybridFilter) CheckAndAdd(data []byte) bool {
	// First check Bloom filter (fast, may have false positives)
	if !h.bloom.CheckAndAdd(data) {
		return false // Definitely not a replay
	}

	// Bloom filter says it might be a replay, check sliding window
	// Hash data to get a nonce for the sliding window
	hash := fnv.New64a()
	hash.Write(data)
	nonce := hash.Sum64()

	return h.window.CheckAndAdd(nonce)
}

// Stats returns statistics for both filters.
func (h *HybridFilter) Stats() map[string]interface{} {
	return map[string]interface{}{
		"bloom":  h.bloom.Stats(),
		"window": map[string]interface{}{
			"size":       len(h.window.window),
			"max_size":   h.window.maxSize,
			"window_sec": h.window.windowSize.Seconds(),
		},
	}
}

// DefaultServerFilter creates a default server-side replay filter.
func DefaultServerFilter() *Filter {
	return New(1_000_000, 1e-6) // 1M capacity, 0.0001% error rate
}

// DefaultClientFilter creates a default client-side replay filter.
func DefaultClientFilter() *Filter {
	return New(10_000, 1e-15) // 10K capacity, extremely low error rate
}

// DefaultHybridServer creates a default hybrid server filter.
func DefaultHybridServer() *HybridFilter {
	return NewHybrid(1_000_000, 1e-6, 5*time.Minute, 100_000)
}

// DefaultHybridClient creates a default hybrid client filter.
func DefaultHybridClient() *HybridFilter {
	return NewHybrid(10_000, 1e-15, 1*time.Minute, 10_000)
}
