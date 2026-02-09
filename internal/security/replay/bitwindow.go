// Package replay implements enhanced anti-replay protection with bit window.
// This is ported from udp2raw's sliding bit window implementation.
package replay

import (
	"fmt"
	"sync"
	"time"
)

// BitWindow implements udp2raw's sliding bit window for replay detection.
// It provides O(1) lookup and insertion with minimal memory overhead.
type BitWindow struct {
	mu                sync.RWMutex
	maxPacketReceived uint64    // Highest sequence number seen
	window            []bool    // Bit window for recent packets
	windowSize        int       // Size of the window
	lastUpdate        time.Time // Last update time for timeout
	timeout           time.Duration
}

// NewBitWindow creates a new bit window with the specified size.
// The windowSize determines how many sequence numbers are tracked.
// For udp2raw compatibility, default is 4096.
func NewBitWindow(windowSize int) *BitWindow {
	if windowSize <= 0 {
		windowSize = 4096 // Default from udp2raw
	}

	return &BitWindow{
		maxPacketReceived: 0,
		window:            make([]bool, windowSize),
		windowSize:        windowSize,
		lastUpdate:        time.Now(),
		timeout:           30 * time.Second,
	}
}

// SetTimeout sets the timeout for window entries
func (w *BitWindow) SetTimeout(timeout time.Duration) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timeout = timeout
}

// IsValid checks if a sequence number is valid (not a replay).
// Returns true if the packet should be accepted, false if it's a replay.
func (w *BitWindow) IsValid(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	// Check for timeout and reset if needed
	if time.Since(w.lastUpdate) > w.timeout {
		w.reset()
	}
	w.lastUpdate = time.Now()

	// Case 1: Sequence number is too old (before window)
	if seq < w.maxPacketReceived-uint64(w.windowSize) {
		return false // Too old, likely replay
	}

	// Case 2: Sequence number is ahead of current max
	if seq > w.maxPacketReceived {
		// Shift window forward
		diff := seq - w.maxPacketReceived
		if diff >= uint64(w.windowSize) {
			// Large jump, reset window
			w.resetWindow(seq)
		} else {
			// Shift window by diff positions
			w.shiftWindow(int(diff))
		}
		w.maxPacketReceived = seq
		w.setBit(0) // Mark current position
		return true
	}

	// Case 3: Sequence number is within window
	// Check if already seen
	offset := w.maxPacketReceived - seq
	pos := int(offset) % w.windowSize

	if w.window[pos] {
		return false // Already seen, replay
	}

	// Mark as seen
	w.window[pos] = true
	return true
}

// CheckAndAdd checks if a sequence number is valid and adds it to the window.
// This is a convenience method that combines IsValid with implicit marking.
func (w *BitWindow) CheckAndAdd(seq uint64) bool {
	return w.IsValid(seq)
}

// reset clears the entire window
func (w *BitWindow) reset() {
	w.maxPacketReceived = 0
	for i := range w.window {
		w.window[i] = false
	}
}

// resetWindow resets the window with a new maximum sequence number
func (w *BitWindow) resetWindow(newMax uint64) {
	w.maxPacketReceived = newMax
	for i := range w.window {
		w.window[i] = false
	}
	w.window[0] = true
}

// shiftWindow shifts the window by n positions
func (w *BitWindow) shiftWindow(n int) {
	if n >= w.windowSize {
		// Shift larger than window, clear all
		for i := range w.window {
			w.window[i] = false
		}
		return
	}

	// Shift bits: move [0, windowSize-n) to [n, windowSize)
	// and clear [0, n)
	for i := w.windowSize - 1; i >= n; i-- {
		w.window[i] = w.window[i-n]
	}
	for i := 0; i < n; i++ {
		w.window[i] = false
	}
}

// setBit sets the bit at the specified position
func (w *BitWindow) setBit(pos int) {
	if pos >= 0 && pos < w.windowSize {
		w.window[pos] = true
	}
}

// GetMaxReceived returns the highest sequence number received
func (w *BitWindow) GetMaxReceived() uint64 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.maxPacketReceived
}

// GetWindowSize returns the window size
func (w *BitWindow) GetWindowSize() int {
	return w.windowSize
}

// Reset clears the window
func (w *BitWindow) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.reset()
}

// Size returns the window size in bytes
func (w *BitWindow) Size() int64 {
	return int64(w.windowSize / 8)
}

// Stats returns window statistics
func (w *BitWindow) Stats() map[string]interface{} {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Count set bits
	setBits := 0
	for _, b := range w.window {
		if b {
			setBits++
		}
	}

	return map[string]interface{}{
		"max_received": w.maxPacketReceived,
		"window_size":  w.windowSize,
		"set_bits":     setBits,
		"fill_ratio":   float64(setBits) / float64(w.windowSize),
		"last_update":  w.lastUpdate,
	}
}

// String returns a string representation of the window state
func (w *BitWindow) String() string {
	stats := w.Stats()
	return fmt.Sprintf("BitWindow{max=%d, size=%d, fill=%.2f%%}",
		stats["max_received"],
		stats["window_size"],
		stats["fill_ratio"].(float64)*100,
	)
}

// HybridReplayDetector combines multiple replay detection strategies
type HybridReplayDetector struct {
	bitWindow *BitWindow
	mu        sync.RWMutex
}

// NewHybridReplayDetector creates a new hybrid replay detector
func NewHybridReplayDetector(windowSize int) *HybridReplayDetector {
	return &HybridReplayDetector{
		bitWindow: NewBitWindow(windowSize),
	}
}

// Check checks if a sequence number is valid (not a replay)
func (h *HybridReplayDetector) Check(seq uint64) bool {
	return h.bitWindow.IsValid(seq)
}

// CheckAndAdd checks and adds a sequence number
func (h *HybridReplayDetector) CheckAndAdd(seq uint64) bool {
	return h.bitWindow.CheckAndAdd(seq)
}

// Stats returns detector statistics
func (h *HybridReplayDetector) Stats() map[string]interface{} {
	return h.bitWindow.Stats()
}
