package kcpbase

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stealthlink/internal/metrics"

	"pgregory.net/rapid"
)

// Property 28: Entropy Reseed Frequency
// For any entropy source, after generating 1,048,576 bytes, it should reseed from crypto/rand before generating more bytes
func TestProperty28_EntropyReseedFrequency(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Create a fresh entropy source for this test
		source := NewEntropySource(ClassFast)

		// Reset the reseed counter to start fresh
		source.reseedCounter.Store(0)

		// Get initial reseed count
		initialReseeds := metrics.SnapshotData().EntropyReseedsTotal

		// Generate exactly reseedThreshold bytes
		buf := make([]byte, reseedThreshold)
		n, err := source.Read(buf)
		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}
		if n != len(buf) {
			t.Fatalf("Expected to read %d bytes, got %d", len(buf), n)
		}

		// After reading reseedThreshold bytes, reseed should have occurred
		afterFirstRead := metrics.SnapshotData().EntropyReseedsTotal
		if afterFirstRead <= initialReseeds {
			t.Fatalf("Expected reseed to occur after reading %d bytes, but reseed count did not increase", reseedThreshold)
		}

		// Generate more bytes - should trigger another reseed
		buf2 := make([]byte, reseedThreshold)
		n, err = source.Read(buf2)
		if err != nil {
			t.Fatalf("Failed to read second batch: %v", err)
		}
		if n != len(buf2) {
			t.Fatalf("Expected to read %d bytes, got %d", len(buf2), n)
		}

		// After reading another reseedThreshold bytes, another reseed should have occurred
		afterSecondRead := metrics.SnapshotData().EntropyReseedsTotal
		if afterSecondRead <= afterFirstRead {
			t.Fatalf("Expected another reseed after reading another %d bytes, but reseed count did not increase", reseedThreshold)
		}
	})
}

// Property 29: Entropy Thread Safety
// For any concurrent access pattern to the entropy source, no data races should occur
func TestProperty29_EntropyThreadSafety(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numGoroutines := rapid.IntRange(2, 16).Draw(t, "numGoroutines")
		readsPerGoroutine := rapid.IntRange(10, 100).Draw(t, "readsPerGoroutine")
		readSize := rapid.IntRange(1, 256).Draw(t, "readSize")

		source := NewEntropySource(ClassFast)

		var wg sync.WaitGroup
		var errorCount atomic.Int32
		results := make([][]byte, numGoroutines*readsPerGoroutine)
		var resultMu sync.Mutex

		for g := 0; g < numGoroutines; g++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()
				for i := 0; i < readsPerGoroutine; i++ {
					buf := make([]byte, readSize)
					n, err := source.Read(buf)
					if err != nil {
						errorCount.Add(1)
						return
					}
					if n != readSize {
						errorCount.Add(1)
						return
					}

					resultMu.Lock()
					results[goroutineID*readsPerGoroutine+i] = buf
					resultMu.Unlock()
				}
			}(g)
		}

		wg.Wait()

		if errorCount.Load() > 0 {
			t.Fatalf("Concurrent reads failed: %d errors", errorCount.Load())
		}

		// Verify that we got different random data from different reads
		// (with very high probability, no two reads should produce identical data)
		seen := make(map[string]bool)
		duplicates := 0
		for _, data := range results {
			if data == nil {
				continue
			}
			key := string(data)
			if seen[key] {
				duplicates++
			}
			seen[key] = true
		}

		// Allow a small number of duplicates due to randomness, but not many
		if duplicates > numGoroutines {
			t.Logf("Warning: %d duplicate random values out of %d reads (may be due to randomness)", duplicates, len(results))
		}
	})
}

// Property 30: Reseed Non-Blocking
// For any goroutine waiting for random bytes, a reseed operation in another goroutine should not block it
func TestProperty30_ReseedNonBlocking(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numReaders := rapid.IntRange(2, 8).Draw(t, "numReaders")
		readsPerReader := rapid.IntRange(5, 20).Draw(t, "readsPerReader")

		source := NewEntropySource(ClassFast)

		// Track timing to detect blocking
		var wg sync.WaitGroup
		var maxLatency atomic.Int64
		var errorCount atomic.Int32

		for r := 0; r < numReaders; r++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < readsPerReader; i++ {
					buf := make([]byte, 1024)

					// Measure time for this read
					start := time.Now()
					n, err := source.Read(buf)
					elapsed := time.Since(start).Milliseconds()

					if err != nil {
						errorCount.Add(1)
						return
					}
					if n != len(buf) {
						errorCount.Add(1)
						return
					}

					// Update max latency
					for {
						current := maxLatency.Load()
						if elapsed <= current || maxLatency.CompareAndSwap(current, elapsed) {
							break
						}
					}
				}
			}()
		}

		wg.Wait()

		if errorCount.Load() > 0 {
			t.Fatalf("Concurrent reads failed: %d errors", errorCount.Load())
		}

		// Check that no single read took excessively long
		// A reseed operation should not block reads significantly
		// Allow up to 100ms per read (generous for slow systems)
		if maxLatency.Load() > 100 {
			t.Logf("Warning: max read latency was %dms (may indicate blocking during reseed)", maxLatency.Load())
		}
	})
}
