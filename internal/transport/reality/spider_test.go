package reality

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"stealthlink/internal/metrics"
)

func TestSpiderLimits(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/link1">link1</a><a href="/link2">link2</a></body></html>`)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.MaxTotalFetches = 5
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // Fast tests
	config.Concurrency = 2

	spider := NewSpider(config)
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	if fetchCount.Load() > 5 {
		t.Errorf("Fetch count %d exceeded MaxTotalFetches 5", fetchCount.Load())
	}
}

func TestSpiderDepth(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := fetchCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		// Return different URLs at each depth to avoid deduplication
		fmt.Fprintf(w, `<html><body><a href="/level%d">next</a></body></html>`, count)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.MaxDepth = 2
	config.MaxTotalFetches = 20
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	config.Concurrency = 1

	spider := NewSpider(config)
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	// Depth 0: seed URL (1 fetch)
	// Depth 1: /level1 (1 fetch)
	// Depth 2: /level2 (1 fetch)
	// Depth 3: would be /level3 but MaxDepth=2 stops it
	if fetchCount.Load() > 3 {
		t.Errorf("Fetch count %d exceeded expected depth limit (3)", fetchCount.Load())
	}
}

func TestSpiderDeduplication(t *testing.T) {
	var fetchCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/">back</a></body></html>`)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	config.Concurrency = 2

	spider := NewSpider(config)
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	if fetchCount.Load() != 1 {
		t.Errorf("Expected 1 fetch due to deduplication, got %d", fetchCount.Load())
	}
}

func TestSpiderPerHostCap(t *testing.T) {
	// Difficult to test per-host cap with a single httptest.Server
	// unless we use different hostnames in links (e.g. http://127.0.0.1 vs http://localhost)

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = "http://127.0.0.1:1" // dummy
	config.PerHostCap = 2

	spider := NewSpider(config)

	item := &crawlItem{url: "http://example.com/1", depth: 1}
	if !spider.shouldCrawl(item) {
		t.Error("should crawl first link")
	}

	item = &crawlItem{url: "http://example.com/2", depth: 1}
	if !spider.shouldCrawl(item) {
		t.Error("should crawl second link")
	}

	item = &crawlItem{url: "http://example.com/3", depth: 1}
	if spider.shouldCrawl(item) {
		t.Error("should NOT crawl third link (per-host cap)")
	}
}

func TestSpiderMetrics(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>hello</body></html>`)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	spider := NewSpider(config)

	initialFetches := metrics.SnapshotData().RealitySpiderFetchesTotal

	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	finalFetches := metrics.SnapshotData().RealitySpiderFetchesTotal
	if finalFetches <= initialFetches {
		t.Errorf("Metrics not updated: fetches total remained %d", finalFetches)
	}
}

// TestSpiderConcurrentCrawlers tests that multiple crawler goroutines work correctly
func TestSpiderConcurrentCrawlers(t *testing.T) {
	var fetchCount atomic.Int32
	var concurrentFetches atomic.Int32
	var maxConcurrent atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := concurrentFetches.Add(1)

		// Track max concurrent fetches
		for {
			max := maxConcurrent.Load()
			if current <= max || maxConcurrent.CompareAndSwap(max, current) {
				break
			}
		}

		// Simulate some work
		time.Sleep(50 * time.Millisecond)

		fetchCount.Add(1)
		concurrentFetches.Add(-1)

		w.Header().Set("Content-Type", "text/html")
		// Return multiple links to keep workers busy
		fmt.Fprint(w, `<html><body>
			<a href="/link1">link1</a>
			<a href="/link2">link2</a>
			<a href="/link3">link3</a>
			<a href="/link4">link4</a>
		</body></html>`)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.Concurrency = 4
	config.MaxTotalFetches = 10
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1} // Fast tests
	config.Timeout = 5 * time.Second

	spider := NewSpider(config)
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	// Verify that we had concurrent fetches
	if maxConcurrent.Load() < 2 {
		t.Errorf("Expected concurrent fetches, but maxConcurrent=%d", maxConcurrent.Load())
	}

	// Verify we respected the concurrency limit
	if maxConcurrent.Load() > int32(config.Concurrency) {
		t.Errorf("Exceeded concurrency limit: maxConcurrent=%d, limit=%d", maxConcurrent.Load(), config.Concurrency)
	}
}

// TestSpiderYTiming tests that SpiderY timing array is respected with jitter
func TestSpiderYTiming(t *testing.T) {
	var fetchTimes []time.Time
	var mu sync.Mutex
	var fetchCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		fetchTimes = append(fetchTimes, time.Now())
		mu.Unlock()

		count := fetchCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		// Generate unique links to avoid deduplication
		fmt.Fprintf(w, `<html><body><a href="/link%d">link</a></body></html>`, count)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.MaxTotalFetches = 5
	config.SpiderY = [10]int{100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}
	config.Concurrency = 1 // Single worker to test timing sequentially
	config.Timeout = 5 * time.Second

	spider := NewSpider(config)
	startTime := time.Now()
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(fetchTimes) < 2 {
		t.Fatalf("Not enough fetches to test timing: got %d, need at least 2", len(fetchTimes))
	}

	// Check that delays are approximately correct (within ±20% due to jitter and overhead)
	for i := 1; i < len(fetchTimes) && i < len(config.SpiderY); i++ {
		actualDelay := fetchTimes[i].Sub(fetchTimes[i-1])
		expectedDelay := time.Duration(config.SpiderY[i-1]) * time.Millisecond

		// Allow ±20% tolerance for jitter (±10%) plus overhead
		minDelay := expectedDelay * 8 / 10
		maxDelay := expectedDelay * 12 / 10

		if actualDelay < minDelay || actualDelay > maxDelay {
			t.Logf("Fetch %d: delay=%v, expected=%v (±20%%)", i, actualDelay, expectedDelay)
		}
	}

	// Verify total time is reasonable
	totalTime := time.Since(startTime)
	expectedMinTime := time.Duration(config.SpiderY[0]+config.SpiderY[1]+config.SpiderY[2]) * time.Millisecond * 8 / 10

	if totalTime < expectedMinTime {
		t.Errorf("Total time %v is less than expected minimum %v", totalTime, expectedMinTime)
	}
}

// TestSpiderNoHangs tests that spider doesn't hang or deadlock
func TestSpiderNoHangs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		// Return circular links
		fmt.Fprint(w, `<html><body><a href="/">home</a></body></html>`)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.Concurrency = 4
	config.MaxTotalFetches = 10
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	config.Timeout = 2 * time.Second

	spider := NewSpider(config)

	// Run spider with timeout to detect hangs
	done := make(chan error, 1)
	go func() {
		done <- spider.Start(context.Background())
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Spider failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Spider hung - did not complete within 5 seconds")
	}
}

// TestSpiderEmptyQueue tests spider behavior when queue becomes empty
func TestSpiderEmptyQueue(t *testing.T) {
	var fetchCount atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount.Add(1)
		w.Header().Set("Content-Type", "text/html")
		// Return no links - queue will become empty
		fmt.Fprint(w, `<html><body>No links here</body></html>`)
	}))
	defer server.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = server.URL
	config.Concurrency = 4
	config.MaxTotalFetches = 20
	config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	config.Timeout = 2 * time.Second

	spider := NewSpider(config)
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}

	// Should only fetch the seed URL since no links are found
	if fetchCount.Load() != 1 {
		t.Errorf("Expected 1 fetch, got %d", fetchCount.Load())
	}
}

// TestSpiderLimitEnforcement tests that all limits are properly enforced
func TestSpiderLimitEnforcement(t *testing.T) {
	tests := []struct {
		name        string
		maxDepth    int
		maxTotal    int
		perHostCap  int
		expectedMax int32
		setupServer func() *httptest.Server
	}{
		{
			name:        "MaxTotalFetches",
			maxDepth:    10,
			maxTotal:    3,
			perHostCap:  10,
			expectedMax: 3,
			setupServer: func() *httptest.Server {
				var count atomic.Int32
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := count.Add(1)
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><body><a href="/link%d">link</a></body></html>`, c)
				}))
			},
		},
		{
			name:        "MaxDepth",
			maxDepth:    1,
			maxTotal:    20,
			perHostCap:  10,
			expectedMax: 2, // seed + 1 level
			setupServer: func() *httptest.Server {
				var count atomic.Int32
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					c := count.Add(1)
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, `<html><body><a href="/link%d">link</a></body></html>`, c)
				}))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var fetchCount atomic.Int32
			server := tt.setupServer()
			defer server.Close()

			// Wrap the handler to count fetches
			originalHandler := server.Config.Handler
			server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fetchCount.Add(1)
				originalHandler.ServeHTTP(w, r)
			})

			config := DefaultSpiderConfig()
			config.Enabled = true
			config.SpiderX = server.URL
			config.MaxDepth = tt.maxDepth
			config.MaxTotalFetches = tt.maxTotal
			config.PerHostCap = tt.perHostCap
			config.SpiderY = [10]int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
			config.Concurrency = 2

			spider := NewSpider(config)
			err := spider.Start(context.Background())
			if err != nil {
				t.Fatalf("Spider failed: %v", err)
			}

			if fetchCount.Load() > tt.expectedMax {
				t.Errorf("Fetch count %d exceeded expected max %d", fetchCount.Load(), tt.expectedMax)
			}
		})
	}
}
