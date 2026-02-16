package reality

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"stealthlink/internal/metrics"
)

func TestSpiderIntegrationWithExampleCom(t *testing.T) {
	// Use a local server instead of the public internet to avoid flakiness.
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body><a href="/next">next</a></body></html>`))
	})
	mux.HandleFunc("/next", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><body>ok</body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = srv.URL + "/"
	config.MaxDepth = 1
	config.MaxTotalFetches = 2
	config.Concurrency = 2
	config.Timeout = 10 * time.Second

	spider := NewSpider(config)
	
	initialFetches := metrics.SnapshotData().RealitySpiderFetchesTotal
	
	err := spider.Start(context.Background())
	if err != nil {
		t.Fatalf("Spider failed: %v", err)
	}
	
	finalSnapshot := metrics.SnapshotData()
	if finalSnapshot.RealitySpiderFetchesTotal <= initialFetches {
		t.Errorf("Expected spider fetches to increase, still %d", finalSnapshot.RealitySpiderFetchesTotal)
	}
	
	if finalSnapshot.RealitySpiderDurationSeconds <= 0 {
		t.Errorf("Expected spider duration to be positive, got %f", finalSnapshot.RealitySpiderDurationSeconds)
	}
	
	t.Logf("Spider finished in %f seconds with %d fetches", 
		finalSnapshot.RealitySpiderDurationSeconds, 
		finalSnapshot.RealitySpiderFetchesTotal - initialFetches)
}
