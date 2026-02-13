package reality

import (
	"context"
	"testing"
	"time"

	"stealthlink/internal/metrics"
)

func TestSpiderIntegrationWithExampleCom(t *testing.T) {
	config := DefaultSpiderConfig()
	config.Enabled = true
	config.SpiderX = "https://www.example.com"
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
