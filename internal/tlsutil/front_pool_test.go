package tlsutil

import (
	"testing"
	"time"
)

// UPSTREAM_WIRING: psiphon-tunnel-core

func TestOrderFrontCandidatesDemotesUnhealthyPrimary(t *testing.T) {
	resetFrontPoolsForTest()

	opts := FrontDialOptions{
		Enabled:       true,
		PoolKey:       "k",
		FrontDomain:   "a.example",
		FailoverHosts: []string{"b.example", "c.example"},
	}

	ReportFrontCandidateResult("k", "a.example", false, 0)
	ReportFrontCandidateResult("k", "a.example", false, 0)

	got := OrderFrontCandidates(opts)
	if len(got) != 3 {
		t.Fatalf("unexpected candidates: %v", got)
	}
	if got[0] == "a.example" {
		t.Fatalf("expected unhealthy primary to be demoted, got=%v", got)
	}
}

func TestOrderFrontCandidatesPrimaryRecoversAfterCooldown(t *testing.T) {
	resetFrontPoolsForTest()
	origNow := frontNow
	origCooldown := frontCooldown
	defer func() {
		frontNow = origNow
		frontCooldown = origCooldown
	}()

	now := time.Unix(1700000000, 0)
	frontNow = func() time.Time { return now }
	frontCooldown = 10 * time.Second

	opts := FrontDialOptions{
		Enabled:       true,
		PoolKey:       "k2",
		FrontDomain:   "a.example",
		FailoverHosts: []string{"b.example"},
	}

	ReportFrontCandidateResult(opts.PoolKey, "a.example", false, 0)
	ReportFrontCandidateResult(opts.PoolKey, "a.example", false, 0)
	if got := OrderFrontCandidates(opts); got[0] == "a.example" {
		t.Fatalf("expected demotion before cooldown, got=%v", got)
	}

	now = now.Add(11 * time.Second)
	if got := OrderFrontCandidates(opts); got[0] != "a.example" {
		t.Fatalf("expected recovery after cooldown, got=%v", got)
	}
}

func TestOrderConnectIPCandidatesDemotesAndRecovers(t *testing.T) {
	resetConnectPoolsForTest()
	origNow := connectNow
	origCooldown := connectCooldown
	defer func() {
		connectNow = origNow
		connectCooldown = origCooldown
	}()

	now := time.Unix(1700000000, 0)
	connectNow = func() time.Time { return now }
	connectCooldown = 10 * time.Second

	key := "df:real.example"
	cands := []string{"203.0.113.1", "203.0.113.2"}

	ReportConnectIPResult(key, "203.0.113.1", false, 0)
	ReportConnectIPResult(key, "203.0.113.1", false, 0)
	got := OrderConnectIPCandidates(key, cands)
	if len(got) != 2 {
		t.Fatalf("unexpected candidates: %v", got)
	}
	if got[0] == "203.0.113.1" {
		t.Fatalf("expected demotion, got=%v", got)
	}

	now = now.Add(11 * time.Second)
	got = OrderConnectIPCandidates(key, cands)
	if got[0] != "203.0.113.1" {
		t.Fatalf("expected recovery after cooldown, got=%v", got)
	}
}
