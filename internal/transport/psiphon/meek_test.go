package psiphon

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestBuildMeekTargetsFromFrontPairs(t *testing.T) {
	cfg := DefaultMeekConfig()
	cfg.FrontingDomain = "front.cdn.example"
	cfg.Path = "/default"
	cfg.FrontPairs = []MeekFrontPair{
		{Host: "real-a.example", Path: "/a"},
		{Host: "real-b.example"},
	}

	u, _ := url.Parse("https://origin.example/base")
	targets := buildMeekTargets(u, cfg)
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].dialHost != "front.cdn.example" || targets[0].hostHeader != "real-a.example" || targets[0].path != "/a" {
		t.Fatalf("unexpected first target: %+v", targets[0])
	}
	if targets[1].dialHost != "front.cdn.example" || targets[1].hostHeader != "real-b.example" || targets[1].path != "/default" {
		t.Fatalf("unexpected second target: %+v", targets[1])
	}
}

func TestBuildMeekTargetsFromHostsAndPathCandidates(t *testing.T) {
	cfg := DefaultMeekConfig()
	cfg.FrontingDomain = "front.cdn.example"
	cfg.FrontingHosts = []string{"h1.example", "h2.example"}
	cfg.Path = "/p0"
	cfg.PathCandidates = []string{"/p1", "p2"}

	u, _ := url.Parse("https://origin.example/base")
	targets := buildMeekTargets(u, cfg)
	if len(targets) != 6 {
		t.Fatalf("expected 6 targets, got %d", len(targets))
	}
	if targets[0].hostHeader != "h1.example" || targets[0].path != "/p0" {
		t.Fatalf("unexpected target order[0]: %+v", targets[0])
	}
	if targets[1].hostHeader != "h1.example" || targets[1].path != "/p1" {
		t.Fatalf("unexpected target order[1]: %+v", targets[1])
	}
	if targets[2].hostHeader != "h1.example" || targets[2].path != "/p2" {
		t.Fatalf("unexpected target order[2]: %+v", targets[2])
	}
	if targets[3].hostHeader != "h2.example" || targets[3].path != "/p0" {
		t.Fatalf("unexpected target order[3]: %+v", targets[3])
	}
}

func TestDoRequestWithFailoverFallsBackToHealthyTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			http.Error(w, "blocked", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Server-Token", "ok")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	cfg := DefaultMeekConfig()
	cfg.FrontPairs = []MeekFrontPair{
		{Host: u.Host, Path: "/bad"},
		{Host: u.Host, Path: "/good"},
	}
	cfg.MaxFailoverAttempts = 2

	targets := buildMeekTargets(u, cfg)
	now := time.Now()
	state := make([]meekTargetState, len(targets))
	for i := range state {
		state[i] = meekTargetState{healthScore: 50, lastSuccess: now}
	}
	conn := &MeekConn{
		config:      cfg,
		httpClient:  srv.Client(),
		scheme:      u.Scheme,
		sessionID:   "s1",
		targets:     targets,
		targetState: state,
	}

	resp, err := conn.doRequestWithFailover(http.MethodGet, nil, nil)
	if err != nil {
		t.Fatalf("expected failover success, got error: %v", err)
	}
	resp.Body.Close()

	conn.targetMu.Lock()
	firstFailures := conn.targetState[0].failures
	secondFailures := conn.targetState[1].failures
	secondSuccesses := conn.targetState[1].successes
	secondHealth := conn.targetState[1].healthScore
	conn.targetMu.Unlock()
	if firstFailures == 0 {
		t.Fatal("expected first target failure to be recorded")
	}
	if secondFailures != 0 {
		t.Fatal("expected successful target to have zero failures")
	}
	if secondSuccesses != 1 {
		t.Fatalf("expected 1 success on second target, got %d", secondSuccesses)
	}
	if secondHealth <= 50 {
		t.Fatalf("expected health score to improve after success, got %f", secondHealth)
	}
}

func TestComputeHealthScore(t *testing.T) {
	now := time.Now()

	s := &meekTargetState{
		successes:    10,
		failures:     0,
		avgLatencyMs: 50,
		lastSuccess:  now,
	}
	score := s.computeHealthScore()
	if score < 60 || score > 100 {
		t.Fatalf("expected high health score for good target, got %f", score)
	}

	s2 := &meekTargetState{
		successes:    0,
		failures:     10,
		avgLatencyMs: 2000,
		lastSuccess:  now.Add(-10 * time.Minute),
	}
	score2 := s2.computeHealthScore()
	if score2 >= score {
		t.Fatalf("bad target score %f should be lower than good target score %f", score2, score)
	}
}

func TestOrderedTargetIndexesPrefersHigherHealthScore(t *testing.T) {
	cfg := DefaultMeekConfig()
	conn := &MeekConn{
		config: cfg,
		targets: []meekTarget{
			{dialHost: "a", hostHeader: "a", path: "/"},
			{dialHost: "b", hostHeader: "b", path: "/"},
			{dialHost: "c", hostHeader: "c", path: "/"},
		},
		targetState: []meekTargetState{
			{healthScore: 30, lastSuccess: time.Now()},
			{healthScore: 90, lastSuccess: time.Now()},
			{healthScore: 60, lastSuccess: time.Now()},
		},
	}

	counts := map[int]int{}
	for i := 0; i < 100; i++ {
		order := conn.orderedTargetIndexes()
		counts[order[0]]++
	}
	if counts[1] < 80 {
		t.Fatalf("expected target 1 (highest health) to be first most of the time, got counts=%v", counts)
	}
}

func TestOrderedTargetIndexesSkipsCoolingTarget(t *testing.T) {
	cfg := DefaultMeekConfig()
	cfg.FailureBaseBackoff = 200 * time.Millisecond
	cfg.FailureMaxBackoff = 1 * time.Second

	conn := &MeekConn{
		config: cfg,
		targets: []meekTarget{
			{dialHost: "a", hostHeader: "a", path: "/"},
			{dialHost: "b", hostHeader: "b", path: "/"},
		},
		targetState: make([]meekTargetState, 2),
	}
	conn.markTargetResult(0, false)
	order := conn.orderedTargetIndexes()
	if len(order) == 0 || order[0] != 1 {
		t.Fatalf("expected cooling target to be deprioritized, got order=%v", order)
	}
}
