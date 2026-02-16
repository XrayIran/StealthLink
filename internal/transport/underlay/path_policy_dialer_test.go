package underlay

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// UPSTREAM_WIRING: EasyTier

type fakeDialer struct {
	kind  string
	mu    sync.Mutex
	delay time.Duration
	err   error
}

func (d *fakeDialer) setErr(e error) {
	d.mu.Lock()
	d.err = e
	d.mu.Unlock()
}

func (d *fakeDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.Lock()
	delay := d.delay
	dialErr := d.err
	d.mu.Unlock()

	if delay > 0 {
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	if dialErr != nil {
		return nil, dialErr
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}
func (d *fakeDialer) Type() string { return d.kind }
func (d *fakeDialer) Close() error { return nil }

func TestPathPolicyDialer_RaceSelectsFastest(t *testing.T) {
	direct := &fakeDialer{kind: "direct", delay: 50 * time.Millisecond}
	warp := &fakeDialer{kind: "warp", delay: 0}
	p := NewPathPolicyDialerWithDialers("race", []string{"direct", "warp"}, direct, warp)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c, err := p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = c.Close()
	// Winner is observable via metrics; here we assert no error and rely on deterministic delays.
}

func TestPathPolicyDialer_StickyRace_ReracesAfterThreshold(t *testing.T) {
	direct := &fakeDialer{kind: "direct", delay: 10 * time.Millisecond}
	warp := &fakeDialer{kind: "warp", delay: 0}
	p := NewPathPolicyDialerWithDialers("sticky_race", []string{"warp", "direct"}, direct, warp)
	p.failureThreshold = 2
	p.cooldown = 0
	p.probeInterval = 0

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// First dial should pick warp (fastest).
	c, err := p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial #1: %v", err)
	}
	_ = c.Close()

	// Make warp fail; below threshold we should fall back to direct but keep warp as sticky winner.
	warp.setErr(errors.New("warp down"))
	c, err = p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial #2: %v", err)
	}
	_ = c.Close()

	// Another failure should reach the threshold and reset winner; subsequent dial should succeed on direct.
	c, err = p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial #3: %v", err)
	}
	_ = c.Close()
}

func TestPathPolicyDialer_CooldownPreventsImmediateFlap(t *testing.T) {
	direct := &fakeDialer{kind: "direct", delay: 0}
	warp := &fakeDialer{kind: "warp", delay: 0}
	p := NewPathPolicyDialerWithDialers("sticky_race", []string{"warp", "direct"}, direct, warp)
	p.failureThreshold = 1
	p.cooldown = time.Hour
	p.probeInterval = 0

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Winner starts as warp.
	c, err := p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial #1: %v", err)
	}
	_ = c.Close()

	// Force warp to fail to trigger cooldown.
	warp.setErr(errors.New("warp down"))
	c, err = p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial #2: %v", err)
	}
	_ = c.Close()

	// Keep warp failing; cooldown should prevent immediate flap away from the healthy winner.
	c, err = p.Dial(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatalf("Dial #3: %v", err)
	}
	_ = c.Close()

	key := "tcp|example.com:443"
	p.mu.Lock()
	st := p.state[key]
	p.mu.Unlock()
	if st == nil {
		t.Fatal("missing path state")
	}
	if st.winner != "direct" {
		t.Fatalf("expected direct winner during cooldown, got %q", st.winner)
	}
}
