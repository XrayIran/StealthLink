package underlay

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
	"stealthlink/internal/transport/racing"
)

// PathPolicyDialer is an EasyTier-inspired L3 path selector for StealthLink's point-to-point model.
// It races between underlay candidates (direct/WARP) and optionally sticks to a winner until failures
// trigger a re-race.
//
// Note: carrier selection is currently out of scope here; the carrier remains fixed by UQSP variant.
type PathPolicyDialer struct {
	mode             string
	probeInterval    time.Duration
	failureThreshold int
	cooldown         time.Duration

	mu    sync.Mutex
	state map[string]*pathState // key = network|addr

	direct Dialer
	warp   Dialer

	// candidates are strings "direct"|"warp"
	candidates []string
}

type pathState struct {
	winner        string
	lastProbe     time.Time
	failures      int
	cooldownUntil time.Time
}

func NewPathPolicyDialer(uqsp config.UQSPPathPolicyConfig, transportCfg *config.Transport) (*PathPolicyDialer, error) {
	mode := strings.ToLower(strings.TrimSpace(uqsp.Mode))
	if mode == "" {
		mode = "off"
	}
	if mode == "off" {
		return nil, fmt.Errorf("path_policy.mode=off")
	}
	if mode != "race" && mode != "sticky_race" {
		return nil, fmt.Errorf("path_policy.mode must be one of: off, race, sticky_race")
	}
	if transportCfg == nil {
		return nil, fmt.Errorf("transport config is required")
	}

	// Normalize candidates.
	var cands []string
	seen := map[string]bool{}
	for _, c := range uqsp.Candidates {
		u := strings.ToLower(strings.TrimSpace(c.Underlay))
		if u == "" {
			continue
		}
		if u != "direct" && u != "warp" {
			return nil, fmt.Errorf("unsupported candidate underlay: %s", u)
		}
		if !seen[u] {
			seen[u] = true
			cands = append(cands, u)
		}
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("path_policy.candidates is required")
	}

	d := &PathPolicyDialer{
		mode:             mode,
		probeInterval:    uqsp.ProbeInterval,
		failureThreshold: uqsp.FailureThreshold,
		cooldown:         uqsp.Cooldown,
		state:            map[string]*pathState{},
		direct:           NewDirectDialer(),
		candidates:       cands,
	}
	if d.probeInterval == 0 {
		d.probeInterval = 30 * time.Second
	}
	if d.failureThreshold <= 0 {
		d.failureThreshold = 3
	}
	if d.cooldown == 0 {
		d.cooldown = 30 * time.Second
	}

	// Only initialize WARP dialer if needed.
	for _, c := range cands {
		if c == "warp" {
			w, err := NewWARPDialer(transportCfg.WARPDialer)
			if err != nil {
				return nil, err
			}
			d.warp = w
			break
		}
	}
	return d, nil
}

// NewPathPolicyDialerWithDialers is test-only; it allows injecting fake underlays.
func NewPathPolicyDialerWithDialers(mode string, candidates []string, direct Dialer, warp Dialer) *PathPolicyDialer {
	return &PathPolicyDialer{
		mode:             strings.ToLower(strings.TrimSpace(mode)),
		probeInterval:    30 * time.Second,
		failureThreshold: 3,
		cooldown:         30 * time.Second,
		state:            map[string]*pathState{},
		candidates:       candidates,
		direct:           direct,
		warp:             warp,
	}
}

func (d *PathPolicyDialer) Type() string { return "path_policy" }

func (d *PathPolicyDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var firstErr error
	if d.warp != nil {
		if err := d.warp.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		d.warp = nil
	}
	if d.direct != nil {
		_ = d.direct.Close()
		d.direct = nil
	}
	return firstErr
}

func (d *PathPolicyDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	key := strings.ToLower(strings.TrimSpace(network)) + "|" + strings.TrimSpace(address)
	if d.mode == "race" {
		return d.raceOnce(ctx, network, address)
	}
	return d.stickyRace(ctx, key, network, address)
}

func (d *PathPolicyDialer) stickyRace(ctx context.Context, key, network, address string) (net.Conn, error) {
	d.mu.Lock()
	st := d.state[key]
	if st == nil {
		st = &pathState{}
		d.state[key] = st
	}
	now := time.Now()
	winner := st.winner
	inCooldown := now.Before(st.cooldownUntil)
	shouldProbe := !inCooldown && d.probeInterval > 0 && winner != "" && now.Sub(st.lastProbe) >= d.probeInterval
	failures := st.failures
	d.mu.Unlock()

	// Fast path: try winner first unless in cooldown. Probe periodically by forcing a race.
	if winner != "" && !inCooldown && !shouldProbe {
		start := time.Now()
		conn, err := d.dialUnderlay(ctx, winner, network, address)
		metrics.ObservePathPolicyDialLatency(winner, time.Since(start))
		if err == nil {
			metrics.SetUnderlaySelected(winner)
			metrics.IncPathPolicyWinnerSelection(winner)
			return conn, nil
		}

		// Winner failed: below threshold we fail over for this dial but keep the winner sticky.
		if failures+1 < d.failureThreshold {
			d.noteFailure(key, winner, false)
			conn, alt, aerr := d.raceExcluding(ctx, winner, network, address)
			if aerr == nil {
				metrics.SetUnderlaySelected(alt)
				metrics.IncPathPolicyWinnerSelection(alt)
				return conn, nil
			}
			// Fall back to original error if alternates also failed.
			return nil, err
		}

		// Threshold reached: cooldown the old winner and force a full race.
		d.noteFailure(key, winner, true)
	}

	// If we got here, either no winner yet, winner failed too much, probe is due, or cooldown.
	metrics.IncPathPolicyRerace()
	conn, win, err := d.raceOnceWithWinner(ctx, network, address)
	d.mu.Lock()
	st = d.state[key]
	if st == nil {
		st = &pathState{}
		d.state[key] = st
	}
	st.lastProbe = time.Now()
	if err == nil {
		st.winner = win
		st.failures = 0
	}
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	metrics.SetUnderlaySelected(win)
	metrics.IncPathPolicyWinnerSelection(win)
	return conn, nil
}

func (d *PathPolicyDialer) noteFailure(key, winner string, forceCooldown bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	st := d.state[key]
	if st == nil {
		st = &pathState{}
		d.state[key] = st
	}
	st.failures++
	if forceCooldown || st.failures >= d.failureThreshold {
		st.cooldownUntil = time.Now().Add(d.cooldown)
		st.winner = ""
		st.failures = 0
	}
}

func (d *PathPolicyDialer) raceOnce(ctx context.Context, network, address string) (net.Conn, error) {
	conn, win, err := d.raceOnceWithWinner(ctx, network, address)
	if err != nil {
		return nil, err
	}
	metrics.SetUnderlaySelected(win)
	metrics.IncPathPolicyWinnerSelection(win)
	return conn, nil
}

func (d *PathPolicyDialer) raceOnceWithWinner(ctx context.Context, network, address string) (net.Conn, string, error) {
	r := racing.NewRacer()
	// Keep races quick; failures should fall back to next candidate or error fast.
	r.SetConfig(0, len(d.candidates), 10*time.Second)

	for _, c := range d.candidates {
		c := c
		r.AddCandidate(&racing.Candidate{
			Name:     c,
			Priority: 0,
			Dialer: func(ctx context.Context) (net.Conn, error) {
				return d.dialUnderlay(ctx, c, network, address)
			},
		})
	}

	start := time.Now()
	res, err := r.Race(ctx)
	if err != nil {
		return nil, "", err
	}
	if res.Winner == nil || res.Conn == nil {
		return nil, "", fmt.Errorf("race produced no winner")
	}
	metrics.ObservePathPolicyDialLatency(res.Winner.Name, time.Since(start))
	return res.Conn, res.Winner.Name, nil
}

func (d *PathPolicyDialer) raceExcluding(ctx context.Context, exclude, network, address string) (net.Conn, string, error) {
	r := racing.NewRacer()
	r.SetConfig(0, len(d.candidates), 10*time.Second)
	for _, c := range d.candidates {
		if c == exclude {
			continue
		}
		c := c
		r.AddCandidate(&racing.Candidate{
			Name:     c,
			Priority: 0,
			Dialer: func(ctx context.Context) (net.Conn, error) {
				return d.dialUnderlay(ctx, c, network, address)
			},
		})
	}
	start := time.Now()
	res, err := r.Race(ctx)
	if err != nil {
		return nil, "", err
	}
	if res.Winner == nil || res.Conn == nil {
		return nil, "", fmt.Errorf("race produced no winner")
	}
	metrics.ObservePathPolicyDialLatency(res.Winner.Name, time.Since(start))
	return res.Conn, res.Winner.Name, nil
}

func (d *PathPolicyDialer) dialUnderlay(ctx context.Context, which, network, address string) (net.Conn, error) {
	switch which {
	case "direct":
		if d.direct == nil {
			return nil, fmt.Errorf("direct dialer unavailable")
		}
		return d.direct.Dial(ctx, network, address)
	case "warp":
		if d.warp == nil {
			return nil, fmt.Errorf("warp dialer unavailable")
		}
		return d.warp.Dial(ctx, network, address)
	default:
		return nil, fmt.Errorf("unknown underlay: %s", which)
	}
}
