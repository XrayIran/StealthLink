package tlsutil

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type frontHostState struct {
	consecutiveFailures int
	lastResult          time.Time
}

var (
	frontMu    sync.Mutex
	frontPools = map[string]map[string]*frontHostState{}
	frontNow   = time.Now

	// frontCooldown defines how long a previously failing primary is kept demoted
	// before it is treated as healthy again (technique-only).
	frontCooldown = 30 * time.Second
)

// OrderFrontCandidates returns an ordered list of SNI candidates for a fronting dial.
// It is intentionally conservative: the configured primary is tried first unless it
// has a recent streak of failures, in which case healthier candidates are attempted first.
func OrderFrontCandidates(opts FrontDialOptions) []string {
	primary := strings.TrimSpace(opts.FrontDomain)
	failovers := make([]string, 0, len(opts.FailoverHosts))
	for _, h := range opts.FailoverHosts {
		h = strings.TrimSpace(h)
		if h == "" || h == primary {
			continue
		}
		failovers = append(failovers, h)
	}
	if primary == "" {
		return failovers
	}

	key := strings.TrimSpace(opts.PoolKey)
	if key == "" || len(failovers) == 0 {
		return append([]string{primary}, failovers...)
	}

	frontMu.Lock()
	defer frontMu.Unlock()
	pool := frontPools[key]
	if pool == nil {
		pool = map[string]*frontHostState{}
		frontPools[key] = pool
	}
	st := pool[primary]
	if st == nil || st.consecutiveFailures < 2 {
		return append([]string{primary}, failovers...)
	}
	// Cooldown: after some time, allow primary to be tried first again.
	if frontCooldown > 0 && !st.lastResult.IsZero() && frontNow().Sub(st.lastResult) >= frontCooldown {
		return append([]string{primary}, failovers...)
	}

	// Primary looks unhealthy: sort all candidates by fewer consecutive failures.
	all := append([]string{primary}, failovers...)
	sort.SliceStable(all, func(i, j int) bool {
		ai := pool[all[i]]
		aj := pool[all[j]]
		fi := 0
		fj := 0
		if ai != nil {
			fi = ai.consecutiveFailures
		}
		if aj != nil {
			fj = aj.consecutiveFailures
		}
		return fi < fj
	})
	return all
}

// ReportFrontCandidateResult updates health state for a fronting SNI candidate.
func ReportFrontCandidateResult(poolKey, host string, ok bool, _ time.Duration) {
	poolKey = strings.TrimSpace(poolKey)
	host = strings.TrimSpace(host)
	if poolKey == "" || host == "" {
		return
	}
	frontMu.Lock()
	defer frontMu.Unlock()
	pool := frontPools[poolKey]
	if pool == nil {
		pool = map[string]*frontHostState{}
		frontPools[poolKey] = pool
	}
	st := pool[host]
	if st == nil {
		st = &frontHostState{}
		pool[host] = st
	}
	st.lastResult = frontNow()
	if ok {
		st.consecutiveFailures = 0
	} else {
		st.consecutiveFailures++
	}
}

type connectIPState struct {
	consecutiveFailures int
	lastResult          time.Time
}

var (
	connectMu    sync.Mutex
	connectPools = map[string]map[string]*connectIPState{}
	connectNow   = time.Now
	connectCooldown = 30 * time.Second
)

// OrderConnectIPCandidates returns a (possibly re-ordered) list of connect-IP candidates.
// The first input element is treated as the primary.
func OrderConnectIPCandidates(poolKey string, candidates []string) []string {
	poolKey = strings.TrimSpace(poolKey)
	if poolKey == "" {
		return dedupeStrings(candidates)
	}
	cands := dedupeStrings(candidates)
	if len(cands) <= 1 {
		return cands
	}
	primary := cands[0]

	connectMu.Lock()
	defer connectMu.Unlock()
	pool := connectPools[poolKey]
	if pool == nil {
		pool = map[string]*connectIPState{}
		connectPools[poolKey] = pool
	}
	st := pool[primary]
	if st == nil || st.consecutiveFailures < 2 {
		return cands
	}
	if connectCooldown > 0 && !st.lastResult.IsZero() && connectNow().Sub(st.lastResult) >= connectCooldown {
		return cands
	}

	// Primary looks unhealthy: stable-sort all candidates by fewer consecutive failures.
	out := append([]string(nil), cands...)
	sort.SliceStable(out, func(i, j int) bool {
		ai := pool[out[i]]
		aj := pool[out[j]]
		fi := 0
		fj := 0
		if ai != nil {
			fi = ai.consecutiveFailures
		}
		if aj != nil {
			fj = aj.consecutiveFailures
		}
		return fi < fj
	})
	return out
}

// ReportConnectIPResult updates health state for a connect-IP candidate.
func ReportConnectIPResult(poolKey, ip string, ok bool, _ time.Duration) {
	poolKey = strings.TrimSpace(poolKey)
	ip = strings.TrimSpace(ip)
	if poolKey == "" || ip == "" {
		return
	}
	connectMu.Lock()
	defer connectMu.Unlock()
	pool := connectPools[poolKey]
	if pool == nil {
		pool = map[string]*connectIPState{}
		connectPools[poolKey] = pool
	}
	st := pool[ip]
	if st == nil {
		st = &connectIPState{}
		pool[ip] = st
	}
	st.lastResult = connectNow()
	if ok {
		st.consecutiveFailures = 0
	} else {
		st.consecutiveFailures++
	}
}

func dedupeStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// resetFrontPoolsForTest clears in-memory health state (tests only).
func resetFrontPoolsForTest() {
	frontMu.Lock()
	defer frontMu.Unlock()
	frontPools = map[string]map[string]*frontHostState{}
}

func resetConnectPoolsForTest() {
	connectMu.Lock()
	defer connectMu.Unlock()
	connectPools = map[string]map[string]*connectIPState{}
}
