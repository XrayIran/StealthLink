package wssmux

import (
	"math/rand"
	"sync"
	"time"
)

// UserAgentList contains browser User-Agent strings for rotation.
// Based on Backhaul's approach with modern browser UAs.
var UserAgentList = []string{
	// Chrome on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
	// Chrome on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
	// Firefox on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
	// Firefox on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0",
	// Safari on macOS
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
	// Edge on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
	// Chrome on Linux
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	// Firefox on Linux
	"Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
	// Opera on Windows
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
	// Chrome on Android
	"Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
	// Safari on iOS
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
}

// UserAgentMode defines how User-Agent rotation behaves.
type UserAgentMode string

const (
	// UAModeStatic uses a fixed User-Agent.
	UAModeStatic UserAgentMode = "static"
	// UAModeRandom selects a random UA per connection.
	UAModeRandom UserAgentMode = "random"
	// UAModeRotate cycles through UAs sequentially.
	UAModeRotate UserAgentMode = "rotate"
)

// UserAgentRotator manages User-Agent rotation.
type UserAgentRotator struct {
	mu        sync.RWMutex
	agents    []string
	mode      UserAgentMode
	current   int
	staticUA  string
	rng       *rand.Rand
}

// NewUserAgentRotator creates a new rotator with the given mode.
func NewUserAgentRotator(mode UserAgentMode, staticUA string) *UserAgentRotator {
	r := &UserAgentRotator{
		agents:   UserAgentList,
		mode:     mode,
		staticUA: staticUA,
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	if mode == "" {
		r.mode = UAModeStatic
	}
	return r
}

// Get returns the User-Agent for the current connection.
func (r *UserAgentRotator) Get() string {
	r.mu.Lock()
	defer r.mu.Unlock()

	switch r.mode {
	case UAModeRandom:
		return r.agents[r.rng.Intn(len(r.agents))]
	case UAModeRotate:
		ua := r.agents[r.current]
		r.current = (r.current + 1) % len(r.agents)
		return ua
	case UAModeStatic:
		fallthrough
	default:
		if r.staticUA != "" {
			return r.staticUA
		}
		return r.agents[0]
	}
}

// SetMode changes the rotation mode.
func (r *UserAgentRotator) SetMode(mode UserAgentMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
}

// SetCustomAgents replaces the default agent list.
func (r *UserAgentRotator) SetCustomAgents(agents []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(agents) > 0 {
		r.agents = agents
		r.current = 0
	}
}

// RandomUserAgent returns a random User-Agent from the default list.
func RandomUserAgent() string {
	return UserAgentList[rand.Intn(len(UserAgentList))]
}
