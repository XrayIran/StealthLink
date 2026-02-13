package timing

import (
	"crypto/rand"
	"math"
	"sync"
	"time"

	"stealthlink/internal/metrics"
)

type TimingPattern int

const (
	PatternUniform TimingPattern = iota
	PatternBurst
	PatternPoisson
	PatternGaussian
	PatternAdaptive
)

type TimingObfuscatorConfig struct {
	Enabled      bool
	Pattern      TimingPattern
	BaseInterval time.Duration
	JitterMin    time.Duration
	JitterMax    time.Duration
	BurstSize    int
	BurstGap     time.Duration
}

type TimingObfuscator struct {
	config       TimingObfuscatorConfig
	patternState *patternState
	mu           sync.Mutex
	running      bool
}

type patternState struct {
	lastSend      time.Time
	burstCount    int
	poissonLambda float64
	gaussianMean  float64
	gaussianStd   float64
}

func NewTimingObfuscator(cfg TimingObfuscatorConfig) *TimingObfuscator {
	if cfg.BaseInterval == 0 {
		cfg.BaseInterval = 10 * time.Millisecond
	}
	if cfg.JitterMin == 0 {
		cfg.JitterMin = 1 * time.Millisecond
	}
	if cfg.JitterMax == 0 {
		cfg.JitterMax = 50 * time.Millisecond
	}
	if cfg.BurstSize == 0 {
		cfg.BurstSize = 5
	}
	if cfg.BurstGap == 0 {
		cfg.BurstGap = 100 * time.Millisecond
	}

	return &TimingObfuscator{
		config: cfg,
		patternState: &patternState{
			poissonLambda: cfg.BaseInterval.Seconds() * 1000,
			gaussianMean:  cfg.BaseInterval.Seconds() * 1000,
			gaussianStd:   cfg.JitterMax.Seconds() * 1000 / 3,
		},
	}
}

func (o *TimingObfuscator) Wait() time.Duration {
	o.mu.Lock()
	defer o.mu.Unlock()

	if !o.config.Enabled {
		return 0
	}

	var delay time.Duration

	switch o.config.Pattern {
	case PatternUniform:
		delay = o.uniformDelay()
	case PatternBurst:
		delay = o.burstDelay()
	case PatternPoisson:
		delay = o.poissonDelay()
	case PatternGaussian:
		delay = o.gaussianDelay()
	case PatternAdaptive:
		delay = o.adaptiveDelay()
	default:
		delay = o.uniformDelay()
	}

	o.patternState.lastSend = time.Now()
	metrics.IncObfsJunkPackets(1)
	return delay
}

func (o *TimingObfuscator) uniformDelay() time.Duration {
	jitter := o.randomDuration(o.config.JitterMin, o.config.JitterMax)
	return o.config.BaseInterval + jitter
}

func (o *TimingObfuscator) burstDelay() time.Duration {
	state := o.patternState

	if state.burstCount < o.config.BurstSize {
		state.burstCount++
		return time.Duration(o.randomFloat(0.5, 2) * float64(o.config.BaseInterval))
	}

	state.burstCount = 0
	return o.config.BurstGap
}

func (o *TimingObfuscator) poissonDelay() time.Duration {
	lambda := o.patternState.poissonLambda
	if lambda <= 0 {
		lambda = 10
	}

	u := o.randomFloat(0, 1)
	if u >= 1 {
		u = 0.9999
	}

	ms := -math.Log(1-u) * lambda
	return time.Duration(ms) * time.Millisecond
}

func (o *TimingObfuscator) gaussianDelay() time.Duration {
	u1 := o.randomFloat(0, 1)
	u2 := o.randomFloat(0, 1)

	if u1 <= 0 {
		u1 = 0.0001
	}

	z := math.Sqrt(-2*math.Log(u1)) * math.Cos(2*math.Pi*u2)
	ms := o.patternState.gaussianMean + z*o.patternState.gaussianStd

	if ms < float64(o.config.JitterMin.Milliseconds()) {
		ms = float64(o.config.JitterMin.Milliseconds())
	}

	return time.Duration(ms) * time.Millisecond
}

func (o *TimingObfuscator) adaptiveDelay() time.Duration {
	now := time.Now()
	elapsed := now.Sub(o.patternState.lastSend)

	var baseDelay time.Duration
	if elapsed < o.config.BaseInterval*2 {
		baseDelay = o.config.BaseInterval + o.config.JitterMax
	} else if elapsed < o.config.BaseInterval*5 {
		baseDelay = o.config.BaseInterval + o.config.JitterMin
	} else {
		baseDelay = o.config.BaseInterval / 2
	}

	jitter := o.randomDuration(0, o.config.JitterMin)
	return baseDelay + jitter
}

func (o *TimingObfuscator) randomDuration(min, max time.Duration) time.Duration {
	if min >= max {
		return min
	}

	diff := max - min
	b := make([]byte, 8)
	rand.Read(b)

	offset := time.Duration(int64(b[0]) % int64(diff))
	return min + offset
}

func (o *TimingObfuscator) randomFloat(min, max float64) float64 {
	b := make([]byte, 8)
	rand.Read(b)

	u := float64(b[0]) / 255.0
	return min + u*(max-min)
}

func (o *TimingObfuscator) SetPattern(pattern TimingPattern) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.config.Pattern = pattern
}

func (o *TimingObfuscator) SetBaseInterval(d time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.config.BaseInterval = d
}

type TrafficShaper struct {
	obfuscator *TimingObfuscator
	queue      chan []byte
	batchSize  int
	running    bool
	mu         sync.Mutex
	wg         sync.WaitGroup
}

func NewTrafficShaper(cfg TimingObfuscatorConfig, batchSize int) *TrafficShaper {
	if batchSize == 0 {
		batchSize = 16
	}
	return &TrafficShaper{
		obfuscator: NewTimingObfuscator(cfg),
		queue:      make(chan []byte, 1024),
		batchSize:  batchSize,
	}
}

func (s *TrafficShaper) Start(sendFn func([][]byte) error) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()

		batch := make([][]byte, 0, s.batchSize)
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()

		for {
			select {
			case pkt, ok := <-s.queue:
				if !ok {
					if len(batch) > 0 {
						sendFn(batch)
					}
					return
				}
				batch = append(batch, pkt)
				if len(batch) >= s.batchSize {
					if err := sendFn(batch); err == nil {
						batch = batch[:0]
						delay := s.obfuscator.Wait()
						if delay > 0 {
							time.Sleep(delay)
						}
					}
				}

			case <-ticker.C:
				if len(batch) > 0 {
					if err := sendFn(batch); err == nil {
						batch = batch[:0]
						delay := s.obfuscator.Wait()
						if delay > 0 {
							time.Sleep(delay)
						}
					}
				}
			}
		}
	}()
}

func (s *TrafficShaper) Enqueue(pkt []byte) bool {
	select {
	case s.queue <- pkt:
		return true
	default:
		return false
	}
}

func (s *TrafficShaper) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	s.running = false
	s.mu.Unlock()

	close(s.queue)
	s.wg.Wait()
}

func ParseTimingPattern(s string) TimingPattern {
	switch s {
	case "uniform", "0":
		return PatternUniform
	case "burst", "1":
		return PatternBurst
	case "poisson", "2":
		return PatternPoisson
	case "gaussian", "3":
		return PatternGaussian
	case "adaptive", "4":
		return PatternAdaptive
	default:
		return PatternUniform
	}
}
