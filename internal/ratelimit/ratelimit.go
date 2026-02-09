package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu sync.Mutex
	maxBPS int
	maxPPS int
	burst int
	mode string
	bytes float64
	packets float64
	last time.Time
}

func New(maxBPS, maxPPS, burst int, mode string) *Limiter {
	if burst <= 0 {
		burst = maxBPS
		if burst <= 0 {
			burst = 1
		}
	}
	if mode == "" {
		mode = "drop"
	}
	return &Limiter{maxBPS: maxBPS, maxPPS: maxPPS, burst: burst, mode: mode, last: time.Now()}
}

func (l *Limiter) Allow(n int) bool {
	if l == nil {
		return true
	}
	if l.maxBPS == 0 && l.maxPPS == 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill()

	needBytes := float64(n)
	needPackets := 1.0
	if l.maxBPS > 0 && l.bytes < needBytes {
		return l.handleLimit(needBytes, 0)
	}
	if l.maxPPS > 0 && l.packets < needPackets {
		return l.handleLimit(0, needPackets)
	}
	if l.maxBPS > 0 {
		l.bytes -= needBytes
	}
	if l.maxPPS > 0 {
		l.packets -= needPackets
	}
	return true
}

func (l *Limiter) handleLimit(needBytes, needPackets float64) bool {
	if l.mode == "drop" {
		return false
	}
	// pace
	for {
		l.refill()
		ok := true
		if l.maxBPS > 0 && l.bytes < needBytes {
			ok = false
		}
		if l.maxPPS > 0 && l.packets < needPackets {
			ok = false
		}
		if ok {
			if l.maxBPS > 0 {
				l.bytes -= needBytes
			}
			if l.maxPPS > 0 {
				l.packets -= needPackets
			}
			return true
		}
		l.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
		l.mu.Lock()
	}
}

func (l *Limiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	if elapsed <= 0 {
		return
	}
	l.last = now
	if l.maxBPS > 0 {
		l.bytes += elapsed * float64(l.maxBPS)
		if l.bytes > float64(l.burst) {
			l.bytes = float64(l.burst)
		}
	}
	if l.maxPPS > 0 {
		l.packets += elapsed * float64(l.maxPPS)
		if l.packets > float64(l.burst) {
			l.packets = float64(l.burst)
		}
	}
}
