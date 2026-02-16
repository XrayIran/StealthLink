package uqsp

import (
	"sync"
	"time"
)

type nonceCache struct {
	mu      sync.Mutex
	seen    map[[reverseAuthNonceSize]byte]time.Time
	maxSize int
	ttl     time.Duration
}

func newNonceCache(maxSize int, ttl time.Duration) *nonceCache {
	if maxSize <= 0 {
		maxSize = 4096
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &nonceCache{
		seen:    make(map[[reverseAuthNonceSize]byte]time.Time),
		maxSize: maxSize,
		ttl:     ttl,
	}
}

// Add records nonce as seen and returns true if it was not already present.
// If nonce is already present and not expired, it returns false (replay).
func (c *nonceCache) Add(nonce [reverseAuthNonceSize]byte, now time.Time) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for k, expiresAt := range c.seen {
		if now.After(expiresAt) {
			delete(c.seen, k)
		}
	}

	if expiresAt, ok := c.seen[nonce]; ok && now.Before(expiresAt) {
		return false
	}

	if len(c.seen) >= c.maxSize {
		var oldestKey [reverseAuthNonceSize]byte
		var oldestTime time.Time
		var haveOldest bool
		for k, exp := range c.seen {
			if !haveOldest || exp.Before(oldestTime) {
				oldestKey = k
				oldestTime = exp
				haveOldest = true
			}
		}
		if haveOldest {
			delete(c.seen, oldestKey)
		}
	}

	c.seen[nonce] = now.Add(c.ttl)
	return true
}
