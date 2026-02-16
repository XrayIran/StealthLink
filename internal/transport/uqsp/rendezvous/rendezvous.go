package rendezvous

import (
	"context"
	"time"
)

// Client is a technique-only rendezvous helper used for reverse-init orchestration.
//
// "Publish" registers an address/value for later retrieval and "Poll" fetches it.
// Keying is broker-specific; StealthLink uses the reverse auth token as the default key.
type Client interface {
	Publish(ctx context.Context, key, value string, ttl time.Duration) error
	Poll(ctx context.Context, key string) (value string, err error)
}

