// Package transportutil provides shared utilities for transport implementations.
package transportutil

import (
	"errors"
	"strings"
	"syscall"
	"time"
)

// TransientBufferConfig configures retry behavior for transient buffer errors.
type TransientBufferConfig struct {
	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
}

// DefaultTransientBufferConfig returns the default configuration for handling
// transient buffer errors (ENOBUFS/ENOMEM).
func DefaultTransientBufferConfig() TransientBufferConfig {
	return TransientBufferConfig{
		MaxRetries:  5,
		BaseBackoff: 200 * time.Microsecond,
		MaxBackoff:  5 * time.Millisecond,
	}
}

// IsTransientBufferError detects transient buffer exhaustion errors.
// It handles both syscall errors (ENOBUFS, ENOMEM, EAGAIN) and string-wrapped
// variants that may be returned by libpcap or other low-level libraries.
func IsTransientBufferError(err error) bool {
	if err == nil {
		return false
	}
	// Check for syscall errors directly
	if errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) || errors.Is(err, syscall.EAGAIN) {
		return true
	}
	// Check for string-wrapped variants (libpcap can wrap these as plain strings)
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "enobufs") || strings.Contains(lower, "enomem") || strings.Contains(lower, "eagain")
}

// RetryWithBackoff executes the provided function with exponential backoff
// retry logic for transient buffer errors. It returns the result of the function
// or an error if all retries are exhausted.
func RetryWithBackoff(
	cfg TransientBufferConfig,
	isTransient func(error) bool,
	onRetry func(attempt int),
	onDrop func(),
	fn func() error,
) error {
	backoff := cfg.BaseBackoff
	for attempt := 0; ; attempt++ {
		err := fn()
		if err == nil {
			return nil
		}
		if !isTransient(err) {
			return err
		}

		if attempt >= cfg.MaxRetries {
			if onDrop != nil {
				onDrop()
			}
			return nil // Treat as success (drop)
		}

		if onRetry != nil {
			onRetry(attempt)
		}

		time.Sleep(backoff)
		if backoff < cfg.MaxBackoff {
			backoff *= 2
			if backoff > cfg.MaxBackoff {
				backoff = cfg.MaxBackoff
			}
		}
	}
}

// WriteWithRetry attempts to write data with retry logic for transient errors.
// It is a convenience wrapper around RetryWithBackoff for write operations.
func WriteWithRetry(
	cfg TransientBufferConfig,
	write func() (int, error),
	isTransient func(error) bool,
	onRetry func(attempt int),
	onDrop func(),
) (int, error) {
	var n int
	err := RetryWithBackoff(cfg, isTransient, onRetry, onDrop, func() error {
		var err error
		n, err = write()
		return err
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
