package transportutil

import (
	"errors"
	"syscall"
	"testing"
	"time"
)

func TestIsTransientBufferError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "enobufs", err: syscall.ENOBUFS, want: true},
		{name: "enomem", err: syscall.ENOMEM, want: true},
		{name: "wrapped_enobufs", err: errors.New("send failed: ENOBUFS"), want: true},
		{name: "wrapped_enomem", err: errors.New("malloc failed: ENOMEM"), want: true},
		{name: "lowercase", err: errors.New("no buffer: enobufs"), want: true},
		{name: "other", err: errors.New("permission denied"), want: false},
		{name: "io_eof", err: errors.New("EOF"), want: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTransientBufferError(tc.err); got != tc.want {
				t.Fatalf("IsTransientBufferError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestDefaultTransientBufferConfig(t *testing.T) {
	cfg := DefaultTransientBufferConfig()
	if cfg.MaxRetries != 5 {
		t.Errorf("MaxRetries = %d, want 5", cfg.MaxRetries)
	}
	if cfg.BaseBackoff != 200*time.Microsecond {
		t.Errorf("BaseBackoff = %v, want 200µs", cfg.BaseBackoff)
	}
	if cfg.MaxBackoff != 5*time.Millisecond {
		t.Errorf("MaxBackoff = %v, want 5ms", cfg.MaxBackoff)
	}
}

func TestRetryWithBackoff_Success(t *testing.T) {
	cfg := TransientBufferConfig{
		MaxRetries:  3,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}

	callCount := 0
	err := RetryWithBackoff(
		cfg,
		IsTransientBufferError,
		nil,
		nil,
		func() error {
			callCount++
			return nil
		},
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1", callCount)
	}
}

func TestRetryWithBackoff_Failure(t *testing.T) {
	cfg := TransientBufferConfig{
		MaxRetries:  2,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}

	persistentErr := errors.New("persistent error")
	callCount := 0
	err := RetryWithBackoff(
		cfg,
		IsTransientBufferError,
		nil,
		nil,
		func() error {
			callCount++
			return persistentErr
		},
	)

	if err != persistentErr {
		t.Fatalf("expected %v, got %v", persistentErr, err)
	}
	if callCount != 1 {
		t.Errorf("callCount = %d, want 1 (no retries for non-transient errors)", callCount)
	}
}

func TestRetryWithBackoff_TransientEventuallySucceeds(t *testing.T) {
	cfg := TransientBufferConfig{
		MaxRetries:  3,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}

	callCount := 0
	err := RetryWithBackoff(
		cfg,
		IsTransientBufferError,
		nil,
		nil,
		func() error {
			callCount++
			if callCount < 3 {
				return syscall.ENOBUFS
			}
			return nil
		},
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if callCount != 3 {
		t.Errorf("callCount = %d, want 3", callCount)
	}
}

func TestRetryWithBackoff_MaxRetriesExceeded(t *testing.T) {
	cfg := TransientBufferConfig{
		MaxRetries:  2,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}

	retryCount := 0
	dropCalled := false
	err := RetryWithBackoff(
		cfg,
		IsTransientBufferError,
		func(attempt int) { retryCount++ },
		func() { dropCalled = true },
		func() error {
			return syscall.ENOBUFS
		},
	)

	if err != nil {
		t.Fatalf("expected nil error after max retries (drop), got %v", err)
	}
	if retryCount != 2 {
		t.Errorf("retryCount = %d, want 2", retryCount)
	}
	if !dropCalled {
		t.Error("drop callback was not called")
	}
}

func TestWriteWithRetry_Success(t *testing.T) {
	cfg := TransientBufferConfig{
		MaxRetries:  2,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}

	written := 0
	n, err := WriteWithRetry(
		cfg,
		func() (int, error) {
			written = 42
			return written, nil
		},
		IsTransientBufferError,
		nil,
		nil,
	)

	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if n != 42 {
		t.Errorf("n = %d, want 42", n)
	}
}

func TestWriteWithRetry_Drop(t *testing.T) {
	cfg := TransientBufferConfig{
		MaxRetries:  1,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	}

	n, err := WriteWithRetry(
		cfg,
		func() (int, error) {
			return 0, syscall.ENOBUFS
		},
		IsTransientBufferError,
		nil,
		nil,
	)

	if err != nil {
		t.Fatalf("expected nil error after drop, got %v", err)
	}
	// When dropped, n should be 0 (indicating drop occurred)
	if n != 0 {
		t.Errorf("n = %d, want 0 (drop)", n)
	}
}
