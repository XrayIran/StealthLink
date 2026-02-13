//go:build linux
// +build linux

package batch

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// BatchConfig configures batch I/O behavior
type BatchConfig struct {
	Enabled   bool
	BatchSize int           // 1-64, default 32
	Timeout   time.Duration // for recvmmsg, default 0 (no timeout)
}

// DefaultBatchConfig returns the default batch configuration
func DefaultBatchConfig() BatchConfig {
	return BatchConfig{
		Enabled:   true,
		BatchSize: 32,
		Timeout:   0, // no timeout by default
	}
}

// BatchIOManager manages batch I/O state and fallback
type BatchIOManager struct {
	config           BatchConfig
	syscallAvailable atomic.Bool
	fallbackReason   string
	mu               sync.RWMutex
}

// NewBatchIOManager creates a new batch I/O manager
func NewBatchIOManager(config BatchConfig) *BatchIOManager {
	if config.BatchSize < 1 {
		config.BatchSize = 1
	}
	if config.BatchSize > 64 {
		config.BatchSize = 64
	}

	mgr := &BatchIOManager{
		config: config,
	}

	// Initially assume syscalls are available
	mgr.syscallAvailable.Store(true)

	return mgr
}

// SendBatch sends multiple UDP packets in a single syscall
// Returns the number of messages sent and any error
func (m *BatchIOManager) SendBatch(conn *net.UDPConn, msgs [][]byte) (int, error) {
	if !m.config.Enabled || len(msgs) == 0 {
		return sendBatchFallback(conn, msgs)
	}

	if !m.syscallAvailable.Load() {
		return sendBatchFallback(conn, msgs)
	}

	// Limit batch size
	if len(msgs) > m.config.BatchSize {
		msgs = msgs[:m.config.BatchSize]
	}

	batchSendsTotal.Inc()

	n, err := SendBatch(conn, msgs)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
			m.disableSyscall(err)
			// SendBatch logic already handles fallback retry for ENOSYS usually,
			// but we return whatever it did.
		}
	}

	batchSendMessagesTotal.Add(float64(n))
	return n, err
}

// SendBatchAddr sends multiple UDP packets to specific addresses
// Returns the number of messages sent and any error
func (m *BatchIOManager) SendBatchAddr(conn *net.UDPConn, msgs [][]byte, addrs []*net.UDPAddr) (int, error) {
	if !m.config.Enabled || len(msgs) == 0 {
		return sendBatchAddrFallback(conn, msgs, addrs)
	}

	if len(msgs) != len(addrs) {
		return 0, errors.New("batch: msgs and addrs length mismatch")
	}

	if !m.syscallAvailable.Load() {
		return sendBatchAddrFallback(conn, msgs, addrs)
	}

	// Limit batch size
	if len(msgs) > m.config.BatchSize {
		msgs = msgs[:m.config.BatchSize]
		addrs = addrs[:m.config.BatchSize]
	}

	batchSendsTotal.Inc()

	n, err := SendBatchAddr(conn, msgs, addrs)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
			m.disableSyscall(err)
		}
	}

	batchSendMessagesTotal.Add(float64(n))
	return n, err
}

// RecvBatch receives multiple UDP packets in a single syscall
// Returns the number of messages received, their addresses, and any error
// Now correctly slices buffers to their actual received length.
func (m *BatchIOManager) RecvBatch(conn *net.UDPConn, buffers [][]byte) (int, []net.Addr, error) {
	if !m.config.Enabled || len(buffers) == 0 {
		n, lens, addrs, err := recvBatchFallback(conn, buffers)
		if err != nil {
			return 0, nil, err
		}
		if n > 0 {
			buffers[0] = buffers[0][:lens[0]]
		}
		return n, addrs, nil
	}

	if !m.syscallAvailable.Load() {
		n, lens, addrs, err := recvBatchFallback(conn, buffers)
		if err != nil {
			return 0, nil, err
		}
		if n > 0 {
			buffers[0] = buffers[0][:lens[0]]
		}
		return n, addrs, nil
	}

	// Limit batch size
	if len(buffers) > m.config.BatchSize {
		buffers = buffers[:m.config.BatchSize]
	}

	batchRecvsTotal.Inc()

	n, addrs, err := RecvBatch(conn, buffers)
	if err != nil {
		if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EINVAL) {
			m.disableSyscall(err)
		}
	}

	batchRecvMessagesTotal.Add(float64(n))
	return n, addrs, err
}

// disableSyscall permanently disables batch syscalls and records the reason
func (m *BatchIOManager) disableSyscall(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.syscallAvailable.Load() {
		m.syscallAvailable.Store(false)
		m.fallbackReason = err.Error()

		// Record fallback metric
		reason := "unknown"
		if errors.Is(err, syscall.ENOSYS) {
			reason = "ENOSYS"
		} else if errors.Is(err, syscall.EINVAL) {
			reason = "EINVAL"
		}
		batchFallbackTotal.WithLabelValues(reason).Inc()
	}
}

// IsSyscallAvailable returns whether batch syscalls are available
func (m *BatchIOManager) IsSyscallAvailable() bool {
	return m.syscallAvailable.Load()
}

// FallbackReason returns the reason for fallback, if any
func (m *BatchIOManager) FallbackReason() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.fallbackReason
}

// BatchSize returns the configured batch size
func (m *BatchIOManager) BatchSize() int {
	return m.config.BatchSize
}
