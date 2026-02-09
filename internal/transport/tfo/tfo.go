// Package tfo provides TCP Fast Open (TFO) support.
// TCP Fast Open reduces connection latency by allowing data to be sent
// in the initial SYN packet, eliminating one RTT.
package tfo

import (
	"context"
	"net"
	"runtime"
	"syscall"
	"time"
)

// Config configures TCP Fast Open behavior.
type Config struct {
	Enabled   bool          `yaml:"enabled"`
	QueueSize int           `yaml:"queue_size"` // TFO queue size (default: 1024)
	Timeout   time.Duration `yaml:"timeout"`    // Connection timeout
}

// ApplyDefaults sets default values.
func (c *Config) ApplyDefaults() {
	if c.QueueSize <= 0 {
		c.QueueSize = 1024
	}
	if c.Timeout <= 0 {
		c.Timeout = 30 * time.Second
	}
}

// Dialer creates a dialer with TFO support.
func Dialer(config Config) *net.Dialer {
	config.ApplyDefaults()

	if !config.Enabled {
		return &net.Dialer{
			Timeout: config.Timeout,
		}
	}

	return &net.Dialer{
		Timeout: config.Timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			return setTFO(c, config.QueueSize)
		},
	}
}

// DialerWithTFO creates a dialer with TFO enabled.
func DialerWithTFO(queueSize int) *net.Dialer {
	if queueSize <= 0 {
		queueSize = 1024
	}

	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return setTFO(c, queueSize)
		},
	}
}

// setTFO sets the TCP Fast Open socket option.
func setTFO(c syscall.RawConn, queueSize int) error {
	var sockErr error

	err := c.Control(func(fd uintptr) {
		sockErr = setTFOSocketOption(fd, queueSize)
	})

	if err != nil {
		return err
	}
	return sockErr
}

// DialContext dials with TFO support.
func DialContext(ctx context.Context, network, address string, config Config) (net.Conn, error) {
	d := Dialer(config)
	return d.DialContext(ctx, network, address)
}

// Dial dials with TFO support.
func Dial(network, address string, config Config) (net.Conn, error) {
	d := Dialer(config)
	return d.Dial(network, address)
}

// Listener creates a TCP listener with TFO support.
func Listener(network, address string, config Config) (net.Listener, error) {
	config.ApplyDefaults()

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			if !config.Enabled {
				return nil
			}
			return setTFO(c, config.QueueSize)
		},
	}

	return lc.Listen(context.Background(), network, address)
}

// IsSupported checks if TFO is supported on this platform.
func IsSupported() bool {
	switch runtime.GOOS {
	case "linux":
		return true
	case "darwin":
		// macOS supports TFO but with different API
		return true
	case "windows":
		// Windows 10 1607+ supports TFO but requires specific APIs
		return false // Not implemented yet
	default:
		return false
	}
}

// Platform returns the current platform TFO support status.
func Platform() string {
	switch runtime.GOOS {
	case "linux":
		return "linux (full support)"
	case "darwin":
		return "darwin (limited support)"
	case "windows":
		return "windows (not implemented)"
	default:
		return runtime.GOOS + " (unsupported)"
	}
}

// WrapDialer wraps an existing dialer function to add TFO support.
func WrapDialer(dialFunc func(ctx context.Context, network, addr string) (net.Conn, error), config Config) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if !config.Enabled {
		return dialFunc
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return DialContext(ctx, network, addr, config)
	}
}

// TFOConn wraps a connection to provide TFO-specific information.
type TFOConn struct {
	net.Conn
	TFOEnabled bool
}

// NewTFOConn wraps a connection with TFO metadata.
func NewTFOConn(conn net.Conn, enabled bool) *TFOConn {
	return &TFOConn{
		Conn:       conn,
		TFOEnabled: enabled,
	}
}

// FallbackDialer creates a dialer that tries TFO first, then falls back to regular TCP.
func FallbackDialer(config Config) *net.Dialer {
	config.ApplyDefaults()

	if !config.Enabled {
		return &net.Dialer{Timeout: config.Timeout}
	}

	return &net.Dialer{
		Timeout: config.Timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			// Try to set TFO, but don't fail if it doesn't work
			_ = setTFO(c, config.QueueSize)
			return nil
		},
	}
}

// Stats provides TFO statistics (placeholder for future implementation).
type Stats struct {
	ConnectionsWithTFO int64
	ConnectionsWithout int64
	BytesSentInSYN     int64
}

// GlobalStats tracks TFO usage statistics.
var GlobalStats Stats
