package underlay

import (
	"context"
	"fmt"
	"net"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
)

// Dialer is the interface for underlay dialers
type Dialer interface {
	// Dial establishes a connection to the given address
	Dial(ctx context.Context, network, address string) (net.Conn, error)

	// Type returns the dialer type ("direct", "warp", "socks")
	Type() string

	// Close closes the dialer and releases resources
	Close() error
}

// NewDialer creates a new underlay dialer based on configuration
func NewDialer(cfg *config.Transport) (Dialer, error) {
	dialerType := cfg.Dialer
	if dialerType == "" {
		dialerType = "direct" // default
	}

	var dialer Dialer
	var err error

	switch dialerType {
	case "direct":
		dialer = NewDirectDialer()
	case "warp":
		dialer, err = NewWARPDialer(cfg.WARPDialer)
	case "socks":
		dialer, err = NewSOCKSDialer(cfg.SOCKSDialer)
	default:
		return nil, fmt.Errorf("unknown dialer type: %s", dialerType)
	}

	if err != nil {
		return nil, err
	}

	// Set metrics
	metrics.SetUnderlaySelected(dialerType)
	if warpDialer, ok := dialer.(*WARPDialer); ok {
		metrics.SetWARPHealth(warpDialer.Health())
	}

	return dialer, nil
}

// DirectDialer implements direct network dialing (existing behavior)
type DirectDialer struct {
	dialer *net.Dialer
}

// NewDirectDialer creates a new direct dialer
func NewDirectDialer() *DirectDialer {
	return &DirectDialer{
		dialer: &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		},
	}
}

// Dial establishes a direct connection
func (d *DirectDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialer.DialContext(ctx, network, address)
}

// Type returns the dialer type
func (d *DirectDialer) Type() string {
	return "direct"
}

// Close closes the dialer (no-op for direct dialer)
func (d *DirectDialer) Close() error {
	return nil
}
