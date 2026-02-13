package underlay

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/proxy"

	"stealthlink/internal/config"
)

// SOCKSDialer implements dialing through SOCKS5 proxy
type SOCKSDialer struct {
	config config.SOCKSDialer
	dialer proxy.Dialer
}

// NewSOCKSDialer creates a new SOCKS5 dialer
func NewSOCKSDialer(cfg config.SOCKSDialer) (*SOCKSDialer, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("SOCKS5 address is required")
	}

	// Create SOCKS5 dialer
	var auth *proxy.Auth
	if cfg.Username != "" || cfg.Password != "" {
		auth = &proxy.Auth{
			User:     cfg.Username,
			Password: cfg.Password,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", cfg.Address, auth, &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("create SOCKS5 dialer: %w", err)
	}

	return &SOCKSDialer{
		config: cfg,
		dialer: dialer,
	}, nil
}

// Dial establishes a connection through SOCKS5 proxy
func (d *SOCKSDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	// proxy.Dialer doesn't support context, so we use a timeout
	// and wrap the connection with context cancellation
	conn, err := d.dialer.Dial(network, address)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dial: %w", err)
	}

	// Monitor context cancellation
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	return conn, nil
}

// Type returns the dialer type
func (d *SOCKSDialer) Type() string {
	return "socks"
}

// Close closes the SOCKS dialer (no-op)
func (d *SOCKSDialer) Close() error {
	return nil
}
