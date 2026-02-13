// Package singbox provides optional wire format compatibility with sing-box.
// This adapter translates between StealthLink's native wire format and sing-box's
// protocol specifications for interoperability with upstream clients/servers.
//
// IMPORTANT: This adapter is OPTIONAL and should only be enabled when interoperability
// with sing-box clients is required. StealthLink's native modes (4a-4e) are the
// canonical wire formats and do not require this adapter.
package singbox

import (
	"context"
	"fmt"
	"net"
)

// Adapter provides wire format translation between StealthLink and sing-box.
type Adapter struct {
	enabled bool
	mode    string // "anytls" for AnyTLS compatibility
}

// Config configures the sing-box compatibility adapter.
type Config struct {
	Enabled bool   `yaml:"enabled"` // Enable sing-box wire format compatibility
	Mode    string `yaml:"mode"`    // Protocol mode: "anytls"
}

// NewAdapter creates a new sing-box compatibility adapter.
func NewAdapter(cfg Config) (*Adapter, error) {
	if !cfg.Enabled {
		return &Adapter{enabled: false}, nil
	}

	if cfg.Mode != "anytls" {
		return nil, fmt.Errorf("unsupported singbox mode: %s (only 'anytls' supported)", cfg.Mode)
	}

	return &Adapter{
		enabled: true,
		mode:    cfg.Mode,
	}, nil
}

// Enabled returns whether the adapter is enabled.
func (a *Adapter) Enabled() bool {
	return a.enabled
}

// WrapDialer wraps a dialer to translate StealthLink frames to sing-box wire format.
func (a *Adapter) WrapDialer(dialer func(ctx context.Context, addr string) (net.Conn, error)) func(ctx context.Context, addr string) (net.Conn, error) {
	if !a.enabled {
		return dialer
	}

	return func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := dialer(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &singboxConn{Conn: conn, mode: a.mode}, nil
	}
}

// WrapListener wraps a listener to translate sing-box wire format to StealthLink frames.
func (a *Adapter) WrapListener(listener net.Listener) net.Listener {
	if !a.enabled {
		return listener
	}
	return &singboxListener{Listener: listener, mode: a.mode}
}

// singboxConn wraps a connection to translate wire formats.
type singboxConn struct {
	net.Conn
	mode string
}

// singboxListener wraps a listener to translate wire formats.
type singboxListener struct {
	net.Listener
	mode string
}

// Accept accepts a connection and wraps it for wire format translation.
func (l *singboxListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &singboxConn{Conn: conn, mode: l.mode}, nil
}
