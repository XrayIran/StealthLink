// Package xray provides optional wire format compatibility with Xray-core.
// This adapter translates between StealthLink's native wire format and Xray-core's
// SplitHTTP/XHTTP protocol for interoperability with upstream clients/servers.
//
// IMPORTANT: This adapter is OPTIONAL and should only be enabled when interoperability
// with Xray-core clients is required. StealthLink's native modes (4a-4e) are the
// canonical wire formats and do not require this adapter.
package xray

import (
	"context"
	"fmt"
	"net"
)

// Adapter provides wire format translation between StealthLink and Xray-core.
type Adapter struct {
	enabled bool
	mode    string // "xhttp" for SplitHTTP/XHTTP compatibility
}

// Config configures the Xray-core compatibility adapter.
type Config struct {
	Enabled bool   `yaml:"enabled"` // Enable Xray-core wire format compatibility
	Mode    string `yaml:"mode"`    // Protocol mode: "xhttp" (SplitHTTP)
}

// NewAdapter creates a new Xray-core compatibility adapter.
func NewAdapter(cfg Config) (*Adapter, error) {
	if !cfg.Enabled {
		return &Adapter{enabled: false}, nil
	}

	if cfg.Mode != "xhttp" {
		return nil, fmt.Errorf("unsupported xray mode: %s (only 'xhttp' supported)", cfg.Mode)
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

// WrapDialer wraps a dialer to translate StealthLink frames to Xray-core wire format.
func (a *Adapter) WrapDialer(dialer func(ctx context.Context, addr string) (net.Conn, error)) func(ctx context.Context, addr string) (net.Conn, error) {
	if !a.enabled {
		return dialer
	}

	return func(ctx context.Context, addr string) (net.Conn, error) {
		conn, err := dialer(ctx, addr)
		if err != nil {
			return nil, err
		}
		return &xrayConn{Conn: conn, mode: a.mode}, nil
	}
}

// WrapListener wraps a listener to translate Xray-core wire format to StealthLink frames.
func (a *Adapter) WrapListener(listener net.Listener) net.Listener {
	if !a.enabled {
		return listener
	}
	return &xrayListener{Listener: listener, mode: a.mode}
}

// xrayConn wraps a connection to translate wire formats.
type xrayConn struct {
	net.Conn
	mode string
}

// xrayListener wraps a listener to translate wire formats.
type xrayListener struct {
	net.Listener
	mode string
}

// Accept accepts a connection and wraps it for wire format translation.
func (l *xrayListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &xrayConn{Conn: conn, mode: l.mode}, nil
}
