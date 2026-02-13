package underlay

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
	"stealthlink/internal/warp"
)

// WARPDialer implements dialing through Cloudflare WARP
type WARPDialer struct {
	config config.WARPDialer
	tunnel *warp.Tunnel
	mu     sync.RWMutex
	health string // "up" | "down"
}

// NewWARPDialer creates a new WARP dialer
func NewWARPDialer(cfg config.WARPDialer) (*WARPDialer, error) {
	// Test-only escape hatch: allow wiring/variant tests to validate that the
	// "warp" dialer path is selectable without requiring privileged WARP setup.
	//
	// This does NOT provide WARP egress; it dials directly. Do not use in production.
	if os.Getenv("STEALTHLINK_WARP_DIALER_MOCK") == "1" {
		d := &WARPDialer{config: cfg, tunnel: nil, health: "up"}
		metrics.SetWARPHealth("up")
		return d, nil
	}

	engine := strings.ToLower(strings.TrimSpace(cfg.Engine))
	if engine == "" {
		engine = "builtin"
	}

	// Create WARP configuration
	warpCfg := warp.Config{
		Enabled:       true,
		Required:      cfg.Required,
		Mode:          engine, // internal engine selector: "builtin" | "wgquick"
		Endpoint:      "engage.cloudflareclient.com:2408",
		RoutingMode:   "vpn_only", // Route only StealthLink traffic through WARP
		InterfaceName: "warp0",
		Keepalive:     25 * time.Second,
	}

	// Create WARP tunnel
	tunnel, err := warp.NewTunnel(warpCfg)
	if err != nil {
		return nil, fmt.Errorf("create WARP tunnel: %w", err)
	}

	// Set device ID if provided
	if cfg.DeviceID != "" {
		device := tunnel.GetDevice()
		if device == nil {
			device = &warp.WARPDevice{}
		}
		device.ID = cfg.DeviceID
	}

	d := &WARPDialer{
		config: cfg,
		tunnel: tunnel,
		health: "down",
	}

	// Start WARP tunnel
	if err := tunnel.Start(); err != nil {
		return nil, fmt.Errorf("start WARP tunnel: %w", err)
	}

	d.health = "up"

	// Update metrics
	metrics.SetWARPHealth("up")

	return d, nil
}

// Dial establishes a connection through WARP
func (d *WARPDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if d.health != "up" {
		return nil, fmt.Errorf("WARP tunnel is down")
	}

	// Use standard dialer but traffic will be routed through WARP
	// due to routing configuration
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return dialer.DialContext(ctx, network, address)
}

// Type returns the dialer type
func (d *WARPDialer) Type() string {
	return "warp"
}

// Health returns the WARP tunnel health status
func (d *WARPDialer) Health() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.health
}

// Close closes the WARP dialer and tunnel
func (d *WARPDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.health = "down"

	// Update metrics
	metrics.SetWARPHealth("down")

	if d.tunnel != nil {
		return d.tunnel.Close()
	}

	return nil
}
