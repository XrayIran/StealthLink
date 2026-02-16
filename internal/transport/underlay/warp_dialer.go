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

type WARPDialer struct {
	config     config.WARPDialer
	tunnel     *warp.Tunnel
	mu         sync.RWMutex
	health     string
	policyCfg  warp.PolicyRoutingConfig
	routingSet bool
}

func NewWARPDialer(cfg config.WARPDialer) (*WARPDialer, error) {
	if os.Getenv("STEALTHLINK_WARP_DIALER_MOCK") == "1" {
		d := &WARPDialer{config: cfg, tunnel: nil, health: "up"}
		metrics.SetWARPHealth("up")
		metrics.SetUnderlaySelected("warp")
		return d, nil
	}

	engine := strings.ToLower(strings.TrimSpace(cfg.Engine))
	if engine == "" {
		engine = "builtin"
	}

	routingPolicy := strings.ToLower(strings.TrimSpace(cfg.RoutingPolicy))
	if routingPolicy == "" {
		routingPolicy = "socket_mark"
	}

	warpCfg := warp.Config{
		Enabled:       true,
		Required:      cfg.Required,
		Mode:          engine,
		Endpoint:      "engage.cloudflareclient.com:2408",
		RoutingMode:   "vpn_only",
		InterfaceName: "warp0",
		Keepalive:     25 * time.Second,
	}

	tunnel, err := warp.NewTunnel(warpCfg)
	if err != nil {
		if cfg.Required {
			return nil, fmt.Errorf("create WARP tunnel (required): %w", err)
		}
		d := &WARPDialer{config: cfg, health: "down"}
		metrics.SetWARPHealth("down")
		return d, nil
	}

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
		policyCfg: warp.PolicyRoutingConfig{
			Mark:         cfg.Mark,
			Table:        cfg.Table,
			RulePriority: cfg.RulePriority,
			IfaceName:    warpCfg.InterfaceName,
		},
	}

	if err := tunnel.Start(); err != nil {
		if cfg.Required {
			return nil, fmt.Errorf("start WARP tunnel (required): %w", err)
		}
		metrics.SetWARPHealth("down")
		return d, nil
	}

	if routingPolicy == "socket_mark" {
		if err := warp.SetupPolicyRouting(d.policyCfg); err != nil {
			tunnel.Close()
			if cfg.Required {
				return nil, fmt.Errorf("setup WARP policy routing (required): %w", err)
			}
			metrics.SetWARPHealth("down")
			return d, nil
		}
		d.routingSet = true
	}

	d.health = "up"
	metrics.SetWARPHealth("up")
	metrics.SetUnderlaySelected("warp")

	return d, nil
}

func (d *WARPDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.mu.RLock()
	health := d.health
	d.mu.RUnlock()

	if health != "up" {
		return nil, fmt.Errorf("WARP tunnel is down")
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   d.socketControl,
	}

	return dialer.DialContext(ctx, network, address)
}

func (d *WARPDialer) Type() string {
	return "warp"
}

func (d *WARPDialer) Health() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.health
}

func (d *WARPDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.health = "down"
	metrics.SetWARPHealth("down")

	if d.routingSet {
		warp.TeardownPolicyRouting(d.policyCfg)
		d.routingSet = false
	}

	if d.tunnel != nil {
		return d.tunnel.Close()
	}

	return nil
}
