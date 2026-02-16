package underlay

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"stealthlink/internal/config"
	"stealthlink/internal/metrics"
	"stealthlink/internal/routing"
)

// PolicyDialer selects an underlay dialer per destination using routing rules.
// It consolidates policy-routing ideas from dae/leaf/mihomo for StealthLink's
// underlay (direct vs WARP vs SOCKS) selection.
type PolicyDialer struct {
	cfg      *config.Transport
	engine   *routing.Engine
	defaultT string

	mu     sync.Mutex
	direct Dialer
	warp   Dialer
	socks  Dialer
}

func NewPolicyDialer(cfg *config.Transport) (*PolicyDialer, error) {
	if cfg == nil {
		return nil, fmt.Errorf("transport config is required")
	}
	if !cfg.DialerPolicy.Enabled {
		return nil, fmt.Errorf("dialer_policy.enabled is required")
	}

	def := strings.ToLower(strings.TrimSpace(cfg.DialerPolicy.Default))
	if def == "" {
		def = "direct"
	}
	if def != "direct" && def != "warp" && def != "socks" {
		return nil, fmt.Errorf("dialer_policy.default must be one of: direct, warp, socks")
	}

	eng := routing.NewEngine()
	for i := range cfg.DialerPolicy.Rules {
		r := cfg.DialerPolicy.Rules[i]
		// Ensure matchers compiled (config validation should already do this).
		for j := range r.Matchers {
			if err := r.Matchers[j].Compile(); err != nil {
				return nil, fmt.Errorf("dialer_policy.rules[%d] matcher[%d]: %w", i, j, err)
			}
		}
		if err := eng.AddRule(&r); err != nil {
			return nil, fmt.Errorf("add rule %q: %w", r.Name, err)
		}
	}

	return &PolicyDialer{
		cfg:      cfg,
		engine:   eng,
		defaultT: def,
		direct:   NewDirectDialer(),
	}, nil
}

func (d *PolicyDialer) Type() string { return "policy" }

func (d *PolicyDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	var firstErr error
	if d.warp != nil {
		if err := d.warp.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		d.warp = nil
	}
	if d.socks != nil {
		if err := d.socks.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		d.socks = nil
	}
	if d.direct != nil {
		_ = d.direct.Close()
		d.direct = nil
	}
	return firstErr
}

func (d *PolicyDialer) Dial(ctx context.Context, network, address string) (net.Conn, error) {
	inner, innerType, err := d.selectDialer(network, address)
	if err != nil {
		return nil, err
	}
	metrics.SetUnderlaySelected(innerType)
	return inner.Dial(ctx, network, address)
}

func (d *PolicyDialer) selectDialer(network, address string) (Dialer, string, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		// If address is missing port, treat whole string as host.
		host = address
		port = ""
	}
	proto := strings.ToLower(strings.TrimSpace(network))
	if proto == "" {
		proto = "tcp"
	}

	target := &routing.Target{Host: host, Protocol: proto}
	if port != "" {
		// Best-effort port parse.
		_, _ = fmt.Sscanf(port, "%d", &target.Port)
	}

	_, action, err := d.engine.RouteNoResolve(target)
	if err != nil {
		return nil, "", err
	}

	choice := d.defaultT
	if action != nil {
		switch action.Type {
		case routing.ActionTypeBlock:
			return nil, "", fmt.Errorf("blocked by dialer policy")
		case routing.ActionTypeDirect:
			choice = d.defaultT
		case routing.ActionTypeChain:
			if s := strings.ToLower(strings.TrimSpace(action.Chain)); s != "" {
				choice = s
			}
		case routing.ActionTypeProxy:
			if s := strings.ToLower(strings.TrimSpace(action.Proxy)); s != "" {
				choice = s
			} else if s := strings.ToLower(strings.TrimSpace(action.Chain)); s != "" {
				choice = s
			}
		}
	}

	switch choice {
	case "direct":
		return d.direct, "direct", nil
	case "warp":
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.warp == nil {
			w, err := NewWARPDialer(d.cfg.WARPDialer)
			if err != nil {
				return nil, "", err
			}
			d.warp = w
		}
		return d.warp, "warp", nil
	case "socks":
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.socks == nil {
			s, err := NewSOCKSDialer(d.cfg.SOCKSDialer)
			if err != nil {
				return nil, "", err
			}
			d.socks = s
		}
		return d.socks, "socks", nil
	default:
		return nil, "", fmt.Errorf("unsupported dialer policy choice: %s", choice)
	}
}
