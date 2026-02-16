package config

import (
	"fmt"
	"strings"

	"stealthlink/internal/routing"
)

// DialerPolicyConfig configures per-destination selection between underlay dialers.
//
// This is intentionally a small surface to consolidate routing-policy ideas from
// dae/leaf/mihomo into StealthLink's underlay selection.
//
// Example:
// transport:
//
//	dialer: policy
//	dialer_policy:
//	  enabled: true
//	  default: direct
//	  rules:
//	    - name: use-warp-for-example
//	      priority: 100
//	      enabled: true
//	      matchers:
//	        - type: domain_suffix
//	          pattern: ".example.com"
//	      action:
//	        type: chain
//	        chain: warp
type DialerPolicyConfig struct {
	Enabled bool           `yaml:"enabled"`
	Default string         `yaml:"default"` // direct | warp | socks
	Rules   []routing.Rule `yaml:"rules"`
}

func (c *Config) validateDialerPolicy() error {
	p := c.Transport.DialerPolicy
	if !p.Enabled {
		return nil
	}

	def := strings.ToLower(strings.TrimSpace(p.Default))
	if def == "" {
		def = "direct"
	}
	switch def {
	case "direct", "warp", "socks":
	default:
		return fmt.Errorf("transport.dialer_policy.default must be one of: direct, warp, socks")
	}

	for i := range p.Rules {
		r := &p.Rules[i]
		if strings.TrimSpace(r.Name) == "" {
			return fmt.Errorf("transport.dialer_policy.rules[%d].name is required", i)
		}
		// Compile matchers (validates patterns).
		for j := range r.Matchers {
			if err := r.Matchers[j].Compile(); err != nil {
				return fmt.Errorf("transport.dialer_policy.rules[%d] matcher[%d]: %w", i, j, err)
			}
		}

		// Validate action -> dialer mapping.
		act := strings.ToLower(strings.TrimSpace(string(r.Action.Type)))
		switch act {
		case "direct":
			// Uses default dialer.
		case "chain":
			d := strings.ToLower(strings.TrimSpace(r.Action.Chain))
			switch d {
			case "direct", "warp", "socks":
			default:
				return fmt.Errorf("transport.dialer_policy.rules[%d] action.chain must be one of: direct, warp, socks", i)
			}
		case "proxy":
			// Allow proxy action but require proxy name be one of the dialers.
			d := strings.ToLower(strings.TrimSpace(r.Action.Proxy))
			if d == "" {
				d = strings.ToLower(strings.TrimSpace(r.Action.Chain))
			}
			switch d {
			case "direct", "warp", "socks":
			default:
				return fmt.Errorf("transport.dialer_policy.rules[%d] action.proxy must be one of: direct, warp, socks", i)
			}
		case "block":
			// Explicit block is supported.
		default:
			return fmt.Errorf("transport.dialer_policy.rules[%d] action.type must be one of: direct, chain, proxy, block", i)
		}
	}

	return nil
}
