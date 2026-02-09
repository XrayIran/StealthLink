package config

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"time"
)

// TLSMirrorConfig configures experimental TLS record mirroring.
type TLSMirrorConfig struct {
	Enabled            bool   `yaml:"enabled"`
	ControlChannel     string `yaml:"control_channel"`
	EnrollmentRequired bool   `yaml:"enrollment_required"`
	AntiLoopback       bool   `yaml:"anti_loopback"`
}

// AWGObfsConfig configures AWG-style obfuscation transport.
type AWGObfsConfig struct {
	PrivateKey    string `yaml:"private_key"`
	PublicKey     string `yaml:"public_key"`
	PeerPublicKey string `yaml:"peer_public_key"`
	Endpoint      string `yaml:"endpoint"`
	ProtocolVer   int    `yaml:"protocol_ver"`
	JunkCount     int    `yaml:"junk_count"`
	JunkMinSize   int    `yaml:"junk_min_size"`
	JunkMaxSize   int    `yaml:"junk_max_size"`
	JunkInterval  string `yaml:"junk_interval"`
}

// RawAdapterConfig configures raw adapters inspired by udp2raw/tcpraw modes.
type RawAdapterConfig struct {
	Mode         string `yaml:"mode"` // rawtcp, icmp, faketcp
	ReplayWindow int    `yaml:"replay_window"`
	AutoFirewall bool   `yaml:"auto_firewall"`
}

// PipelineConfig defines a declarative processing graph.
type PipelineConfig struct {
	Enabled bool           `yaml:"enabled"`
	Nodes   []PipelineNode `yaml:"nodes"`
	Edges   []PipelineEdge `yaml:"edges"`
}

// PipelineNode represents a processing node in transport pipeline.
type PipelineNode struct {
	ID     string            `yaml:"id"`
	Type   string            `yaml:"type"`
	Params map[string]string `yaml:"params"`
}

// PipelineEdge defines a directed edge in the pipeline graph.
type PipelineEdge struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// TransparentProxyConfig configures transparent proxy policy matrix.
type TransparentProxyConfig struct {
	Mode           string   `yaml:"mode"`    // off, redirect, tproxy, tun_system, tun_gvisor
	Backend        string   `yaml:"backend"` // auto, iptables, nftables
	WhitelistCIDRs []string `yaml:"whitelist_cidrs"`
}

// ObfuscationConfig groups configurable obfuscation modules.
type ObfuscationConfig struct {
	Noize NoizeConfig `yaml:"noize"`
}

// HostOptConfig standardizes host optimization settings.
type HostOptConfig struct {
	Profile       string `yaml:"profile"` // balanced, throughput, low-latency
	DryRun        bool   `yaml:"dry_run"`
	RollbackToken string `yaml:"rollback_token"`
}

// AuthConfig configures pluggable authentication providers.
type AuthConfig struct {
	Strict    bool                 `yaml:"strict"`
	Providers []AuthProviderConfig `yaml:"providers"`
}

// AuthProviderConfig defines one provider instance.
type AuthProviderConfig struct {
	Name    string                   `yaml:"name"`
	Type    string                   `yaml:"type"` // static, oidc, radius
	Enabled bool                     `yaml:"enabled"`
	Static  StaticAuthProviderConfig `yaml:"static"`
	OIDC    OIDCAuthProviderConfig   `yaml:"oidc"`
	Radius  RadiusAuthProviderConfig `yaml:"radius"`
}

// StaticAuthProviderConfig holds static token maps.
type StaticAuthProviderConfig struct {
	AgentTokens map[string]string `yaml:"agent_tokens"`
}

// OIDCAuthProviderConfig holds OIDC/JWT validation settings.
type OIDCAuthProviderConfig struct {
	Issuer         string   `yaml:"issuer"`
	Audience       string   `yaml:"audience"`
	HS256Secret    string   `yaml:"hs256_secret"`
	RequiredGroups []string `yaml:"required_groups"`
	ClockSkew      string   `yaml:"clock_skew"`
}

// RadiusAuthProviderConfig holds RADIUS bridge settings.
type RadiusAuthProviderConfig struct {
	SharedSecret string            `yaml:"shared_secret"`
	Users        map[string]string `yaml:"users"`
	Timeout      string            `yaml:"timeout"`
}

func (c *Config) applyExtensionDefaults() {
	if c.TransparentProxy.Mode == "" {
		c.TransparentProxy.Mode = "off"
	}
	if c.TransparentProxy.Backend == "" {
		if runtime.GOOS == "linux" {
			c.TransparentProxy.Backend = "auto"
		} else {
			c.TransparentProxy.Backend = "iptables"
		}
	}
	if c.HostOpt.Profile == "" {
		c.HostOpt.Profile = "balanced"
	}

	// Allow top-level obfuscation.noize as canonical config while keeping backward compatibility.
	if !c.Transport.Stealth.Shaping.Noize.Enabled && c.Obfuscation.Noize.Enabled {
		c.Transport.Stealth.Shaping.Noize = c.Obfuscation.Noize
	}
	if !c.Obfuscation.Noize.Enabled && c.Transport.Stealth.Shaping.Noize.Enabled {
		c.Obfuscation.Noize = c.Transport.Stealth.Shaping.Noize
	}

	for i := range c.Auth.Providers {
		if c.Auth.Providers[i].Name == "" {
			c.Auth.Providers[i].Name = fmt.Sprintf("provider-%d", i+1)
		}
		if !c.Auth.Providers[i].Enabled {
			c.Auth.Providers[i].Enabled = true
		}
		if c.Auth.Providers[i].OIDC.ClockSkew == "" {
			c.Auth.Providers[i].OIDC.ClockSkew = "30s"
		}
		if c.Auth.Providers[i].Radius.Timeout == "" {
			c.Auth.Providers[i].Radius.Timeout = "2s"
		}
	}
}

func (c *Config) validateExtensions() error {
	if c.Transport.Pipeline.Enabled {
		if err := validatePipelineDAG(c.Transport.Pipeline); err != nil {
			return err
		}
	}

	switch c.TransparentProxy.Mode {
	case "off", "redirect", "tproxy", "tun_system", "tun_gvisor":
	default:
		return fmt.Errorf("transparent_proxy.mode must be one of: off, redirect, tproxy, tun_system, tun_gvisor")
	}
	switch c.TransparentProxy.Backend {
	case "auto", "iptables", "nftables":
	default:
		return fmt.Errorf("transparent_proxy.backend must be one of: auto, iptables, nftables")
	}
	for _, cidr := range c.TransparentProxy.WhitelistCIDRs {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("transparent_proxy.whitelist_cidrs contains invalid CIDR %q: %w", cidr, err)
		}
	}

	switch c.HostOpt.Profile {
	case "balanced", "throughput", "low-latency":
	default:
		return fmt.Errorf("host_opt.profile must be one of: balanced, throughput, low-latency")
	}

	for _, p := range c.Auth.Providers {
		if !p.Enabled {
			continue
		}
		switch p.Type {
		case "static":
			// No required fields; falls back to security.* if empty.
		case "oidc":
			if p.OIDC.Issuer == "" || p.OIDC.Audience == "" || p.OIDC.HS256Secret == "" {
				return fmt.Errorf("auth provider %q (oidc) requires issuer, audience, hs256_secret", p.Name)
			}
			if _, err := time.ParseDuration(p.OIDC.ClockSkew); err != nil {
				return fmt.Errorf("auth provider %q oidc.clock_skew invalid: %w", p.Name, err)
			}
		case "radius":
			if p.Radius.SharedSecret == "" {
				return fmt.Errorf("auth provider %q (radius) requires shared_secret", p.Name)
			}
			if _, err := time.ParseDuration(p.Radius.Timeout); err != nil {
				return fmt.Errorf("auth provider %q radius.timeout invalid: %w", p.Name, err)
			}
		default:
			return fmt.Errorf("auth provider %q has unsupported type %q", p.Name, p.Type)
		}
	}
	return nil
}

func validatePipelineDAG(p PipelineConfig) error {
	if len(p.Nodes) == 0 {
		return fmt.Errorf("transport.pipeline.enabled requires at least one node")
	}
	index := make(map[string]struct{}, len(p.Nodes))
	inDegree := make(map[string]int, len(p.Nodes))
	adj := make(map[string][]string, len(p.Nodes))

	for _, n := range p.Nodes {
		id := strings.TrimSpace(n.ID)
		if id == "" {
			return fmt.Errorf("transport.pipeline.nodes[].id is required")
		}
		if _, ok := index[id]; ok {
			return fmt.Errorf("transport.pipeline contains duplicate node id: %s", id)
		}
		index[id] = struct{}{}
		inDegree[id] = 0
	}

	for _, e := range p.Edges {
		if _, ok := index[e.From]; !ok {
			return fmt.Errorf("transport.pipeline edge references unknown node: %s", e.From)
		}
		if _, ok := index[e.To]; !ok {
			return fmt.Errorf("transport.pipeline edge references unknown node: %s", e.To)
		}
		if e.From == e.To {
			return fmt.Errorf("transport.pipeline self-loop at node: %s", e.From)
		}
		adj[e.From] = append(adj[e.From], e.To)
		inDegree[e.To]++
	}

	queue := make([]string, 0, len(p.Nodes))
	for id, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, id)
		}
	}
	seen := 0
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		seen++
		for _, to := range adj[n] {
			inDegree[to]--
			if inDegree[to] == 0 {
				queue = append(queue, to)
			}
		}
	}
	if seen != len(p.Nodes) {
		return fmt.Errorf("transport.pipeline graph contains a cycle")
	}
	return nil
}
