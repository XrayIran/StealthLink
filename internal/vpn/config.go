package vpn

// Config holds VPN configuration for TUN (L3) mode.
type Config struct {
	Enabled     bool     `yaml:"enabled"`
	Mode        string   `yaml:"mode"`         // "tun" (only)
	Name        string   `yaml:"name"`         // Interface name (e.g., "stealth0")
	InterfaceIP string   `yaml:"interface_ip"` // Local IP with CIDR (e.g., "10.0.0.1/24")
	PeerIP      string   `yaml:"peer_ip"`      // Remote peer IP (optional, for point-to-point)
	MTU         int      `yaml:"mtu"`          // Interface MTU (default: 1400)
	Routes      []Route  `yaml:"routes"`       // Additional routes to add
	DNS         []string `yaml:"dns"`          // DNS servers to configure

	// Reverse proxy integration
	Reverse ReverseConfig `yaml:"reverse"`
}

// Route represents a network route to configure.
type Route struct {
	Destination string `yaml:"destination"` // CIDR (e.g., "0.0.0.0/0" for default)
	Gateway     string `yaml:"gateway"`     // Gateway IP (optional)
	Metric      int    `yaml:"metric"`      // Route metric
}

// ReverseConfig configures reverse proxy integration.
type ReverseConfig struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"` // reverse proxy type
}

// DefaultConfig returns a default VPN configuration.
func DefaultConfig() Config {
	return Config{
		Enabled: false,
		Mode:    "tun",
		Name:    "stealth0",
		MTU:     1400,
		Routes:  []Route{},
		DNS:     []string{},
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	// L3-only: reject TAP.
	if c.Mode == "" {
		c.Mode = "tun"
	}
	if c.Mode != "tun" {
		return ErrInvalidMode
	}

	if c.InterfaceIP == "" {
		return ErrMissingInterfaceIP
	}

	if c.MTU <= 0 {
		c.MTU = 1400
	}

	if c.MTU > 9000 {
		c.MTU = 9000
	}

	return nil
}
