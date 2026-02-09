package warp

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Config holds WARP configuration.
type Config struct {
	Enabled       bool          `yaml:"enabled"`
	Mode          string        `yaml:"mode"`           // "builtin" (wireguard-go) or "wgquick" (system)
	PrivateKey    string        `yaml:"private_key"`    // WireGuard private key (base64)
	PublicKey     string        `yaml:"public_key"`     // Cloudflare WARP server public key
	Endpoint      string        `yaml:"endpoint"`       // e.g., "engage.cloudflareclient.com:2408"
	LicenseKey    string        `yaml:"license_key"`    // Optional WARP+ license key
	DNS           []string      `yaml:"dns"`            // DNS servers to use
	RoutingMode   string        `yaml:"routing_mode"`   // "all" or "vpn_only"
	InterfaceName string        `yaml:"interface_name"` // TUN interface name
	VPNSubnet     string        `yaml:"vpn_subnet"`     // VPN subnet for split routing
	MTU           int           `yaml:"mtu"`
	Keepalive     time.Duration `yaml:"keepalive"`
}

// DefaultConfig returns a default WARP configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:     false,
		Mode:        "builtin",
		Endpoint:    "engage.cloudflareclient.com:2408",
		DNS:         []string{"1.1.1.1", "1.0.0.1"},
		RoutingMode: "vpn_only",
		MTU:         1280,
		Keepalive:   30 * time.Second,
	}
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}

	if c.Mode != "builtin" && c.Mode != "wgquick" {
		return fmt.Errorf("invalid WARP mode: %s (must be 'builtin' or 'wgquick')", c.Mode)
	}

	if c.Endpoint == "" {
		return fmt.Errorf("WARP endpoint is required")
	}
	if _, _, err := net.SplitHostPort(c.Endpoint); err != nil {
		return fmt.Errorf("invalid WARP endpoint %q: expected host:port", c.Endpoint)
	}

	if c.MTU <= 0 {
		c.MTU = 1280
	}
	if c.MTU < 1200 || c.MTU > 1500 {
		return fmt.Errorf("WARP mtu must be between 1200 and 1500")
	}

	if c.RoutingMode != "all" && c.RoutingMode != "vpn_only" {
		return fmt.Errorf("invalid routing mode: %s (must be 'all' or 'vpn_only')", c.RoutingMode)
	}
	if c.RoutingMode == "vpn_only" && strings.TrimSpace(c.VPNSubnet) == "" {
		c.VPNSubnet = "10.8.0.0/24"
	}
	if c.Keepalive <= 0 {
		c.Keepalive = 30 * time.Second
	}
	if c.InterfaceName == "" {
		c.InterfaceName = "warp0"
	}

	return nil
}

// CloudflareWARPPublicKey is the public key for Cloudflare WARP servers.
// This is a well-known key distributed by Cloudflare.
const CloudflareWARPPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

// WARPToken represents a WARP authentication token.
type WARPToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// IsExpired returns true if the token is expired.
func (t *WARPToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// WARPCredentials holds WARP authentication credentials.
type WARPCredentials struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	DeviceID     string `json:"device_id"`
}

// WARPDevice represents a registered WARP device.
type WARPDevice struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Token      string `json:"token"`
	IPv4       string `json:"ipv4"`
	IPv6       string `json:"ipv6"`
}
