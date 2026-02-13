package config

import "fmt"

// XrayCompatConfig configures the Xray-core compatibility adapter.
// This adapter is OPTIONAL and should only be enabled when interoperability
// with Xray-core clients is required.
type XrayCompatConfig struct {
	Enabled bool   `yaml:"enabled"` // Enable Xray-core wire format compatibility
	Mode    string `yaml:"mode"`    // Protocol mode: "xhttp" (SplitHTTP)
}

// SingboxCompatConfig configures the sing-box compatibility adapter.
// This adapter is OPTIONAL and should only be enabled when interoperability
// with sing-box clients is required.
type SingboxCompatConfig struct {
	Enabled bool   `yaml:"enabled"` // Enable sing-box wire format compatibility
	Mode    string `yaml:"mode"`    // Protocol mode: "anytls"
}

// ValidateCompatMode validates the compatibility mode configuration.
func (c *Config) ValidateCompatMode() error {
	// Default to "none" if not specified
	if c.Transport.CompatMode == "" {
		c.Transport.CompatMode = "none"
		return nil
	}

	// Validate compat_mode value
	switch c.Transport.CompatMode {
	case "none":
		// No adapter enabled - this is the default and recommended mode
		return nil
	case "xray":
		// Xray-core adapter
		if !c.Transport.Xray.Enabled {
			return fmt.Errorf("compat_mode is 'xray' but transport.xray.enabled is false")
		}
		if c.Transport.Xray.Mode != "xhttp" {
			return fmt.Errorf("unsupported xray mode: %s (only 'xhttp' supported)", c.Transport.Xray.Mode)
		}
		return nil
	case "singbox":
		// sing-box adapter
		if !c.Transport.Singbox.Enabled {
			return fmt.Errorf("compat_mode is 'singbox' but transport.singbox.enabled is false")
		}
		if c.Transport.Singbox.Mode != "anytls" {
			return fmt.Errorf("unsupported singbox mode: %s (only 'anytls' supported)", c.Transport.Singbox.Mode)
		}
		return nil
	default:
		return fmt.Errorf("invalid compat_mode: %s (must be 'none', 'xray', or 'singbox')", c.Transport.CompatMode)
	}
}

// ApplyCompatDefaults applies default values for compatibility adapter configuration.
func (c *Config) ApplyCompatDefaults() {
	// Default to "none" if not specified
	if c.Transport.CompatMode == "" {
		c.Transport.CompatMode = "none"
	}

	// Apply defaults for Xray adapter
	if c.Transport.CompatMode == "xray" && c.Transport.Xray.Mode == "" {
		c.Transport.Xray.Mode = "xhttp"
	}

	// Apply defaults for sing-box adapter
	if c.Transport.CompatMode == "singbox" && c.Transport.Singbox.Mode == "" {
		c.Transport.Singbox.Mode = "anytls"
	}
}
