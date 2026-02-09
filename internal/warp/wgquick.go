package warp

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// WGQuick provides a fallback implementation using system wg-quick.
type WGQuick struct {
	config     Config
	device     *WARPDevice
	configFile string
	interfaceName string
}

// NewWGQuick creates a new wg-quick based WARP tunnel.
func NewWGQuick(cfg Config, device *WARPDevice) (*WGQuick, error) {
	if cfg.Mode != "wgquick" {
		return nil, fmt.Errorf("wgquick mode not selected")
	}

	return &WGQuick{
		config:        cfg,
		device:        device,
		interfaceName: "warp0",
	}, nil
}

// Start starts the wg-quick tunnel.
func (w *WGQuick) Start() error {
	// Generate wg-quick config file
	configPath, err := w.generateConfig()
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}
	w.configFile = configPath

	// Run wg-quick up
	cmd := exec.Command("wg-quick", "up", w.configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick up failed: %w (output: %s)", err, output)
	}

	return nil
}

// Stop stops the wg-quick tunnel.
func (w *WGQuick) Stop() error {
	if w.configFile == "" {
		return nil
	}

	// Run wg-quick down
	cmd := exec.Command("wg-quick", "down", w.configFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wg-quick down failed: %w (output: %s)", err, output)
	}

	// Remove config file
	os.Remove(w.configFile)

	return nil
}

// generateConfig generates a wg-quick configuration file.
func (w *WGQuick) generateConfig() (string, error) {
	config := w.buildConfig()

	// Write to temporary file
	tmpFile, err := os.CreateTemp("", "warp-*.conf")
	if err != nil {
		return "", err
	}
	defer tmpFile.Close()

	if _, err := tmpFile.WriteString(config); err != nil {
		return "", err
	}

	return tmpFile.Name(), nil
}

// buildConfig builds the WireGuard configuration.
func (w *WGQuick) buildConfig() string {
	var sb strings.Builder

	// Interface section
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", w.config.PrivateKey))
	sb.WriteString(fmt.Sprintf("Address = %s\n", w.device.IPv4+"/32"))
	if w.device.IPv6 != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", w.device.IPv6+"/128"))
	}
	sb.WriteString(fmt.Sprintf("DNS = %s\n", strings.Join(w.config.DNS, ", ")))
	sb.WriteString(fmt.Sprintf("MTU = %d\n", w.config.MTU))
	sb.WriteString("\n")

	// Peer section (Cloudflare WARP)
	sb.WriteString("[Peer]\n")
	publicKey := w.config.PublicKey
	if publicKey == "" {
		publicKey = CloudflareWARPPublicKey
	}
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", publicKey))
	sb.WriteString(fmt.Sprintf("Endpoint = %s\n", w.config.Endpoint))
	sb.WriteString("AllowedIPs = 0.0.0.0/0, ::/0\n")

	// Keepalive
	if w.config.Keepalive > 0 {
		sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", int(w.config.Keepalive.Seconds())))
	}

	return sb.String()
}

// GenerateWGQuickConfig generates a wg-quick configuration string.
func GenerateWGQuickConfig(cfg Config, device *WARPDevice) string {
	wg := &WGQuick{
		config: cfg,
		device: device,
	}
	return wg.buildConfig()
}

// SaveWGQuickConfig saves a wg-quick config to a file.
func SaveWGQuickConfig(path string, cfg Config, device *WARPDevice) error {
	config := GenerateWGQuickConfig(cfg, device)
	return os.WriteFile(path, []byte(config), 0600)
}

// ApplyWGQuick applies a wg-quick configuration directly.
func ApplyWGQuick(cfg Config, device *WARPDevice) error {
	wg, err := NewWGQuick(cfg, device)
	if err != nil {
		return err
	}
	return wg.Start()
}

// RemoveWGQuick removes a wg-quick configuration.
func RemoveWGQuick(cfg Config) error {
	// Run wg-quick down with interface name
	cmd := exec.Command("wg-quick", "down", "warp0")
	return cmd.Run()
}

// CheckWGQuickAvailable checks if wg-quick is available.
func CheckWGQuickAvailable() bool {
	_, err := exec.LookPath("wg-quick")
	return err == nil
}

// CheckWGAvailable checks if WireGuard tools are available.
func CheckWGAvailable() bool {
	_, err := exec.LookPath("wg")
	return err == nil
}

// GetWGInterface returns the WireGuard interface status.
func GetWGInterface(name string) (map[string]string, error) {
	cmd := exec.Command("wg", "show", name)
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}

	return result, nil
}
