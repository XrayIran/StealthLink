// Package killswitch provides kill switch functionality for macOS
// using PF (Packet Filter).
package killswitch

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// DarwinKillSwitch implements the kill switch for macOS using PF
type DarwinKillSwitch struct {
	tunnelIface string
	enabled     bool
	pfFile      string
}

// NewDarwin creates a new Darwin kill switch
func NewDarwin(tunnelIface string) (*DarwinKillSwitch, error) {
	return &DarwinKillSwitch{
		tunnelIface: tunnelIface,
		pfFile:      "/etc/pf.conf", // Use main PF config
	}, nil
}

// Enable enables the kill switch
func (k *DarwinKillSwitch) Enable() error {
	if k.enabled {
		return nil
	}

	// Create anchor configuration
	anchorConfig := k.generateAnchorConfig()

	// Write to anchor file
	anchorFile := "/etc/pf.anchors/killswitch"
	if err := os.WriteFile(anchorFile, []byte(anchorConfig), 0600); err != nil {
		return fmt.Errorf("write anchor: %w", err)
	}

	// Add anchor to main config if not present
	if err := k.addAnchor(); err != nil {
		return err
	}

	// Enable PF if not already enabled
	if err := k.runCmd("pfctl", "-e"); err != nil {
		// May already be enabled
	}

	// Load rules
	if err := k.runCmd("pfctl", "-f", k.pfFile); err != nil {
		return fmt.Errorf("load pf rules: %w", err)
	}

	k.enabled = true
	return nil
}

// Disable disables the kill switch
func (k *DarwinKillSwitch) Disable() error {
	if !k.enabled {
		return nil
	}

	// Remove anchor from config
	k.removeAnchor()

	// Flush killswitch anchor
	k.runCmd("pfctl", "-a", "killswitch", "-F", "all")

	// Reload rules without anchor
	k.runCmd("pfctl", "-f", k.pfFile)

	// Remove anchor file
	os.Remove("/etc/pf.anchors/killswitch")

	k.enabled = false
	return nil
}

// generateAnchorConfig generates PF anchor configuration
func (k *DarwinKillSwitch) generateAnchorConfig() string {
	var sb strings.Builder

	sb.WriteString("# Kill Switch Anchor\n\n")

	// Block all outbound by default on main interfaces
	sb.WriteString("block drop out all\n")

	// Allow loopback
	sb.WriteString("pass quick on lo0 all\n")

	// Allow established connections
	sb.WriteString("pass out quick all flags any keep state\n")

	// Allow LAN
	lanRanges := []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
	}
	for _, cidr := range lanRanges {
		sb.WriteString(fmt.Sprintf("pass out quick to %s\n", cidr))
	}

	// Allow tunnel interface
	if k.tunnelIface != "" {
		sb.WriteString(fmt.Sprintf("pass out quick on %s all\n", k.tunnelIface))
	}

	// Allow DHCP
	sb.WriteString("pass out quick proto udp to any port 67\n")
	sb.WriteString("pass in quick proto udp to any port 68\n")

	// Allow DNS
	sb.WriteString("pass out quick proto { tcp, udp } to any port 53\n")

	return sb.String()
}

// addAnchor adds the killswitch anchor to PF config
func (k *DarwinKillSwitch) addAnchor() error {
	// Check if anchor already present
	content, err := os.ReadFile(k.pfFile)
	if err != nil {
		return err
	}

	anchorLine := "anchor killswitch"
	if strings.Contains(string(content), anchorLine) {
		return nil
	}

	// Append anchor
	f, err := os.OpenFile(k.pfFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString("\n" + anchorLine + "\n")
	return err
}

// removeAnchor removes the killswitch anchor from PF config
func (k *DarwinKillSwitch) removeAnchor() error {
	content, err := os.ReadFile(k.pfFile)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string

	for _, line := range lines {
		if !strings.Contains(line, "anchor killswitch") {
			newLines = append(newLines, line)
		}
	}

	return os.WriteFile(k.pfFile, []byte(strings.Join(newLines, "\n")), 0644)
}

// runCmd runs a command
func (k *DarwinKillSwitch) runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%s %v failed: %v: %s", name, args, err, output)
	}
	return nil
}

// IsEnabled returns whether the kill switch is enabled
func (k *DarwinKillSwitch) IsEnabled() bool {
	return k.enabled
}

// SetTunnelInterface updates the tunnel interface
func (k *DarwinKillSwitch) SetTunnelInterface(iface string) {
	k.tunnelIface = iface
}

// AddAllowedIP adds an IP to the allowed list
func (k *DarwinKillSwitch) AddAllowedIP(ip string) {
	// Add pass rule for this IP
	anchorFile := "/etc/pf.anchors/killswitch"
	content, _ := os.ReadFile(anchorFile)

	newRule := fmt.Sprintf("pass out quick to %s\n", ip)
	content = append(content, []byte(newRule)...)

	os.WriteFile(anchorFile, content, 0600)

	// Reload rules
	k.runCmd("pfctl", "-f", k.pfFile)
}
