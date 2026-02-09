// Package killswitch provides kill switch functionality for Windows
// using Windows Filtering Platform (WFP).
package killswitch

import (
	"fmt"
	"os/exec"
	"strings"
)

// WindowsKillSwitch implements the kill switch for Windows using WFP
type WindowsKillSwitch struct {
	tunnelGUID string
	tunnelIface string
	enabled    bool
	filterID   string
}

// NewWindows creates a new Windows kill switch
func NewWindows(tunnelIface string) (*WindowsKillSwitch, error) {
	return &WindowsKillSwitch{
		tunnelIface: tunnelIface,
	}, nil
}

// Enable enables the kill switch
func (k *WindowsKillSwitch) Enable() error {
	if k.enabled {
		return nil
	}

	// Use netsh to configure Windows Firewall
	// This is a simplified implementation - full WFP integration would require
	// calling the Win32 API directly via CGO or using a driver

	// Enable firewall
	if err := k.runNetsh("advfirewall", "set", "allprofiles", "state", "on"); err != nil {
		return fmt.Errorf("enable firewall: %w", err)
	}

	// Block all outbound by default
	if err := k.runNetsh("advfirewall", "firewall", "set", "rule", "all", "new", "enable=no"); err != nil {
		// Non-fatal
	}

	// Allow loopback
	if err := k.runNetsh("advfirewall", "firewall", "add", "rule",
		"name=KillSwitch_Loopback",
		"dir=out",
		"action=allow",
		"remoteip=127.0.0.0/8"); err != nil {
		return err
	}

	// Allow LAN
	lanRanges := []string{
		"192.168.0.0/16",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"fe80::/10",
	}

	for _, cidr := range lanRanges {
		if err := k.runNetsh("advfirewall", "firewall", "add", "rule",
			"name=KillSwitch_LAN",
			"dir=out",
			"action=allow",
			"remoteip="+cidr); err != nil {
			return err
		}
	}

	// Allow DHCP
	if err := k.runNetsh("advfirewall", "firewall", "add", "rule",
		"name=KillSwitch_DHCP",
		"dir=out",
		"action=allow",
		"protocol=udp",
		"remoteport=67",
		"localport=68"); err != nil {
		return err
	}

	// Allow DNS
	if err := k.runNetsh("advfirewall", "firewall", "add", "rule",
		"name=KillSwitch_DNS_TCP",
		"dir=out",
		"action=allow",
		"protocol=tcp",
		"remoteport=53"); err != nil {
		return err
	}
	if err := k.runNetsh("advfirewall", "firewall", "add", "rule",
		"name=KillSwitch_DNS_UDP",
		"dir=out",
		"action=allow",
		"protocol=udp",
		"remoteport=53"); err != nil {
		return err
	}

	// Block all other outbound
	if err := k.runNetsh("advfirewall", "firewall", "add", "rule",
		"name=KillSwitch_Block",
		"dir=out",
		"action=block",
		"enable=yes"); err != nil {
		return err
	}

	k.enabled = true
	return nil
}

// Disable disables the kill switch
func (k *WindowsKillSwitch) Disable() error {
	if !k.enabled {
		return nil
	}

	// Remove kill switch rules
	k.runNetsh("advfirewall", "firewall", "delete", "rule", "name=KillSwitch_Loopback")
	k.runNetsh("advfirewall", "firewall", "delete", "rule", "name=KillSwitch_LAN")
	k.runNetsh("advfirewall", "firewall", "delete", "rule", "name=KillSwitch_DHCP")
	k.runNetsh("advfirewall", "firewall", "delete", "rule", "name=KillSwitch_DNS_TCP")
	k.runNetsh("advfirewall", "firewall", "delete", "rule", "name=KillSwitch_DNS_UDP")
	k.runNetsh("advfirewall", "firewall", "delete", "rule", "name=KillSwitch_Block")

	k.enabled = false
	return nil
}

// runNetsh runs a netsh command
func (k *WindowsKillSwitch) runNetsh(args ...string) error {
	cmd := exec.Command("netsh", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh %v failed: %v: %s", args, err, output)
	}
	return nil
}

// runPowerShell runs a PowerShell command
func (k *WindowsKillSwitch) runPowerShell(script string) error {
	cmd := exec.Command("powershell", "-ExecutionPolicy", "Bypass", "-Command", script)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("powershell failed: %v: %s", err, output)
	}
	return nil
}

// IsEnabled returns whether the kill switch is enabled
func (k *WindowsKillSwitch) IsEnabled() bool {
	return k.enabled
}

// SetTunnelInterface updates the tunnel interface
func (k *WindowsKillSwitch) SetTunnelInterface(iface string) {
	k.tunnelIface = iface
}

// AddAllowedIP adds an IP to the allowed list
func (k *WindowsKillSwitch) AddAllowedIP(ip string) {
	// Add WFP filter for this IP
	ruleName := fmt.Sprintf("KillSwitch_Allow_%s", strings.ReplaceAll(ip, "/", "_"))
	k.runNetsh("advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=out",
		"action=allow",
		"remoteip="+ip)
}
