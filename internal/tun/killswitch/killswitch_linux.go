// Package killswitch provides kill switch functionality for Linux
// using iptables/nftables.
package killswitch

import (
	"fmt"
	"os/exec"
	"strings"
)

// Backend represents the firewall backend to use
type Backend string

const (
	BackendIPTables Backend = "iptables"
	BackendNFTables Backend = "nftables"
)

// LinuxKillSwitch implements the kill switch for Linux
type LinuxKillSwitch struct {
	backend    Backend
	tunnelIface string
	tunnelIP   string
	allowedLAN []string
	enabled    bool
}

// NewLinux creates a new Linux kill switch
func NewLinux(tunnelIface string) (*LinuxKillSwitch, error) {
	// Detect backend
	backend := detectBackend()

	return &LinuxKillSwitch{
		backend:     backend,
		tunnelIface: tunnelIface,
		allowedLAN:  []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"},
	}, nil
}

// detectBackend detects which firewall backend is available
func detectBackend() Backend {
	// Prefer nftables
	if _, err := exec.LookPath("nft"); err == nil {
		return BackendNFTables
	}
	// Fall back to iptables
	if _, err := exec.LookPath("iptables"); err == nil {
		return BackendIPTables
	}
	return BackendIPTables // Default
}

// Enable enables the kill switch
func (k *LinuxKillSwitch) Enable() error {
	if k.enabled {
		return nil
	}

	switch k.backend {
	case BackendNFTables:
		if err := k.enableNFTables(); err != nil {
			return err
		}
	case BackendIPTables:
		if err := k.enableIPTables(); err != nil {
			return err
		}
	}

	k.enabled = true
	return nil
}

// Disable disables the kill switch
func (k *LinuxKillSwitch) Disable() error {
	if !k.enabled {
		return nil
	}

	switch k.backend {
	case BackendNFTables:
		if err := k.disableNFTables(); err != nil {
			return err
		}
	case BackendIPTables:
		if err := k.disableIPTables(); err != nil {
			return err
		}
	}

	k.enabled = false
	return nil
}

// enableNFTables enables kill switch using nftables
func (k *LinuxKillSwitch) enableNFTables() error {
	// Create nftables configuration
	config := fmt.Sprintf(`
table ip killswitch {
	chain output {
		type filter hook output priority 0; policy drop;

		# Allow loopback
		oif "lo" accept

		# Allow established connections
		ct state established,related accept

		# Allow LAN traffic
		ip daddr 192.168.0.0/16 accept
		ip daddr 10.0.0.0/8 accept
		ip daddr 172.16.0.0/12 accept

		# Allow tunnel interface
		oif "%s" accept

		# Allow DHCP
		udp dport 67 udp sport 68 accept
		udp dport 68 udp sport 67 accept

		# Allow DNS (needed for initial connection)
		udp dport 53 accept
		tcp dport 53 accept
	}

	chain input {
		type filter hook input priority 0; policy drop;

		# Allow loopback
		iif "lo" accept

		# Allow established connections
		ct state established,related accept

		# Allow LAN traffic
		ip saddr 192.168.0.0/16 accept
		ip saddr 10.0.0.0/8 accept
		ip saddr 172.16.0.0/12 accept

		# Allow tunnel interface
		iif "%s" accept

		# Allow DHCP
		udp dport 67 udp sport 68 accept
		udp dport 68 udp sport 67 accept
	}
}`, k.tunnelIface, k.tunnelIface)

	// Apply configuration
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(config)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nftables failed: %v: %s", err, output)
	}

	return nil
}

// disableNFTables disables the nftables kill switch
func (k *LinuxKillSwitch) disableNFTables() error {
	cmd := exec.Command("nft", "delete", "table", "ip", "killswitch")
	// Ignore error - table might not exist
	cmd.Run()
	return nil
}

// enableIPTables enables kill switch using iptables
func (k *LinuxKillSwitch) enableIPTables() error {
	// Save current rules
	exec.Command("iptables-save", ">", "/tmp/iptables.backup").Run()

	// Flush existing rules
	if err := k.runIPTables("-F"); err != nil {
		return err
	}

	// Set default policy to DROP
	if err := k.runIPTables("-P", "OUTPUT", "DROP"); err != nil {
		return err
	}
	if err := k.runIPTables("-P", "INPUT", "DROP"); err != nil {
		return err
	}

	// Allow loopback
	if err := k.runIPTables("-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := k.runIPTables("-A", "INPUT", "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Allow established connections
	if err := k.runIPTables("-A", "OUTPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := k.runIPTables("-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Allow LAN
	for _, cidr := range k.allowedLAN {
		if err := k.runIPTables("-A", "OUTPUT", "-d", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := k.runIPTables("-A", "INPUT", "-s", cidr, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	// Allow tunnel interface
	if err := k.runIPTables("-A", "OUTPUT", "-o", k.tunnelIface, "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := k.runIPTables("-A", "INPUT", "-i", k.tunnelIface, "-j", "ACCEPT"); err != nil {
		return err
	}

	// Allow DHCP
	if err := k.runIPTables("-A", "OUTPUT", "-p", "udp", "--dport", "67", "--sport", "68", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := k.runIPTables("-A", "INPUT", "-p", "udp", "--dport", "68", "--sport", "67", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Allow DNS
	if err := k.runIPTables("-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := k.runIPTables("-A", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"); err != nil {
		return err
	}

	return nil
}

// disableIPTables disables the iptables kill switch
func (k *LinuxKillSwitch) disableIPTables() error {
	// Set policy back to ACCEPT
	k.runIPTables("-P", "OUTPUT", "ACCEPT")
	k.runIPTables("-P", "INPUT", "ACCEPT")

	// Flush rules
	k.runIPTables("-F")

	// Restore backup if exists
	exec.Command("iptables-restore", "<", "/tmp/iptables.backup").Run()

	return nil
}

// runIPTables runs an iptables command
func (k *LinuxKillSwitch) runIPTables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("iptables %v failed: %v: %s", args, err, output)
	}
	return nil
}

// IsEnabled returns whether the kill switch is enabled
func (k *LinuxKillSwitch) IsEnabled() bool {
	return k.enabled
}

// SetTunnelInterface updates the tunnel interface
func (k *LinuxKillSwitch) SetTunnelInterface(iface string) {
	k.tunnelIface = iface
}

// AddAllowedIP adds an IP to the allowed list
func (k *LinuxKillSwitch) AddAllowedIP(ip string) {
	k.allowedLAN = append(k.allowedLAN, ip)
}
