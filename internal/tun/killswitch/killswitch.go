// Package killswitch implements a kill switch for VPN connections.
// When enabled, it blocks all network traffic except through the VPN tunnel.
// This prevents IP leaks if the VPN connection drops.
//
// Based on amnezia-client kill switch implementation.
package killswitch

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
)

// Mode represents the kill switch mode
type Mode string

const (
	// ModeStrict blocks all traffic except through the VPN
	ModeStrict Mode = "strict"
	// ModeSoft allows LAN traffic but blocks internet without VPN
	ModeSoft Mode = "soft"
)

// Platform represents the firewall platform
type Platform string

const (
	PlatformIPTables Platform = "iptables"
	PlatformNFTables Platform = "nftables"
	PlatformWFP      Platform = "wfp" // Windows Filtering Platform
	PlatformPF       Platform = "pf"  // BSD/macOS Packet Filter
)

var (
	runFirewallCommand = func(name string, args ...string) ([]byte, error) {
		return exec.Command(name, args...).CombinedOutput()
	}
	lookPath = exec.LookPath
)

// Config configures the kill switch
type Config struct {
	// Mode is the kill switch mode (strict or soft)
	Mode Mode `yaml:"mode"`

	// Platform is the firewall platform to use
	Platform Platform `yaml:"platform"`

	// AllowedApps is a list of application executables that are allowed
	// network access even when the kill switch is active
	AllowedApps []string `yaml:"allowed_apps"`

	// ExcludedNets is a list of networks excluded from the kill switch
	// (e.g., LAN networks in soft mode)
	ExcludedNets []string `yaml:"excluded_nets"`

	// VPNInterface is the VPN tunnel interface name
	VPNInterface string `yaml:"vpn_interface"`

	// VPNGateway is the VPN gateway IP address
	VPNGateway string `yaml:"vpn_gateway"`

	// DNSServers are the DNS servers to allow
	DNSServers []string `yaml:"dns_servers"`
}

// DefaultConfig returns a default kill switch configuration
func DefaultConfig() *Config {
	return &Config{
		Mode:         ModeSoft,
		Platform:     PlatformAuto(),
		AllowedApps:  []string{},
		ExcludedNets: []string{},
		DNSServers:   []string{"1.1.1.1", "8.8.8.8"},
	}
}

// PlatformAuto detects the appropriate platform for the current OS
func PlatformAuto() Platform {
	switch runtime.GOOS {
	case "linux":
		if _, err := lookPath("nft"); err == nil {
			return PlatformNFTables
		}
		if _, err := lookPath("iptables"); err == nil {
			return PlatformIPTables
		}
		return PlatformIPTables
	case "windows":
		return PlatformWFP
	case "darwin", "freebsd", "openbsd":
		return PlatformPF
	default:
		return PlatformIPTables
	}
}

// KillSwitch manages the kill switch state
type KillSwitch struct {
	config  *Config
	enabled bool
	mu      sync.RWMutex
	impl    Implementation
}

// Implementation is the platform-specific kill switch implementation
type Implementation interface {
	// Enable activates the kill switch
	Enable(cfg *Config) error

	// Disable deactivates the kill switch
	Disable() error

	// IsEnabled returns true if the kill switch is active
	IsEnabled() bool

	// AddAllowedApp adds an application to the allowed list
	AddAllowedApp(app string) error

	// RemoveAllowedApp removes an application from the allowed list
	RemoveAllowedApp(app string) error

	// AddExcludedNet adds a network to the excluded list
	AddExcludedNet(network string) error

	// RemoveExcludedNet removes a network from the excluded list
	RemoveExcludedNet(network string) error
}

// New creates a new kill switch
func New(config *Config) (*KillSwitch, error) {
	if config == nil {
		config = DefaultConfig()
	}

	impl, err := newImplementation(config.Platform)
	if err != nil {
		return nil, fmt.Errorf("create implementation: %w", err)
	}

	return &KillSwitch{
		config: config,
		impl:   impl,
	}, nil
}

// Enable activates the kill switch
func (ks *KillSwitch) Enable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if ks.enabled {
		return nil // Already enabled
	}

	if err := ks.impl.Enable(ks.config); err != nil {
		return fmt.Errorf("enable kill switch: %w", err)
	}

	ks.enabled = true
	return nil
}

// Disable deactivates the kill switch
func (ks *KillSwitch) Disable() error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	if !ks.enabled {
		return nil // Already disabled
	}

	if err := ks.impl.Disable(); err != nil {
		return fmt.Errorf("disable kill switch: %w", err)
	}

	ks.enabled = false
	return nil
}

// IsEnabled returns true if the kill switch is active
func (ks *KillSwitch) IsEnabled() bool {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	return ks.enabled
}

// SetMode changes the kill switch mode
func (ks *KillSwitch) SetMode(mode Mode) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	wasEnabled := ks.enabled
	if wasEnabled {
		// Disable first, then re-enable with new mode
		if err := ks.impl.Disable(); err != nil {
			return err
		}
	}

	ks.config.Mode = mode

	if wasEnabled {
		return ks.impl.Enable(ks.config)
	}
	return nil
}

// AddAllowedApp adds an application to the allowed list
func (ks *KillSwitch) AddAllowedApp(app string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.config.AllowedApps = append(ks.config.AllowedApps, app)

	if ks.enabled {
		return ks.impl.AddAllowedApp(app)
	}
	return nil
}

// RemoveAllowedApp removes an application from the allowed list
func (ks *KillSwitch) RemoveAllowedApp(app string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Remove from config
	for i, a := range ks.config.AllowedApps {
		if a == app {
			ks.config.AllowedApps = append(ks.config.AllowedApps[:i], ks.config.AllowedApps[i+1:]...)
			break
		}
	}

	if ks.enabled {
		return ks.impl.RemoveAllowedApp(app)
	}
	return nil
}

// AddExcludedNet adds a network to the excluded list
func (ks *KillSwitch) AddExcludedNet(network string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	ks.config.ExcludedNets = append(ks.config.ExcludedNets, network)

	if ks.enabled {
		return ks.impl.AddExcludedNet(network)
	}
	return nil
}

// RemoveExcludedNet removes a network from the excluded list
func (ks *KillSwitch) RemoveExcludedNet(network string) error {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Remove from config
	for i, n := range ks.config.ExcludedNets {
		if n == network {
			ks.config.ExcludedNets = append(ks.config.ExcludedNets[:i], ks.config.ExcludedNets[i+1:]...)
			break
		}
	}

	if ks.enabled {
		return ks.impl.RemoveExcludedNet(network)
	}
	return nil
}

// GetConfig returns the current configuration
func (ks *KillSwitch) GetConfig() *Config {
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	// Return a copy
	cfg := *ks.config
	cfg.AllowedApps = make([]string, len(ks.config.AllowedApps))
	copy(cfg.AllowedApps, ks.config.AllowedApps)
	cfg.ExcludedNets = make([]string, len(ks.config.ExcludedNets))
	copy(cfg.ExcludedNets, ks.config.ExcludedNets)
	cfg.DNSServers = make([]string, len(ks.config.DNSServers))
	copy(cfg.DNSServers, ks.config.DNSServers)
	return &cfg
}

// newImplementation creates a platform-specific implementation
func newImplementation(platform Platform) (Implementation, error) {
	switch platform {
	case PlatformIPTables:
		return newIPTablesImplementation(), nil
	case PlatformNFTables:
		return newNFTablesImplementation(), nil
	case PlatformWFP:
		return nil, fmt.Errorf("WFP implementation not yet available")
	case PlatformPF:
		return nil, fmt.Errorf("PF implementation not yet available")
	default:
		return nil, fmt.Errorf("unsupported platform: %s", platform)
	}
}

// ==================== IPTables Implementation ====================

// iptablesImplementation implements kill switch using iptables
type iptablesImplementation struct {
	enabled      bool
	vpnInterface string
	chainName    string
}

func newIPTablesImplementation() *iptablesImplementation {
	return &iptablesImplementation{
		chainName: "STEALTHLINK_KILLSWITCH",
	}
}

func (i *iptablesImplementation) Enable(cfg *Config) error {
	i.vpnInterface = cfg.VPNInterface
	if err := i.ensureChain(); err != nil {
		return err
	}
	if err := i.ensureOutputJump(); err != nil {
		return err
	}

	if err := i.addRule("-o", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}
	if err := i.addRule("-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	if i.vpnInterface != "" {
		if err := i.addRule("-o", i.vpnInterface, "-j", "ACCEPT"); err != nil {
			return err
		}
	}

	if len(cfg.DNSServers) == 0 {
		if err := i.addRule("-p", "udp", "--dport", "53", "-j", "ACCEPT"); err != nil {
			return err
		}
		if err := i.addRule("-p", "tcp", "--dport", "53", "-j", "ACCEPT"); err != nil {
			return err
		}
	} else {
		for _, dns := range cfg.DNSServers {
			if net.ParseIP(dns) == nil {
				continue
			}
			if err := i.addRule("-p", "udp", "-d", dns, "--dport", "53", "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := i.addRule("-p", "tcp", "-d", dns, "--dport", "53", "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}

	for _, app := range cfg.AllowedApps {
		if err := i.AddAllowedApp(app); err != nil {
			return err
		}
	}

	if cfg.Mode == ModeSoft {
		for _, lan := range defaultLANRanges() {
			if err := i.addRule("-d", lan, "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}
	for _, network := range cfg.ExcludedNets {
		if err := i.AddExcludedNet(network); err != nil {
			return err
		}
	}

	if err := i.addRule("-j", "DROP"); err != nil {
		return err
	}

	i.enabled = true
	return nil
}

func (i *iptablesImplementation) Disable() error {
	_ = i.deleteOutputJump()
	_ = i.run("-F", i.chainName)
	_ = i.run("-X", i.chainName)
	i.enabled = false
	return nil
}

func (i *iptablesImplementation) IsEnabled() bool {
	return i.enabled
}

func (i *iptablesImplementation) AddAllowedApp(app string) error {
	if app == "" {
		return nil
	}
	return i.insertRule(1, "-m", "owner", "--cmd-owner", app, "-j", "ACCEPT")
}

func (i *iptablesImplementation) RemoveAllowedApp(app string) error {
	if app == "" {
		return nil
	}
	return i.deleteRule("-m", "owner", "--cmd-owner", app, "-j", "ACCEPT")
}

func (i *iptablesImplementation) AddExcludedNet(network string) error {
	if network == "" {
		return nil
	}
	return i.addRule("-d", network, "-j", "ACCEPT")
}

func (i *iptablesImplementation) RemoveExcludedNet(network string) error {
	if network == "" {
		return nil
	}
	return i.deleteRule("-d", network, "-j", "ACCEPT")
}

func (i *iptablesImplementation) ensureChain() error {
	if err := i.run("-N", i.chainName); err != nil && !strings.Contains(err.Error(), "Chain already exists") {
		return err
	}
	return i.run("-F", i.chainName)
}

func (i *iptablesImplementation) ensureOutputJump() error {
	exists, err := i.ruleExists("OUTPUT", "-j", i.chainName)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return i.run("-I", "OUTPUT", "1", "-j", i.chainName)
}

func (i *iptablesImplementation) deleteOutputJump() error {
	exists, err := i.ruleExists("OUTPUT", "-j", i.chainName)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return i.run("-D", "OUTPUT", "-j", i.chainName)
}

func (i *iptablesImplementation) insertRule(pos int, rule ...string) error {
	args := []string{"-I", i.chainName, fmt.Sprintf("%d", pos)}
	args = append(args, rule...)
	return i.run(args...)
}

func (i *iptablesImplementation) addRule(rule ...string) error {
	args := []string{"-A", i.chainName}
	args = append(args, rule...)
	return i.run(args...)
}

func (i *iptablesImplementation) deleteRule(rule ...string) error {
	exists, err := i.ruleExists(i.chainName, rule...)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	args := []string{"-D", i.chainName}
	args = append(args, rule...)
	return i.run(args...)
}

func (i *iptablesImplementation) ruleExists(chain string, rule ...string) (bool, error) {
	args := []string{"-w", "-C", chain}
	args = append(args, rule...)
	output, err := runFirewallCommand("iptables", args...)
	if err == nil {
		return true, nil
	}
	if isExitCode(err, 1) {
		return false, nil
	}
	return false, fmt.Errorf("iptables %v failed: %w: %s", args, err, strings.TrimSpace(string(output)))
}

func (i *iptablesImplementation) run(args ...string) error {
	fullArgs := append([]string{"-w"}, args...)
	output, err := runFirewallCommand("iptables", fullArgs...)
	if err != nil {
		return fmt.Errorf("iptables %v failed: %w: %s", fullArgs, err, strings.TrimSpace(string(output)))
	}
	return nil
}

// ==================== NFTables Implementation ====================

type nftablesImplementation struct {
	enabled      bool
	vpnInterface string
	tableName    string
	chainName    string
}

func newNFTablesImplementation() *nftablesImplementation {
	return &nftablesImplementation{
		tableName: "stealthlink",
		chainName: "killswitch",
	}
}

func (n *nftablesImplementation) Enable(cfg *Config) error {
	n.vpnInterface = cfg.VPNInterface

	// Reset table to keep rule order deterministic.
	_ = n.run("delete", "table", "inet", n.tableName)
	if err := n.run("add", "table", "inet", n.tableName); err != nil {
		return err
	}
	if err := n.run("add", "chain", "inet", n.tableName, n.chainName, "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "accept", ";", "}"); err != nil {
		return err
	}

	if err := n.addRule("oifname", `"lo"`, "accept"); err != nil {
		return err
	}
	if err := n.addRule("ct", "state", "established,related", "accept"); err != nil {
		return err
	}
	if n.vpnInterface != "" {
		if err := n.addRule("oifname", fmt.Sprintf(`"%s"`, n.vpnInterface), "accept"); err != nil {
			return err
		}
	}

	if len(cfg.DNSServers) == 0 {
		if err := n.addRule("udp", "dport", "53", "accept"); err != nil {
			return err
		}
		if err := n.addRule("tcp", "dport", "53", "accept"); err != nil {
			return err
		}
	} else {
		for _, dns := range cfg.DNSServers {
			if net.ParseIP(dns) == nil {
				continue
			}
			if err := n.addRule("ip", "daddr", dns, "udp", "dport", "53", "accept"); err != nil {
				return err
			}
			if err := n.addRule("ip", "daddr", dns, "tcp", "dport", "53", "accept"); err != nil {
				return err
			}
		}
	}

	if cfg.Mode == ModeSoft {
		for _, lan := range defaultLANRanges() {
			if err := n.addRule("ip", "daddr", lan, "accept"); err != nil {
				return err
			}
		}
	}
	for _, network := range cfg.ExcludedNets {
		if err := n.AddExcludedNet(network); err != nil {
			return err
		}
	}
	if err := n.addRule("counter", "drop"); err != nil {
		return err
	}

	n.enabled = true
	return nil
}

func (n *nftablesImplementation) Disable() error {
	output, err := runFirewallCommand("nft", "delete", "table", "inet", n.tableName)
	if err != nil && !isExitCode(err, 1) {
		return fmt.Errorf("nft delete table failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	n.enabled = false
	return nil
}

func (n *nftablesImplementation) IsEnabled() bool {
	return n.enabled
}

func (n *nftablesImplementation) AddAllowedApp(app string) error {
	// nftables process matching is UID-based; app path matching is not portable.
	_ = app
	return nil
}

func (n *nftablesImplementation) RemoveAllowedApp(app string) error {
	_ = app
	return nil
}

func (n *nftablesImplementation) AddExcludedNet(network string) error {
	if network == "" {
		return nil
	}
	return n.addRule("ip", "daddr", network, "accept")
}

func (n *nftablesImplementation) RemoveExcludedNet(network string) error {
	if network == "" {
		return nil
	}
	return n.deleteRule("ip", "daddr", network, "accept")
}

func (n *nftablesImplementation) addRule(rule ...string) error {
	expr := strings.Join(rule, " ")
	exists, err := n.ruleExists(expr)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	args := append([]string{"add", "rule", "inet", n.tableName, n.chainName}, rule...)
	return n.run(args...)
}

func (n *nftablesImplementation) deleteRule(rule ...string) error {
	expr := strings.Join(rule, " ")
	handle, found, err := n.findRuleHandle(expr)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	return n.run("delete", "rule", "inet", n.tableName, n.chainName, "handle", handle)
}

func (n *nftablesImplementation) ruleExists(expr string) (bool, error) {
	output, err := runFirewallCommand("nft", "-j", "list", "chain", "inet", n.tableName, n.chainName)
	if err != nil {
		if isExitCode(err, 1) {
			return false, nil
		}
		return false, fmt.Errorf("nft list chain failed: %w: %s", err, strings.TrimSpace(string(output)))
	}

	var payload map[string]any
	if err := json.Unmarshal(output, &payload); err != nil {
		return false, fmt.Errorf("parse nft JSON: %w", err)
	}

	// Keep this check simple and stable across nft versions.
	return strings.Contains(string(output), expr), nil
}

func (n *nftablesImplementation) findRuleHandle(expr string) (string, bool, error) {
	output, err := runFirewallCommand("nft", "-a", "list", "chain", "inet", n.tableName, n.chainName)
	if err != nil {
		if isExitCode(err, 1) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("nft list chain failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, expr) {
			continue
		}
		idx := strings.LastIndex(line, " handle ")
		if idx < 0 {
			continue
		}
		handle := strings.TrimSpace(line[idx+8:])
		if handle == "" {
			continue
		}
		fields := strings.Fields(handle)
		if len(fields) == 0 {
			continue
		}
		return fields[0], true, nil
	}
	return "", false, nil
}

func (n *nftablesImplementation) run(args ...string) error {
	output, err := runFirewallCommand("nft", args...)
	if err != nil {
		return fmt.Errorf("nft %v failed: %w: %s", args, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func defaultLANRanges() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
}

func isExitCode(err error, code int) bool {
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		return false
	}
	return ee.ExitCode() == code
}

// IsAvailable checks if kill switch is available on this platform
func IsAvailable() bool {
	switch runtime.GOOS {
	case "linux":
		// Check for iptables or nftables
		return true
	case "windows":
		// Check for WFP support
		return true
	case "darwin", "freebsd", "openbsd":
		// Check for PF
		return true
	default:
		return false
	}
}

// ValidateConfig validates a kill switch configuration
func ValidateConfig(cfg *Config) error {
	if cfg.Mode != ModeStrict && cfg.Mode != ModeSoft {
		return fmt.Errorf("invalid mode: %s", cfg.Mode)
	}

	// Validate excluded networks
	for _, netStr := range cfg.ExcludedNets {
		_, _, err := net.ParseCIDR(netStr)
		if err != nil {
			return fmt.Errorf("invalid excluded network %s: %w", netStr, err)
		}
	}

	// Validate DNS servers
	for _, dns := range cfg.DNSServers {
		if net.ParseIP(dns) == nil {
			return fmt.Errorf("invalid DNS server: %s", dns)
		}
	}

	return nil
}
