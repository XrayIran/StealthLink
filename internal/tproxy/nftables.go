//go:build linux
// +build linux

package tproxy

import (
	"fmt"
	"strconv"
)

// NFTables provides nftables support for TProxy.
type NFTables struct {
	tableName string
	chainName string
	mark      int
}

// NewNFTables creates a new nftables handler.
func NewNFTables(mark int) *NFTables {
	return &NFTables{
		tableName: "stealthlink",
		chainName: "prerouting",
		mark:      mark,
	}
}

// Setup sets up nftables rules for TPROXY.
func (n *NFTables) Setup(listenPort int) error {
	// Create table
	cmd := execCommand("nft", "add", "table", "ip", n.tableName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft add table: %w", err)
	}

	// Create chain
	cmd = execCommand("nft", "add", "chain", "ip", n.tableName, n.chainName,
		"{ type filter hook prerouting priority mangle; policy accept; }")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft add chain: %w", err)
	}

	// Add TPROXY rule
	cmd = execCommand("nft", "add", "rule", "ip", n.tableName, n.chainName,
		"meta", "l4proto", "tcp",
		"tproxy", "to", ":"+strconv.Itoa(listenPort),
		"meta", "mark", "set", strconv.Itoa(n.mark))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft add rule: %w", err)
	}

	// Setup routing
	if err := n.setupRouting(); err != nil {
		return err
	}

	return nil
}

// setupRouting sets up routing for marked packets.
func (n *NFTables) setupRouting() error {
	// Add routing rule
	cmd := execCommand("ip", "rule", "add", "fwmark", strconv.Itoa(n.mark), "lookup", "100")
	_ = cmd.Run() // Ignore error if already exists

	// Add routing table
	cmd = execCommand("ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", "100")
	_ = cmd.Run() // Ignore error if already exists

	return nil
}

// Cleanup removes nftables rules.
func (n *NFTables) Cleanup(listenPort int) error {
	// Delete table (this removes all rules)
	cmd := execCommand("nft", "delete", "table", "ip", n.tableName)
	_ = cmd.Run() // Ignore error

	// Cleanup routing
	cmd = execCommand("ip", "rule", "del", "fwmark", strconv.Itoa(n.mark), "lookup", "100")
	_ = cmd.Run()

	return nil
}

// AddExcludeRule adds an exclusion rule for a CIDR.
func (n *NFTables) AddExcludeRule(cidr string) error {
	cmd := execCommand("nft", "insert", "rule", "ip", n.tableName, n.chainName,
		"ip", "daddr", cidr, "return")
	return cmd.Run()
}

// AddInterfaceRule adds a rule for a specific interface.
func (n *NFTables) AddInterfaceRule(iface string) error {
	cmd := execCommand("nft", "add", "rule", "ip", n.tableName, n.chainName,
		"iif", iface,
		"meta", "l4proto", "tcp",
		"tproxy", "to", ":"+strconv.Itoa(n.mark))
	return cmd.Run()
}

// NFTablesBackend implements a backend that supports both iptables and nftables.
type NFTablesBackend struct {
	UseNFTables bool
	Mark        int
}

// NewBackend creates a new firewall backend.
func NewBackend(useNFTables bool, mark int) *NFTablesBackend {
	return &NFTablesBackend{
		UseNFTables: useNFTables,
		Mark:        mark,
	}
}

// Setup sets up the firewall rules.
func (b *NFTablesBackend) Setup(listenPort int) error {
	if b.UseNFTables {
		nft := NewNFTables(b.Mark)
		return nft.Setup(listenPort)
	}
	return SetupIPTables(listenPort, b.Mark)
}

// Cleanup removes the firewall rules.
func (b *NFTablesBackend) Cleanup(listenPort int) error {
	if b.UseNFTables {
		nft := NewNFTables(b.Mark)
		return nft.Cleanup(listenPort)
	}
	return CleanupIPTables(listenPort, b.Mark)
}

// IsNFTablesAvailable checks if nftables is available.
func IsNFTablesAvailable() bool {
	cmd := execCommand("nft", "--version")
	return cmd.Run() == nil
}
