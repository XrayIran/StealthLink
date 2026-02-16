//go:build linux

package warp

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

type policyRoutingConfig struct {
	Mark         int
	Table        int
	RulePriority int
	IfaceName    string
	VPNSubnet    string
}

func setupPolicyRouting(cfg policyRoutingConfig) error {
	if cfg.Mark <= 0 || cfg.Mark > 0xFFFFFFFF {
		return fmt.Errorf("invalid fwmark %d (must be 1-%d)", cfg.Mark, 0xFFFFFFFF)
	}
	if cfg.Table <= 0 || cfg.Table > 0xFFFFFFFF {
		return fmt.Errorf("invalid routing table %d (must be 1-%d)", cfg.Table, 0xFFFFFFFF)
	}
	if cfg.RulePriority <= 0 || cfg.RulePriority > 32767 {
		return fmt.Errorf("invalid rule priority %d (must be 1-32767)", cfg.RulePriority)
	}

	mark := cfg.Mark
	table := cfg.Table
	priority := cfg.RulePriority
	iface := cfg.IfaceName

	_, err := exec.Command("ip", "route", "replace", "default", "dev", iface, "table", strconv.Itoa(table)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace default dev %s table %d: %w", iface, table, err)
	}

	out, err := exec.Command("ip", "rule", "list").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip rule list: %w", err)
	}
	ruleStr := fmt.Sprintf("fwmark %#x", mark)
	if strings.Contains(string(out), ruleStr) {
		_, _ = exec.Command("ip", "rule", "del", "fwmark", strconv.Itoa(mark), "table", strconv.Itoa(table), "priority", strconv.Itoa(priority)).CombinedOutput()
	}

	_, err = exec.Command("ip", "rule", "add", "fwmark", strconv.Itoa(mark), "lookup", strconv.Itoa(table), "priority", strconv.Itoa(priority)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip rule add fwmark %d lookup %d priority %d: %w", mark, table, priority, err)
	}

	if cfg.VPNSubnet != "" {
		_, err = exec.Command("ip", "route", "replace", cfg.VPNSubnet, "dev", iface, "table", strconv.Itoa(table)).CombinedOutput()
		if err != nil {
			return fmt.Errorf("ip route replace %s dev %s table %d: %w", cfg.VPNSubnet, iface, table, err)
		}
	}

	return nil
}

func teardownPolicyRouting(cfg policyRoutingConfig) error {
	var errs []error

	_, err := exec.Command("ip", "rule", "del", "fwmark", strconv.Itoa(cfg.Mark), "table", strconv.Itoa(cfg.Table), "priority", strconv.Itoa(cfg.RulePriority)).CombinedOutput()
	if err != nil {
		if !strings.Contains(err.Error(), "No such file or directory") {
			errs = append(errs, fmt.Errorf("ip rule del: %w", err))
		}
	}

	_, err = exec.Command("ip", "route", "flush", "table", strconv.Itoa(cfg.Table)).CombinedOutput()
	if err != nil {
		errs = append(errs, fmt.Errorf("ip route flush table %d: %w", cfg.Table, err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown errors: %v", errs)
	}
	return nil
}

func SetupPolicyRouting(cfg PolicyRoutingConfig) error {
	return setupPolicyRouting(policyRoutingConfig{
		Mark:         cfg.Mark,
		Table:        cfg.Table,
		RulePriority: cfg.RulePriority,
		IfaceName:    cfg.IfaceName,
		VPNSubnet:    cfg.VPNSubnet,
	})
}

func TeardownPolicyRouting(cfg PolicyRoutingConfig) error {
	return teardownPolicyRouting(policyRoutingConfig{
		Mark:         cfg.Mark,
		Table:        cfg.Table,
		RulePriority: cfg.RulePriority,
		IfaceName:    cfg.IfaceName,
		VPNSubnet:    cfg.VPNSubnet,
	})
}

func setupIPv6PolicyRouting(cfg policyRoutingConfig) error {
	if cfg.Mark <= 0 || cfg.Mark > 0xFFFFFFFF {
		return fmt.Errorf("invalid fwmark %d", cfg.Mark)
	}

	mark := cfg.Mark
	table := cfg.Table
	priority := cfg.RulePriority
	iface := cfg.IfaceName

	_, err := exec.Command("ip", "-6", "route", "replace", "default", "dev", iface, "table", strconv.Itoa(table)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -6 route replace default dev %s table %d: %w", iface, table, err)
	}

	out, err := exec.Command("ip", "-6", "rule", "list").CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -6 rule list: %w", err)
	}
	ruleStr := fmt.Sprintf("fwmark %#x", mark)
	if strings.Contains(string(out), ruleStr) {
		_, _ = exec.Command("ip", "-6", "rule", "del", "fwmark", strconv.Itoa(mark), "table", strconv.Itoa(table), "priority", strconv.Itoa(priority)).CombinedOutput()
	}

	_, err = exec.Command("ip", "-6", "rule", "add", "fwmark", strconv.Itoa(mark), "lookup", strconv.Itoa(table), "priority", strconv.Itoa(priority)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip -6 rule add fwmark %d lookup %d priority %d: %w", mark, table, priority, err)
	}

	return nil
}

func teardownIPv6PolicyRouting(cfg policyRoutingConfig) error {
	_, _ = exec.Command("ip", "-6", "rule", "del", "fwmark", strconv.Itoa(cfg.Mark), "table", strconv.Itoa(cfg.Table), "priority", strconv.Itoa(cfg.RulePriority)).CombinedOutput()
	_, _ = exec.Command("ip", "-6", "route", "flush", "table", strconv.Itoa(cfg.Table)).CombinedOutput()
	return nil
}

func checkIPCommand() error {
	_, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("ip command not found (required for WARP routing): %w", err)
	}
	return nil
}

func checkCapNetAdmin() bool {
	out, err := exec.Command("cat", "/proc/self/status").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			hexStr := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
			mask, err := strconv.ParseUint(hexStr, 16, 64)
			if err != nil {
				return false
			}
			const CAP_NET_ADMIN = 12
			return (mask & (1 << CAP_NET_ADMIN)) != 0
		}
	}
	return false
}
