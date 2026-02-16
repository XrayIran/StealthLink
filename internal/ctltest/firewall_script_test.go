package ctltest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// UPSTREAM_WIRING: paqctl

func TestStealthlinkCtlFirewallRawHardeningRulesPresent(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	p := filepath.Join(root, "scripts", "stealthlink-ctl")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	s := string(b)

	// iptables raw NOTRACK for inbound and RST drop for outbound.
	mustContain(t, s, `iptables -t raw -I PREROUTING -p tcp --dport "${port}" -j CT --notrack`)
	mustContain(t, s, `iptables -I OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP`)
	mustContain(t, s, `iptables -t raw -D PREROUTING -p tcp --dport "${port}" -j CT --notrack`)
	mustContain(t, s, `iptables -D OUTPUT -p tcp --sport "${port}" --tcp-flags RST RST -j DROP`)

	// nftables equivalents.
	mustContain(t, s, `nft add rule ip stealthlink_raw prerouting tcp dport "${port}" notrack`)
	mustContain(t, s, `nft add rule ip stealthlink_raw output tcp sport "${port}" tcp flags rst / rst drop`)
	mustContain(t, s, `nft delete rule ip stealthlink_raw prerouting tcp dport "${port}" notrack`)
	mustContain(t, s, `nft delete rule ip stealthlink_raw output tcp sport "${port}" tcp flags rst / rst drop`)

	// State is per-role so gateway+agent installs don't overwrite each other.
	mustContain(t, s, `firewall_state_file(){ local role="$1"; echo "${FIREWALL_STATE_DIR}/${role}.json"; }`)

	// Apply is idempotent: checks exist before inserting.
	mustContain(t, s, `iptables -C INPUT -p tcp --dport "${port}" -j ACCEPT`)
	mustContain(t, s, `iptables -t raw -C PREROUTING -p tcp --dport "${port}" -j CT --notrack`)
	mustContain(t, s, `nft list chain ip stealthlink_raw prerouting | grep -q "tcp dport ${port} notrack"`)
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Fatalf("expected stealthlink-ctl to contain %q", needle)
	}
}
