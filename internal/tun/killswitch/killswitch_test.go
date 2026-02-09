package killswitch

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestIPTablesEnableBuildsExpectedRules(t *testing.T) {
	origRun := runFirewallCommand
	defer func() { runFirewallCommand = origRun }()

	exit1 := makeExitError(t, 1)
	var calls []string
	runFirewallCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "iptables" && len(args) > 2 && args[1] == "-C" {
			return nil, exit1
		}
		return nil, nil
	}

	impl := newIPTablesImplementation()
	cfg := &Config{
		Mode:         ModeSoft,
		VPNInterface: "tun0",
		DNSServers:   []string{"1.1.1.1"},
		ExcludedNets: []string{"100.64.0.0/10"},
	}
	if err := impl.Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	assertHasCall(t, calls, "iptables -w -N STEALTHLINK_KILLSWITCH")
	assertHasCall(t, calls, "iptables -w -I OUTPUT 1 -j STEALTHLINK_KILLSWITCH")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -o lo -j ACCEPT")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -o tun0 -j ACCEPT")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -p udp -d 1.1.1.1 --dport 53 -j ACCEPT")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -d 192.168.0.0/16 -j ACCEPT")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -d 100.64.0.0/10 -j ACCEPT")
	assertHasCall(t, calls, "iptables -w -A STEALTHLINK_KILLSWITCH -j DROP")
}

func TestIPTablesDisableRemovesRules(t *testing.T) {
	origRun := runFirewallCommand
	defer func() { runFirewallCommand = origRun }()

	var calls []string
	runFirewallCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}

	impl := newIPTablesImplementation()
	impl.enabled = true
	if err := impl.Disable(); err != nil {
		t.Fatalf("Disable failed: %v", err)
	}

	assertHasCall(t, calls, "iptables -w -D OUTPUT -j STEALTHLINK_KILLSWITCH")
	assertHasCall(t, calls, "iptables -w -F STEALTHLINK_KILLSWITCH")
	assertHasCall(t, calls, "iptables -w -X STEALTHLINK_KILLSWITCH")
}

func TestNFTablesEnableUsesJSONChecks(t *testing.T) {
	origRun := runFirewallCommand
	defer func() { runFirewallCommand = origRun }()

	var calls []string
	runFirewallCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name == "nft" && len(args) >= 2 && args[0] == "-j" {
			return []byte(`{"nftables":[]}`), nil
		}
		if name == "nft" && len(args) >= 1 && args[0] == "-a" {
			return []byte(""), nil
		}
		return nil, nil
	}

	impl := newNFTablesImplementation()
	cfg := &Config{
		Mode:         ModeSoft,
		VPNInterface: "tun0",
		DNSServers:   []string{"1.1.1.1"},
		ExcludedNets: []string{"10.10.0.0/16"},
	}
	if err := impl.Enable(cfg); err != nil {
		t.Fatalf("Enable failed: %v", err)
	}

	foundJSONCheck := false
	for _, c := range calls {
		if strings.Contains(c, "nft -j list chain inet stealthlink killswitch") {
			foundJSONCheck = true
			break
		}
	}
	if !foundJSONCheck {
		t.Fatalf("expected nft JSON list checks, calls=%v", calls)
	}
}

func TestPlatformAutoPrefersNFTablesOnLinux(t *testing.T) {
	orig := lookPath
	defer func() { lookPath = orig }()

	lookPath = func(file string) (string, error) {
		switch file {
		case "nft":
			return "/usr/sbin/nft", nil
		case "iptables":
			return "/usr/sbin/iptables", nil
		default:
			return "", fmt.Errorf("not found")
		}
	}

	if got := PlatformAuto(); got != PlatformNFTables {
		t.Fatalf("PlatformAuto=%s want=%s", got, PlatformNFTables)
	}
}

func assertHasCall(t *testing.T, calls []string, want string) {
	t.Helper()
	for _, call := range calls {
		if call == want {
			return
		}
	}
	t.Fatalf("missing call %q\ncalls:\n%s", want, strings.Join(calls, "\n"))
}

func makeExitError(t *testing.T, code int) error {
	t.Helper()
	cmd := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code))
	err := cmd.Run()
	if err == nil {
		t.Fatalf("expected non-nil error for exit code %d", code)
	}
	return err
}
