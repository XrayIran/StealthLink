//go:build linux
// +build linux

package tproxy

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestIPTablesBackendE2ECommandFlow(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "cmd.log")
	writeFakeCommand(t, tmp, "ip", logPath)
	writeFakeCommand(t, tmp, "iptables", logPath)
	t.Setenv("PATH", tmp+":"+os.Getenv("PATH"))

	const (
		port = 15001
		mark = 1
	)
	if err := SetupIPTables(port, mark); err != nil {
		t.Fatalf("SetupIPTables failed: %v", err)
	}
	if err := CleanupIPTables(port, mark); err != nil {
		t.Fatalf("CleanupIPTables failed: %v", err)
	}

	lines := readCommandLog(t, logPath)
	assertContainsInOrder(t, lines, []string{
		"ip rule add fwmark 1 lookup 100",
		"ip route add local 0.0.0.0/0 dev lo table 100",
		"iptables -t mangle -A PREROUTING -p tcp -j TPROXY --tproxy-mark 1 --on-port 15001",
		"iptables -t mangle -D PREROUTING -p tcp -j TPROXY --tproxy-mark 1 --on-port 15001",
	})
}

func TestNFTablesBackendE2ECommandFlow(t *testing.T) {
	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "cmd.log")
	writeFakeCommand(t, tmp, "ip", logPath)
	writeFakeCommand(t, tmp, "nft", logPath)
	t.Setenv("PATH", tmp+":"+os.Getenv("PATH"))

	const (
		port = 15001
		mark = 1
	)
	b := NewBackend(true, mark)
	if err := b.Setup(port); err != nil {
		t.Fatalf("backend setup failed: %v", err)
	}
	if err := b.Cleanup(port); err != nil {
		t.Fatalf("backend cleanup failed: %v", err)
	}

	lines := readCommandLog(t, logPath)
	assertContainsInOrder(t, lines, []string{
		"nft add table ip stealthlink",
		"nft add chain ip stealthlink prerouting { type filter hook prerouting priority mangle; policy accept; }",
		"nft add rule ip stealthlink prerouting meta l4proto tcp tproxy to :15001 meta mark set 1",
		"ip rule add fwmark 1 lookup 100",
		"ip route add local 0.0.0.0/0 dev lo table 100",
		"nft delete table ip stealthlink",
		"ip rule del fwmark 1 lookup 100",
	})
}

func TestTCPAddrFromRawSockaddr(t *testing.T) {
	raw := syscall.RawSockaddrInet4{
		Port: 0x901f, // 8080 in network byte order on little-endian hosts.
		Addr: [4]byte{203, 0, 113, 10},
	}
	got := tcpAddrFromRawSockaddr(raw)
	if got.String() != "203.0.113.10:8080" {
		t.Fatalf("unexpected parsed address: %s", got.String())
	}
}

func TestGetOriginalDstRejectsNonTCPConn(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	_, err := GetOriginalDst(c1)
	if err == nil || !strings.Contains(err.Error(), "not a TCP connection") {
		t.Fatalf("expected non-TCP error, got: %v", err)
	}
}

func writeFakeCommand(t *testing.T, dir, name, logPath string) {
	t.Helper()
	script := "#!/bin/sh\n" +
		"echo \"" + name + " $*\" >> \"" + logPath + "\"\n"
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake command %s: %v", name, err)
	}
}

func readCommandLog(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func assertContainsInOrder(t *testing.T, lines []string, want []string) {
	t.Helper()
	start := 0
	for _, w := range want {
		found := false
		for i := start; i < len(lines); i++ {
			if strings.Contains(lines[i], w) {
				start = i + 1
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing command %q; got log: %v", w, lines)
		}
	}
}
