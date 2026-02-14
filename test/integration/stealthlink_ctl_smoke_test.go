package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStealthlinkCtlHelpSmoke(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("stealthlink-ctl helper targets linux ops in this repo")
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	scriptPath := filepath.Join(repoRoot, "scripts", "stealthlink-ctl")

	cmd := exec.Command("bash", "-c", scriptPath+" --help")
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("help failed: %v\n%s", err, string(out))
	}
	s := string(out)
	for _, want := range []string{
		"stealthlink-ctl v",
		"stealthlink-ctl install",
		"stealthlink-ctl wizard",
		"stealthlink-ctl validate",
		"stealthlink-ctl service",
		"stealthlink-ctl firewall",
		"stealthlink-ctl uninstall",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("expected help to contain %q, got:\n%s", want, s)
		}
	}
}
