package integration

import (
	"archive/zip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStealthlinkCtlBundleZipLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("stealthlink-ctl integration test targets Linux install layout")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	scriptPath := filepath.Join(repoRoot, "scripts", "stealthlink-ctl")

	tempDir := t.TempDir()
	bundleRoot := filepath.Join(tempDir, "bundle")
	if err := os.MkdirAll(bundleRoot, 0o755); err != nil {
		t.Fatalf("mkdir bundle root: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(bundleRoot, "systemd"), 0o755); err != nil {
		t.Fatalf("mkdir systemd: %v", err)
	}

	required := []string{"stealthlink-gateway", "stealthlink-agent", "stealthlink-tools", "stealthlink", "stealthlink-ctl"}
	for _, name := range required {
		path := filepath.Join(bundleRoot, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake binary %s: %v", name, err)
		}
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "systemd", "stealthlink-gateway.service"), []byte("[Unit]\nDescription=fake\n"), 0o644); err != nil {
		t.Fatalf("write fake unit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundleRoot, "systemd", "stealthlink-agent.service"), []byte("[Unit]\nDescription=fake\n"), 0o644); err != nil {
		t.Fatalf("write fake unit: %v", err)
	}

	zipPath := filepath.Join(tempDir, "bundle.zip")
	if err := createZipFromDir(bundleRoot, zipPath); err != nil {
		t.Fatalf("create zip: %v", err)
	}

	harness := fmt.Sprintf(`set -euo pipefail
set -x
export STEALTHLINK_CTL_SOURCE_ONLY=1
source %q
bundle_resolve_root %q
root="$BUNDLE_ROOT"
test -n "$root"
test -f "$root/stealthlink-gateway"
test -f "$root/stealthlink-agent"
test -f "$root/stealthlink-tools"
test -f "$root/stealthlink"
test -f "$root/stealthlink-ctl"
test -f "$root/systemd/stealthlink-gateway.service"
test -f "$root/systemd/stealthlink-agent.service"
echo "$root"
`, scriptPath, zipPath)

	cmd := exec.Command("bash", "-c", harness)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bundle lifecycle harness failed: %v\n%s", err, string(out))
	}
	if len(out) == 0 {
		t.Fatalf("expected bundle root output")
	}
}

func createZipFromDir(srcDir, zipPath string) error {
	file, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer file.Close()

	w := zip.NewWriter(file)
	defer w.Close()

	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		src := filepath.Join(srcDir, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		f, err := w.Create(name)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
	}
	// Include systemd dir entries (this helper expects them).
	sysd := filepath.Join(srcDir, "systemd")
	sysEntries, err := os.ReadDir(sysd)
	if err != nil {
		return err
	}
	for _, entry := range sysEntries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		src := filepath.Join(sysd, name)
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		f, err := w.Create(filepath.Join("systemd", name))
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
	}
	return nil
}
