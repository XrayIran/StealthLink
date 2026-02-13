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

	required := []string{"stealthlink-gateway", "stealthlink-agent", "stealthlink-tools", "stealthlink-ctl"}
	for _, name := range required {
		path := filepath.Join(bundleRoot, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake binary %s: %v", name, err)
		}
	}

	zipPath := filepath.Join(tempDir, "bundle.zip")
	if err := createZipFromDir(bundleRoot, zipPath); err != nil {
		t.Fatalf("create zip: %v", err)
	}

	configDir := filepath.Join(tempDir, "opt", "stealthlink")
	binDir := filepath.Join(tempDir, "usr", "local", "bin")
	harness := fmt.Sprintf(`set -euo pipefail
export STEALTHLINK_CTL_SOURCE_ONLY=1
export STEALTHLINK_CONFIG_DIR=%q
export STEALTHLINK_BIN_DIR=%q
source %q
INSTALL_BUNDLE_PATH=%q
INSTALL_LOCAL_MODE=false
bundle_root="$(resolve_install_asset_root)"
test -n "$bundle_root"
install_binaries_from_root "$bundle_root"
cleanup_install_tmp
`, configDir, binDir, scriptPath, zipPath)

	cmd := exec.Command("bash", "-c", harness)
	cmd.Dir = repoRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bundle lifecycle harness failed: %v\n%s", err, string(out))
	}

	for _, name := range required {
		if _, err := os.Stat(filepath.Join(configDir, name)); err != nil {
			t.Fatalf("expected installed file missing (%s): %v", name, err)
		}
		linkPath := filepath.Join(binDir, name)
		target, err := os.Readlink(linkPath)
		if err != nil {
			t.Fatalf("expected symlink missing (%s): %v", name, err)
		}
		if target != filepath.Join(configDir, name) {
			t.Fatalf("unexpected symlink target for %s: %s", name, target)
		}
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
	return nil
}
