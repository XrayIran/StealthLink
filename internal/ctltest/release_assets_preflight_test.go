package ctltest

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestReleaseAssetsPreflightAcceptsPolicyShape(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "stealthlink-linux-amd64-v2.0.0.zip"), "zip")
	mustWrite(t, filepath.Join(dir, "stealthlink-ctl"), "#!/usr/bin/env bash\n")
	mustWrite(t, filepath.Join(dir, "SHA256SUMS"), "deadbeef  stealthlink-linux-amd64-v2.0.0.zip\nfeedface  stealthlink-ctl\n")

	if out, err := runPreflight(dir); err != nil {
		t.Fatalf("preflight should pass, err=%v out=%s", err, out)
	}
}

func TestReleaseAssetsPreflightRejectsUnexpectedFile(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "stealthlink-linux-amd64-v2.0.0.zip"), "zip")
	mustWrite(t, filepath.Join(dir, "stealthlink-ctl"), "#!/usr/bin/env bash\n")
	mustWrite(t, filepath.Join(dir, "SHA256SUMS"), "deadbeef  stealthlink-linux-amd64-v2.0.0.zip\nfeedface  stealthlink-ctl\n")
	mustWrite(t, filepath.Join(dir, "notes.txt"), "nope")

	if out, err := runPreflight(dir); err == nil {
		t.Fatalf("preflight should fail when extra file exists, out=%s", out)
	}
}

func TestReleaseAssetsPreflightRejectsBadChecksumReference(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "stealthlink-linux-amd64-v2.0.0.zip"), "zip")
	mustWrite(t, filepath.Join(dir, "stealthlink-ctl"), "#!/usr/bin/env bash\n")
	mustWrite(t, filepath.Join(dir, "SHA256SUMS"), "deadbeef  payload.tar.gz\n")

	if out, err := runPreflight(dir); err == nil {
		t.Fatalf("preflight should fail for disallowed SHA entry, out=%s", out)
	}
}

func runPreflight(assetsDir string) (string, error) {
	root := filepath.Clean(filepath.Join("..", ".."))
	script := filepath.Join(root, "scripts", "release-assets-preflight.sh")
	cmd := exec.Command(script, "--assets-dir", assetsDir)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func mustWrite(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
