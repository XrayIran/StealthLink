package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStealthlinkCtlInstallModeForBundleDefaultsOffline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("bash install harness test targets linux")
	}

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	repoRoot := filepath.Clean(filepath.Join(wd, "..", ".."))
	scriptPath := filepath.Join(repoRoot, "scripts", "stealthlink-ctl")

	cases := []struct {
		name              string
		args              []string
		wantSkippedCalls  []string
		wantExecutedCalls []string
	}{
		{
			name:             "bundle defaults offline",
			args:             []string{"--bundle=/tmp/fake.zip", "--role=gateway"},
			wantSkippedCalls: []string{"install_deps", "install_phase5_tooling"},
			wantExecutedCalls: []string{
				"install_download_binary",
				"install_sync_local_assets",
				"install_setup_config",
			},
		},
		{
			name: "bundle online override",
			args: []string{"--bundle=/tmp/fake.zip", "--role=agent", "--online"},
			wantExecutedCalls: []string{
				"install_deps",
				"install_download_binary",
				"install_phase5_tooling",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			traceFile := filepath.Join(t.TempDir(), "trace.log")
			callArgs := strings.Join(tc.args, " ")
			harness := fmt.Sprintf(`set -euo pipefail
export STEALTHLINK_CTL_SOURCE_ONLY=1
source %q
TRACE_FILE=%q
record() { echo "$1" >> "$TRACE_FILE"; }
require_root() { :; }
detect_os() { :; }
detect_arch() { :; }
install_detect_network() { :; }
install_deps() { record install_deps; }
install_download_binary() { record install_download_binary; }
install_sync_local_assets() { record install_sync_local_assets; }
install_setup_config() { record install_setup_config; }
install_phase5_tooling() { record install_phase5_tooling; }
install_setup_service() { record install_setup_service; }
install_setup_capabilities() { record install_setup_capabilities; }
install_deploy_dashboard() { record install_deploy_dashboard; }
install_setup_logrotate() { record install_setup_logrotate; }
install_print_success() { record install_print_success; }
cleanup_install_tmp() { :; }
cmd_install %s
`, scriptPath, traceFile, callArgs)

			cmd := exec.Command("bash", "-c", harness)
			cmd.Dir = repoRoot
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("install harness failed: %v\n%s", err, string(out))
			}

			traceBytes, err := os.ReadFile(traceFile)
			if err != nil {
				t.Fatalf("read trace file: %v", err)
			}
			trace := string(traceBytes)
			for _, fn := range tc.wantExecutedCalls {
				if !strings.Contains(trace, fn+"\n") {
					t.Fatalf("expected %s to run, trace:\n%s", fn, trace)
				}
			}
			for _, fn := range tc.wantSkippedCalls {
				if strings.Contains(trace, fn+"\n") {
					t.Fatalf("expected %s to be skipped, trace:\n%s", fn, trace)
				}
			}
		})
	}
}
