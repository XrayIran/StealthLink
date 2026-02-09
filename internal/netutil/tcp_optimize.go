// Package netutil provides network optimization utilities.
package netutil

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"stealthlink/internal/config"
)

// ApplyTCPOptimizations applies TCP optimization settings to a connection.
func ApplyTCPOptimizations(conn net.Conn, cfg config.TCPOptimizationConfig) error {
	if !cfg.Enabled {
		return nil
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil // Not a TCP connection
	}

	file, err := tcpConn.File()
	if err != nil {
		return fmt.Errorf("get underlying fd: %w", err)
	}
	defer file.Close()

	fd := int(file.Fd())

	// Apply NoDelay (disable Nagle's algorithm)
	if cfg.NoDelay {
		if err := tcpConn.SetNoDelay(true); err != nil {
			return fmt.Errorf("set no delay: %w", err)
		}
	}

	// Apply buffer sizes
	if cfg.ReadBufferSize > 0 {
		if err := tcpConn.SetReadBuffer(cfg.ReadBufferSize); err != nil {
			return fmt.Errorf("set read buffer: %w", err)
		}
	}
	if cfg.WriteBufferSize > 0 {
		if err := tcpConn.SetWriteBuffer(cfg.WriteBufferSize); err != nil {
			return fmt.Errorf("set write buffer: %w", err)
		}
	}

	// Apply keepalive settings
	if cfg.KeepAlive {
		if err := tcpConn.SetKeepAlive(true); err != nil {
			return fmt.Errorf("set keepalive: %w", err)
		}
		if cfg.KeepAliveIdle > 0 {
			if err := setKeepAliveIdle(fd, cfg.KeepAliveIdle); err != nil {
				return fmt.Errorf("set keepalive idle: %w", err)
			}
		}
		if cfg.KeepAliveInterval > 0 {
			if err := setKeepAliveInterval(fd, cfg.KeepAliveInterval); err != nil {
				return fmt.Errorf("set keepalive interval: %w", err)
			}
		}
	}

	// Platform-specific optimizations
	if err := applyPlatformSpecific(fd, cfg); err != nil {
		return fmt.Errorf("platform-specific optimizations: %w", err)
	}

	return nil
}

// SetCongestionAlgorithm sets the TCP congestion control algorithm.
func SetCongestionAlgorithm(conn net.Conn, algorithm string) error {
	if algorithm == "" {
		return nil
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil
	}

	file, err := tcpConn.File()
	if err != nil {
		return err
	}
	defer file.Close()

	return setCongestionAlgorithm(int(file.Fd()), algorithm)
}

// ApplySystemWideTCP applies system-wide TCP optimizations (requires root).
func ApplySystemWideTCP(cfg config.TCPOptimizationConfig) error {
	if !cfg.Enabled {
		return nil
	}

	if runtime.GOOS != "linux" {
		return nil // Only supported on Linux
	}

	// Set congestion control algorithm
	if cfg.CongestionAlgorithm != "" {
		if err := writeSysctl("net.ipv4.tcp_congestion_control", cfg.CongestionAlgorithm); err != nil {
			return fmt.Errorf("set congestion control: %w", err)
		}
	}

	// Enable TCP Fast Open
	if cfg.FastOpen {
		if err := writeSysctl("net.ipv4.tcp_fastopen", "3"); err != nil {
			return fmt.Errorf("enable TCP fast open: %w", err)
		}
	}

	// Enable BBR if requested
	if cfg.CongestionAlgorithm == "bbr" || cfg.CongestionAlgorithm == "bbrv3" {
		// Ensure TCP BBR is available and enable it
		if err := writeSysctl("net.ipv4.tcp_congestion_control", "bbr"); err != nil {
			return fmt.Errorf("enable BBR: %w", err)
		}
	}

	// Optimize buffer sizes
	if cfg.ReadBufferSize > 0 {
		value := strconv.Itoa(cfg.ReadBufferSize)
		if err := writeSysctl("net.core.rmem_max", value); err != nil {
			return err
		}
		if err := writeSysctl("net.ipv4.tcp_rmem", fmt.Sprintf("4096 87380 %s", value)); err != nil {
			return err
		}
	}

	if cfg.WriteBufferSize > 0 {
		value := strconv.Itoa(cfg.WriteBufferSize)
		if err := writeSysctl("net.core.wmem_max", value); err != nil {
			return err
		}
		if err := writeSysctl("net.ipv4.tcp_wmem", fmt.Sprintf("4096 65536 %s", value)); err != nil {
			return err
		}
	}

	return nil
}

// writeSysctl writes a value to a sysctl parameter.
func writeSysctl(key, value string) error {
	cmd := exec.Command("sysctl", "-w", fmt.Sprintf("%s=%s", key, value))
	return cmd.Run()
}

// Platform-specific implementations

func setKeepAliveIdle(fd, seconds int) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, seconds)
}

func setKeepAliveInterval(fd, seconds int) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, seconds)
}

func setCongestionAlgorithm(fd int, algorithm string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	// Linux-specific: TCP_CONGESTION socket option
	algoBytes := append([]byte(algorithm), 0)                                       // null-terminated
	return syscall.SetsockoptString(fd, syscall.IPPROTO_TCP, 13, string(algoBytes)) // 13 = TCP_CONGESTION
}

func applyPlatformSpecific(fd int, cfg config.TCPOptimizationConfig) error {
	if runtime.GOOS != "linux" {
		return nil
	}

	// Enable TCP_QUICKACK if requested
	if cfg.QuickAck {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1); err != nil {
			return fmt.Errorf("set quickack: %w", err)
		}
	}

	// Set congestion algorithm if specified
	if cfg.CongestionAlgorithm != "" {
		if err := setCongestionAlgorithm(fd, cfg.CongestionAlgorithm); err != nil {
			return fmt.Errorf("set congestion algorithm: %w", err)
		}
	}

	return nil
}

// GetAvailableCongestionAlgorithms returns the available congestion control algorithms.
func GetAvailableCongestionAlgorithms() ([]string, error) {
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("not supported on %s", runtime.GOOS)
	}

	data, err := exec.Command("sysctl", "-n", "net.ipv4.tcp_available_congestion_control").Output()
	if err != nil {
		return nil, err
	}

	// Parse space-separated algorithm names.
	return strings.Fields(string(data)), nil
}

// IsBBRAvailable checks if BBR congestion control is available.
func IsBBRAvailable() bool {
	algos, err := GetAvailableCongestionAlgorithms()
	if err != nil {
		return false
	}

	for _, algo := range algos {
		if algo == "bbr" {
			return true
		}
	}
	return false
}

// SysctlSnapshot stores system TCP sysctl values for rollback.
type SysctlSnapshot struct {
	Token     string            `json:"token"`
	CreatedAt time.Time         `json:"created_at"`
	Values    map[string]string `json:"values"`
}

var trackedSysctls = []string{
	"net.ipv4.tcp_congestion_control",
	"net.ipv4.tcp_fastopen",
	"net.core.rmem_max",
	"net.core.wmem_max",
	"net.ipv4.tcp_rmem",
	"net.ipv4.tcp_wmem",
}

// SnapshotSystemTCP captures current TCP sysctl settings and returns a rollback token.
func SnapshotSystemTCP() (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("snapshot unsupported on %s", runtime.GOOS)
	}
	values := make(map[string]string, len(trackedSysctls))
	for _, key := range trackedSysctls {
		out, err := exec.Command("sysctl", "-n", key).Output()
		if err != nil {
			return "", fmt.Errorf("read %s: %w", key, err)
		}
		values[key] = strings.TrimSpace(string(out))
	}
	token := fmt.Sprintf("hostopt-%d", time.Now().Unix())
	snap := SysctlSnapshot{
		Token:     token,
		CreatedAt: time.Now().UTC(),
		Values:    values,
	}
	path := snapshotFile(token)
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

// RestoreSystemTCPSnapshot restores previously snapshotted sysctl values.
func RestoreSystemTCPSnapshot(token string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("rollback unsupported on %s", runtime.GOOS)
	}
	data, err := os.ReadFile(snapshotFile(token))
	if err != nil {
		return err
	}
	var snap SysctlSnapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	for key, value := range snap.Values {
		if err := writeSysctl(key, value); err != nil {
			return fmt.Errorf("restore %s: %w", key, err)
		}
	}
	return nil
}

func snapshotFile(token string) string {
	return filepath.Join(os.TempDir(), "stealthlink-"+token+".json")
}
