//go:build !linux || (linux && !netlink)

package vpn

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// SetupInterface configures the network interface using system commands.
func SetupInterface(cfg NetworkConfig) error {
	switch runtime.GOOS {
	case "linux":
		return setupInterfaceLinux(cfg)
	case "darwin":
		return setupInterfaceDarwin(cfg)
	case "windows":
		return setupInterfaceWindows(cfg)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// setupInterfaceLinux configures the interface on Linux using ip command.
func setupInterfaceLinux(cfg NetworkConfig) error {
	// Add IP address (honor point-to-point peer semantics when PeerIP is set).
	localIP, ipNet, err := net.ParseCIDR(cfg.InterfaceIP)
	if err != nil {
		return fmt.Errorf("invalid interface IP: %w", err)
	}
	ones, _ := ipNet.Mask.Size()
	addr := fmt.Sprintf("%s/%d", localIP.String(), ones)

	args := []string{"addr", "add", addr}
	if cfg.PeerIP != "" {
		peer := net.ParseIP(strings.TrimSpace(cfg.PeerIP))
		if peer == nil {
			return fmt.Errorf("invalid peer_ip: %q", cfg.PeerIP)
		}
		args = append(args, "peer", peer.String())
	}
	args = append(args, "dev", cfg.InterfaceName)

	if localIP.To4() == nil {
		args = append([]string{"-6"}, args...)
	}
	cmd := exec.Command("ip", args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		// Address might already exist, ignore that error
		if !strings.Contains(string(out), "File exists") {
			return fmt.Errorf("ip addr add failed: %v: %s", err, out)
		}
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", cfg.InterfaceName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up failed: %v: %s", err, out)
	}

	// Set MTU if specified
	if cfg.MTU > 0 {
		cmd = exec.Command("ip", "link", "set", "dev", cfg.InterfaceName, "mtu", fmt.Sprintf("%d", cfg.MTU))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ip link set mtu failed: %v: %s", err, out)
		}
	}

	// Add routes
	for _, route := range cfg.Routes {
		_, dstNet, err := net.ParseCIDR(route.Destination)
		if err != nil || dstNet == nil {
			return fmt.Errorf("invalid route destination: %q", route.Destination)
		}
		args := []string{"route", "add", route.Destination, "dev", cfg.InterfaceName}
		if route.Gateway != "" {
			args = append(args, "via", route.Gateway)
		}
		if route.Metric > 0 {
			args = append(args, "metric", fmt.Sprintf("%d", route.Metric))
		}

		if dstNet.IP.To4() == nil {
			args = append([]string{"-6"}, args...)
		}
		cmd = exec.Command("ip", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Route might already exist
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("ip route add failed: %v: %s", err, out)
			}
		}
	}

	return nil
}

// setupInterfaceDarwin configures the interface on macOS.
func setupInterfaceDarwin(cfg NetworkConfig) error {
	// Add IP address
	cmd := exec.Command("ifconfig", cfg.InterfaceName, "inet", strings.Split(cfg.InterfaceIP, "/")[0], cfg.PeerIP)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig failed: %v: %s", err, out)
	}

	// Bring interface up
	cmd = exec.Command("ifconfig", cfg.InterfaceName, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ifconfig up failed: %v: %s", err, out)
	}

	// Set MTU if specified
	if cfg.MTU > 0 {
		cmd = exec.Command("ifconfig", cfg.InterfaceName, "mtu", fmt.Sprintf("%d", cfg.MTU))
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("ifconfig mtu failed: %v: %s", err, out)
		}
	}

	// Add routes
	for _, route := range cfg.Routes {
		args := []string{"add", "-net", route.Destination, "-interface", cfg.InterfaceName}
		if route.Gateway != "" {
			args = []string{"add", "-net", route.Destination, route.Gateway}
		}

		cmd = exec.Command("route", args...)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Route might already exist
			if !strings.Contains(string(out), "File exists") {
				return fmt.Errorf("route add failed: %v: %s", err, out)
			}
		}
	}

	return nil
}

// setupInterfaceWindows configures the interface on Windows.
func setupInterfaceWindows(cfg NetworkConfig) error {
	// Windows requires different approach, typically using netsh or WinAPI
	// This is a placeholder implementation

	// Set IP address
	ip := strings.Split(cfg.InterfaceIP, "/")[0]
	mask := "255.255.255.0" // Default, should calculate from CIDR

	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name=\""+cfg.InterfaceName+"\"", "static", ip, mask)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address failed: %v: %s", err, out)
	}

	// Add routes
	for _, route := range cfg.Routes {
		cmd = exec.Command("route", "add", route.Destination, "MASK", "255.255.255.0",
			cfg.PeerIP, "IF", cfg.InterfaceName)
		if out, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "already exists") {
				return fmt.Errorf("route add failed: %v: %s", err, out)
			}
		}
	}

	return nil
}

// RemoveInterface removes network configuration from an interface.
func RemoveInterface(cfg NetworkConfig) error {
	switch runtime.GOOS {
	case "linux":
		return removeInterfaceLinux(cfg)
	case "darwin":
		return removeInterfaceDarwin(cfg)
	case "windows":
		return removeInterfaceWindows(cfg)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

// removeInterfaceLinux removes configuration on Linux.
func removeInterfaceLinux(cfg NetworkConfig) error {
	// Remove routes first (best-effort).
	for _, route := range cfg.Routes {
		_, dstNet, err := net.ParseCIDR(route.Destination)
		if err != nil || dstNet == nil {
			continue
		}
		args := []string{"route", "del", route.Destination, "dev", cfg.InterfaceName}
		if dstNet.IP.To4() == nil {
			args = append([]string{"-6"}, args...)
		}
		_ = exec.Command("ip", args...).Run()
	}

	// Remove address (best-effort, idempotent).
	localIP, ipNet, err := net.ParseCIDR(cfg.InterfaceIP)
	if err == nil && ipNet != nil {
		ones, _ := ipNet.Mask.Size()
		addr := fmt.Sprintf("%s/%d", localIP.String(), ones)
		args := []string{"addr", "del", addr}
		if cfg.PeerIP != "" {
			peer := net.ParseIP(strings.TrimSpace(cfg.PeerIP))
			if peer != nil {
				args = append(args, "peer", peer.String())
			}
		}
		args = append(args, "dev", cfg.InterfaceName)
		if localIP.To4() == nil {
			args = append([]string{"-6"}, args...)
		}
		_ = exec.Command("ip", args...).Run()
	}

	// Bring interface down last.
	_ = exec.Command("ip", "link", "set", "dev", cfg.InterfaceName, "down").Run()

	return nil
}

// removeInterfaceDarwin removes configuration on macOS.
func removeInterfaceDarwin(cfg NetworkConfig) error {
	cmd := exec.Command("ifconfig", cfg.InterfaceName, "down")
	_ = cmd.Run()
	return nil
}

// removeInterfaceWindows removes configuration on Windows.
func removeInterfaceWindows(cfg NetworkConfig) error {
	// Windows TUN interfaces are typically cleaned up on process exit
	return nil
}
