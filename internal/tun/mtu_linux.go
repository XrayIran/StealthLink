//go:build linux

package tun

import (
	"fmt"
	"os/exec"
)

func setMTU(name string, mtu int) error {
	if mtu <= 0 {
		return nil
	}
	cmd := exec.Command("ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu))
	return cmd.Run()
}

func getInterfaceMTU(name string) (int, error) {
	// Use ip command to get MTU
	cmd := exec.Command("ip", "link", "show", name)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("get MTU: %w", err)
	}
	// Parse output to find MTU
	// Format: ... mtu 1500 ...
	var mtu int
	_, err = fmt.Sscanf(string(out), "%*s mtu %d", &mtu)
	if err != nil {
		return 1500, nil // Default if parsing fails
	}
	return mtu, nil
}
