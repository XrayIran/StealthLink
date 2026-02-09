//go:build darwin

package tun

import (
	"fmt"
	"os/exec"
)

func setMTU(name string, mtu int) error {
	if mtu <= 0 {
		return nil
	}
	cmd := exec.Command("ifconfig", name, "mtu", fmt.Sprintf("%d", mtu))
	return cmd.Run()
}

func getInterfaceMTU(name string) (int, error) {
	// Use ifconfig to get MTU
	cmd := exec.Command("ifconfig", name)
	out, err := cmd.Output()
	if err != nil {
		return 0, fmt.Errorf("get MTU: %w", err)
	}
	// Parse output to find MTU
	var mtu int
	_, err = fmt.Sscanf(string(out), "%*s mtu %d", &mtu)
	if err != nil {
		return 1500, nil // Default if parsing fails
	}
	return mtu, nil
}
