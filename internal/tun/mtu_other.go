//go:build !linux && !darwin

package tun

import "fmt"

func setMTU(name string, mtu int) error {
	if mtu <= 0 {
		return nil
	}
	return fmt.Errorf("setting MTU not supported on this OS")
}

func getInterfaceMTU(name string) (int, error) {
	return 1500, nil // Default MTU
}
