//go:build !linux || !netlink

package warp

import "fmt"

// addDefaultRouteViaInterface is a stub for non-Linux platforms.
func addDefaultRouteViaInterface(ifaceName string) error {
	return fmt.Errorf("WARP routing requires Linux with netlink support")
}

// addRouteViaInterface is a stub for non-Linux platforms.
func addRouteViaInterface(ifaceName string, destination string, gateway string) error {
	return fmt.Errorf("WARP routing requires Linux with netlink support")
}

// removeRoutesViaInterface is a stub for non-Linux platforms.
func removeRoutesViaInterface(ifaceName string) error {
	return nil // Nothing to do on non-Linux platforms
}
