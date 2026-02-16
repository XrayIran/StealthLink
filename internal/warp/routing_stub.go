//go:build !linux

package warp

import "fmt"

func SetupPolicyRouting(cfg PolicyRoutingConfig) error {
	return fmt.Errorf("WARP policy routing requires Linux")
}

func TeardownPolicyRouting(cfg PolicyRoutingConfig) error {
	return nil
}

func checkIPCommand() error {
	return fmt.Errorf("WARP routing requires Linux")
}

func checkCapNetAdmin() bool {
	return false
}
