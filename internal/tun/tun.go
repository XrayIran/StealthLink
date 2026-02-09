package tun

import (
	"fmt"

	"github.com/songgao/water"
)

// Config holds TUN/TAP device configuration.
type Config struct {
	Name string
	MTU  int
	Mode string // "tun" or "tap"
}

// Open creates a new TUN or TAP interface.
func Open(name string, mtu int) (*water.Interface, error) {
	return OpenWithMode(Config{
		Name: name,
		MTU:  mtu,
		Mode: "tun",
	})
}

// OpenWithMode creates a new TUN or TAP interface with full configuration.
func OpenWithMode(cfg Config) (*water.Interface, error) {
	var deviceType water.DeviceType
	switch cfg.Mode {
	case "tun", "":
		deviceType = water.TUN
	case "tap":
		deviceType = water.TAP
	default:
		return nil, fmt.Errorf("invalid mode: %s (must be 'tun' or 'tap')", cfg.Mode)
	}

	wcfg := water.Config{DeviceType: deviceType}
	if cfg.Name != "" {
		wcfg.Name = cfg.Name
	}

	iface, err := water.New(wcfg)
	if err != nil {
		return nil, err
	}

	if cfg.MTU > 0 {
		if err := setMTU(iface.Name(), cfg.MTU); err != nil {
			_ = iface.Close()
			return nil, err
		}
	}

	return iface, nil
}

// IsTAP returns true if the interface is a TAP device.
func IsTAP(iface *water.Interface) bool {
	// water.Interface doesn't expose the device type directly,
	// but we can infer from the name or by trying to read/write
	// For now, we track this separately in the bridge
	return false // Default to TUN, caller should track mode
}
