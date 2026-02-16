package vpn

import "errors"

var (
	// StealthLink is L3-only: TAP/L2 is intentionally not supported in the public surface.
	ErrInvalidMode        = errors.New("invalid VPN mode: only 'tun' is supported")
	ErrMissingInterfaceIP = errors.New("VPN interface IP is required")
	ErrInterfaceNotFound  = errors.New("TUN interface not found")
	ErrSetupFailed        = errors.New("failed to setup VPN interface")
	ErrBridgeFailed       = errors.New("VPN bridge failed")
)
