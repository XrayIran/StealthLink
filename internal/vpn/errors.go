package vpn

import "errors"

var (
	ErrInvalidMode        = errors.New("invalid VPN mode: must be 'tun' or 'tap'")
	ErrMissingInterfaceIP = errors.New("VPN interface IP is required")
	ErrInterfaceNotFound  = errors.New("TUN/TAP interface not found")
	ErrSetupFailed        = errors.New("failed to setup VPN interface")
	ErrBridgeFailed       = errors.New("VPN bridge failed")
)
