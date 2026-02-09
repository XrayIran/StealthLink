package vpn

// NetworkConfig holds configuration for setting up a network interface.
type NetworkConfig struct {
	InterfaceName string
	InterfaceIP   string
	PeerIP        string
	MTU           int
	Routes        []Route
	DNS           []string
}
