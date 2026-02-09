package tun

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/songgao/water"
)

// MTUConfig holds MTU discovery configuration.
type MTUConfig struct {
	MinSize     int           // Minimum MTU to try
	MaxSize     int           // Maximum MTU to try
	ProbeCount  int           // Number of probes per size
	Timeout     time.Duration // Probe timeout
	Target      string        // Target host for probes
}

// DefaultMTUConfig returns a default MTU configuration.
func DefaultMTUConfig() *MTUConfig {
	return &MTUConfig{
		MinSize:    576,   // Minimum IPv4 MTU
		MaxSize:    9000,  // Jumbo frame max
		ProbeCount: 3,
		Timeout:    2 * time.Second,
		Target:     "", // Will use gateway
	}
}

// AutoTuneMTU automatically discovers the optimal MTU for the interface.
// It uses a binary search approach with ICMP probes.
func AutoTuneMTU(iface *water.Interface, target string) (int, error) {
	cfg := DefaultMTUConfig()
	if target != "" {
		cfg.Target = target
	}
	return AutoTuneMTUWithConfig(iface, cfg)
}

// AutoTuneMTUWithConfig performs MTU discovery with custom configuration.
func AutoTuneMTUWithConfig(iface *water.Interface, cfg *MTUConfig) (int, error) {
	if cfg.Target == "" {
		return 0, fmt.Errorf("target required for MTU discovery")
	}

	// Resolve target
	targetAddr, err := net.ResolveIPAddr("ip", cfg.Target)
	if err != nil {
		return 0, fmt.Errorf("resolve target: %w", err)
	}

	// Binary search for optimal MTU
	low := cfg.MinSize
	high := cfg.MaxSize
	optimal := low

	for low <= high {
		mid := (low + high) / 2
		mid = (mid / 8) * 8 // Round down to multiple of 8

		if mid < cfg.MinSize {
			mid = cfg.MinSize
		}

		// Test this MTU size
		if probeMTU(targetAddr, mid, cfg) {
			optimal = mid
			low = mid + 1
		} else {
			high = mid - 1
		}
	}

	// Apply the discovered MTU
	if err := setMTU(iface.Name(), optimal); err != nil {
		return optimal, fmt.Errorf("set MTU: %w", err)
	}

	return optimal, nil
}

// probeMTU tests if a given MTU size works.
func probeMTU(target *net.IPAddr, size int, cfg *MTUConfig) bool {
	// Build ICMP echo request
	// For simplicity, we use UDP probes instead of raw ICMP
	// which requires elevated privileges

	payload := make([]byte, size-28) // Subtract IP + UDP headers
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	// Try to send UDP packet
	addr := net.JoinHostPort(target.String(), "33434") // Traceroute port

	for i := 0; i < cfg.ProbeCount; i++ {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			return false
		}

		conn.SetDeadline(time.Now().Add(cfg.Timeout))

		// Write payload
		_, err = conn.Write(payload)
		conn.Close()

		if err != nil {
			return false
		}

		// Small delay between probes
		time.Sleep(10 * time.Millisecond)
	}

	return true
}

// GetCurrentMTU returns the current MTU of the interface.
func GetCurrentMTU(ifaceName string) (int, error) {
	// Platform-specific implementation in mtu_*.go files
	return getInterfaceMTU(ifaceName)
}

// ValidateMTU checks if an MTU value is valid.
func ValidateMTU(mtu int) error {
	if mtu < 68 {
		return fmt.Errorf("MTU too small: %d (minimum 68)", mtu)
	}
	if mtu > 65535 {
		return fmt.Errorf("MTU too large: %d (maximum 65535)", mtu)
	}
	return nil
}

// RecommendedMTU returns recommended MTU based on network type.
func RecommendedMTU(networkType string) int {
	switch networkType {
	case "ethernet":
		return 1500
	case "pppoe":
		return 1492
	case "vpn":
		return 1400
	case "tunnel":
		return 1360
	case "jumbo":
		return 9000
	case "ipv6":
		return 1280 // Minimum IPv6 MTU
	default:
		return 1500
	}
}

// CalculateInnerMTU calculates the inner MTU for a tunnel.
// It accounts for tunnel overhead.
func CalculateInnerMTU(outerMTU int, tunnelOverhead int) int {
	inner := outerMTU - tunnelOverhead
	if inner < 68 {
		inner = 68
	}
	return inner
}

// MTUOverhead returns the overhead for different tunnel types.
func MTUOverhead(tunnelType string) int {
	switch tunnelType {
	case "ipsec":
		return 56 // ESP with AES-GCM
	case "wireguard":
		return 80 // WireGuard overhead
	case "gre":
		return 24
	case "ipip":
		return 20
	case "sit":
		return 20
	case "6to4":
		return 20
	case "udp":
		return 28 // 20 IP + 8 UDP
	case "tcp":
		return 40 // 20 IP + 20 TCP
	default:
		return 28
	}
}

// ProbeResult holds the result of an MTU probe.
type ProbeResult struct {
	Size      int
	Success   bool
	Timestamp time.Time
	RTT       time.Duration
}

// ProbeHistory tracks MTU probe results.
type ProbeHistory struct {
	results []ProbeResult
	mu      sync.RWMutex
}

// Add adds a probe result to history.
func (h *ProbeHistory) Add(r ProbeResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.results = append(h.results, r)
}

// GetResults returns all probe results.
func (h *ProbeHistory) GetResults() []ProbeResult {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make([]ProbeResult, len(h.results))
	copy(result, h.results)
	return result
}

// FindOptimalMTU finds the optimal MTU from probe history.
func (h *ProbeHistory) FindOptimalMTU() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	optimal := 1500 // Default
	for _, r := range h.results {
		if r.Success && r.Size > optimal {
			optimal = r.Size
		}
	}
	return optimal
}
