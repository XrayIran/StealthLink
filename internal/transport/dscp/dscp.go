// Package dscp provides DSCP/TOS marking for traffic prioritization.
package dscp

import (
	"fmt"
	"net"
)

// DSCP values for traffic prioritization.
const (
	CS0  = 0   // Class Selector 0 (default)
	CS1  = 8   // Class Selector 1 (scavenger)
	CS2  = 16  // Class Selector 2 (bulk)
	CS3  = 24  // Class Selector 3 (critical applications)
	CS4  = 32  // Class Selector 4 (realtime)
	CS5  = 40  // Class Selector 5 (broadcast video)
	CS6  = 48  // Class Selector 6 (network control)
	CS7  = 56  // Class Selector 7
	AF11 = 10  // Assured Forwarding 11
	AF12 = 12  // Assured Forwarding 12
	AF13 = 14  // Assured Forwarding 13
	AF21 = 18  // Assured Forwarding 21
	AF22 = 20  // Assured Forwarding 22
	AF23 = 22  // Assured Forwarding 23
	AF31 = 26  // Assured Forwarding 31
	AF32 = 28  // Assured Forwarding 32
	AF33 = 30  // Assured Forwarding 33
	AF41 = 34  // Assured Forwarding 41
	AF42 = 36  // Assured Forwarding 42
	AF43 = 38  // Assured Forwarding 43
	EF   = 46  // Expedited Forwarding (low delay)
)

// TrafficClass represents a named DSCP class.
type TrafficClass string

const (
	ClassDefault          TrafficClass = "default"
	ClassLowPriority      TrafficClass = "low"
	ClassBulk             TrafficClass = "bulk"
	ClassBestEffort       TrafficClass = "best-effort"
	ClassCritical         TrafficClass = "critical"
	ClassRealtime         TrafficClass = "realtime"
	ClassNetworkControl   TrafficClass = "network-control"
	ClassExpedited        TrafficClass = "expedited"
)

// ToDSCP converts a traffic class name to DSCP value.
func (tc TrafficClass) ToDSCP() int {
	switch tc {
	case ClassLowPriority:
		return CS1
	case ClassBulk:
		return CS2
	case ClassBestEffort:
		return CS0
	case ClassCritical:
		return CS3
	case ClassRealtime:
		return CS4
	case ClassNetworkControl:
		return CS6
	case ClassExpedited:
		return EF
	default:
		return CS0
	}
}

// Settable interface for connections that support DSCP setting.
type Settable interface {
	SetDSCP(dscp int) error
}

// Set sets the DSCP value on a connection.
// It attempts to use the Settable interface first, then falls back to
// platform-specific implementations.
func Set(conn net.Conn, dscp int) error {
	// Try the interface first
	if s, ok := conn.(Settable); ok {
		return s.SetDSCP(dscp)
	}

	// Fall back to platform-specific implementation
	return setPlatformDSCP(conn, dscp)
}

// SetByClass sets DSCP using a traffic class name.
func SetByClass(conn net.Conn, class string) error {
	dscp := TrafficClass(class).ToDSCP()
	return Set(conn, dscp)
}

// SetTOS sets the legacy TOS field (DSCP is in upper 6 bits).
func SetTOS(conn net.Conn, tos int) error {
	// TOS is DSCP << 2
	return Set(conn, tos>>2)
}

// GetDSCPName returns a human-readable name for a DSCP value.
func GetDSCPName(dscp int) string {
	switch dscp {
	case CS0:
		return "CS0 (default)"
	case CS1:
		return "CS1 (scavenger)"
	case CS2:
		return "CS2 (bulk)"
	case CS3:
		return "CS3 (critical)"
	case CS4:
		return "CS4 (realtime)"
	case CS5:
		return "CS5 (broadcast)"
	case CS6:
		return "CS6 (network control)"
	case CS7:
		return "CS7"
	case AF11:
		return "AF11"
	case AF12:
		return "AF12"
	case AF13:
		return "AF13"
	case AF21:
		return "AF21"
	case AF22:
		return "AF22"
	case AF23:
		return "AF23"
	case AF31:
		return "AF31"
	case AF32:
		return "AF32"
	case AF33:
		return "AF33"
	case AF41:
		return "AF41"
	case AF42:
		return "AF42"
	case AF43:
		return "AF43"
	case EF:
		return "EF (expedited forwarding)"
	default:
		return fmt.Sprintf("DSCP %d", dscp)
	}
}

// Config holds DSCP configuration for different traffic types.
type Config struct {
	Control int // DSCP for control traffic
	Data    int // DSCP for data traffic
	Probe   int // DSCP for probe/healthcheck traffic
}

// DefaultConfig returns a default DSCP configuration.
func DefaultConfig() *Config {
	return &Config{
		Control: CS6, // Network control for control traffic
		Data:    CS0, // Default for data
		Probe:   CS2, // Bulk for probes
	}
}

// LowLatencyConfig returns a DSCP configuration optimized for low latency.
func LowLatencyConfig() *Config {
	return &Config{
		Control: CS6, // Network control
		Data:    EF,  // Expedited forwarding for low latency
		Probe:   CS3, // Critical for probes
	}
}

// HighThroughputConfig returns a DSCP configuration optimized for throughput.
func HighThroughputConfig() *Config {
	return &Config{
		Control: CS6, // Network control
		Data:    CS4, // Realtime for high throughput
		Probe:   CS2, // Bulk for probes
	}
}
