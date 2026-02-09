package carrier

import (
	"net"
	"testing"
	"time"
)

func TestCapabilityString(t *testing.T) {
	tests := []struct {
		cap      Capability
		expected string
	}{
		{CapabilityReliable, "reliable"},
		{CapabilityOrdered, "ordered"},
		{CapabilityDatagram, "datagram"},
		{CapabilityStream, "stream"},
		{CapabilityCongestionControl, "congestion_control"},
		{CapabilityFlowControl, "flow_control"},
		{CapabilityNATTraversal, "nat_traversal"},
		{CapabilityObfuscation, "obfuscation"},
		{CapabilityMultipath, "multipath"},
		{CapabilityZeroRTT, "0rtt"},
		{CapabilityMobility, "mobility"},
		{Capability(1 << 20), "unknown"}, // Unknown capability
	}

	for _, tt := range tests {
		if got := tt.cap.String(); got != tt.expected {
			t.Errorf("Capability(%d).String() = %s, want %s", tt.cap, got, tt.expected)
		}
	}
}

func TestCapabilityHas(t *testing.T) {
	// Single capability
	c := CapabilityReliable
	if !c.Has(CapabilityReliable) {
		t.Error("expected Has to return true for same capability")
	}
	if c.Has(CapabilityOrdered) {
		t.Error("expected Has to return false for different capability")
	}

	// Multiple capabilities
	c = CapabilityReliable | CapabilityOrdered | CapabilityStream
	if !c.Has(CapabilityReliable) {
		t.Error("expected Has to return true for Reliable")
	}
	if !c.Has(CapabilityOrdered) {
		t.Error("expected Has to return true for Ordered")
	}
	if !c.Has(CapabilityStream) {
		t.Error("expected Has to return true for Stream")
	}
	if c.Has(CapabilityDatagram) {
		t.Error("expected Has to return false for Datagram")
	}

	// Combined check
	if !c.Has(CapabilityReliable | CapabilityOrdered) {
		t.Error("expected Has to return true for combined capabilities")
	}
}

func TestNewBaseCarrier(t *testing.T) {
	caps := CapabilityReliable | CapabilityStream | CapabilityCongestionControl
	carrier := NewBaseCarrier("test", caps)

	if carrier.Name() != "test" {
		t.Errorf("expected name 'test', got '%s'", carrier.Name())
	}

	if carrier.Capabilities() != caps {
		t.Errorf("expected capabilities %v, got %v", caps, carrier.Capabilities())
	}

	info := carrier.Info()
	if info.Name != "test" {
		t.Errorf("expected info.Name 'test', got '%s'", info.Name)
	}

	if info.Capabilities != caps {
		t.Errorf("expected info.Capabilities %v, got %v", caps, info.Capabilities)
	}

	if info.MTU != 1500 {
		t.Errorf("expected default MTU 1500, got %d", info.MTU)
	}
}

func TestBaseCarrierSetInfo(t *testing.T) {
	carrier := NewBaseCarrier("test", CapabilityReliable)

	newInfo := Info{
		Name:         "updated",
		Capabilities: CapabilityStream,
		DefaultPort:  8080,
		MTU:          1400,
	}

	carrier.SetInfo(newInfo)

	info := carrier.Info()
	if info.Name != "updated" {
		t.Errorf("expected name 'updated', got '%s'", info.Name)
	}

	if info.DefaultPort != 8080 {
		t.Errorf("expected default port 8080, got %d", info.DefaultPort)
	}

	if info.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", info.MTU)
	}
}

func TestDefaultCongestionConfig(t *testing.T) {
	cfg := DefaultCongestionConfig()

	if cfg.Algorithm != CongestionControlBBR {
		t.Errorf("expected default algorithm BBR, got %s", cfg.Algorithm)
	}

	if cfg.InitialWindow != 10 {
		t.Errorf("expected initial window 10, got %d", cfg.InitialWindow)
	}

	if cfg.MinWindow != 2 {
		t.Errorf("expected min window 2, got %d", cfg.MinWindow)
	}

	if cfg.MaxWindow != 1000 {
		t.Errorf("expected max window 1000, got %d", cfg.MaxWindow)
	}

	if !cfg.Pacing {
		t.Error("expected pacing to be enabled by default")
	}
}

func TestCongestionControlString(t *testing.T) {
	tests := []struct {
		cc       CongestionControl
		expected string
	}{
		{CongestionControlCubic, "cubic"},
		{CongestionControlBBR, "bbr"},
		{CongestionControlReno, "reno"},
		{CongestionControlBrutal, "brutal"},
	}

	for _, tt := range tests {
		if string(tt.cc) != tt.expected {
			t.Errorf("expected %s, got %s", tt.expected, tt.cc)
		}
	}
}

func TestWrapConn(t *testing.T) {
	// Create a mock connection (we can't actually use it, but we can verify the wrapper)
	mockConn := &mockConn{}

	wrapped := WrapConn(mockConn, "tcp", 1400)

	if wrapped.Carrier != "tcp" {
		t.Errorf("expected carrier 'tcp', got '%s'", wrapped.Carrier)
	}

	if wrapped.LocalMTU != 1400 {
		t.Errorf("expected local MTU 1400, got %d", wrapped.LocalMTU)
	}

	if wrapped.RemoteMTU != 1400 {
		t.Errorf("expected remote MTU 1400, got %d", wrapped.RemoteMTU)
	}

	if wrapped.Conn != mockConn {
		t.Error("expected wrapped connection to hold original connection")
	}
}

func TestInfoStruct(t *testing.T) {
	info := Info{
		Name:         "test-carrier",
		Capabilities: CapabilityReliable | CapabilityStream,
		DefaultPort:  443,
		Overhead:     40,
		MTU:          1400,
	}

	info.Supports.Multiplexing = true
	info.Supports.Encryption = true
	info.Supports.Authentication = false

	if info.Name != "test-carrier" {
		t.Errorf("expected name 'test-carrier', got '%s'", info.Name)
	}

	if !info.Capabilities.Has(CapabilityReliable) {
		t.Error("expected Reliable capability")
	}

	if !info.Capabilities.Has(CapabilityStream) {
		t.Error("expected Stream capability")
	}

	if info.DefaultPort != 443 {
		t.Errorf("expected default port 443, got %d", info.DefaultPort)
	}

	if info.Overhead != 40 {
		t.Errorf("expected overhead 40, got %d", info.Overhead)
	}

	if info.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", info.MTU)
	}

	if !info.Supports.Multiplexing {
		t.Error("expected Multiplexing support")
	}

	if !info.Supports.Encryption {
		t.Error("expected Encryption support")
	}

	if info.Supports.Authentication {
		t.Error("expected no Authentication support")
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{
		Address:   "127.0.0.1",
		Port:      8080,
		Timeout:   30,
		Keepalive: 15,
		MTU:       1400,
		BufferSize: 8192,
	}

	if cfg.Address != "127.0.0.1" {
		t.Errorf("expected address '127.0.0.1', got '%s'", cfg.Address)
	}

	if cfg.Port != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.Port)
	}

	if cfg.Timeout != 30 {
		t.Errorf("expected timeout 30, got %d", cfg.Timeout)
	}

	if cfg.Keepalive != 15 {
		t.Errorf("expected keepalive 15, got %d", cfg.Keepalive)
	}

	if cfg.MTU != 1400 {
		t.Errorf("expected MTU 1400, got %d", cfg.MTU)
	}

	if cfg.BufferSize != 8192 {
		t.Errorf("expected buffer size 8192, got %d", cfg.BufferSize)
	}
}

// Mock connection for testing
type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }
