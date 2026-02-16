package carrier

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// mockCarrier is a minimal implementation of the Carrier interface for testing.
type mockCarrier struct {
	capabilities CarrierCapabilities
	config       CarrierConfig
	stats        CarrierStats
}

func (m *mockCarrier) Dial(ctx context.Context, addr string) (Session, error) {
	return &mockSession{}, nil
}

func (m *mockCarrier) Listen(addr string) (Listener, error) {
	return &mockListener{}, nil
}

func (m *mockCarrier) Capabilities() CarrierCapabilities {
	return m.capabilities
}

func (m *mockCarrier) Configure(config CarrierConfig) error {
	m.config = config
	return nil
}

func (m *mockCarrier) Stats() CarrierStats {
	return m.stats
}

// mockSession is a minimal implementation of the Session interface for testing.
type mockSession struct {
	closed bool
}

func (m *mockSession) Read(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.EOF
	}
	return 0, nil
}

func (m *mockSession) Write(p []byte) (n int, err error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (m *mockSession) Close() error {
	m.closed = true
	return nil
}

func (m *mockSession) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (m *mockSession) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
}

func (m *mockSession) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockSession) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockSession) SetWriteDeadline(t time.Time) error {
	return nil
}

// mockListener is a minimal implementation of the Listener interface for testing.
type mockListener struct {
	closed bool
}

func (m *mockListener) Accept() (Session, error) {
	if m.closed {
		return nil, io.EOF
	}
	return &mockSession{}, nil
}

func (m *mockListener) Close() error {
	m.closed = true
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(0, 0, 0, 0), Port: 8080}
}

// TestCarrierInterface verifies that the Carrier interface contract is satisfied.
func TestCarrierInterface(t *testing.T) {
	carrier := &mockCarrier{
		capabilities: CarrierCapabilities{
			StreamOriented:   true,
			ZeroRTT:          false,
			ReplayProtection: true,
		},
	}

	// Test Configure
	config := CarrierConfig{
		Mode: "HTTP+",
		MTU:  1500,
	}
	if err := carrier.Configure(config); err != nil {
		t.Errorf("Configure() error = %v", err)
	}

	// Test Capabilities
	caps := carrier.Capabilities()
	if !caps.StreamOriented {
		t.Error("Expected StreamOriented to be true")
	}
	if !caps.ReplayProtection {
		t.Error("Expected ReplayProtection to be true")
	}

	// Test Dial
	ctx := context.Background()
	session, err := carrier.Dial(ctx, "localhost:8080")
	if err != nil {
		t.Errorf("Dial() error = %v", err)
	}
	if session == nil {
		t.Error("Dial() returned nil session")
	}

	// Test Listen
	listener, err := carrier.Listen(":8080")
	if err != nil {
		t.Errorf("Listen() error = %v", err)
	}
	if listener == nil {
		t.Error("Listen() returned nil listener")
	}

	// Test Stats
	stats := carrier.Stats()
	_ = stats // Just verify it doesn't panic
}

// TestSessionInterface verifies that the Session interface contract is satisfied.
func TestSessionInterface(t *testing.T) {
	session := &mockSession{}

	// Test Write
	data := []byte("hello")
	n, err := session.Write(data)
	if err != nil {
		t.Errorf("Write() error = %v", err)
	}
	if n != len(data) {
		t.Errorf("Write() wrote %d bytes, want %d", n, len(data))
	}

	// Test Read
	buf := make([]byte, 100)
	_, err = session.Read(buf)
	if err != nil && err != io.EOF {
		t.Errorf("Read() error = %v", err)
	}

	// Test addresses
	if session.LocalAddr() == nil {
		t.Error("LocalAddr() returned nil")
	}
	if session.RemoteAddr() == nil {
		t.Error("RemoteAddr() returned nil")
	}

	// Test deadlines
	deadline := time.Now().Add(time.Second)
	if err := session.SetDeadline(deadline); err != nil {
		t.Errorf("SetDeadline() error = %v", err)
	}
	if err := session.SetReadDeadline(deadline); err != nil {
		t.Errorf("SetReadDeadline() error = %v", err)
	}
	if err := session.SetWriteDeadline(deadline); err != nil {
		t.Errorf("SetWriteDeadline() error = %v", err)
	}

	// Test Close
	if err := session.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify closed state
	_, err = session.Write(data)
	if err == nil {
		t.Error("Write() after Close() should return error")
	}
}

// TestListenerInterface verifies that the Listener interface contract is satisfied.
func TestListenerInterface(t *testing.T) {
	listener := &mockListener{}

	// Test Addr
	if listener.Addr() == nil {
		t.Error("Addr() returned nil")
	}

	// Test Accept
	session, err := listener.Accept()
	if err != nil {
		t.Errorf("Accept() error = %v", err)
	}
	if session == nil {
		t.Error("Accept() returned nil session")
	}

	// Test Close
	if err := listener.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	// Verify closed state
	_, err = listener.Accept()
	if err == nil {
		t.Error("Accept() after Close() should return error")
	}
}

// TestCarrierCapabilities verifies capability flag behavior.
func TestCarrierCapabilities(t *testing.T) {
	tests := []struct {
		name string
		caps CarrierCapabilities
	}{
		{
			name: "mode HTTP+ capabilities",
			caps: CarrierCapabilities{
				StreamOriented: true,
				ZeroRTT:        true,
				Fronting:       true,
			},
		},
		{
			name: "mode TCP+ capabilities",
			caps: CarrierCapabilities{
				ReplayProtection: true,
				ServerInitiated:  true,
			},
		},
		{
			name: "mode TLS+ capabilities",
			caps: CarrierCapabilities{
				StreamOriented: true,
				ZeroRTT:        true,
				CoverTraffic:   true,
			},
		},
		{
			name: "mode UDP+ capabilities",
			caps: CarrierCapabilities{
				StreamOriented: true,
				ZeroRTT:        true,
				PathMigration:  true,
				Multipath:      true,
			},
		},
		{
			name: "mode TLS capabilities",
			caps: CarrierCapabilities{
				StreamOriented:  true,
				ZeroRTT:         true,
				ServerInitiated: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the struct can be created and accessed
			_ = tt.caps.StreamOriented
			_ = tt.caps.ZeroRTT
			_ = tt.caps.ReplayProtection
			_ = tt.caps.PathMigration
			_ = tt.caps.Multipath
			_ = tt.caps.ServerInitiated
			_ = tt.caps.Fronting
			_ = tt.caps.CoverTraffic
		})
	}
}

// TestCarrierConfig verifies configuration structure.
func TestCarrierConfig(t *testing.T) {
	config := CarrierConfig{
		Mode:              "HTTP+",
		MTU:               1500,
		CongestionControl: "cubic",
		Reliability:       "none",
		MuxSettings: MuxConfig{
			Enabled:           true,
			MaxStreams:        256,
			StreamBufferSize:  65536,
			KeepAliveInterval: 30 * time.Second,
			KeepAliveTimeout:  90 * time.Second,
		},
		RotationPolicy: RotationConfig{
			Enabled:         true,
			MaxReuseTimes:   32,
			MaxRequestTimes: 100,
			MaxLifetime:     3600 * time.Second,
			DrainTimeout:    30 * time.Second,
		},
		PaddingPolicy: PaddingConfig{
			Enabled:  true,
			Scheme:   "random",
			Min:      100,
			Max:      900,
			Interval: 1 * time.Second,
		},
	}

	// Verify all fields are accessible
	if config.Mode != "HTTP+" {
		t.Errorf("Mode = %s, want HTTP+", config.Mode)
	}
	if config.MTU != 1500 {
		t.Errorf("MTU = %d, want 1500", config.MTU)
	}
	if !config.MuxSettings.Enabled {
		t.Error("MuxSettings.Enabled should be true")
	}
	if !config.RotationPolicy.Enabled {
		t.Error("RotationPolicy.Enabled should be true")
	}
	if !config.PaddingPolicy.Enabled {
		t.Error("PaddingPolicy.Enabled should be true")
	}
}

// TestCarrierStats verifies statistics structure.
func TestCarrierStats(t *testing.T) {
	stats := CarrierStats{
		ConnectionsActive: 10,
		ConnectionsTotal:  100,
		ConnectionsFailed: 5,
		BytesSent:         1024000,
		BytesReceived:     2048000,
		PacketsSent:       1000,
		PacketsReceived:   2000,
		PacketsLost:       10,
		RTTMean:           50.5,
		RTTP95:            100.0,
		RTTP99:            150.0,
	}

	// Verify all fields are accessible
	if stats.ConnectionsActive != 10 {
		t.Errorf("ConnectionsActive = %d, want 10", stats.ConnectionsActive)
	}
	if stats.BytesSent != 1024000 {
		t.Errorf("BytesSent = %d, want 1024000", stats.BytesSent)
	}
	if stats.RTTMean != 50.5 {
		t.Errorf("RTTMean = %f, want 50.5", stats.RTTMean)
	}
}
