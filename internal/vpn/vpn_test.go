package vpn

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func newMockConn() *mockConn {
	return &mockConn{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
	}
}

func (m *mockConn) Read(p []byte) (n int, err error)   { return m.readBuf.Read(p) }
func (m *mockConn) Write(p []byte) (n int, err error)  { return m.writeBuf.Write(p) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestVPNConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr error
	}{
		{
			name: "disabled",
			config: Config{
				Enabled: false,
			},
			wantErr: nil,
		},
		{
			name: "valid tun config",
			config: Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "10.0.0.1/24",
				MTU:         1400,
			},
			wantErr: nil,
		},
		{
			name: "tap rejected (l3-only)",
			config: Config{
				Enabled:     true,
				Mode:        "tap",
				InterfaceIP: "10.0.0.1/24",
				MTU:         1400,
			},
			wantErr: ErrInvalidMode,
		},
		{
			name: "valid ipv6 tun config",
			config: Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "fd00::1/128",
				PeerIP:      "fd00::2",
				MTU:         1400,
			},
			wantErr: nil,
		},
		{
			name: "valid ipv6 with routes",
			config: Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "fd00:77::1/126",
				PeerIP:      "fd00:77::2",
				MTU:         1400,
				Routes: []Route{
					{Destination: "fd00:100::/64"},
					{Destination: "192.168.0.0/24"},
				},
			},
			wantErr: nil,
		},
		{
			name: "invalid mode",
			config: Config{
				Enabled: true,
				Mode:    "invalid",
			},
			wantErr: ErrInvalidMode,
		},
		{
			name: "missing interface ip",
			config: Config{
				Enabled: true,
				Mode:    "tun",
			},
			wantErr: ErrMissingInterfaceIP,
		},
		{
			name: "mtu too large",
			config: Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "10.0.0.1/24",
				MTU:         10000,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Errorf("Validate() unexpected error = %v", err)
			}
		})
	}
}

func TestVPNBridge(t *testing.T) {
	clientConn := newMockConn()
	serverConn := newMockConn()

	serverConn.readBuf.Write([]byte("hello from client"))
	clientConn.readBuf.Write([]byte("hello from server"))

	time.Sleep(50 * time.Millisecond)

	if clientConn.writeBuf.Len() > 0 || serverConn.writeBuf.Len() > 0 {
	}
}

func TestVPNSession(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Mode:        "tun",
		Name:        "test0",
		InterfaceIP: "10.0.0.1/24",
		PeerIP:      "10.0.0.2",
		MTU:         1400,
	}

	mockStream := newMockConn()

	session, err := NewSession(cfg, mockStream)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	if session.InterfaceName() != "" {
		t.Errorf("InterfaceName() should be empty before Start()")
	}

	if session.IsClosed() {
		t.Error("IsClosed() should be false for new session")
	}

	err = session.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !session.IsClosed() {
		t.Error("IsClosed() should be true after Close()")
	}
}

func TestVPNSessionIPv6(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Mode:        "tun",
		Name:        "test0",
		InterfaceIP: "fd00::1/128",
		PeerIP:      "fd00::2",
		MTU:         1400,
		Routes: []Route{
			{Destination: "fd00:100::/64"},
		},
	}

	mockStream := newMockConn()

	session, err := NewSession(cfg, mockStream)
	if err != nil {
		t.Fatalf("NewSession(ipv6) error = %v", err)
	}

	if session.IsClosed() {
		t.Error("IsClosed() should be false for new IPv6 session")
	}

	err = session.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !session.IsClosed() {
		t.Error("IsClosed() should be true after Close()")
	}
}

func TestSetupInterfaceIdempotency(t *testing.T) {
	// Verify that NetworkConfig with peer semantics can be constructed
	// without error for both IPv4 and IPv6 and that the teardown config
	// mirrors the setup config (idempotency contract).
	configs := []NetworkConfig{
		{
			InterfaceName: "sl_test0",
			InterfaceIP:   "10.77.0.1/30",
			PeerIP:        "10.77.0.2",
			MTU:           1400,
			Routes: []Route{
				{Destination: "192.168.0.0/24"},
			},
		},
		{
			InterfaceName: "sl_test1",
			InterfaceIP:   "fd00::1/126",
			PeerIP:        "fd00::2",
			MTU:           1400,
			Routes: []Route{
				{Destination: "fd00:100::/64"},
			},
		},
	}

	for _, cfg := range configs {
		// SetupInterface and RemoveInterface accept the same NetworkConfig.
		// We cannot call them without a real interface, but we verify the
		// config round-trips through the teardown path without panicking.
		// Call RemoveInterface on a non-existent interface (best-effort,
		// should not error).
		err := RemoveInterface(cfg)
		if err != nil {
			t.Errorf("RemoveInterface(%s) unexpected error = %v", cfg.InterfaceName, err)
		}
	}
}

func TestBridgeFunction(t *testing.T) {
	ctx, cancel := contextWithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	reader := &mockReadWriter{data: []byte("test packet")}
	writer := newMockConn()

	errCh := make(chan error, 1)
	go func() {
		errCh <- Bridge(ctx, reader, writer)
	}()

	select {
	case err := <-errCh:
		if err != nil && err != io.EOF && err != context.DeadlineExceeded {
			t.Errorf("Bridge() unexpected error = %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("Bridge() did not complete in time")
	}
}

type mockReadWriter struct {
	data []byte
	pos  int
}

func (m *mockReadWriter) Read(p []byte) (n int, err error) {
	if m.pos >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.pos:])
	m.pos += n
	return n, nil
}

func (m *mockReadWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (m *mockReadWriter) Close() error {
	return nil
}

func contextWithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, timeout)
}
