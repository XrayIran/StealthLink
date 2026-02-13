package singbox

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// TestAdapterCreation tests adapter initialization
func TestAdapterCreation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "disabled adapter",
			cfg: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "enabled anytls adapter",
			cfg: Config{
				Enabled: true,
				Mode:    "anytls",
			},
			wantErr: false,
		},
		{
			name: "unsupported mode",
			cfg: Config{
				Enabled: true,
				Mode:    "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := NewAdapter(tt.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewAdapter() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && adapter == nil {
				t.Error("NewAdapter() returned nil adapter")
			}
			if !tt.wantErr && adapter.Enabled() != tt.cfg.Enabled {
				t.Errorf("adapter.Enabled() = %v, want %v", adapter.Enabled(), tt.cfg.Enabled)
			}
		})
	}
}

// TestWrapDialer tests dialer wrapping behavior
func TestWrapDialer(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		mode    string
	}{
		{
			name:    "disabled adapter passthrough",
			enabled: false,
		},
		{
			name:    "enabled anytls adapter",
			enabled: true,
			mode:    "anytls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled: tt.enabled,
				Mode:    tt.mode,
			}
			adapter, err := NewAdapter(cfg)
			if err != nil {
				t.Fatalf("NewAdapter() error = %v", err)
			}

			// Create a mock dialer
			mockDialer := func(ctx context.Context, addr string) (net.Conn, error) {
				return &mockConn{}, nil
			}

			wrappedDialer := adapter.WrapDialer(mockDialer)
			if wrappedDialer == nil {
				t.Fatal("WrapDialer() returned nil")
			}

			// Test dialing
			conn, err := wrappedDialer(context.Background(), "test:1234")
			if err != nil {
				t.Fatalf("wrappedDialer() error = %v", err)
			}
			if conn == nil {
				t.Fatal("wrappedDialer() returned nil connection")
			}

			// Verify connection type
			if tt.enabled {
				if _, ok := conn.(*singboxConn); !ok {
					t.Error("expected singboxConn when adapter enabled")
				}
			} else {
				if _, ok := conn.(*mockConn); !ok {
					t.Error("expected mockConn when adapter disabled")
				}
			}
		})
	}
}

// TestWrapListener tests listener wrapping behavior
func TestWrapListener(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
		mode    string
	}{
		{
			name:    "disabled adapter passthrough",
			enabled: false,
		},
		{
			name:    "enabled anytls adapter",
			enabled: true,
			mode:    "anytls",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Enabled: tt.enabled,
				Mode:    tt.mode,
			}
			adapter, err := NewAdapter(cfg)
			if err != nil {
				t.Fatalf("NewAdapter() error = %v", err)
			}

			mockListener := &mockListener{}
			wrappedListener := adapter.WrapListener(mockListener)
			if wrappedListener == nil {
				t.Fatal("WrapListener() returned nil")
			}

			// Verify listener type
			if tt.enabled {
				if _, ok := wrappedListener.(*singboxListener); !ok {
					t.Error("expected singboxListener when adapter enabled")
				}
			} else {
				if wrappedListener != mockListener {
					t.Error("expected original mockListener when adapter disabled")
				}
			}
		})
	}
}

// TestSingboxConn tests connection wrapping
func TestSingboxConn(t *testing.T) {
	mockConn := &mockConn{}
	singboxConn := &singboxConn{
		Conn: mockConn,
		mode: "anytls",
	}

	// Test that underlying connection is accessible
	if singboxConn.Conn != mockConn {
		t.Error("underlying Conn should be accessible")
	}

	// Test mode is set
	if singboxConn.mode != "anytls" {
		t.Errorf("mode = %v, want anytls", singboxConn.mode)
	}
}

// TestSingboxListener tests listener wrapping and accept
func TestSingboxListener(t *testing.T) {
	mockListener := &mockListener{}
	singboxListener := &singboxListener{
		Listener: mockListener,
		mode:     "anytls",
	}

	conn, err := singboxListener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}

	// Verify connection is wrapped
	if _, ok := conn.(*singboxConn); !ok {
		t.Error("Accept() should return singboxConn")
	}

	// Verify mode is set
	if sc, ok := conn.(*singboxConn); ok {
		if sc.mode != "anytls" {
			t.Errorf("mode = %v, want anytls", sc.mode)
		}
	}
}

// Mock implementations for testing

type mockConn struct {
	net.Conn
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, io.EOF
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

type mockListener struct {
	net.Listener
}

func (m *mockListener) Accept() (net.Conn, error) {
	return &mockConn{}, nil
}

func (m *mockListener) Close() error {
	return nil
}

func (m *mockListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
}
