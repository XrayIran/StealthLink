package tlsmux

import (
	"net"
	"testing"
	"time"
)

func TestNewUnifiedDialer(t *testing.T) {
	cfg := &UnifiedTLSConfig{
		Mode:  ModeDirect,
		Guard: "test-guard",
	}

	dialer, err := NewUnifiedDialer(cfg)
	if err != nil {
		t.Fatalf("failed to create dialer: %v", err)
	}

	if dialer.config != cfg {
		t.Error("dialer config mismatch")
	}

	if dialer.handler == nil {
		t.Error("expected handler to be set")
	}

	if dialer.handler.Mode() != ModeDirect {
		t.Errorf("expected ModeDirect handler, got %s", dialer.handler.Mode())
	}
}

func TestNewUnifiedListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	cfg := &UnifiedTLSConfig{
		Mode:  ModeDirect,
		Guard: "test-guard",
	}

	ul, err := NewUnifiedListener(ln, cfg)
	if err != nil {
		t.Fatalf("failed to create unified listener: %v", err)
	}

	if ul.ln != ln {
		t.Error("listener mismatch")
	}

	if ul.config != cfg {
		t.Error("config mismatch")
	}

	if ul.handler == nil {
		t.Error("expected handler to be set")
	}
}

func TestUnifiedListenerAddr(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	cfg := &UnifiedTLSConfig{
		Mode: ModeDirect,
	}

	ul, err := NewUnifiedListener(ln, cfg)
	if err != nil {
		t.Fatalf("failed to create unified listener: %v", err)
	}

	if ul.Addr().String() != ln.Addr().String() {
		t.Error("address mismatch")
	}
}

func TestGetHandler(t *testing.T) {
	tests := []struct {
		name      string
		mode      TLSMode
		cfg       *UnifiedTLSConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "direct mode",
			mode:    ModeDirect,
			cfg:     &UnifiedTLSConfig{},
			wantErr: false,
		},
		{
			name: "reality mode with config",
			mode: ModeReality,
			cfg: &UnifiedTLSConfig{
				Reality: &RealityConfig{
					Dest:       "www.example.com",
					PrivateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				},
			},
			wantErr: false,
		},
		{
			name:      "reality mode without config",
			mode:      ModeReality,
			cfg:       &UnifiedTLSConfig{},
			wantErr:   true,
			errSubstr: "reality config required",
		},
		{
			name: "shadowtls mode with config",
			mode: ModeShadowTLS,
			cfg: &UnifiedTLSConfig{
				ShadowTLS: &ShadowTLSConfig{
					Version:  3,
					Password: "test",
				},
			},
			wantErr: false,
		},
		{
			name:      "shadowtls mode without config",
			mode:      ModeShadowTLS,
			cfg:       &UnifiedTLSConfig{},
			wantErr:   true,
			errSubstr: "shadowtls config required",
		},
		{
			name: "tlsmirror mode with config",
			mode: ModeTLSMirror,
			cfg: &UnifiedTLSConfig{
				TLSMirror: &TLSMirrorConfig{
					Enabled: true,
				},
			},
			wantErr: false,
		},
		{
			name: "tlsmirror mode without config (creates default)",
			mode: ModeTLSMirror,
			cfg:  &UnifiedTLSConfig{},
			// Creates default config, no error
			wantErr: false,
		},
		{
			name: "ech mode with config",
			mode: ModeECH,
			cfg: &UnifiedTLSConfig{
				ECH: &ECHConfig{
					Enabled:    true,
					PublicName: "cloudflare-ech.com",
				},
			},
			wantErr: false,
		},
		{
			name:      "ech mode without config",
			mode:      ModeECH,
			cfg:       &UnifiedTLSConfig{},
			wantErr:   true,
			errSubstr: "ech config required",
		},
		{
			name:      "unsupported mode",
			mode:      TLSMode("invalid"),
			cfg:       &UnifiedTLSConfig{},
			wantErr:   true,
			errSubstr: "unsupported TLS mode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler, err := getHandler(tt.mode, tt.cfg)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" {
					if err.Error() == "" || len(tt.errSubstr) > 0 {
						found := false
						for i := 0; i <= len(err.Error())-len(tt.errSubstr); i++ {
							if err.Error()[i:i+len(tt.errSubstr)] == tt.errSubstr {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
						}
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if handler == nil {
					t.Error("expected handler, got nil")
				} else if handler.Mode() != tt.mode {
					t.Errorf("expected handler mode %s, got %s", tt.mode, handler.Mode())
				}
			}
		})
	}
}

func TestApplyTLSShaping(t *testing.T) {
	// Create mock connection
	mockConn := &mockConn{}

	// Test nil shaping
	result := applyTLSShaping(mockConn, nil)
	if result != mockConn {
		t.Error("expected same connection when shaping is nil")
	}

	// Test disabled fragmentation
	shaping := &TLSShapingConfig{
		Fragment: TLSFragmentConfig{
			Enabled: false,
		},
	}
	result = applyTLSShaping(mockConn, shaping)
	if result != mockConn {
		t.Error("expected same connection when fragmentation is disabled")
	}

	// Test enabled fragmentation
	shaping = &TLSShapingConfig{
		Fragment: TLSFragmentConfig{
			Enabled: true,
			Size:    100,
		},
	}
	result = applyTLSShaping(mockConn, shaping)
	if result == mockConn {
		t.Error("expected wrapped connection when fragmentation is enabled")
	}

	// Check it's the right type
	if _, ok := result.(*fragmentedConn); !ok {
		t.Errorf("expected *fragmentedConn, got %T", result)
	}
}

func TestFragmentedConnWriteNonHandshake(t *testing.T) {
	mockConn := &mockConn{}
	fc := &fragmentedConn{
		Conn: mockConn,
		config: &TLSFragmentConfig{
			Enabled: true,
			Size:    100,
		},
	}

	// Test non-handshake data (not TLS record type 0x16)
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	n, err := fc.Write(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
}

func TestFragmentedConnWriteEmpty(t *testing.T) {
	mockConn := &mockConn{}
	fc := &fragmentedConn{
		Conn: mockConn,
		config: &TLSFragmentConfig{
			Enabled: true,
			Size:    100,
		},
	}

	// Test empty data
	n, err := fc.Write([]byte{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes written, got %d", n)
	}
}

func TestFragmentedConnWriteDisabled(t *testing.T) {
	mockConn := &mockConn{}
	fc := &fragmentedConn{
		Conn: mockConn,
		config: &TLSFragmentConfig{
			Enabled: false,
			Size:    100,
		},
	}

	// Test when disabled - should pass through
	data := []byte{0x16, 0x03, 0x01, 0x00, 0x10} // TLS handshake header
	n, err := fc.Write(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}
}

func TestFragmentedConnWriteWithFragmentation(t *testing.T) {
	mockConn := &mockConn{}
	fc := &fragmentedConn{
		Conn: mockConn,
		config: &TLSFragmentConfig{
			Enabled: true,
			Size:    10,
		},
	}

	// TLS handshake record (0x16) with enough data to fragment
	data := make([]byte, 50)
	data[0] = 0x16 // TLS handshake type
	data[1] = 0x03 // Version major
	data[2] = 0x03 // Version minor

	n, err := fc.Write(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("expected %d bytes written, got %d", len(data), n)
	}

	// With Size=10 and 50 bytes of data, should write at least 5 fragments
	// The exact count depends on implementation details
}

func TestTLSModeConstants(t *testing.T) {
	tests := []struct {
		mode TLSMode
		want string
	}{
		{ModeDirect, "direct"},
		{ModeReality, "reality"},
		{ModeShadowTLS, "shadowtls"},
		{ModeTLSMirror, "tlsmirror"},
		{ModeECH, "ech"},
	}

	for _, tt := range tests {
		if string(tt.mode) != tt.want {
			t.Errorf("expected mode %q, got %q", tt.want, tt.mode)
		}
	}
}

func TestTLSFragmentConfig(t *testing.T) {
	cfg := TLSFragmentConfig{
		Enabled:   true,
		Mode:      "fixed",
		Size:      100,
		NumFrags:  10,
		DelayMin:  10,
		DelayMax:  50,
		Randomize: true,
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if cfg.Mode != "fixed" {
		t.Errorf("expected Mode 'fixed', got %q", cfg.Mode)
	}
	if cfg.Size != 100 {
		t.Errorf("expected Size 100, got %d", cfg.Size)
	}
}

func TestSNIBlendConfig(t *testing.T) {
	cfg := SNIBlendConfig{
		Enabled:        true,
		FakeSNIs:       []string{"fake1.com", "fake2.com"},
		BlendRatio:     0.3,
		RotateInterval: 300,
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if len(cfg.FakeSNIs) != 2 {
		t.Errorf("expected 2 fake SNIs, got %d", len(cfg.FakeSNIs))
	}
	if cfg.BlendRatio != 0.3 {
		t.Errorf("expected BlendRatio 0.3, got %f", cfg.BlendRatio)
	}
}

func TestHandshakePaddingConfig(t *testing.T) {
	cfg := HandshakePaddingConfig{
		Enabled:   true,
		MinSize:   100,
		MaxSize:   1000,
		Randomize: true,
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if cfg.MinSize != 100 {
		t.Errorf("expected MinSize 100, got %d", cfg.MinSize)
	}
	if cfg.MaxSize != 1000 {
		t.Errorf("expected MaxSize 1000, got %d", cfg.MaxSize)
	}
}

func TestRealityConfig(t *testing.T) {
	cfg := &RealityConfig{
		Dest:        "www.microsoft.com",
		ServerNames: []string{"www.microsoft.com", "www.bing.com"},
		PrivateKey:  "test-key",
		ShortIDs:    []string{"id1", "id2"},
		SpiderX:     "/search",
		Show:        true,
	}

	if cfg.Dest != "www.microsoft.com" {
		t.Errorf("expected Dest 'www.microsoft.com', got %q", cfg.Dest)
	}
	if len(cfg.ServerNames) != 2 {
		t.Errorf("expected 2 server names, got %d", len(cfg.ServerNames))
	}
	if !cfg.Show {
		t.Error("expected Show to be true")
	}
}

func TestShadowTLSConfig(t *testing.T) {
	cfg := &ShadowTLSConfig{
		Version:       3,
		Password:      "secret",
		ServerNames:   []string{"example.com"},
		StrictMode:    true,
		WildcardSNIMode: "authed",
		MinTLSVersion: 0x0303,
		MaxTLSVersion: 0x0304,
	}

	if cfg.Version != 3 {
		t.Errorf("expected Version 3, got %d", cfg.Version)
	}
	if cfg.Password != "secret" {
		t.Errorf("expected Password 'secret', got %q", cfg.Password)
	}
	if !cfg.StrictMode {
		t.Error("expected StrictMode to be true")
	}
}

func TestECHConfig(t *testing.T) {
	cfg := &ECHConfig{
		Enabled:    true,
		PublicName: "cloudflare-ech.com",
		InnerSNI:   "example.com",
		RequireECH: true,
	}

	if !cfg.Enabled {
		t.Error("expected Enabled to be true")
	}
	if cfg.PublicName != "cloudflare-ech.com" {
		t.Errorf("expected PublicName 'cloudflare-ech.com', got %q", cfg.PublicName)
	}
	if cfg.InnerSNI != "example.com" {
		t.Errorf("expected InnerSNI 'example.com', got %q", cfg.InnerSNI)
	}
	if !cfg.RequireECH {
		t.Error("expected RequireECH to be true")
	}
}

// Mock connection for testing
type mockConn struct {
	writeData []byte
	closed    bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return 0, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1234}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5678}
}

func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }
