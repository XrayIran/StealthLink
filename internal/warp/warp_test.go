package warp

import (
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestWARPConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "disabled",
			config: Config{
				Enabled: false,
			},
			wantErr: false,
		},
		{
			name: "valid builtin config",
			config: Config{
				Enabled:     true,
				Mode:        "builtin",
				Endpoint:    "engage.cloudflareclient.com:2408",
				RoutingMode: "vpn_only",
				MTU:         1280,
			},
			wantErr: false,
		},
		{
			name: "valid wgquick config",
			config: Config{
				Enabled:     true,
				Mode:        "wgquick",
				Endpoint:    "engage.cloudflareclient.com:2408",
				RoutingMode: "all",
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			config: Config{
				Enabled: true,
				Mode:    "invalid",
			},
			wantErr: true,
		},
		{
			name: "missing endpoint",
			config: Config{
				Enabled: true,
				Mode:    "builtin",
			},
			wantErr: true,
		},
		{
			name: "invalid routing mode",
			config: Config{
				Enabled:     true,
				Mode:        "builtin",
				Endpoint:    "engage.cloudflareclient.com:2408",
				RoutingMode: "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWARPConfigDefaults(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Enabled {
		t.Error("DefaultConfig().Enabled should be false")
	}
	if cfg.Mode != "builtin" {
		t.Errorf("DefaultConfig().Mode = %v, want builtin", cfg.Mode)
	}
	if cfg.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("DefaultConfig().Endpoint = %v, want engage.cloudflareclient.com:2408", cfg.Endpoint)
	}
	if cfg.RoutingMode != "vpn_only" {
		t.Errorf("DefaultConfig().RoutingMode = %v, want vpn_only", cfg.RoutingMode)
	}
	if cfg.MTU != 1280 {
		t.Errorf("DefaultConfig().MTU = %v, want 1280", cfg.MTU)
	}
	if cfg.Keepalive != 30*time.Second {
		t.Errorf("DefaultConfig().Keepalive = %v, want 30s", cfg.Keepalive)
	}
}

func TestWARPTokenExpired(t *testing.T) {
	tests := []struct {
		name     string
		token    WARPToken
		expected bool
	}{
		{
			name: "not expired",
			token: WARPToken{
				Token:     "test-token",
				ExpiresAt: time.Now().Add(1 * time.Hour),
			},
			expected: false,
		},
		{
			name: "expired",
			token: WARPToken{
				Token:     "test-token",
				ExpiresAt: time.Now().Add(-1 * time.Hour),
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.token.IsExpired(); got != tt.expected {
				t.Errorf("IsExpired() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWARPTunnelManager(t *testing.T) {
	manager := NewWARPTunnelManager()

	if manager == nil {
		t.Fatal("NewWARPTunnelManager() returned nil")
	}

	if len(manager.tunnels) != 0 {
		t.Errorf("NewWARPTunnelManager() should start with empty tunnels, got %d", len(manager.tunnels))
	}

	manager.StopAll()
}

func TestWARPTunnelManagerWithTunnel(t *testing.T) {
	manager := NewWARPTunnelManager()

	cfg := Config{
		Enabled:     true,
		Mode:        "builtin",
		Endpoint:    "engage.cloudflareclient.com:2408",
		RoutingMode: "vpn_only",
	}
	tunnel, err := NewTunnel(cfg)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}

	manager.AddTunnel("test", tunnel)

	if _, ok := manager.GetTunnel("test"); !ok {
		t.Error("GetTunnel() should find added tunnel")
	}

	manager.RemoveTunnel("test")

	if _, ok := manager.GetTunnel("test"); ok {
		t.Error("GetTunnel() should not find removed tunnel")
	}
}

func TestWARPTunnelDisabled(t *testing.T) {
	cfg := Config{Enabled: false}

	_, err := NewTunnel(cfg)
	if err == nil {
		t.Error("NewTunnel() with disabled config should return error")
	}
}

func TestWARPTunnelClosed(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Mode:        "builtin",
		Endpoint:    "engage.cloudflareclient.com:2408",
		RoutingMode: "vpn_only",
	}
	tunnel, err := NewTunnel(cfg)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}

	if tunnel.IsClosed() {
		t.Error("New tunnel should not be closed")
	}

	_ = tunnel.Close()

	if !tunnel.IsClosed() {
		t.Error("Tunnel should be closed after Close()")
	}
}

func TestGenerateInstallID(t *testing.T) {
	id1 := GenerateInstallID()
	id2 := GenerateInstallID()

	if id1 == "" {
		t.Error("GenerateInstallID() returned empty string")
	}

	if id1 == id2 {
		t.Error("GenerateInstallID() should return unique IDs")
	}
}

func TestRegistrationClient(t *testing.T) {
	client := NewRegistrationClient()

	if client == nil {
		t.Fatal("NewRegistrationClient() returned nil")
	}

	if client.baseURL == "" {
		t.Error("RegistrationClient.baseURL should not be empty")
	}
}

func TestRegistrationClientRegisterDevice(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := NewRegistrationClient()

	// Use a real-looking base64 X25519 public key (32 bytes)
	device, err := client.RegisterDevice("dGVzdC1wdWJsaWMta2V5LXRoYXQtaXMtMzItYg==")
	if err != nil {
		t.Skipf("RegisterDevice() requires network access: %v", err)
	}

	if device == nil {
		t.Fatal("RegisterDevice() returned nil device")
	}

	if device.ID == "" {
		t.Error("RegisterDevice() device.ID should not be empty")
	}
}

func TestRegisterWithGateway(t *testing.T) {
	cfg := Config{
		Enabled:     true,
		Mode:        "builtin",
		Endpoint:    "engage.cloudflareclient.com:2408",
		RoutingMode: "all",
	}
	tunnel, err := NewTunnel(cfg)
	if err != nil {
		t.Fatalf("NewTunnel() error = %v", err)
	}
	if err := RegisterWithGateway(tunnel, "10.8.0.0/24"); err != nil {
		t.Fatalf("RegisterWithGateway() error = %v", err)
	}
	got := tunnel.GetConfig()
	if got.RoutingMode != "vpn_only" {
		t.Fatalf("routing mode = %q, want vpn_only", got.RoutingMode)
	}
	if got.VPNSubnet != "10.8.0.0/24" {
		t.Fatalf("vpn subnet = %q, want 10.8.0.0/24", got.VPNSubnet)
	}
}

func TestIsVPNReturnTraffic(t *testing.T) {
	if !IsVPNReturnTraffic("10.8.0.4", "10.8.0.0/24") {
		t.Fatal("expected VPN return traffic match")
	}
	if IsVPNReturnTraffic("1.1.1.1", "10.8.0.0/24") {
		t.Fatal("unexpected VPN return traffic match")
	}
}

func TestRegistrationClientGetConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	client := NewRegistrationClient()

	config, err := client.GetConfig("test-device-id", "test-access-token")
	if err != nil {
		t.Skipf("GetConfig() requires valid credentials: %v", err)
	}

	if config == nil {
		t.Fatal("GetConfig() returned nil config")
	}

	if len(config.Peers) == 0 {
		t.Error("GetConfig() should return at least one peer")
	}
}

func TestSendKeepaliveWritesEncryptedTransportFrame(t *testing.T) {
	mock := &captureConn{}
	key := make([]byte, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New: %v", err)
	}

	tunnel := &Tunnel{
		conn:     mock,
		sendAEAD: aead,
	}

	tunnel.sendKeepalive()

	if len(mock.writes) != 1 {
		t.Fatalf("writes=%d want=1", len(mock.writes))
	}
	got := mock.writes[0]
	if len(got) < 16+aead.Overhead() {
		t.Fatalf("keepalive too short: %d", len(got))
	}
	if got[0] != wgTypeTransport {
		t.Fatalf("message type=%d want=%d", got[0], wgTypeTransport)
	}
	if tunnel.sendCounter != 1 {
		t.Fatalf("sendCounter=%d want=1", tunnel.sendCounter)
	}
}

func TestNoiseHelperFunctions(t *testing.T) {
	// Test noiseInitHash produces deterministic output
	ck1, h1 := noiseInitHash()
	ck2, h2 := noiseInitHash()
	if ck1 != ck2 || h1 != h2 {
		t.Fatal("noiseInitHash should be deterministic")
	}

	// Test noiseHash
	a := []byte{1}
	b := []byte{2}
	result := noiseHash(a, b)
	empty := [32]byte{}
	if result == empty {
		t.Fatal("noiseHash should not return zero hash")
	}

	// Test noiseKDF2
	key := []byte("test-key-that-is-long-enough-ok!")
	input := []byte("test-input")
	k1, k2 := noiseKDF2(key, input)
	if k1 == empty || k2 == empty {
		t.Fatal("noiseKDF2 should not return zero keys")
	}
	if k1 == k2 {
		t.Fatal("noiseKDF2 should return different keys")
	}

	// Test clampKey
	raw := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	clampKey(raw)
	if raw[0]&7 != 0 {
		t.Fatal("clampKey should clear low 3 bits of first byte")
	}
	if raw[31]&128 != 0 {
		t.Fatal("clampKey should clear high bit of last byte")
	}
	if raw[31]&64 == 0 {
		t.Fatal("clampKey should set bit 6 of last byte")
	}
}

func TestShouldRouteViaWARP(t *testing.T) {
	if !ShouldRouteViaWARP("all", "1.1.1.1", "") {
		t.Fatal("all mode should route everything via WARP")
	}
	if ShouldRouteViaWARP("vpn_only", "1.1.1.1", "10.8.0.0/24") {
		t.Fatal("vpn_only should not route non-VPN traffic")
	}
	if !ShouldRouteViaWARP("vpn_only", "10.8.0.5", "10.8.0.0/24") {
		t.Fatal("vpn_only should route VPN subnet traffic")
	}
}

type captureConn struct {
	writes [][]byte
}

func (c *captureConn) Read(_ []byte) (int, error) {
	return 0, io.EOF
}

func (c *captureConn) Write(p []byte) (int, error) {
	cp := append([]byte(nil), p...)
	c.writes = append(c.writes, cp)
	return len(p), nil
}

func (c *captureConn) Close() error                       { return nil }
func (c *captureConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *captureConn) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (c *captureConn) SetDeadline(_ time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(_ time.Time) error { return nil }
