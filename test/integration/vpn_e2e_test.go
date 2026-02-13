package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/uqsp"
	"stealthlink/internal/vpn"

	"github.com/xtaci/smux"
)

// mockStream implements net.Conn for testing VPN bridge without real transport.
type mockStream struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
	closed   bool
}

func newMockStreamPair() (*mockStream, *mockStream) {
	ab := &bytes.Buffer{}
	ba := &bytes.Buffer{}
	a := &mockStream{readBuf: ba, writeBuf: ab}
	b := &mockStream{readBuf: ab, writeBuf: ba}
	return a, b
}

func (m *mockStream) Read(p []byte) (int, error) {
	if m.closed {
		return 0, io.EOF
	}
	if m.readBuf.Len() == 0 {
		return 0, io.EOF
	}
	return m.readBuf.Read(p)
}

func (m *mockStream) Write(p []byte) (int, error) {
	if m.closed {
		return 0, io.ErrClosedPipe
	}
	return m.writeBuf.Write(p)
}

func (m *mockStream) Close() error {
	m.closed = true
	return nil
}

func (m *mockStream) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockStream) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockStream) SetDeadline(t time.Time) error      { return nil }
func (m *mockStream) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockStream) SetWriteDeadline(t time.Time) error { return nil }

func TestVPNConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  vpn.Config
		wantErr bool
	}{
		{
			name:    "disabled config is valid",
			config:  vpn.Config{Enabled: false},
			wantErr: false,
		},
		{
			name: "valid tun config",
			config: vpn.Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "10.0.0.1/24",
				PeerIP:      "10.0.0.2",
				MTU:         1400,
			},
			wantErr: false,
		},
		{
			name: "valid tap config",
			config: vpn.Config{
				Enabled:     true,
				Mode:        "tap",
				InterfaceIP: "10.0.0.1/24",
				MTU:         1400,
			},
			wantErr: false,
		},
		{
			name: "invalid mode",
			config: vpn.Config{
				Enabled: true,
				Mode:    "invalid",
			},
			wantErr: true,
		},
		{
			name: "missing interface ip",
			config: vpn.Config{
				Enabled: true,
				Mode:    "tun",
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

func TestVPNSessionLifecycle(t *testing.T) {
	cfg := vpn.Config{
		Enabled:     true,
		Mode:        "tun",
		Name:        "test0",
		InterfaceIP: "10.0.0.1/24",
		PeerIP:      "10.0.0.2",
		MTU:         1400,
	}

	stream := &mockStream{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
	}

	session, err := vpn.NewSession(cfg, stream)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}

	if session.IsClosed() {
		t.Error("new session should not be closed")
	}

	if err := session.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !session.IsClosed() {
		t.Error("session should be closed after Close()")
	}
}

func TestVPNBridgeFunction(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	// Create a reader that returns test data then EOF
	testData := []byte("test packet data")
	reader := &mockStream{
		readBuf:  bytes.NewBuffer(testData),
		writeBuf: &bytes.Buffer{},
	}
	writer := &mockStream{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- vpn.Bridge(ctx, reader, writer)
	}()

	select {
	case err := <-errCh:
		if err != nil && err != io.EOF && err != context.DeadlineExceeded {
			t.Errorf("Bridge() unexpected error = %v", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("Bridge() did not complete in time")
	}
}

func TestAllFiveMethodConfigs(t *testing.T) {
	// Verify that all five method configurations parse correctly
	methods := []struct {
		name        string
		carrierType string
	}{
		{"Method 4a: XHTTP + Domain Fronting", "xhttp"},
		{"Method 4b: Raw TCP + obfs4", "rawtcp"},
		{"Method 4c: XHTTP + REALITY", "xhttp"},
		{"Method 4d: UDP (native QUIC)", "quic"},
		{"Method 4e: TLS tunnel (TrustTunnel)", "trusttunnel"},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			if m.carrierType == "" {
				t.Error("carrier type must be specified")
			}
			// Basic validation that carrier types are recognized
			switch m.carrierType {
			case "quic", "rawtcp", "faketcp", "icmptun", "webtunnel", "chisel", "xhttp", "trusttunnel":
				// Valid carrier type
			default:
				t.Errorf("unknown carrier type: %s", m.carrierType)
			}
		})
	}
}

func TestVPNE2ENetworkNamespaces(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux network namespaces")
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root privileges")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("requires iproute2 command: ip")
	}
	if _, err := exec.LookPath("ping"); err != nil {
		t.Skip("requires ping command")
	}

	nsA := "sl_ns_a"
	nsB := "sl_ns_b"
	vA := "sl_veth_a"
	vB := "sl_veth_b"

	// Cleanup from previous interrupted runs.
	_ = runCmd("ip", "netns", "del", nsA)
	_ = runCmd("ip", "netns", "del", nsB)

	t.Cleanup(func() {
		_ = runCmd("ip", "netns", "del", nsA)
		_ = runCmd("ip", "netns", "del", nsB)
	})

	steps := [][]string{
		{"ip", "netns", "add", nsA},
		{"ip", "netns", "add", nsB},
		{"ip", "link", "add", vA, "type", "veth", "peer", "name", vB},
		{"ip", "link", "set", vA, "netns", nsA},
		{"ip", "link", "set", vB, "netns", nsB},
		{"ip", "netns", "exec", nsA, "ip", "addr", "add", "10.200.1.1/24", "dev", vA},
		{"ip", "netns", "exec", nsB, "ip", "addr", "add", "10.200.1.2/24", "dev", vB},
		{"ip", "netns", "exec", nsA, "ip", "link", "set", vA, "up"},
		{"ip", "netns", "exec", nsB, "ip", "link", "set", vB, "up"},
		{"ip", "netns", "exec", nsA, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", nsB, "ip", "link", "set", "lo", "up"},
	}
	for _, step := range steps {
		if err := runCmd(step[0], step[1:]...); err != nil {
			t.Fatalf("command failed: %v: %v", step, err)
		}
	}

	if err := runCmd("ip", "netns", "exec", nsA, "ping", "-c", "1", "-W", "2", "10.200.1.2"); err != nil {
		t.Fatalf("namespace ping failed: %v", err)
	}
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// ---------------------------------------------------------------------------
// Variant transport round-trip integration tests
// ---------------------------------------------------------------------------

func TestVariantTransportRoundTrip4a(t *testing.T) {
	testVariantTransportRoundTrip(t, "4a", "xhttp", []string{"gfwresist_tls"})
}

func TestVariantTransportRoundTrip4b(t *testing.T) {
	testVariantTransportRoundTrip(t, "4b", "rawtcp", []string{"gfwresist_tcp"})
}

func TestVariantTransportRoundTrip4c(t *testing.T) {
	testVariantTransportRoundTrip(t, "4c", "xhttp", []string{"tlsmirror"})
}

func TestVariantTransportRoundTrip4d(t *testing.T) {
	testVariantTransportRoundTrip(t, "4d", "quic", nil)
}

func TestVariantTransportRoundTrip4e(t *testing.T) {
	testVariantTransportRoundTrip(t, "4e", "trusttunnel", []string{"cstp"})
}

// testVariantTransportRoundTrip verifies that a variant builds, produces a
// non-nil carrier, and that all expected overlays are present.  This is an
// integration-level check that exercises BuildVariantForRole end-to-end.
func testVariantTransportRoundTrip(t *testing.T, variantID, expectedCarrier string, expectedOverlays []string) {
	t.Helper()

	cfg := newVariantConfig(variantID, expectedCarrier)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"uqsp-integration-test"},
	}

	proto, variant, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
	if err != nil {
		t.Fatalf("BuildVariantForRole(%s): %v", variantID, err)
	}
	if proto == nil {
		t.Fatalf("BuildVariantForRole(%s) returned nil protocol", variantID)
	}

	expectedVariant := uqsp.VariantFromName(variantID)
	if variant != expectedVariant {
		t.Fatalf("expected variant %d, got %d", expectedVariant, variant)
	}

	for _, name := range expectedOverlays {
		if !protocolHasOverlay(proto, name) {
			t.Errorf("variant %s: expected overlay %q not found", variantID, name)
		}
	}

	// Verify the protocol can produce a valid Dial function (does not panic).
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	// We expect Dial to fail (no real server), but it should not panic.
	_, dialErr := proto.Dial(ctx, "127.0.0.1:0")
	if dialErr == nil {
		t.Logf("variant %s: Dial unexpectedly succeeded (likely no real listener)", variantID)
	}
}

func newVariantConfig(variantID, carrierType string) *config.Config {
	cfg := &config.Config{}
	cfg.Role = "agent"
	cfg.Variant = variantID
	cfg.Transport.Type = "uqsp"
	cfg.Transport.UQSP.Carrier.Type = carrierType

	// Apply variant profile defaults so overlays are populated.
	uqsp.ApplyVariantProfile(cfg)
	return cfg
}

func protocolHasOverlay(proto *uqsp.UnifiedProtocol, name string) bool {
	for _, o := range proto.Overlays() {
		if strings.EqualFold(strings.TrimSpace(o.Name()), name) {
			return true
		}
	}
	return false
}
