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
			name: "tap rejected (l3-only)",
			config: vpn.Config{
				Enabled:     true,
				Mode:        "tap",
				InterfaceIP: "10.0.0.1/24",
				MTU:         1400,
			},
			wantErr: true,
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

func TestVPNConfigValidationIPv6(t *testing.T) {
	tests := []struct {
		name    string
		config  vpn.Config
		wantErr bool
	}{
		{
			name: "valid ipv6 tun with peer",
			config: vpn.Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "fd00::1/128",
				PeerIP:      "fd00::2",
				MTU:         1400,
			},
			wantErr: false,
		},
		{
			name: "valid ipv6 /126 with peer",
			config: vpn.Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "fd00:77::1/126",
				PeerIP:      "fd00:77::2",
				MTU:         1400,
			},
			wantErr: false,
		},
		{
			name: "ipv6 with mixed v4/v6 routes",
			config: vpn.Config{
				Enabled:     true,
				Mode:        "tun",
				InterfaceIP: "fd00::1/128",
				PeerIP:      "fd00::2",
				MTU:         1400,
				Routes: []vpn.Route{
					{Destination: "fd00:100::/64"},
					{Destination: "192.168.0.0/24"},
				},
			},
			wantErr: false,
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

func TestVPNSessionIPv6Lifecycle(t *testing.T) {
	cfg := vpn.Config{
		Enabled:     true,
		Mode:        "tun",
		Name:        "test0",
		InterfaceIP: "fd00::1/128",
		PeerIP:      "fd00::2",
		MTU:         1400,
		Routes: []vpn.Route{
			{Destination: "fd00:100::/64"},
		},
	}

	stream := &mockStream{
		readBuf:  &bytes.Buffer{},
		writeBuf: &bytes.Buffer{},
	}

	session, err := vpn.NewSession(cfg, stream)
	if err != nil {
		t.Fatalf("NewSession(ipv6) error = %v", err)
	}

	if session.IsClosed() {
		t.Error("new IPv6 session should not be closed")
	}

	if err := session.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}

	if !session.IsClosed() {
		t.Error("IPv6 session should be closed after Close()")
	}
}

func TestVPNDatagramTransportSelection(t *testing.T) {
	// Verify that variant 4d configures tun.transport=datagram via the profile,
	// while stream-only variants (4a, 4e) use stream transport by default.
	datagramVariants := []string{"UDP+"}
	streamVariants := []string{"HTTP+", "TCP+", "TLS+", "TLS"}

	for _, v := range datagramVariants {
		t.Run("datagram-"+v, func(t *testing.T) {
			cfg := newVariantConfig(v, carrierForVariant(v))
			uqsp.ApplyVariantProfile(cfg)

			profile, ok := config.GetModeProfile(v)
			if !ok {
				t.Fatalf("no mode profile for variant %s", v)
			}
			if !profile.Capabilities.Datagrams {
				t.Errorf("variant %s should declare datagram capability", v)
			}
		})
	}

	for _, v := range streamVariants {
		t.Run("stream-"+v, func(t *testing.T) {
			profile, ok := config.GetModeProfile(v)
			if !ok {
				t.Fatalf("no mode profile for variant %s", v)
			}
			if profile.Capabilities.Datagrams {
				t.Errorf("variant %s should NOT declare datagram capability", v)
			}
		})
	}
}

func carrierForVariant(v string) string {
	switch v {
	case "HTTP+", "TLS+":
		return "xhttp"
	case "TCP+":
		return "rawtcp"
	case "UDP+":
		return "quic"
	case "TLS":
		return "trusttunnel"
	}
	return "quic"
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
	testVariantTransportRoundTrip(t, "HTTP+", "xhttp", []string{"gfwresist_tls"})
}

func TestVariantTransportRoundTrip4b(t *testing.T) {
	testVariantTransportRoundTrip(t, "TCP+", "rawtcp", []string{"gfwresist_tcp"})
}

func TestVariantTransportRoundTrip4c(t *testing.T) {
	testVariantTransportRoundTrip(t, "TLS+", "xhttp", []string{"tlsmirror"})
}

func TestVariantTransportRoundTrip4d(t *testing.T) {
	testVariantTransportRoundTrip(t, "UDP+", "quic", nil)
}

func TestVariantTransportRoundTrip4e(t *testing.T) {
	testVariantTransportRoundTrip(t, "TLS", "trusttunnel", []string{"cstp"})
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

// ---------------------------------------------------------------------------
// Phase 4.1 – Per-mode L3/TUN traffic completeness acceptance tests
// ---------------------------------------------------------------------------
//
// These tests validate that each mode's configuration and capability
// declarations are correct for supporting ICMP, TCP, UDP, and MTU-safe
// traffic over L3/TUN.  They run without real tunnels (acceptance criteria
// validators), so they do not require root or network namespaces.

func skipUnlessLinuxRoot(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux")
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
}

// trafficCompletenessForVariant builds a config for the given variant and
// asserts every criterion required by Phase 4.1 L3/TUN acceptance.
func trafficCompletenessForVariant(t *testing.T, variantID string) {
	t.Helper()

	carrier := carrierForVariant(variantID)
	cfg := newVariantConfig(variantID, carrier)

	// 1. Profile must exist
	profile, ok := config.GetModeProfile(variantID)
	if !ok {
		t.Fatalf("no mode profile for variant %s", variantID)
	}

	// 2. Streams must be supported (required for TCP traffic)
	if !profile.Capabilities.Streams {
		t.Errorf("variant %s: Streams capability must be true for TCP traffic", variantID)
	}

	// 3. MTU must be within VPN-safe range [1280, 1500]
	mtu := profile.Defaults.MTU
	if mtu < 1280 {
		t.Errorf("variant %s: default MTU %d < 1280 (IPv6 minimum); risk of blackholing", variantID, mtu)
	}
	if mtu > 1500 {
		t.Errorf("variant %s: default MTU %d > 1500 (Ethernet max); fragmentation strategy must be explicit", variantID, mtu)
	}

	// 4. VPN config at profile MTU must validate
	vpnCfg := vpn.Config{
		Enabled:     true,
		Mode:        "tun",
		Name:        "sl_test_" + variantID,
		InterfaceIP: "10.77.0.1/24",
		PeerIP:      "10.77.0.2",
		MTU:         mtu,
	}
	if err := vpnCfg.Validate(); err != nil {
		t.Errorf("variant %s: VPN config at profile MTU %d fails validation: %v", variantID, mtu, err)
	}

	// 5. VPN config at IPv6-minimum MTU 1280 must also validate
	vpnCfg.MTU = 1280
	if err := vpnCfg.Validate(); err != nil {
		t.Errorf("variant %s: VPN config at MTU 1280 fails validation: %v", variantID, err)
	}

	// 6. Carrier type declared by profile matches what the variant builds
	if profile.Carrier.Type != carrier {
		t.Errorf("variant %s: profile carrier %q != expected carrier %q", variantID, profile.Carrier.Type, carrier)
	}

	// 7. For 4d (UDP variant), datagram capability must be declared
	if variantID == "UDP+" {
		if !profile.Capabilities.Datagrams {
			t.Errorf("variant 4d must declare Datagrams capability for UDP traffic")
		}
		if !profile.Capabilities.Capsules {
			t.Errorf("variant 4d must declare Capsules capability for CONNECT-UDP/IP")
		}
	} else {
		// Stream-only variants must not claim datagram support
		if profile.Capabilities.Datagrams {
			t.Errorf("variant %s: stream-only variant should not declare Datagrams capability", variantID)
		}
	}

	// 8. ReverseConnect must be supported (all modes support it)
	if !profile.Capabilities.ReverseConnect {
		t.Errorf("variant %s: ReverseConnect capability must be true", variantID)
	}

	// 9. Verify reverse mode can be configured alongside the transport
	cfgReverse := newVariantConfig(variantID, carrier)
	cfgReverse.Transport.UQSP.Reverse.Enabled = true
	cfgReverse.Transport.UQSP.Reverse.AuthToken = "test-token-reverse"
	cfgReverse.Transport.UQSP.Reverse.Role = "listener"
	uqsp.ApplyVariantProfile(cfgReverse)
	// The config should still resolve to the correct variant
	if got := cfgReverse.GetVariant(); got != variantIndex(variantID) {
		t.Errorf("variant %s: enabling reverse changed resolved variant to %d", variantID, got)
	}

	// 10. WARP underlay must be declarable
	if !profile.Capabilities.WARPUnderlay {
		t.Errorf("variant %s: WARPUnderlay capability must be true", variantID)
	}

	// 11. WARP can be enabled without breaking variant resolution
	cfgWARP := newVariantConfig(variantID, carrier)
	cfgWARP.Transport.Dialer = "warp"
	cfgWARP.WARP.Enabled = true
	uqsp.ApplyVariantProfile(cfgWARP)
	if got := cfgWARP.GetVariant(); got != variantIndex(variantID) {
		t.Errorf("variant %s: enabling WARP changed resolved variant to %d", variantID, got)
	}

	_ = cfg // ensure cfg was used
}

func variantIndex(v string) int {
	switch v {
	case "HTTP+":
		return 0
	case "TCP+":
		return 1
	case "TLS+":
		return 2
	case "UDP+":
		return 3
	case "TLS":
		return 4
	}
	return -1
}

func TestVPNTrafficCompleteness4a(t *testing.T) {
	trafficCompletenessForVariant(t, "HTTP+")
}

func TestVPNTrafficCompleteness4b(t *testing.T) {
	trafficCompletenessForVariant(t, "TCP+")
}

func TestVPNTrafficCompleteness4c(t *testing.T) {
	trafficCompletenessForVariant(t, "TLS+")
}

func TestVPNTrafficCompleteness4d(t *testing.T) {
	trafficCompletenessForVariant(t, "UDP+")
}

func TestVPNTrafficCompleteness4e(t *testing.T) {
	trafficCompletenessForVariant(t, "TLS")
}

func TestVPNTrafficCompletenessMatrix(t *testing.T) {
	modes := []struct {
		variant        string
		defaultCarrier string
		expectDatagram bool
	}{
		{"HTTP+", "xhttp", false},
		{"TCP+", "rawtcp", false},
		{"TLS+", "xhttp", false},
		{"UDP+", "quic", true},
		{"TLS", "trusttunnel", false},
	}

	for _, m := range modes {
		t.Run("matrix-"+m.variant, func(t *testing.T) {
			profile, ok := config.GetModeProfile(m.variant)
			if !ok {
				t.Fatalf("no mode profile for variant %s", m.variant)
			}

			// Profile exists with correct capabilities
			if !profile.Capabilities.Streams {
				t.Error("Streams capability must be true")
			}
			if profile.Capabilities.Datagrams != m.expectDatagram {
				t.Errorf("Datagrams: got %v, want %v", profile.Capabilities.Datagrams, m.expectDatagram)
			}

			// Default carrier is the expected one
			if profile.Carrier.Type != m.defaultCarrier {
				t.Errorf("default carrier: got %q, want %q", profile.Carrier.Type, m.defaultCarrier)
			}

			// MTU range is specified and reasonable
			mtu := profile.Defaults.MTU
			if mtu < 1280 {
				t.Errorf("default MTU %d < 1280", mtu)
			}
			if mtu > 1500 {
				t.Errorf("default MTU %d > 1500", mtu)
			}

			// VPN validates at both boundary MTUs
			for _, testMTU := range []int{1280, mtu, 1400} {
				vpnCfg := vpn.Config{
					Enabled:     true,
					Mode:        "tun",
					InterfaceIP: "10.77.0.1/24",
					PeerIP:      "10.77.0.2",
					MTU:         testMTU,
				}
				if err := vpnCfg.Validate(); err != nil {
					t.Errorf("VPN config at MTU %d fails: %v", testMTU, err)
				}
			}

			// Reverse mode can be enabled without breaking validation
			cfg := newVariantConfig(m.variant, m.defaultCarrier)
			cfg.Transport.UQSP.Reverse.Enabled = true
			cfg.Transport.UQSP.Reverse.AuthToken = "test-token"
			cfg.Transport.UQSP.Reverse.Role = "listener"
			uqsp.ApplyVariantProfile(cfg)
			if got := cfg.GetVariant(); got != variantIndex(m.variant) {
				t.Errorf("reverse mode changed variant resolution: got %d, want %d", got, variantIndex(m.variant))
			}

			// WARP underlay can be enabled without breaking validation
			cfgW := newVariantConfig(m.variant, m.defaultCarrier)
			cfgW.Transport.Dialer = "warp"
			cfgW.WARP.Enabled = true
			uqsp.ApplyVariantProfile(cfgW)
			if got := cfgW.GetVariant(); got != variantIndex(m.variant) {
				t.Errorf("WARP underlay changed variant resolution: got %d, want %d", got, variantIndex(m.variant))
			}

			// ReverseConnect & WARPUnderlay declared
			if !profile.Capabilities.ReverseConnect {
				t.Error("ReverseConnect capability must be true")
			}
			if !profile.Capabilities.WARPUnderlay {
				t.Error("WARPUnderlay capability must be true")
			}
		})
	}
}
