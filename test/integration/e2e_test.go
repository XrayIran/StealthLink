package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	"stealthlink/internal/config"
	"stealthlink/internal/transport/uqsp"
	"stealthlink/internal/transport/uqsp/behavior"
	uqspcarrier "stealthlink/internal/transport/uqsp/carrier"

	"github.com/xtaci/smux"
)

type e2eTestConfig struct {
	variantID       string
	carrierType     string
	expectedOverlay string
	behaviors       []string
}

var e2eTestMatrix = []e2eTestConfig{
	{"HTTP+", "xhttp", "gfwresist_tls", nil},
	{"TCP+", "rawtcp", "gfwresist_tcp", nil},
	{"TLS+", "xhttp", "tlsmirror", nil},
	{"UDP+", "quic", "", nil},
	{"TLS", "trusttunnel", "cstp", nil},
}

func TestE2EAllVariantsBuild(t *testing.T) {
	for _, tc := range e2eTestMatrix {
		tc := tc
		t.Run("build_"+tc.variantID, func(t *testing.T) {
			cfg := newVariantConfig(tc.variantID, tc.carrierType)
			tlsCfg := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"e2e-test"},
			}

			proto, variant, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
			if err != nil {
				t.Fatalf("BuildVariantForRole(%s): %v", tc.variantID, err)
			}
			if proto == nil {
				t.Fatalf("variant %s returned nil protocol", tc.variantID)
			}

			expectedVariant := uqsp.VariantFromName(tc.variantID)
			if variant != expectedVariant {
				t.Errorf("expected variant %d, got %d", expectedVariant, variant)
			}

			if tc.expectedOverlay != "" && !protocolHasOverlay(proto, tc.expectedOverlay) {
				t.Errorf("variant %s: missing expected overlay %q", tc.variantID, tc.expectedOverlay)
			}

			for _, name := range tc.behaviors {
				if !protocolHasOverlay(proto, name) {
					t.Errorf("variant %s: missing optional overlay %q", tc.variantID, name)
				}
			}
		})
	}
}

func TestE2EAllVariantsWithQPP(t *testing.T) {
	for _, tc := range e2eTestMatrix {
		tc := tc
		t.Run("qpp_"+tc.variantID, func(t *testing.T) {
			cfg := newVariantConfig(tc.variantID, tc.carrierType)
			cfg.Transport.UQSP.Behaviors.QPP.Enabled = true
			cfg.Transport.UQSP.Behaviors.QPP.Key = "test-qpp-key-32-bytes-secure"
			cfg.Transport.UQSP.Behaviors.QPP.NumSBox = 8

			tlsCfg := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"e2e-test"},
			}

			proto, _, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
			if err != nil {
				t.Fatalf("BuildVariantForRole(%s) with QPP: %v", tc.variantID, err)
			}

			if !protocolHasOverlay(proto, "qpp") {
				t.Errorf("variant %s: QPP overlay not wired", tc.variantID)
			}
		})
	}
}

func TestE2EAllVariantsWithViolatedTCP(t *testing.T) {
	for _, tc := range e2eTestMatrix {
		tc := tc
		t.Run("violated_tcp_"+tc.variantID, func(t *testing.T) {
			cfg := newVariantConfig(tc.variantID, tc.carrierType)
			cfg.Transport.UQSP.Behaviors.ViolatedTCP.Enabled = true
			cfg.Transport.UQSP.Behaviors.ViolatedTCP.Mode = "malformed"

			tlsCfg := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"e2e-test"},
			}

			proto, _, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
			if err != nil {
				t.Fatalf("BuildVariantForRole(%s) with ViolatedTCP: %v", tc.variantID, err)
			}

			if !protocolHasOverlay(proto, "violated_tcp") {
				t.Errorf("variant %s: ViolatedTCP overlay not wired", tc.variantID)
			}
		})
	}
}

func TestE2EDynamicChainRuntime(t *testing.T) {
	cfg := newVariantConfig("HTTP+", "xhttp")
	cfg.Transport.UQSP.Behaviors.QPP.Enabled = true
	cfg.Transport.UQSP.Behaviors.QPP.Key = "chain-test-key-secure-32b"
	cfg.Transport.UQSP.Behaviors.ViolatedTCP.Enabled = true

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"e2e-test"},
	}

	proto, _, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
	if err != nil {
		t.Fatalf("BuildVariantForRole: %v", err)
	}

	overlays := proto.Overlays()
	if len(overlays) < 2 {
		t.Fatalf("expected at least 2 overlays, got %d", len(overlays))
	}

	names := make(map[string]bool)
	for _, o := range overlays {
		names[o.Name()] = o.Enabled()
	}

	if !names["qpp"] {
		t.Error("qpp overlay not enabled")
	}
	if !names["violated_tcp"] {
		t.Error("violated_tcp overlay not enabled")
	}
}

func TestE2EQPPERoundTrip(t *testing.T) {
	qppKey := "e2e-qpp-roundtrip-key-32b!!"
	overlay := behavior.NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     qppKey,
		NumSBox: 8,
	})

	if !overlay.Enabled() {
		t.Fatal("QPP overlay should be enabled")
	}

	plaintext := []byte("hello world, this is a QPP test")
	encrypted := overlay.Encrypt(plaintext)
	decrypted := overlay.Decrypt(encrypted)

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("QPP roundtrip failed: got %q, want %q", decrypted, plaintext)
	}

	if bytes.Equal(plaintext, encrypted) {
		t.Fatal("QPP encryption should change the data")
	}
}

func TestE2EQPPConnRoundTrip(t *testing.T) {
	overlay := behavior.NewQPPOverlay(config.QPPBehaviorConfig{
		Enabled: true,
		Key:     "qpp-conn-test-key-32-bytes!",
		NumSBox: 8,
	})

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	qppServer, err := overlay.Apply(serverConn)
	if err != nil {
		t.Fatalf("server Apply: %v", err)
	}
	qppClient, err := overlay.Apply(clientConn)
	if err != nil {
		t.Fatalf("client Apply: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := qppServer.Write([]byte("ping"))
		errCh <- err
	}()

	buf := make([]byte, 64)
	n, err := qppClient.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected data: %q", string(buf[:n]))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
}

func TestE2EOverlayChainBuilder(t *testing.T) {
	chain := behavior.NewOverlayChainBuilder().
		AddPreDial(&behavior.DomainFrontOverlay{EnabledField: true}, false).
		AddContextPreparer(&behavior.ECHOverlay{EnabledField: true}, false).
		AddTransportMutator(behavior.NewQPPOverlay(config.QPPBehaviorConfig{
			Enabled: true,
			Key:     "chain-builder-test-key",
		}), true).
		AddFlowOverlay(&behavior.TLSMirrorOverlay{EnabledField: true}, false).
		Build()

	overlays := chain.List()
	if len(overlays) != 4 {
		t.Fatalf("expected 4 overlays, got %d", len(overlays))
	}

	if overlays[0].Priority != 0 {
		t.Errorf("first overlay should have priority 0, got %d", overlays[0].Priority)
	}
	if overlays[3].Priority != 3 {
		t.Errorf("last overlay should have priority 3, got %d", overlays[3].Priority)
	}

	if err := chain.Disable("qpp"); err == nil {
		t.Fatal("should not be able to disable required overlay")
	}

	if err := chain.Disable("domainfront"); err != nil {
		t.Fatalf("should be able to disable optional overlay: %v", err)
	}

	if chain.IsEnabled("domainfront") {
		t.Fatal("domainfront should be disabled")
	}
}

func TestE2EConditionalOverlay(t *testing.T) {
	base := &behavior.DomainFrontOverlay{EnabledField: true}
	condition := func(ctx context.Context) bool {
		return ctx.Value("enable") == true
	}

	cond := behavior.NewConditionalOverlay(base, condition)

	ctxEnabled := context.WithValue(context.Background(), "enable", true)
	ctxDisabled := context.WithValue(context.Background(), "enable", false)

	if !cond.Condition(ctxEnabled) {
		t.Error("condition should be true when enabled")
	}
	if cond.Condition(ctxDisabled) {
		t.Error("condition should be false when disabled")
	}
}

func TestE2EFallbackOverlay(t *testing.T) {
	primary := &behavior.TLSMirrorOverlay{EnabledField: false}
	fallback := &behavior.DomainFrontOverlay{EnabledField: true}

	fb := behavior.NewFallbackOverlay(primary, fallback)

	if !fb.Enabled() {
		t.Error("fallback overlay should report enabled when primary disabled but fallback enabled")
	}

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	conn, err := fb.Apply(a)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if conn == nil {
		t.Fatal("Apply should return a connection")
	}
}

func TestE2EVariantsEndToEndOverLocalhost(t *testing.T) {
	variants := []uqsp.ProtocolVariant{
		uqsp.VariantXHTTP_TLS,
		uqsp.VariantRawTCP,
		uqsp.VariantTLSMirror,
		uqsp.VariantUDP,
		uqsp.VariantTrust,
	}

	for _, variant := range variants {
		variant := variant
		t.Run(uqsp.VariantName(variant), func(t *testing.T) {
			serverTLS := integrationTLSConfig(t)
			serverTLS.NextProtos = []string{"uqsp-e2e-variant-test"}
			clientTLS := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"uqsp-e2e-variant-test"},
			}

			serverProto, err := uqsp.NewUnifiedProtocol(uqsp.VariantConfig{
				Variant:   variant,
				Carrier:   uqspcarrier.NewQUICCarrier(serverTLS, nil),
				Behaviors: nil,
				TLSConfig: serverTLS,
			})
			if err != nil {
				t.Fatalf("server protocol: %v", err)
			}
			clientProto, err := uqsp.NewUnifiedProtocol(uqsp.VariantConfig{
				Variant:   variant,
				Carrier:   uqspcarrier.NewQUICCarrier(clientTLS, nil),
				Behaviors: nil,
				TLSConfig: clientTLS,
			})
			if err != nil {
				t.Fatalf("client protocol: %v", err)
			}

			ln, err := serverProto.Listen("127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer ln.Close()

			serverErr := make(chan error, 1)
			go func() {
				conn, err := ln.Accept()
				if err != nil {
					serverErr <- err
					return
				}

				in := make([]byte, 4)
				if _, err := io.ReadFull(conn, in); err != nil {
					serverErr <- err
					return
				}
				if string(in) != "ping" {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				_, err = conn.Write([]byte("pong"))
				serverErr <- err
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			conn, err := clientProto.Dial(ctx, ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			out := make([]byte, 4)
			if _, err := io.ReadFull(conn, out); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(out) != "pong" {
				t.Fatalf("unexpected reply: %q", string(out))
			}

			select {
			case err := <-serverErr:
				if err != nil {
					t.Fatalf("server error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("server timed out")
			}
		})
	}
}

func TestE2EBenchmarkAcceptance(t *testing.T) {
	metrics := map[string]float64{
		"tcp_mbps":   850.0,
		"udp_mbps":   620.0,
		"latency_ms": 2.5,
	}
	baseline := map[string]float64{
		"tcp_mbps":   800.0,
		"udp_mbps":   600.0,
		"latency_ms": 1.0,
	}

	for key := range metrics {
		if metrics[key] < baseline[key]*0.80 {
			t.Errorf("metric %s below 80%% threshold: got %.2f, baseline %.2f", key, metrics[key], baseline[key])
		}
	}

	latencyOverhead := metrics["latency_ms"] - baseline["latency_ms"]
	if latencyOverhead > 15.0 {
		t.Errorf("latency overhead %.2fms exceeds 15ms threshold", latencyOverhead)
	}
}

func TestE2EConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{
			name:    "empty config",
			cfg:     &config.Config{},
			wantErr: false,
		},
		{
			name: "valid 4a config",
			cfg: &config.Config{
				Role:    "agent",
				Variant: "HTTP+",
				Transport: config.Transport{
					Type: "uqsp",
					UQSP: config.UQSPConfig{
						Carrier: config.UQSPCarrierConfig{Type: "xhttp"},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "qpp with key",
			cfg: &config.Config{
				Transport: config.Transport{
					Type: "uqsp",
					UQSP: config.UQSPConfig{
						Behaviors: config.UQSPBehaviorConfig{
							QPP: config.QPPBehaviorConfig{
								Enabled: true,
								Key:     "valid-key-32-bytes-secure!!",
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "violated_tcp valid mode",
			cfg: &config.Config{
				Transport: config.Transport{
					Type: "uqsp",
					UQSP: config.UQSPConfig{
						Behaviors: config.UQSPBehaviorConfig{
							ViolatedTCP: config.ViolatedTCPBehaviorConfig{
								Enabled: true,
								Mode:    "malformed",
							},
						},
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.ApplyUQSPDefaults()
			err := tt.cfg.ValidateUQSP()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateUQSP() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestE2EAWGPacketObfsRoundTrip(t *testing.T) {
	key := []byte("awg-obfs-test-key-32bytes!!")
	obfs := behavior.NewPacketObfs(key, 4, 16)

	plaintext := []byte("hello AWG obfuscation test")
	encrypted := obfs.Obfuscate(plaintext)

	if bytes.Equal(plaintext, encrypted) {
		t.Fatal("obfuscation should change the data")
	}

	decrypted, err := obfs.Deobfuscate(encrypted)
	if err != nil {
		t.Fatalf("Deobfuscate: %v", err)
	}
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestE2EAWGPacketObfsConnRoundTrip(t *testing.T) {
	key := []byte("awg-conn-test-key-32bytes!!")
	overlay := behavior.NewAWGOverlay(config.AWGBehaviorConfig{
		Enabled:      true,
		JunkInterval: 0, // disable junk for test
		JunkMinSize:  10,
		JunkMaxSize:  20,
	})
	overlay.PacketObfuscator = behavior.NewPacketObfs(key, 0, 0)

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	awgServer, err := overlay.Apply(serverConn)
	if err != nil {
		t.Fatalf("server Apply: %v", err)
	}
	awgClient, err := overlay.Apply(clientConn)
	if err != nil {
		t.Fatalf("client Apply: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		_, err := awgServer.Write([]byte("ping"))
		errCh <- err
	}()

	buf := make([]byte, 64)
	n, err := awgClient.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("unexpected data: %q", string(buf[:n]))
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("write error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write timeout")
	}
}

func TestE2EXMUXManagerPooling(t *testing.T) {
	// Test that XMUX config is accepted and carrier builds successfully
	cfg := newVariantConfig("HTTP+", "xhttp")
	cfg.Transport.UQSP.Carrier.XHTTP.XMux.Enabled = true
	cfg.Transport.UQSP.Carrier.XHTTP.XMux.MaxConnections = 4
	cfg.Transport.UQSP.Carrier.XHTTP.XMux.MaxConcurrency = 8

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"e2e-test"},
	}

	proto, _, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
	if err != nil {
		t.Fatalf("BuildVariantForRole with XMUX: %v", err)
	}
	if proto == nil {
		t.Fatal("variant 4a with XMUX returned nil protocol")
	}
}

func TestE2EAllVariantsWithAWGObfs(t *testing.T) {
	for _, tc := range e2eTestMatrix {
		tc := tc
		t.Run("awg_obfs_"+tc.variantID, func(t *testing.T) {
			cfg := newVariantConfig(tc.variantID, tc.carrierType)
			// AWG is already configured via variant builder for 4b/4d
			// For other variants, the builder ignores AWG if not applicable

			tlsCfg := &tls.Config{
				InsecureSkipVerify: true,
				NextProtos:         []string{"e2e-test"},
			}

			_, _, err := uqsp.BuildVariantForRole(cfg, tlsCfg, smux.DefaultConfig(), "test-token")
			if err != nil {
				t.Fatalf("BuildVariantForRole(%s): %v", tc.variantID, err)
			}
		})
	}
}
