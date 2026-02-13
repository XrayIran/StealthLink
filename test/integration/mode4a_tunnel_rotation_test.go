package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"stealthlink/internal/metrics"
	"stealthlink/internal/transport/xhttp"

	"github.com/xtaci/smux"
)

// TestMode4a_EstablishTunnelTriggerRotationVerifyNewConnection is the integration test for task 3.5a.
// It verifies that Mode 4a (XHTTP) can:
// 1. Establish a tunnel successfully
// 2. Send data through the tunnel
// 3. Trigger connection rotation based on configured limits
// 4. Verify that a new connection is established after rotation
// 5. Confirm rotation metrics are properly updated
func TestMode4a_EstablishTunnelTriggerRotationVerifyNewConnection(t *testing.T) {
	// Setup server with TLS and HTTP/2
	serverTLS := generateMode4aTLSConfig(t)
	serverTLS.NextProtos = []string{"h2", "http/1.1"}
	smuxCfg := smux.DefaultConfig()

	addr := "127.0.0.1:0"
	path := "/mode4a-tunnel"
	guard := "mode4a-test-guard"

	cfg := xhttp.Config{
		Path: path,
	}
	cfg.ApplyDefaults()

	// Start XHTTP listener (Mode 4a server)
	ln, err := xhttp.Listen(addr, cfg, serverTLS, smuxCfg, guard)
	if err != nil {
		t.Fatalf("Failed to start Mode 4a server: %v", err)
	}
	defer ln.Close()

	// Handle incoming sessions on server
	go func() {
		for {
			sess, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				for {
					stream, err := sess.AcceptStream()
					if err != nil {
						return
					}
					go io.Copy(stream, stream) // Echo
				}
			}()
		}
	}()

	// Setup client with rotation limits configured
	clientTLS := generateMode4aTLSConfig(t)
	clientTLS.InsecureSkipVerify = true
	clientTLS.NextProtos = []string{"h2", "http/1.1"}

	clientCfg := xhttp.Config{
		Path: path,
		XMux: xhttp.XMuxConfig{
			Enabled:          true,
			MaxConnections:   1,
			CMaxReuseTimes:   3,  // Rotate after 3 reuses
			HMaxRequestTimes: 10, // Rotate after 10 requests
			HMaxReusableSecs: 60, // Age limit (won't trigger in this test)
			DrainTimeout:     5 * time.Second,
		},
	}
	clientCfg.ApplyDefaults()

	dialer := xhttp.NewDialer(clientCfg, clientTLS, smuxCfg, "", "", guard)
	serverAddr := ln.Addr().String()

	// Capture initial metrics
	initialStats := metrics.SnapshotData()
	initialRotations := int64(0)
	if count, ok := initialStats.XmuxConnectionRotationsTotal["reuse_limit"]; ok {
		initialRotations = count
	}
	initialReuses := initialStats.XmuxConnectionReusesTotal

	t.Log("=== Phase 1: Establish tunnel and send data ===")

	// Establish first connection and send data
	sess1, err := dialer.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("Failed to establish Mode 4a tunnel: %v", err)
	}

	stream1, err := sess1.OpenStream()
	if err != nil {
		t.Fatalf("Failed to open stream in tunnel: %v", err)
	}

	// Send test data through the tunnel
	testData := []byte("Mode 4a tunnel test data - initial connection")
	if _, err := stream1.Write(testData); err != nil {
		t.Fatalf("Failed to write data through tunnel: %v", err)
	}

	// Read echo response
	buf := make([]byte, len(testData))
	if _, err := io.ReadFull(stream1, buf); err != nil {
		t.Fatalf("Failed to read data from tunnel: %v", err)
	}

	if string(buf) != string(testData) {
		t.Errorf("Data mismatch: got %q, want %q", buf, testData)
	}

	stream1.Close()
	sess1.Close() // Return to pool

	t.Log("✓ Tunnel established and data transmitted successfully")

	// Verify initial pool stats
	stats, ok := dialer.Stats()
	if !ok {
		t.Fatal("Stats not available from dialer")
	}

	if stats.Total < 1 {
		t.Errorf("Expected at least 1 connection in pool, got %d", stats.Total)
	}

	t.Logf("Initial pool stats: Total=%d, Active=%d, Idle=%d", stats.Total, stats.Active, stats.Idle)

	t.Log("=== Phase 2: Trigger rotation by exceeding reuse limit ===")

	// Reuse the connection multiple times to trigger rotation
	// CMaxReuseTimes=3, so after 4 Get/Close cycles, rotation should occur
	for i := 0; i < 4; i++ {
		sess, err := dialer.Dial(context.Background(), serverAddr)
		if err != nil {
			t.Fatalf("Dial %d failed: %v", i+2, err)
		}

		stream, err := sess.OpenStream()
		if err != nil {
			t.Fatalf("OpenStream %d failed: %v", i+2, err)
		}

		msg := []byte("Reuse test message")
		if _, err := stream.Write(msg); err != nil {
			t.Fatalf("Write %d failed: %v", i+2, err)
		}

		respBuf := make([]byte, len(msg))
		if _, err := io.ReadFull(stream, respBuf); err != nil {
			t.Fatalf("Read %d failed: %v", i+2, err)
		}

		stream.Close()
		sess.Close()

		t.Logf("Reuse cycle %d completed", i+1)
	}

	// Allow time for rotation to complete
	time.Sleep(500 * time.Millisecond)

	t.Log("=== Phase 3: Verify new connection established ===")

	// Get updated pool stats
	statsAfterRotation, ok := dialer.Stats()
	if !ok {
		t.Fatal("Stats not available after rotation")
	}

	t.Logf("Post-rotation pool stats: Total=%d, Active=%d, Idle=%d, Draining=%d",
		statsAfterRotation.Total, statsAfterRotation.Active, statsAfterRotation.Idle, statsAfterRotation.Draining)

	// Verify that at least 2 connections have been created (original + rotated)
	if statsAfterRotation.Total < 2 {
		t.Errorf("Expected at least 2 total connections after rotation, got %d", statsAfterRotation.Total)
	}

	// Verify metrics show rotation occurred
	finalStats := metrics.SnapshotData()
	finalRotations := int64(0)
	if count, ok := finalStats.XmuxConnectionRotationsTotal["reuse_limit"]; ok {
		finalRotations = count
	}
	finalReuses := finalStats.XmuxConnectionReusesTotal

	if finalRotations <= initialRotations {
		t.Errorf("Expected reuse_limit rotations to increase from %d, got %d", initialRotations, finalRotations)
	}

	if finalReuses <= initialReuses {
		t.Errorf("Expected connection reuses to increase from %d, got %d", initialReuses, finalReuses)
	}

	t.Logf("✓ Rotation metrics updated: rotations %d -> %d, reuses %d -> %d",
		initialRotations, finalRotations, initialReuses, finalReuses)

	t.Log("=== Phase 4: Verify new connection works correctly ===")

	// Establish a new session and verify it works
	sess2, err := dialer.Dial(context.Background(), serverAddr)
	if err != nil {
		t.Fatalf("Failed to dial after rotation: %v", err)
	}

	stream2, err := sess2.OpenStream()
	if err != nil {
		t.Fatalf("Failed to open stream after rotation: %v", err)
	}

	// Send data through the new connection
	newConnData := []byte("Mode 4a tunnel test data - after rotation")
	if _, err := stream2.Write(newConnData); err != nil {
		t.Fatalf("Failed to write data after rotation: %v", err)
	}

	buf2 := make([]byte, len(newConnData))
	if _, err := io.ReadFull(stream2, buf2); err != nil {
		t.Fatalf("Failed to read data after rotation: %v", err)
	}

	if string(buf2) != string(newConnData) {
		t.Errorf("Data mismatch after rotation: got %q, want %q", buf2, newConnData)
	}

	stream2.Close()
	sess2.Close()

	t.Log("✓ New connection after rotation works correctly")

	t.Log("=== Test Summary ===")
	t.Logf("✓ Mode 4a tunnel established successfully")
	t.Logf("✓ Data transmitted through tunnel")
	t.Logf("✓ Connection rotation triggered (reuse limit)")
	t.Logf("✓ New connection established and verified")
	t.Logf("✓ Rotation metrics updated correctly")
}

// generateMode4aTLSConfig creates a self-signed TLS config for Mode 4a testing
func generateMode4aTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "mode4a-test.local",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "mode4a-test.local"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("Failed to load key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
}
